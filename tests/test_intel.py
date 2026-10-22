"""Feed fetchers, HTTP retry/rate-limit behaviour and the enrichment stage (HTTP mocked)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy.orm import Session

from vulntriage.config import Settings
from vulntriage.intel.cache import cache_get, feed_health
from vulntriage.intel.enrich import enrich, ttl_map
from vulntriage.intel.feeds import (
    fetch_epss,
    osv_ecosystem,
    osv_fixed_versions,
    osv_version,
    parse_epss,
    parse_kev,
    parse_nvd,
)
from vulntriage.intel.http import FeedClient, FeedError, RateLimiter
from vulntriage.models import AssetKind, CveIntel, FeedStatus, Finding
from vulntriage.scanners.base import RawFinding, ScanResult
from vulntriage.scanners.ingest import AssetSpec, ingest_results

NOW = datetime(2026, 10, 20, 3, 0, tzinfo=UTC)
KEV_URL = "https://kev.test/kev.json"
EPSS_URL = "https://epss.test/epss"
NVD_URL = "https://nvd.test/cves"
OSV_URL = "https://osv.test/query"

KEV_DATA = {
    "catalogVersion": "2026.10.19",
    "vulnerabilities": [
        {"cveID": "CVE-2023-4911", "dateAdded": "2023-11-21", "dueDate": "2023-12-12",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known"},
    ],
}  # fmt: skip


def nvd_payload(cve: str, score: float = 7.5) -> dict[str, Any]:
    return {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve,
                    "descriptions": [
                        {"lang": "es", "value": "x"},
                        {"lang": "en", "value": "Heap overflow."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Secondary",
                                "cvssData": {"baseScore": 1.0, "vectorString": "sec"},
                            },
                            {
                                "type": "Primary",
                                "cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N"},
                            },
                        ]
                    },
                    "weaknesses": [
                        {"description": [{"value": "NVD-CWE-noinfo"}, {"value": "CWE-787"}]}
                    ],
                }
            }
        ],
    }


def epss_handler(request: httpx.Request) -> httpx.Response:
    cves = request.url.params["cve"].split(",")
    scores = {"CVE-2023-4911": "0.71", "CVE-2021-44228": "0.94", "CVE-2024-0001": "0.002"}
    data = [
        {"cve": c, "epss": scores[c], "percentile": "0.99", "date": "2026-10-19"}
        for c in cves
        if c in scores
    ]
    return httpx.Response(200, json={"status": "OK", "data": data})


@pytest.fixture
def feed_settings(settings: Settings) -> Settings:
    return settings.model_copy(
        update={"kev_url": KEV_URL, "epss_url": EPSS_URL, "nvd_url": NVD_URL, "osv_url": OSV_URL}
    )


@pytest.fixture
def client() -> FeedClient:
    return FeedClient(httpx.Client(), max_retries=2, sleep=lambda _s: None)


def no_limit() -> RateLimiter:
    return RateLimiter(10**6, 1.0, sleep=lambda _s: None)


def seed(session: Session) -> None:
    findings = [
        RawFinding(vuln_id="CVE-2023-4911", package_name="libc6", package_type="debian",
                   installed_version="2.36-9", fixed_version="2.36-9+deb12u3", cvss_score=7.8),
        RawFinding(vuln_id="CVE-2021-44228", package_name="log4j-core", package_type="jar",
                   target="app/lib/log4j-core.jar", installed_version="2.14.1"),
        RawFinding(vuln_id="CVE-2024-0001", package_name="requests", package_type="python-pkg",
                   target="usr/lib/python3/site-packages/requests", installed_version="2.30.0"),
        RawFinding(vuln_id="GHSA-abcd-efgh-ijkl", package_name="x", package_type="npm",
                   target="app/node_modules/x", installed_version="1.0.0"),
    ]  # fmt: skip
    result = ScanResult(scanner="trivy", artifact_name="app:1", os_family="debian", os_name="12.5",
                        findings=findings)  # fmt: skip
    ingest_results(session, AssetSpec(AssetKind.IMAGE, "app", "1"), [result], now=NOW)


def mock_all(router: respx.MockRouter, kev_status: int = 200) -> dict[str, respx.Route]:
    osv = {
        "vulns": [
            {"id": "GHSA-1", "aliases": ["CVE-2024-0001"],
             "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]}
        ]
    }  # fmt: skip

    def nvd(request: httpx.Request) -> httpx.Response:
        cve = request.url.params["cveId"]
        if cve == "CVE-2021-44228":
            return httpx.Response(200, json=nvd_payload(cve, 10.0))
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    def osv_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(200, json=osv if body["package"]["name"] == "requests" else {})

    return {
        "kev": router.get(KEV_URL).mock(
            return_value=httpx.Response(kev_status, json=KEV_DATA if kev_status == 200 else {})
        ),
        "epss": router.get(EPSS_URL).mock(side_effect=epss_handler),
        "nvd": router.get(NVD_URL).mock(side_effect=nvd),
        "osv": router.post(OSV_URL).mock(side_effect=osv_handler),
    }


# --- parsers ----------------------------------------------------------------------------


def test_parse_kev_flags_ransomware() -> None:
    kev = parse_kev(KEV_DATA)
    assert kev["CVE-2021-44228"].ransomware_use is True
    assert kev["CVE-2023-4911"].ransomware_use is False
    assert kev["CVE-2023-4911"].due_date == "2023-12-12"


def test_parse_epss_skips_malformed_rows() -> None:
    parsed = parse_epss(
        {"data": [{"cve": "CVE-1", "epss": "0.5", "percentile": "0.9"}, {"cve": "CVE-2"}]}
    )
    assert list(parsed) == ["CVE-1"] and parsed["CVE-1"].epss == 0.5


def test_parse_nvd_prefers_primary_v31_and_real_cwe() -> None:
    entry = parse_nvd(nvd_payload("CVE-1", 9.1), "CVE-1")
    assert entry is not None
    assert (entry.cvss_score, entry.cvss_vector, entry.cwe) == (9.1, "CVSS:3.1/AV:N", "CWE-787")
    assert entry.description == "Heap overflow."
    assert parse_nvd({"vulnerabilities": []}, "CVE-1") is None


def test_parse_nvd_falls_back_to_v30() -> None:
    payload = {"vulnerabilities": [{"cve": {"id": "CVE-1", "metrics": {
        "cvssMetricV30": [{"type": "Primary", "cvssData": {"baseScore": 5.3, "vectorString": "v30"}}]}}}]}  # fmt: skip
    entry = parse_nvd(payload, "CVE-1")
    assert entry is not None and entry.cvss_score == 5.3 and entry.cwe is None


@pytest.mark.parametrize(
    ("pkg_type", "os_name", "expected"),
    [("python-pkg", None, "PyPI"), ("gobinary", None, "Go"), ("debian", "12.5", "Debian:12"),
     ("alpine", "3.14.3", "Alpine:v3.14"), ("ubuntu", "22.04", "Ubuntu:22.04"), ("debian", None, None),
     ("weird", None, None)],
)  # fmt: skip
def test_osv_ecosystem(pkg_type: str, os_name: str | None, expected: str | None) -> None:
    assert osv_ecosystem(pkg_type, os_name) == expected


def test_osv_fixed_versions_matches_alias_and_package() -> None:
    payload = {"vulns": [
        {"id": "GO-1", "aliases": ["CVE-9"], "affected": [
            {"package": {"name": "other"}, "ranges": [{"events": [{"fixed": "9.9"}]}]},
            {"package": {"name": "lib"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.4"}]},
                                                     {"events": [{"fixed": "1.2.4"}, {"fixed": "2.0.1"}]}]}]},
        {"id": "GO-2", "aliases": ["CVE-10"], "affected": [{"package": {"name": "lib"}, "ranges": [{"events": [{"fixed": "3"}]}]}]},
    ]}  # fmt: skip
    assert osv_fixed_versions(payload, "CVE-9", "lib") == ["1.2.4", "2.0.1"]
    assert osv_fixed_versions(payload, "GO-2", "lib") == ["3"]
    assert osv_fixed_versions({}, "CVE-9", "lib") == []
    assert osv_version("Go", "v1.2.3") == "1.2.3" and osv_version("PyPI", "v1") == "v1"


# --- HTTP plumbing -------------------------------------------------------------------------


@respx.mock
def test_feed_client_retries_then_succeeds(client: FeedClient) -> None:
    route = respx.get("https://x.test/a").mock(
        side_effect=[
            httpx.Response(503),
            httpx.ConnectError("boom"),
            httpx.Response(200, json={"ok": 1}),
        ]
    )
    assert client.get_json("https://x.test/a") == {"ok": 1}
    assert route.call_count == 3


@respx.mock
def test_feed_client_honours_retry_after_and_gives_up() -> None:
    sleeps: list[float] = []
    client = FeedClient(httpx.Client(), max_retries=2, sleep=sleeps.append)
    respx.get("https://x.test/a").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "7"})
    )
    with pytest.raises(FeedError, match="HTTP 429"):
        client.get_json("https://x.test/a")
    assert sleeps == [7.0, 7.0]


@respx.mock
def test_feed_client_does_not_retry_client_errors(client: FeedClient) -> None:
    route = respx.get("https://x.test/a").mock(return_value=httpx.Response(400))
    with pytest.raises(FeedError, match="HTTP 400"):
        client.get_json("https://x.test/a")
    assert route.call_count == 1
    respx.get("https://x.test/missing").mock(return_value=httpx.Response(404))
    assert client.get_json("https://x.test/missing", allow_404=True) is None
    respx.get("https://x.test/html").mock(return_value=httpx.Response(200, text="<html>"))
    with pytest.raises(FeedError, match="not JSON"):
        client.get_json("https://x.test/html")


def test_rate_limiter_sleeps_when_window_full() -> None:
    t = [0.0]
    slept: list[float] = []

    def sleep(s: float) -> None:
        slept.append(s)
        t[0] += s

    limiter = RateLimiter(2, 30.0, clock=lambda: t[0], sleep=sleep)
    limiter.acquire()
    limiter.acquire()
    assert slept == []
    t[0] = 10.0
    limiter.acquire()
    assert slept == [20.0]


@respx.mock
def test_fetch_epss_batches_requests(client: FeedClient) -> None:
    route = respx.get(EPSS_URL).mock(side_effect=epss_handler)
    cves = [f"CVE-2020-{i:05d}" for i in range(150)] + ["CVE-2023-4911", "GHSA-x"]
    result = fetch_epss(client, EPSS_URL, cves)
    assert route.call_count == 2
    assert list(result) == ["CVE-2023-4911"]


# --- enrichment stage ------------------------------------------------------------------------


@respx.mock
def test_enrich_populates_intel_fix_versions_and_status(
    session: Session, feed_settings: Settings, client: FeedClient
) -> None:
    seed(session)
    routes = mock_all(respx.mock)
    summary = enrich(session, feed_settings, client, now=NOW, nvd_rate_limiter=no_limit())

    assert summary.cves == 3 and summary.kev_listed == 2 and not summary.errors
    glibc = session.get(CveIntel, "CVE-2023-4911")
    log4j = session.get(CveIntel, "CVE-2021-44228")
    assert glibc and log4j
    assert (glibc.in_kev, glibc.epss, glibc.kev_date_added, glibc.ransomware_use) == (
        True,
        0.71,
        "2023-11-21",
        False,
    )
    assert log4j.ransomware_use is True
    # Only CVEs without scanner CVSS go to NVD (mode=missing).
    called = sorted(c.request.url.params["cveId"] for c in routes["nvd"].calls)
    assert called == ["CVE-2021-44228", "CVE-2024-0001"]
    assert (log4j.cvss_score, log4j.cvss_source, log4j.cwe) == (10.0, "nvd", "CWE-787")
    assert glibc.cvss_source == "scanner"

    requests_finding = session.query(Finding).filter_by(package_name="requests").one()
    assert (requests_finding.fixed_version, requests_finding.fixed_version_source) == (
        "2.32.0",
        "osv",
    )
    assert summary.osv_fixes == 1
    assert {f: h.last_error for f, h in summary.health.items()} == dict.fromkeys(
        ("kev", "epss", "nvd", "osv")
    )


@respx.mock
def test_enrich_uses_cache_within_ttl(
    session: Session, feed_settings: Settings, client: FeedClient
) -> None:
    seed(session)
    routes = mock_all(respx.mock)
    enrich(session, feed_settings, client, now=NOW, nvd_rate_limiter=no_limit())
    counts = {k: r.call_count for k, r in routes.items()}
    enrich(
        session, feed_settings, client, now=NOW + timedelta(hours=2), nvd_rate_limiter=no_limit()
    )
    assert {k: r.call_count for k, r in routes.items()} == counts


@respx.mock
def test_enrich_falls_back_to_stale_cache_when_feed_down(
    session: Session, feed_settings: Settings, client: FeedClient
) -> None:
    seed(session)
    mock_all(respx.mock)
    enrich(session, feed_settings, client, now=NOW, nvd_rate_limiter=no_limit())

    later = NOW + timedelta(days=3)
    respx.mock.routes.clear()
    mock_all(respx.mock, kev_status=503)
    respx.get(EPSS_URL).mock(side_effect=httpx.ConnectError("down"))
    summary = enrich(session, feed_settings, client, now=later, nvd_rate_limiter=no_limit())

    assert any(e.startswith("kev:") for e in summary.errors)
    assert any(e.startswith("epss:") for e in summary.errors)
    intel = session.get(CveIntel, "CVE-2023-4911")
    assert intel and intel.in_kev and intel.epss == 0.71  # cached values survive
    health = summary.health["kev"]
    assert health.stale and health.age_hours == pytest.approx(72.0)
    assert "HTTP 503" in (health.last_error or "")
    assert "3.0 days old" in health.describe() and "stale" in health.describe()


@respx.mock
def test_offline_mode_makes_no_requests(
    session: Session, feed_settings: Settings, client: FeedClient
) -> None:
    seed(session)
    routes = mock_all(respx.mock)
    summary = enrich(session, feed_settings.model_copy(update={"offline": True}), client, now=NOW)
    assert all(r.call_count == 0 for r in routes.values())
    assert "kev: no cached catalog; KEV status unknown" in summary.errors
    assert summary.health["epss"].describe() == "epss: never fetched"


@respx.mock
def test_nvd_gives_up_after_consecutive_failures(
    session: Session, feed_settings: Settings, client: FeedClient
) -> None:
    for i in range(6):
        result = ScanResult(scanner="trivy", artifact_name="a", findings=[
            RawFinding(vuln_id=f"CVE-2024-{i:04d}", package_name=f"p{i}", package_type="debian")])  # fmt: skip
        ingest_results(session, AssetSpec(AssetKind.IMAGE, f"a{i}", "1"), [result], now=NOW)
    mock_all(respx.mock)
    route = respx.get(NVD_URL).mock(return_value=httpx.Response(503))
    summary = enrich(session, feed_settings, client, now=NOW, nvd_rate_limiter=no_limit())
    assert route.call_count == 3 * (client.max_retries + 1)
    assert any("giving up" in e for e in summary.errors)
    status = session.get(FeedStatus, "nvd")
    assert status is not None and status.last_success_at is None


def test_feed_health_and_ttl_map(session: Session, settings: Settings) -> None:
    health = feed_health(session, ttl_map(settings), NOW)
    assert set(health) == {"kev", "epss", "nvd", "osv"}
    assert all(h.stale and h.last_success_at is None for h in health.values())
    assert cache_get(session, "kev", "catalog") is None


@respx.mock
def test_cli_enrich_and_feeds(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    import vulntriage.cli as cli
    from vulntriage.db import get_engine, init_db, session_scope

    cfg = settings.model_copy(
        update={"kev_url": KEV_URL, "epss_url": EPSS_URL, "nvd_url": NVD_URL, "osv_url": OSV_URL,
                "nvd_mode": "never"}
    )  # fmt: skip
    engine = get_engine(cfg.database_url)
    init_db(engine)
    with session_scope(engine) as s:
        seed(s)
    monkeypatch.setattr(cli, "get_settings", lambda: cfg)
    mock_all(respx.mock)
    runner = CliRunner(env={"COLUMNS": "200"})
    result = runner.invoke(cli.app, ["enrich"])
    assert result.exit_code == 0, result.output
    assert "enriched 3 CVEs: 2 in KEV" in result.output
    feeds_out = runner.invoke(cli.app, ["feeds"])
    assert "kev: 0.0 h old" in feeds_out.output
    assert "nvd: never fetched" in feeds_out.output

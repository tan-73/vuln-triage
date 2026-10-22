"""Deduplication across runs: first_seen/last_seen, resolution, re-opening, scanner merge."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.conftest import load_fixture
from vulntriage.models import Asset, AssetKind, CveIntel, Finding, FindingStatus
from vulntriage.scanners.base import RawFinding, ScanResult
from vulntriage.scanners.ingest import (
    AssetSpec,
    ingest_results,
    merge_raw_findings,
    parse_image_ref,
    retire_missing_assets,
)
from vulntriage.scanners.trivy import parse_trivy_report

T0 = datetime(2026, 10, 1, 2, 30, tzinfo=UTC)
SPEC = AssetSpec(AssetKind.IMAGE, "app", "1.0", scan_target="app:1.0", containers=("web",))


def _raw(vuln: str, pkg: str = "openssl", **kw: object) -> RawFinding:
    return RawFinding(vuln_id=vuln, package_name=pkg, package_type="debian", **kw)  # type: ignore[arg-type]


def _result(*findings: RawFinding, scanner: str = "trivy") -> ScanResult:
    return ScanResult(scanner=scanner, artifact_name="app:1.0", findings=list(findings))


def test_parse_image_ref_variants() -> None:
    assert parse_image_ref("nginx") == ("nginx", "latest")
    assert parse_image_ref("nginx:1.25") == ("nginx", "1.25")
    assert parse_image_ref("registry:5000/team/app:2") == ("registry:5000/team/app", "2")
    assert parse_image_ref("registry:5000/team/app") == ("registry:5000/team/app", "latest")
    assert parse_image_ref("nginx@sha256:abc") == ("nginx", "sha256:abc")


def test_ingest_tracks_first_last_seen_and_resolves(session: Session) -> None:
    a = _raw("CVE-2024-0001", fixed_version="3.0.1")
    b = _raw("CVE-2024-0002", pkg="zlib")
    asset, stats = ingest_results(session, SPEC, [_result(a, b)], now=T0)
    assert (stats.total, stats.new, stats.resolved) == (2, 2, 0)
    assert asset.containers == ["web"] and asset.last_scanned == T0

    t1 = T0 + timedelta(days=1)
    _, stats = ingest_results(session, SPEC, [_result(a)], now=t1)
    assert (stats.new, stats.resolved) == (0, 1)
    rows = {f.cve_id: f for f in session.scalars(select(Finding))}
    assert rows["CVE-2024-0001"].first_seen == T0
    assert rows["CVE-2024-0001"].last_seen == t1
    assert rows["CVE-2024-0002"].status == FindingStatus.RESOLVED
    assert rows["CVE-2024-0002"].resolved_at == t1
    assert rows["CVE-2024-0002"].resolution_reason == "not_detected"

    t2 = t1 + timedelta(days=1)
    _, stats = ingest_results(session, SPEC, [_result(a, b)], now=t2)
    assert stats.reopened == 1
    reopened = session.scalars(select(Finding).where(Finding.cve_id == "CVE-2024-0002")).one()
    assert reopened.status == FindingStatus.OPEN
    assert reopened.first_seen == T0 and reopened.resolved_at is None
    assert session.scalar(select(Asset).where(Asset.name == "app")) is asset


def test_same_cve_in_two_targets_is_two_findings(session: Session) -> None:
    one = RawFinding(vuln_id="CVE-1", package_name="glog", package_type="gobinary", target="bin/a")
    two = one.model_copy(update={"target": "bin/b"})
    _, stats = ingest_results(session, SPEC, [_result(one, two)], now=T0)
    assert stats.total == 2


def test_merge_trivy_and_grype_fills_gaps() -> None:
    t = _raw("CVE-1", severity="MEDIUM")
    g = _raw("CVE-1", severity="HIGH", fixed_version="1.2", cvss_score=7.5, scanner="grype")
    only_grype = _raw("CVE-2", scanner="grype")
    merged = merge_raw_findings([_result(t), _result(g, only_grype, scanner="grype")])
    first = merged[("CVE-1", "openssl", "os")]
    assert first.scanner == "grype,trivy"
    assert (first.severity, first.fixed_version, first.cvss_score) == ("HIGH", "1.2", 7.5)
    assert merged[("CVE-2", "openssl", "os")].scanner == "grype"


def test_scanner_intel_seeds_cve_intel_but_never_overrides_nvd(session: Session) -> None:
    session.add(CveIntel(cve_id="CVE-9", cvss_score=9.8, cvss_source="nvd", cvss_vector="nvd"))
    session.flush()
    raw_known = _raw("CVE-9", cvss_score=5.0, cvss_vector="scanner", description="d")
    raw_new = _raw("CVE-10", cvss_score=6.1, cvss_vector="v", cwe="CWE-79")
    ghsa = _raw("GHSA-aaaa-bbbb-cccc")
    ingest_results(session, SPEC, [_result(raw_known, raw_new, ghsa)], now=T0)
    assert session.get(CveIntel, "CVE-9").cvss_score == 9.8  # type: ignore[union-attr]
    new = session.get(CveIntel, "CVE-10")
    assert new is not None and (new.cvss_score, new.cvss_source, new.cwe) == (
        6.1,
        "scanner",
        "CWE-79",
    )
    assert session.get(CveIntel, "GHSA-aaaa-bbbb-cccc") is None


def test_retire_missing_assets_resolves_their_findings(session: Session) -> None:
    keep, _ = ingest_results(session, SPEC, [_result(_raw("CVE-1"))], now=T0)
    gone_spec = AssetSpec(AssetKind.IMAGE, "old", "1", scan_target="old:1")
    gone, _ = ingest_results(session, gone_spec, [_result(_raw("CVE-2"))], now=T0)
    resolved = retire_missing_assets(session, AssetKind.IMAGE, {keep.id}, now=T0)
    assert resolved == 1
    assert gone.active is False and keep.active is True
    assert gone.findings[0].resolution_reason == "asset_removed"


def test_ingest_real_fixture_is_idempotent(session: Session) -> None:
    result = parse_trivy_report(load_fixture("trivy/redis_6.2.6.json"))
    spec = AssetSpec(AssetKind.IMAGE, "redis", "6.2.6", scan_target="redis:6.2.6")
    _, first = ingest_results(session, spec, [result], now=T0)
    _, second = ingest_results(session, spec, [result], now=T0 + timedelta(days=1))
    assert first.new == first.total > 0
    assert (second.new, second.resolved, second.total) == (0, 0, first.total)
    assert session.query(Finding).count() == first.total

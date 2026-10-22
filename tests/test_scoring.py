"""Deterministic scoring and remediation grouping."""

from __future__ import annotations

import random

import pydantic
import pytest
from sqlalchemy.orm import Session

from vulntriage.config import ScoringWeights, Settings
from vulntriage.models import AssetKind, CveIntel, ExposureLevel, Finding
from vulntriage.remediation import (
    build_groups,
    line_tag,
    os_upgrade_command,
    package_command,
    pick_fix,
    version_key,
)
from vulntriage.scanners.base import RawFinding, ScanResult
from vulntriage.scanners.ingest import AssetSpec, ingest_results
from vulntriage.scoring import ScoreInput, score_all, score_finding

W = ScoringWeights()


def inp(**kw: object) -> ScoreInput:
    base: dict[str, object] = {
        "cve_id": "CVE-2024-0001", "package_name": "openssl", "asset_kind": AssetKind.IMAGE,
        "exposure": ExposureLevel.LAN, "epss": 0.1, "epss_percentile": 0.9, "in_kev": False,
        "ransomware_use": False, "cvss": 7.5, "severity": "HIGH", "fixed_version": None,
    }  # fmt: skip
    base.update(kw)
    return ScoreInput(**base)  # type: ignore[arg-type]


def test_score_is_sum_of_components_and_explained() -> None:
    result = score_finding(inp(fixed_version="3.0.2"), W)
    assert result.score == pytest.approx(sum(c["points"] for c in result.components), abs=1e-3)
    # 0.1 * 100 * 0.5 = 5; fix boost +25% = 1.25; CVSS 7.5 -> 0.75
    assert result.score == pytest.approx(5 + 1.25 + 0.75)
    text = result.explanation()
    assert text[0].startswith(
        "Exploit likelihood x exposure: EPSS 0.1000 (percentile 0.90) x lan exposure"
    )
    assert any("fixed in 3.0.2" in line for line in text)
    assert result.as_dict()["tier"] == "standard"


def test_kev_always_outranks_non_kev_randomised() -> None:
    rng = random.Random(1234)
    levels = list(ExposureLevel)
    for _ in range(3000):
        kev = score_finding(
            inp(in_kev=True, epss=rng.choice([None, 0.0, rng.random()]), exposure=rng.choice(levels),
                cvss=rng.choice([None, 0.0]), fixed_version=None, package_name="linux-libc-dev"),
            W,
        ).score  # fmt: skip
        other = score_finding(
            inp(
                epss=1.0,
                exposure=ExposureLevel.INTERNET,
                cvss=10.0,
                fixed_version="9",
                in_kev=False,
            ),
            W,
        ).score
        assert kev > other


def test_exposure_multiplier_ordering() -> None:
    scores = [score_finding(inp(exposure=lvl), W).score for lvl in
              (ExposureLevel.INTERNET, ExposureLevel.LAN, ExposureLevel.LOCALHOST, ExposureLevel.NONE)]  # fmt: skip
    assert scores == sorted(scores, reverse=True) and len(set(scores)) == 4


def test_cvss_only_breaks_ties() -> None:
    low = score_finding(inp(epss=0.2, cvss=2.0), W).score
    high = score_finding(inp(epss=0.2, cvss=9.8), W).score
    more_likely = score_finding(inp(epss=0.25, cvss=2.0), W).score
    assert low < high < more_likely


def test_ransomware_bonus_and_kev_breakdown() -> None:
    result = score_finding(inp(in_kev=True, ransomware_use=True, kev_date_added="2023-11-21"), W)
    labels = [c["label"] for c in result.components]
    assert labels[:2] == ["CISA KEV", "Ransomware use"]
    assert "added 2023-11-21" in result.components[0]["detail"]
    assert result.tier == "kev"
    plain_kev = score_finding(inp(in_kev=True), W).score
    assert result.score - plain_kev == pytest.approx(W.ransomware_bonus)


def test_kernel_packages_in_images_are_not_applicable() -> None:
    image = score_finding(inp(package_name="linux-libc-dev", epss=0.5), W)
    host = score_finding(inp(package_name="linux-libc-dev", epss=0.5, asset_kind=AssetKind.HOST), W)
    assert image.score == pytest.approx(0.75)  # only the CVSS tiebreaker survives
    assert any(c.get("not_applicable") for c in image.components)
    assert host.score > 20


def test_missing_epss_and_cvss_fall_back_transparently() -> None:
    result = score_finding(inp(epss=None, epss_percentile=None, cvss=None, severity="CRITICAL"), W)
    assert result.score == pytest.approx(0.9)
    assert "no EPSS score; assuming 0.0" in result.explanation()[0]
    assert "no CVSS; CRITICAL severity treated as 9.0" in result.explanation()[-1]
    weighted = score_finding(
        inp(epss=None, epss_percentile=None), ScoringWeights(unknown_epss=0.05)
    )
    assert weighted.score > result.score


def test_weights_validator_protects_kev_tier() -> None:
    with pytest.raises(pydantic.ValidationError, match="kev_tier_offset"):
        ScoringWeights(kev_tier_offset=50)
    with pytest.raises(pydantic.ValidationError):
        ScoringWeights(epss_scale=2000)


def test_weights_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCORING__EXPOSURE_LAN", "0.7")
    monkeypatch.setenv("ACTION_THRESHOLD", "12.5")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.scoring.exposure_lan == 0.7 and s.action_threshold == 12.5


# --- remediation helpers ---------------------------------------------------------------------


def test_version_key_orders_real_world_versions() -> None:
    ordered = ["1.2", "1.9", "1.10", "1:0.5", "2.36-9", "2.36-9+deb12u3", "2.36-10"]
    assert sorted(ordered, key=version_key)[:3] == ["1.2", "1.9", "1.10"]
    assert version_key("2.36-9+deb12u3") > version_key("2.36-9")
    assert version_key("1:0.5") > version_key("9.9")
    assert version_key("1.0~rc1") < version_key("1.0")
    assert version_key("v1.2.3") == version_key("1.2.3")


@pytest.mark.parametrize(
    ("installed", "fixed", "expected"),
    [("1.20.1", "1.19.9, 1.20.4, 1.21.1", "1.20.4"), ("2.0.0", "1.2.4", "1.2.4"),
     ("v0.0.0-2016", "1.2.4", "1.2.4"), ("1.0", None, None), ("3.0.2", "3.0.7, 3.1.0", "3.0.7"),
     ("0.9", "1.5, 1.4", "1.5")],
)  # fmt: skip
def test_pick_fix(installed: str, fixed: str | None, expected: str | None) -> None:
    assert pick_fix(installed, fixed) == expected


@pytest.mark.parametrize(
    ("tag", "expected"),
    [("3.11.4-slim", "3.11-slim"), ("8.3.0", "8.3"), ("13.2", "13"), ("latest", None),
     ("alpine", None), ("v2.10.4", "v2.10")],
)  # fmt: skip
def test_line_tag(tag: str, expected: str | None) -> None:
    assert line_tag(tag) == expected


def test_commands() -> None:
    assert (
        package_command("python-pkg", "requests", "2.32.0")
        == "pip install --upgrade 'requests>=2.32.0'"
    )
    assert package_command("npm", "lodash", "4.17.21") == "npm install lodash@4.17.21"
    assert (
        package_command("gobinary", "golang.org/x/net", "v0.23.0")
        == "go get golang.org/x/net@v0.23.0"
    )
    assert package_command("weird", "x", "1") == "upgrade x to 1"
    assert os_upgrade_command("alpine", ["musl", "busybox"]) == "apk upgrade busybox musl"
    assert os_upgrade_command("rocky", ["openssl"]) == "sudo dnf upgrade openssl"
    assert os_upgrade_command("ubuntu", ["libc6", "libc6"]).endswith("--only-upgrade libc6")


# --- end to end on the database --------------------------------------------------------------


def _seed(session: Session) -> None:
    def raw(
        cve: str,
        pkg: str,
        typ: str = "debian",
        target: str = "os",
        inst: str = "1.0",
        fix: str | None = "1.1",
    ):
        return RawFinding(vuln_id=cve, package_name=pkg, package_type=typ, target=target,
                          installed_version=inst, fixed_version=fix, severity="HIGH")  # fmt: skip

    web = AssetSpec(AssetKind.IMAGE, "nginx", "1.25.1", containers=("proxy",))
    ingest_results(session, web, [ScanResult(scanner="trivy", artifact_name="nginx", os_family="debian", findings=[
        raw("CVE-2023-4911", "libc6", inst="2.36-9", fix="2.36-9+deb12u3"),
        raw("CVE-2023-4911", "libc-bin", inst="2.36-9", fix="2.36-9+deb12u3"),
        raw("CVE-2024-1111", "curl"), raw("CVE-2024-2222", "zlib", fix=None),
        raw("CVE-2024-3333", "linux-libc-dev"),
    ])])  # fmt: skip
    app = AssetSpec(AssetKind.IMAGE, "registry.local/me/app", "2", containers=("app",))
    ingest_results(session, app, [ScanResult(scanner="trivy", artifact_name="app", findings=[
        raw("CVE-2024-4444", "requests", "python-pkg", "app/requirements.txt", "2.30.0", "2.32.0"),
        raw("CVE-2024-5555", "requests", "python-pkg", "app/requirements.txt", "2.30.0", "2.31.0"),
        raw("CVE-2024-6666", "openssl", inst="3.0.2", fix="3.0.7"),
    ])])  # fmt: skip
    host = AssetSpec(AssetKind.HOST, "nas")
    ingest_results(session, host, [ScanResult(scanner="trivy", artifact_name="nas", os_family="ubuntu", findings=[
        raw("CVE-2024-7777", "linux-image-generic"), raw("CVE-2024-8888", "sudo"),
    ])])  # fmt: skip
    for cve, epss, kev in [("CVE-2023-4911", 0.7, True), ("CVE-2024-1111", 0.3, False),
                           ("CVE-2024-4444", 0.02, False), ("CVE-2024-8888", 0.5, False)]:  # fmt: skip
        intel = session.get(CveIntel, cve) or CveIntel(cve_id=cve)
        intel.epss, intel.epss_percentile, intel.in_kev = epss, 0.9, kev
        session.add(intel)
    from vulntriage.models import Asset

    for asset in session.query(Asset):
        asset.exposure_level = {"nginx": "internet", "nas": "lan"}.get(asset.name, "none")
    session.flush()


def test_score_all_and_groups(session: Session, settings: Settings) -> None:
    _seed(session)
    cfg = settings.model_copy(update={"own_image_patterns": ["registry.local/me/*"]})
    summary = score_all(session, cfg)
    assert summary.scored == 10 and summary.kev == 2
    groups = build_groups(session, cfg, assign_keys=True)
    by_kind = {g.kind: g for g in groups}

    top = groups[0]
    assert top.rank == 1 and top.kind == "image" and top.asset_ref == "nginx:1.25.1"
    assert top.kev_cves == ["CVE-2023-4911"] and top.finding_count == 4
    assert top.command == "docker pull nginx:1.25  # then redeploy: docker compose up -d"
    assert {p.package: p.fixed for p in top.packages}["libc6"] == "2.36-9+deb12u3"
    assert any("kernel packages inside a container" in n for n in top.notes)

    host = by_kind["host-os"]
    assert host.command == ("sudo apt-get update && sudo apt-get install --only-upgrade "
                            "linux-image-generic sudo")  # fmt: skip
    assert any("reboot" in n for n in host.notes)

    pkg = next(g for g in groups if g.kind == "pkg")
    assert pkg.title.startswith(
        "Upgrade requests 2.30.0 -> 2.32.0 in registry.local/me/app:2 (2 findings)"
    )
    assert pkg.command == "pip install --upgrade 'requests>=2.32.0'"
    assert (
        by_kind["rebuild"].command == "docker build --pull --no-cache -t registry.local/me/app:2 ."
    )
    nofix = by_kind["nofix"]
    assert nofix.fixable is False and nofix.command is None and "No fix available" in nofix.title

    assert [g.rank for g in groups] == list(range(1, len(groups) + 1))
    assert [g.max_score for g in groups] == sorted((g.max_score for g in groups), reverse=True)
    keys = {f.remediation_key for f in session.query(Finding)}
    assert keys == {g.key for g in groups}
    assert top.as_dict()["finding_count"] == 4 and "finding_ids" not in top.as_dict()


def test_cli_score_groups_explain(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    import vulntriage.cli as cli
    from vulntriage.db import get_engine, init_db, session_scope

    engine = get_engine(settings.database_url)
    init_db(engine)
    with session_scope(engine) as s:
        _seed(s)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    runner = CliRunner(env={"COLUMNS": "250"})
    out = runner.invoke(cli.app, ["score"])
    assert out.exit_code == 0, out.output
    assert "scored 10 open findings" in out.output and "2 KEV-listed" in out.output
    out = runner.invoke(cli.app, ["groups", "--limit", "3"])
    assert "Update image nginx:1.25.1" in out.output
    with session_scope(engine) as s:
        fid = s.query(Finding).filter_by(package_name="libc6").one().id
    out = runner.invoke(cli.app, ["explain", str(fid)])
    assert "CISA KEV: known exploited in the wild" in out.output
    assert runner.invoke(cli.app, ["explain", "99999"]).exit_code == 1

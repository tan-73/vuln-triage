"""Trivy/Grype parsing and runner behaviour, using stored scanner JSON fixtures."""

from __future__ import annotations

import json
import subprocess

import pytest

from tests.conftest import FIXTURES, load_fixture
from vulntriage.scanners.base import ScanError, normalise_severity, normalise_target
from vulntriage.scanners.grype import GrypeRunner, parse_grype_report
from vulntriage.scanners.trivy import TrivyRunner, _pick_cvss, parse_trivy_report


def _completed(
    stdout: str = "", returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_parse_trivy_alpine_image_with_go_binaries() -> None:
    result = parse_trivy_report(load_fixture("trivy/grafana_grafana_8.3.0.json"))
    assert result.scanner == "trivy"
    assert result.artifact_name == "grafana/grafana:8.3.0"
    assert result.os_family == "alpine"
    assert result.digest and result.digest.startswith("sha256:")

    traversal = [f for f in result.findings if f.vuln_id == "CVE-2021-43798"]
    assert {f.target for f in traversal} == {
        "usr/share/grafana/bin/grafana-server",
        "usr/share/grafana/bin/grafana-cli",
    }
    assert all(f.package_type == "gobinary" for f in traversal)

    os_findings = [f for f in result.findings if f.package_type == "alpine"]
    assert os_findings and all(f.target == "os" for f in os_findings)
    assert all(
        f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} for f in result.findings
    )


def test_parse_trivy_debian_image_counts_match_raw() -> None:
    raw = load_fixture("trivy/postgres_13.2.json")
    expected = sum(len(r.get("Vulnerabilities") or []) for r in raw["Results"])
    result = parse_trivy_report(raw)
    assert len(result.findings) == expected > 50
    assert result.os_family == "debian"


def test_pick_cvss_prefers_nvd_and_skips_empty() -> None:
    cvss = {
        "ghsa": {"V3Score": 5.0, "V3Vector": "ghsa-vec"},
        "nvd": {"V3Score": 9.8, "V3Vector": "nvd-vec"},
    }
    assert _pick_cvss(cvss) == (9.8, "nvd-vec")
    assert _pick_cvss({"redhat": {"V2Score": 5.0}}) == (None, None)
    assert _pick_cvss(None) == (None, None)


def test_parse_trivy_report_without_results() -> None:
    result = parse_trivy_report({"ArtifactName": "scratch:latest", "Metadata": {}})
    assert result.findings == []
    assert result.digest is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("critical", "CRITICAL"), ("Negligible", "LOW"), ("bogus", "UNKNOWN"), (None, "UNKNOWN")],
)
def test_normalise_severity(raw: str | None, expected: str) -> None:
    assert normalise_severity(raw) == expected


def test_normalise_target() -> None:
    assert normalise_target("debian", "/var/lib/dpkg/status") == "os"
    assert normalise_target("python-pkg", "/usr/lib/x/METADATA") == "usr/lib/x/METADATA"
    assert normalise_target("gobinary", None) == "os"


def test_trivy_runner_builds_command_and_parses() -> None:
    calls: list[list[str]] = []
    payload = (FIXTURES / "trivy/redis_6.2.6.json").read_text()

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        assert kwargs["timeout"] == 42
        return _completed(payload)

    runner = TrivyRunner("trivy", timeout=42, extra_args=["--skip-db-update"], runner=fake_run)
    result = runner.scan("image", "redis:6.2.6")
    assert calls == [
        ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln",
         "--skip-db-update", "redis:6.2.6"]
    ]  # fmt: skip
    assert result.artifact_name == "redis:6.2.6"
    assert result.findings


@pytest.mark.parametrize(
    ("behaviour", "message"),
    [
        (lambda *a, **k: _completed("", 1, "FATAL boom"), "exited 1: FATAL boom"),
        (lambda *a, **k: _completed("not json"), "invalid JSON"),
    ],
)
def test_trivy_runner_errors(behaviour, message: str) -> None:
    with pytest.raises(ScanError, match=message):
        TrivyRunner(runner=behaviour).scan("image", "x")


def test_trivy_runner_timeout_and_missing_binary() -> None:
    def timeout(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="trivy", timeout=1)

    def missing(*_a, **_k):
        raise FileNotFoundError("trivy")

    with pytest.raises(ScanError, match="timed out"):
        TrivyRunner(runner=timeout).scan("image", "x")
    with pytest.raises(ScanError, match="not found"):
        TrivyRunner(runner=missing).scan("image", "x")


def test_parse_grype_maps_ghsa_to_cve_and_fix_state() -> None:
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "severity": "High",
                    "fix": {"versions": ["2.0.1"], "state": "fixed"},
                    "cvss": [],
                },
                "relatedVulnerabilities": [
                    {
                        "id": "CVE-2024-0001",
                        "description": "desc",
                        "cvss": [
                            {"version": "3.1", "type": "Primary", "source": "nvd@nist.gov",
                             "vector": "CVSS:3.1/AV:N", "metrics": {"baseScore": 8.1}}
                        ],
                    }
                ],
                "artifact": {"name": "lib", "version": "2.0.0", "type": "python",
                             "locations": [{"path": "/app/requirements.txt"}]},
            },
            {
                "vulnerability": {"id": "CVE-2024-0002", "severity": "Negligible",
                                  "fix": {"versions": [], "state": "wont-fix"}},
                "artifact": {"name": "libc6", "version": "2.31", "type": "deb",
                             "locations": [{"path": "/var/lib/dpkg/status"}]},
            },
        ],
        "source": {"target": {"userInput": "app:1", "repoDigests": ["app@sha256:abc"]}},
        "distro": {"name": "debian", "version": "11"},
    }  # fmt: skip
    result = parse_grype_report(data)
    first, second = result.findings
    assert first.vuln_id == "CVE-2024-0001"
    assert (first.cvss_score, first.fixed_version, first.target) == (
        8.1,
        "2.0.1",
        "app/requirements.txt",
    )
    assert first.severity == "HIGH"
    assert second.fixed_version is None and second.severity == "LOW" and second.target == "os"
    assert result.digest == "sha256:abc"


def test_parse_grype_fixture() -> None:
    result = parse_grype_report(load_fixture("grype/redis_6.2.6.json"))
    assert result.scanner == "grype"
    assert result.os_family == "debian"
    assert len(result.findings) > 20
    assert all(f.scanner == "grype" for f in result.findings)


def test_grype_runner_uses_docker_source() -> None:
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **_k: object) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        return _completed(json.dumps({"matches": []}))

    GrypeRunner(runner=fake_run).scan("image", "redis:6.2.6")
    GrypeRunner(runner=fake_run).scan("fs", "/srv/app")
    assert seen[0][1] == "docker:redis:6.2.6"
    assert seen[1][1] == "dir:/srv/app"

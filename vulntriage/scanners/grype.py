"""Optional second scanner: Grype (``grype <source> -o json``)."""

from __future__ import annotations

import subprocess
from typing import Any

from vulntriage.scanners.base import (
    RawFinding,
    Runner,
    ScanResult,
    normalise_severity,
    normalise_target,
    run_json_command,
)


def _best_cvss(entries: list[dict[str, Any]]) -> tuple[float | None, str | None]:
    """Prefer a v3.x primary (NVD) score; fall back to any v3.x score."""
    v3 = [e for e in entries or [] if str(e.get("version", "")).startswith("3")]
    v3.sort(key=lambda e: (e.get("type") != "Primary", "nvd" not in str(e.get("source", ""))))
    for entry in v3:
        score = (entry.get("metrics") or {}).get("baseScore")
        if score is not None:
            return float(score), entry.get("vector")
    return None, None


def parse_grype_report(data: dict[str, Any]) -> ScanResult:
    """Convert Grype JSON into a :class:`ScanResult`.

    GHSA-only matches are reported under their CVE alias when Grype lists one in
    ``relatedVulnerabilities`` so they deduplicate against Trivy's CVE-keyed findings.
    """
    findings: list[RawFinding] = []
    for match in data.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        related = match.get("relatedVulnerabilities") or []
        vuln_id = vuln.get("id", "")
        intel = vuln
        if not vuln_id.startswith("CVE-"):
            cve = next((r for r in related if str(r.get("id", "")).startswith("CVE-")), None)
            if cve:
                vuln_id, intel = cve["id"], {**vuln, **{k: v for k, v in cve.items() if v}}
        score, vector = _best_cvss(intel.get("cvss") or vuln.get("cvss") or [])
        fix = vuln.get("fix") or {}
        fixed = ", ".join(fix.get("versions") or []) or None
        pkg_type = artifact.get("type", "")
        locations = artifact.get("locations") or []
        path = locations[0].get("path") if locations else None
        findings.append(
            RawFinding(
                vuln_id=vuln_id,
                package_name=artifact.get("name", ""),
                package_type=pkg_type,
                target=normalise_target(pkg_type, path),
                installed_version=artifact.get("version", ""),
                fixed_version=fixed if fix.get("state") == "fixed" else None,
                severity=normalise_severity(vuln.get("severity")),
                description=intel.get("description"),
                cvss_score=score,
                cvss_vector=vector,
                scanner="grype",
            )
        )
    source = data.get("source") or {}
    target = source.get("target") or {}
    distro = data.get("distro") or {}
    repo_digests = target.get("repoDigests") or [] if isinstance(target, dict) else []
    return ScanResult(
        scanner="grype",
        artifact_name=target.get("userInput", "") if isinstance(target, dict) else str(target),
        digest=repo_digests[0].split("@", 1)[-1] if repo_digests else None,
        os_family=distro.get("name"),
        os_name=distro.get("version"),
        findings=findings,
    )


class GrypeRunner:
    """Invoke the Grype CLI."""

    name = "grype"

    def __init__(
        self, binary: str = "grype", timeout: int = 900, runner: Runner = subprocess.run
    ) -> None:
        self.binary = binary
        self.timeout = timeout
        self._runner = runner

    def scan(self, mode: str, target: str) -> ScanResult:
        """Scan an image (``mode='image'``, via the Docker daemon) or a directory."""
        source = f"docker:{target}" if mode == "image" else f"dir:{target}"
        cmd = [self.binary, source, "-o", "json", "-q"]
        return parse_grype_report(run_json_command(cmd, self.timeout, self._runner))

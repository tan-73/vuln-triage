"""Trivy runner and JSON parser (``trivy image|rootfs|fs --format json``)."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from typing import Any

from vulntriage.scanners.base import (
    RawFinding,
    Runner,
    ScanResult,
    normalise_severity,
    normalise_target,
    run_json_command,
)

#: CVSS sources in order of preference when Trivy reports several.
CVSS_SOURCE_PREFERENCE = ("nvd", "ghsa", "redhat", "bitnami")


def _pick_cvss(cvss: dict[str, Any] | None) -> tuple[float | None, str | None]:
    """Choose one CVSS v3 score/vector, preferring NVD."""
    if not cvss:
        return None, None
    ordered = [s for s in CVSS_SOURCE_PREFERENCE if s in cvss] + sorted(
        s for s in cvss if s not in CVSS_SOURCE_PREFERENCE
    )
    for source in ordered:
        entry = cvss[source] or {}
        if entry.get("V3Score") is not None:
            return float(entry["V3Score"]), entry.get("V3Vector")
    return None, None


def _clean_fixed(value: str | None) -> str | None:
    """Trivy may list several fixed versions (``"1.2.3, 1.3.1"``); keep them, trimmed."""
    if not value:
        return None
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return ", ".join(parts) or None


def parse_trivy_report(data: dict[str, Any]) -> ScanResult:
    """Convert a Trivy JSON report (schema v2) into a :class:`ScanResult`."""
    metadata = data.get("Metadata") or {}
    os_info = metadata.get("OS") or {}
    repo_digests = metadata.get("RepoDigests") or []
    digest = repo_digests[0].split("@", 1)[-1] if repo_digests else metadata.get("ImageID")

    findings: list[RawFinding] = []
    for result in data.get("Results") or []:
        pkg_type = result.get("Type", "")
        is_os = result.get("Class") == "os-pkgs"
        for vuln in result.get("Vulnerabilities") or []:
            score, vector = _pick_cvss(vuln.get("CVSS"))
            cwes = vuln.get("CweIDs") or []
            path = None if is_os else (vuln.get("PkgPath") or result.get("Target"))
            findings.append(
                RawFinding(
                    vuln_id=vuln["VulnerabilityID"],
                    package_name=vuln.get("PkgName", ""),
                    package_type=pkg_type,
                    target=normalise_target(pkg_type, path),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=_clean_fixed(vuln.get("FixedVersion")),
                    severity=normalise_severity(vuln.get("Severity")),
                    title=vuln.get("Title"),
                    description=vuln.get("Description"),
                    cvss_score=score,
                    cvss_vector=vector,
                    cwe=cwes[0] if cwes else None,
                    scanner="trivy",
                )
            )
    return ScanResult(
        scanner="trivy",
        artifact_name=data.get("ArtifactName", ""),
        digest=digest,
        os_family=os_info.get("Family"),
        os_name=os_info.get("Name"),
        findings=findings,
    )


class TrivyRunner:
    """Invoke the Trivy CLI. The binary reads ``DOCKER_HOST`` from the environment."""

    name = "trivy"

    def __init__(
        self,
        binary: str = "trivy",
        timeout: int = 900,
        extra_args: Sequence[str] = (),
        runner: Runner = subprocess.run,
    ) -> None:
        self.binary = binary
        self.timeout = timeout
        self.extra_args = list(extra_args)
        self._runner = runner

    def _cmd(self, mode: str, target: str) -> list[str]:
        if mode not in ("image", "rootfs", "fs"):
            raise ValueError(f"unsupported trivy mode: {mode!r}")
        return [
            self.binary,
            mode,
            "--quiet",
            "--format",
            "json",
            "--scanners",
            "vuln",
            *self.extra_args,
            target,
        ]

    def scan(self, mode: str, target: str) -> ScanResult:
        """Scan ``target`` (``mode`` is ``image``, ``rootfs`` or ``fs``) and parse findings."""
        raw = run_json_command(self._cmd(mode, target), self.timeout, self._runner)
        return parse_trivy_report(raw)

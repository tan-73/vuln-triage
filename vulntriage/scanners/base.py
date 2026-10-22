"""Scanner-neutral data types and the subprocess helper shared by Trivy and Grype."""

from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Callable, Sequence
from typing import Any

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

#: Signature of :func:`subprocess.run`, injectable for tests.
Runner = Callable[..., "subprocess.CompletedProcess[str]"]

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

#: Package types that are operating-system packages (normalised target ``os``).
OS_PACKAGE_TYPES = frozenset(
    {
        "alpine", "debian", "ubuntu", "redhat", "centos", "rocky", "alma", "amazon",
        "oracle", "photon", "suse", "opensuse", "wolfi", "chainguard", "azurelinux",
        "cbl-mariner", "fedora", "deb", "rpm", "apk",
    }
)  # fmt: skip


class RawFinding(BaseModel):
    """One vulnerability match as reported by a scanner, before deduplication."""

    vuln_id: str
    package_name: str
    package_type: str = ""
    target: str = "os"
    installed_version: str = ""
    fixed_version: str | None = None
    severity: str = "UNKNOWN"
    title: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    scanner: str = "trivy"

    @property
    def key(self) -> tuple[str, str, str]:
        """Deduplication key within one asset."""
        return (self.vuln_id, self.package_name, self.target)


class ScanResult(BaseModel):
    """Parsed output of one scanner run against one artifact."""

    scanner: str
    artifact_name: str
    digest: str | None = None
    os_family: str | None = None
    os_name: str | None = None
    findings: list[RawFinding] = Field(default_factory=list)


class ScanError(RuntimeError):
    """A scanner failed or produced unparsable output."""


def normalise_severity(value: str | None) -> str:
    """Map scanner severity strings onto CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN."""
    sev = (value or "").strip().upper()
    if sev == "NEGLIGIBLE":
        return "LOW"
    return sev if sev in SEVERITIES else "UNKNOWN"


def normalise_target(package_type: str, path: str | None) -> str:
    """OS packages share one target (``os``); language packages keep their file path."""
    if package_type.lower() in OS_PACKAGE_TYPES or not path:
        return "os"
    return path.lstrip("/")


def run_json_command(
    cmd: Sequence[str], timeout: int, runner: Runner = subprocess.run
) -> dict[str, Any]:
    """Run a scanner command and parse its stdout as JSON.

    Raises:
        ScanError: on non-zero exit, timeout, missing binary or invalid JSON.
    """
    log.debug("running %s", " ".join(cmd))
    try:
        proc = runner(list(cmd), capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise ScanError(f"scanner binary not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"scanner timed out after {timeout}s: {' '.join(cmd)}") from exc
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip().splitlines()
        raise ScanError(f"{cmd[0]} exited {proc.returncode}: {stderr[-1] if stderr else ''}")
    try:
        data: dict[str, Any] = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScanError(f"{cmd[0]} produced invalid JSON") from exc
    return data

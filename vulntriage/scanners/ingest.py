"""Persist scan results: upsert assets, deduplicate findings across runs, resolve fixed ones."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulntriage.models import Asset, AssetKind, CveIntel, Finding, FindingStatus, utcnow
from vulntriage.scanners.base import RawFinding, ScanResult

log = logging.getLogger(__name__)

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


@dataclass(frozen=True)
class AssetSpec:
    """Identity and context of something about to be scanned."""

    kind: AssetKind
    name: str
    tag: str = ""
    scan_target: str = ""
    containers: tuple[str, ...] = ()


@dataclass
class IngestStats:
    """Counts produced by one :func:`ingest_results` call."""

    total: int = 0
    new: int = 0
    reopened: int = 0
    resolved: int = 0


def parse_image_ref(ref: str) -> tuple[str, str]:
    """Split an image reference into ``(name, tag_or_digest)``.

    >>> parse_image_ref("ghcr.io/org/app:v1.2")
    ('ghcr.io/org/app', 'v1.2')
    >>> parse_image_ref("localhost:5000/app")
    ('localhost:5000/app', 'latest')
    >>> parse_image_ref("nginx@sha256:abc")
    ('nginx', 'sha256:abc')
    """
    if "@" in ref:
        name, digest = ref.split("@", 1)
        return name, digest
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
        return name, tag
    return ref, "latest"


def merge_raw_findings(results: Iterable[ScanResult]) -> dict[tuple[str, str, str], RawFinding]:
    """Merge findings from several scanners; the same key keeps the richest data.

    The first scanner's record wins for each field; later scanners fill gaps, and the
    ``scanner`` field becomes a comma-separated list (``trivy,grype``).
    """
    merged: dict[tuple[str, str, str], RawFinding] = {}
    for result in results:
        for raw in result.findings:
            existing = merged.get(raw.key)
            if existing is None:
                merged[raw.key] = raw.model_copy()
                continue
            updates = {
                field: value
                for field, value in raw.model_dump().items()
                if getattr(existing, field) in (None, "", "UNKNOWN") and value not in (None, "")
            }
            scanners = sorted(set(existing.scanner.split(",")) | {raw.scanner})
            updates["scanner"] = ",".join(scanners)
            if SEVERITY_RANK[raw.severity] > SEVERITY_RANK[existing.severity]:
                updates["severity"] = raw.severity
            merged[raw.key] = existing.model_copy(update=updates)
    return merged


def upsert_asset(session: Session, spec: AssetSpec, now: datetime | None = None) -> Asset:
    """Find or create the asset for ``spec`` and mark it active."""
    asset = session.scalar(
        select(Asset).where(Asset.kind == spec.kind, Asset.name == spec.name, Asset.tag == spec.tag)
    )
    if asset is None:
        asset = Asset(kind=spec.kind, name=spec.name, tag=spec.tag, first_seen=now or utcnow())
        session.add(asset)
    asset.active = True
    if spec.containers:
        asset.containers = sorted(spec.containers)
    session.flush()
    return asset


def _upsert_scanner_intel(session: Session, raw: RawFinding, now: datetime) -> None:
    """Seed :class:`CveIntel` with scanner-supplied CVSS/CWE/description (NVD wins later)."""
    if not raw.vuln_id.startswith("CVE-"):
        return
    intel = session.get(CveIntel, raw.vuln_id)
    if intel is None:
        intel = CveIntel(cve_id=raw.vuln_id, fetched_at=now)
        session.add(intel)
    if intel.cvss_source != "nvd":
        if raw.cvss_score is not None:
            intel.cvss_score = raw.cvss_score
            intel.cvss_vector = raw.cvss_vector
            intel.cvss_source = "scanner"
        intel.cwe = intel.cwe or raw.cwe
        intel.description = intel.description or raw.description


def ingest_results(
    session: Session,
    spec: AssetSpec,
    results: list[ScanResult],
    now: datetime | None = None,
) -> tuple[Asset, IngestStats]:
    """Write merged scanner results for one asset.

    * new keys become ``open`` findings with ``first_seen = now``;
    * keys seen before refresh ``last_seen`` (and are re-opened if they had been resolved);
    * open findings of this asset that were not reported this time are ``resolved``.
    """
    now = now or utcnow()
    asset = upsert_asset(session, spec, now)
    asset.last_scanned = now
    for result in results:
        asset.digest = result.digest or asset.digest
        asset.os_family = result.os_family or asset.os_family
        asset.os_name = result.os_name or asset.os_name

    merged = merge_raw_findings(results)
    existing = {
        (f.cve_id, f.package_name, f.target): f
        for f in session.scalars(select(Finding).where(Finding.asset_id == asset.id))
    }
    stats = IngestStats(total=len(merged))
    seen_intel: set[str] = set()
    for key, raw in merged.items():
        finding = existing.get(key)
        if finding is None:
            finding = Finding(
                asset_id=asset.id,
                cve_id=raw.vuln_id,
                package_name=raw.package_name,
                target=raw.target,
                first_seen=now,
                status=FindingStatus.OPEN,
            )
            session.add(finding)
            stats.new += 1
        elif finding.status == FindingStatus.RESOLVED:
            finding.status = FindingStatus.OPEN
            finding.resolved_at = None
            finding.resolution_reason = None
            stats.reopened += 1
        finding.package_type = raw.package_type
        finding.installed_version = raw.installed_version
        if raw.fixed_version or finding.fixed_version_source != "osv":
            finding.fixed_version = raw.fixed_version
            finding.fixed_version_source = "scanner" if raw.fixed_version else None
        finding.severity = raw.severity
        finding.title = raw.title
        finding.scanner = raw.scanner
        finding.last_seen = now
        if raw.vuln_id not in seen_intel:
            _upsert_scanner_intel(session, raw, now)
            seen_intel.add(raw.vuln_id)

    for key, finding in existing.items():
        if key not in merged and finding.status == FindingStatus.OPEN:
            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now
            finding.resolution_reason = "not_detected"
            stats.resolved += 1
    session.flush()
    log.info(
        "%s: %d findings (%d new, %d reopened, %d resolved)",
        asset.ref, stats.total, stats.new, stats.reopened, stats.resolved,
    )  # fmt: skip
    return asset, stats


def retire_missing_assets(
    session: Session, kind: AssetKind, seen_ids: set[int], now: datetime | None = None
) -> int:
    """Deactivate assets of ``kind`` not seen in a full scan and resolve their findings.

    Returns the number of findings resolved.
    """
    now = now or utcnow()
    resolved = 0
    for asset in session.scalars(select(Asset).where(Asset.kind == kind, Asset.active)):
        if asset.id in seen_ids:
            continue
        asset.active = False
        for finding in asset.findings:
            if finding.status == FindingStatus.OPEN:
                finding.status = FindingStatus.RESOLVED
                finding.resolved_at = now
                finding.resolution_reason = "asset_removed"
                resolved += 1
    session.flush()
    return resolved

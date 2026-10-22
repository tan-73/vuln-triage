"""Scan orchestration: discover targets, run scanners, ingest results."""

from __future__ import annotations

import fnmatch
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol

from sqlalchemy.orm import Session

from vulntriage.models import AssetKind, utcnow
from vulntriage.scanners.base import ScanError, ScanResult
from vulntriage.scanners.docker_api import ContainerInfo, DockerClient
from vulntriage.scanners.grype import parse_grype_report
from vulntriage.scanners.ingest import (
    AssetSpec,
    ingest_results,
    parse_image_ref,
    retire_missing_assets,
)
from vulntriage.scanners.trivy import parse_trivy_report

log = logging.getLogger(__name__)

_IMAGE_ID = re.compile(r"^(sha256:)?[0-9a-f]{12,64}$")


class Scanner(Protocol):
    """Anything that can scan a target and return parsed results."""

    name: str

    def scan(self, mode: str, target: str) -> ScanResult:
        """Scan ``target``; ``mode`` is ``image``, ``rootfs`` or ``fs``."""
        ...


class FixtureScanner:
    """Replays stored scanner JSON instead of running a binary (tests and demo mode).

    ``files`` maps a scan target (image ref or path) to a JSON report on disk.
    """

    def __init__(self, name: str, files: dict[str, Path]) -> None:
        self.name = name
        self.files = files

    def scan(self, mode: str, target: str) -> ScanResult:
        """Parse the fixture registered for ``target``."""
        path = self.files.get(target)
        if path is None:
            raise ScanError(f"no {self.name} fixture for {target!r}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return parse_grype_report(data) if self.name == "grype" else parse_trivy_report(data)


@dataclass
class ScanSummary:
    """Aggregate result of :func:`run_scan`."""

    assets_scanned: int = 0
    findings_total: int = 0
    findings_new: int = 0
    findings_resolved: int = 0
    errors: list[str] = field(default_factory=list)


def discover_image_targets(
    containers: list[ContainerInfo],
    exclude: list[str] | None = None,
    docker: DockerClient | None = None,
) -> list[AssetSpec]:
    """Collapse running containers into one :class:`AssetSpec` per image reference."""
    by_ref: dict[str, list[str]] = defaultdict(list)
    for c in containers:
        ref = c.image
        if _IMAGE_ID.match(ref) and docker is not None:
            tags = docker.inspect_image(ref).get("RepoTags") or []
            ref = tags[0] if tags else ref
        by_ref[ref].append(c.name)

    specs: list[AssetSpec] = []
    for ref, names in sorted(by_ref.items()):
        if any(fnmatch.fnmatch(ref, pat) for pat in exclude or []):
            log.info("skipping excluded image %s", ref)
            continue
        if _IMAGE_ID.match(ref):
            name, tag = f"untagged/{names[0]}", ref.removeprefix("sha256:")[:12]
        else:
            name, tag = parse_image_ref(ref)
        specs.append(
            AssetSpec(AssetKind.IMAGE, name, tag, scan_target=ref, containers=tuple(names))
        )
    return specs


def path_targets(pairs: list[tuple[str, str]], kind: AssetKind) -> list[AssetSpec]:
    """Build host (``rootfs``) or directory (``fs``) specs from ``name=/path`` pairs."""
    return [AssetSpec(kind, name, "", scan_target=path) for name, path in pairs]


_MODE = {AssetKind.IMAGE: "image", AssetKind.HOST: "rootfs", AssetKind.FS: "fs"}


def scan_specs(
    session: Session,
    specs: list[AssetSpec],
    scanners: list[Scanner],
    retire_missing: bool = True,
    now: datetime | None = None,
) -> ScanSummary:
    """Scan every spec with every scanner and ingest the merged results.

    A spec for which *all* scanners fail is skipped without touching its stored findings,
    so a transient scanner error never marks real vulnerabilities as resolved. When
    ``retire_missing`` is set (a full scan), assets of the scanned kinds that no longer
    exist are deactivated.
    """
    now = now or utcnow()
    summary = ScanSummary()
    seen: dict[AssetKind, set[int]] = defaultdict(set)
    failed_kinds: set[AssetKind] = set()
    for spec in specs:
        results: list[ScanResult] = []
        for scanner in scanners:
            if scanner.name == "grype" and spec.kind == AssetKind.HOST:
                continue  # grype has no rootfs mode equivalent to trivy's
            try:
                results.append(scanner.scan(_MODE[spec.kind], spec.scan_target))
            except ScanError as exc:
                msg = f"{scanner.name} failed on {spec.scan_target}: {exc}"
                log.warning(msg)
                summary.errors.append(msg)
        if not results:
            failed_kinds.add(spec.kind)
            continue
        asset, stats = ingest_results(session, spec, results, now)
        seen[spec.kind].add(asset.id)
        summary.assets_scanned += 1
        summary.findings_total += stats.total
        summary.findings_new += stats.new + stats.reopened
        summary.findings_resolved += stats.resolved

    if retire_missing:
        for kind in {s.kind for s in specs} | {AssetKind.IMAGE}:
            if kind in failed_kinds:
                continue  # an unscanned asset is not a removed asset
            summary.findings_resolved += retire_missing_assets(session, kind, seen[kind], now)
    return summary

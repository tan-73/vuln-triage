"""Pipeline stages and the end-to-end nightly run.

Each stage is a plain function that takes a session and settings, so the CLI, the
scheduler and the demo all share one code path. :class:`StageTimer` records per-stage
wall-clock time onto the :class:`~vulntriage.models.ScanRun`.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.orm import Session

from vulntriage.config import Settings
from vulntriage.exposure.analyze import ExposureSummary, apply_exposure
from vulntriage.exposure.guard import ScanScopeGuard
from vulntriage.exposure.nmap import NmapResult, run_nmap
from vulntriage.exposure.proxies import load_routes
from vulntriage.models import AssetKind, ScanRun, utcnow
from vulntriage.remediation import RemediationGroup, build_groups
from vulntriage.scanners.base import Runner
from vulntriage.scanners.docker_api import ContainerInfo, DockerClient
from vulntriage.scanners.grype import GrypeRunner
from vulntriage.scanners.ingest import AssetSpec, parse_image_ref
from vulntriage.scanners.service import (
    Scanner,
    ScanSummary,
    discover_image_targets,
    path_targets,
    scan_specs,
)
from vulntriage.scanners.trivy import TrivyRunner
from vulntriage.scoring import ScoringSummary, score_all

log = logging.getLogger(__name__)


class StageTimer:
    """Collects ``{stage: seconds}`` for one run."""

    def __init__(self, run: ScanRun) -> None:
        self.run = run

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        """Time the enclosed block and store it under ``name``."""
        start = time.perf_counter()
        try:
            yield
        finally:
            timings = dict(self.run.stage_timings or {})
            timings[name] = round(time.perf_counter() - start, 3)
            self.run.stage_timings = timings  # reassign so SQLAlchemy sees the change


def build_scanners(settings: Settings) -> list[Scanner]:
    """Trivy always; Grype when ``ENABLE_GRYPE`` is set."""
    os.environ.setdefault("DOCKER_HOST", settings.docker_host)
    timeout = settings.scan_timeout_seconds
    scanners: list[Scanner] = [TrivyRunner(settings.trivy_bin, timeout, settings.trivy_extra_args)]
    if settings.enable_grype:
        scanners.append(GrypeRunner(settings.grype_bin, timeout))
    return scanners


def collect_specs(
    settings: Settings, docker: DockerClient | None, images: list[str] | None = None
) -> tuple[list[AssetSpec], bool]:
    """Work out what to scan.

    Returns ``(specs, full_scan)``. ``full_scan`` is False when explicit images were given
    or container discovery failed; in that case missing assets must not be retired.
    """
    specs: list[AssetSpec] = []
    if images:
        for ref in images:
            name, tag = parse_image_ref(ref)
            specs.append(AssetSpec(AssetKind.IMAGE, name, tag, scan_target=ref))
        return specs, False
    full = True
    if docker is not None:
        try:
            specs = discover_image_targets(
                docker.list_containers(), settings.exclude_images, docker
            )
        except Exception as exc:  # any discovery failure must disable retiring
            log.error("container discovery failed: %s", exc)
            full = False
    specs += path_targets(settings.parsed_targets("host_scan_targets"), AssetKind.HOST)
    specs += path_targets(settings.parsed_targets("fs_scan_targets"), AssetKind.FS)
    return specs, full


def run_scan_stage(
    session: Session,
    settings: Settings,
    run: ScanRun,
    scanners: list[Scanner] | None = None,
    docker: DockerClient | None = None,
    images: list[str] | None = None,
    specs: list[AssetSpec] | None = None,
) -> ScanSummary:
    """Discover targets, scan them and update the run's counters."""
    if specs is None:
        specs, full = collect_specs(settings, docker, images)
    else:
        full = True
    summary = scan_specs(session, specs, scanners or build_scanners(settings), retire_missing=full)
    run.assets_scanned = summary.assets_scanned
    run.findings_total = summary.findings_total
    run.findings_new = summary.findings_new
    run.findings_resolved = summary.findings_resolved
    run.errors = [*run.errors, *summary.errors]
    return summary


def run_exposure_stage(
    session: Session,
    settings: Settings,
    run: ScanRun,
    docker: DockerClient | None = None,
    containers: list[ContainerInfo] | None = None,
    nmap_runner: Runner = subprocess.run,
) -> ExposureSummary | None:
    """Work out how reachable each asset is and store it on the asset.

    Returns ``None`` (leaving the previous exposure in place) if containers cannot be
    listed, because an empty container list would wrongly downgrade every asset.
    """
    if containers is None:
        try:
            containers = docker.list_containers() if docker is not None else []
        except Exception as exc:  # any failure: keep last known exposure
            run.errors = [*run.errors, f"exposure: container listing failed: {exc}"]
            return None
    routes, errors = load_routes(
        settings.parsed_targets("nginx_config_paths"),
        settings.parsed_targets("caddy_config_paths"),
        containers,
        settings.traefik_labels,
    )
    nmap: NmapResult | None = None
    if settings.nmap_enabled and settings.nmap_targets:
        guard = ScanScopeGuard(settings.allowed_scan_cidrs)
        nmap = run_nmap(
            settings.nmap_targets,
            guard,
            settings.nmap_bin,
            settings.nmap_top_ports,
            runner=nmap_runner,
        )
        errors += nmap.refused + nmap.errors
    summary = apply_exposure(session, settings, containers, routes, nmap)
    summary.errors = errors
    run.errors = [*run.errors, *errors]
    return summary


def run_score_stage(
    session: Session, settings: Settings
) -> tuple[ScoringSummary, list[RemediationGroup]]:
    """Score every open finding, then assign and rank remediation groups."""
    summary = score_all(session, settings)
    groups = build_groups(session, settings, assign_keys=True)
    return summary, groups


def start_run(session: Session, trigger: str) -> ScanRun:
    """Create and flush a new :class:`ScanRun`."""
    run = ScanRun(trigger=trigger, started_at=utcnow(), stage_timings={}, errors=[])
    session.add(run)
    session.flush()
    return run


def finish_run(run: ScanRun) -> None:
    """Mark ``run`` finished; ``partial`` if any stage recorded errors."""
    run.finished_at = utcnow()
    run.status = "partial" if run.errors else "ok"

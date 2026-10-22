"""Pipeline stages and the end-to-end nightly run.

Each stage is a plain function that takes a session and settings, so the CLI, the
scheduler and the demo all share one code path. :class:`StageTimer` records per-stage
wall-clock time onto the :class:`~vulntriage.models.ScanRun`.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.orm import Session

from vulntriage.config import Settings
from vulntriage.models import AssetKind, ScanRun, utcnow
from vulntriage.scanners.docker_api import DockerClient
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

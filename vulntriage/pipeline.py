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
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from vulntriage.config import Settings
from vulntriage.exposure.analyze import ExposureSummary, apply_exposure
from vulntriage.exposure.guard import ScanScopeGuard
from vulntriage.exposure.nmap import NmapResult, run_nmap
from vulntriage.exposure.proxies import load_routes
from vulntriage.intel.http import FeedClient, RateLimiter
from vulntriage.llm.base import LLMProvider
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
    now: datetime | None = None,
) -> ScanSummary:
    """Discover targets, scan them and update the run's counters."""
    if specs is None:
        specs, full = collect_specs(settings, docker, images)
    else:
        full = True
    summary = scan_specs(
        session, specs, scanners or build_scanners(settings), retire_missing=full, now=now
    )
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
    now: datetime | None = None,
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
    summary = apply_exposure(session, settings, containers, routes, nmap, now)
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


def start_run(session: Session, trigger: str, now: datetime | None = None) -> ScanRun:
    """Create and flush a new :class:`ScanRun`."""
    run = ScanRun(trigger=trigger, started_at=now or utcnow(), stage_timings={}, errors=[])
    session.add(run)
    session.flush()
    return run


def finish_run(run: ScanRun, now: datetime | None = None) -> None:
    """Mark ``run`` finished; ``partial`` if any stage recorded errors."""
    run.finished_at = now or utcnow()
    run.status = "partial" if run.errors else "ok"


@dataclass
class PipelineResult:
    """Outcome of one end-to-end run."""

    run_id: int
    status: str
    report_path: Path | None = None
    grounding_rate: float | None = None
    open_findings: int = 0
    actionable_findings: int = 0
    kev_findings: int = 0
    alerts_sent: int = 0
    stage_timings: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def run_pipeline(
    engine: Engine,
    settings: Settings,
    trigger: str = "cli",
    *,
    docker: DockerClient | None = None,
    scanners: list[Scanner] | None = None,
    specs: list[AssetSpec] | None = None,
    containers: list[ContainerInfo] | None = None,
    feed_client: FeedClient | None = None,
    nvd_rate_limiter: RateLimiter | None = None,
    provider: LLMProvider | None = None,
    now: datetime | None = None,
    alerts: bool = True,
) -> PipelineResult:
    """scan -> enrich -> exposure -> score -> report -> alerts, committing after each stage.

    Every dependency can be injected (the demo replaces scanners, Docker, feeds and the
    LLM with fixtures); by default they are built from ``settings``. A stage failure is
    recorded on the run and later stages still run on whatever data exists.
    """
    from vulntriage.agent.report import generate_report, headline
    from vulntriage.alerts import dispatch_alerts
    from vulntriage.intel.cache import feed_health
    from vulntriage.intel.enrich import enrich, ttl_map
    from vulntriage.llm.factory import get_provider

    if docker is None and specs is None and containers is None:
        docker = DockerClient(settings.docker_host)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    result: PipelineResult
    try:
        run = start_run(session, trigger, now)
        session.commit()
        timer = StageTimer(run)

        def stage(name: str, fn: Callable[[], object]) -> None:
            with timer.stage(name):
                try:
                    fn()
                    session.commit()
                except Exception as exc:  # one broken stage must not kill the nightly run
                    session.rollback()
                    log.exception("stage %s failed", name)
                    run.errors = [*run.errors, f"{name}: {type(exc).__name__}: {exc}"]
                    session.add(run)
                    session.commit()

        outcome: dict[str, object] = {}
        stage(
            "scan",
            lambda: run_scan_stage(session, settings, run, scanners, docker, None, specs, now),
        )

        def _enrich() -> None:
            summary = enrich(session, settings, feed_client, now, nvd_rate_limiter)
            run.errors = [*run.errors, *summary.errors]

        stage("enrich", _enrich)
        stage(
            "exposure",
            lambda: run_exposure_stage(session, settings, run, docker, containers, now=now),
        )
        stage("score", lambda: run_score_stage(session, settings))

        def _report() -> None:
            llm = provider or get_provider(settings)
            health = feed_health(session, ttl_map(settings), now)
            out = generate_report(session, settings, llm, run, health, now)
            outcome["report"] = out
            if out.agent.error:
                run.errors = [*run.errors, f"agent: {out.agent.error}"]

        stage("report", _report)
        if alerts:

            def _alerts() -> None:
                sent = dispatch_alerts(session, settings, now)
                outcome["alerts"] = sent
                run.errors = [*run.errors, *sent.errors]

            stage("alerts", _alerts)

        head = headline(session, settings)
        run.open_findings, run.actionable_findings, run.kev_findings = (
            head.raw,
            head.actionable,
            head.kev,
        )
        finish_run(run, now)
        session.commit()
        report_out = outcome.get("report")
        alert_out = outcome.get("alerts")
        result = PipelineResult(
            run_id=run.id,
            status=run.status,
            report_path=getattr(report_out, "path", None),
            grounding_rate=getattr(getattr(report_out, "report", None), "grounding_rate", None),
            open_findings=head.raw,
            actionable_findings=head.actionable,
            kev_findings=head.kev,
            alerts_sent=len(getattr(alert_out, "items", []))
            if getattr(alert_out, "sent_via", None)
            else 0,
            stage_timings=dict(run.stage_timings),
            errors=list(run.errors),
        )
    finally:
        session.close()
    log.info(
        "pipeline run %d %s: %d open, %d need action, %d KEV; stages %s",
        result.run_id, result.status, result.open_findings, result.actionable_findings,
        result.kev_findings, result.stage_timings,
    )  # fmt: skip
    return result

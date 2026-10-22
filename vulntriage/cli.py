"""Typer command-line interface: ``vulntriage --help``."""

from __future__ import annotations

import logging
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import Engine, select

from vulntriage.config import Settings, get_settings
from vulntriage.db import get_engine, init_db, session_scope
from vulntriage.models import Asset, CveIntel, Finding, FindingStatus
from vulntriage.pipeline import StageTimer, finish_run, run_scan_stage, start_run
from vulntriage.scanners.docker_api import DockerClient

app = typer.Typer(
    help="VulnTriage: scan, enrich and rank homelab vulnerabilities by real-world risk.",
    no_args_is_help=True,
)
console = Console()


@app.callback()
def _main(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _engine(settings: Settings) -> Engine:
    engine = get_engine(settings.database_url)
    init_db(engine)
    return engine


@app.command("init-db")
def init_db_cmd() -> None:
    """Create database tables."""
    _engine(get_settings())
    console.print("[green]database ready[/green]")


@app.command()
def scan(
    image: Annotated[
        list[str] | None,
        typer.Option("--image", "-i", help="Scan only this image ref (repeatable)."),
    ] = None,
    grype: Annotated[
        bool | None, typer.Option("--grype/--no-grype", help="Override ENABLE_GRYPE.")
    ] = None,
) -> None:
    """Scan running containers' images (and configured hosts/paths) for vulnerabilities."""
    settings = get_settings()
    if grype is not None:
        settings = settings.model_copy(update={"enable_grype": grype})
    engine = _engine(settings)
    docker = None if image else DockerClient(settings.docker_host)
    with session_scope(engine) as session:
        run = start_run(session, "cli-scan")
        with StageTimer(run).stage("scan"):
            summary = run_scan_stage(session, settings, run, docker=docker, images=image)
        finish_run(run)
    console.print(
        f"scanned [bold]{summary.assets_scanned}[/bold] assets: "
        f"{summary.findings_total} findings, {summary.findings_new} new, "
        f"{summary.findings_resolved} resolved"
    )
    for err in summary.errors:
        console.print(f"[yellow]warning:[/yellow] {err}")


@app.command()
def enrich(
    offline: Annotated[
        bool, typer.Option("--offline", help="Use cached feed data only (no network).")
    ] = False,
) -> None:
    """Fetch EPSS, CISA KEV, NVD and OSV data for open findings (cached, rate-limited)."""
    from vulntriage.intel.enrich import enrich as run_enrich

    settings = get_settings()
    if offline:
        settings = settings.model_copy(update={"offline": True})
    engine = _engine(settings)
    with session_scope(engine) as session:
        run = start_run(session, "cli-enrich")
        with StageTimer(run).stage("enrich"):
            summary = run_enrich(session, settings)
        run.errors = summary.errors
        finish_run(run)
    console.print(
        f"enriched [bold]{summary.cves}[/bold] CVEs: {summary.kev_listed} in KEV, "
        f"{summary.epss_updated} EPSS updated, {summary.nvd_updated} from NVD, "
        f"{summary.osv_fixes} fix versions from OSV"
    )
    for health in summary.health.values():
        console.print(f"  {health.describe()}")
    for err in summary.errors:
        console.print(f"[yellow]warning:[/yellow] {err}")


@app.command()
def feeds() -> None:
    """Show how fresh each cached threat-intel feed is."""
    from vulntriage.intel.cache import feed_health
    from vulntriage.intel.enrich import ttl_map

    settings = get_settings()
    with session_scope(_engine(settings)) as session:
        for health in feed_health(session, ttl_map(settings)).values():
            console.print(health.describe())


@app.command("list-findings")
def list_findings(
    status: Annotated[str, typer.Option(help="open | resolved | all")] = "open",
    asset: Annotated[str | None, typer.Option(help="Filter by asset name substring.")] = None,
    severity: Annotated[str | None, typer.Option(help="Minimum severity, e.g. HIGH.")] = None,
    kev: Annotated[bool, typer.Option("--kev", help="Only KEV-listed CVEs.")] = False,
    limit: Annotated[int, typer.Option(help="Maximum rows.")] = 50,
) -> None:
    """List stored findings (highest severity first)."""
    from vulntriage.scanners.ingest import SEVERITY_RANK

    engine = _engine(get_settings())
    with session_scope(engine) as session:
        stmt = (
            select(Finding, Asset, CveIntel)
            .join(Asset, Finding.asset_id == Asset.id)
            .outerjoin(CveIntel, CveIntel.cve_id == Finding.cve_id)
        )
        if status != "all":
            stmt = stmt.where(Finding.status == FindingStatus(status))
        if asset:
            stmt = stmt.where(Asset.name.contains(asset))
        if kev:
            stmt = stmt.where(CveIntel.in_kev.is_(True))
        rows = session.execute(stmt).all()
        min_rank = SEVERITY_RANK.get((severity or "UNKNOWN").upper(), 0)
        rows = [r for r in rows if SEVERITY_RANK.get(r[0].severity, 0) >= min_rank]
        rows.sort(key=lambda r: _sort_key(r[0], r[2]), reverse=True)

        table = Table(title=f"{len(rows)} findings ({status})")
        for col in ("id", "asset", "cve", "package", "installed", "fixed", "sev", "score"):
            table.add_column(col)
        for f, a, intel in rows[:limit]:
            table.add_row(
                str(f.id),
                a.ref,
                f.cve_id + (" [red]KEV[/red]" if intel and intel.in_kev else ""),
                f.package_name,
                f.installed_version,
                f.fixed_version or "-",
                f.severity,
                f"{getattr(f, 'score', None) or 0:.1f}",
            )
        console.print(table)


def _sort_key(finding: Finding, intel: CveIntel | None) -> tuple[float, int, float]:
    from vulntriage.scanners.ingest import SEVERITY_RANK

    score = getattr(finding, "score", None) or 0.0
    cvss = intel.cvss_score if intel and intel.cvss_score is not None else 0.0
    return (score, SEVERITY_RANK.get(finding.severity, 0), cvss)


if __name__ == "__main__":  # pragma: no cover
    app()

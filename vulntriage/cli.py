"""Typer command-line interface: ``vulntriage --help``."""

from __future__ import annotations

import logging
from pathlib import Path
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


@app.command()
def exposure() -> None:
    """Compute how reachable each asset is (internet / lan / localhost / none) and show why."""
    from vulntriage.pipeline import run_exposure_stage

    settings = get_settings()
    engine = _engine(settings)
    with session_scope(engine) as session:
        run = start_run(session, "cli-exposure")
        with StageTimer(run).stage("exposure"):
            summary = run_exposure_stage(session, settings, run, DockerClient(settings.docker_host))
        finish_run(run)
        if summary is None:
            console.print("[red]container listing failed; previous exposure kept[/red]")
            raise typer.Exit(1)
        table = Table(title=f"exposure ({summary.routes} proxy routes)")
        for col in ("asset", "level", "evidence"):
            table.add_column(col)
        for asset in session.scalars(select(Asset).where(Asset.active).order_by(Asset.name)):
            table.add_row(asset.ref, asset.exposure_level, "\n".join(asset.exposure_evidence))
        console.print(table)
        for err in summary.errors:
            console.print(f"[yellow]warning:[/yellow] {err}")


@app.command("list-findings")
def list_findings(
    status: Annotated[str, typer.Option(help="open | resolved | all")] = "open",
    asset: Annotated[str | None, typer.Option(help="Filter by asset name substring.")] = None,
    severity: Annotated[str | None, typer.Option(help="Minimum severity, e.g. HIGH.")] = None,
    kev: Annotated[bool, typer.Option("--kev", help="Only KEV-listed CVEs.")] = False,
    limit: Annotated[int, typer.Option(help="Maximum rows.")] = 50,
) -> None:
    """List stored findings (highest risk score first, then severity)."""
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
                f"{f.score or 0:.1f}",
            )
        console.print(table)


def _sort_key(finding: Finding, intel: CveIntel | None) -> tuple[float, int, float]:
    from vulntriage.scanners.ingest import SEVERITY_RANK

    score = finding.score or 0.0
    cvss = intel.cvss_score if intel and intel.cvss_score is not None else 0.0
    return (score, SEVERITY_RANK.get(finding.severity, 0), cvss)


@app.command()
def score() -> None:
    """Score open findings and rank remediation groups (deterministic, no LLM)."""
    from vulntriage.pipeline import run_score_stage

    settings = get_settings()
    with session_scope(_engine(settings)) as session:
        run = start_run(session, "cli-score")
        with StageTimer(run).stage("score"):
            summary, groups = run_score_stage(session, settings)
        finish_run(run)
    console.print(
        f"scored [bold]{summary.scored}[/bold] open findings: {summary.actionable} need action "
        f"(score >= {settings.action_threshold}), {summary.kev} KEV-listed; "
        f"{len(groups)} remediation groups"
    )


@app.command()
def groups(
    limit: Annotated[int, typer.Option(help="Maximum groups to show.")] = 15,
) -> None:
    """Show remediation actions ranked by risk."""
    from vulntriage.remediation import build_groups

    settings = get_settings()
    with session_scope(_engine(settings)) as session:
        ranked = build_groups(session, settings)
    table = Table(title=f"{len(ranked)} remediation groups")
    for col in ("#", "action", "exposure", "findings", "KEV", "max score", "command"):
        table.add_column(col)
    for g in ranked[:limit]:
        table.add_row(
            str(g.rank),
            g.title,
            g.exposure,
            str(g.finding_count),
            ", ".join(g.kev_cves) or "-",
            f"{g.max_score:.1f}",
            g.command or "-",
        )
    console.print(table)


@app.command()
def explain(finding_id: Annotated[int, typer.Argument(help="Finding id.")]) -> None:
    """Show why a finding scored the way it did."""
    settings = get_settings()
    with session_scope(_engine(settings)) as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            console.print(f"[red]no finding {finding_id}[/red]")
            raise typer.Exit(1)
        console.print(
            f"[bold]{finding.cve_id}[/bold] in {finding.package_name} {finding.installed_version} "
            f"on {finding.asset.ref}: score {finding.score or 0:.2f}"
        )
        for line in (finding.score_breakdown or {}).get("text", []):
            console.print(f"  - {line}")


@app.command()
def report(
    provider: Annotated[
        str | None, typer.Option(help="Override LLM_PROVIDER (mock|anthropic|gemini|openai).")
    ] = None,
) -> None:
    """Run the LLM triage agent and write reports/YYYY-MM-DD.md."""
    from vulntriage.agent.report import generate_report
    from vulntriage.intel.cache import feed_health
    from vulntriage.intel.enrich import ttl_map
    from vulntriage.llm.factory import get_provider

    settings = get_settings()
    llm = get_provider(settings, provider)
    with session_scope(_engine(settings)) as session:
        run = start_run(session, "cli-report")
        with StageTimer(run).stage("report"):
            outcome = generate_report(
                session, settings, llm, run, feed_health(session, ttl_map(settings))
            )
        if outcome.agent.error:
            run.errors = [*run.errors, f"agent: {outcome.agent.error}"]
        finish_run(run)
    g = outcome.grounding
    console.print(
        f"report written to [bold]{outcome.path}[/bold]; grounding {g.verified}/{g.total} "
        f"claims verified ({g.rate:.1%})"
    )
    if outcome.agent.error:
        console.print(f"[yellow]agent error:[/yellow] {outcome.agent.error}")


@app.command()
def run(
    demo: Annotated[
        bool,
        typer.Option("--demo", help="Use the bundled fixture homelab (no Docker/network/key)."),
    ] = False,
    no_alerts: Annotated[bool, typer.Option("--no-alerts", help="Skip alert delivery.")] = False,
) -> None:
    """Run the full nightly pipeline: scan, enrich, exposure, score, report, alerts."""
    from vulntriage.pipeline import run_pipeline

    settings = get_settings()
    if demo:
        from vulntriage.demo import run_demo

        demo_cfg, results = run_demo(settings)
        for res in results:
            _print_result(res)
        console.print(
            f"\n[bold green]demo complete[/bold green]: database {demo_cfg.database_url}, "
            f"reports in {demo_cfg.reports_dir}/. "
            "Browse it with: [bold]vulntriage serve --demo[/bold]"
        )
        return
    result = run_pipeline(_engine(settings), settings, trigger="cli", alerts=not no_alerts)
    _print_result(result)
    if result.status != "ok":
        raise typer.Exit(1)


def _print_result(res: object) -> None:
    from vulntriage.pipeline import PipelineResult

    assert isinstance(res, PipelineResult)
    grounding = f"{res.grounding_rate:.1%}" if res.grounding_rate is not None else "n/a"
    timings = ", ".join(f"{k} {v:.1f}s" for k, v in res.stage_timings.items())
    console.print(
        f"run {res.run_id} ({res.status}): {res.open_findings:,} open findings -> "
        f"{res.actionable_findings:,} need action ({res.kev_findings} KEV); "
        f"report {res.report_path} (grounding {grounding}); {timings}"
    )
    for err in res.errors:
        console.print(f"  [yellow]warning:[/yellow] {err}")


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port.")] = 8080,
    demo: Annotated[
        bool, typer.Option("--demo", help="Serve the demo database (built if missing).")
    ] = False,
) -> None:
    """Start the dashboard (and the nightly scheduler if SCHEDULE_ENABLED=true)."""
    import uvicorn

    from vulntriage.web.app import create_app

    settings = get_settings()
    if demo or settings.demo_mode:
        from vulntriage.demo import demo_settings, run_demo

        cfg = demo_settings(settings)
        if not (cfg.data_dir / "demo.db").exists():
            console.print("building demo database...")
            cfg, _ = run_demo(settings)
        settings = cfg.model_copy(update={"schedule_enabled": False})
    uvicorn.run(create_app(settings), host=host, port=port, log_level="info", proxy_headers=False)


@app.command()
def scheduler() -> None:
    """Run only the nightly scheduler in the foreground (SCHEDULE_CRON, SCHEDULE_TIMEZONE)."""
    from vulntriage.scheduler import run_blocking

    run_blocking(get_settings())


@app.command("eval")
def eval_cmd(
    demo: Annotated[
        bool, typer.Option("--demo", help="Rebuild and evaluate the bundled demo dataset.")
    ] = False,
    output: Annotated[Path, typer.Option(help="Markdown file to write.")] = Path(
        "docs/EVALUATION.md"
    ),
    reports: Annotated[int, typer.Option(help="Grounding rate over the last N reports.")] = 10,
) -> None:
    """Measure KEV recall vs. baselines, noise reduction, grounding rate and stage runtimes."""
    import json
    from datetime import datetime

    from sqlalchemy.orm import sessionmaker

    from vulntriage.agent.report import generate_report
    from vulntriage.evaluation import DEMO_DATASET, REPRODUCE, evaluate, render_markdown
    from vulntriage.llm.mock import MockProvider

    settings = get_settings()
    dataset = "this homelab's live database"
    if demo:
        from vulntriage.demo import fixtures_dir, run_demo

        meta = json.loads((fixtures_dir() / "intel/meta.json").read_text())
        captured = datetime.fromisoformat(meta["captured_at"])
        settings, _ = run_demo(settings, now=captured)
        dataset = DEMO_DATASET.format(captured=f"captured {captured.date().isoformat()}")
    engine = _engine(settings)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as probe:  # grounding self-test; rolled back, never stored
        selftest = generate_report(
            probe,
            settings,
            MockProvider(top_n=settings.report_top_n, hallucinate=True),
            write=False,
        ).grounding
        probe.rollback()
    with session_scope(engine) as session:
        result = evaluate(session, settings, reports, selftest)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(result, dataset, REPRODUCE), encoding="utf-8")
    vt = result.rankings[0]
    console.print(
        f"wrote [bold]{output}[/bold]: {result.open_findings:,} open -> {result.actionable:,} "
        f"need action; KEV recall@10 {vt.recall[10]:.0%}, @20 {vt.recall[20]:.0%}; grounding "
        + (f"{result.grounding_micro:.1%}" if result.grounding_micro is not None else "n/a")
    )


if __name__ == "__main__":  # pragma: no cover
    app()

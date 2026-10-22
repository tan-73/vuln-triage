"""FastAPI + Jinja2 dashboard (read-only).

Meant for the LAN or a tailnet only: it binds to 127.0.0.1 by default and supports
optional HTTP basic auth (``DASHBOARD_USER`` / ``DASHBOARD_PASSWORD``). It has no
endpoints that change state. Do not publish it to the Internet.
"""

# No `from __future__ import annotations` here: FastAPI must resolve the dependency
# aliases defined inside create_app() at runtime.
import re
import secrets
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from vulntriage import __version__
from vulntriage.agent.report import headline
from vulntriage.config import Settings
from vulntriage.db import get_engine, init_db
from vulntriage.intel.cache import feed_health
from vulntriage.intel.enrich import ttl_map
from vulntriage.models import Asset, CveIntel, Finding, FindingStatus, Report, ScanRun
from vulntriage.remediation import build_groups, is_deferrable
from vulntriage.scoring import is_actionable
from vulntriage.web.charts import line_chart

HERE = Path(__file__).resolve().parent
EXPOSURE_ORDER = {"internet": 0, "lan": 1, "localhost": 2, "none": 3}
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
#: Markdown renderer with raw HTML disabled: report prose comes from an LLM.
_md = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")


_ALIGN = re.compile(r' style="text-align:(left|right|center)"')


def render_markdown(text: str) -> str:
    """Render report Markdown to HTML without passing through any raw HTML.

    Table alignment becomes a class instead of an inline style so the strict CSP holds.
    """
    return _ALIGN.sub(r' class="align-\1"', str(_md.render(text)))


def create_app(settings: Settings) -> FastAPI:
    """Build the dashboard application for ``settings``."""
    if bool(settings.dashboard_user) != bool(settings.dashboard_password):
        raise ValueError("set both DASHBOARD_USER and DASHBOARD_PASSWORD, or neither")
    engine = get_engine(settings.database_url)
    init_db(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.globals.update(version=__version__, exposure_order=EXPOSURE_ORDER)
    templates.env.filters["markdown"] = render_markdown

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        scheduler = None
        if settings.schedule_enabled:
            from vulntriage.scheduler import start_background

            scheduler = start_background(settings)
        yield
        if scheduler is not None:
            scheduler.shutdown(wait=False)

    app = FastAPI(
        title="VulnTriage", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None
    )
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    basic = HTTPBasic(auto_error=False)

    def require_auth(
        credentials: Annotated[HTTPBasicCredentials | None, Depends(basic)],
    ) -> None:
        if not settings.dashboard_user or not settings.dashboard_password:
            return
        expected_pw = settings.dashboard_password.get_secret_value().encode()
        ok = credentials is not None and (
            secrets.compare_digest(credentials.username.encode(), settings.dashboard_user.encode())
            & secrets.compare_digest(credentials.password.encode(), expected_pw)
        )
        if not ok:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "authentication required",
                headers={"WWW-Authenticate": 'Basic realm="vulntriage"'},
            )

    def get_session() -> Iterator[Session]:
        with factory() as session:
            yield session

    SessionDep = Annotated[Session, Depends(get_session)]
    router = APIRouter(dependencies=[Depends(require_auth)])

    def page(request: Request, name: str, **context: Any) -> HTMLResponse:
        return templates.TemplateResponse(request, name, {"settings": settings, **context})

    @router.get("/", response_class=HTMLResponse)
    def overview(request: Request, session: SessionDep) -> HTMLResponse:
        head = headline(session, settings)
        runs = list(
            session.scalars(
                select(ScanRun)
                .where(ScanRun.open_findings.is_not(None))
                .order_by(ScanRun.started_at.desc())
                .limit(30)
            )
        )[::-1]
        charts = [
            line_chart("Open findings", [(r.started_at, r.open_findings or 0) for r in runs]),
            line_chart("Need action", [(r.started_at, r.actionable_findings or 0) for r in runs]),
            line_chart("KEV-listed findings", [(r.started_at, r.kev_findings or 0) for r in runs]),
        ]
        groups = build_groups(session, settings)
        exposure_counts: dict[str, int] = {
            level: count
            for level, count in session.execute(
                select(Asset.exposure_level, func.count())
                .where(Asset.active)
                .group_by(Asset.exposure_level)
            ).all()
        }
        last_run = session.scalar(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(1))
        latest = session.scalar(select(Report).order_by(Report.created_at.desc()).limit(1))
        return page(
            request,
            "overview.html",
            head=head,
            charts=charts,
            runs=runs,
            groups=[g for g in groups if g.max_score >= settings.action_threshold][:5],
            exposure_counts=exposure_counts,
            last_run=last_run,
            latest=latest,
            health=feed_health(session, ttl_map(settings)).values(),
        )

    @router.get("/groups", response_class=HTMLResponse)
    def groups_view(request: Request, session: SessionDep) -> HTMLResponse:
        groups = build_groups(session, settings)
        return page(
            request,
            "groups.html",
            action=[g for g in groups if g.max_score >= settings.action_threshold],
            rest=[g for g in groups if g.max_score < settings.action_threshold],
            deferrable={g.key for g in groups if is_deferrable(g, settings.action_threshold)},
        )

    @router.get("/assets", response_class=HTMLResponse)
    def assets_view(request: Request, session: SessionDep) -> HTMLResponse:
        counts = {
            asset_id: (total, action, kev)
            for asset_id, total, action, kev in session.execute(
                select(
                    Finding.asset_id,
                    func.count(),
                    func.sum((Finding.score >= settings.action_threshold).cast(_int())),
                    func.sum(func.coalesce(CveIntel.in_kev, False).cast(_int())),
                )
                .outerjoin(CveIntel, CveIntel.cve_id == Finding.cve_id)
                .where(Finding.status == FindingStatus.OPEN)
                .group_by(Finding.asset_id)
            ).all()
        }
        assets = sorted(
            session.scalars(select(Asset).where(Asset.active)),
            key=lambda a: (
                EXPOSURE_ORDER.get(a.exposure_level, 9),
                -counts.get(a.id, (0, 0, 0))[1],
            ),
        )
        return page(request, "assets.html", assets=assets, counts=counts)

    @router.get("/assets/{asset_id}", response_class=HTMLResponse)
    def asset_view(asset_id: int, request: Request, session: SessionDep) -> HTMLResponse:
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(404, "no such asset")
        rows = session.execute(
            select(Finding, CveIntel)
            .outerjoin(CveIntel, CveIntel.cve_id == Finding.cve_id)
            .where(Finding.asset_id == asset_id, Finding.status == FindingStatus.OPEN)
            .order_by(Finding.score.desc().nulls_last(), Finding.id)
        ).all()
        groups = [g for g in build_groups(session, settings) if g.asset_ref == asset.ref]
        return page(
            request, "asset.html", asset=asset, rows=rows[:200], total=len(rows), groups=groups,
            actionable=sum(is_actionable(f.score, settings) for f, _ in rows),
        )  # fmt: skip

    @router.get("/findings/{finding_id}", response_class=HTMLResponse)
    def finding_view(finding_id: int, request: Request, session: SessionDep) -> HTMLResponse:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404, "no such finding")
        intel = session.get(CveIntel, finding.cve_id)
        return page(
            request, "finding.html", f=finding, intel=intel, asset=finding.asset,
            actionable=is_actionable(finding.score, settings),
        )  # fmt: skip

    @router.get("/reports", response_class=HTMLResponse)
    def reports_view(request: Request, session: SessionDep) -> HTMLResponse:
        reports = list(
            session.scalars(select(Report).order_by(Report.created_at.desc()).limit(100))
        )
        return page(request, "reports.html", reports=reports)

    @router.get("/reports/{report_id}", response_class=HTMLResponse)
    def report_view(report_id: int, request: Request, session: SessionDep) -> HTMLResponse:
        report = session.get(Report, report_id)
        if report is None:
            raise HTTPException(404, "no such report")
        return page(request, "report.html", report=report)

    @router.get("/api/summary")
    def api_summary(session: SessionDep) -> JSONResponse:
        head = headline(session, settings)
        return JSONResponse(
            {
                "open_findings": head.raw,
                "actionable_findings": head.actionable,
                "kev_findings": head.kev,
                "internet_exposed_assets": head.internet_assets,
            }
        )

    app.include_router(router)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


def _int() -> Any:
    from sqlalchemy import Integer

    return Integer()

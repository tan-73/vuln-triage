"""End-to-end pipeline on the demo dataset, the dashboard, alerts and the scheduler."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.test_scoring import _seed
from vulntriage.alerts import collect_alerts, dispatch_alerts, format_message
from vulntriage.config import Settings
from vulntriage.db import get_engine, init_db, session_scope
from vulntriage.models import Asset, Finding, Report, ScanRun
from vulntriage.scoring import score_all
from vulntriage.web.app import create_app, render_markdown
from vulntriage.web.charts import compact, line_chart, nice_ceiling

# --- pipeline / demo -----------------------------------------------------------------------


def test_demo_runs_three_nightly_snapshots(demo_env: tuple[Settings, list[Any]]) -> None:
    settings, results = demo_env
    assert len(results) == 3
    assert all(r.status == "ok" and not r.errors for r in results)
    assert all(r.grounding_rate == 1.0 for r in results)
    assert set(results[0].stage_timings) == {"scan", "enrich", "exposure", "score", "report"}
    # Day 2 adds gitea; day 3 replaces nginx 1.25.1 by 1.25.4 (old findings resolved).
    assert results[1].open_findings > results[0].open_findings
    assert results[2].open_findings < results[1].open_findings
    assert results[2].kev_findings < results[1].kev_findings
    assert all(r.actionable_findings < r.open_findings / 10 for r in results)
    reports = sorted(p.name for p in settings.reports_dir.glob("*.md"))
    assert reports == ["2026-10-20.md", "2026-10-21.md", "2026-10-22.md"]
    with session_scope(get_engine(settings.database_url)) as s:
        old = s.scalar(select(Asset).where(Asset.name == "nginx", Asset.tag == "1.25.1"))
        assert old is not None and old.active is False
        runs = list(s.scalars(select(ScanRun).order_by(ScanRun.started_at)))
        assert [r.started_at.date().isoformat() for r in runs] == [
            "2026-10-20",
            "2026-10-21",
            "2026-10-22",
        ]
        gitea = s.scalar(select(Asset).where(Asset.name == "gitea/gitea"))
        assert gitea is not None and gitea.exposure_level == "internet"


def test_pipeline_stage_failure_is_recorded_not_fatal(session: Session, settings: Settings) -> None:
    from vulntriage.llm.mock import MockProvider
    from vulntriage.models import AssetKind
    from vulntriage.pipeline import run_pipeline
    from vulntriage.scanners.base import ScanError, ScanResult
    from vulntriage.scanners.ingest import AssetSpec

    class Broken:
        name = "trivy"

        def scan(self, mode: str, target: str) -> ScanResult:
            raise ScanError("trivy db missing")

    def offline(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    from vulntriage.intel.http import FeedClient

    engine = get_engine(settings.database_url)
    init_db(engine)
    result = run_pipeline(
        engine, settings, "test",
        scanners=[Broken()], specs=[AssetSpec(AssetKind.IMAGE, "x", "1", scan_target="x:1")],
        containers=[], feed_client=FeedClient(httpx.Client(transport=httpx.MockTransport(offline)), max_retries=0),
        provider=MockProvider(), alerts=False,
    )  # fmt: skip
    assert result.status == "partial"
    assert any("trivy db missing" in e for e in result.errors)
    assert any(e.startswith("kev:") for e in result.errors)
    assert "report" in result.stage_timings and result.report_path is not None


# --- dashboard ------------------------------------------------------------------------------


@pytest.fixture
def client(demo_env: tuple[Settings, list[Any]]) -> TestClient:
    return TestClient(create_app(demo_env[0]))


def test_dashboard_pages(client: TestClient) -> None:
    home = client.get("/")
    assert home.status_code == 200
    html = home.text
    assert "Need action" in html and "Noise filtered" in html and "<svg" in html
    assert "Update image python:3.11.4-slim" in html
    assert home.headers["content-security-policy"].startswith("default-src 'self'")
    assert home.headers["x-frame-options"] == "DENY"
    for path in (
        "/groups",
        "/assets",
        "/assets/1",
        "/findings/1",
        "/reports",
        "/reports/1",
        "/static/style.css",
    ):
        assert client.get(path).status_code == 200, path
    for path in ("/assets/99999", "/findings/99999", "/reports/99999"):
        assert client.get(path).status_code == 404
    summary = client.get("/api/summary").json()
    assert summary["open_findings"] > summary["actionable_findings"] > 0
    assert client.get("/healthz").json()["status"] == "ok"


def test_report_page_never_renders_raw_html(demo_env: tuple[Settings, list[Any]]) -> None:
    html = render_markdown("**ok** <script>alert(1)</script>\n\n| a |\n|--:|\n| 1 |\n")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert 'class="align-right"' in html and "style=" not in html


def test_basic_auth(demo_env: tuple[Settings, list[Any]]) -> None:
    settings = demo_env[0].model_copy(
        update={"dashboard_user": "admin", "dashboard_password": SecretStr("s3cret")}
    )
    client = TestClient(create_app(settings))
    assert client.get("/").status_code == 401
    assert client.get("/").headers["www-authenticate"].startswith("Basic")
    bad = base64.b64encode(b"admin:wrong").decode()
    assert client.get("/", headers={"Authorization": f"Basic {bad}"}).status_code == 401
    good = base64.b64encode(b"admin:s3cret").decode()
    assert client.get("/", headers={"Authorization": f"Basic {good}"}).status_code == 200
    assert client.get("/healthz").status_code == 200  # health check stays open for Docker
    with pytest.raises(ValueError, match="both DASHBOARD_USER"):
        create_app(demo_env[0].model_copy(update={"dashboard_user": "admin"}))


def test_empty_dashboard(settings: Settings) -> None:
    client = TestClient(create_app(settings))
    page = client.get("/")
    assert page.status_code == 200 and "No runs yet" in page.text


def test_charts_helpers() -> None:
    assert [nice_ceiling(v) for v in (0, 3, 7.5, 230, 4300)] == [1.0, 5.0, 10.0, 250.0, 5000.0]
    assert [compact(v) for v in (950, 1000, 1250, 12000)] == ["950", "1K", "1.2K", "12K"]
    chart = line_chart("x", [(datetime(2026, 1, d, tzinfo=UTC), v) for d, v in ((1, 10), (2, 20))])
    assert chart.path.startswith("M") and chart.last is not None and chart.last.value == 20
    assert chart.y_ticks[-1][1] == "25"
    assert line_chart("x", []).empty


# --- alerts -------------------------------------------------------------------------------------


@pytest.fixture
def alert_db(session: Session, settings: Settings) -> Settings:
    _seed(session)
    score_all(session, settings)
    return settings.model_copy(
        update={"alert_min_score": 20.0, "dashboard_url": "http://vt.lan:8080/"}
    )


def test_collect_alerts_kev_and_hot_internet(session: Session, alert_db: Settings) -> None:
    items = collect_alerts(session, alert_db)
    assert {i.cve_id for i in items} == {"CVE-2023-4911", "CVE-2024-1111"}
    assert all(i.asset == "nginx:1.25.1" for i in items)  # host sudo (lan) is high but not internet
    subject, body = format_message(items, alert_db.dashboard_url)
    assert subject == "VulnTriage: 2 KEV-listed and 1 high-risk internet-exposed findings"
    assert "Dashboard: http://vt.lan:8080/groups" in body and "[KEV, internet]" in body


def test_dispatch_telegram_and_email_marks_alerted(session: Session, alert_db: Settings) -> None:
    sent: list[dict[str, Any]] = []

    def telegram(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        assert request.url.path == "/botTOKEN123/sendMessage"
        return httpx.Response(200, json={"ok": True})

    mails: list[Any] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            self.calls: list[str] = []

        def __enter__(self) -> FakeSMTP:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def starttls(self) -> None:
            self.calls.append("starttls")

        def login(self, user: str, password: str) -> None:
            assert (user, password) == ("vt", "pw")

        def send_message(self, msg: Any) -> None:
            mails.append(msg)

    cfg = alert_db.model_copy(update={
        "telegram_enabled": True, "telegram_bot_token": SecretStr("TOKEN123"), "telegram_chat_id": "42",
        "smtp_enabled": True, "smtp_host": "smtp.test", "smtp_from": "vt@test", "smtp_to": ["me@test"],
        "smtp_user": "vt", "smtp_password": SecretStr("pw"),
    })  # fmt: skip
    out = dispatch_alerts(
        session, cfg, telegram_client=httpx.Client(transport=httpx.MockTransport(telegram)),
        smtp_factory=FakeSMTP,  # type: ignore[arg-type]
    )  # fmt: skip
    assert out.sent_via == ["telegram", "email"] and not out.errors
    assert sent[0]["chat_id"] == "42" and "CVE-2023-4911" in sent[0]["text"]
    assert mails[0]["Subject"].startswith("VulnTriage:") and mails[0]["To"] == "me@test"
    assert all(
        f.alerted_at is not None
        for f in session.query(Finding)
        if f.cve_id in {"CVE-2023-4911", "CVE-2024-1111"}
    )
    # Already alerted: nothing new to say on the next run.
    again = dispatch_alerts(session, cfg, telegram_client=httpx.Client(transport=httpx.MockTransport(telegram)),
                            smtp_factory=FakeSMTP)  # type: ignore[arg-type]  # fmt: skip
    assert again.items == [] and len(sent) == 1


def test_failed_delivery_is_retried_next_time(session: Session, alert_db: Settings) -> None:
    def down(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(502)

    cfg = alert_db.model_copy(
        update={
            "telegram_enabled": True,
            "telegram_bot_token": SecretStr("T"),
            "telegram_chat_id": "1",
        }
    )
    out = dispatch_alerts(
        session, cfg, telegram_client=httpx.Client(transport=httpx.MockTransport(down))
    )
    assert out.sent_via == [] and out.errors == ["telegram: telegram API returned HTTP 502"]
    assert all(f.alerted_at is None for f in session.query(Finding))
    assert "T" not in out.errors[0].replace("Telegram", "").replace(
        "HTTP", ""
    )  # token never echoed


def test_alerts_disabled_by_default(session: Session, alert_db: Settings) -> None:
    assert dispatch_alerts(session, alert_db).items == []


# --- scheduler ------------------------------------------------------------------------------------


def test_scheduler_job_and_overlap_guard(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    import vulntriage.pipeline as pipeline
    import vulntriage.scheduler as sched

    calls: list[str] = []
    monkeypatch.setattr(
        pipeline, "run_pipeline", lambda *a, **k: calls.append(k.get("trigger", ""))
    )
    sched.nightly_job(settings)
    assert calls == ["schedule"]
    assert sched._lock.acquire(blocking=False)
    try:
        sched.nightly_job(settings)  # previous run "still in progress": skipped
    finally:
        sched._lock.release()
    assert calls == ["schedule"]

    bg = sched.start_background(settings.model_copy(update={"schedule_cron": "15 3 * * *"}))
    try:
        job = bg.get_job("nightly")
        assert (
            job is not None and "hour='3'" in str(job.trigger) and "minute='15'" in str(job.trigger)
        )
    finally:
        bg.shutdown(wait=False)


def test_cli_run_demo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    import vulntriage.cli as cli

    base = Settings(_env_file=None, data_dir=tmp_path / "d", reports_dir=tmp_path / "r")  # type: ignore[call-arg]
    monkeypatch.setattr(cli, "get_settings", lambda: base)
    out = CliRunner(env={"COLUMNS": "300"}).invoke(cli.app, ["run", "--demo"])
    assert out.exit_code == 0, out.output
    assert "demo complete" in out.output and out.output.count("(ok)") == 3
    assert len(list((tmp_path / "r" / "demo").glob("*.md"))) == 3
    with session_scope(get_engine(f"sqlite:///{tmp_path / 'd' / 'demo' / 'demo.db'}")) as s:
        assert s.query(Report).count() == 3

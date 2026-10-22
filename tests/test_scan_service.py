"""Container discovery, the scan service and the Phase-1 CLI."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from tests.conftest import FIXTURES, load_fixture
from vulntriage.config import Settings
from vulntriage.models import Asset, AssetKind, Finding, FindingStatus, ScanRun
from vulntriage.pipeline import collect_specs, run_scan_stage, start_run
from vulntriage.scanners.base import ScanError, ScanResult
from vulntriage.scanners.docker_api import ContainerInfo, DockerClient
from vulntriage.scanners.ingest import AssetSpec
from vulntriage.scanners.service import FixtureScanner, discover_image_targets, scan_specs

TRIVY = {
    "redis:6.2.6": FIXTURES / "trivy/redis_6.2.6.json",
    "postgres:13.2": FIXTURES / "trivy/postgres_13.2.json",
}


def docker_with(containers: list[dict], images: dict[str, dict] | None = None) -> DockerClient:
    """A DockerClient backed by an in-memory MockTransport."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET", "the Docker client must be read-only"
        if request.url.path == "/containers/json":
            return httpx.Response(200, json=containers)
        if request.url.path.startswith("/images/"):
            ref = request.url.path.removeprefix("/images/").removesuffix("/json")
            if images and ref in images:
                return httpx.Response(200, json=images[ref])
            return httpx.Response(404, json={"message": "no such image"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    return DockerClient(client=client)


def test_container_info_from_api_fixture() -> None:
    containers = [ContainerInfo.from_api(c) for c in load_fixture("docker/containers.json")]
    proxy = containers[0]
    assert proxy.name == "proxy"
    assert {(p.host_ip, p.public_port) for p in proxy.ports} == {
        ("0.0.0.0", 80),
        ("0.0.0.0", 443),
        ("::", 443),
    }
    assert proxy.networks == ["edge"]


def test_discover_groups_containers_by_image_and_excludes() -> None:
    docker = docker_with(load_fixture("docker/containers.json"))
    specs = discover_image_targets(docker.list_containers(), exclude=["redis:*"], docker=docker)
    refs = {s.scan_target: s for s in specs}
    assert "redis:6.2.6" not in refs
    assert refs["python:3.11.4-slim"].containers == ("webapp", "webapp-worker")
    assert refs["grafana/grafana:8.3.0"].name == "grafana/grafana"
    assert refs["grafana/grafana:8.3.0"].tag == "8.3.0"


def test_discover_resolves_bare_image_ids() -> None:
    raw = [{"Id": "x", "Names": ["/notes-app"], "Image": "9f1c2e7d4a6b", "ImageID": "sha256:3b8"}]
    tagged = docker_with(raw, images={"9f1c2e7d4a6b": {"RepoTags": ["notes-app:2.0"]}})
    assert (
        discover_image_targets(tagged.list_containers(), docker=tagged)[0].scan_target
        == "notes-app:2.0"
    )
    untagged = docker_with(raw)
    spec = discover_image_targets(untagged.list_containers(), docker=untagged)[0]
    assert (spec.name, spec.tag, spec.scan_target) == (
        "untagged/notes-app",
        "9f1c2e7d4a6b",
        "9f1c2e7d4a6b",
    )


def test_scan_failure_keeps_existing_findings_open(session: Session) -> None:
    good = FixtureScanner("trivy", TRIVY)
    spec = AssetSpec(AssetKind.IMAGE, "redis", "6.2.6", scan_target="redis:6.2.6")
    first = scan_specs(session, [spec], [good])
    assert first.assets_scanned == 1 and not first.errors

    class Broken:
        name = "trivy"

        def scan(self, mode: str, target: str) -> ScanResult:
            raise ScanError("db download failed")

    second = scan_specs(session, [spec], [Broken()])
    assert second.assets_scanned == 0 and second.errors
    open_count = session.query(Finding).filter(Finding.status == FindingStatus.OPEN).count()
    assert open_count == first.findings_total
    assert session.scalar(select(Asset)).active is True  # type: ignore[union-attr]


def test_full_scan_retires_removed_images(session: Session) -> None:
    scanner = FixtureScanner("trivy", TRIVY)
    redis = AssetSpec(AssetKind.IMAGE, "redis", "6.2.6", scan_target="redis:6.2.6")
    pg = AssetSpec(AssetKind.IMAGE, "postgres", "13.2", scan_target="postgres:13.2")
    scan_specs(session, [redis, pg], [scanner])
    summary = scan_specs(session, [redis], [scanner])
    assert summary.findings_resolved > 0
    pg_asset = session.scalar(select(Asset).where(Asset.name == "postgres"))
    assert pg_asset is not None and pg_asset.active is False


def test_collect_specs_marks_discovery_failure_as_partial(settings: Settings) -> None:
    class Down(DockerClient):
        def __init__(self) -> None:
            pass

        def list_containers(self, include_stopped: bool = False) -> list[ContainerInfo]:
            raise httpx.ConnectError("socket missing")

    cfg = settings.model_copy(update={"host_scan_targets": ["nas=/host"]})
    specs, full = collect_specs(cfg, Down())
    assert full is False
    assert [(s.kind, s.name, s.scan_target) for s in specs] == [(AssetKind.HOST, "nas", "/host")]
    specs, full = collect_specs(cfg, None, images=["nginx:1.25"])
    assert full is False and specs[0].tag == "1.25"


def test_run_scan_stage_updates_run(session: Session, settings: Settings) -> None:
    run = start_run(session, "test")
    docker = docker_with([c for c in load_fixture("docker/containers.json") if c["Image"] in TRIVY])
    summary = run_scan_stage(
        session, settings, run, scanners=[FixtureScanner("trivy", TRIVY)], docker=docker
    )
    assert run.assets_scanned == 2 == summary.assets_scanned
    assert run.findings_total == summary.findings_total > 0
    assert run.findings_new == run.findings_total


@pytest.fixture
def cli_env(settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Settings:
    import vulntriage.cli as cli
    import vulntriage.pipeline as pipeline

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(pipeline, "build_scanners", lambda _s: [FixtureScanner("trivy", TRIVY)])
    return settings


def test_cli_scan_and_list_findings(cli_env: Settings) -> None:
    from vulntriage.cli import app

    runner = CliRunner(env={"COLUMNS": "200"})
    result = runner.invoke(app, ["scan", "--image", "redis:6.2.6"])
    assert result.exit_code == 0, result.output
    assert "scanned 1 assets" in result.output

    listed = runner.invoke(app, ["list-findings", "--severity", "critical", "--limit", "5"])
    assert listed.exit_code == 0, listed.output
    assert "redis:6.2.6" in listed.output

    from vulntriage.db import get_engine, session_scope

    with session_scope(get_engine(cli_env.database_url)) as s:
        run = s.scalar(select(ScanRun))
        assert run is not None and run.status == "ok" and "scan" in run.stage_timings

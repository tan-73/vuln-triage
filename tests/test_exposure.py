"""Exposure analysis: scan-scope guard, nmap, proxy parsers and level computation."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pydantic
import pytest
from sqlalchemy.orm import Session

from tests.conftest import FIXTURES, load_fixture
from vulntriage.config import Settings
from vulntriage.exposure.analyze import (
    analyze_containers,
    apply_exposure,
    classify_bind,
    is_internet_hostname,
)
from vulntriage.exposure.guard import ScanScopeGuard, ScopeViolation
from vulntriage.exposure.nmap import NmapResult, parse_nmap_xml, run_nmap
from vulntriage.exposure.proxies import (
    load_routes,
    parse_caddyfile,
    parse_nginx,
    parse_traefik_labels,
    split_upstream,
)
from vulntriage.models import AssetKind, ExposureLevel, ScanRun
from vulntriage.pipeline import run_exposure_stage
from vulntriage.scanners.base import ScanResult
from vulntriage.scanners.docker_api import ContainerInfo
from vulntriage.scanners.ingest import AssetSpec, ingest_results

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.168.50.10" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
<ports><port protocol="tcp" portid="3000"><state state="open"/></port>
<port protocol="tcp" portid="22"><state state="open"/></port>
<port protocol="tcp" portid="443"><state state="filtered"/></port>
<port protocol="udp" portid="53"><state state="open"/></port></ports></host>
<host><address addr="192.168.50.20" addrtype="ipv4"/><ports/></host></nmaprun>"""


def containers() -> list[ContainerInfo]:
    return [ContainerInfo.from_api(c) for c in load_fixture("docker/containers.json")]


@pytest.fixture
def demo_settings(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "internet_hostname_patterns": ["*.example.com"],
            "host_lan_ips": ["192.168.50.10"],
            "nginx_config_paths": [f"proxy={FIXTURES / 'proxy/nginx'}"],
        }
    )


# --- guard -----------------------------------------------------------------------------------


def test_guard_accepts_only_allowed_private_targets() -> None:
    guard = ScanScopeGuard(["192.168.50.0/24", "fd00::/8"])
    assert str(guard.check("192.168.50.10")) == "192.168.50.10/32"
    assert str(guard.check("192.168.50.0/25")) == "192.168.50.0/25"
    assert str(guard.check("fd00::1")) == "fd00::1/128"
    for bad, reason in [
        ("8.8.8.8", "public address space"),
        ("192.168.0.0/16", "not inside ALLOWED_SCAN_CIDRS"),
        ("10.0.0.5", "not inside ALLOWED_SCAN_CIDRS"),
        ("nas.local", "not a literal IP"),
        ("192.168.50.1-20", "not a literal IP"),
        ("0.0.0.0/0", "public address space"),
    ]:
        with pytest.raises(ScopeViolation, match=reason):
            guard.check(bad)


def test_guard_logs_refusals(caplog: pytest.LogCaptureFixture) -> None:
    ok, refused = ScanScopeGuard(["10.0.0.0/8"]).filter(["10.1.2.3", "1.1.1.1"])
    assert ok == ["10.1.2.3/32"] and len(refused) == 1
    assert "refusing to scan '1.1.1.1'" in caplog.text


def test_public_cidr_in_allow_list_is_rejected() -> None:
    with pytest.raises(ScopeViolation):
        ScanScopeGuard(["203.0.113.0/24"])
    with pytest.raises(pydantic.ValidationError, match="private ranges"):
        Settings(_env_file=None, allowed_scan_cidrs="192.168.50.0/24,203.0.113.0/24")  # type: ignore[call-arg]
    assert Settings(_env_file=None).allowed_scan_cidrs == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]  # type: ignore[call-arg]


# --- nmap ------------------------------------------------------------------------------------


def test_parse_nmap_xml() -> None:
    assert parse_nmap_xml(NMAP_XML) == {"192.168.50.10": {3000, 22}}


def test_run_nmap_never_passes_refused_targets() -> None:
    seen: list[list[str]] = []

    def fake(cmd: list[str], **_k: object) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, NMAP_XML, "")

    guard = ScanScopeGuard(["192.168.50.0/24"])
    result = run_nmap(["192.168.50.0/24", "93.184.216.34", "example.com"], guard, runner=fake)
    assert [c[-1] for c in seen] == ["192.168.50.0/24"]
    assert seen[0][:4] == ["nmap", "-sT", "-Pn", "-n"]
    assert len(result.refused) == 2 and result.open_ports["192.168.50.10"] == {22, 3000}


def test_run_nmap_records_errors() -> None:
    def failing(cmd: list[str], **_k: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "nope")

    def garbage(cmd: list[str], **_k: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 0, "<not xml", "")

    guard = ScanScopeGuard(["10.0.0.0/8"])
    assert run_nmap(["10.0.0.1"], guard, runner=failing).errors == ["nmap 10.0.0.1/32: exit 1"]
    assert "unparsable XML" in run_nmap(["10.0.0.1"], guard, runner=garbage).errors[0]


# --- proxy parsers ---------------------------------------------------------------------------


def test_parse_nginx_proxy_manager_configs() -> None:
    routes, errors = load_routes([("proxy", str(FIXTURES / "proxy/nginx"))], [], [], traefik_labels=False)
    assert not errors
    by_host = {r.hostnames[0]: r for r in routes}
    git = by_host["git.example.com"]
    assert (git.upstream_host, git.upstream_port, git.owner, git.lan_only) == ("gitea", 3000, "proxy", False)
    grafana = by_host["grafana.home.arpa"]
    assert (grafana.upstream_host, grafana.upstream_port, grafana.lan_only) == ("192.168.50.10", 3000, True)


def test_parse_nginx_plain_proxy_pass_and_upstreams() -> None:
    conf = """
    upstream backend { server app1:8080; server app2:8080 weight=2; }
    server {
        listen 443 ssl; server_name shop.example.com www.shop.example.com;  # comment
        location /api/ { proxy_pass http://backend; }
        location /static { root /srv; }
        location /admin { allow 10.0.0.0/8; deny all; proxy_pass http://admin:9000/; }
    }
    server { server_name _; return 444; }
    """
    routes = parse_nginx(conf, "test.conf")
    assert [(r.upstream_host, r.upstream_port, r.lan_only) for r in routes] == [
        ("app1", 8080, False), ("app2", 8080, False), ("admin", 9000, True)
    ]  # fmt: skip
    assert routes[0].hostnames == ["shop.example.com", "www.shop.example.com"]


def test_parse_caddyfile_fixture() -> None:
    text = (FIXTURES / "proxy/caddy/Caddyfile").read_text()
    routes = parse_caddyfile(text, "Caddyfile", owner="caddy")
    summary = [(tuple(r.hostnames), r.upstream_host, r.upstream_port, r.lan_only) for r in routes]
    assert summary == [
        (("docs.example.com", "www.docs.example.com"), "wiki", 8080, False),
        (("media.home.arpa",), "jellyfin", 8096, True),
        (("status.example.com",), "uptime", 3001, False),
        (("status.example.com",), "uptime-2", 3001, False),
    ]
    assert all(r.owner == "caddy" for r in routes)


def test_parse_traefik_labels() -> None:
    webapp = next(c for c in containers() if c.name == "webapp")
    (route,) = parse_traefik_labels(webapp)
    assert (route.hostnames, route.upstream_port, route.target_container) == (["app.example.com"], 8000, "webapp")
    disabled = webapp.model_copy(update={"labels": {**webapp.labels, "traefik.enable": "false"}})
    assert parse_traefik_labels(disabled) == []
    multi = webapp.model_copy(
        update={"labels": {"traefik.http.routers.r.rule": "Host(`a.example.com`, `b.example.com`) || Host(`c.lan`)"}}
    )
    assert parse_traefik_labels(multi)[0].hostnames == ["a.example.com", "b.example.com", "c.lan"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("http://gitea:3000/", ("gitea", 3000)), ("gitea:3000", ("gitea", 3000)), ("https://x", ("x", 443)),
     ("unix//run/app.sock", (None, None)), ("$upstream", (None, None)), ("http://[fd00::1]:81", ("fd00::1", 81))],
)  # fmt: skip
def test_split_upstream(value: str, expected: tuple[str | None, int | None]) -> None:
    assert split_upstream(value) == expected


def test_missing_proxy_path_is_tolerated(tmp_path: Path) -> None:
    routes, errors = load_routes([(str(tmp_path / "nope"), str(tmp_path / "nope"))], [], [], False)
    assert routes == [] and errors == []


# --- levels ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ip", "level"),
    [(None, ExposureLevel.LAN), ("0.0.0.0", ExposureLevel.LAN), ("::", ExposureLevel.LAN),
     ("127.0.0.1", ExposureLevel.LOCALHOST), ("::1", ExposureLevel.LOCALHOST),
     ("192.168.50.5", ExposureLevel.LAN), ("100.101.102.103", ExposureLevel.LAN),
     ("93.184.216.34", ExposureLevel.INTERNET)],
)  # fmt: skip
def test_classify_bind(ip: str | None, level: ExposureLevel) -> None:
    assert classify_bind(ip)[0] == level


def test_internet_hostname_patterns() -> None:
    assert is_internet_hostname("Git.Example.com.", ["*.example.com"])
    assert not is_internet_hostname("grafana.home.arpa", ["*.example.com"])
    assert not is_internet_hostname("example.com", [])


def test_analyze_demo_homelab(demo_settings: Settings) -> None:
    routes, _ = load_routes(
        demo_settings.parsed_targets("nginx_config_paths"), [], containers(), traefik_labels=True
    )
    result = analyze_containers(containers(), routes, demo_settings)
    levels = {name: exp.level for name, exp in result.items()}
    assert levels == {
        "proxy": ExposureLevel.INTERNET,
        "gitea": ExposureLevel.INTERNET,
        "grafana": ExposureLevel.LAN,
        "gitea-db": ExposureLevel.NONE,
        "cache": ExposureLevel.LOCALHOST,
        "webapp": ExposureLevel.INTERNET,
        "webapp-worker": ExposureLevel.NONE,
    }
    assert any("public hostname git.example.com" in e for e in result["gitea"].evidence)
    assert any("serves nginx route git.example.com" in e for e in result["proxy"].evidence)
    assert any("restricted to private client IPs" in e for e in result["grafana"].evidence)


def test_without_internet_patterns_routes_are_lan(demo_settings: Settings) -> None:
    cfg = demo_settings.model_copy(update={"internet_hostname_patterns": []})
    routes, _ = load_routes(cfg.parsed_targets("nginx_config_paths"), [], containers())
    assert analyze_containers(containers(), routes, cfg)["gitea"].level == ExposureLevel.LAN


def test_nmap_confirms_and_raises(demo_settings: Settings) -> None:
    cs = containers()
    nmap = NmapResult(open_ports={"192.168.50.10": {3000, 6379}})
    result = analyze_containers(cs, [], demo_settings, nmap)
    assert "nmap: port 3000 open on 192.168.50.10" in result["grafana"].evidence
    # redis is bound to loopback per Docker, but nmap sees it from the LAN: raise to lan.
    assert result["cache"].level == ExposureLevel.LAN


def test_host_network_mode_is_lan(demo_settings: Settings) -> None:
    c = containers()[3].model_copy(update={"network_mode": "host", "ports": []})
    assert analyze_containers([c], [], demo_settings)[c.name].level == ExposureLevel.LAN


def _ingest_demo_assets(session: Session) -> None:
    for name, tag, conts in [
        ("gitea/gitea", "1.16.0", ("gitea",)),
        ("redis", "6.2.6", ("cache",)),
        ("python", "3.11.4-slim", ("webapp", "webapp-worker")),
        ("postgres", "13.2", ("gitea-db",)),
    ]:
        spec = AssetSpec(AssetKind.IMAGE, name, tag, containers=conts)
        ingest_results(session, spec, [ScanResult(scanner="trivy", artifact_name=name)])
    ingest_results(session, AssetSpec(AssetKind.HOST, "nas"), [ScanResult(scanner="trivy", artifact_name="nas")])


def test_apply_exposure_with_overrides(session: Session, demo_settings: Settings) -> None:
    _ingest_demo_assets(session)
    cfg = demo_settings.model_copy(update={"exposure_overrides": ["postgres=lan", "bogus=wat"]})
    routes, _ = load_routes(cfg.parsed_targets("nginx_config_paths"), [], containers())
    summary = apply_exposure(session, cfg, containers(), routes)
    from vulntriage.models import Asset

    assets = {a.ref: a for a in session.query(Asset)}
    assert assets["gitea/gitea:1.16.0"].exposure_level == "internet"
    assert assets["redis:6.2.6"].exposure_level == "localhost"
    assert assets["python:3.11.4-slim"].exposure_level == "internet"
    assert any(e.startswith("webapp: traefik route") for e in assets["python:3.11.4-slim"].exposure_evidence)
    assert assets["postgres:13.2"].exposure_level == "lan"
    assert "override: EXPOSURE_OVERRIDES sets lan" in assets["postgres:13.2"].exposure_evidence
    assert assets["host:nas"].exposure_level == "lan"
    assert summary.levels == {"internet": 2, "localhost": 1, "lan": 2}


def test_exposure_stage_keeps_previous_levels_when_docker_is_down(
    session: Session, demo_settings: Settings
) -> None:
    from vulntriage.scanners.docker_api import DockerClient

    class Down(DockerClient):
        def __init__(self) -> None:
            pass

        def list_containers(self, include_stopped: bool = False) -> list[ContainerInfo]:
            raise ConnectionError("no socket")

    run = ScanRun(stage_timings={}, errors=[])
    assert run_exposure_stage(session, demo_settings, run, docker=Down()) is None
    assert "container listing failed" in run.errors[0]


def test_exposure_stage_runs_guarded_nmap(session: Session, demo_settings: Settings) -> None:
    _ingest_demo_assets(session)
    calls: list[list[str]] = []

    def fake(cmd: list[str], **_k: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, NMAP_XML, "")

    cfg = demo_settings.model_copy(
        update={"nmap_enabled": True, "nmap_targets": ["192.168.50.10", "8.8.8.8"],
                "allowed_scan_cidrs": ["192.168.50.0/24"]}
    )  # fmt: skip
    run = ScanRun(stage_timings={}, errors=[])
    summary = run_exposure_stage(session, cfg, run, containers=containers(), nmap_runner=fake)
    assert summary is not None
    assert [c[-1] for c in calls] == ["192.168.50.10/32"]
    assert any("refusing to scan '8.8.8.8'" in e for e in run.errors)

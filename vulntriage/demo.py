"""Fixture-backed demo homelab: the full pipeline with no Docker, no network and no LLM key.

The demo replays stored scanner JSON (:class:`~vulntriage.scanners.service.FixtureScanner`),
serves a real public intel snapshot through an in-process HTTP mock transport (the normal
enrichment code path runs unchanged), and reads fictional proxy configs and container
listings from ``fixtures/``. See ``fixtures/demo.yaml``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import yaml
from pydantic import BaseModel, Field

from vulntriage.config import Settings
from vulntriage.intel.http import FeedClient, RateLimiter
from vulntriage.models import AssetKind
from vulntriage.scanners.docker_api import ContainerInfo
from vulntriage.scanners.ingest import AssetSpec
from vulntriage.scanners.service import FixtureScanner, Scanner, discover_image_targets

if TYPE_CHECKING:
    from vulntriage.pipeline import PipelineResult


def fixtures_dir() -> Path:
    """Fixtures shipped inside the wheel, or the repository's ``fixtures/`` in a checkout."""
    packaged = Path(__file__).resolve().parent / "_fixtures"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parent.parent / "fixtures"


class Snapshot(BaseModel):
    """One simulated nightly run."""

    days_ago: int
    note: str = ""
    remove_containers: list[str] = Field(default_factory=list)
    replace_images: dict[str, str] = Field(default_factory=dict)


class DemoManifest(BaseModel):
    """Parsed ``fixtures/demo.yaml``."""

    settings: dict[str, Any] = Field(default_factory=dict)
    images: dict[str, str]
    grype: dict[str, str] = Field(default_factory=dict)
    hosts: dict[str, str] = Field(default_factory=dict)
    snapshots: list[Snapshot]


def load_manifest(root: Path | None = None) -> DemoManifest:
    """Read the demo manifest."""
    root = root or fixtures_dir()
    data = yaml.safe_load((root / "demo.yaml").read_text(encoding="utf-8"))
    return DemoManifest.model_validate(data)


def demo_settings(
    base: Settings, workdir: Path | None = None, root: Path | None = None
) -> Settings:
    """Settings for a self-contained demo: its own SQLite DB (``DATA_DIR/demo``) and
    reports directory (``REPORTS_DIR/demo``)."""
    root = root or fixtures_dir()
    manifest = load_manifest(root)
    overrides = dict(manifest.settings)
    overrides["nginx_config_paths"] = [
        f"{owner}={root / path}"
        for owner, _, path in (p.partition("=") for p in overrides.get("nginx_config_paths", []))
    ]
    workdir = workdir or base.data_dir / "demo"
    workdir.mkdir(parents=True, exist_ok=True)
    return base.model_copy(
        update={
            **overrides,
            "database_url": f"sqlite:///{workdir / 'demo.db'}",
            "data_dir": workdir,
            "reports_dir": base.reports_dir / "demo",
            "offline": False,  # the mock transport below *is* the network
            "llm_provider": "mock",
            "nmap_enabled": False,
            "caddy_config_paths": [],
            "fs_scan_targets": [],
            "host_scan_targets": [],
        }
    )


def snapshot_containers(snapshot: Snapshot, root: Path | None = None) -> list[ContainerInfo]:
    """Container listing for one snapshot (base listing with removals/replacements)."""
    root = root or fixtures_dir()
    raw = json.loads((root / "docker/containers.json").read_text(encoding="utf-8"))
    containers = []
    for item in raw:
        info = ContainerInfo.from_api(item)
        if info.name in snapshot.remove_containers:
            continue
        if info.image in snapshot.replace_images:
            info = info.model_copy(update={"image": snapshot.replace_images[info.image]})
        containers.append(info)
    return containers


def snapshot_specs(
    manifest: DemoManifest, snapshot: Snapshot, root: Path | None = None
) -> list[AssetSpec]:
    """Assets scanned in one snapshot: discovered images plus demo hosts."""
    specs = discover_image_targets(snapshot_containers(snapshot, root))
    specs += [AssetSpec(AssetKind.HOST, name, "", scan_target=name) for name in manifest.hosts]
    return specs


def demo_scanners(
    manifest: DemoManifest, root: Path | None = None, grype: bool = True
) -> list[Scanner]:
    """Fixture-replaying Trivy (and Grype) scanners."""
    root = root or fixtures_dir()
    trivy_files = {ref: root / path for ref, path in {**manifest.images, **manifest.hosts}.items()}
    scanners: list[Scanner] = [FixtureScanner("trivy", trivy_files)]
    if grype and manifest.grype:
        grype_files = {ref: root / path for ref, path in manifest.grype.items()}
        scanners.append(_LenientFixtureScanner("grype", grype_files))
    return scanners


class _LenientFixtureScanner(FixtureScanner):
    """Grype fixtures exist for a subset of images; others yield no findings, not an error."""

    def scan(self, mode: str, target: str) -> Any:
        from vulntriage.scanners.base import ScanResult

        if target not in self.files:
            return ScanResult(scanner=self.name, artifact_name=target)
        return super().scan(mode, target)


@lru_cache(maxsize=4)
def _intel(root: Path) -> dict[str, Any]:
    nvd = {p.stem: json.loads(p.read_text()) for p in sorted((root / "intel/nvd").glob("*.json"))}
    return {
        "kev": json.loads((root / "intel/kev.json").read_text()),
        "epss": json.loads((root / "intel/epss.json").read_text()),
        "osv": json.loads((root / "intel/osv.json").read_text()),
        "nvd": nvd,
    }


def fixture_transport(settings: Settings, root: Path | None = None) -> httpx.MockTransport:
    """An httpx transport that answers EPSS/KEV/NVD/OSV requests from the intel snapshot."""
    intel = _intel((root or fixtures_dir()).resolve())
    epss_rows = {row["cve"]: row for row in intel["epss"]["data"]}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url).split("?", 1)[0]
        if url == settings.kev_url:
            return httpx.Response(200, json=intel["kev"])
        if url == settings.epss_url:
            wanted = request.url.params.get("cve", "").split(",")
            rows = [epss_rows[c] for c in wanted if c in epss_rows]
            return httpx.Response(200, json={"status": "OK", "data": rows})
        if url == settings.nvd_url:
            cve = request.url.params.get("cveId", "")
            empty = {"totalResults": 0, "vulnerabilities": []}
            return httpx.Response(200, json=intel["nvd"].get(cve, empty))
        if url == settings.osv_url:
            body = json.loads(request.content or b"{}")
            pkg = body.get("package") or {}
            key = f"{pkg.get('ecosystem')}|{pkg.get('name')}|{body.get('version', '')}"
            alt = f"{pkg.get('ecosystem')}|{pkg.get('name')}|v{body.get('version', '')}"
            return httpx.Response(200, json=intel["osv"].get(key) or intel["osv"].get(alt) or {})
        return httpx.Response(404, json={"error": f"demo transport has no route for {url}"})

    return httpx.MockTransport(handler)


def demo_feed_client(settings: Settings, root: Path | None = None) -> FeedClient:
    """A :class:`FeedClient` wired to :func:`fixture_transport` (never sleeps)."""
    http = httpx.Client(transport=fixture_transport(settings, root))
    return FeedClient(http, max_retries=0, sleep=lambda _s: None)


def no_rate_limit() -> RateLimiter:
    """The demo transport is in-process, so NVD's public rate limit does not apply."""
    return RateLimiter(10**9, 1.0, sleep=lambda _s: None)


def snapshot_time(snapshot: Snapshot, now: datetime) -> datetime:
    """Wall-clock time of a snapshot's simulated nightly run (02:30 UTC)."""
    day = (now - timedelta(days=snapshot.days_ago)).replace(
        hour=2, minute=30, second=0, microsecond=0
    )
    return min(day, now)


def run_demo(
    base: Settings, now: datetime | None = None, root: Path | None = None
) -> tuple[Settings, list[PipelineResult]]:
    """Rebuild the demo database from scratch and replay every snapshot through the pipeline.

    Returns the demo settings (to locate its DB/reports) and one result per snapshot.
    No Docker, network or API key is used: scanners, feeds and the LLM are all local.
    """
    from vulntriage.db import dispose_engine, get_engine, init_db
    from vulntriage.llm.mock import MockProvider
    from vulntriage.models import utcnow
    from vulntriage.pipeline import run_pipeline

    root = root or fixtures_dir()
    settings = demo_settings(base, root=root)
    dispose_engine(settings.database_url)
    for suffix in ("", "-wal", "-shm"):
        (settings.data_dir / f"demo.db{suffix}").unlink(missing_ok=True)
    engine = get_engine(settings.database_url)
    init_db(engine)

    manifest = load_manifest(root)
    now = now or utcnow()
    results = []
    for snapshot in manifest.snapshots:
        when = snapshot_time(snapshot, now)
        results.append(
            run_pipeline(
                engine,
                settings,
                trigger="demo",
                scanners=demo_scanners(manifest, root),
                specs=snapshot_specs(manifest, snapshot, root),
                containers=snapshot_containers(snapshot, root),
                feed_client=demo_feed_client(settings, root),
                nvd_rate_limiter=no_rate_limit(),
                provider=MockProvider(top_n=settings.report_top_n),
                now=when,
                alerts=False,
            )
        )
    return settings, results

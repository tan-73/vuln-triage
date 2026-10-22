"""Combine Docker port bindings, proxy routes and nmap results into one exposure level per asset.

Rules (highest wins, every rule that fires adds an evidence line):

* A proxy route whose hostname matches ``INTERNET_HOSTNAME_PATTERNS`` (and is not
  restricted to private client IPs) makes its upstream container ``internet``. Any
  other route makes it ``lan``. The proxy container that owns the route inherits the level.
* A port published on ``0.0.0.0``/``::`` or a private/Tailscale address is ``lan``. On
  ``127.0.0.1``/``::1`` it is ``localhost``. On a public address it is ``internet``.
* ``network_mode: host`` is ``lan`` (every listening socket is on the host's interfaces).
* nmap, when enabled, adds evidence when it confirms a published port is open on a LAN IP,
  and raises the asset to ``lan`` if the asset was rated lower.
* ``EXPOSURE_OVERRIDES`` (``name=level``) always wins. Use it for paths VulnTriage can't
  see, such as a tunnel configured in a cloud dashboard.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulntriage.config import Settings
from vulntriage.exposure.nmap import NmapResult
from vulntriage.exposure.proxies import ProxyRoute
from vulntriage.models import Asset, AssetKind, ExposureLevel, utcnow
from vulntriage.scanners.docker_api import ContainerInfo

log = logging.getLogger(__name__)

LOOPBACK_UPSTREAMS = {"localhost", "127.0.0.1", "::1", "host.docker.internal", "172.17.0.1"}


@dataclass
class Exposure:
    """An exposure level with the evidence that produced it."""

    level: ExposureLevel = ExposureLevel.NONE
    evidence: list[str] = field(default_factory=list)

    def raise_to(self, level: ExposureLevel, reason: str) -> None:
        """Record ``reason``; keep the higher of the current and the new level."""
        if reason not in self.evidence:
            self.evidence.append(reason)
        if level.rank > self.level.rank:
            self.level = level


@dataclass
class ExposureSummary:
    """Counts of assets per exposure level after a run."""

    levels: dict[str, int] = field(default_factory=dict)
    routes: int = 0
    errors: list[str] = field(default_factory=list)


def classify_bind(host_ip: str | None) -> tuple[ExposureLevel, str]:
    """Exposure implied by the host address a port is published on."""
    if host_ip in (None, "", "0.0.0.0", "::"):  # noqa: S104 - classifying, not binding
        return ExposureLevel.LAN, "all host interfaces"
    try:
        ip = ipaddress.ip_address(host_ip)
    except ValueError:
        return ExposureLevel.LAN, f"host address {host_ip}"
    if ip.is_loopback:
        return ExposureLevel.LOCALHOST, f"loopback {host_ip}"
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return ExposureLevel.LAN, f"tailnet/CGNAT address {host_ip}"
    if ip.is_private or ip.is_link_local:
        return ExposureLevel.LAN, f"private address {host_ip}"
    return ExposureLevel.INTERNET, f"public address {host_ip}"


def is_internet_hostname(hostname: str, patterns: list[str]) -> bool:
    """True if ``hostname`` matches an ``INTERNET_HOSTNAME_PATTERNS`` glob (case-insensitive)."""
    host = hostname.lower().rstrip(".")
    return any(fnmatch.fnmatchcase(host, pat.lower()) for pat in patterns)


def route_level(route: ProxyRoute, patterns: list[str]) -> tuple[ExposureLevel, str]:
    """Exposure granted by one proxy route."""
    public = [h for h in route.hostnames if is_internet_hostname(h, patterns)]
    if public and not route.lan_only:
        return ExposureLevel.INTERNET, f"{route.describe()}; public hostname {public[0]}"
    note = "restricted to private client IPs" if route.lan_only else "hostname not public"
    return ExposureLevel.LAN, f"{route.describe()}; {note}"


def match_route(
    route: ProxyRoute, containers: list[ContainerInfo], host_ips: list[str]
) -> list[ContainerInfo]:
    """Containers a route's upstream refers to (by name, compose service, IP or published port)."""
    if route.target_container:
        return [c for c in containers if c.name == route.target_container]
    host = (route.upstream_host or "").lower()
    if not host:
        return []
    direct = [
        c
        for c in containers
        if host in (c.name.lower(), c.labels.get("com.docker.compose.service", "").lower())
        or host in c.ip_addresses
    ]
    if direct:
        return direct
    if host in LOOPBACK_UPSTREAMS or host in host_ips:
        return [c for c in containers if any(p.public_port == route.upstream_port for p in c.ports)]
    return []


def analyze_containers(
    containers: list[ContainerInfo],
    routes: list[ProxyRoute],
    settings: Settings,
    nmap: NmapResult | None = None,
) -> dict[str, Exposure]:
    """Exposure for every container, keyed by container name."""
    result = {c.name: Exposure() for c in containers}
    patterns = settings.internet_hostname_patterns
    host_ips = settings.host_lan_ips

    for c in containers:
        exp = result[c.name]
        if (c.network_mode or "") == "host":
            exp.raise_to(
                ExposureLevel.LAN, "network_mode=host: all listening ports on host interfaces"
            )
        for port in c.ports:
            if port.public_port is None:
                continue
            level, why = classify_bind(port.host_ip)
            exp.raise_to(level, f"port {port.public_port}/{port.protocol} published on {why}")

    traefik_level: tuple[ExposureLevel, str] | None = None
    for route in routes:
        level, why = route_level(route, patterns)
        targets = match_route(route, containers, host_ips)
        for target in targets:
            result[target.name].raise_to(level, why)
        if route.owner and route.owner in result:
            result[route.owner].raise_to(level, f"serves {why}")
        if route.kind == "traefik" and (
            traefik_level is None or level.rank > traefik_level[0].rank
        ):
            traefik_level = (level, why)
        if not targets:
            log.debug("route matched no container: %s", route.describe())
    if traefik_level is not None:
        for c in containers:
            if "traefik" in c.image.lower():
                result[c.name].raise_to(
                    traefik_level[0], f"Traefik entrypoint for {traefik_level[1]}"
                )

    if nmap is not None:
        for ip, ports in nmap.open_ports.items():
            if ip not in host_ips:
                continue
            for c in containers:
                for port in c.ports:
                    if port.public_port in ports:
                        result[c.name].raise_to(
                            ExposureLevel.LAN, f"nmap: port {port.public_port} open on {ip}"
                        )
    return result


def apply_exposure(
    session: Session,
    settings: Settings,
    containers: list[ContainerInfo],
    routes: list[ProxyRoute],
    nmap: NmapResult | None = None,
    now: datetime | None = None,
) -> ExposureSummary:
    """Compute and store ``exposure_level``/``exposure_evidence`` on every active asset."""
    now = now or utcnow()
    per_container = analyze_containers(containers, routes, settings, nmap)
    overrides = {
        name: ExposureLevel(level.strip().lower())
        for name, level in settings.parsed_targets("exposure_overrides")
        if level.strip().lower() in {lvl.value for lvl in ExposureLevel}
    }
    summary = ExposureSummary(routes=len(routes))
    for asset in session.scalars(select(Asset).where(Asset.active)):
        exp = Exposure()
        if asset.kind == AssetKind.IMAGE:
            for name in asset.containers:
                c_exp = per_container.get(name)
                if c_exp is None:
                    continue
                for line in c_exp.evidence:
                    exp.raise_to(ExposureLevel.NONE, f"{name}: {line}")
                exp.level = ExposureLevel.most_exposed([exp.level, c_exp.level])
            if not exp.evidence:
                exp.evidence.append("no published ports or proxy routes found")
        elif asset.kind == AssetKind.HOST:
            exp.raise_to(
                ExposureLevel(settings.host_exposure),
                f"host default (HOST_EXPOSURE={settings.host_exposure})",
            )
        else:
            exp.evidence.append("directory scan: no network exposure of its own")
        forced = overrides.get(asset.name) or overrides.get(asset.ref)
        if forced is not None:
            exp.level = forced
            exp.evidence.append(f"override: EXPOSURE_OVERRIDES sets {forced.value}")
        asset.exposure_level = exp.level
        asset.exposure_evidence = exp.evidence
        asset.exposure_updated_at = now
        summary.levels[exp.level.value] = summary.levels.get(exp.level.value, 0) + 1
    session.flush()
    return summary

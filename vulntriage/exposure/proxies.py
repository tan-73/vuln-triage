"""Reverse-proxy route discovery: Nginx (incl. Nginx Proxy Manager), Caddy and Traefik labels.

Each parser yields :class:`ProxyRoute` objects: *which hostnames* reach *which upstream*.
The parsers are deliberately tolerant, best-effort readers of common configurations,
not full grammars. Anything they cannot interpret is skipped rather than guessed.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from vulntriage.scanners.docker_api import ContainerInfo

log = logging.getLogger(__name__)


@dataclass
class ProxyRoute:
    """One hostname set routed by a proxy to one upstream."""

    kind: str
    hostnames: list[str]
    upstream_host: str | None
    upstream_port: int | None
    source: str
    owner: str | None = None
    lan_only: bool = False
    target_container: str | None = None

    def describe(self) -> str:
        """Short text for evidence lists."""
        hosts = ", ".join(self.hostnames) or "(any host)"
        up = (
            f"{self.upstream_host}:{self.upstream_port}"
            if self.upstream_port
            else self.upstream_host
        )
        return f"{self.kind} route {hosts} -> {up or self.target_container} ({self.source})"


def _is_private_range(value: str) -> bool:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return value in ("private_ranges", "localhost")
    return bool(net.is_private)


def split_upstream(value: str) -> tuple[str | None, int | None]:
    """Parse ``http://host:port/path``, ``host:port`` or ``host`` into ``(host, port)``."""
    value = value.strip().strip('"').strip("'")
    if not value or value.startswith(("unix:", "unix/", "{", "$")):
        return None, None
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None, None
    if port is None:
        port = {"http": 80, "https": 443, "h2c": 80, "grpc": 80}.get(parts.scheme)
    return parts.hostname, port


def _iter_files(path: Path, patterns: tuple[str, ...]) -> Iterator[Path]:
    if path.is_file():
        yield path
    elif path.is_dir():
        for pattern in patterns:
            yield from sorted(p for p in path.rglob(pattern) if p.is_file())
    else:
        log.warning("proxy config path does not exist: %s", path)


# --- Nginx -------------------------------------------------------------------------------


@dataclass
class _Directive:
    name: str
    args: list[str]
    children: list[_Directive] | None = None


_NGINX_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};]+')


def _nginx_tokens(text: str) -> list[str]:
    text = re.sub(r"(^|\s)#[^\n]*", r"\1", text)
    return _NGINX_TOKEN.findall(text)


def _nginx_tree(tokens: list[str]) -> list[_Directive]:
    root: list[_Directive] = []
    stack: list[list[_Directive]] = [root]
    current: list[str] = []
    for tok in tokens:
        if tok == ";":
            if current:
                stack[-1].append(_Directive(current[0], current[1:]))
            current = []
        elif tok == "{":
            node = _Directive(current[0] if current else "", current[1:], [])
            stack[-1].append(node)
            stack.append(node.children)  # type: ignore[arg-type]
            current = []
        elif tok == "}":
            current = []
            if len(stack) > 1:
                stack.pop()
        else:
            current.append(tok.strip('"').strip("'"))
    return root


def _walk(nodes: Iterable[_Directive], name: str) -> Iterator[_Directive]:
    for node in nodes:
        if node.name == name:
            yield node
        if node.children:
            yield from _walk(node.children, name)


def _substitute(value: str, variables: dict[str, str]) -> str:
    return re.sub(r"\$\{?(\w+)\}?", lambda m: variables.get(m.group(1), m.group(0)), value)


def _nginx_lan_only(block: list[_Directive]) -> bool:
    allows = [d.args[0] for d in block if d.name == "allow" and d.args]
    denies_all = any(d.name == "deny" and d.args == ["all"] for d in block)
    return bool(allows) and denies_all and all(_is_private_range(a) for a in allows)


def parse_nginx(text: str, source: str, owner: str | None = None) -> list[ProxyRoute]:
    """Extract routes from nginx config text (``server`` blocks, ``upstream`` blocks).

    Understands plain ``proxy_pass``, ``upstream`` groups, and Nginx Proxy Manager's
    generated files (``set $server ...; set $port ...;`` plus ``include .../proxy.conf``).
    """
    tree = _nginx_tree(_nginx_tokens(text))
    upstreams: dict[str, list[str]] = {}
    for up in _walk(tree, "upstream"):
        if up.args and up.children:
            upstreams[up.args[0]] = [
                d.args[0] for d in up.children if d.name == "server" and d.args
            ]

    routes: list[ProxyRoute] = []
    for server in _walk(tree, "server"):
        if server.children is None:
            continue  # a `server` line inside an upstream block
        block = server.children
        names = [
            n for d in block if d.name == "server_name" for n in d.args if n not in ("_", '""')
        ]
        server_vars = {
            d.args[0].lstrip("$"): d.args[1] for d in block if d.name == "set" and len(d.args) >= 2
        }
        server_lan_only = _nginx_lan_only(block)

        def targets(
            nodes: list[_Directive], variables: dict[str, str], lan_only: bool
        ) -> Iterator[tuple[str, bool]]:
            local_vars = {
                **variables,
                **{
                    d.args[0].lstrip("$"): d.args[1]
                    for d in nodes
                    if d.name == "set" and len(d.args) >= 2
                },
            }
            for d in nodes:
                if d.name in ("proxy_pass", "grpc_pass") and d.args:
                    yield _substitute(d.args[0], local_vars), lan_only
                elif (
                    d.name == "include"
                    and d.args
                    and d.args[0].endswith("proxy.conf")
                    and "server" in local_vars
                ):
                    scheme = local_vars.get("forward_scheme", "http")
                    port = local_vars.get("port", "80")
                    yield f"{scheme}://{local_vars['server']}:{port}", lan_only
                elif d.name == "location" and d.children is not None:
                    yield from targets(
                        d.children, local_vars, lan_only or _nginx_lan_only(d.children)
                    )

        seen: set[tuple[str | None, int | None]] = set()
        for target, lan_only in targets(block, server_vars, server_lan_only):
            host, port = split_upstream(target)
            hosts = upstreams.get(host or "")
            resolved = [split_upstream(h) for h in hosts] if hosts else [(host, port)]
            for up_host, up_port in resolved:
                if up_host is None or (up_host, up_port) in seen:
                    continue
                seen.add((up_host, up_port))
                routes.append(ProxyRoute("nginx", names, up_host, up_port, source, owner, lan_only))
    return routes


# --- Caddy -------------------------------------------------------------------------------


def _caddy_address_host(address: str) -> str:
    address = address.strip().rstrip(",")
    if "://" in address:
        address = address.split("://", 1)[1]
    address = address.split("/", 1)[0]
    if address.startswith("["):
        return address.split("]")[0].lstrip("[")
    return address.rsplit(":", 1)[0] if ":" in address else address


def parse_caddyfile(text: str, source: str, owner: str | None = None) -> list[ProxyRoute]:
    """Extract ``reverse_proxy`` routes per site block from a Caddyfile.

    A site is treated as LAN-only when it uses a ``remote_ip``/``client_ip`` matcher with
    only private ranges together with ``abort`` or a 403 response (the usual idiom).
    """
    routes: list[ProxyRoute] = []
    depth = 0
    site: list[str] | None = None
    site_lines: list[str] = []
    in_proxy_block = False
    proxy_upstreams: list[str] = []

    def flush_site() -> None:
        if site is None:
            return
        body = "\n".join(site_lines)
        ranges = re.findall(r"(?:remote_ip|client_ip)\s+([^\n{}]+)", body)
        private = bool(ranges) and all(
            _is_private_range(r) for line in ranges for r in line.split()
        )
        lan_only = private and bool(re.search(r"\babort\b|\brespond\b[^\n]*\b403\b", body))
        hosts = [h for h in (_caddy_address_host(a) for a in site) if h]
        for upstream in proxy_upstreams:
            host, port = split_upstream(upstream)
            if host:
                routes.append(ProxyRoute("caddy", hosts, host, port, source, owner, lan_only))

    for raw_line in text.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw_line).strip()
        if not line:
            continue
        opens, closes = line.count("{") - line.count("{$"), line.count("}") - line.count("{$")
        if depth == 0 and line.endswith("{"):
            header = line[:-1].strip()
            site = (
                None if (not header or header.startswith("(")) else header.replace(",", " ").split()
            )
            site_lines, proxy_upstreams = [], []
        elif site is not None:
            site_lines.append(line)
            tokens = line.split()
            if tokens[0] == "reverse_proxy":
                ups = [t for t in tokens[1:] if t != "{" and not t.startswith(("@", "/", "*"))]
                proxy_upstreams.extend(ups)
                in_proxy_block = line.endswith("{")
            elif in_proxy_block and tokens[0] == "to":
                proxy_upstreams.extend(tokens[1:])
        depth += opens - closes
        if in_proxy_block and closes and depth <= 1:
            in_proxy_block = False
        if depth == 0 and site is not None and closes:
            flush_site()
            site = None
    return routes


# --- Traefik labels ------------------------------------------------------------------------

_HOST_RULE = re.compile(r"Host(?:SNI)?\(([^)]*)\)")


def parse_traefik_labels(container: ContainerInfo) -> list[ProxyRoute]:
    """Routes declared by Traefik docker labels on ``container`` (the upstream itself)."""
    labels = container.labels
    if labels.get("traefik.enable", "").lower() == "false":
        return []
    rules: dict[str, str] = {}
    for key, value in labels.items():
        m = re.fullmatch(r"traefik\.(?:http|tcp)\.routers\.([^.]+)\.rule", key)
        if m:
            rules[m.group(1)] = value
    port_key = re.compile(r"traefik\.(?:http|tcp)\.services\.[^.]+\.loadbalancer\.server\.port")
    ports = [int(v) for k, v in labels.items() if port_key.fullmatch(k) and v.isdigit()]
    port = ports[0] if ports else next((p.private_port for p in container.ports), None)
    routes = []
    for router, rule in sorted(rules.items()):
        hosts = [h.strip().strip("`\"' ") for m in _HOST_RULE.findall(rule) for h in m.split(",")]
        routes.append(
            ProxyRoute(
                "traefik",
                [h for h in hosts if h],
                container.name,
                port,
                f"traefik labels on {container.name} (router {router})",
                target_container=container.name,
            )
        )
    return routes


# --- loading -----------------------------------------------------------------------------


def load_routes(
    nginx_paths: list[tuple[str, str]],
    caddy_paths: list[tuple[str, str]],
    containers: list[ContainerInfo],
    traefik_labels: bool = True,
) -> tuple[list[ProxyRoute], list[str]]:
    """Read every configured proxy source. Returns ``(routes, errors)``.

    Path entries are ``(owner, path)`` pairs; when ``owner`` differs from the path it names
    the proxy container that serves the config.
    """
    routes: list[ProxyRoute] = []
    errors: list[str] = []
    for kind, entries, patterns, parser in (
        ("nginx", nginx_paths, ("*.conf",), parse_nginx),
        ("caddy", caddy_paths, ("Caddyfile", "*.caddy", "*.caddyfile"), parse_caddyfile),
    ):
        for owner, path in entries:
            owner_name = owner if owner != path else None
            for file in _iter_files(Path(path), patterns):
                try:
                    routes += parser(
                        file.read_text(encoding="utf-8", errors="replace"), str(file), owner_name
                    )
                except (OSError, ValueError, IndexError) as exc:
                    errors.append(f"{kind} config {file}: {exc}")
    if traefik_labels:
        for container in containers:
            routes += parse_traefik_labels(container)
    return routes, errors

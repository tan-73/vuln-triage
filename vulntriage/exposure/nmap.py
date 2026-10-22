"""Optional nmap TCP connect scan, restricted by :class:`~vulntriage.exposure.guard.ScanScopeGuard`.

Uses ``-sT`` (connect scan) so no raw sockets or root are needed, ``-Pn -n`` to skip host
discovery and DNS, and ``--open`` to report only open ports.
"""

from __future__ import annotations

import logging
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from vulntriage.exposure.guard import ScanScopeGuard
from vulntriage.scanners.base import Runner

log = logging.getLogger(__name__)


@dataclass
class NmapResult:
    """Open TCP ports per IP address, plus refused targets and errors."""

    open_ports: dict[str, set[int]] = field(default_factory=dict)
    refused: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def parse_nmap_xml(xml_text: str) -> dict[str, set[int]]:
    """Parse ``nmap -oX`` output into ``{ip: {open tcp ports}}``."""
    root = ET.fromstring(xml_text)  # noqa: S314 - trusted local nmap output
    out: dict[str, set[int]] = {}
    for host in root.iter("host"):
        addr = next(
            (a.get("addr") for a in host.iter("address") if a.get("addrtype") in ("ipv4", "ipv6")),
            None,
        )
        if not addr:
            continue
        ports = {
            int(p.get("portid", "0"))
            for p in host.iter("port")
            if p.get("protocol") == "tcp"
            and (state := p.find("state")) is not None
            and state.get("state") == "open"
        }
        if ports:
            out[addr] = ports
    return out


def run_nmap(
    targets: list[str],
    guard: ScanScopeGuard,
    binary: str = "nmap",
    top_ports: int = 200,
    timeout: int = 600,
    runner: Runner = subprocess.run,
) -> NmapResult:
    """Scan every in-scope target; out-of-scope targets are refused and never passed to nmap."""
    result = NmapResult()
    allowed, result.refused = guard.filter(targets)
    for target in allowed:
        cmd = [
            binary,
            "-sT",
            "-Pn",
            "-n",
            "--open",
            "--top-ports",
            str(top_ports),
            "-oX",
            "-",
            target,
        ]
        try:
            proc = runner(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            result.errors.append(f"nmap {target}: {exc}")
            continue
        if proc.returncode != 0:
            result.errors.append(f"nmap {target}: exit {proc.returncode}")
            continue
        try:
            for ip, ports in parse_nmap_xml(proc.stdout).items():
                result.open_ports.setdefault(ip, set()).update(ports)
        except ET.ParseError as exc:
            result.errors.append(f"nmap {target}: unparsable XML ({exc})")
    return result

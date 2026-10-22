"""Scan-scope guard: network scans may only target allow-listed, non-public ranges.

Every nmap target passes through :meth:`ScanScopeGuard.check`. A target is accepted only
if it is a literal IP address or CIDR (hostnames are refused because DNS could point
anywhere), lies entirely inside one of ``ALLOWED_SCAN_CIDRS``, and is non-public address
space. Refusals are logged at WARNING level.
"""

from __future__ import annotations

import ipaddress
import logging

from vulntriage.config import is_non_public_network

log = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeViolation(ValueError):
    """Raised for a scan target outside the allowed scope."""


class ScanScopeGuard:
    """Validates network-scan targets against an allow-list of private CIDRs."""

    def __init__(self, allowed_cidrs: list[str]) -> None:
        self.allowed: list[IPNetwork] = []
        for cidr in allowed_cidrs:
            if not is_non_public_network(cidr):
                raise ScopeViolation(f"allow-list entry {cidr!r} is public address space")
            self.allowed.append(ipaddress.ip_network(cidr, strict=False))

    def check(self, target: str) -> IPNetwork:
        """Return the parsed network for ``target`` or raise :class:`ScopeViolation`."""
        try:
            net = ipaddress.ip_network(target.strip(), strict=False)
        except ValueError:
            return self._refuse(target, "not a literal IP address or CIDR")
        if not is_non_public_network(str(net)):
            return self._refuse(target, "public address space is never scanned")
        if not any(
            net.version == allowed.version and net.subnet_of(allowed)  # type: ignore[arg-type]
            for allowed in self.allowed
        ):
            return self._refuse(target, "not inside ALLOWED_SCAN_CIDRS")
        return net

    def filter(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """Split ``targets`` into ``(allowed, refused_messages)``."""
        ok: list[str] = []
        refused: list[str] = []
        for target in targets:
            try:
                ok.append(str(self.check(target)))
            except ScopeViolation as exc:
                refused.append(str(exc))
        return ok, refused

    @staticmethod
    def _refuse(target: str, reason: str) -> IPNetwork:
        msg = f"refusing to scan {target!r}: {reason}"
        log.warning(msg)
        raise ScopeViolation(msg)

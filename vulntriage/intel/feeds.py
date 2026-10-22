"""Fetchers and parsers for EPSS, CISA KEV, NVD 2.0 and OSV.

Fetchers only talk HTTP and return parsed values; caching and persistence live in
:mod:`vulntriage.intel.enrich`. All parsers are pure functions so they are easy to test.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from vulntriage.intel.http import FeedClient, RateLimiter

log = logging.getLogger(__name__)

EPSS_BATCH = 100
"""CVEs per EPSS request; keeps the query string well under URL length limits."""


# --- CISA KEV ------------------------------------------------------------------------


@dataclass(frozen=True)
class KevEntry:
    """One CISA Known Exploited Vulnerabilities catalog entry."""

    cve_id: str
    date_added: str | None
    due_date: str | None
    ransomware_use: bool
    vendor: str | None = None
    product: str | None = None
    name: str | None = None


def parse_kev(catalog: dict[str, Any]) -> dict[str, KevEntry]:
    """Index the KEV catalog JSON by CVE ID."""
    entries: dict[str, KevEntry] = {}
    for item in catalog.get("vulnerabilities") or []:
        cve = item.get("cveID")
        if not cve:
            continue
        entries[cve] = KevEntry(
            cve_id=cve,
            date_added=item.get("dateAdded"),
            due_date=item.get("dueDate"),
            ransomware_use=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            vendor=item.get("vendorProject"),
            product=item.get("product"),
            name=item.get("vulnerabilityName"),
        )
    return entries


def fetch_kev(client: FeedClient, url: str) -> dict[str, Any]:
    """Download the full KEV catalog (about 1.5 MB, one request)."""
    data: dict[str, Any] = client.get_json(url)
    if "vulnerabilities" not in data:
        raise ValueError("KEV response has no 'vulnerabilities' key")
    return data


# --- EPSS ------------------------------------------------------------------------------


@dataclass(frozen=True)
class EpssEntry:
    """EPSS probability of exploitation in the next 30 days, and its percentile."""

    cve_id: str
    epss: float
    percentile: float
    date: str | None


def _chunks(items: list[str], size: int) -> Iterator[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def parse_epss(payload: dict[str, Any]) -> dict[str, EpssEntry]:
    """Parse one EPSS API response page."""
    out: dict[str, EpssEntry] = {}
    for row in payload.get("data") or []:
        try:
            out[row["cve"]] = EpssEntry(
                cve_id=row["cve"],
                epss=float(row["epss"]),
                percentile=float(row["percentile"]),
                date=row.get("date"),
            )
        except (KeyError, TypeError, ValueError):
            log.warning("skipping malformed EPSS row: %r", row)
    return out


def fetch_epss(client: FeedClient, url: str, cves: Iterable[str]) -> dict[str, EpssEntry]:
    """Batch-query EPSS for ``cves``. CVEs unknown to EPSS are simply absent."""
    wanted = sorted({c for c in cves if c.startswith("CVE-")})
    out: dict[str, EpssEntry] = {}
    for batch in _chunks(wanted, EPSS_BATCH):
        payload = client.get_json(url, params={"cve": ",".join(batch), "limit": str(len(batch))})
        out.update(parse_epss(payload))
    return out


# --- NVD 2.0 ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NvdEntry:
    """The NVD fields VulnTriage stores."""

    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None
    cwe: str | None
    description: str | None


def nvd_limiter(has_key: bool) -> RateLimiter:
    """NVD's published limits: 5 requests / 30 s anonymously, 50 / 30 s with an API key."""
    return RateLimiter(max_calls=50 if has_key else 5, period=30.0)


def parse_nvd(payload: dict[str, Any], cve_id: str) -> NvdEntry | None:
    """Extract CVSS v3.1 (falling back to v3.0), CWE and English description."""
    for vuln in payload.get("vulnerabilities") or []:
        cve = vuln.get("cve") or {}
        if cve.get("id") != cve_id:
            continue
        metrics = cve.get("metrics") or {}
        score = vector = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            candidates = sorted(metrics.get(key) or [], key=lambda m: m.get("type") != "Primary")
            if candidates:
                data = candidates[0].get("cvssData") or {}
                score, vector = data.get("baseScore"), data.get("vectorString")
                break
        cwe = None
        for weakness in cve.get("weaknesses") or []:
            for desc in weakness.get("description") or []:
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwe = value
                    break
            if cwe:
                break
        description = next(
            (d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), None
        )
        return NvdEntry(
            cve_id=cve_id,
            cvss_score=float(score) if score is not None else None,
            cvss_vector=vector,
            cwe=cwe,
            description=description,
        )
    return None


def fetch_nvd(
    client: FeedClient,
    url: str,
    cve_id: str,
    api_key: str | None = None,
    limiter: RateLimiter | None = None,
) -> NvdEntry | None:
    """Look up one CVE in NVD 2.0. Returns ``None`` if NVD does not know it."""
    headers = {"apiKey": api_key} if api_key else None
    payload = client.get_json(url, params={"cveId": cve_id}, headers=headers, limiter=limiter)
    return parse_nvd(payload or {}, cve_id)


# --- OSV -----------------------------------------------------------------------------

#: Trivy/Grype package type -> OSV ecosystem name.
OSV_ECOSYSTEMS = {
    "python-pkg": "PyPI", "pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "uv": "PyPI",
    "python": "PyPI", "npm": "npm", "node-pkg": "npm", "yarn": "npm", "pnpm": "npm",
    "gobinary": "Go", "gomod": "Go", "go-module": "Go", "jar": "Maven", "pom": "Maven",
    "gradle": "Maven", "java-archive": "Maven", "cargo": "crates.io", "rust-binary": "crates.io",
    "rust-crate": "crates.io", "gemspec": "RubyGems", "bundler": "RubyGems", "gem": "RubyGems",
    "composer": "Packagist", "php-composer": "Packagist", "nuget": "NuGet",
    "dotnet-core": "NuGet", "dotnet": "NuGet",
}  # fmt: skip


def osv_ecosystem(package_type: str, os_name: str | None = None) -> str | None:
    """Map a scanner package type (plus OS version for distro packages) to an OSV ecosystem."""
    pkg_type = package_type.lower()
    if pkg_type in OSV_ECOSYSTEMS:
        return OSV_ECOSYSTEMS[pkg_type]
    if pkg_type in ("debian", "deb") and os_name:
        return f"Debian:{os_name.split('.')[0]}"
    if pkg_type in ("alpine", "apk") and os_name:
        major_minor = ".".join(os_name.split(".")[:2])
        return f"Alpine:v{major_minor}"
    if pkg_type == "ubuntu" and os_name:
        return f"Ubuntu:{os_name}"
    return None


def osv_version(ecosystem: str, version: str) -> str:
    """OSV's Go ecosystem uses versions without the leading ``v``."""
    return version.removeprefix("v") if ecosystem == "Go" else version


def query_osv(
    client: FeedClient, url: str, package: str, ecosystem: str, version: str | None = None
) -> dict[str, Any]:
    """POST an OSV ``/v1/query``. Without ``version`` it lists every advisory for the package."""
    body: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        body["version"] = osv_version(ecosystem, version)
    result: dict[str, Any] = client.request_json("POST", url, json=body) or {}
    return result


def osv_fixed_versions(payload: dict[str, Any], vuln_id: str, package: str) -> list[str]:
    """Fixed versions of ``package`` for the advisory matching ``vuln_id`` (ID or alias)."""
    fixed: list[str] = []
    for vuln in payload.get("vulns") or []:
        ids = {vuln.get("id"), *(vuln.get("aliases") or [])}
        if vuln_id not in ids:
            continue
        for affected in vuln.get("affected") or []:
            if (affected.get("package") or {}).get("name") != package:
                continue
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    value = event.get("fixed")
                    if value and value not in fixed:
                        fixed.append(value)
    return fixed

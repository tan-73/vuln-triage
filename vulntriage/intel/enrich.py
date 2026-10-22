"""Enrichment stage: merge EPSS, KEV, NVD and OSV data into :class:`CveIntel` and findings.

Offline tolerance: every feed is cached locally with a timestamp. A feed is only fetched
when its cache is older than its TTL. If a fetch fails (or ``OFFLINE=true``) the cached
data is used, and :class:`~vulntriage.models.FeedStatus` records the error so the report
can state how old the data is.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulntriage.config import Settings
from vulntriage.intel.cache import (
    FeedHealth,
    cache_get,
    cache_put,
    feed_health,
    is_fresh,
    record_attempt,
)
from vulntriage.intel.feeds import (
    EPSS_BATCH,
    fetch_epss,
    fetch_kev,
    fetch_nvd,
    nvd_limiter,
    osv_ecosystem,
    osv_fixed_versions,
    parse_kev,
    query_osv,
)
from vulntriage.intel.http import FeedClient, FeedError, RateLimiter
from vulntriage.models import Asset, CveIntel, Finding, FindingStatus, utcnow

log = logging.getLogger(__name__)

NVD_MAX_CONSECUTIVE_FAILURES = 3


@dataclass
class EnrichSummary:
    """What one enrichment run did."""

    cves: int = 0
    kev_listed: int = 0
    epss_updated: int = 0
    nvd_updated: int = 0
    osv_fixes: int = 0
    errors: list[str] = field(default_factory=list)
    health: dict[str, FeedHealth] = field(default_factory=dict)


def ttl_map(settings: Settings) -> dict[str, float]:
    """Per-feed cache lifetime in hours."""
    return {
        "kev": settings.intel_ttl_hours,
        "epss": settings.intel_ttl_hours,
        "osv": settings.intel_ttl_hours,
        "nvd": settings.nvd_ttl_hours,
    }


class Enricher:
    """Runs all feeds for the CVEs of currently open findings."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        client: FeedClient,
        now: datetime | None = None,
        nvd_rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.session = session
        self.settings = settings
        self.client = client
        self.now = now or utcnow()
        api_key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
        self.nvd_api_key = api_key
        self.nvd_rate_limiter = nvd_rate_limiter or nvd_limiter(bool(api_key))
        self.summary = EnrichSummary()

    # -- helpers ------------------------------------------------------------------------

    def _fail(self, feed: str, error: Exception | str) -> None:
        msg = f"{feed}: {error}"
        log.warning("feed error, using cache: %s", msg)
        self.summary.errors.append(msg)
        record_attempt(self.session, feed, str(error), self.now)

    def _intel_rows(self) -> list[CveIntel]:
        cves = sorted(
            set(
                self.session.scalars(
                    select(Finding.cve_id)
                    .where(Finding.status == FindingStatus.OPEN)
                    .where(Finding.cve_id.like("CVE-%"))
                )
            )
        )
        rows = {r.cve_id: r for r in self.session.scalars(select(CveIntel))}
        out = []
        for cve in cves:
            row = rows.get(cve)
            if row is None:
                row = CveIntel(cve_id=cve, fetched_at=self.now)
                self.session.add(row)
            out.append(row)
        self.session.flush()
        return out

    # -- feeds ----------------------------------------------------------------------------

    def kev(self, rows: list[CveIntel]) -> None:
        """Refresh the KEV catalog if stale, then flag every row."""
        entry = cache_get(self.session, "kev", "catalog")
        fresh = entry is not None and is_fresh(
            entry.fetched_at, self.settings.intel_ttl_hours, self.now
        )
        if not self.settings.offline and not fresh:
            try:
                data = fetch_kev(self.client, self.settings.kev_url)
            except (FeedError, ValueError) as exc:
                self._fail("kev", exc)
            else:
                entry = cache_put(self.session, "kev", "catalog", data, self.now)
                record_attempt(self.session, "kev", None, self.now)
        if entry is None:
            self.summary.errors.append("kev: no cached catalog; KEV status unknown")
            return
        catalog = parse_kev(entry.payload)
        for row in rows:
            kev = catalog.get(row.cve_id)
            row.in_kev = kev is not None
            row.kev_date_added = kev.date_added if kev else None
            row.kev_due_date = kev.due_date if kev else None
            row.ransomware_use = bool(kev and kev.ransomware_use)
        self.summary.kev_listed = sum(r.in_kev for r in rows)

    def epss(self, rows: list[CveIntel]) -> None:
        """Batch-refresh EPSS for rows whose score is older than the TTL."""
        if self.settings.offline:
            return
        stale = [
            r
            for r in rows
            if not is_fresh(r.epss_fetched_at, self.settings.intel_ttl_hours, self.now)
        ]
        if not stale:
            return
        ok = True
        for i in range(0, len(stale), EPSS_BATCH):
            batch = stale[i : i + EPSS_BATCH]
            try:
                scores = fetch_epss(self.client, self.settings.epss_url, [r.cve_id for r in batch])
            except FeedError as exc:
                self._fail("epss", exc)
                ok = False
                break
            for row in batch:
                hit = scores.get(row.cve_id)
                row.epss = hit.epss if hit else None
                row.epss_percentile = hit.percentile if hit else None
                row.epss_date = hit.date if hit else None
                row.epss_fetched_at = self.now
                row.fetched_at = self.now
                self.summary.epss_updated += 1
        if ok:
            record_attempt(self.session, "epss", None, self.now)

    def nvd(self, rows: list[CveIntel]) -> None:
        """Fill CVSS/CWE/description from NVD, respecting rate limits and a per-run cap."""
        mode = self.settings.nvd_mode
        if self.settings.offline or mode == "never":
            return
        candidates = [
            r
            for r in rows
            if (mode == "always" or r.cvss_score is None)
            and not is_fresh(r.nvd_fetched_at, self.settings.nvd_ttl_hours, self.now)
        ]
        # Most important first, so the per-run cap drops the least useful lookups.
        candidates.sort(key=lambda r: (not r.in_kev, -(r.epss or 0.0), r.cve_id))
        candidates = candidates[: self.settings.nvd_max_per_run]
        failures = 0
        attempted = False
        for row in candidates:
            attempted = True
            try:
                entry = fetch_nvd(
                    self.client,
                    self.settings.nvd_url,
                    row.cve_id,
                    self.nvd_api_key,
                    self.nvd_rate_limiter,
                )
            except FeedError as exc:
                failures += 1
                if failures >= NVD_MAX_CONSECUTIVE_FAILURES:
                    self._fail("nvd", f"{exc} (giving up after {failures} consecutive failures)")
                    return
                continue
            failures = 0
            row.nvd_fetched_at = self.now
            if entry is None:
                continue
            if entry.cvss_score is not None:
                row.cvss_score = entry.cvss_score
                row.cvss_vector = entry.cvss_vector
                row.cvss_source = "nvd"
            row.cwe = entry.cwe or row.cwe
            row.description = entry.description or row.description
            row.fetched_at = self.now
            self.summary.nvd_updated += 1
        if attempted:
            record_attempt(self.session, "nvd", None, self.now)

    def osv(self) -> None:
        """Look up fix versions in OSV for open findings the scanner reported as unfixed."""
        stmt = (
            select(Finding, Asset)
            .join(Asset, Finding.asset_id == Asset.id)
            .where(Finding.status == FindingStatus.OPEN, Finding.fixed_version.is_(None))
        )
        queries: dict[tuple[str, str, str], list[Finding]] = {}
        for finding, asset in self.session.execute(stmt):
            eco = osv_ecosystem(finding.package_type, asset.os_name)
            if eco:
                key = (eco, finding.package_name, finding.installed_version)
                queries.setdefault(key, []).append(finding)
        budget = self.settings.osv_max_per_run
        attempted = feed_down = False
        for (eco, pkg, version), findings in sorted(queries.items()):
            cache_key = f"{eco}|{pkg}|{version}"
            entry = cache_get(self.session, "osv", cache_key)
            fresh = entry is not None and is_fresh(
                entry.fetched_at, self.settings.intel_ttl_hours, self.now
            )
            if not fresh and not self.settings.offline and not feed_down and budget > 0:
                budget -= 1
                attempted = True
                try:
                    payload = query_osv(self.client, self.settings.osv_url, pkg, eco, version)
                except FeedError as exc:
                    self._fail("osv", exc)
                    feed_down = True  # keep going with cached answers only
                else:
                    entry = cache_put(self.session, "osv", cache_key, payload, self.now)
            if entry is None:
                continue
            for finding in findings:
                fixed = osv_fixed_versions(entry.payload, finding.cve_id, pkg)
                if fixed:
                    finding.fixed_version = ", ".join(fixed)
                    finding.fixed_version_source = "osv"
                    self.summary.osv_fixes += 1
        if attempted and not feed_down:
            record_attempt(self.session, "osv", None, self.now)

    def run(self) -> EnrichSummary:
        """Run every feed; never raises for feed failures (they are recorded instead)."""
        rows = self._intel_rows()
        self.summary.cves = len(rows)
        self.kev(rows)
        self.epss(rows)
        self.nvd(rows)
        self.osv()
        self.session.flush()
        self.summary.health = feed_health(self.session, ttl_map(self.settings), self.now)
        log.info(
            "enriched %d CVEs: %d KEV, %d EPSS updated, %d NVD updated, %d OSV fixes",
            self.summary.cves,
            self.summary.kev_listed,
            self.summary.epss_updated,
            self.summary.nvd_updated,
            self.summary.osv_fixes,
        )
        return self.summary


def enrich(
    session: Session,
    settings: Settings,
    client: FeedClient | None = None,
    now: datetime | None = None,
    nvd_rate_limiter: RateLimiter | None = None,
) -> EnrichSummary:
    """Convenience wrapper that builds a :class:`FeedClient` from settings if needed."""
    own = client is None
    client = client or FeedClient(
        timeout=settings.http_timeout_seconds, max_retries=settings.http_max_retries
    )
    try:
        return Enricher(session, settings, client, now, nvd_rate_limiter).run()
    finally:
        if own:
            client.close()

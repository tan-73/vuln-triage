"""Local cache of feed payloads and feed health, stored in the main database."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulntriage.models import FeedCacheEntry, FeedStatus, utcnow

FEEDS = ("kev", "epss", "nvd", "osv")


def cache_get(session: Session, feed: str, key: str) -> FeedCacheEntry | None:
    """Return the cached entry for ``(feed, key)`` if present."""
    return session.scalar(
        select(FeedCacheEntry).where(FeedCacheEntry.feed == feed, FeedCacheEntry.key == key)
    )


def cache_put(
    session: Session, feed: str, key: str, payload: dict[str, Any], now: datetime | None = None
) -> FeedCacheEntry:
    """Insert or replace the cached payload for ``(feed, key)``."""
    entry = cache_get(session, feed, key)
    if entry is None:
        entry = FeedCacheEntry(feed=feed, key=key)
        session.add(entry)
    entry.payload = payload
    entry.fetched_at = now or utcnow()
    session.flush()
    return entry


def is_fresh(fetched_at: datetime | None, ttl_hours: float, now: datetime | None = None) -> bool:
    """True if ``fetched_at`` is within ``ttl_hours`` of ``now``."""
    if fetched_at is None:
        return False
    return (now or utcnow()) - fetched_at < timedelta(hours=ttl_hours)


def record_attempt(
    session: Session, feed: str, error: str | None = None, now: datetime | None = None
) -> FeedStatus:
    """Record a fetch attempt; a ``None`` error counts as success."""
    now = now or utcnow()
    status = session.get(FeedStatus, feed)
    if status is None:
        status = FeedStatus(feed=feed)
        session.add(status)
    status.last_attempt_at = now
    if error is None:
        status.last_success_at = now
        status.last_error = None
    else:
        status.last_error = error[:2000]
    session.flush()
    return status


@dataclass(frozen=True)
class FeedHealth:
    """How current one feed's data is, for display in reports."""

    feed: str
    last_success_at: datetime | None
    age_hours: float | None
    stale: bool
    last_error: str | None

    def describe(self) -> str:
        """One-line human summary, e.g. ``epss: 3.2 days old (stale; last error: HTTP 503)``."""
        if self.last_success_at is None or self.age_hours is None:
            text = f"{self.feed}: never fetched"
        elif self.age_hours < 48:
            text = f"{self.feed}: {self.age_hours:.1f} h old"
        else:
            text = f"{self.feed}: {self.age_hours / 24:.1f} days old"
        notes = []
        if self.stale and self.last_success_at is not None:
            notes.append("stale")
        if self.last_error:
            notes.append(f"last error: {self.last_error}")
        return f"{text} ({'; '.join(notes)})" if notes else text


def feed_health(
    session: Session, ttl_hours: dict[str, float], now: datetime | None = None
) -> dict[str, FeedHealth]:
    """Health for every known feed. A feed is stale when older than twice its TTL."""
    now = now or utcnow()
    out: dict[str, FeedHealth] = {}
    for feed in FEEDS:
        status = session.get(FeedStatus, feed)
        last = status.last_success_at if status else None
        age = (now - last).total_seconds() / 3600 if last else None
        ttl = ttl_hours.get(feed, 24.0)
        out[feed] = FeedHealth(
            feed=feed,
            last_success_at=last,
            age_hours=age,
            stale=age is None or age > 2 * ttl,
            last_error=status.last_error if status else None,
        )
    return out

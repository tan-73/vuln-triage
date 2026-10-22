"""SQLAlchemy 2.0 ORM models.

Portable across SQLite and PostgreSQL: only generic column types are used, and all
timestamps are stored as UTC (see :class:`UTCDateTime`).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Store naive UTC, always return aware UTC (SQLite drops tzinfo otherwise)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    """Declarative base with JSON mapping for dict/list annotations."""

    type_annotation_map = {
        dict[str, Any]: JSON,
        list[Any]: JSON,
        list[str]: JSON,
        datetime: UTCDateTime,
    }


class AssetKind(StrEnum):
    """What was scanned."""

    IMAGE = "image"
    HOST = "host"
    FS = "fs"


class ExposureLevel(StrEnum):
    """How reachable an asset is, from most to least exposed."""

    INTERNET = "internet"
    LAN = "lan"
    LOCALHOST = "localhost"
    NONE = "none"

    @property
    def rank(self) -> int:
        """3 for internet down to 0 for none; higher means more exposed."""
        return {"internet": 3, "lan": 2, "localhost": 1, "none": 0}[self.value]

    @classmethod
    def most_exposed(cls, levels: list[ExposureLevel]) -> ExposureLevel:
        """The highest exposure in ``levels`` (``NONE`` for an empty list)."""
        return max(levels, key=lambda lvl: lvl.rank, default=cls.NONE)


class FindingStatus(StrEnum):
    """Lifecycle of a finding across scan runs."""

    OPEN = "open"
    RESOLVED = "resolved"


class Asset(Base):
    """A scanned thing: a container image (name + tag) or a host / directory."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("kind", "name", "tag", name="uq_asset_identity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(512))
    tag: Mapped[str] = mapped_column(String(256), default="")
    digest: Mapped[str | None] = mapped_column(String(128))
    os_family: Mapped[str | None] = mapped_column(String(64))
    os_name: Mapped[str | None] = mapped_column(String(64))
    containers: Mapped[list[str]] = mapped_column(default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_scanned: Mapped[datetime | None]
    exposure_level: Mapped[str] = mapped_column(String(16), default=ExposureLevel.NONE)
    #: Human-readable reasons for ``exposure_level`` (one string per signal).
    exposure_evidence: Mapped[list[str]] = mapped_column(default=list)
    exposure_updated_at: Mapped[datetime | None]

    findings: Mapped[list[Finding]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )

    @property
    def ref(self) -> str:
        """Human-readable reference, e.g. ``nginx:1.25.1`` or ``host:nas``."""
        if self.kind == AssetKind.IMAGE:
            return f"{self.name}:{self.tag}" if self.tag else self.name
        return f"{self.kind}:{self.name}"


class Finding(Base):
    """One vulnerability in one package of one asset, deduplicated across runs."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "asset_id", "cve_id", "package_name", "target", name="uq_finding_identity"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    #: Usually a CVE ID; may be a GHSA/OSV ID when no CVE alias exists.
    cve_id: Mapped[str] = mapped_column(String(64), index=True)
    package_name: Mapped[str] = mapped_column(String(256))
    #: Scanner package type, e.g. ``debian``, ``alpine``, ``python-pkg``, ``gobinary``.
    package_type: Mapped[str] = mapped_column(String(64), default="")
    #: Normalised location: ``os`` for OS packages, else the file path inside the asset.
    target: Mapped[str] = mapped_column(String(1024), default="os")
    installed_version: Mapped[str] = mapped_column(String(256), default="")
    fixed_version: Mapped[str | None] = mapped_column(String(256))
    fixed_version_source: Mapped[str | None] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    title: Mapped[str | None] = mapped_column(Text)
    scanner: Mapped[str] = mapped_column(String(64), default="trivy")
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default=FindingStatus.OPEN, index=True)
    resolved_at: Mapped[datetime | None]
    resolution_reason: Mapped[str | None] = mapped_column(String(64))
    #: Deterministic risk score (see ``vulntriage.scoring``); ``None`` until scored.
    score: Mapped[float | None] = mapped_column(Float, index=True)
    #: Machine- and human-readable explanation of ``score``.
    score_breakdown: Mapped[dict[str, Any]] = mapped_column(default=dict)
    #: Key of the remediation group this finding belongs to.
    remediation_key: Mapped[str | None] = mapped_column(String(512), index=True)
    alerted_at: Mapped[datetime | None]

    asset: Mapped[Asset] = relationship(back_populates="findings")


class CveIntel(Base):
    """Threat intelligence for a single CVE, merged from EPSS, KEV, NVD and scanner data."""

    __tablename__ = "cve_intel"

    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[str | None] = mapped_column(String(16))
    epss_fetched_at: Mapped[datetime | None]
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[str | None] = mapped_column(String(16))
    kev_due_date: Mapped[str | None] = mapped_column(String(16))
    ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    #: ``nvd`` when fetched from NVD, ``scanner`` when copied from scanner output.
    cvss_source: Mapped[str | None] = mapped_column(String(16))
    cwe: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    nvd_fetched_at: Mapped[datetime | None]
    fetched_at: Mapped[datetime] = mapped_column(default=utcnow)


class ScanRun(Base):
    """One pipeline execution: timings per stage and headline counts."""

    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None]
    status: Mapped[str] = mapped_column(String(16), default="running")
    trigger: Mapped[str] = mapped_column(String(32), default="cli")
    stage_timings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    assets_scanned: Mapped[int] = mapped_column(Integer, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, default=0)
    findings_new: Mapped[int] = mapped_column(Integer, default=0)
    findings_resolved: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list[Any]] = mapped_column(default=list)


class FeedCacheEntry(Base):
    """Raw cached payload of an external feed (whole KEV catalog, OSV query results...)."""

    __tablename__ = "feed_cache"
    __table_args__ = (UniqueConstraint("feed", "key", name="uq_feed_cache_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    feed: Mapped[str] = mapped_column(String(32))
    key: Mapped[str] = mapped_column(String(512))
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    fetched_at: Mapped[datetime] = mapped_column(default=utcnow)


class FeedStatus(Base):
    """Health of one external feed: when it last worked, and the last error if any."""

    __tablename__ = "feed_status"

    feed: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_success_at: Mapped[datetime | None]
    last_attempt_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)


class Report(Base):
    """One generated triage report and its grounding statistics."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"))
    report_date: Mapped[str] = mapped_column(String(10))
    path: Mapped[str | None] = mapped_column(String(1024))
    markdown: Mapped[str] = mapped_column(Text, default="")
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    raw_findings: Mapped[int] = mapped_column(Integer, default=0)
    actionable_findings: Mapped[int] = mapped_column(Integer, default=0)
    kev_findings: Mapped[int] = mapped_column(Integer, default=0)
    grounding_total: Mapped[int] = mapped_column(Integer, default=0)
    grounding_verified: Mapped[int] = mapped_column(Integer, default=0)
    #: ``None`` when the report made no checkable claims (e.g. the LLM call failed).
    grounding_rate: Mapped[float | None] = mapped_column(Float)
    flagged_claims: Mapped[list[Any]] = mapped_column(default=list)
    agent_turns: Mapped[int] = mapped_column(Integer, default=0)
    tool_calls: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)

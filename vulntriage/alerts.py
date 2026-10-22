"""Optional alerts (Telegram bot, SMTP email) for findings that need attention now.

An alert is sent only when there is something *new* to say:

* a KEV-listed open finding that has not been alerted on yet (a new finding, or an
  existing one whose CVE was just added to KEV), or
* a not-yet-alerted open finding with ``score >= ALERT_MIN_SCORE`` on an
  internet-exposed asset.

Each finding is alerted once (``Finding.alerted_at``). It is only marked as alerted
when at least one channel accepted the message, so a failed send is retried on the
next run.
"""

from __future__ import annotations

import logging
import smtplib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulntriage.config import Settings
from vulntriage.models import Asset, CveIntel, Finding, FindingStatus, utcnow

log = logging.getLogger(__name__)

MAX_LINES = 15


@dataclass
class AlertItem:
    """One finding worth interrupting someone for."""

    finding_id: int
    cve_id: str
    package: str
    asset: str
    exposure: str
    score: float
    kev: bool
    fixed_version: str | None

    def line(self) -> str:
        """One line of plain text."""
        tags = ["KEV"] if self.kev else []
        tags.append(self.exposure)
        fix = f", fix: {self.fixed_version}" if self.fixed_version else ", no fix yet"
        return (
            f"- {self.cve_id} in {self.package} on {self.asset} "
            f"[{', '.join(tags)}] score {self.score:.1f}{fix}"
        )


@dataclass
class AlertOutcome:
    """What :func:`dispatch_alerts` did."""

    items: list[AlertItem] = field(default_factory=list)
    sent_via: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def collect_alerts(session: Session, settings: Settings) -> list[AlertItem]:
    """Open, not-yet-alerted findings that are KEV-listed or high-risk and internet-exposed."""
    stmt = (
        select(Finding, Asset, CveIntel)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(CveIntel, CveIntel.cve_id == Finding.cve_id)
        .where(Finding.status == FindingStatus.OPEN, Finding.alerted_at.is_(None))
        .order_by(Finding.score.desc().nulls_last())
    )
    items = []
    for f, a, intel in session.execute(stmt):
        kev = bool(intel and intel.in_kev)
        hot = (f.score or 0) >= settings.alert_min_score and a.exposure_level == "internet"
        if kev or hot:
            items.append(
                AlertItem(
                    f.id,
                    f.cve_id,
                    f.package_name,
                    a.ref,
                    a.exposure_level,
                    f.score or 0.0,
                    kev,
                    f.fixed_version,
                )
            )
    return items


def format_message(items: list[AlertItem], dashboard_url: str | None = None) -> tuple[str, str]:
    """Return ``(subject, body)`` for a batch of alert items."""
    kev = sum(i.kev for i in items)
    hot = len(items) - kev
    parts = []
    if kev:
        parts.append(f"{kev} KEV-listed")
    if hot:
        parts.append(f"{hot} high-risk internet-exposed")
    subject = f"VulnTriage: {' and '.join(parts)} finding{'s' if len(items) != 1 else ''}"
    lines = [subject, ""] + [i.line() for i in items[:MAX_LINES]]
    if len(items) > MAX_LINES:
        lines.append(f"... and {len(items) - MAX_LINES} more")
    if dashboard_url:
        lines += ["", f"Dashboard: {dashboard_url.rstrip('/')}/groups"]
    return subject, "\n".join(lines)


def send_telegram(settings: Settings, text: str, client: httpx.Client | None = None) -> None:
    """POST to the Telegram Bot API. The token is never logged."""
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        raise ValueError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required")
    token = settings.telegram_bot_token.get_secret_value()
    http = client or httpx.Client(timeout=20.0)
    try:
        resp = http.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": settings.telegram_chat_id, "text": text[:4000],
                  "disable_web_page_preview": True},
        )  # fmt: skip
    except httpx.HTTPError as exc:
        raise RuntimeError(f"telegram request failed: {type(exc).__name__}") from None
    finally:
        if client is None:
            http.close()
    if resp.status_code != 200:
        raise RuntimeError(f"telegram API returned HTTP {resp.status_code}")


def send_email(
    settings: Settings,
    subject: str,
    body: str,
    smtp_factory: Callable[..., smtplib.SMTP] | None = None,
) -> None:
    """Send a plain-text email (STARTTLS on 587 by default, implicit TLS on 465)."""
    if not (settings.smtp_host and settings.smtp_from and settings.smtp_to):
        raise ValueError("SMTP_HOST, SMTP_FROM and SMTP_TO are required")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(settings.smtp_to)
    msg.set_content(body)
    implicit_tls = settings.smtp_port == 465
    factory = smtp_factory or (smtplib.SMTP_SSL if implicit_tls else smtplib.SMTP)
    with factory(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
        if settings.smtp_starttls and not implicit_tls:
            smtp.starttls()
        if settings.smtp_user and settings.smtp_password:
            smtp.login(settings.smtp_user, settings.smtp_password.get_secret_value())
        smtp.send_message(msg)


def dispatch_alerts(
    session: Session,
    settings: Settings,
    now: datetime | None = None,
    telegram_client: httpx.Client | None = None,
    smtp_factory: Callable[..., smtplib.SMTP] | None = None,
) -> AlertOutcome:
    """Send alerts on every enabled channel and mark the findings as alerted."""
    outcome = AlertOutcome()
    if not (settings.telegram_enabled or settings.smtp_enabled):
        return outcome
    outcome.items = collect_alerts(session, settings)
    if not outcome.items:
        return outcome
    subject, body = format_message(outcome.items, settings.dashboard_url)
    if settings.telegram_enabled:
        try:
            send_telegram(settings, body, telegram_client)
            outcome.sent_via.append("telegram")
        except (RuntimeError, ValueError) as exc:
            outcome.errors.append(f"telegram: {exc}")
    if settings.smtp_enabled:
        try:
            send_email(settings, subject, body, smtp_factory)
            outcome.sent_via.append("email")
        except (OSError, smtplib.SMTPException, ValueError) as exc:
            outcome.errors.append(f"email: {type(exc).__name__}: {exc}")
    if outcome.sent_via:
        stamp = now or utcnow()
        ids = {i.finding_id for i in outcome.items}
        for finding in session.scalars(select(Finding).where(Finding.id.in_(ids))):
            finding.alerted_at = stamp
        session.flush()
    for err in outcome.errors:
        log.warning("alert delivery failed: %s", err)
    return outcome

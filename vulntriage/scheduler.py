"""Nightly scheduling with APScheduler (or use system cron with ``vulntriage run``)."""

from __future__ import annotations

import logging
import threading
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from vulntriage.config import Settings
from vulntriage.db import get_engine, init_db

log = logging.getLogger(__name__)
_lock = threading.Lock()


def nightly_job(settings: Settings) -> None:
    """One pipeline run; skipped if the previous one is still going."""
    from vulntriage.pipeline import run_pipeline

    if not _lock.acquire(blocking=False):
        log.warning("previous pipeline run still in progress; skipping this trigger")
        return
    try:
        engine = get_engine(settings.database_url)
        init_db(engine)
        run_pipeline(engine, settings, trigger="schedule")
    except Exception:
        log.exception("scheduled pipeline run failed")
    finally:
        _lock.release()


def _add_job(scheduler: Any, settings: Settings) -> None:
    trigger = CronTrigger.from_crontab(settings.schedule_cron, timezone=settings.schedule_timezone)
    scheduler.add_job(
        nightly_job,
        trigger,
        args=[settings],
        id="nightly",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        replace_existing=True,
    )
    log.info(
        "nightly pipeline scheduled: '%s' (%s)", settings.schedule_cron, settings.schedule_timezone
    )


def start_background(settings: Settings) -> BackgroundScheduler:
    """Start a background scheduler inside the web process."""
    scheduler = BackgroundScheduler(timezone=settings.schedule_timezone)
    _add_job(scheduler, settings)
    scheduler.start()
    return scheduler


def run_blocking(settings: Settings) -> None:
    """Run the scheduler in the foreground until interrupted."""
    scheduler = BlockingScheduler(timezone=settings.schedule_timezone)
    _add_job(scheduler, settings)
    scheduler.start()

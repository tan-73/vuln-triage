"""Engine and session helpers. ``DATABASE_URL`` selects SQLite (default) or PostgreSQL."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from vulntriage.models import Base

_engines: dict[str, Engine] = {}


def get_engine(database_url: str) -> Engine:
    """Return a cached engine for ``database_url``, creating SQLite parent dirs as needed."""
    if database_url in _engines:
        return _engines[database_url]
    url = make_url(database_url)
    kwargs: dict[str, object] = {"future": True}
    if url.get_backend_name() == "sqlite":
        if url.database and url.database != ":memory:":
            Path(url.database).parent.mkdir(parents=True, exist_ok=True)
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(database_url, **kwargs)
    if url.get_backend_name() == "sqlite":

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    _engines[database_url] = engine
    return engine


def dispose_engine(database_url: str) -> None:
    """Close and forget the cached engine for ``database_url`` (e.g. before deleting its file)."""
    engine = _engines.pop(database_url, None)
    if engine is not None:
        engine.dispose()


def init_db(engine: Engine) -> None:
    """Create all tables that do not exist yet."""
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on error."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

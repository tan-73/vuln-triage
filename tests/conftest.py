"""Shared pytest fixtures. No test touches the network: HTTP is mocked with respx/MockTransport."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from vulntriage.config import Settings
from vulntriage.models import Base

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Belt and braces: any real socket connection attempt fails the test."""
    import socket

    def guard(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("network access attempted in a test")

    monkeypatch.setattr(socket.socket, "connect", guard)


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the repository's ``fixtures/`` directory."""
    return FIXTURES


def load_fixture(rel: str) -> Any:
    """Load a JSON fixture by path relative to ``fixtures/``."""
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings isolated from the developer's ``.env`` and real paths."""
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        offline=False,
    )


@pytest.fixture
def engine() -> Iterator[Engine]:
    """Fresh in-memory SQLite database with all tables."""
    eng = create_engine("sqlite://", future=True)
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    """A session on the in-memory database."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as sess:
        yield sess

"""Evaluation metrics and the `vulntriage eval` command."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from vulntriage.config import Settings
from vulntriage.db import get_engine, session_scope
from vulntriage.evaluation import Row, evaluate, interpret, rank, ranking_metrics, render_markdown


def row(
    i: int, score: float = 0, cvss: float = 0, epss: float = 0, kev: bool = False, **kw: Any
) -> Row:
    return Row(i, score, cvss, epss, kev, kw.get("ransomware", False), kw.get("exposure", "none"),
               kw.get("fixable", True))  # fmt: skip


def test_rank_is_deterministic_on_ties() -> None:
    rows = [row(3, score=1), row(1, score=1), row(2, score=5)]
    assert [r.id for r in rank(rows, lambda r: r.score)] == [2, 1, 3]


def test_ranking_metrics_recall_and_ranks() -> None:
    rows = [row(i, score=100 - i, kev=i in (2, 15, 30), exposure="internet" if i < 5 else "none")
            for i in range(1, 41)]  # fmt: skip
    m = ranking_metrics("x", rank(rows, lambda r: r.score))
    assert m.hits == {10: 1, 20: 2} and m.recall[20] == pytest.approx(2 / 3)
    assert (m.best_kev_rank, m.median_kev_rank) == (2, 15)
    assert m.exposed_top20 == pytest.approx(4 / 20)
    empty = ranking_metrics("none", [])
    assert empty.recall == {10: 0.0, 20: 0.0} and empty.best_kev_rank is None


def test_evaluate_demo_database(demo_env: tuple[Settings, list[Any]]) -> None:
    settings = demo_env[0]
    with session_scope(get_engine(settings.database_url)) as s:
        result = evaluate(s, settings)
    names = [m.name for m in result.rankings]
    assert names == [
        "VulnTriage",
        "VulnTriage, KEV-ablated",
        "CVSS-only baseline",
        "EPSS-only baseline",
    ]
    vt, ablated, cvss, _ = result.rankings
    assert result.kev_findings == 11 and result.kev_cves == 3
    assert vt.hits[10] == 10 and vt.recall[20] == 1.0  # KEV tier: every KEV finding first
    assert vt.recall[10] >= max(m.recall[10] for m in result.rankings[1:])
    assert ablated.median_kev_rank is not None and cvss.median_kev_rank is not None
    assert ablated.median_kev_rank < cvss.median_kev_rank  # exposure context beats CVSS
    assert result.actionable < result.open_findings * 0.1
    assert [rep["rate"] for rep in result.reports] == [1.0, 1.0, 1.0]
    assert set(result.stage_stats) == {"scan", "enrich", "exposure", "score", "report"}
    md = render_markdown(result, "demo", "repro")
    for heading in (
        "## Summary",
        "## 1. Does the ranking",
        "## 2. Noise reduction",
        "## 3. Grounding of agent output",
        "## 4. Pipeline runtime per stage",
        "## Reproduce",
    ):
        assert heading in md  # fmt: skip
    assert "Median KEV rank" in md and "**Result.**" in md
    assert any("closer to the top" in p for p in interpret(result))


def test_cli_eval_writes_markdown(demo_env: tuple[Settings, list[Any]], tmp_path: Path,
                                  monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    from typer.testing import CliRunner

    import vulntriage.cli as cli
    from vulntriage.models import Report

    monkeypatch.setattr(cli, "get_settings", lambda: demo_env[0])
    out_file = tmp_path / "EVAL.md"
    result = CliRunner(env={"COLUMNS": "250"}).invoke(
        cli.app, ["eval", "--output", str(out_file), "--reports", "2"]
    )
    assert result.exit_code == 0, result.output
    text = out_file.read_text()
    assert "KEV recall@10" in text and "Checker self-test" in text and "last 2 reports" in text
    with session_scope(get_engine(demo_env[0].database_url)) as s:
        assert s.query(Report).count() == 3  # the hallucination self-test is never stored

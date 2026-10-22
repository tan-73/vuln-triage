"""``vulntriage eval``: measure ranking quality, noise reduction, grounding and runtime.

Rankings compared on the same open findings (ties broken by finding id, so every
ranking is deterministic):

* **VulnTriage**: the stored score (KEV tier, EPSS × exposure, fix bonus, CVSS tiebreak).
* **VulnTriage, KEV-ablated**: the same score with the KEV and ransomware terms removed.
  KEV recall for the full ranking is partly circular (KEV is an input), so the ablated
  ranking shows whether EPSS × exposure alone puts known-exploited bugs near the top.
* **CVSS-only**: CVSS base score (scanner severity when no CVSS), the classic approach.
* **EPSS-only**: EPSS probability, no exposure or fix context.
"""

from __future__ import annotations

import statistics
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulntriage.agent.grounding import GroundingResult
from vulntriage.config import Settings
from vulntriage.models import Asset, CveIntel, Finding, FindingStatus, Report, ScanRun, utcnow
from vulntriage.remediation import build_groups
from vulntriage.scoring import SEVERITY_FALLBACK_CVSS

KS = (10, 20)
THRESHOLDS = (1.0, 2.0, 5.0, 10.0, 20.0)


@dataclass
class Row:
    """One open finding with the fields every ranking needs."""

    id: int
    score: float
    cvss: float
    epss: float
    kev: bool
    ransomware: bool
    exposure: str
    fixable: bool


@dataclass
class RankingMetrics:
    """Quality numbers for one ranking."""

    name: str
    hits: dict[int, int]
    recall: dict[int, float]
    fixable_top20: float
    exposed_top20: float
    best_kev_rank: int | None = None
    median_kev_rank: float | None = None


@dataclass
class EvalResult:
    """Everything written to ``docs/EVALUATION.md``."""

    generated_at: datetime
    open_findings: int
    kev_findings: int
    kev_cves: int
    actionable: int
    action_groups: int
    total_groups: int
    threshold: float
    rankings: list[RankingMetrics]
    threshold_sweep: list[tuple[float, int]]
    reports: list[dict[str, Any]]
    grounding_micro: float | None
    stage_stats: dict[str, tuple[float, float, int]]
    selftest: GroundingResult | None = None
    notes: list[str] = field(default_factory=list)


def load_rows(session: Session) -> list[Row]:
    """All open findings with intel needed for ranking."""
    stmt = (
        select(Finding, Asset, CveIntel)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(CveIntel, CveIntel.cve_id == Finding.cve_id)
        .where(Finding.status == FindingStatus.OPEN)
    )
    rows = []
    for f, a, intel in session.execute(stmt):
        cvss = intel.cvss_score if intel and intel.cvss_score is not None else None
        rows.append(
            Row(
                id=f.id,
                score=f.score or 0.0,
                cvss=cvss if cvss is not None else SEVERITY_FALLBACK_CVSS.get(f.severity, 0.0),
                epss=intel.epss if intel and intel.epss is not None else 0.0,
                kev=bool(intel and intel.in_kev),
                ransomware=bool(intel and intel.ransomware_use),
                exposure=a.exposure_level,
                fixable=bool(f.fixed_version),
            )
        )
    return rows


def rank(rows: list[Row], key: Callable[[Row], float]) -> list[Row]:
    """Sort descending by ``key``; ties broken by ascending finding id."""
    return sorted(rows, key=lambda r: (-key(r), r.id))


def ranking_metrics(name: str, ranked: list[Row], ks: tuple[int, ...] = KS) -> RankingMetrics:
    """KEV recall@k plus how actionable the top 20 are."""
    total_kev = sum(r.kev for r in ranked)
    hits = {k: sum(r.kev for r in ranked[:k]) for k in ks}
    recall = {k: (hits[k] / total_kev if total_kev else 0.0) for k in ks}
    top = ranked[:20] or [Row(0, 0, 0, 0, False, False, "none", False)]
    kev_ranks = [i for i, r in enumerate(ranked, start=1) if r.kev]
    return RankingMetrics(
        name=name,
        hits=hits,
        recall=recall,
        fixable_top20=sum(r.fixable for r in top) / len(top),
        exposed_top20=sum(r.exposure in ("internet", "lan") for r in top) / len(top),
        best_kev_rank=kev_ranks[0] if kev_ranks else None,
        median_kev_rank=statistics.median(kev_ranks) if kev_ranks else None,
    )


def evaluate(
    session: Session,
    settings: Settings,
    n_reports: int = 10,
    selftest: GroundingResult | None = None,
) -> EvalResult:
    """Compute every metric from the current database state."""
    rows = load_rows(session)
    w = settings.scoring

    def ablated(r: Row) -> float:
        return (
            r.score
            - (w.kev_tier_offset if r.kev else 0.0)
            - (w.ransomware_bonus if r.kev and r.ransomware else 0.0)
        )

    rankings = [
        ranking_metrics("VulnTriage", rank(rows, lambda r: r.score)),
        ranking_metrics("VulnTriage, KEV-ablated", rank(rows, ablated)),
        ranking_metrics("CVSS-only baseline", rank(rows, lambda r: r.cvss)),
        ranking_metrics("EPSS-only baseline", rank(rows, lambda r: r.epss)),
    ]
    groups = build_groups(session, settings)
    threshold = settings.action_threshold
    kev_cves = {
        f.cve_id
        for f in session.scalars(
            select(Finding)
            .join(CveIntel, CveIntel.cve_id == Finding.cve_id)
            .where(Finding.status == FindingStatus.OPEN, CveIntel.in_kev)
        )
    }

    reports = list(
        session.scalars(select(Report).order_by(Report.created_at.desc()).limit(n_reports))
    )[::-1]
    report_rows: list[dict[str, Any]] = [
        {
            "date": r.report_date,
            "model": f"{r.provider}/{r.model}",
            "verified": r.grounding_verified,
            "total": r.grounding_total,
            "rate": r.grounding_rate,
            "flagged": len(r.flagged_claims or []),
            "error": r.error,
        }
        for r in reports
    ]
    checked = sum(r["total"] for r in report_rows)
    micro = sum(r["verified"] for r in report_rows) / checked if checked else None

    stages: dict[str, list[float]] = {}
    for run in session.scalars(select(ScanRun).where(ScanRun.status != "running")):
        for stage, secs in (run.stage_timings or {}).items():
            stages.setdefault(stage, []).append(float(secs))
    stage_stats = {s: (statistics.mean(v), max(v), len(v)) for s, v in stages.items() if v}
    return EvalResult(
        generated_at=utcnow(),
        open_findings=len(rows),
        kev_findings=sum(r.kev for r in rows),
        kev_cves=len(kev_cves),
        actionable=sum(r.score >= threshold for r in rows),
        action_groups=sum(g.max_score >= threshold for g in groups),
        total_groups=len(groups),
        threshold=threshold,
        rankings=rankings,
        threshold_sweep=[(t, sum(r.score >= t for r in rows)) for t in THRESHOLDS],
        reports=report_rows,
        grounding_micro=micro,
        stage_stats=stage_stats,
        selftest=selftest,
    )


def interpret(r: EvalResult) -> list[str]:
    """Plain-language reading of the ranking table, generated from the numbers."""
    by = {m.name: m for m in r.rankings}
    full, abl = by["VulnTriage"], by["VulnTriage, KEV-ablated"]
    cvss, epss = by["CVSS-only baseline"], by["EPSS-only baseline"]
    if not r.kev_findings or abl.median_kev_rank is None:
        return ["_No KEV-listed findings in this dataset, so KEV recall is undefined._"]
    out = [
        f"**Result.** With KEV as an input, VulnTriage puts {full.hits[10]} of {r.kev_findings} "
        f"KEV findings in its top 10. The baselines put {cvss.hits[10]} (CVSS-only) and "
        f"{epss.hits[10]} (EPSS-only) there."
    ]
    if abl.hits[20] == 0:
        out.append(
            f"Without the KEV signal, no KEV finding reaches the top 20: the median KEV "
            f"finding sits at rank {abl.median_kev_rank:,.0f}, compared with "
            f"{cvss.median_kev_rank:,.0f} for CVSS-only and {epss.median_kev_rank:,.0f} for "
            "EPSS-only. In this dataset, non-KEV findings with higher EPSS on exposed services "
            "outrank the KEV CVEs. Exploit-prediction signals alone do not reproduce KEV, "
            "which is why KEV is a hard tier rather than just another weight."
        )
    if cvss.median_kev_rank and epss.median_kev_rank:
        out.append(
            f"Exposure and fix context still help: even without KEV, the median KEV finding "
            f"ranks {cvss.median_kev_rank / abl.median_kev_rank:.1f}× closer to the top than "
            f"with CVSS-only and {epss.median_kev_rank / abl.median_kev_rank:.1f}× closer than "
            "with EPSS-only."
        )
    else:
        out.append(
            f"Without the KEV signal, {abl.hits[20]} KEV findings still reach the top 20 "
            f"(median rank {abl.median_kev_rank:,.0f} vs. {cvss.median_kev_rank:,.0f} for "
            "CVSS-only)."
        )
    return out


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def render_markdown(result: EvalResult, dataset: str, reproduce: str) -> str:
    """Render the evaluation as Markdown."""
    r = result
    lines = [
        "# VulnTriage evaluation",
        "",
        f"_Generated by `vulntriage eval` on {r.generated_at.strftime('%Y-%m-%d %H:%M')} UTC._",
        "",
        f"**Dataset:** {dataset}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Open findings (raw scanner output, deduplicated) | {r.open_findings:,} |",
        f"| Findings needing action (score ≥ {r.threshold:g}) | {r.actionable:,} |",
        f"| Noise reduction | {_pct(1 - r.actionable / r.open_findings) if r.open_findings else 'n/a'} |",
        f"| Remediation actions needing attention | {r.action_groups} (of {r.total_groups} groups) |",
        f"| KEV-listed findings / distinct KEV CVEs | {r.kev_findings} / {r.kev_cves} |",
    ]
    vt = r.rankings[0]
    for k in KS:
        lines.append(f"| KEV recall@{k} (VulnTriage) | {_pct(vt.recall[k])} |")
    lines.append(f"| Grounding rate, last {len(r.reports)} reports | {_pct(r.grounding_micro)} |")

    lines += [
        "",
        "## 1. Does the ranking put known-exploited vulnerabilities first?",
        "",
        "KEV recall@k is the share of all KEV-listed open findings that a ranking places in its "
        f"top k. There are {r.kev_findings} KEV-listed findings, so recall@10 can be at most "
        f"{_pct(min(10, r.kev_findings) / r.kev_findings) if r.kev_findings else 'n/a'}.",
        "",
        "| Ranking | KEV in top 10 | Recall@10 | KEV in top 20 | Recall@20 | Best KEV rank | Median KEV rank | Top 20 with a fix | Top 20 exposed (internet/LAN) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for m in r.rankings:
        best = f"{m.best_kev_rank:,}" if m.best_kev_rank else "–"
        median = f"{m.median_kev_rank:,.0f}" if m.median_kev_rank else "–"
        lines.append(
            f"| {m.name} | {m.hits[10]} | {_pct(m.recall[10])} | {m.hits[20]} | {_pct(m.recall[20])} "
            f"| {best} | {median} | {_pct(m.fixable_top20)} | {_pct(m.exposed_top20)} |"
        )
    lines += ["", f"_Out of {r.open_findings:,} open findings; rank 1 is the top._", ""]
    for paragraph in interpret(r):
        lines += [paragraph, ""]
    lines += [
        "",
        "**How to read this.** VulnTriage uses KEV membership as an input, so its own KEV "
        "recall is high by construction. That is the intended behaviour, but it is not "
        "evidence of predictive skill. The **KEV-ablated** row removes the KEV and "
        "ransomware terms and ranks on EPSS × exposure (plus the fix bonus and CVSS "
        "tiebreak) alone. It shows how well the non-KEV signals surface exploited bugs, "
        "which matters for the window before CISA lists a CVE. The CVSS-only baseline is "
        "what many scanners sort by. Ties are broken by finding id, so baselines with "
        "many equal scores (CVSS 9.8, EPSS 0) are not flattered by a lucky order.",
        "",
        "## 2. Noise reduction",
        "",
        f"{r.open_findings:,} open findings → **{r.actionable:,}** need action → "
        f"**{r.action_groups}** remediation actions (one command each).",
        "",
        "Sensitivity to `ACTION_THRESHOLD`:",
        "",
        "| Threshold | Findings needing action | Share of raw |",
        "|---:|---:|---:|",
    ]
    for t, n in r.threshold_sweep:
        share = _pct(n / r.open_findings) if r.open_findings else "n/a"
        lines.append(f"| {t:g} | {n:,} | {share} |")

    lines += [
        "",
        "## 3. Grounding of agent output",
        "",
        "The share of factual claims in LLM-written text (CVE IDs, versions, package/version/"
        "asset pairs, EPSS, CVSS, KEV and exposure statements) that the post-check verified "
        "against tool results. Unverified claims are stripped from the report.",
        "",
        "| Report | Model | Verified / checked | Grounding rate | Claims removed | Agent error |",
        "|---|---|---:|---:|---:|---|",
    ]
    for rep in r.reports:
        lines.append(
            f"| {rep['date']} | {rep['model']} | {rep['verified']} / {rep['total']} | "
            f"{_pct(rep['rate'])} | {rep['flagged']} | {rep['error'] or ''} |"
        )
    if not r.reports:
        lines.append("| _no reports yet_ | | | | | |")
    lines += [
        "",
        f"Micro-averaged grounding rate: **{_pct(r.grounding_micro)}**.",
    ]
    if r.selftest is not None:
        kinds = sorted({c.kind for c in r.selftest.flagged})
        lines += [
            "",
            "**Checker self-test.** The same data was re-run with the mock agent in "
            "`hallucinate` mode, which injects an invented CVE, version, EPSS value and KEV "
            f"claim. The check verified {r.selftest.verified} of {r.selftest.total} claims "
            f"({_pct(r.selftest.rate)}) and flagged and removed {len(r.selftest.flagged)} "
            f"({', '.join(kinds)}). This shows the check catches fabrications rather than "
            "rubber-stamping everything.",
        ]
    lines += [
        "",
        "> The demo uses the deterministic mock agent, which only writes from tool results, so "
        "100% is expected there. Real models (Anthropic, Gemini, OpenAI-compatible) are "
        "measured the same way on a real homelab; see *Reproduce* below.",
        "",
        "## 4. Pipeline runtime per stage",
        "",
        "| Stage | Mean (s) | Max (s) | Runs |",
        "|---|---:|---:|---:|",
    ]
    for stage in ("scan", "enrich", "exposure", "score", "report", "alerts"):
        if stage in r.stage_stats:
            mean, mx, n = r.stage_stats[stage]
            lines.append(f"| {stage} | {mean:.2f} | {mx:.2f} | {n} |")
    lines += [
        "",
        "In the demo, *scan* replays stored Trivy JSON (parse, deduplicate and ingest), and "
        "*enrich* uses an in-process mock of the feed APIs. On a real homelab, *scan* "
        "includes Trivy itself (typically 5-60 s per image, plus a one-time database "
        "download), and *enrich* is bounded by NVD's rate limit for CVEs the scanner "
        "gave no CVSS for.",
    ]
    lines += ["", "## Reproduce", "", reproduce, ""]
    for note in r.notes:
        lines.append(f"> {note}")
    return "\n".join(lines).rstrip() + "\n"


DEMO_DATASET = (
    "bundled demo homelab (`fixtures/demo.yaml`). Seven old public container images "
    "(nginx 1.25.1→1.25.4, gitea 1.16.0, grafana 8.3.0, postgres 13.2, redis 6.2.6, "
    "python 3.11.4-slim) and one Ubuntu 22.04 host, scanned with Trivy 0.75.0 and Grype "
    "0.120.0. The data covers three simulated nightly runs. Threat intel is a real "
    "EPSS/KEV/NVD/OSV snapshot ({captured}). Container names, IPs and hostnames are "
    "fictional. `linux-libc-dev` entries in the python image are down-sampled from "
    "9,341 to 300 to keep the fixture small."
)

REPRODUCE = """\
Demo (no Docker, network or API key; numbers above):

```bash
pip install -e ".[dev]"
vulntriage eval --demo            # rebuilds the demo DB, then writes docs/EVALUATION.md
```

On your homelab, after a few nightly runs (or `vulntriage run` a few times):

```bash
vulntriage eval --output docs/EVALUATION.homelab.md --reports 14
# or inside Docker:
docker compose exec vulntriage vulntriage eval --output /reports/EVALUATION.md
```

To measure a real model's grounding rate, set `LLM_PROVIDER`/`LLM_MODEL` and the API key
in `.env` and let reports accumulate. Each report stores its verified/checked claim counts,
and `eval` aggregates the last N. Keep homelab results out of the public repo
(`reports/` and `data/` are git-ignored)."""

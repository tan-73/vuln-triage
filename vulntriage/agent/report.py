"""Assemble the nightly Markdown report from deterministic data plus grounded LLM prose.

Division of labour (hard rules 1 and 2):

* **Deterministic**: which groups appear, their order, titles, commands, fixed-version
  tables, counts, data freshness. All of these come straight from the database.
* **LLM**: the executive summary, the "why it matters" text, evidence bullets and the
  reasons something can wait. Every one of those strings goes through
  :func:`~vulntriage.agent.grounding.check_text` before it is rendered. An action or
  deferral that names a group outside the allowed set is dropped and counted as an
  ungrounded claim.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vulntriage.agent.grounding import Claim, GroundingResult, Ledger, check_text
from vulntriage.agent.runner import AgentResult, ReportDraft, TriageAgent
from vulntriage.agent.tools import Toolbox
from vulntriage.config import Settings
from vulntriage.intel.cache import FeedHealth
from vulntriage.llm.base import LLMProvider
from vulntriage.models import Asset, CveIntel, Finding, FindingStatus, Report, ScanRun, utcnow
from vulntriage.remediation import RemediationGroup, is_deferrable

log = logging.getLogger(__name__)


@dataclass
class ReportOutcome:
    """Everything produced by :func:`generate_report`."""

    report: Report
    markdown: str
    grounding: GroundingResult
    agent: AgentResult
    path: Path | None


@dataclass
class Headline:
    """Counts shown at the top of the report."""

    raw: int
    actionable: int
    kev: int
    internet_assets: int


def headline(session: Session, settings: Settings) -> Headline:
    """Raw vs. actionable counts for open findings."""
    open_q = select(func.count()).select_from(Finding).where(Finding.status == FindingStatus.OPEN)
    raw = session.scalar(open_q) or 0
    actionable = session.scalar(open_q.where(Finding.score >= settings.action_threshold)) or 0
    kev = (
        session.scalar(
            open_q.join(CveIntel, CveIntel.cve_id == Finding.cve_id).where(CveIntel.in_kev)
        )
        or 0
    )
    internet = (
        session.scalar(
            select(func.count())
            .select_from(Asset)
            .where(Asset.active, Asset.exposure_level == "internet")
        )
        or 0
    )
    return Headline(raw, actionable, kev, internet)


def _check(text: str, ledger: Ledger, grounding: GroundingResult) -> str:
    cleaned, result = check_text(text, ledger)
    grounding.extend(result)
    return cleaned.strip()


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_report(
    settings: Settings,
    groups: list[RemediationGroup],
    draft: ReportDraft | None,
    ledger: Ledger,
    head: Headline,
    agent: AgentResult,
    provider: LLMProvider,
    health: dict[str, FeedHealth] | None,
    now: datetime,
) -> tuple[str, GroundingResult]:
    """Render Markdown; returns the text and the grounding result for all LLM prose."""
    grounding = GroundingResult()
    threshold = settings.action_threshold
    actions = [g for g in groups if g.max_score >= threshold][: settings.report_top_n]
    action_keys = {g.key for g in actions}
    defer_pool = {g.key: g for g in groups if is_deferrable(g, threshold)}

    drafts = {a.group_key: a for a in (draft.actions if draft else [])}
    for key in drafts.keys() - action_keys:
        grounding.claims.append(
            Claim("group", key, False, "action for a group outside the top list")
        )

    lines = [f"# VulnTriage report: {now.date().isoformat()}", ""]
    lines.append(
        f"_Generated {now.strftime('%Y-%m-%d %H:%M')} UTC by {provider.name}/{provider.model}. "
        "The ranking is computed deterministically; the LLM only explains it._"
    )
    lines += [
        "",
        "## At a glance",
        "",
        "| Open findings | Need action | KEV-listed findings | Internet-exposed assets |",
        "|---:|---:|---:|---:|",
        f"| {head.raw:,} | {head.actionable:,} | {head.kev:,} | {head.internet_assets:,} |",
        "",
        f"Noise filtered out: **{head.raw - head.actionable:,}** findings score below the "
        f"action threshold ({threshold:g}).",
        "",
        "## Executive summary",
        "",
    ]
    if draft and draft.executive_summary:
        lines.append(_check(draft.executive_summary, ledger, grounding))
    else:
        reason = agent.error or "no summary returned"
        lines.append(
            f"_LLM summary unavailable ({reason}). "
            "The actions below are the deterministic ranking._"
        )

    lines += ["", f"## Fix these {len(actions)} things first", ""]
    if not actions:
        lines.append("Nothing scores above the action threshold. Nice.")
    for i, g in enumerate(actions, start=1):
        d = drafts.get(g.key)
        kev = ", ".join(g.kev_cves) if g.kev_cves else "none"
        lines += [
            f"### {i}. {g.title}",
            "",
            f"**Asset:** `{g.asset_ref}` · **Exposure:** {g.exposure} · **Findings:** "
            f"{g.finding_count} ({g.actionable_count} need action) · **KEV:** {kev} · "
            f"**Top score:** {g.max_score:.1f}",
            "",
        ]
        if d and d.why:
            lines += [f"**Why it matters:** {_check(d.why, ledger, grounding)}", ""]
        else:
            lines += ["**Why it matters:** _no explanation from the LLM; see score breakdown._", ""]
        if d and d.evidence:
            lines.append("**Evidence:**")
            lines += [f"- {_check(e, ledger, grounding)}" for e in d.evidence]
            lines.append("")
        if g.command:
            lines += ["**Fix:**", "", "```sh", g.command, "```", ""]
        else:
            lines += [
                "**Fix:** no fixed version is available yet. Reduce exposure or accept the risk.",
                "",
            ]
        if d and d.fix and g.command and d.fix.strip() != g.command.strip():
            lines += [f"_Agent note:_ {_check(d.fix, ledger, grounding)}", ""]
        fixed = [p for p in g.packages if p.fixed][:10]
        if fixed:
            lines += ["| Package | Installed | Fixed in | CVEs |", "|---|---|---|---|"]
            for p in fixed:
                cves = ", ".join(p.cves[:4]) + (f" +{len(p.cves) - 4}" if len(p.cves) > 4 else "")
                lines.append(
                    f"| {_md_escape(p.package)} | {_md_escape(p.installed)} | "
                    f"{_md_escape(p.fixed or '')} | {cves} |"
                )
            if len([p for p in g.packages if p.fixed]) > 10:
                lines.append(f"| … | | | {len(g.packages) - 10} more packages |")
            lines.append("")
        for note in g.notes:
            lines.append(f"> {note}")
        lines.append("")

    lines += ["## Safe to defer", ""]
    deferred = 0
    for item in draft.defer if draft else []:
        grp = defer_pool.get(item.group_key)
        if grp is None:
            grounding.claims.append(
                Claim("defer", item.group_key, False, "deferral of a group that needs action")
            )
            continue
        deferred += 1
        lines.append(
            f"- **{grp.title}** (top score {grp.max_score:.1f}, exposure {grp.exposure}): "
            f"{_check(item.reason, ledger, grounding)}"
        )
    if not deferred:
        for grp in list(defer_pool.values())[:5]:
            lines.append(
                f"- **{grp.title}** (top score {grp.max_score:.1f}, exposure {grp.exposure})"
            )
    if not defer_pool:
        lines.append(
            "_Nothing qualifies: every group needs action, is KEV-listed or is internet-exposed._"
        )

    lines += ["", "## Data freshness", ""]
    for h in (health or {}).values():
        lines.append(f"- {h.describe()}")
    if not health:
        lines.append("- feed status unavailable")

    lines += ["", "## Grounding check", ""]
    lines.append(
        f"{grounding.total} factual claims in LLM text checked against tool results: "
        f"{grounding.verified} verified ({grounding.rate:.1%})."
    )
    if grounding.flagged:
        lines.append("")
        lines.append("Removed or flagged claims:")
        lines += [f"- `{c.kind}`: {_md_escape(c.value)}" for c in grounding.flagged[:20]]
    lines += [
        "",
        f"_Agent: {agent.turns} turns, {agent.tool_calls} tool calls; ledger of "
        f"{ledger.tool_results} tool results._",
        "",
    ]
    return "\n".join(lines), grounding


def generate_report(
    session: Session,
    settings: Settings,
    provider: LLMProvider,
    run: ScanRun | None = None,
    health: dict[str, FeedHealth] | None = None,
    now: datetime | None = None,
    write: bool = True,
) -> ReportOutcome:
    """Run the agent, render and grounding-check the report, store it and write the file."""
    now = now or utcnow()
    toolbox = Toolbox(session, settings)
    agent = TriageAgent(provider, toolbox, settings.report_top_n, settings.llm_max_turns).run()
    head = headline(session, settings)
    markdown, grounding = render_report(
        settings, toolbox.groups, agent.draft, toolbox.ledger, head, agent, provider, health, now
    )
    path: Path | None = None
    if write:
        settings.reports_dir.mkdir(parents=True, exist_ok=True)
        path = settings.reports_dir / f"{now.date().isoformat()}.md"
        path.write_text(markdown, encoding="utf-8")
    report = Report(
        created_at=now,
        run_id=run.id if run else None,
        report_date=now.date().isoformat(),
        path=str(path) if path else None,
        markdown=markdown,
        provider=provider.name,
        model=provider.model,
        raw_findings=head.raw,
        actionable_findings=head.actionable,
        kev_findings=head.kev,
        grounding_total=grounding.total,
        grounding_verified=grounding.verified,
        grounding_rate=grounding.rate if grounding.total else None,
        flagged_claims=[
            {"kind": c.kind, "value": c.value, "context": c.context} for c in grounding.flagged
        ],
        agent_turns=agent.turns,
        tool_calls=agent.tool_calls,
        error=agent.error,
    )
    session.add(report)
    session.flush()
    log.info(
        "report %s: grounding %d/%d claims verified (%.1f%%)%s",
        report.report_date,
        grounding.verified,
        grounding.total,
        grounding.rate * 100,
        f"; agent error: {agent.error}" if agent.error else "",
    )
    return ReportOutcome(report, markdown, grounding, agent, path)

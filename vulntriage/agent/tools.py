"""Read-only tools exposed to the triage agent.

Every tool is a pure database query, so the agent cannot change state, scan anything or
reach the network. Each result is also recorded in a :class:`~vulntriage.agent.grounding.Ledger`,
the only source of facts the report may use.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from vulntriage.agent.grounding import Ledger
from vulntriage.agent.untrusted import wrap_untrusted
from vulntriage.config import Settings
from vulntriage.intel.feeds import OSV_ECOSYSTEMS
from vulntriage.llm.base import ToolSpec
from vulntriage.models import Asset, CveIntel, Finding, FindingStatus
from vulntriage.remediation import RemediationGroup, build_groups, is_deferrable
from vulntriage.scoring import is_actionable

log = logging.getLogger(__name__)

MAX_TOP_FINDINGS = 50

TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        "get_top_findings",
        "Highest-risk open findings in deterministic rank order (score, KEV, EPSS, exposure).",
        {
            "type": "object",
            "properties": {"n": {"type": "integer", "minimum": 1, "maximum": MAX_TOP_FINDINGS}},
            "required": ["n"],
        },
    ),
    ToolSpec(
        "get_finding",
        "Full detail for one finding id, including its score breakdown and threat intel.",
        {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]},
    ),
    ToolSpec(
        "lookup_cve",
        "Threat intel for one CVE: EPSS, CISA KEV status, CVSS, CWE, description, affected assets.",
        {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
    ),
    ToolSpec(
        "get_fix_version",
        "Installed and fixed versions of a package across assets (ecosystem optional, e.g. PyPI).",
        {
            "type": "object",
            "properties": {"package": {"type": "string"}, "ecosystem": {"type": "string"}},
            "required": ["package"],
        },
    ),
    ToolSpec(
        "get_asset_exposure",
        "Exposure level (internet/lan/localhost/none) of an asset and the evidence for it.",
        {"type": "object", "properties": {"asset": {"type": "string"}}, "required": ["asset"]},
    ),
    ToolSpec(
        "get_remediation_groups",
        "Remediation actions in deterministic rank order with commands and fixed versions, "
        "plus groups that are candidates to defer.",
        {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 30}},
        },
    ),
]


class Toolbox:
    """Executes tool calls against the database and records results in a ledger."""

    def __init__(self, session: Session, settings: Settings, ledger: Ledger | None = None) -> None:
        self.session = session
        self.settings = settings
        self.ledger = ledger or Ledger()
        self.calls: list[dict[str, Any]] = []
        self._groups: list[RemediationGroup] | None = None
        self._handlers: dict[str, Callable[..., Any]] = {
            "get_top_findings": self.get_top_findings,
            "get_finding": self.get_finding,
            "lookup_cve": self.lookup_cve,
            "get_fix_version": self.get_fix_version,
            "get_asset_exposure": self.get_asset_exposure,
            "get_remediation_groups": self.get_remediation_groups,
        }

    @property
    def groups(self) -> list[RemediationGroup]:
        """Ranked remediation groups (computed once per agent run)."""
        if self._groups is None:
            self._groups = build_groups(self.session, self.settings)
        return self._groups

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        """Run tool ``name`` and return its JSON result (errors are returned, not raised)."""
        handler = self._handlers.get(name)
        if handler is None:
            result: Any = {"error": f"unknown tool {name!r}"}
        else:
            try:
                result = handler(**arguments)
            except TypeError as exc:
                result = {"error": f"bad arguments for {name}: {exc}"}
        self.ledger.add(result)
        self.calls.append({"tool": name, "arguments": arguments})
        return json.dumps(result, default=str)

    # -- helpers ----------------------------------------------------------------------------

    def _finding_row(self, f: Finding, a: Asset, intel: CveIntel | None) -> dict[str, Any]:
        return {
            "id": f.id,
            "cve_id": f.cve_id,
            "asset": a.ref,
            "exposure": a.exposure_level,
            "package": f.package_name,
            "installed_version": f.installed_version,
            "fixed_version": f.fixed_version,
            "severity": f.severity,
            "score": f.score,
            "needs_action": is_actionable(f.score, self.settings),
            "in_kev": bool(intel and intel.in_kev),
            "epss": intel.epss if intel else None,
            "epss_percentile": intel.epss_percentile if intel else None,
            "cvss": intel.cvss_score if intel else None,
            "remediation_key": f.remediation_key,
        }

    def _open(self) -> Any:
        return (
            select(Finding, Asset, CveIntel)
            .join(Asset, Finding.asset_id == Asset.id)
            .outerjoin(CveIntel, CveIntel.cve_id == Finding.cve_id)
            .where(Finding.status == FindingStatus.OPEN)
        )

    # -- tools --------------------------------------------------------------------------------

    def get_top_findings(self, n: int = 10) -> dict[str, Any]:
        """Top ``n`` open findings by score."""
        n = max(1, min(int(n), MAX_TOP_FINDINGS))
        rows = self.session.execute(
            self._open().order_by(Finding.score.desc().nulls_last(), Finding.id).limit(n)
        ).all()
        return {"findings": [self._finding_row(*r) for r in rows]}

    def get_finding(self, id: int) -> dict[str, Any]:
        """One finding with breakdown and intel."""
        row = self.session.execute(self._open().where(Finding.id == int(id))).first()
        if row is None:
            return {"error": f"no open finding with id {id}"}
        f, a, intel = row
        data = self._finding_row(f, a, intel)
        data["score_breakdown"] = (f.score_breakdown or {}).get("text", [])
        data["first_seen"] = f.first_seen.date().isoformat()
        data["title"] = wrap_untrusted(f.title, "scanner title")
        data["description"] = wrap_untrusted(intel.description if intel else None, "advisory")
        return data

    def lookup_cve(self, cve_id: str) -> dict[str, Any]:
        """Intel for one CVE plus where it occurs."""
        cve_id = cve_id.strip().upper()
        intel = self.session.get(CveIntel, cve_id)
        if intel is None:
            return {"error": f"{cve_id} is not among the scanned findings", "cve_id": cve_id}
        rows = self.session.execute(self._open().where(Finding.cve_id == cve_id)).all()
        return {
            "cve_id": cve_id,
            "in_kev": intel.in_kev,
            "kev_date_added": intel.kev_date_added,
            "kev_due_date": intel.kev_due_date,
            "ransomware_use": intel.ransomware_use,
            "epss": intel.epss,
            "epss_percentile": intel.epss_percentile,
            "epss_date": intel.epss_date,
            "cvss": intel.cvss_score,
            "cvss_vector": intel.cvss_vector,
            "cwe": intel.cwe,
            "description": wrap_untrusted(intel.description, "advisory"),
            "occurrences": [
                {
                    "asset": a.ref,
                    "exposure": a.exposure_level,
                    "package": f.package_name,
                    "installed_version": f.installed_version,
                    "fixed_version": f.fixed_version,
                }
                for f, a, _ in rows
            ],
        }

    def get_fix_version(self, package: str, ecosystem: str | None = None) -> dict[str, Any]:
        """Installed vs. fixed versions of ``package`` across open findings."""
        stmt = self._open().where(Finding.package_name == package)
        if ecosystem:
            types = [t for t, eco in OSV_ECOSYSTEMS.items() if eco.lower() == ecosystem.lower()]
            if types:
                stmt = stmt.where(or_(*(Finding.package_type == t for t in types)))
        rows = self.session.execute(stmt).all()
        if not rows:
            return {"package": package, "error": "package not found in open findings"}
        entries: dict[tuple[str, str], dict[str, Any]] = {}
        for f, a, _ in rows:
            entry = entries.setdefault(
                (a.ref, f.installed_version),
                {
                    "asset": a.ref,
                    "installed_version": f.installed_version,
                    "fixed_versions": [],
                    "fixed_version_source": f.fixed_version_source,
                    "cves": [],
                },
            )
            if f.fixed_version and f.fixed_version not in entry["fixed_versions"]:
                entry["fixed_versions"].append(f.fixed_version)
            entry["cves"].append(f.cve_id)
        return {"package": package, "ecosystem": ecosystem, "occurrences": list(entries.values())}

    def get_asset_exposure(self, asset: str) -> dict[str, Any]:
        """Exposure and evidence for an asset given by ref, name or container name."""
        needle = asset.strip()
        for a in self.session.scalars(select(Asset).where(Asset.active)):
            if needle in (a.ref, a.name, f"{a.name}:{a.tag}") or needle in (a.containers or []):
                return {
                    "asset": a.ref,
                    "kind": a.kind,
                    "exposure": a.exposure_level,
                    "evidence": a.exposure_evidence,
                    "containers": a.containers,
                }
        return {"asset": needle, "error": "unknown asset"}

    def get_remediation_groups(self, limit: int = 10) -> dict[str, Any]:
        """Top remediation groups plus deferral candidates."""
        limit = max(1, min(int(limit), 30))
        threshold = self.settings.action_threshold
        ranked = [g.as_dict(max_packages=8) for g in self.groups[:limit]]
        defer = [
            {
                "key": g.key,
                "rank": g.rank,
                "title": g.title,
                "asset_ref": g.asset_ref,
                "exposure": g.exposure,
                "finding_count": g.finding_count,
                "max_score": round(g.max_score, 2),
                "fixable": g.fixable,
            }
            for g in self.groups
            if is_deferrable(g, threshold)
        ][:10]
        return {
            "action_threshold": threshold,
            "groups": ranked,
            "defer_candidates": defer,
            "note": "Order is final and computed deterministically; do not re-rank.",
        }

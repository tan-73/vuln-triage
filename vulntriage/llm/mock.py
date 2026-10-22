"""Deterministic mock LLM for demo mode and tests (no API key, no network).

It follows the same tool-calling protocol as a real model: first it requests the
remediation groups and top findings, then it looks up the KEV CVEs and asset exposure,
and finally it writes the JSON draft *only* from what those tool results said. Its
output goes through the same grounding check as a real model's.
With ``hallucinate=True`` it adds deliberately invented facts, so tests can prove the
grounding check catches them.
"""

from __future__ import annotations

import json
from typing import Any

from vulntriage.llm.base import LLMProvider, LLMResponse, Message, ToolCall, ToolSpec


class MockProvider(LLMProvider):
    """A scripted, tool-using stand-in for a real model."""

    name = "mock"

    def __init__(
        self, model: str = "mock-triage-1", top_n: int = 5, hallucinate: bool = False
    ) -> None:
        super().__init__(model)
        self.top_n = top_n
        self.hallucinate = hallucinate

    @staticmethod
    def _results(messages: list[Message]) -> dict[str, list[Any]]:
        names = {c.id: c.name for m in messages if m.role == "assistant" for c in m.tool_calls}
        out: dict[str, list[Any]] = {}
        for m in messages:
            if m.role == "tool" and m.tool_call_id in names:
                out.setdefault(names[m.tool_call_id], []).append(json.loads(m.content))
        return out

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        """Return the next scripted step based on what tools have answered so far."""
        stage = sum(1 for m in messages if m.role == "assistant" and m.tool_calls)
        results = self._results(messages)
        if stage == 0:
            return LLMResponse(
                text="",
                tool_calls=[
                    ToolCall("m1", "get_remediation_groups", {"limit": self.top_n + 5}),
                    ToolCall("m2", "get_top_findings", {"n": 10}),
                ],
            )
        groups_result = results["get_remediation_groups"][0]
        threshold = groups_result["action_threshold"]
        action_groups = [g for g in groups_result["groups"] if g["max_score"] >= threshold][
            : self.top_n
        ]
        if stage == 1:
            kev = list(dict.fromkeys(c for g in action_groups for c in g["kev_cves"]))[:6]
            assets = list(dict.fromkeys(g["asset_ref"] for g in action_groups))
            calls = [ToolCall(f"k{i}", "lookup_cve", {"cve_id": c}) for i, c in enumerate(kev)]
            calls += [
                ToolCall(f"a{i}", "get_asset_exposure", {"asset": a}) for i, a in enumerate(assets)
            ]
            if calls:
                return LLMResponse(text="", tool_calls=calls)
        draft = self._compose(groups_result, action_groups, results)
        return LLMResponse(text=json.dumps(draft, indent=2), stop_reason="end_turn")

    def _compose(
        self,
        groups_result: dict[str, Any],
        action_groups: list[dict[str, Any]],
        results: dict[str, list[Any]],
    ) -> dict[str, Any]:
        cves = {r["cve_id"]: r for r in results.get("lookup_cve", []) if "error" not in r}
        exposure = {
            r["asset"]: r for r in results.get("get_asset_exposure", []) if "error" not in r
        }
        top = results.get("get_top_findings", [{"findings": []}])[0]["findings"]
        best_by_group: dict[str, dict[str, Any]] = {}
        for f in top:
            best_by_group.setdefault(f.get("remediation_key") or "", f)

        actions = []
        for g in action_groups:
            evidence: list[str] = []
            why_parts: list[str] = []
            for cve_id in g["kev_cves"][:2]:
                intel = cves.get(cve_id)
                if intel:
                    occ = next(
                        (o for o in intel["occurrences"] if o["asset"] == g["asset_ref"]), None
                    )
                    where = f" ({occ['package']} {occ['installed_version']})" if occ else ""
                    why_parts.append(
                        f"{g['asset_ref']} contains {cve_id}{where}, which CISA lists as known "
                        f"exploited (added {intel['kev_date_added']})."
                    )
                    evidence.append(
                        f"{cve_id} is in CISA KEV; EPSS {intel['epss']:.4f}"
                        if intel.get("epss") is not None
                        else f"{cve_id} is in CISA KEV"
                    )
            level = exposure.get(g["asset_ref"], {}).get("exposure", g["exposure"])
            phrase = {
                "internet": "is internet-exposed",
                "lan": "is LAN-only",
                "localhost": "is localhost-only",
                "none": "is not exposed",
            }[level]
            ev = exposure.get(g["asset_ref"], {}).get("evidence") or []
            evidence.append(f"{g['asset_ref']} {phrase}" + (f": {ev[0]}" if ev else ""))
            best = best_by_group.get(g["key"])
            if not why_parts and best and best.get("epss") is not None:
                why_parts.append(
                    f"Its riskiest finding, {best['cve_id']} in {best['package']}, has EPSS "
                    f"{best['epss']:.4f}."
                )
            why_parts.append(f"{g['asset_ref']} {phrase}.")
            for pkg in g["packages"][:3]:
                if pkg["fixed"]:
                    evidence.append(f"{pkg['package']} {pkg['installed']} -> {pkg['fixed']}")
            fix = g["command"] or "No fixed version is available yet; reduce exposure instead."
            actions.append(
                {
                    "group_key": g["key"],
                    "why": " ".join(why_parts),
                    "evidence": evidence,
                    "fix": fix,
                }
            )

        kev_all = list(dict.fromkeys(c for g in action_groups for c in g["kev_cves"]))
        internet = [g for g in action_groups if g["exposure"] == "internet"]
        total = sum(g["finding_count"] for g in action_groups)
        summary = []
        if action_groups:
            first = action_groups[0]
            summary.append(f"{len(action_groups)} remediation actions need attention tonight.")
            summary.append(f"The most urgent is: {first['title']}.")
        if kev_all:
            summary.append(
                f"{len(kev_all)} of the CVEs involved are listed in CISA KEV as known exploited: "
                f"{', '.join(kev_all)}."
            )
        if internet:
            summary.append(
                f"{len(internet)} of these actions affect internet-facing assets "
                f"({', '.join(dict.fromkeys(g['asset_ref'] for g in internet))})."
            )
        summary.append(f"Together they close {total} open findings.")
        if self.hallucinate:
            summary.append(
                "Also upgrade openssl to 9.9.9 to fix CVE-2099-0001, which is known exploited, "
                "and note that its EPSS is 0.9731."
            )

        defer = [
            {
                "group_key": d["key"],
                "reason": f"Highest score {d['max_score']} is below the action threshold "
                f"{groups_result['action_threshold']} and no CVE in it is in CISA KEV.",
            }
            for d in groups_result.get("defer_candidates", [])[:5]
        ]
        return {"executive_summary": " ".join(summary), "actions": actions, "defer": defer}

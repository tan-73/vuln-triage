"""Deterministic, explainable risk scoring.

The score is plain arithmetic over stored data. No LLM is involved, so the same inputs
always produce the same ranking. With the default weights (see ``docs/SCORING.md``)::

    likelihood = EPSS (0-1)                      # unknown EPSS -> SCORING__UNKNOWN_EPSS
    reach      = exposure multiplier            # internet 1.0 > lan 0.5 > localhost 0.2 > none 0.1
    risk       = 100 * likelihood * reach
    risk      *= 1.25 if a fixed version exists  # cheap to fix -> do it first
    risk       = 0 for kernel packages inside container images (they use the host kernel)
    tiebreak   = CVSS / 10                       # at most 1 point
    score      = risk + tiebreak
    score     += 1000 if in CISA KEV             # KEV always outranks non-KEV
    score     += 100 if KEV notes ransomware use

``ScoringWeights`` validates that the KEV offset exceeds the best possible non-KEV score,
so the KEV tier can never be overtaken.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulntriage.config import ScoringWeights, Settings
from vulntriage.models import Asset, AssetKind, CveIntel, ExposureLevel, Finding, FindingStatus

log = logging.getLogger(__name__)

#: CVSS-like stand-in when no CVSS score is known, derived from scanner severity.
SEVERITY_FALLBACK_CVSS = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 2.0, "UNKNOWN": 0.0}

#: Kernel packages: present in many base images but irrelevant inside a container.
KERNEL_PACKAGE = re.compile(
    r"^(linux-libc-dev|linux-headers.*|linux-image.*|kernel-headers|linux-modules.*)$"
)


@dataclass(frozen=True)
class ScoreInput:
    """Everything the scoring function looks at, decoupled from the ORM for testability."""

    cve_id: str
    package_name: str
    asset_kind: str
    exposure: ExposureLevel
    epss: float | None
    epss_percentile: float | None
    in_kev: bool
    ransomware_use: bool
    cvss: float | None
    severity: str
    fixed_version: str | None
    kev_date_added: str | None = None


@dataclass
class ScoreResult:
    """A score plus the ordered list of components that produced it."""

    score: float
    components: list[dict[str, Any]] = field(default_factory=list)
    tier: str = "standard"

    def explanation(self) -> list[str]:
        """Human-readable lines, one per component."""
        return [f"{c['label']}: {c['detail']} ({c['points']:+.2f})" for c in self.components]

    def as_dict(self) -> dict[str, Any]:
        """JSON form stored on ``Finding.score_breakdown``."""
        return {
            "score": round(self.score, 4),
            "tier": self.tier,
            "components": self.components,
            "text": self.explanation(),
        }


def _component(label: str, detail: str, points: float, **data: Any) -> dict[str, Any]:
    return {"label": label, "detail": detail, "points": round(points, 4), **data}


def score_finding(inp: ScoreInput, w: ScoringWeights) -> ScoreResult:
    """Compute the risk score of one finding. Pure function; see module docstring."""
    components: list[dict[str, Any]] = []
    exposure_mult = {
        ExposureLevel.INTERNET: w.exposure_internet,
        ExposureLevel.LAN: w.exposure_lan,
        ExposureLevel.LOCALHOST: w.exposure_localhost,
        ExposureLevel.NONE: w.exposure_none,
    }[inp.exposure]

    epss = inp.epss if inp.epss is not None else w.unknown_epss
    epss_note = (
        f"EPSS {inp.epss:.4f} (percentile {inp.epss_percentile:.2f})"
        if inp.epss is not None and inp.epss_percentile is not None
        else f"no EPSS score; assuming {w.unknown_epss}"
    )
    risk = epss * w.epss_scale * exposure_mult
    components.append(
        _component(
            "Exploit likelihood x exposure",
            f"{epss_note} x {inp.exposure.value} exposure ({exposure_mult})",
            risk,
            epss=inp.epss,
            exposure=inp.exposure.value,
        )
    )

    if inp.fixed_version:
        bonus = risk * (w.fix_available_multiplier - 1.0)
        risk += bonus
        components.append(
            _component("Fix available", f"fixed in {inp.fixed_version}", bonus, fixed=True)
        )

    if inp.asset_kind == AssetKind.IMAGE and KERNEL_PACKAGE.match(inp.package_name):
        components.append(
            _component(
                "Not applicable in containers",
                f"{inp.package_name} is a kernel package; containers run on the host kernel",
                -risk,
                not_applicable=True,
            )
        )
        risk = 0.0

    cvss = inp.cvss
    cvss_note = f"CVSS {cvss:.1f}" if cvss is not None else None
    if cvss is None:
        cvss = SEVERITY_FALLBACK_CVSS.get(inp.severity, 0.0)
        cvss_note = f"no CVSS; {inp.severity} severity treated as {cvss:.1f}"
    tiebreak = cvss / 10.0 * w.cvss_weight
    components.append(_component("Severity tiebreaker", str(cvss_note), tiebreak, cvss=inp.cvss))

    score = risk + tiebreak
    tier = "standard"
    if inp.in_kev:
        tier = "kev"
        added = f", added {inp.kev_date_added}" if inp.kev_date_added else ""
        components.insert(
            0,
            _component(
                "CISA KEV", f"known exploited in the wild{added}", w.kev_tier_offset, kev=True
            ),
        )
        score += w.kev_tier_offset
        if inp.ransomware_use:
            components.insert(
                1,
                _component(
                    "Ransomware use", "KEV lists known ransomware campaign use", w.ransomware_bonus
                ),
            )
            score += w.ransomware_bonus
    return ScoreResult(score=score, components=components, tier=tier)


@dataclass
class ScoringSummary:
    """Headline numbers after scoring all open findings."""

    scored: int = 0
    actionable: int = 0
    kev: int = 0


def score_all(session: Session, settings: Settings) -> ScoringSummary:
    """Score every open finding and store score + breakdown on it."""
    stmt = (
        select(Finding, Asset, CveIntel)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(CveIntel, CveIntel.cve_id == Finding.cve_id)
        .where(Finding.status == FindingStatus.OPEN)
    )
    summary = ScoringSummary()
    for finding, asset, intel in session.execute(stmt):
        result = score_finding(
            ScoreInput(
                cve_id=finding.cve_id,
                package_name=finding.package_name,
                asset_kind=asset.kind,
                exposure=ExposureLevel(asset.exposure_level or ExposureLevel.NONE),
                epss=intel.epss if intel else None,
                epss_percentile=intel.epss_percentile if intel else None,
                in_kev=bool(intel and intel.in_kev),
                ransomware_use=bool(intel and intel.ransomware_use),
                cvss=intel.cvss_score if intel else None,
                severity=finding.severity,
                fixed_version=finding.fixed_version,
                kev_date_added=intel.kev_date_added if intel else None,
            ),
            settings.scoring,
        )
        finding.score = round(result.score, 4)
        finding.score_breakdown = result.as_dict()
        summary.scored += 1
        summary.kev += result.tier == "kev"
        summary.actionable += is_actionable(finding.score, settings)
    session.flush()
    log.info(
        "scored %d findings: %d actionable, %d KEV",
        summary.scored,
        summary.actionable,
        summary.kev,
    )
    return summary


def is_actionable(score: float | None, settings: Settings) -> bool:
    """A finding needs action when its score reaches ``ACTION_THRESHOLD`` (KEV always does)."""
    return score is not None and score >= settings.action_threshold

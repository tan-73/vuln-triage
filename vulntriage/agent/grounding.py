"""Grounding post-check: every factual claim in LLM output must come from a tool result.

A :class:`Ledger` holds the facts that tools actually returned. :func:`check_text` finds
claims in a piece of model output, verifies each against the ledger, and replaces the
ones it cannot verify:

==========  ==============================================  ============================
Claim       How it is detected                              Verified when
==========  ==============================================  ============================
CVE ID      ``CVE-YYYY-NNNN``                               the ID appears in tool output
version     dotted version tokens (``2.36-9+deb12u3``,      the token appears in tool
            ``1.25.4``, or ``3.11`` after a version cue)    output
EPSS        a number after "EPSS" (0.64 or 64%)             within rounding of a returned
                                                            EPSS score/percentile
CVSS        a number after "CVSS"                           equals a returned CVSS score
KEV         a sentence naming a CVE and "KEV"/"known        the CVE's KEV flag matches
            exploited" (negation aware)
exposure    a sentence naming an asset and an exposure      the asset's level matches
            phrase ("internet-exposed", "LAN-only", ...)
==========  ==============================================  ============================

Text inside untrusted-data markers is excluded from the ledger, so a CVE ID or version
that appears only inside an advisory description cannot "ground" a claim.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from vulntriage.agent.untrusted import UNTRUSTED_BLOCK

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
#: Dotted version token, optionally with distro/semver suffixes.
VERSION_RE = re.compile(
    r"(?<![\w.\-+])v?(\d+(?:\.\d+)+(?:[-+~:][0-9A-Za-z][0-9A-Za-z.+~:\-]*)?)(?![\w])"
)
VERSION_CUE = re.compile(
    r"(?:version|versions|v|to|from|->|→|>=|<=|==|@|:|upgrade|bump|release|tag|fixed in|"
    r"installed)\s*$",
    re.IGNORECASE,
)
EPSS_RE = re.compile(
    r"EPSS(?:\s+(?:score|probability|of|is|at|=|:|percentile))*\s*(?:of\s+)?[:=]?\s*"
    r"(\d+(?:\.\d+)?)\s*(%)?",
    re.IGNORECASE,
)
CVSS_RE = re.compile(
    r"CVSS(?:\s*v?3(?:\.[01])?)?(?:\s+(?:base\s+)?score)?(?:\s+(?:of|is))?\s*[:=]?\s*(\d{1,2}\.\d)",
    re.IGNORECASE,
)
KEV_RE = re.compile(
    r"\bKEV\b|known[- ]exploited|actively exploited|exploited in the wild", re.IGNORECASE
)
NEGATION_RE = re.compile(
    r"\b(?:not|no|isn't|is not|aren't|never|without)\b[^.]{0,30}$", re.IGNORECASE
)
_INTERNET = (
    r"internet[- ]exposed|exposed to the internet|internet[- ]facing|"
    r"publicly (?:reachable|exposed|accessible)|reachable from the internet"
)
_LAN = r"\bLAN[- ]only\b|only (?:reachable|exposed) (?:on|from) the LAN|LAN[- ]exposed"
_LOCALHOST = (
    r"localhost[- ]only|only (?:reachable|bound) (?:on|to|from) localhost|"
    r"bound to (?:127\.0\.0\.1|localhost)"
)
EXPOSURE_PHRASES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(_INTERNET, re.I), "internet"),
    (re.compile(_LAN, re.I), "lan"),
    (re.compile(_LOCALHOST, re.I), "localhost"),
    (re.compile(r"not exposed|no network exposure|unexposed", re.I), "none"),
]
#: Sentence boundary: ., ! or ? followed by whitespace (so "1.25.4" stays intact), or newline.
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
SENTENCE_SPLIT_KEEP = re.compile(r"((?<=[.!?])\s+|\n+)")

EPSS_TOLERANCE = 0.006


def _norm_version(token: str) -> str:
    return token.lower().removeprefix("v").rstrip(".,;:)")


@dataclass
class Ledger:
    """Facts returned by tool calls during one agent run."""

    cves: set[str] = field(default_factory=set)
    versions: set[str] = field(default_factory=set)
    epss_values: set[float] = field(default_factory=set)
    cvss_values: set[float] = field(default_factory=set)
    kev: dict[str, bool] = field(default_factory=dict)
    exposures: dict[str, str] = field(default_factory=dict)
    #: Known (package, version) pairs and (asset alias, package, version) triples.
    pkg_versions: set[tuple[str, str]] = field(default_factory=set)
    asset_pkg_versions: set[tuple[str, str, str]] = field(default_factory=set)
    asset_aliases: dict[str, set[str]] = field(default_factory=dict)
    tool_results: int = 0

    def add(self, result: Any) -> None:
        """Absorb one tool result (any JSON-serialisable value)."""
        self.tool_results += 1
        self._walk(result, asset=None, package=None)
        text = UNTRUSTED_BLOCK.sub(" ", json.dumps(result, default=str))
        self.cves.update(c.upper() for c in CVE_RE.findall(text))
        self.versions.update(_norm_version(m.group(1)) for m in VERSION_RE.finditer(text))

    def _walk(self, node: Any, asset: str | None, package: str | None) -> None:
        if isinstance(node, dict):
            asset = next(
                (node[k] for k in ("asset", "asset_ref") if isinstance(node.get(k), str)), asset
            )
            package = node["package"] if isinstance(node.get("package"), str) else package
            cve = node.get("cve_id") or node.get("cve")
            if isinstance(cve, str) and "in_kev" in node:
                self.kev[cve.upper()] = bool(node["in_kev"])
            for kev_cve in node.get("kev_cves") or []:
                if isinstance(kev_cve, str):
                    self.kev[kev_cve.upper()] = True
            level = node.get("exposure") or node.get("exposure_level")
            if isinstance(level, str):
                for key in ("asset", "asset_ref", "ref", "name"):
                    if isinstance(node.get(key), str):
                        self._add_asset(node[key], level)
                for container in node.get("containers") or []:
                    if isinstance(container, str):
                        self._add_asset(container, level)
                        if isinstance(node.get("asset"), str):
                            self._alias(node["asset"], container)
            if package:
                self._add_versions(node, asset, package)
            for key, value in node.items():
                if key in ("epss", "epss_percentile") and isinstance(value, int | float):
                    self.epss_values.add(float(value))
                elif key in ("cvss", "cvss_score") and isinstance(value, int | float):
                    self.cvss_values.add(round(float(value), 1))
                self._walk(value, asset, package)
        elif isinstance(node, list):
            for item in node:
                self._walk(item, asset, package)

    def _add_versions(self, node: dict[str, Any], asset: str | None, package: str) -> None:
        values: list[str] = []
        for key in ("installed_version", "installed", "fixed_version", "fixed"):
            if isinstance(node.get(key), str):
                values += node[key].split(",")
        for item in node.get("fixed_versions") or []:
            if isinstance(item, str):
                values += item.split(",")
        pkg = package.lower()
        for raw in values:
            ver = _norm_version(raw.strip())
            if not ver:
                continue
            self.pkg_versions.add((pkg, ver))
            if asset:
                for alias in self._aliases_of(asset):
                    self.asset_pkg_versions.add((alias, pkg, ver))

    def _alias(self, ref: str, alias: str) -> None:
        self.asset_aliases.setdefault(ref.lower(), set()).add(alias.lower())

    def _aliases_of(self, ref: str) -> set[str]:
        low = ref.lower()
        names = {low} | self.asset_aliases.get(low, set())
        if low.startswith(("host:", "fs:")):
            names.add(low.split(":", 1)[1])
        elif ":" in low:
            names.add(low.rsplit(":", 1)[0])
        return names

    def known_pair(self, package: str, version: str, asset: str | None) -> bool:
        """True if ``package`` at ``version`` was reported (on ``asset``, when given)."""
        key = (package.lower(), _norm_version(version))
        if asset is None:
            return key in self.pkg_versions
        return (asset.lower(), *key) in self.asset_pkg_versions

    @property
    def package_names(self) -> list[str]:
        """Known package names, longest first (so ``libssl3`` wins over ``libssl``)."""
        return sorted({p for p, _ in self.pkg_versions}, key=len, reverse=True)

    def _add_asset(self, ref: str, level: str) -> None:
        self.exposures[ref.lower()] = level
        if ":" in ref and not ref.startswith(("host:", "fs:")):
            self.exposures.setdefault(ref.rsplit(":", 1)[0].lower(), level)
        elif ref.startswith(("host:", "fs:")):
            self.exposures.setdefault(ref.split(":", 1)[1].lower(), level)

    def has_epss(self, value: float) -> bool:
        """True if ``value`` matches a returned EPSS score or percentile within rounding."""
        return any(abs(value - known) <= EPSS_TOLERANCE for known in self.epss_values)


@dataclass
class Claim:
    """One factual claim found in model output."""

    kind: str
    value: str
    verified: bool
    context: str = ""


@dataclass
class GroundingResult:
    """Outcome of checking one or more texts."""

    claims: list[Claim] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Number of claims checked."""
        return len(self.claims)

    @property
    def verified(self) -> int:
        """Number of claims supported by tool results."""
        return sum(c.verified for c in self.claims)

    @property
    def rate(self) -> float:
        """Share of verified claims (1.0 when there were no claims)."""
        return self.verified / self.total if self.total else 1.0

    @property
    def flagged(self) -> list[Claim]:
        """Claims that failed verification."""
        return [c for c in self.claims if not c.verified]

    def extend(self, other: GroundingResult) -> None:
        """Merge another result into this one."""
        self.claims.extend(other.claims)


def _sentences(text: str) -> Iterable[str]:
    for part in SENTENCE_SPLIT.split(text):
        part = part.strip()
        if part:
            yield part


def _mentioned_assets(sentence: str, ledger: Ledger) -> list[str]:
    low = sentence.lower()
    return [
        ref
        for ref in sorted(ledger.exposures, key=len, reverse=True)
        if len(ref) >= 4 and re.search(rf"(?<![\w/.-]){re.escape(ref)}(?![\w/-])", low)
    ]


REMOVED = "[removed: claim not supported by tool data]"


def check_text(text: str, ledger: Ledger) -> tuple[str, GroundingResult]:
    """Verify every claim in ``text``; return the cleaned text and the claims found.

    Works sentence by sentence. Unverified CVE IDs, versions and numbers are replaced
    with ``[unverified ...]`` markers. A sentence whose KEV or exposure claim contradicts
    the data is removed entirely, but every claim inside it is still counted.
    """
    result = GroundingResult()
    parts = SENTENCE_SPLIT_KEEP.split(text)
    out: list[str] = []
    for i, part in enumerate(parts):
        if i % 2 or not part.strip():
            out.append(part)  # separator or blank
        else:
            out.append(_check_sentence(part, ledger, result))
    return "".join(out), result


def _check_sentence(sentence: str, ledger: Ledger, result: GroundingResult) -> str:
    drop = False
    kev_hit = KEV_RE.search(sentence)
    if kev_hit:
        negated = bool(NEGATION_RE.search(sentence[: kev_hit.start()]))
        for cve in dict.fromkeys(c.upper() for c in CVE_RE.findall(sentence)):
            known = ledger.kev.get(cve)
            ok = known is not None and known == (not negated)
            result.claims.append(
                Claim("kev", f"{cve} {'not ' if negated else ''}in KEV", ok, sentence)
            )
            drop |= not ok
    for pattern, level in EXPOSURE_PHRASES:
        if pattern.search(sentence):
            ref = _single_asset(sentence, ledger) or next(
                iter(_mentioned_assets(sentence, ledger)), None
            )
            if ref is not None:
                ok = ledger.exposures.get(ref) == level
                result.claims.append(Claim("exposure", f"{ref} is {level}", ok, sentence))
                drop |= not ok
            break

    cleaned = _check_package_versions(sentence, ledger, result)

    def cve_sub(m: re.Match[str]) -> str:
        ok = m.group(0).upper() in ledger.cves
        result.claims.append(Claim("cve", m.group(0).upper(), ok, sentence))
        return m.group(0) if ok else "[unverified CVE]"

    def epss_sub(m: re.Match[str]) -> str:
        value = float(m.group(1)) / (100 if m.group(2) else 1)
        ok = ledger.has_epss(value) or (
            not m.group(2) and value > 1 and ledger.has_epss(value / 100)
        )
        result.claims.append(Claim("epss", m.group(0).strip(), ok, sentence))
        if ok:
            return m.group(0)
        return m.group(0).replace(m.group(1) + (m.group(2) or ""), "[unverified]")

    def cvss_sub(m: re.Match[str]) -> str:
        ok = round(float(m.group(1)), 1) in ledger.cvss_values
        result.claims.append(Claim("cvss", m.group(0).strip(), ok, sentence))
        return m.group(0) if ok else m.group(0).replace(m.group(1), "[unverified]")

    cleaned = CVE_RE.sub(cve_sub, cleaned)
    cleaned = EPSS_RE.sub(epss_sub, cleaned)
    cleaned = CVSS_RE.sub(cvss_sub, cleaned)

    def version_sub(m: re.Match[str]) -> str:
        token = m.group(1)
        prefix = cleaned[max(0, m.start() - 16) : m.start()]
        is_version = (
            token.count(".") >= 2 or re.search(r"[-+~:]", token) or VERSION_CUE.search(prefix)
        )
        if not is_version or "[unverified" in prefix:
            return m.group(0)
        ok = _norm_version(token) in ledger.versions
        result.claims.append(Claim("version", token, ok, sentence))
        return m.group(0) if ok else m.group(0).replace(token, "[unverified version]")

    cleaned = VERSION_RE.sub(version_sub, cleaned)
    return REMOVED if drop else cleaned


def _single_asset(sentence: str, ledger: Ledger) -> str | None:
    """The one asset a sentence talks about (aliases collapse), or ``None``."""
    mentions = _mentioned_assets(sentence, ledger)
    if not mentions:
        return None
    longest = mentions[0]
    aliases = ledger._aliases_of(longest)
    return longest if all(m in aliases for m in mentions) else None


def _package_pattern(ledger: Ledger) -> re.Pattern[str] | None:
    names = ledger.package_names
    if not names:
        return None
    pkg_alt = "|".join(re.escape(n) for n in names)
    end = r"(?=[\s,;)]|\.(?:\s|$)|$)"
    return re.compile(
        rf"(?<![\w.+-])({pkg_alt})(?:\s+|\s*@\s*|\s+version\s+)v?(\d[\w.+~:-]*?){end}"
        rf"(?:\s*(?:->|→|to)\s*v?(\d[\w.+~:-]*?){end})?",
        re.IGNORECASE,
    )


def _check_package_versions(sentence: str, ledger: Ledger, result: GroundingResult) -> str:
    """Association check: "<package> <version>" must match what tools reported.

    When the sentence names exactly one asset, the pair must have been reported *for that
    asset*. This catches a real-but-misattributed version (e.g. a Debian glibc version
    quoted for an Ubuntu host). Failing versions are replaced; passing ones are left
    for the generic version check to count, so each version is counted once.
    """
    pattern = _package_pattern(ledger)
    if pattern is None:
        return sentence
    asset = _single_asset(sentence, ledger)
    fixed = sentence
    for m in pattern.finditer(sentence):
        package = m.group(1)
        for version in filter(None, (m.group(2), m.group(3))):
            if not re.search(r"[.+~:-]", version):
                continue  # a bare number ("tar 2 times") is not a version claim
            if ledger.known_pair(package, version, asset):
                continue
            where = f" on {asset}" if asset else ""
            result.claims.append(
                Claim("package_version", f"{package} {version}{where}", False, sentence)
            )
            fixed = fixed.replace(version, "[unverified version]", 1)
    return fixed

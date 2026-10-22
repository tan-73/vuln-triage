"""Group findings by the single action that fixes them, and rank the groups.

People fix *actions*, not CVEs: "pull a newer nginx 1.25.x image" can close 40 findings
at once. Each open finding gets a ``remediation_key``; findings sharing a key form a
:class:`RemediationGroup`. Groups are ranked deterministically by their worst finding's
score, then KEV count, then total score.

Grouping rules:

* **Third-party image**: every fixable finding means "update the image". The suggested
  command pulls the same release line (``3.11.4-slim`` becomes ``3.11-slim``), and the
  exact fixed package versions are listed so the upgrade can be checked.
* **Own image** (matches ``OWN_IMAGE_PATTERNS``): OS packages mean "rebuild on a fresh
  base". Each language package gets its own "bump package X" group with an ecosystem
  command.
* **Host**: one OS-package upgrade command per host (apt, apk or dnf).
* **Directory (fs)**: one "bump package X" group per package.
* Findings with **no fixed version** go into a per-asset "no fix available" group. These
  are candidates to defer unless they are KEV-listed or internet-exposed.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulntriage.config import Settings
from vulntriage.models import Asset, AssetKind, CveIntel, Finding, FindingStatus
from vulntriage.scanners.base import OS_PACKAGE_TYPES
from vulntriage.scoring import KERNEL_PACKAGE, is_actionable


def version_key(version: str) -> tuple[Any, ...]:
    """Natural sort key that copes with Debian/RPM/semver strings well enough to order fixes.

    ``1:2.3-4`` (epoch) sorts after ``2.4``; ``1.10`` sorts after ``1.9``. A ``~`` suffix
    (pre-release) sorts before the bare version.
    """
    epoch = 0
    if re.match(r"^\d+:", version):
        epoch_s, version = version.split(":", 1)
        epoch = int(epoch_s)
    version = version.lstrip("vV")
    parts: list[tuple[int, Any]] = []
    for piece in re.findall(r"\d+|[A-Za-z]+|~", version):
        if piece == "~":
            parts.append((-2, 0))
        elif piece.isdigit():
            parts.append((1, int(piece)))
        else:
            parts.append((0, piece))
    parts.append((-1, 0))  # end marker: after "~", before any further component
    return (epoch, tuple(parts))


def pick_fix(installed: str, fixed: str | None) -> str | None:
    """Choose the version to upgrade to from a comma-separated list of fixed versions.

    Prefers the lowest fixed version on the installed release line (same leading
    component) that is newer than the installed one; otherwise the highest fixed version.
    """
    if not fixed:
        return None
    candidates = sorted({v.strip() for v in fixed.split(",") if v.strip()}, key=version_key)
    if not candidates:
        return None
    current = version_key(installed) if installed else None
    major = re.match(r"v?(\d+)", installed or "")
    for cand in candidates:
        if current is not None and version_key(cand) <= current:
            continue
        cand_major = re.match(r"v?(\d+)", cand)
        if major and cand_major and major.group(1) == cand_major.group(1):
            return cand
    return candidates[-1]


def line_tag(tag: str) -> str | None:
    """The release-line tag one level up: ``3.11.4-slim`` -> ``3.11-slim``, ``13.2`` -> ``13``."""
    m = re.fullmatch(r"(v?\d+(?:\.\d+)*)\.\d+(.*)", tag)
    return f"{m.group(1)}{m.group(2)}" if m else None


@dataclass
class PackageFix:
    """One package upgrade within a group."""

    package: str
    package_type: str
    installed: str
    fixed: str | None
    cves: list[str] = field(default_factory=list)
    kev_cves: list[str] = field(default_factory=list)
    max_score: float = 0.0


@dataclass
class RemediationGroup:
    """A single remediation action and the findings it resolves."""

    key: str
    kind: str
    title: str
    asset_ref: str
    asset_kind: str
    exposure: str
    command: str | None
    fixable: bool
    finding_ids: list[int] = field(default_factory=list)
    packages: list[PackageFix] = field(default_factory=list)
    kev_cves: list[str] = field(default_factory=list)
    max_score: float = 0.0
    total_score: float = 0.0
    actionable_count: int = 0
    not_applicable_count: int = 0
    notes: list[str] = field(default_factory=list)
    rank: int = 0

    @property
    def finding_count(self) -> int:
        """Number of open findings this action resolves."""
        return len(self.finding_ids)

    @property
    def cves(self) -> list[str]:
        """Distinct vulnerability IDs in the group, highest-scoring package first."""
        seen: dict[str, None] = {}
        for pkg in self.packages:
            for cve in pkg.cves:
                seen.setdefault(cve, None)
        return list(seen)

    def as_dict(self, max_packages: int = 25) -> dict[str, Any]:
        """JSON-friendly representation (used by the agent tools and the dashboard)."""
        data = asdict(self)
        data["finding_count"] = self.finding_count
        data["packages"] = data["packages"][:max_packages]
        data["packages_truncated"] = max(0, len(self.packages) - max_packages)
        data.pop("finding_ids")
        return data


def is_own_image(asset: Asset, settings: Settings) -> bool:
    """True if the image is built locally (matches ``OWN_IMAGE_PATTERNS``)."""
    return any(fnmatch.fnmatch(asset.ref, pat) for pat in settings.own_image_patterns)


def group_key(finding: Finding, asset: Asset, settings: Settings) -> str:
    """The remediation key for ``finding`` (see module docstring)."""
    if not finding.fixed_version:
        return f"nofix:{asset.id}"
    is_os = finding.target == "os" or finding.package_type.lower() in OS_PACKAGE_TYPES
    if asset.kind == AssetKind.IMAGE:
        if not is_own_image(asset, settings):
            return f"image:{asset.id}"
        if is_os:
            return f"rebuild:{asset.id}"
    elif asset.kind == AssetKind.HOST and is_os:
        return f"host-os:{asset.id}"
    return f"pkg:{asset.id}:{finding.package_type}:{finding.package_name}"


_PKG_COMMANDS = {
    "PyPI": "pip install --upgrade {q}{name}>={ver}{q}",
    "npm": "npm install {name}@{ver}",
    "Go": "go get {name}@v{ver_nov}",
    "Maven": "set {name} to version {ver} in your pom.xml / build.gradle",
    "crates.io": "cargo update -p {name} --precise {ver}",
    "RubyGems": "bundle update {name} --conservative  # to >= {ver}",
    "Packagist": "composer require {name}:^{ver}",
    "NuGet": "dotnet add package {name} --version {ver}",
}


def package_command(package_type: str, name: str, version: str) -> str:
    """Ecosystem-specific upgrade command for one package."""
    from vulntriage.intel.feeds import osv_ecosystem

    eco = osv_ecosystem(package_type) or ""
    template = _PKG_COMMANDS.get(eco, "upgrade {name} to {ver}")
    return template.format(name=name, ver=version, ver_nov=version.removeprefix("v"), q="'")


def os_upgrade_command(os_family: str | None, packages: list[str]) -> str:
    """Distro package-manager command upgrading only ``packages``."""
    pkgs = " ".join(shlex.quote(p) for p in sorted(set(packages)))
    family = (os_family or "").lower()
    if family in ("alpine", "wolfi", "chainguard"):
        return f"apk upgrade {pkgs}"
    if family in ("redhat", "centos", "rocky", "alma", "fedora", "amazon", "oracle", "azurelinux"):
        return f"sudo dnf upgrade {pkgs}"
    if family in ("suse", "opensuse", "opensuse-leap", "sles"):
        return f"sudo zypper update {pkgs}"
    return f"sudo apt-get update && sudo apt-get install --only-upgrade {pkgs}"


def _describe(group: RemediationGroup, asset: Asset) -> None:
    """Fill in title, command and notes once all packages are known."""
    fixes = [p for p in group.packages if p.fixed]
    names = [p.package for p in fixes]
    n = group.finding_count
    if group.kind == "nofix":
        group.title = f"No fix available yet for {n} findings in {asset.ref}"
        group.notes.append(
            "Reduce exposure or accept the risk; re-check after upstream releases a fix."
        )
    elif group.kind == "image":
        line = line_tag(asset.tag) if asset.tag else None
        target = f"{asset.name}:{line}" if line else asset.ref
        group.title = f"Update image {asset.ref} (fixes {n} findings in {len(fixes)} packages)"
        group.command = f"docker pull {target}  # then redeploy: docker compose up -d"
        group.notes.append(
            f"Move to the newest {target} release; the listed package versions are the minimum "
            "that the new image must contain."
        )
    elif group.kind == "rebuild":
        group.title = f"Rebuild {asset.ref} on a patched base image ({n} findings)"
        group.command = "docker build --pull --no-cache -t " + shlex.quote(asset.ref) + " ."
    elif group.kind == "host-os":
        group.title = f"Upgrade {len(fixes)} OS packages on host {asset.name} ({n} findings)"
        group.command = os_upgrade_command(asset.os_family, names)
        if any(KERNEL_PACKAGE.match(p) for p in names):
            group.notes.append("Includes kernel packages: reboot the host afterwards.")
    else:  # pkg
        pkg = fixes[0]
        group.title = (
            f"Upgrade {pkg.package} {pkg.installed} -> {pkg.fixed} in {asset.ref} ({n} findings)"
        )
        group.command = package_command(pkg.package_type, pkg.package, pkg.fixed or "")
    if group.not_applicable_count:
        group.notes.append(
            f"{group.not_applicable_count} findings are kernel packages inside a container image "
            "(not exploitable there; patch the host kernel instead)."
        )


def build_groups(
    session: Session, settings: Settings, assign_keys: bool = False
) -> list[RemediationGroup]:
    """Build and rank remediation groups from all open, scored findings.

    With ``assign_keys`` the ``remediation_key`` column is (re)written on every finding.
    """
    stmt = (
        select(Finding, Asset, CveIntel)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(CveIntel, CveIntel.cve_id == Finding.cve_id)
        .where(Finding.status == FindingStatus.OPEN)
    )
    groups: dict[str, RemediationGroup] = {}
    assets: dict[str, Asset] = {}
    pkg_index: dict[tuple[str, str, str], PackageFix] = {}
    for finding, asset, intel in session.execute(stmt):
        key = group_key(finding, asset, settings)
        if assign_keys:
            finding.remediation_key = key
        group = groups.get(key)
        if group is None:
            group = groups[key] = RemediationGroup(
                key=key,
                kind=key.split(":", 1)[0],
                title="",
                asset_ref=asset.ref,
                asset_kind=asset.kind,
                exposure=asset.exposure_level,
                command=None,
                fixable=not key.startswith("nofix:"),
            )
            assets[key] = asset
        score = finding.score or 0.0
        group.finding_ids.append(finding.id)
        group.max_score = max(group.max_score, score)
        group.total_score += score
        group.actionable_count += is_actionable(finding.score, settings)
        if (finding.score_breakdown or {}).get("components") and any(
            c.get("not_applicable") for c in finding.score_breakdown["components"]
        ):
            group.not_applicable_count += 1

        pkey = (key, finding.package_name, finding.installed_version)
        pkg = pkg_index.get(pkey)
        if pkg is None:
            pkg = pkg_index[pkey] = PackageFix(
                package=finding.package_name,
                package_type=finding.package_type,
                installed=finding.installed_version,
                fixed=None,
            )
            group.packages.append(pkg)
        chosen = pick_fix(finding.installed_version, finding.fixed_version)
        if chosen and (pkg.fixed is None or version_key(chosen) > version_key(pkg.fixed)):
            pkg.fixed = chosen
        if finding.cve_id not in pkg.cves:
            pkg.cves.append(finding.cve_id)
        pkg.max_score = max(pkg.max_score, score)
        if intel is not None and intel.in_kev:
            if finding.cve_id not in pkg.kev_cves:
                pkg.kev_cves.append(finding.cve_id)
            if finding.cve_id not in group.kev_cves:
                group.kev_cves.append(finding.cve_id)

    ranked = sorted(
        groups.values(),
        key=lambda g: (-g.max_score, -len(g.kev_cves), -g.total_score, g.key),
    )
    for rank, group in enumerate(ranked, start=1):
        group.rank = rank
        group.packages.sort(key=lambda p: (-p.max_score, p.package))
        group.total_score = round(group.total_score, 4)
        _describe(group, assets[group.key])
    if assign_keys:
        session.flush()
    return ranked

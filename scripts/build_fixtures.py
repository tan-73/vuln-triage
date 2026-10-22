#!/usr/bin/env python3
"""Trim raw scanner JSON into the compact fixtures shipped in ``fixtures/``.

The demo dataset was produced by scanning *old public images* (never a private network)::

    trivy image --image-src remote --scanners vuln --format json -o raw/nginx_1.25.1.json nginx:1.25.1
    grype registry:redis:6.2.6 -o json --file raw/grype_redis_6.2.6.json

then trimmed with::

    python scripts/build_fixtures.py trivy raw/*.json --out fixtures/trivy
    python scripts/build_fixtures.py grype raw/grype_*.json --out fixtures/grype

Trimming drops references, layer data and vendor scores and shortens descriptions so the
fixtures stay small, while keeping every field VulnTriage parses.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

DESC_LIMIT = 280
TRIVY_VULN_KEYS = (
    "VulnerabilityID", "PkgName", "PkgPath", "InstalledVersion", "FixedVersion", "Status",
    "Severity", "Title", "Description", "CweIDs", "CVSS", "PublishedDate",
)  # fmt: skip


def _short(text: str | None) -> str | None:
    if not text or len(text) <= DESC_LIMIT:
        return text
    return text[: DESC_LIMIT - 1].rsplit(" ", 1)[0] + "…"


def _sample(vulns: list[dict[str, Any]], caps: dict[str, int]) -> list[dict[str, Any]]:
    """Down-sample packages with thousands of entries (e.g. linux-libc-dev) by even striding."""
    out: list[dict[str, Any]] = []
    for pkg in dict.fromkeys(v.get("PkgName") for v in vulns):
        group = [v for v in vulns if v.get("PkgName") == pkg]
        cap = caps.get(str(pkg))
        if cap and len(group) > cap:
            step = len(group) / cap
            group = [group[int(i * step)] for i in range(cap)]
        out.extend(group)
    return out


def trim_trivy(data: dict[str, Any], caps: dict[str, int] | None = None) -> dict[str, Any]:
    """Keep only the fields :func:`vulntriage.scanners.trivy.parse_trivy_report` reads."""
    meta = data.get("Metadata") or {}
    out: dict[str, Any] = {
        "SchemaVersion": data.get("SchemaVersion"),
        "ArtifactName": data.get("ArtifactName"),
        "ArtifactType": data.get("ArtifactType"),
        "Metadata": {k: meta[k] for k in ("OS", "RepoTags", "RepoDigests", "ImageID") if k in meta},
        "Results": [],
    }
    for result in data.get("Results") or []:
        vulns = []
        for v in _sample(result.get("Vulnerabilities") or [], caps or {}):
            item = {k: v[k] for k in TRIVY_VULN_KEYS if k in v}
            item["Description"] = _short(item.get("Description"))
            cvss = {
                src: {k: val for k, val in body.items() if k in ("V3Score", "V3Vector")}
                for src, body in (v.get("CVSS") or {}).items()
                if src in ("nvd", "ghsa")
            }
            item["CVSS"] = {k: val for k, val in cvss.items() if val}
            vulns.append(item)
        out["Results"].append(
            {
                "Target": result.get("Target"),
                "Class": result.get("Class"),
                "Type": result.get("Type"),
                "Vulnerabilities": vulns,
            }
        )
    return out


def trim_grype(data: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields :func:`vulntriage.scanners.grype.parse_grype_report` reads."""
    matches = []
    for m in data.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        matches.append(
            {
                "vulnerability": {
                    "id": vuln.get("id"),
                    "severity": vuln.get("severity"),
                    "description": _short(vuln.get("description")),
                    "cvss": vuln.get("cvss") or [],
                    "fix": vuln.get("fix") or {},
                },
                "relatedVulnerabilities": [
                    {
                        "id": r.get("id"),
                        "cvss": r.get("cvss") or [],
                        "description": _short(r.get("description")),
                    }
                    for r in m.get("relatedVulnerabilities") or []
                ],
                "artifact": {
                    "name": art.get("name"),
                    "version": art.get("version"),
                    "type": art.get("type"),
                    "locations": [{"path": loc.get("path")} for loc in art.get("locations") or []][
                        :1
                    ],
                },
            }
        )
    src = data.get("source") or {}
    target = src.get("target") or {}
    return {
        "matches": matches,
        "source": {
            "type": src.get("type"),
            "target": {k: target.get(k) for k in ("userInput", "repoDigests")}
            if isinstance(target, dict)
            else target,
        },
        "distro": data.get("distro") or {},
    }


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("kind", choices=["trivy", "grype"])
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--cap",
        action="append",
        default=[],
        metavar="PKG=N",
        help="Keep at most N evenly spaced findings for package PKG (trivy only).",
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    caps = {k: int(v) for k, _, v in (c.partition("=") for c in args.cap)}
    for path in args.inputs:
        data = json.loads(path.read_text(encoding="utf-8"))
        trimmed = trim_trivy(data, caps) if args.kind == "trivy" else trim_grype(data)
        dest = args.out / path.name.removeprefix("grype_")
        dest.write_text(
            json.dumps(trimmed, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"{path} -> {dest} ({dest.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main()

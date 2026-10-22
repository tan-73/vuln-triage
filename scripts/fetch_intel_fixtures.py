#!/usr/bin/env python3
"""Snapshot real EPSS/KEV/NVD/OSV data for the CVEs in ``fixtures/trivy`` (needs Internet).

Run once when refreshing the demo dataset::

    python scripts/fetch_intel_fixtures.py --nvd-limit 60

Writes ``fixtures/intel/{kev.json,epss.json,osv.json,meta.json}`` and
``fixtures/intel/nvd/<CVE>.json``. Only public advisory data is stored.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulntriage.intel.feeds import (
    fetch_epss,
    fetch_kev,
    nvd_limiter,
    osv_ecosystem,
    query_osv,
)
from vulntriage.intel.http import FeedClient
from vulntriage.scanners.trivy import parse_trivy_report

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/query"


def dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8"
    )


def trim_nvd(payload: dict[str, Any]) -> dict[str, Any]:
    vulns = []
    for v in payload.get("vulnerabilities") or []:
        cve = v.get("cve") or {}
        metrics = cve.get("metrics") or {}
        vulns.append(
            {
                "cve": {
                    "id": cve.get("id"),
                    "descriptions": [
                        d for d in cve.get("descriptions") or [] if d.get("lang") == "en"
                    ],
                    "metrics": {
                        k: [
                            {
                                "type": m.get("type"),
                                "source": m.get("source"),
                                "cvssData": {
                                    "baseScore": (m.get("cvssData") or {}).get("baseScore"),
                                    "vectorString": (m.get("cvssData") or {}).get("vectorString"),
                                },
                            }
                            for m in metrics.get(k) or []
                        ]
                        for k in ("cvssMetricV31", "cvssMetricV30")
                        if metrics.get(k)
                    },
                    "weaknesses": cve.get("weaknesses") or [],
                }
            }
        )
    return {"totalResults": payload.get("totalResults", len(vulns)), "vulnerabilities": vulns}


def trim_osv(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "vulns": [
            {
                "id": v.get("id"),
                "aliases": v.get("aliases") or [],
                "affected": [
                    {"package": a.get("package"), "ranges": a.get("ranges") or []}
                    for a in v.get("affected") or []
                ],
            }
            for v in payload.get("vulns") or []
        ]
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nvd-limit", type=int, default=60)
    args = parser.parse_args()

    findings = []
    os_names: dict[str, str | None] = {}
    for path in sorted((FIX / "trivy").glob("*.json")):
        result = parse_trivy_report(json.loads(path.read_text()))
        findings.extend(result.findings)
        os_names[path.name] = result.os_name
        for f in result.findings:
            os_names.setdefault(f"{f.package_type}|{f.package_name}", result.os_name)
    cves = sorted({f.vuln_id for f in findings if f.vuln_id.startswith("CVE-")})
    print(f"{len(cves)} CVEs")

    client = FeedClient(timeout=60, max_retries=4)
    kev = fetch_kev(client, KEV_URL)
    subset = [v for v in kev["vulnerabilities"] if v.get("cveID") in set(cves)]
    dump(
        FIX / "intel/kev.json",
        {
            **{k: kev.get(k) for k in ("title", "catalogVersion", "dateReleased")},
            "count": len(subset),
            "vulnerabilities": subset,
        },
    )
    print(f"KEV: {len(subset)} of our CVEs listed (catalog {kev.get('catalogVersion')})")

    epss = fetch_epss(client, EPSS_URL, cves)
    dump(
        FIX / "intel/epss.json",
        {
            "status": "OK",
            "data": [
                {
                    "cve": e.cve_id,
                    "epss": f"{e.epss:.9f}",
                    "percentile": f"{e.percentile:.9f}",
                    "date": e.date,
                }
                for e in sorted(epss.values(), key=lambda e: e.cve_id)
            ],
        },
    )
    print(f"EPSS: {len(epss)} scores")

    kev_ids = {v["cveID"] for v in subset}
    missing = sorted(
        {f.vuln_id for f in findings if f.vuln_id.startswith("CVE-") and f.cvss_score is None}
    )
    missing.sort(key=lambda c: (c not in kev_ids, -(epss[c].epss if c in epss else 0)))
    key = os.environ.get("NVD_API_KEY")
    limiter = nvd_limiter(bool(key))
    for cve in missing[: args.nvd_limit]:
        payload = client.get_json(
            NVD_URL,
            params={"cveId": cve},
            headers={"apiKey": key} if key else None,
            limiter=limiter,
        )
        dump(FIX / f"intel/nvd/{cve}.json", trim_nvd(payload))
    print(f"NVD: {min(len(missing), args.nvd_limit)} of {len(missing)} CVEs without scanner CVSS")

    osv: dict[str, Any] = {}
    seen: set[str] = set()
    for f in findings:
        if f.fixed_version or f.target == "os":
            continue
        eco = osv_ecosystem(f.package_type)
        if not eco:
            continue
        k = f"{eco}|{f.package_name}|{f.installed_version}"
        if k in seen:
            continue
        seen.add(k)
        osv[k] = trim_osv(query_osv(client, OSV_URL, f.package_name, eco, f.installed_version))
    dump(FIX / "intel/osv.json", osv)
    print(f"OSV: {len(osv)} package queries")
    dump(
        FIX / "intel/meta.json",
        {
            "captured_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "kev_catalog_version": kev.get("catalogVersion"),
        },
    )


if __name__ == "__main__":
    main()

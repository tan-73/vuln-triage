# VulnTriage

AI-assisted vulnerability triage for a self-hosted Linux homelab.

Every night VulnTriage scans each running container image (and optionally the host),
enriches findings with real-world exploit intelligence, ranks them by actual risk
instead of CVSS alone, and writes a short report: *fix these N things first, here's why,
here's the fix.*

> Status: under active development. Scanning, enrichment, exposure analysis and risk scoring are complete.

## What works today

- **Container discovery** through the Docker Engine API (read-only `GET` requests only).
- **Trivy** image, `rootfs` (host OS packages) and `fs` (lockfiles) scanning, with
  **Grype** as an optional second scanner (`ENABLE_GRYPE=true` or `--grype`).
- **Deduplication across runs**: each finding keeps `first_seen`/`last_seen`. Findings no
  longer reported are marked `resolved`, and they reopen if they come back. Images that
  disappear are retired. A failed scan never resolves anything.

- **Threat-intel enrichment** from FIRST **EPSS**, CISA **KEV**, **NVD 2.0** and **OSV**:
  - KEV is one download. EPSS is batch-queried (100 CVEs per request). NVD is queried
    only for CVEs whose CVSS the scanner didn't provide (`NVD_MODE=missing`), under NVD's
    rate limits (5 requests per 30 s, or 50 with `NVD_API_KEY`) and with a per-run cap.
    OSV fills in fix versions the scanner didn't know.
  - Retries use exponential backoff, honour `Retry-After` and retry NVD's 403 rate-limit
    responses.
  - **Offline tolerance**: every feed is cached locally with a timestamp and only
    refetched after its TTL. If a feed is unreachable, or `OFFLINE=true` is set, the cache
    is used and its age is reported (`vulntriage feeds`).
- **Exposure analysis** gives each asset a level of `internet`, `lan`, `localhost` or `none`,
  with evidence, from:
  - Docker published ports: `0.0.0.0` counts as LAN, `127.0.0.1` as localhost, and a
    public bind address as internet;
  - reverse-proxy routes in **Nginx** (including Nginx Proxy Manager's generated files),
    **Caddyfiles** and **Traefik labels**, where a hostname matching
    `INTERNET_HOSTNAME_PATTERNS` counts as internet;
  - an optional **nmap** connect scan, which is only allowed against `ALLOWED_SCAN_CIDRS`.
    Those must be private ranges: a public CIDR in the allow-list is a startup error,
    and every refused target is logged.
- **Deterministic risk scoring** ([docs/SCORING.md](docs/SCORING.md)): KEV-listed
  findings always come first. Within each tier, findings are ordered by EPSS × exposure,
  with a bonus when a fix exists and CVSS used only as a tiebreaker. Every finding stores
  its score *and* a human-readable breakdown (`vulntriage explain <id>`).
- **Remediation groups**: findings are grouped by the single action that fixes them, for
  example "Update image grafana/grafana:8.3.0 (fixes 505 findings in 35 packages)" with
  `docker pull grafana/grafana:8.3`. Groups are ranked by risk and list the exact fixed
  version of every package.

```bash
pip install -e ".[dev]"
vulntriage scan                       # all running containers + configured hosts
vulntriage scan --image nginx:1.25.1  # just one image
vulntriage enrich                     # EPSS / KEV / NVD / OSV
vulntriage feeds                      # cache age and last error per feed
vulntriage exposure                   # internet / lan / localhost / none, with evidence
vulntriage score                      # deterministic risk score + remediation groups
vulntriage groups                     # ranked "fix this first" actions
vulntriage explain 42                 # why finding 42 scored what it did
vulntriage list-findings --kev
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests never touch the network. They use the Trivy/Grype JSON in `fixtures/`, which comes
from scanning old **public** images (see `scripts/build_fixtures.py`).

## License

MIT

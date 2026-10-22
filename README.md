# VulnTriage

AI-assisted vulnerability triage for a self-hosted Linux homelab.

Every night VulnTriage scans each running container image (and optionally the host),
enriches findings with real-world exploit intelligence, ranks them by actual risk
instead of CVSS alone, and writes a short report: *fix these N things first, here's why,
here's the fix.*

> Status: under active development. All features are implemented; documentation polish in progress.

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
- **LLM triage agent** ([docs/AGENT.md](docs/AGENT.md)): read-only tools, native tool
  calling for Anthropic, Gemini and any OpenAI-compatible endpoint (including Ollama),
  plus a deterministic mock for demos. The agent writes the executive summary, explains
  each "fix first" action and lists what is safe to defer. A **grounding post-check**
  verifies every CVE ID, version, package/version/asset association, EPSS, CVSS, KEV and
  exposure claim against the tool results, strips anything unsupported, and logs and
  stores the grounding rate. Advisory text is wrapped as untrusted data to guard against
  prompt injection.
- **Nightly pipeline**: scan → enrich → exposure → score → agent report → alerts, with
  per-stage timings and a commit after each stage. A failed stage is recorded and does
  not stop the run. Reports are saved to `reports/YYYY-MM-DD.md` and in the database.
- **Dashboard** (FastAPI + Jinja2, no external assets, strict CSP): overview with raw vs.
  actionable counts and trends, ranked remediation groups, assets, finding detail with
  score breakdown and intel, and rendered reports. Optional basic auth.
- **Alerts** (Telegram and/or SMTP, off by default) are sent only for *new* KEV-listed or
  high-risk internet-exposed findings, once per finding.

- **Evaluation** (`vulntriage eval [--demo]` → [docs/EVALUATION.md](docs/EVALUATION.md)):
  KEV recall@10/@20 against CVSS-only, EPSS-only and KEV-ablated rankings, noise
  reduction, grounding rate over recent reports with a hallucination self-test, and
  runtime per pipeline stage. On the demo dataset, 4,247 open findings come down to
  220 that need action (94.8% noise reduction) and 11 remediation actions, with KEV
  recall@20 of 100% vs. 0% for CVSS-only.

![Dashboard overview (demo data)](docs/img/dashboard-overview.png)

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
vulntriage report                     # LLM report -> reports/YYYY-MM-DD.md
vulntriage run                        # the whole nightly pipeline once
vulntriage run --demo                 # same, on bundled fixtures: no Docker/network/API key
vulntriage serve [--demo]             # dashboard on 127.0.0.1:8080 (+ scheduler if enabled)

docker compose up -d                  # dashboard + nightly scheduler, 127.0.0.1:8080
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

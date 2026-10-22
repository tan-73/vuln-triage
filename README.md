# VulnTriage

AI-assisted vulnerability triage for a self-hosted Linux homelab.

Every night VulnTriage scans each running container image (and optionally the host),
enriches findings with real-world exploit intelligence, ranks them by actual risk
instead of CVSS alone, and writes a short report: *fix these N things first, here's why,
here's the fix.*

> Status: under active development. Scanning, ingestion and threat-intel enrichment are complete.

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

```bash
pip install -e ".[dev]"
vulntriage scan                       # all running containers + configured hosts
vulntriage scan --image nginx:1.25.1  # just one image
vulntriage enrich                     # EPSS / KEV / NVD / OSV
vulntriage feeds                      # cache age and last error per feed
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

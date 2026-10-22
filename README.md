# VulnTriage

AI-assisted vulnerability triage for a self-hosted Linux homelab.

Every night VulnTriage scans each running container image (and optionally the host),
enriches findings with real-world exploit intelligence, ranks them by actual risk
instead of CVSS alone, and writes a short report: *fix these N things first, here's why,
here's the fix.*

> Status: under active development. Phase 1 (scanning and ingestion) is complete.

## What works today

- **Container discovery** through the Docker Engine API (read-only `GET` requests only).
- **Trivy** image, `rootfs` (host OS packages) and `fs` (lockfiles) scanning, with
  **Grype** as an optional second scanner (`ENABLE_GRYPE=true` or `--grype`).
- **Deduplication across runs**: each finding keeps `first_seen`/`last_seen`. Findings no
  longer reported are marked `resolved`, and they reopen if they come back. Images that
  disappear are retired. A failed scan never resolves anything.

```bash
pip install -e ".[dev]"
vulntriage scan                       # all running containers + configured hosts
vulntriage scan --image nginx:1.25.1  # just one image
vulntriage list-findings --severity high --limit 20
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

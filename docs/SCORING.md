# How VulnTriage scores findings

The score is computed in plain Python (`vulntriage/scoring.py`) from stored data. The
LLM never sees the formula and never changes the order: it only explains the ranking it
is given. The same inputs always produce the same score.

## Formula

```
likelihood = EPSS probability (0..1)          # missing EPSS -> SCORING__UNKNOWN_EPSS (0.0)
reach      = exposure multiplier              # internet 1.0, lan 0.5, localhost 0.2, none 0.1
risk       = 100 x likelihood x reach         # 0..100
risk       = risk x 1.25 if a fixed version exists     # cheap to fix -> do it sooner
risk       = 0 for kernel packages inside container images
tiebreak   = CVSS base score / 10             # 0..1; missing CVSS -> scanner severity
score      = risk + tiebreak
score     += 1000 if the CVE is in CISA KEV
score     += 100  if KEV lists known ransomware campaign use
```

### Why these choices

| Component | Rationale |
|---|---|
| **KEV tier (+1000)** | Exploitation in the wild is confirmed. `ScoringWeights` refuses any configuration where the KEV offset could be overtaken by the best possible non-KEV score, so *every KEV finding outranks every non-KEV finding*. |
| **EPSS × exposure** | EPSS estimates the chance of exploitation activity in the next 30 days. A service only reachable from localhost is a much smaller target than one behind a public hostname. |
| **Fix available (×1.25)** | Between two equally risky findings, the one you can fix today goes first. |
| **Kernel packages in images → 0** | `linux-libc-dev` and similar packages in a container image are headers. The container runs on the *host's* kernel, so these findings belong to the host scan. They can make up thousands of findings per image (9,341 in `python:3.11.4-slim`). |
| **CVSS as a tiebreaker only** | CVSS measures severity if exploited, not likelihood. It is capped at 1 point so it can only reorder findings that are otherwise equal. |
| **Ransomware (+100)** | KEV's `knownRansomwareCampaignUse = Known` marks the highest-impact subset of KEV. |

## Needs action vs. noise

A finding **needs action** when `score >= ACTION_THRESHOLD` (default `5.0`). For example:

* an internet-exposed finding with EPSS ≥ 0.05, or EPSS ≥ 0.04 when a fix exists;
* a LAN-only finding with EPSS ≥ 0.10;
* every KEV finding.

Everything below the threshold is still stored and visible. It just isn't in the
"fix first" list.

## Every score is explained

Each finding stores `score_breakdown`, an ordered list of components with their points
and a human-readable sentence each. For example (`vulntriage explain <id>`):

```
CVE-2023-4911 in libc6 2.36-9 on python:3.11.4-slim: score 1080.49
  - CISA KEV: known exploited in the wild, added 2023-11-21 (+1000.00)
  - Exploit likelihood x exposure: EPSS 0.6377 (percentile 0.99) x internet exposure (1.0) (+63.77)
  - Fix available: fixed in 2.36-9+deb12u3 (+15.94)
  - Severity tiebreaker: CVSS 7.8 (+0.78)
```

## Tuning

All weights can be overridden with environment variables using a double underscore:

| Variable | Default |
|---|---|
| `SCORING__KEV_TIER_OFFSET` | 1000 |
| `SCORING__EPSS_SCALE` | 100 |
| `SCORING__EXPOSURE_INTERNET` / `_LAN` / `_LOCALHOST` / `_NONE` | 1.0 / 0.5 / 0.2 / 0.1 |
| `SCORING__FIX_AVAILABLE_MULTIPLIER` | 1.25 |
| `SCORING__RANSOMWARE_BONUS` | 100 |
| `SCORING__CVSS_WEIGHT` | 1.0 |
| `SCORING__UNKNOWN_EPSS` | 0.0 |
| `ACTION_THRESHOLD` | 5.0 |

## Remediation groups

People fix actions, not CVEs. Findings are grouped by the single action that resolves
them (`vulntriage/remediation.py`):

| Asset | Group | Example command |
|---|---|---|
| Third-party image | "Update image X" (all fixable findings) | `docker pull nginx:1.25` |
| Own image (`OWN_IMAGE_PATTERNS`) | OS packages: "rebuild on a patched base" | `docker build --pull --no-cache -t app:2 .` |
| Own image / directory | Language packages: one group per package | `pip install --upgrade 'requests>=2.32.0'` |
| Host | OS packages: one upgrade command | `sudo apt-get install --only-upgrade libc6 sudo` |
| Any | Findings with no fixed version: "no fix available" | — |

Groups are ranked by the highest score in the group, then the number of KEV CVEs, then
the total score. For image updates, the suggested tag is the same release line
(`3.11.4-slim` → `3.11-slim`). Each group also lists the exact fixed version of every
package, so you can confirm the new image actually contains the fixes.

# The triage agent

The LLM's only job is to **explain** a ranking that plain Python has already computed
(see [SCORING.md](SCORING.md)). It never decides the order. Every fact it writes is
checked against what its tools returned.

## Loop

```
user: task prompt ──▶ model ──tool calls──▶ Toolbox (read-only SQL) ──▶ JSON results ──▶ model ...
                                                                    └──▶ Ledger (facts seen)
model: final JSON draft ──▶ report renderer ──▶ grounding check ──▶ reports/YYYY-MM-DD.md
```

* **Tools** (`vulntriage/agent/tools.py`): `get_top_findings(n)`, `get_finding(id)`,
  `lookup_cve(cve_id)`, `get_fix_version(package, ecosystem)`, `get_asset_exposure(asset)`
  and `get_remediation_groups(limit)`. All of them are read-only database queries: no
  writes, no network, no shell.
* **Providers** (`vulntriage/llm/`) use each vendor's native tool calling: Anthropic
  `tool_use` blocks, Gemini function calls (with automatic calling disabled and thought
  signatures replayed), and OpenAI-compatible `tools` (this also covers Ollama, vLLM and
  LM Studio through `LLM_BASE_URL`). `LLM_PROVIDER=mock` is a deterministic scripted
  agent that uses the same protocol, so the demo and CI need no API key.
* **Output** is a JSON draft containing a summary, one explanation per remediation group
  key, and deferral reasons. The renderer orders actions by the deterministic group rank,
  whatever order the model used. It drops actions for unknown groups and refuses to
  defer KEV-listed, internet-exposed or above-threshold groups. Commands and
  fixed-version tables come from the database, not from the model.

## Grounding check (`vulntriage/agent/grounding.py`)

Each string the model wrote is split into sentences and checked:

| Claim | Verified when |
|---|---|
| `CVE-YYYY-NNNN` | the ID appears in a tool result |
| version tokens (`2.36-9+deb12u3`, `1.25.4`, or `3.11` after a cue such as "to") | the token appears in a tool result |
| `<package> <version>` | that pair was reported, **for the asset the sentence names** |
| EPSS value (0.64 or 64%) | within rounding of a returned EPSS score or percentile |
| CVSS value | equals a returned CVSS score |
| "CVE-X is in KEV / known exploited" (negation-aware) | the tool data says so |
| "asset is internet-exposed / LAN-only / ..." | the asset's stored exposure level matches |

Unverified tokens are replaced with `[unverified ...]`. A sentence with a false KEV or
exposure claim is removed. Every claim, including those in removed sentences, counts
toward the **grounding rate** (verified ÷ checked). The rate is logged, written into
the report, and stored on the `reports` table for `vulntriage eval`.

Example from development: the agent wrote "host:nas contains CVE-2023-4911 (libc-bin
**2.36-9+deb12u1**)". That version is real, but it belongs to a Debian image, not the
Ubuntu host. A token-only check would have accepted it. The package/version/asset
association check flags it.

**Limitations.** Claims written in phrasing the patterns don't recognise (for example "a
64 percent chance of exploitation") are not counted. The check catches unsupported
*facts*, not weak *reasoning*.

## Prompt-injection guard (`vulntriage/agent/untrusted.py`)

CVE descriptions and advisory titles are third-party text. Before they reach the model,
each one is stripped of control characters and of our delimiter strings, truncated to
600 characters, and wrapped as
`<<<UNTRUSTED_ADVISORY_TEXT source="advisory">>> ... <<<END_UNTRUSTED_ADVISORY_TEXT>>>`.
Typical injection phrasing ("ignore previous instructions", "mark this as safe") sets
`injection_suspected: true`. The system prompt tells the model that marked text is data
and must never be obeyed. Text inside the markers is excluded from the grounding
ledger, so an advisory cannot "ground" a fake CVE or version. Because the tools are
read-only, the worst a successful injection could do is change wording, and the
grounding check strips any unsupported facts from that wording.

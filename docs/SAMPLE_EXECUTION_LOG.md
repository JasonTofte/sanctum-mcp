# Sample execution log — tool timeline, token usage, finding traceability

This document is a committed, sanitized sample of a single Sanctum run, provided
so a reviewer can verify three things without running the system:

1. **Tool calls carry timestamps.** Every tool invocation writes a ledger entry
   with a UTC `ts`.
2. **Token usage and cost are recorded.** The eval harness reports per-question
   input/output token means and a total USD cost.
3. **A finding traces to its tool executions.** A `claim_finding` cites the exact
   `audit_id`s of the tool calls that justify it; each resolves to a ledger entry.

The run was a real LLM agent (`claude-opus-4-7`) driving the Sanctum MCP server
over the committed, license-clean synthetic corpus — **no real evidence, no
answer-key leak.** All absolute paths below are redacted (`<REPO>`, `<CASE_OUT>`);
the source ledger and report are not committed because they contain
machine-local paths that the secret scanner rejects.

> **Scope note.** This is one 44-question *smoke* run used to demonstrate the
> logging mechanism. Its task accuracy is **not** a headline benchmark number —
> the accuracy figures live in [`ACCURACY.md`](ACCURACY.md) and
> [`ACCURACY_REPORT.md`](ACCURACY_REPORT.md). This file is about *traceability and
> instrumentation*, not accuracy.

## Run metadata

| Field | Value |
|---|---|
| Date (UTC) | 2026-06-14 |
| Model | `claude-opus-4-7` |
| Arm | `sanctum` (parser + corroboration gate) |
| Corpus | `tests/fixtures/accuracy_corpus/questions.json` (44 questions, 5 families) |
| Case root | `tests/fixtures/accuracy_corpus/cases/` (synthetic, fixture-sidecar mode) |
| Ledger entries | 110 |
| Mean input tokens / question | ≈ 6,429 |
| Mean output tokens / question | ≈ 753 |
| Total cost | $2.24 |

## The autonomous arc (self-correction visible in the ledger)

The gate is a typed function the agent cannot argue past. The ledger shows the
agent discovering that empirically over the run — this behavior lives in the
logs, not in a script:

| Ledger rows | What the agent did | Gate result |
|---|---|---|
| early run | Cited a **single** family's `audit_id` per claim (AppCompat, then Explorer/NTUSER, Background-service, Kernel-ETW, SysMain in turn) | `DRAFT`, `n_distinct_families: 1` — every time |
| mid run | Began citing `audit_id`s from **two independent families** | `CORROBORATED`, `n_distinct_families: 2` |
| mid run | Cited **three** families | `FINAL`, `n_distinct_families: 3`, `c_scale: C5` |
| mid run | Cited two families that **agreed on *what* but disagreed on *when*** | `DRAFT` despite `n_distinct_families: 2` — the temporal demoter fired |

The agent was given goals, not a tool sequence. The transition from repeated
single-family `DRAFT`s to multi-family `CORROBORATED`/`FINAL` is the agent
adjusting its approach against the gate's machine-readable signal — in-context,
externally-verified self-correction. (The gate's correctness is a property of the
typed function and does not depend on the agent reasoning correctly; see
[`docs/THREAT_MODEL_TRIANGULATION.md`](THREAT_MODEL_TRIANGULATION.md).)

## Worked trace — one finding back to its tool executions

The agent reached a `FINAL` verdict on case `mf_c2agent_001`:

> *Hypothesis:* "A suspicious executable consistent with a C2 agent is present and
> was executed on the host, corroborated by Amcache InventoryApplicationFile
> entries, a Prefetch execution record, and Sysmon EID 1 process-create events."

The `claim_finding` payload (`audit_id f25851b0…`, `ts 2026-06-14T20:27:09Z`):

```json
{ "tier": "FINAL", "c_scale": "C5", "n_distinct_families": 3,
  "families": ["AppCompat", "SysMain", "Kernel-ETW"],
  "confirmation_basis": "independent_artifacts",
  "audit_ids": ["c985d678…", "4a04538d…", "9498c5f0…"] }
```

Each cited `audit_id` resolves to a tool execution earlier in the same ledger:

| Cited `audit_id` | Tool | `ts` (UTC) | Family | rows |
|---|---|---|---|---|
| `c985d678…` | `get_amcache` | 2026-06-14T20:26:58Z | AppCompat | 2 |
| `4a04538d…` | `get_prefetch` | 2026-06-14T20:26:58Z | SysMain | 1 |
| `9498c5f0…` | `get_sysmon_4688` | 2026-06-14T20:26:58Z | Kernel-ETW | 2 |

Three different Windows subsystems, recorded through three different code paths,
each defeated by a different anti-forensic technique — so the finding survives the
defeat of any one of them.

## Sanitized ledger excerpt

Six representative entries. Note the `prev_hash → line_hash` HMAC chain links each
entry to the previous one (the `FINAL` claim's `prev_hash` `b369c41e…` equals the
`get_sysmon_4688` entry's `line_hash` `b369c41e…`), so a reviewer can verify the
log was not silently rewritten. Each entry also records
`pre_sanitization_sha256` and `post_sanitization_sha256` of the tool payload.

```jsonl
{"tool":"get_amcache","audit_id":"da89725e…","ts":"2026-06-14T20:10:25Z","case_id":"smoke","rowcount":5,"input_ref":{"path":"<REPO>/tests/fixtures/accuracy_corpus/cases/smoke/registry/Amcache.hve","sha256":"c35f4436…"},"payload_ref":{"bytes":2258,"path":"<CASE_OUT>/get_amcache.json","sha256":"c1bb1b1d…"},"prev_hash":"00000000…","line_hash":"bbae95dd…"}
{"tool":"claim_finding","audit_id":"ca3ebc66…","ts":"2026-06-14T20:10:31Z","case_id":"smoke","rowcount":1,"input_ref":{"finding_hash":"f6bc59b0…"},"payload_ref":{"bytes":461,"path":"<CASE_OUT>/claim_finding.json","sha256":"bb655a83…"},"prev_hash":"bbae95dd…","line_hash":"bc10e55f…"}
{"tool":"get_amcache","audit_id":"c985d678…","ts":"2026-06-14T20:26:58Z","case_id":"mf_c2agent_001","rowcount":2,"input_ref":{"path":"<REPO>/tests/fixtures/accuracy_corpus/cases/mf_c2agent_001/registry/Amcache.hve"},"payload_ref":{"bytes":982,"path":"<CASE_OUT>/get_amcache.json","sha256":"d1c2b3d2…"},"prev_hash":"3e80e5a8…","line_hash":"df77cf37…"}
{"tool":"get_prefetch","audit_id":"4a04538d…","ts":"2026-06-14T20:26:58Z","case_id":"mf_c2agent_001","rowcount":1,"payload_ref":{"bytes":549,"path":"<CASE_OUT>/get_prefetch.json","sha256":"e4053552…"},"prev_hash":"df77cf37…","line_hash":"c4f591e8…"}
{"tool":"get_sysmon_4688","audit_id":"9498c5f0…","ts":"2026-06-14T20:26:58Z","case_id":"mf_c2agent_001","rowcount":2,"input_ref":{"path":"<REPO>/tests/fixtures/accuracy_corpus/cases/mf_c2agent_001/logs/Microsoft-Windows-Sysmon%4Operational.evtx"},"payload_ref":{"bytes":1200,"path":"<CASE_OUT>/get_sysmon_4688.json","sha256":"baaa5dc1…"},"prev_hash":"c4f591e8…","line_hash":"b369c41e…"}
{"tool":"claim_finding","audit_id":"f25851b0…","ts":"2026-06-14T20:27:09Z","case_id":"mf_c2agent_001","rowcount":3,"input_ref":{"finding_hash":"41ab32c4…"},"payload_ref":{"bytes":716,"path":"<CASE_OUT>/claim_finding.json","sha256":"13245135…"},"prev_hash":"b369c41e…","line_hash":"24622c26…"}
```

Hashes are truncated for readability; the full SHA-256 / HMAC values are produced
in the live ledger.

## Reproduce

```bash
ANTHROPIC_API_KEY=<your key> \
python3 -m scripts.run_dfir_metric_eval \
  --arm sanctum \
  --local-corpus tests/fixtures/accuracy_corpus/questions.json \
  --case-root tests/fixtures/accuracy_corpus/cases/smoke \
  --n-runs 1 --max-cost-usd 5 \
  --output-dir reports/ --model claude-opus-4-7
```

The harness runs the server in fixture-sidecar mode against synthetic evidence,
writes the token report to `reports/<run_id>.json`, and writes the audit ledger to
a temp dir (`$TMPDIR/sanctum-eval-*/ledger.jsonl`). Token usage is in the report's
`aggregates.sanctum` block (`mean_tokens_in`, `mean_tokens_out`, `total_cost_usd`);
the per-tool timeline and citation chain are in the ledger.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for how the ledger, family gate, and
sanitization boundary fit together.

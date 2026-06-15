# Accuracy Report

A short, judge-facing summary. The full method, tables, and statistics are in [`ACCURACY.md`](ACCURACY.md).

## Headline

| Measure (43 questions × 3 runs, Opus 4.7) | Sanctum | Bare model |
|---|---|---|
| Accuracy | **99.2%** [95.7, 99.9] | **16.3%** [10.9, 23.6] |
| Precision on CORROBORATED findings | 97.2% | — |
| False-confidence rate | 2.8% | — |

Same model, same questions, same evidence bytes. The only difference is the Sanctum server. The 82.9-point gap is the server's contribution. Confidence intervals are Wilson 95%.

## What we measured, and what we did not

We measured whether the agent gives the right answer on Windows execution-evidence questions, with and without Sanctum. We did not measure long open-ended investigations or how well the model reads a correct result; those depend on the model.

The benchmark is a 43-question subset we selected from DFIR-Metric, the closest published DFIR-LLM benchmark. Because we wrote the subset, an outside question set would be a stronger signal. The independent check below addresses part of that.

## Independent check — NIST CFReDS Data Leakage

We ran Sanctum's parsers against a real Windows 7 disk image that NIST publishes with its own answer key. This tests the parser layer against ground truth we did not write.

- The image was verified against NIST's published SHA-1 hashes and mounted read-only.
- All 8 applications the answer key documents were found.
- The three case-defining tools (Eraser, CCleaner, Google Drive) were each confirmed across three families — FINAL.
- iCloud appeared in one family and was reported as a single-source draft. That is correct: the answer key shows iCloud was uninstalled, which removed its other traces.
- Three of the five families are present on Windows 7 (BAM and Sysmon arrived in later Windows). Coverage is reported honestly as 3 of 5, not dressed up as 5.

The answer key is public, so this is a parser-extraction result, not a clean test of model memory. Full detail and the ingestion procedure are in [`DATASET_NIST_DATALEAKAGE.md`](DATASET_NIST_DATALEAKAGE.md).

## Findings-accuracy self-assessment

Honest accounting of the three error classes, scored against the NIST answer key and the within-model eval.

- **False positives (a confident finding that is wrong): none observed.** The case-critical tools were graded FINAL only where three independent families agreed. iCloud — present in a single family — was *not* promoted to a corroborated finding; it was held at DRAFT, which is correct, because the answer key shows iCloud was uninstalled and its other traces removed. The gate's job is to refuse confidence it has not earned, and here it did.
- **Missed artifacts: none in scope; one documented forensic boundary.** All 8 applications the NIST answer key documents were detected. One honest non-detection is a property of the evidence, not a parser bug: BAM does not record short-lived, PowerShell-launched processes, so a 60-second test binary need not appear there — Sanctum reports BAM's silence rather than inventing an entry. A real false-negative *bug* was found and fixed during validation: `regipy 6.x` returns small `REG_BINARY` values as hex strings rather than `bytes`, which silently dropped BAM and UserAssist entries until `_coerce_to_bytes()` was added. The fix is covered by the parser test suite. See [`ACCURACY.md`](ACCURACY.md) §"Parser bug: regipy 6.x REG_BINARY encoding".
- **Hallucinated claims: structurally prevented, not merely unobserved.** `claim_finding` cites `audit_ids[]`, and the gate refuses any citation that does not resolve to a real ledger entry — the agent cannot invent a source to satisfy the corroboration requirement. The residual risk is the model *misreading a correct result*, which the benchmark measures as a **2.8% false-confidence rate** (Wilson 95%), not a fabricated-evidence rate.

## Evidence integrity & bypass behavior

How the architecture keeps original evidence unmodified, and what happens when the agent (or a hostile input) tries to get around it. These are typed-function and OS-level properties, not prompt instructions.

**Preventing modification of original data:**

- **Evidence is mounted read-only at the OS level.** The operator command is `mount -o ro,noload,norecovery,noexec,nosuid` plus `blockdev --setro` on the backing device. `noload,norecovery` are load-bearing in addition to `ro`: on ext-family images the kernel will replay the journal — writing to the block device — even when mounted `ro` alone (confirmed by the kernel ext4 docs and the Linux write-blocker project). `blockdev --setro` is the belt-and-suspenders guard.
- **The server verifies the mount before serving.** `_validate_evidence_mount()` checks the VFS read-only flag via `os.statvfs` at startup and refuses to serve tool calls if `/cases` is writable. The dev-only `SANCTUM_SKIP_MOUNT_CHECK=1` bypass emits a WARN log — never silent.
- **There is no shell tool.** The MCP server exposes typed `get_*` functions only; no `execute_shell`/`run_command` exists, so there is no path for the agent to issue a write.

**What happens on a bypass attempt** (reproducible via the smoke tests in [`docs/REPRODUCTION.md`](REPRODUCTION.md) §"Bypass smoke test"):

| Attempt | Result |
|---|---|
| Path traversal via `case_id` (`../etc`) | `ValueError` — `_resolve_case` rejects it |
| Non-existent case | `FileNotFoundError` |
| Agent asks to write a file under `/cases/` | PreToolUse hook **deny** (and the mount is read-only regardless) |
| Agent asks to `execute shell` | No matching tool — the request cannot be expressed |
| Writable evidence mount at startup | Server **refuses to start** (no silent downgrade) |
| `claim_finding` citing a fabricated `audit_id` | **Refused** — the id does not resolve in the ledger |
| Post-hoc edit/insert/reorder of a ledger entry | Detected — the HMAC-SHA-256 chain breaks on verification |

Full runtime failure-mode analysis is in [`FAILURE_MODES.md`](FAILURE_MODES.md); the per-layer threat model is in [`ARCHITECTURE.md`](ARCHITECTURE.md) §"Threat model, per layer".

## Reproduce it

The within-model benchmark:

```bash
export ANTHROPIC_API_KEY=<key>
python3 -m scripts.run_dfir_metric_eval --arm both --n-runs 3 --output-dir reports/
```

The NIST parser check follows the read-only mount and extraction steps in [`DATASET_NIST_DATALEAKAGE.md`](DATASET_NIST_DATALEAKAGE.md). Real evidence is not committed to this repository; only results and hashes are.

# Runtime failure modes

This document enumerates runtime failure states for Sanctum's safety
infrastructure and classifies each as **fail-open**, **fail-closed**, or
**silent corruption** — the three categories from NIST-style threat-model
pre-mortems.

> A safety gate that fails-open in a way users cannot detect is worse than no
> gate at all. This table exists to force us to name the condition and its
> recovery path *before* it happens in production.

## State 1: `Bash(*)` accidentally in allow list

- **Trigger**: developer adds `"Bash(*)"` to `settings.json` → all hook
  permission decisions are silently ignored (Claude Code issue #41151).
- **Behaviour**: `PreToolUse` hook fires and returns `permissionDecision: "deny"`;
  Claude Code ignores it; tool executes.
- **Detection**: CI lint (`scripts/check_settings.sh`, week 2) rejects any
  settings.json shipping a wildcard Bash allow.
- **Recovery**: reject the commit; whitelist named commands only.
- **Classification**: **silent corruption** — guardrail appears present, isn't
  enforced.

## State 2: MCP tool-call path bypasses hook

- **Trigger**: Agent calls an `mcp__*` tool; Claude Code does not apply
  PreToolUse hook decisions to MCP calls (issue #33106).
- **Behaviour**: MCP server is the last line of defence; if the server exposes
  a write surface, the agent can reach it.
- **Detection**: `tests/test_server_boundaries.py::test_server_exposes_no_write_tool`
  runs in CI and asserts no tool exports a write/exec/delete verb.
- **Recovery**: server refuses the call from inside the typed-function body.
- **Classification**: **fail-open** relative to hooks; **fail-closed** if the
  server itself has no write tool.

## State 3: Evidence-driven prompt injection poisons the LLM

- **Trigger**: Malware string table or log entry contains a Sygnia-style
  PowerShell prompt injection payload.
- **Behaviour (unmitigated)**: LLM treats injected text as instruction; emits
  fabricated findings; the forged finding passes `claim_finding` if it cites
  ledger entries the agent already legitimately produced.
- **Detection**: the sanitization layer strips known patterns and hashes
  pre/post for audit; drift detectable by `sanctum.audit.verify_chain`.
- **Recovery**: once `claim_finding` ships (week 4), single-source findings
  are rejected, so a forged claim needs to produce ≥2 matching audit_ids —
  materially harder.
- **Classification**: **silent corruption** without mitigation; **fail-closed**
  with sanitization + triangulation in place.

## State 4: Case-path traversal via `case_id`

- **Trigger**: Agent passes `case_id="../../../../etc"` to a typed tool.
- **Behaviour**: `_resolve_case` raises `ValueError`; tool call fails.
- **Detection**: covered by `tests/test_server_boundaries.py`.
- **Recovery**: error surfaces to LLM; retry with valid case_id.
- **Classification**: **fail-closed**.

## State 5: Audit ledger tampered post-hoc

- **Trigger**: An attacker with disk access edits a past ledger entry to
  remove or rewrite a finding.
- **Behaviour**: next `verify_chain()` call detects the break — recomputed
  `line_hash` will not match stored value; `prev_hash` linkage to the next
  line breaks.
- **Detection**: `verify_chain` walks the entire ledger; the submission will
  include a `sanctum-verify` CLI and a weekly cron to stamp the current last
  line hash to an external notary (Sigstore or a one-way syslog).
- **Recovery**: the ledger's integrity failure is reportable but not
  automatically correctable — this is tamper-evidence, not tamper-prevention.
- **Classification**: **fail-closed** on detection; the untrustworthy ledger
  cannot be used to support a finding.

## State 6: Demo sampling non-determinism

- **Trigger**: Opus 4.7 rejects `temperature=0`; the recorded demo run may not
  reproduce the intended self-correction branch.
- **Behaviour**: Reflexion-style critique fires unpredictably.
- **Detection**: rehearse the demo multiple times; if the branch doesn't fire
  reliably, the script needs a hook-induced trigger.
- **Recovery**: convert the demo beat to a `PreToolUse` hook that always fires
  for the demo's specific tool-argument combination, returning a "need
  corroboration" message that forces the agent to call the next tool.
- **Classification**: **fail-open on demo signal** (not a security gate — a
  scoring-axis gate).

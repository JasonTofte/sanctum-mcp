# Runtime failure modes

This document enumerates runtime failure states for Sanctum's safety
infrastructure and classifies each as **fail-open**, **fail-closed**, or
**silent corruption** — the three categories from NIST-style threat-model
pre-mortems.

> A safety gate that fails-open in a way users cannot detect is worse than no
> gate at all. This table exists to force us to name the condition and its
> recovery path *before* it happens in production.

Each state below links to the corresponding bypass test in
[`tests/test_bypass.py`](../tests/test_bypass.py). The suite is the
FIND EVIL! Constraint Implementation rubric's primary evidence artifact —
see the repository [README's Bypass coverage section](../README.md#bypass-coverage)
for the full mapping table.

## State 1: `Bash(*)` accidentally in allow list

*Tested in*: enforced by project `.claude/settings.local.json` design; lint-level concern, not a code-path test.


- **Trigger**: developer adds `"Bash(*)"` to `settings.json`. Every matching
  bash command is then auto-accepted, and Claude Code silently ignores any
  PreToolUse `ask`/`deny` decision on auto-accepted tools (issue #41151,
  *"PreToolUse hooks 'ask'/'deny' decisions are silently ignored for all
  auto-accepted tools"*; companion issue #31523 on the `Bash(*)` wildcard
  specifically).
- **Behaviour**: `PreToolUse` hook fires and returns `permissionDecision: "deny"`;
  Claude Code ignores it; tool executes.
- **Detection**: CI lint (`scripts/check_settings.sh`, week 2) rejects any
  settings.json shipping a wildcard Bash allow.
- **Recovery**: reject the commit; whitelist named commands only.
- **Classification**: **silent corruption** — guardrail appears present, isn't
  enforced.

## State 2: MCP tool-call path bypasses hook

*Tested in*: [`tests/test_bypass.py::test_state2_no_write_exec_verb_exposed`](../tests/test_bypass.py).


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

*Tested in*: [`tests/test_bypass.py::test_state3_*`](../tests/test_bypass.py) — 5 tests.


- **Trigger**: Malware string table or log entry contains a Sygnia-style
  PowerShell prompt injection payload.
- **Behaviour (unmitigated)**: LLM treats injected text as instruction; emits
  fabricated findings; the forged finding passes `claim_finding` if it cites
  ledger entries the agent already legitimately produced.
- **Detection**: the sanitization layer strips known patterns and hashes
  pre/post for audit; drift detectable by `sanctum.audit.verify_chain`.
- **Recovery**: `claim_finding` (shipped) rejects single-source findings, so a
  forged claim needs to produce ≥2 matching audit_ids — materially harder.
- **Classification**: **silent corruption** without mitigation; **fail-closed**
  with sanitization + triangulation in place.
- **Formal analysis**:
  [`docs/THREAT_MODEL_SANITIZATION.md`](THREAT_MODEL_SANITIZATION.md)
  proves the strip-then-truncate ordering is correct under the
  adversarial model (straddle-position probability = 1 for any attacker
  with L > 64 KiB).
  [`docs/THREAT_MODEL_TRIANGULATION.md`](THREAT_MODEL_TRIANGULATION.md)
  quantifies forgery probability for the `claim_finding ≥2-of-5`
  gate and makes the case for a stratified `CORROBORATED | FINAL`
  tier split.

## State 3b: Evidence mount silently writable (ext-family journal replay)

*Tested in*: [`tests/test_bypass.py::test_invariant4_writable_mount_refused_at_startup`](../tests/test_bypass.py), [`tests/test_server_boundaries.py::test_validate_evidence_mount_*`](../tests/test_server_boundaries.py) — 4 tests.


- **Trigger**: operator mounts evidence with `-o ro,noexec,nosuid` alone (no
  `noload,norecovery`) on an ext3/ext4 image whose journal wasn't cleanly
  closed before acquisition. Kernel replays the journal on mount — a real
  write to the block device despite the ro flag.
- **Behaviour (unmitigated)**: evidence mtime/atime may change; a
  sufficiently aware attacker could pre-stage a dirty journal to inject
  content at mount time. The VFS ro flag is also strippable via
  `mount --bind,remount,rw` at the original superblock if an attacker has
  root on the host.
- **Detection**: `_validate_evidence_mount()` checks the VFS ro flag at
  server startup via `os.statvfs(path).f_flag & os.ST_RDONLY`; refuses to
  start if unset. The runtime check does **not** detect journal-replay
  writes (statvfs reports the mount flag, not the block-device state) — the
  `noload,norecovery` + `blockdev --setro` commands in `docs/REPRODUCTION.md`
  are load-bearing together with this check, not alternatives.
- **Recovery**: error message names the correct mount command to re-run.
- **Classification**: **fail-closed** at server startup when the mount is
  VFS-writable; **silent corruption** if operator uses insufficient mount
  flags and journal replay fires — mitigated only by the documented command
  and operator discipline.

## State 4: Case-path traversal via `case_id`

*Tested in*: [`tests/test_bypass.py::test_state4_*`](../tests/test_bypass.py) — 3 tests + 5 gap-closer tests under `test_gap_*_in_case_id_refused` covering Unicode, bidi, zero-width, newline, and shell metacharacter classes.


- **Trigger**: Agent passes `case_id="../../../../etc"` to a typed tool.
- **Behaviour**: `_resolve_case` raises `ValueError`; tool call fails.
- **Detection**: covered by `tests/test_server_boundaries.py`.
- **Recovery**: error surfaces to LLM; retry with valid case_id.
- **Classification**: **fail-closed**.

## State 5: Audit ledger tampered post-hoc

*Tested in*: [`tests/test_bypass.py::test_state5_audit_ledger_tamper_detected`](../tests/test_bypass.py).


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

*Tested in*: not applicable — this is a scoring-axis concern, mitigated by hook-induced demo triggers at recording time.


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

## State 7: Hostile-reviewer concern — Windows-host scope ceiling

*Tested in*: not applicable — this is a scope claim, not a runtime
state. The bypass-test coverage in
[`tests/test_bypass.py`](../tests/test_bypass.py) exercises the runtime
gate, not the scope of artifact families.


- **Trigger**: A reviewer or judge points out that the five-family scheme
  covers Windows-host execution-evidence only — not memory forensics,
  network artifacts, browser history, cloud logs, email, or macOS / Linux
  host forensics. They ask: *can an attacker exfiltrate via a non-covered
  surface and defeat the gate?*
- **Behaviour**: The gate continues to emit `DRAFT` for any claim that
  does not have ≥2 distinct families from the in-scope set. An attacker
  operating purely in an out-of-scope surface produces zero in-scope
  audit_ids; the `claim_finding` call returns no Finding at all (Layer 1
  refusal on empty `audit_ids[]`). An attacker operating partially
  in-scope produces ≤1 in-scope family; the gate returns `DRAFT`.
  Neither case promotes a forged finding past `DRAFT`.
- **Detection**: scope is documented in
  [README §Scope](../README.md) and
  [`docs/THREAT_MODEL_TRIANGULATION.md`](THREAT_MODEL_TRIANGULATION.md)
  §"Known limits and future work" #2. There is no runtime detection
  because there is no runtime corruption — the gate's behaviour is
  unchanged, only the *coverage* of what it can corroborate.
- **Recovery**: not applicable — the verdict is correct under the scope.
  Expansion of the family scheme to memory-resident artifacts is a v2
  followup; v1 chooses depth-over-breadth per the hackathon brief.
- **Classification**: **fail-safe via DRAFT** — out-of-scope evidence
  cannot promote a finding past `DRAFT`, only contribute to a `DRAFT`
  verdict the agent must explicitly mark as needing scope expansion.

## State 8: Hostile-reviewer concern — k=2 threshold is engineering judgment

*Tested in*: not applicable — this is a calibration concern, not a
runtime state. The numeric tables are regression-tested by
[`scripts/validate_threat_model_math.py`](../scripts/validate_threat_model_math.py).


- **Trigger**: A reviewer asks: *the `k=2` boundary leaves ~22% forgery
  probability under your own Poisson-binomial table — why is that
  acceptable?*
- **Behaviour**: The gate emits `CORROBORATED` (not `FINAL`) at `k=2`,
  and `FINAL` only at `k=3` (~4% forgery under the family revision in
  [`docs/THREAT_MODEL_TRIANGULATION.md`](THREAT_MODEL_TRIANGULATION.md)
  §"Revised Poisson-binomial with artifact families"). A consumer
  needing stricter assurance reads `confirmation_basis` and the tier
  name and routes accordingly. The gate does **not** elide the
  calibration question — it surfaces a typed verdict at every tier band.
- **Detection**: the calibration is shipped in tabular form,
  regression-tested by `scripts/validate_threat_model_math.py`, and
  named explicitly as engineering judgment under the
  independent-Bernoulli model in
  [`docs/THREAT_MODEL_TRIANGULATION.md`](THREAT_MODEL_TRIANGULATION.md)
  §"Known limits and future work" #3. The copula refinement that would
  tighten the bound is named as a v2 followup.
- **Recovery**: a deployment that wants `k=3`-only acceptance can treat
  `tier ∈ {DRAFT, CORROBORATED}` as "needs further corroboration" and
  act only on `tier == FINAL`. The typed surface makes that policy
  expressible without re-deriving the threshold.
- **Classification**: **fail-safe via DRAFT / tier-stratification** — the
  gate does not silently promote `k=2` to `FINAL`; the tier band is on
  the verdict and on the ledger entry.

## State 9: Hostile-reviewer concern — adversary corrals evidence to a single family

*Tested in*: not directly as a single bypass scenario — covered in spirit
by [`tests/test_bypass.py::test_state3_*`](../tests/test_bypass.py)
(injection-driven single-family inflation) and the deception-signal
coverage in [`docs/THREAT_MODEL_DECEPTION.md`](THREAT_MODEL_DECEPTION.md).


- **Trigger**: A reviewer asks: *what if an attacker disables four of
  five families (turn off Sysmon, disable BAM, clear Prefetch, flush
  AppCompat) so only one family — say UserAssist — can record evidence?
  The agent then has no path to ≥2 families.*
- **Behaviour**: The gate returns `DRAFT` (single-family input). The
  destruction itself leaves traces in the deception layer
  (`sanctum.deception` reason codes — SysMain service disable, EVTX log
  clearing via `wevtutil cl`, AppCompat flush), which surface as
  `deception_signals` in the next `claim_finding` call. With any
  deception signal present, the gate emits `DRAFT_TAMPER_SUSPECTED`
  regardless of family count. The attacker's single-family forgery thus
  cannot reach `CORROBORATED` *and* the destruction itself is recorded
  as a finding-relevant signal — the asymmetric trace property of
  destruction-vs-forgery noted in
  [`docs/THREAT_MODEL_TRIANGULATION.md`](THREAT_MODEL_TRIANGULATION.md)
  §"Scope and threat-model boundary".
- **Detection**: deception-signal coverage in
  [`docs/THREAT_MODEL_DECEPTION.md`](THREAT_MODEL_DECEPTION.md) and
  audit-ledger immutability via the HMAC chain
  ([`docs/THREAT_MODEL_LEDGER.md`](THREAT_MODEL_LEDGER.md)) — a forged
  ledger entry cannot survive `verify_chain`.
- **Recovery**: agent collects deception signals and re-issues
  `claim_finding` with them; the gate emits `DRAFT_TAMPER_SUSPECTED`,
  which the agent reports honestly to the operator.
- **Classification**: **fail-safe via DRAFT_TAMPER_SUSPECTED** — the
  gate's response to a corralling adversary is to demote, not to
  fabricate certainty.

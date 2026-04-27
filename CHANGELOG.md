# Changelog

All notable changes to Sanctum are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver.

## [Unreleased]

### Added

- **Typed `confirmation_basis` field on `Finding` (Phase B1
  pre-submission hardening).** The `Finding` schema now carries a
  `Literal["single_family", "independent_artifacts",
  "coupled_artifacts", "single_family_strong_signal"]` field that
  records *how* corroboration was achieved. v1 emits exactly two of
  the four values: `single_family` for DRAFT findings (one family
  voted) and `independent_artifacts` for CORROBORATED / FINAL
  findings (≥2 families voted; the v1 families are by-construction
  trust-root-disjoint). The other two values are reserved on the
  wire so a v2 producer can introduce sub-family splits
  (`coupled_artifacts`) or a single-family strong-signal escape
  hatch (`single_family_strong_signal`) without a breaking schema
  change. The field is recorded in both the in-memory `Finding`
  returned to the agent and the `claim_finding` ledger entry's
  `input_ref.finding` payload, and surfaces in the MCP wrapper's
  evidence-wrapped JSON response. Documented in
  [`docs/THREAT_MODEL_TRIANGULATION.md`](docs/THREAT_MODEL_TRIANGULATION.md)
  §"Confirmation basis (v1 vs v2)". Four new tests in
  `test_finding.py` pin the v1 emission contract; one extension to
  `test_finding_ledger_entry_has_finding_metadata` pins the ledger
  payload; one extension to
  `test_claim_finding_output_is_evidence_wrapped` pins the MCP
  response.

- **`claim_finding` exposed as an MCP tool in `src/sanctum/server.py`.**
  The agent can now invoke the family-corroboration gate over the wire:
  `claim_finding(case_id, hypothesis, audit_ids)` is `@mcp.tool()`-decorated,
  validates `case_id` against the same Unicode/path-traversal allowlist as
  `get_amcache` (refactored shared helper `_validate_case_id_format`), calls
  `sanctum.finding.claim_finding`, JSON-encodes the resulting `Finding`, and
  returns the payload through `sanitize() → wrap_evidence()` per CLAUDE.md
  invariant 2 (all tool output is quarantined). The MCP surface intentionally
  omits the `deception_signals` parameter — `DeceptionSignal` objects don't
  serialize cleanly across MCP and week-5 will wire deception detection into
  `get_*` calls automatically. Refusal exceptions
  (`ClaimFindingError`, `UnknownToolError`, `ValueError`) bubble naturally
  to the MCP client so the agent observes them as part of its self-correction
  loop. New boundary tests in `tests/test_server_boundaries.py` pin the
  evidence-wrap, the strict-fail-closed refusal of fabricated audit_ids
  (the most architecturally load-bearing test in the suite), the unsafe-
  case_id rejection (including a bidi-override codepoint case), and the
  property that successful findings extend the same HMAC chain as `get_*`
  calls.

- **`src/sanctum/finding.py` + `src/sanctum/families.py` — `claim_finding`
  family-corroboration gate (week-4 milestone).** The README's "Autonomous
  Execution Quality" row now points to actual code: `claim_finding(case_id,
  hypothesis, audit_ids, deception_signals=())` reads the referenced ledger
  entries, resolves each `audit_id` → family via the `TOOL_TO_FAMILY` policy
  table in `sanctum.families`, deduplicates families per CLAUDE.md invariant
  5, and routes `(n_distinct_families, deception_signal_present)` through
  `classify_confidence()` to produce a tier in
  `{DRAFT_TAMPER_SUSPECTED, DRAFT, CORROBORATED, FINAL}`. The result is
  appended to the audit ledger as a `tool="claim_finding"` entry with the
  finding payload packed into `input_ref.finding` — non-breaking schema
  extension; existing `verify_chain` covers findings on the same HMAC chain
  as `get_*` calls. `FindingConfidence` enum gained
  `DRAFT_TAMPER_SUSPECTED` (the post-demotion floor when a deception
  signal accompanies a single-family claim). `classify_confidence` gained
  a keyword-only `deception_signal_present` arg, default False — fully
  backward-compatible. Strict-fail-closed: empty `audit_ids`, missing
  ledger references, and unknown tool names all raise rather than silently
  routing past the gate. 22 new tests across `test_finding.py` (15) and
  `test_families.py` (7); existing `test_audit.py` extended with 5 new
  tests covering the demotion table.

- **`src/sanctum/deception.py` — forensic-deception reason-code layer.** New
  module recognises three named anti-forensic technique signatures
  (`BaseFlushAppcompatCache` / AppCompat flush, SysMain disabling to
  suppress Prefetch, MFT `$STANDARD_INFORMATION` timestomp) and emits typed
  `TamperReason` enum values consumed by the week-4 `claim_finding` gate
  as a confidence-downgrade signal. Deterministic predicates only — no
  ML, no tuned thresholds; each predicate is a small Boolean over named
  artifact fields. Surfaces explicit ambiguity codes
  (`AMBIGUOUS_LEGITIMATE_FLUSH_CONSISTENT`,
  `AMBIGUOUS_SYSMAIN_DISABLED_OPERATOR_PLAUSIBLE`) when a fingerprint
  also matches a legitimate operator action, per Garfinkel ICIW 2007
  false-positive discipline. Threat model in
  `docs/THREAT_MODEL_DECEPTION.md`; 17 unit tests in
  `tests/test_deception.py` pin signature, ambiguity, and absence-of-
  signal behaviour. Closes the structural-deception gap (attacker-
  authored evidence *structure*, not text) that `sanctum.sanitize`
  does not address.

- **First test fixture skeleton — `tests/fixtures/case_temp_exec_001/`.**
  README documenting the scenario (benign signed binary executed from
  `%TEMP%`, exercising AppCompat ↔ SysMain triangulation) plus the VM
  workflow to populate `artifacts/`; `ground_truth.py` encodes the
  typed expected findings the parser test will assert. Two distinct
  artifact families satisfies CLAUDE.md invariant #5 — `claim_finding`
  must return `CONFIRMED`. Format choice (Python module rather than
  YAML/JSON) is documented in the module docstring per the principle
  that fixture data read by code in the same project should not need
  a parsing layer. `artifacts/` is intentionally empty; the README
  documents how to regenerate it from the Parallels test rig.
- **`scripts/submission_dry_run.sh` + `Makefile`** — dev-time safety net that
  stashes `./.claude/` aside, runs `pytest`, the MCP stdio smoke test, and
  `scripts/check_no_secrets.sh`, then restores `./.claude/` via a shell
  `trap`. Verifies that Sanctum's behaviour is not load-bearing on
  framework-proprietary tooling under `./.claude/` — the property the
  hackathon submission's "architectural guardrails, not framework
  scaffolding" claim depends on. Refuses to run if a previous invocation
  left a `.claude.stash` behind (avoids overwriting manual recovery
  state). Invoke via `make submission-dry-run` or directly as
  `./scripts/submission_dry_run.sh`.

- **`docs/ADR_PARSER_LAYER.md` — five Architecture Decision Records for the
  parser layer.** Permanent extraction of the load-bearing decisions made
  during week-2 (frozen `ExecutionEvent` contract; BOTH-field sidecar
  validation; fail-loud `PartialImplementationError` over null-object;
  env-gated fixture mode; exception-message scrubbing via `_safe_field`).
  Working planning artifact `.sherlock-plan.md` remains the implementation
  trail; the ADR doc is the contributor-facing reference for *why* each
  invariant exists. Cross-linked from `src/sanctum/parsers/__init__.py`.
- **Typed parser layer + frozen `ExecutionEvent` contract.** New
  `src/sanctum/events.py` and the `src/sanctum/parsers/` package (6
  modules: `amcache`, `appcompat`/ShimCache, `prefetch`, `sysmon`, `bam`,
  `userassist`) ship the data contract between artifact parsing and the
  `claim_finding` triangulation gate. Parsers return `list[ExecutionEvent]`
  — a frozen dataclass whose `family` field uses the canonical
  `sanctum.families.TOOL_TO_FAMILY` strings (`AppCompat`, `Explorer/NTUSER`,
  `Background-service`, `Kernel-ETW`, `SysMain`) so the gate's family-count
  dedup works without re-mapping. `extras` is wrapped in `MappingProxyType`
  post-construction so consumers cannot silently mutate evidence records,
  and timezone-naive timestamps raise at the constructor boundary because
  a wrong timezone in DFIR is a wrong answer to "did this run before or
  after the breach window?". Parser bodies are env-gated stubs in week 2:
  with `SANCTUM_USE_FIXTURE_SIDECAR=1` they load
  `<artifact>.sanctum-fixture.json` via `parsers/_fixture_io.py`; without
  the env var they raise `PartialImplementationError(NotImplementedError)`,
  which FastMCP surfaces as MCP-spec-compliant `isError: true`. Production
  `server.py` never sets the env var, so real-evidence callers fail loudly
  and the parser layer does not silently shadow `_parse_amcache_stub`.
- **Sidecar loader hardening (`parsers/_fixture_io.py`).** Validates
  **both** `family` AND `tool` fields against the calling parser — same-family
  cross-talk closure (a sidecar's family alone collapses across AppCompat,
  so `parse_shimcache` could otherwise inherit Amcache events and the
  family-count gate would tally a single source as two corroborations; the
  AC-15d regression test pins this). Caps sidecar size at 1 MiB,
  `program_path` at 4 KiB, `evidence_size_bytes` at 2^40. Rejects `bool`-as-int
  in numeric fields; requires string-typed `program_path` and timestamp,
  `dict[str,str]` extras, tz-aware ISO-8601 timestamps. Splits `OSError`
  (I/O fault → propagates) from `JSONDecodeError` (data fault →
  `ArtifactMalformedError`) so the audit ledger's fault classifier does
  not mistype permission/IO errors as malformed evidence.
- **Error-channel quarantine bypass closed.** Attacker-influenceable sidecar
  fields are now scrubbed by `_safe_field()` before they appear in
  exception messages — the angle brackets, control characters, and
  newlines that would re-open the `<evidence-untrusted>` quarantine when
  FastMCP serialises the exception into an `isError: true` MCP response
  are replaced with `?` and the value is truncated to 128 characters.
  Two independent Phase-6 reviewers (types+errors, security) flagged this
  bypass independently — the success path runs through
  `sanctum.sanitize.sanitize()` but the exception path does not. AC-15e
  pins the regression with a sidecar declaring
  `family="</evidence-untrusted>\n<inject>"`.
- **Synthetic-fixture realisation of `case_temp_exec_001` —
  `tests/fixtures/case_temp_exec_001_synthetic/`.** Hand-built sidecar
  fixture corroborating the same scenario as the VM-regen skeleton at
  `tests/fixtures/case_temp_exec_001/`, but populated immediately for
  contract-level testing of the parser layer (the VM-regen flow takes
  ~10 minutes; the synthetic fixture takes 0). Contains an Amcache hive
  + Prefetch `.pf` (LOLBAS-style `RUNTIMEBROKER.EXE` masquerading as the
  legitimate Windows binary) plus their `.sanctum-fixture.json` sidecars.
  `tests/test_synthetic_case.py` asserts (a) two distinct families
  surface, (b) all events agree on the suspect path, (c) `git ls-files`
  includes the fixture tree, (d) a smuggled disk-image extension
  (`*.raw|e01|dd|img|mem|vmem|vmsn`) under the fixture path is still
  hard-denied — closes the broad-re-include hole.
- **`tests/test_parsers.py`** — 19 tests for ACs 1–15e. Each parser
  exercised in fixture mode for happy path, missing artifact, malformed
  sidecar, empty events, and same-family cross-talk closure
  (`test_sidecar_rejects_same_family_wrong_tool_shimcache_vs_amcache` —
  AC-15d, the load-bearing regression for the silent-corruption path
  identified in `feedback_sidecar_path_lookup.md`). AC-13 verifies
  `_TOOL`/`_FAMILY` constants in every parser module match the canonical
  `families.TOOL_TO_FAMILY` map via `importlib.import_module` — a regex
  over `family="..."` would have been tautological because the parsers
  use module-level constants.

### Changed

- **Phase A design-claim narrowing across README + threat-model docs.**
  Pre-submission audit surfaced ~22 design weaknesses; Phase A addresses
  the subset that is claim-overreach (vs. missing capability) by
  narrowing each claim to its defensible scope. Specifically:
  (1) `docs/THREAT_MODEL_TRIANGULATION.md` gains §"Scope and threat-model
  boundary" — family-count gate is a *pre-compromise* corroboration
  primitive; kernel-mode multi-family forgery is OOS for v1, defense
  shifts to deception layer + HMAC ledger.
  (2) `docs/THREAT_MODEL_DECEPTION.md` gains §"Constructive vs.
  destructive forgery" — v1 detects destructive anti-forensics
  signatures only; coherent constructive forgery is OOS, bounded by
  family count.
  (3) `CLAUDE.md` renames "self-correction demo" → "gate-firing demo";
  hook proves gate fires deterministically, not that LLM learned
  self-correction.
  (4) `README.md` gains §"Limits of structural defenses" — names
  interpretation hallucination, sanitization-allowlist residual,
  kernel-rootkit equivalence, hooks-as-defense-in-depth (vs. server-
  side typed boundary as the real guarantee).
  (5) `docs/THREAT_MODEL_SANITIZATION.md` gains §"Test-coverage scope" —
  bypass tests verify server-side stripping invariants; LLM
  end-to-end behavioral robustness is v2 followup.
  (6) `README.md` lead surfaces an explicit **Scope** line: Windows
  host-based execution-evidence forensics, not general DFIR.
  (7) `docs/REPRODUCTION.md` gains a top-of-file ⚠️ operator-discipline
  callout for ext-family `noload,norecovery` mount flags.
  (8) `README.md` Constraint Implementation row in scoring alignment
  table sharpens the server-side-vs-client-hook tier distinction.
  (9) `docs/THREAT_MODEL_LEDGER.md` gains §"Ledger field roles" —
  separates HMAC-keyed chain-integrity hashes (security boundary)
  from plain-SHA-256 content fingerprints (auditing aids).
  (10) `docs/LLM_AGNOSTIC.md` promotes the "tested-with vs.
  compliant-with" caveat to a top-of-file callout — architecturally
  agnostic, behaviorally validated on Opus 4.7 only for v1.
  No code, math, or test changes. `scripts/validate_threat_model_math.py`
  passes unchanged. Plan tracked at `private/plans/sanctum_v1_design_hardening.md`
  (gitignored).

- **`.gitignore`** — adds globbed disk/memory-image extension hard-denies
  (`**/*.raw`, `e01`, `dd`, `img`, `mem`, `vmem`, `vmsn`) so a smuggled
  evidence-image under any future re-include path is still ignored.
  Last-match-wins gitignore semantics; AC-19b regression test pins this.

## [0.2.0] — 2026-04-25

### Security

- **BREAKING — audit ledger upgraded from plain SHA-256 to HMAC-SHA-256.**
  The prior implementation computed `hashlib.sha256(canonical(entry))`
  with no keyed primitive; the README and CLAUDE.md architecture block
  described it as "HMAC-SHA256 chain" despite the code being a plain
  hash chain. An internal audit flagged the discrepancy: a plain-SHA-256
  chain is forgeable by any attacker with ledger write access, whereas an
  HMAC chain requires the attacker to also compromise
  `SANCTUM_LEDGER_HMAC_KEY`. The env var is now mandatory at server
  startup; `append_entry` and `verify_chain` both raise
  `RuntimeError` if the key is missing or shorter than 16 bytes. Operators
  must generate a 32-byte key via
  `python -c 'import secrets; print(secrets.token_hex(32))'` and export it
  before starting the server. No silent downgrade path exists — by design.
- **New optional RFC 3161 TSA witness — `src/sanctum/notary.py`.**
  `stamp_head()` binds the current ledger head to a Trusted Timestamp
  Authority's digital signature via ``openssl ts`` (no new Python deps);
  archives the request (`.tsq`) and response (`.tsr`) bytes alongside the
  ledger. Raises the integrity guarantee from tamper-evident (HMAC) to
  non-repudiable (PKI-signed witness) — the tier required by FRE 902(14)
  self-authentication and NIST SP 800-53 AU-10(5) Digital Signatures.
  Default TSA is `https://rfc3161.ai.moda`; override via `tsa_url`. Call
  at whatever cadence the incident context justifies (per-session for
  hackathon demos; per-N-entries for continuous monitoring).
- **Hardened `mount -o ro` invariant.** Sanctum now actually implements
  the runtime mount-check that CLAUDE.md has been promising: `main()`
  calls `server._validate_evidence_mount(cases_root)` at startup, checks
  the VFS ro flag via `os.statvfs`, and refuses to start on a writable
  mount. `docs/REPRODUCTION.md` expands the mount command to include
  `noload,norecovery` (required to prevent ext3/4 journal replay, which
  writes to the block device even on `-o ro`) plus `blockdev --setro`
  on the loop device. Dev-only `SANCTUM_SKIP_MOUNT_CHECK=1` bypasses
  with a WARN log — never silent.
- **Expanded sanitizer invisible-codepoint coverage.** `sanctum.sanitize`
  now strips the Unicode Tag block (U+E0001–U+E007F), both variation-
  selector blocks (U+FE00–U+FE0F, U+E0100–U+E01EF), and the classic
  zero-width / bidi / general-format ranges. Motivated by arXiv 2510.05025
  "Imperceptible Jailbreaking" — 100% ASR emoji-smuggling attacks that
  visible-pattern regex strip lists cannot catch. Invisibles are now
  stripped silently (no `[REDACTED]` marker) so dense smuggling payloads
  produce readable output; `SanitizationResult.invisibles_stripped` is a
  new field carried to the ledger.

### Changed

- **README — Autonomous Execution Quality row reframed; Reflexion dropped from
  roadmap.** The brief's "Autonomous Execution Quality" criterion is co-equal
  weight (1/6) **and** first tiebreaker **and** Stage 1 gating — three
  load-bearing roles. The prior README marked it as just "tiebreaker" and
  promised a Reflexion-style `<reflect>` pass on every tool call alongside
  the family gate. Huang ICLR 2024
  ([arXiv:2310.01798](https://arxiv.org/abs/2310.01798)) shows intrinsic
  self-correction (Reflexion / Self-Refine) degrades reasoning on average;
  Kamoi TACL 2024 ([arXiv:2406.01297](https://arxiv.org/abs/2406.01297))
  classifies the family-coupling gate Sanctum already plans to ship as the
  empirically-supported *external-signal* alternative. Net effect: scoring
  table row rewritten to reframe `claim_finding` as the primary self-
  correction primitive; week-5 Reflexion implementation **dropped**;
  freed week becomes `sanctum.deception` reason-code layer + week-6
  adversarial benchmark (refusal-under-tampering). Prior-art section
  adds Huang, Kamoi, and Conlan-Baggili-Breitinger DFRWS 2016 (the
  taxonomic foundation for the deception reason codes).

- **Triangulation gate reframed as *artifact families* not *subsystems*.**
  ShimCache and Amcache are both written by the Windows Application
  Experience Service and defeated together by the one-syscall
  `BaseFlushAppcompatCache` / `ShimFlushCache` anti-forensic primitive
  (open-source `AntiForensic.NET` clears both in one run). Counting them
  as two independent sources overstated forgery resistance by ~4
  percentage points at `k=2`. Updated README "senior-analyst gate",
  CLAUDE.md invariant #5, and `docs/THREAT_MODEL_TRIANGULATION.md` with
  a new "Family coupling and the AppCompat correction" section — the
  five families are {AppCompat, Explorer/NTUSER, BAM, Sysmon/ETW,
  Prefetch/SysMain}. Revised Poisson-binomial table with the family
  tuple `(0.10, 0.15, 0.15, 0.20, 0.30)` is regression-tested by
  `scripts/validate_threat_model_math.py` alongside the existing
  non-uniform table.

- **README IR-Accuracy baseline citation — Memory-LLM → DFIR-Metric.**
  The prior "Memory-LLM ACM 2025 = <20% precision" baseline could not
  be verified. A directed literature search against arXiv / DFRWS /
  ACL / OpenReview found no ACM-published paper matching that title.
  Pinned to **DFIR-Metric** (Cherif et al.,
  [arXiv:2505.19973](https://arxiv.org/abs/2505.19973), May 2025) —
  the verifiable closest prior-art DFIR-LLM benchmark; GPT-4.1's best
  reported score is 38.52% TUS@4 on Module III (disk/memory forensic
  tasks). `docs/ACCURACY.md` (roadmap week 8) will pin regression
  numbers against DFIR-Metric TUS@m going forward.

### Added

- `docs/LLM_AGNOSTIC.md` + `scripts/smoke_test_mcp_stdio.sh`: document and
  verify the LLM-agnosticism claim. The doc states the invariant-by-invariant
  contract between the server and any compliant stdio MCP client, names the
  Claude-Code-specific defense-in-depth layer (PreToolUse hook, Bash
  allowlist, hook-induced demo determinism) with generic equivalents for
  Cline / Continue / Claude Desktop / OpenAI MCP shim, and gives connection
  snippets for each. The smoke test pipes a three-message JSON-RPC handshake
  (`initialize` → `notifications/initialized` → `tools/list`) through
  `python -m sanctum.server` and verifies `get_amcache` is advertised —
  passing this is necessary + sufficient for any stdio MCP client to inherit
  Sanctum's server-side guarantees. Claude Code remains the reference client;
  portability is an architectural claim, not a tested-everywhere one.

- `scripts/threat_model_priors.py`: single source of truth for the
  per-subsystem compromise probabilities feeding
  `docs/THREAT_MODEL_TRIANGULATION.md`. Self-contained dataclass +
  helper functions, no third-party deps. Both
  `validate_threat_model_math.py` and `validate_with_sympy.py` now
  import from here, so a change to a prior cannot drift between code
  and docs without the validators failing. Pinned by
  `tests/test_threat_model_priors.py` (canonical vector, hardest-first
  ordering, mean, and per-row rationale invariants).

- `sanctum.sanitize.MAX_INPUT_BYTES` (16 MiB) + `InputTooLargeError`:
  closes the unbounded-`L` DoS surface flagged in
  `docs/THREAT_MODEL_SANITIZATION.md` §7. Inputs above the cap raise
  before any regex scanning runs. Per-call override available via the
  `max_input_bytes` kwarg for callers with legitimate outsize
  payloads. Regression pinned by new boundary tests.
- `sanctum.audit.FindingConfidence` (enum: DRAFT | CORROBORATED |
  FINAL) and `classify_confidence(n_distinct_subsystems)` helper —
  pins the tier boundaries recommended in
  `docs/THREAT_MODEL_TRIANGULATION.md` §5 into code so the future
  week-4 `claim_finding` implementation cannot silently drift from
  the threat-model doc. Ledger-stable string values enforced by test.

- `scripts/sanctum-mcp.service`: hardened systemd unit for production /
  dedicated-host deployments. Runs Sanctum as a non-privileged `sanctum`
  user with `NoNewPrivileges`, `ProtectSystem=strict`,
  `ReadOnlyPaths=/cases /evidence`, `MemoryDenyWriteExecute`, dropped
  `CapabilityBoundingSet`, and a seccomp filter that denies
  `@privileged @debug @mount @reboot @swap` syscalls. Architectural
  defences still come from the typed tool surface; the sandbox limits
  blast radius under the failure-domain-isolation lens.
  `docs/DEV_PLATFORM.md` gains an install/verification section.

- `docs/THREAT_MODEL_LEDGER.md`: full threat model for the audit-ledger
  posture ladder (rung 0 = plain SHA-256, rung 1 = HMAC, rung 2 = RFC 3161
  witness, rung 3 = public Merkle-tree). Documents the attacker model at
  each rung, residual risk, operational cadence guidance, and the
  `openssl ts -verify` command an independent party would run to check a
  stamp.
- `src/sanctum/notary.py`: RFC 3161 TSA stamping for the ledger head.
  `openssl`-based, no new Python dependencies.
- `tests/test_notary.py`: 6 tests covering the stamp-head happy path,
  head-binding correctness, openssl-missing/TSA-rejection error paths,
  archive-dir override, and empty-ledger behaviour. All tests mock
  subprocess + urllib so the suite never hits the network.

### Changed

- `sanctum.sanitize.sanitize`: accepts new `max_input_bytes` kwarg
  with default `MAX_INPUT_BYTES`. Pre-existing callers are unaffected
  (sub-16-MiB inputs behave identically). The staged pipeline is now
  invisibles-strip → pattern-redact → truncate; the new first stage
  covers the Unicode Tag block, both variation-selector blocks, and
  the classic zero-width / bidi / general-format ranges.

- `docs/THREAT_MODEL_SANITIZATION.md`: formal justification for the
  `strip → truncate` ordering in `sanctum.sanitize`. Proves correctness
  via prefix-closure of pattern-freeness; derives the random-placement
  straddle probability `(k−1)/L` and the adversarial upper bound of 1.
  Flags the unbounded-`L` DoS surface as the remaining obligation.
- `docs/THREAT_MODEL_TRIANGULATION.md`: quantitative analysis of the
  `claim_finding` ≥2-of-5 gate. Uniform Binomial(5,p) and Poisson-
  binomial tables under realistic per-subsystem compromise priors
  (ShimCache 0.05 … Sysmon 0.30). Argues for a stratified
  `CORROBORATED (k=2)` vs `FINAL (k=3)` tier split and shows that
  adding a 6th subsystem at fixed `k` is a regression, not an
  improvement.
- `scripts/validate_threat_model_math.py`: stdlib-only regression
  checker for every numeric claim in the two threat-model docs; exits
  non-zero on drift so the docs can't silently become wrong.
- `scripts/validate_with_sympy.py`: independent exact-rational
  verification using SymPy. Renders each probability as a reduced
  fraction so it can be pasted straight into Wolfram Alpha or any
  CAS for third-party confirmation.

- `scripts/claude-session.sh`: clean-room bash helper that spawns Claude Code
  inside a disposable git worktree on a fresh branch. Disposable by default;
  explicit branch names are preserved on exit. No framework dependencies —
  safe for a public repo. Install as `claude-sanctum` via a symlink into
  `~/.local/bin` (see README "Local development" section).

- `tests/test_bypass.py`: consolidated bypass-attempt test suite (16 tests)
  mapping 1:1 to `docs/FAILURE_MODES.md` states 1–6 plus five gap classes —
  symlink escape via case-dir internals; Unicode/bidi/zero-width/newline/
  shell-metacharacter in `case_id`; truncation-boundary injection; ledger-
  file-missing design-pin. Directly responsive to FIND EVIL! Constraint
  Implementation rubric's "tested for bypass" criterion.
- README "Bypass coverage" section with a scannable matrix mapping attack
  classes to specific test names; `docs/FAILURE_MODES.md` gains "Tested in"
  cross-references to the same suite.

- `docs/DEV_PLATFORM.md`: maintainer-facing developer-platform guide. Documents
  the physical x86_64 Ubuntu 22.04 native setup used to build Sanctum,
  hardware equivalence class and don't-buy list, bring-up sequence, how this
  path differs from the judge-facing `docs/REPRODUCTION.md`, local demo-
  recording setup for the 5-min FIND EVIL! screencast, and the EC2 +
  SANS SIFT AMI cloud fallback. Feeds the hackathon's Try-It-Out Instructions
  deliverable.

### Changed

- `src/sanctum/server.py` `_resolve_case`: tightened case-ID validation before
  filesystem resolution. New `_SAFE_CASE_ID` allowlist rejects Unicode control
  characters (bidi override `\u202e`, zero-width `\u200b`, etc.), shell
  metacharacters, whitespace, and path separators. Adds an explicit `..`
  substring check as belt-and-suspenders, and independently resolves the
  Amcache hive path to catch symlinks *inside* the case directory pointing
  outside — the case-dir containment check alone did not catch this class.
- `pyproject.toml`: allow `E501` in `tests/*` — descriptive test-function
  signatures are self-documenting and wrapping them at 100 chars hurts
  readability without protecting anything.

### Fixed

- `tests/test_sanitize.py::test_pre_and_post_hashes_equal_when_clean`:
  assertion was inverted (`!=` where `==` was intended per the test name and
  the second assertion in the same test). Pinned the property: when no
  injection patterns are stripped and no truncation fires,
  `pre_hash == post_hash` exactly.

- `docs/REPRODUCTION.md`: replaced `REPLACE_WITH_REPO` placeholder in the Step 1
  clone command with the real `JasonTofte/sanctum-mcp` URL; added a note on
  private→public flip timing and `gh auth login` for contributors cloning
  before submission.

### Changed

- `scripts/bootstrap_vm.sh`: pinned `teamdfir/sift-saltstack` to commit
  `96b7d989` (2026-04-14, *"Merge pull request #219 from digitalsleuth/vol3"*)
  so judge reruns match the commit validated during development. The upstream
  repo ships a stale `VERSION` file (`v2020.01.01-rc1`) despite active commits,
  so drift is otherwise silent.

## [0.1.0] — 2026-04-17

### Added

- Initial P0 skeleton: public-safe repository layout, MIT license, hackathon submission scaffolding.
- Python package `sanctum` with MCP server stub, append-only audit ledger, and prompt-injection sanitization helpers.
- One typed tool: `get_amcache(case_id)` returning structured Amcache rows wrapped in `<evidence-untrusted>` delimiters.
- Architecture + reproduction documentation (`docs/ARCHITECTURE.md`, `docs/REPRODUCTION.md`).
- Public-secrets precommit check (`scripts/check_no_secrets.sh`).
- SIFT Workstation bootstrap documentation for Ubuntu 22.04 pinned to a specific `teamdfir/sift-saltstack` commit SHA.

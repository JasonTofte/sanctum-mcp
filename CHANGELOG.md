# Changelog

All notable changes to Sanctum are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver.

## [Unreleased]

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

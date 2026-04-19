# Changelog

All notable changes to Sanctum are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver.

## [Unreleased]

### Added

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

# Changelog

All notable changes to Sanctum are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver.

## [Unreleased]

### Added

- `src/sanctum/payload.py`: write-once on-disk payload offload for tool returns.
  Claude Code's MCP stdio transport silently drops JSON-RPC responses larger than
  ~800–1100 bytes (anthropics/claude-code#36319); an inline evidence dump on a
  realistic Amcache hive would exceed that cliff, leaving the ledger with a
  successful `audit_id` for output the LLM never saw. Every typed tool now writes
  its full sanitized payload under `$SANCTUM_OUTPUT_ROOT/<case_id>/<audit_id>/<tool>.json`
  and returns only a short summary carrying a `payload_ref`. The caller reads the
  referenced file via the generic `Read` tool.
- `LedgerEntry.payload_ref` field: every audit entry now carries the on-disk
  reference (path + sha256 + bytes + format), tamper-evident via the existing
  chain. Older ledgers without the field verify cleanly because `verify_chain`
  hashes whichever keys are present in each entry.
- `append_entry(audit_id=...)` optional kwarg: lets callers pre-generate the UUID
  so the ledger key and an on-disk artifact path are guaranteed to match.

- `scripts/claude-session.sh`: clean-room bash helper that spawns Claude Code
  inside a disposable git worktree on a fresh branch. Disposable by default;
  explicit branch names are preserved on exit. No framework dependencies —
  safe for a public repo. Install as `claude-sanctum` via a symlink into
  `~/.local/bin` (see README "Local development" section).

### Fixed

- `docs/REPRODUCTION.md`: replaced `REPLACE_WITH_REPO` placeholder in the Step 1
  clone command with the real `JasonTofte/sanctum-mcp` URL; added a note on
  private→public flip timing and `gh auth login` for contributors cloning
  before submission.

### Changed

- `get_amcache` return shape: was an inline `<evidence-untrusted>`-wrapped JSON
  dump of parsed Amcache rows; now returns a short summary (JSON wrapped in the
  same delimiter) with `audit_id`, `rowcount`, `input_ref`, `payload_ref`,
  pre/post-sanitization hashes. The full payload lives on disk. Breaking change
  for anything parsing the previous return shape; only the pre-merge smoke
  tests did.

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

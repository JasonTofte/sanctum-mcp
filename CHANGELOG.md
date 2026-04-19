# Changelog

All notable changes to Sanctum are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver.

## [Unreleased]

### Added

- `scripts/claude-session.sh`: clean-room bash helper that spawns Claude Code
  inside a disposable git worktree on a fresh branch. Disposable by default;
  explicit branch names are preserved on exit. No framework dependencies —
  safe for a public repo. Install as `claude-sanctum` via a symlink into
  `~/.local/bin` (see README "Local development" section).

- `docs/DEV_PLATFORM.md`: maintainer-facing developer-platform guide. Documents
  the physical x86_64 Ubuntu 22.04 native setup used to build Sanctum,
  hardware equivalence class and don't-buy list, bring-up sequence, how this
  path differs from the judge-facing `docs/REPRODUCTION.md`, local demo-
  recording setup for the 5-min FIND EVIL! screencast, and the EC2 +
  SANS SIFT AMI cloud fallback. Feeds the hackathon's Try-It-Out Instructions
  deliverable.

### Fixed

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

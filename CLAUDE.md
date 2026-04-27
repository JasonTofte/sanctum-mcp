# Sanctum — project conventions for Claude Code

This file is the project-local guide for AI-assisted development on Sanctum. It is **committed to the public repo** so contributors and judges can see how the project is structured and what invariants must not be violated.

## Non-negotiable invariants

1. **No shell passthrough from the MCP server.** The server exposes typed functions only. If a tool needs new data from a CLI, wrap it with a function whose signature cannot accept arbitrary arguments. Never expose `execute_shell`, `run_command`, or equivalent.

2. **All tool output is quarantined.** Every MCP tool must return its payload wrapped in `<evidence-untrusted>…</evidence-untrusted>` after passing through `sanctum.sanitize.strip_known_injection_patterns()`. No unstructured free-text returns.

3. **Every tool call produces an `audit_id` (UUID).** The ID is written to the append-only JSONL ledger before the call returns. The ledger is HMAC-SHA-256-chained via `SANCTUM_LEDGER_HMAC_KEY` — the server refuses to start if the key is unset (no silent downgrade to plain SHA-256). Optional RFC 3161 TSA stamping via `sanctum.notary.stamp_head()` raises the ledger from tamper-evident to non-repudiable; see [`docs/THREAT_MODEL_LEDGER.md`](docs/THREAT_MODEL_LEDGER.md). Findings must cite `audit_ids[]` for every assertion; the server rejects `claim_finding` calls where any `audit_id` is missing.

4. **Evidence paths are read-only.** `/cases/` and `/evidence/` under the case directory are mounted read-only at the OS level. The operator-side command is `mount -o ro,noload,norecovery,noexec,nosuid` plus `blockdev --setro` on the underlying device — the `noload,norecovery` flags suppress ext-family journal replay on mount, which would otherwise write to the block device despite the `ro` flag. The MCP server runs `_validate_evidence_mount()` at startup, checks the VFS ro flag via `os.statvfs`, and refuses to serve tool calls if the mount is writable. A dev-only `SANCTUM_SKIP_MOUNT_CHECK=1` env var bypasses the runtime check while emitting a WARN log — never silent.

5. **Findings require ≥2 independent artifact *families*** (not per-artifact subsystems — the AppCompat family collapses ShimCache and Amcache because they share a trust root and are defeated together by `BaseFlushAppcompatCache` / `AntiForensic.NET`). The five families are: AppCompat, Explorer/NTUSER, Background-service (BAM), Kernel-ETW (Sysmon/4688), and SysMain (Prefetch). `claim_finding(hypothesis, audit_ids[])` maps each audit_id to its family, deduplicates, and returns DRAFT if fewer than two families are present. See [`docs/THREAT_MODEL_TRIANGULATION.md`](docs/THREAT_MODEL_TRIANGULATION.md) §"Family coupling and the AppCompat correction" for the quantitative justification.

## What does NOT go in this repo

- Framework-proprietary skills, agents, rules, or hooks from the parent dev-framework.
- Live evidence (disk/memory images, case notes, analyst reports).
- API keys, ledger HMAC salts, or test-case ground-truth answers (gate-able data).
- Screenshots or transcripts that contain third-party copyrighted material.

## Private content lives in `/private/`

Drafts, scratch notes, hackathon scoring or ground-truth records, demo takes, copyrighted screenshots, transcripts, and any IP-flavored documentation that must NOT ship with the public repo live in a top-level `/private/` directory. The directory is gitignored as a single line; structure inside is free-form (`notes/`, `scratch/`, `drafts/`, `demo_takes/`, etc.). Do not place private content under `docs/` (which is committed) or in scattered top-level dot-directories — `/private/` is the single root for non-public content, and a single gitignore line is easier to audit than N scattered patterns.

## Project-local `.claude/` is gitignored

The local Claude Code settings (`.claude/settings.json`, any local skills) are gitignored. This is deliberate — the settings file references local absolute paths and may embed developer-specific conventions. A `docs/CLAUDE_SETTINGS_REFERENCE.md` documents the *shape* of the recommended settings for reviewers and contributors.

## Coding conventions

- Python 3.10+, type-hinted throughout (`from __future__ import annotations` in every module).
- `ruff` for lint (`ruff check`), `black` for format (`black .`), `pytest` for tests.
- MCP server uses the official `mcp` Python SDK with the `FastMCP` decorator API.
- No dependency additions without a justification comment in `pyproject.toml` near the entry.

## Commit / release flow

- Semver; version tracked in `src/sanctum/__init__.py` and `pyproject.toml`.
- `CHANGELOG.md` updated on every non-trivial commit under `## [Unreleased]`.
- Pre-commit: run `scripts/check_no_secrets.sh` and `pytest` green before opening a PR.

## Pinning policy

Sanctum is an operator-deployed MCP server, not a library — runtime deps are exact-pinned (`==X.Y.Z`) in `pyproject.toml`, and the resolved tree (with per-wheel SHA256 hashes) is captured in `requirements.txt`. The lockfile is the source of truth for production install.

- **Operator install path**: `pip install -r requirements.txt --require-hashes`. The `--require-hashes` flag rejects any wheel whose hash doesn't match the lockfile, defeating the "compromised mirror swaps a wheel" supply-chain attack on a server that handles attacker-influenced bytes (Prefetch, EVTX, registry hives).
- **Why `windowsprefetch` is the load-bearing pin**: upstream is single-maintainer and last released `4.0.3` on 2021-04-29 — exact-pin + hash-lock is the mitigation for the abandonment-then-account-takeover risk on a parser that consumes attacker bytes. Same caution applies to `regipy` and `python-evtx` (single-maintainer evidence-path libraries); same exact-pin treatment.
- **Bumping a dep**: edit `pyproject.toml`, then regenerate the lockfile in one step:
  ```
  pip install -e '.[dev]'   # if pip-tools isn't already installed
  pip-compile pyproject.toml --generate-hashes -o requirements.txt
  ```
  Commit `pyproject.toml` and `requirements.txt` together. A PR that bumps one without the other will surface as a `--require-hashes` install failure in CI.
- **Vendoring contingency**: if `windowsprefetch` ships a CVE with no upstream patch, vendor under `third_party/windowsprefetch/` (license-text preserved) and remove from `dependencies`. The threat model already names this as the documented contingency — see [`docs/THREAT_MODEL_DEPENDENCIES.md`](docs/THREAT_MODEL_DEPENDENCIES.md) §"Posture ladder" rung 4.

## Testing invariants (enforced by `pytest` in CI)

- **No test may read outside `/tests/fixtures/`.** Test evidence is synthetic or derived from CFReDS public-domain samples only.
- **Every new typed tool must ship with:** a unit test, a sanitization test (evidence containing an injection pattern → pattern stripped), an audit-ledger test (call produces a valid `audit_id`), a bypass test (tool cannot be coerced into a write path).

## Hackathon-specific norms

- **No cute prompt-engineering.** Architectural enforcement first; prompt instructions are defense-in-depth, not primary.
- **Every README claim must be traceable to a source file, a cited paper, or a test.**
- **Demo determinism — gate-firing, not learned self-correction.** The demo proves that the family-corroboration gate *fires deterministically* on a single-family claim and that the LLM's downstream behavior is bounded by that fire. It does **not** claim the LLM learned to self-correct; that distinction is load-bearing. Hook-induced tool blocks make the gate observable to judges in a reproducible way (Opus 4.7 rejects non-default temperature, so sampling-retry demos are unavailable). The gate's correctness is a typed-function property and is independent of agent cognition — see [`docs/THREAT_MODEL_TRIANGULATION.md`](docs/THREAT_MODEL_TRIANGULATION.md) §"Scope and threat-model boundary".

# Sanctum — project conventions for Claude Code

This file is the project-local guide for AI-assisted development on Sanctum. It is **committed to the public repo** so contributors and judges can see how the project is structured and what invariants must not be violated.

## Non-negotiable invariants

1. **No shell passthrough from the MCP server.** The server exposes typed functions only. If a tool needs new data from a CLI, wrap it with a function whose signature cannot accept arbitrary arguments. Never expose `execute_shell`, `run_command`, or equivalent.

2. **All tool output is quarantined.** Every MCP tool must return its payload wrapped in `<evidence-untrusted>…</evidence-untrusted>` after passing through `sanctum.sanitize.strip_known_injection_patterns()`. No unstructured free-text returns.

3. **Every tool call produces an `audit_id` (UUID).** The ID is written to the append-only JSONL ledger before the call returns. Findings must cite `audit_ids[]` for every assertion; the server rejects `claim_finding` calls where any `audit_id` is missing.

4. **Evidence paths are read-only.** `/cases/` and `/evidence/` under the case directory are mounted read-only at the OS level (`mount -o ro,noexec,nosuid`). The MCP server validates this mount before the first tool call and refuses to start if the mount is writable.

5. **Findings require ≥2 independent artifact subsystems.** `claim_finding(hypothesis, audit_ids[])` validates against a rule table. Single-source claims are returned as DRAFT with `needs_corroboration`.

## What does NOT go in this repo

- Framework-proprietary skills, agents, rules, or hooks from the parent dev-framework.
- Live evidence (disk/memory images, case notes, analyst reports).
- API keys, ledger HMAC salts, or test-case ground-truth answers (gate-able data).
- Screenshots or transcripts that contain third-party copyrighted material.

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

## Testing invariants (enforced by `pytest` in CI)

- **No test may read outside `/tests/fixtures/`.** Test evidence is synthetic or derived from CFReDS public-domain samples only.
- **Every new typed tool must ship with:** a unit test, a sanitization test (evidence containing an injection pattern → pattern stripped), an audit-ledger test (call produces a valid `audit_id`), a bypass test (tool cannot be coerced into a write path).

## Hackathon-specific norms

- **No cute prompt-engineering.** Architectural enforcement first; prompt instructions are defense-in-depth, not primary.
- **Every README claim must be traceable to a source file, a cited paper, or a test.**
- **Demo determinism.** Self-correction is demonstrated via hook-induced tool blocks that always fire — never via sampling retries, because Opus 4.7 rejects non-default temperature.

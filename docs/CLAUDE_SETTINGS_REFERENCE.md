# Claude Code settings reference

The project-local `.claude/settings.json` is **gitignored** — it embeds local
paths and developer-specific conventions that should not ship to a public repo.
This document captures the *shape* of the recommended settings so contributors
can reproduce an architecturally-sound configuration.

## Why gitignored

- Absolute paths (e.g., `/Users/<you>/...`) leak dev-machine identity.
- Settings drift frequently during iteration; pinning them in-repo adds churn
  without benefit.
- The architectural guarantees Sanctum relies on come from the MCP server's
  typed boundary, not from this file. Hooks are defense-in-depth.

## Recommended `.claude/settings.json`

```jsonc
{
  "permissions": {
    "allow": [
      // Explicit named bash commands only. NO "Bash(*)" — a wildcard Bash
      // allow makes every matching command auto-accepted, and PreToolUse
      // "ask"/"deny" decisions on auto-accepted tools are silently ignored
      // (Claude Code issue #41151, "PreToolUse hooks 'ask'/'deny' decisions
      // are silently ignored for all auto-accepted tools"; see also #31523
      // on the Bash(*) wildcard specifically).
      "Bash(ls:*)",
      "Bash(cat:*)",
      "Bash(head:*)",
      "Bash(tail:*)",
      "Bash(grep:*)",
      "Bash(rg:*)",
      "Bash(jq:*)",
      "Bash(python3:*)",
      "Bash(pytest:*)",
      "Bash(ruff:*)",
      "Bash(black:*)",
      "Bash(git status)",
      "Bash(git diff:*)",
      "Bash(git log:*)"
    ],
    "deny": [
      // Evidence paths — read-only to the agent, always.
      "Edit(/cases/**)",
      "Edit(/evidence/**)",
      "Write(/cases/**)",
      "Write(/evidence/**)",
      // Audit ledger — append-only, agent must not Edit past entries.
      "Edit(/var/lib/sanctum/**)",
      "Edit(**/ledger.jsonl)",
      // Dangerous bash
      "Bash(rm:*)",
      "Bash(dd:*)",
      "Bash(mkfs:*)",
      "Bash(sudo:*)",
      "Bash(wget:*)",
      "Bash(curl:*)",
      "Bash(ssh:*)",
      "Bash(scp:*)",
      "Bash(nc:*)",
      "Bash(python3 -c:*)",   // arbitrary eval via -c
      "Bash(bash -c:*)",
      "Bash(sh -c:*)"
    ],
    "defaultMode": "default"
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          { "type": "command", "command": "$CLAUDE_PROJECT_DIR/scripts/evidence_path_guard.sh" }
        ]
      }
    ]
  },
  "mcpServers": {
    "sanctum": {
      "command": "python",
      "args": ["-m", "sanctum.server"],
      "env": {
        "SANCTUM_CASES_ROOT": "/cases",
        "SANCTUM_OUTPUT_ROOT": "/var/lib/sanctum/output",
        "SANCTUM_LEDGER_PATH": "/var/lib/sanctum/ledger.jsonl",
        "SANCTUM_LEDGER_HMAC_KEY": "<64-hex-char key — generate, see below>"
      }
    }
  }
}
```

### Required `env` keys

The server **refuses to start** if any of these is unset (no silent defaults):

| Key | Purpose | Notes |
|---|---|---|
| `SANCTUM_CASES_ROOT` | Read-only evidence mount | Mounted `ro` at the OS level in production. |
| `SANCTUM_OUTPUT_ROOT` | Server-writable offload dir for tool payloads | Must **not** resolve under `SANCTUM_CASES_ROOT`. |
| `SANCTUM_LEDGER_PATH` | Append-only HMAC-chained audit ledger | — |
| `SANCTUM_LEDGER_HMAC_KEY` | Ledger HMAC key | Generate once: `python -c 'import secrets; print(secrets.token_hex(32))'`. Keep it out of any committed file. |

If the evidence directory is not a real read-only mount (e.g. testing against
`tests/fixtures/`), also add `"SANCTUM_SKIP_MOUNT_CHECK": "1"` — the server logs
a WARN so the bypass is never silent. Never use it in production.

## The `evidence_path_guard.sh` hook (not yet in-repo — week 2)

Reads the tool-call JSON from stdin, returns exit 2 with a reason if the
target path falls under `/cases/` or `/evidence/`. This is **defence in
depth**. The primary architectural guarantee is that the MCP server exposes
no write tool for evidence — the hook catches residual Edit/Write attempts
from Claude Code's built-in tool family.

## What NOT to put in `.claude/settings.json`

- Your Anthropic API key. Put it in `~/.anthropic/credentials` or use the
  Claude Code auth flow. Never in a project file.
- Organisation-specific framework skill references (e.g., Sherlock/Holmes/
  Hudson methodology). Those belong in your `~/.claude/` globals, not in
  this repo.
- Absolute paths to your home directory in `args` or `env`. Use
  `$CLAUDE_PROJECT_DIR` for project-relative paths, `/cases` for evidence.

## Known Claude Code hook-bypass classes to be aware of

The tests in `tests/test_server_boundaries.py` (and the week-7 bypass suite)
exercise these directly. If you see a hook silently fail, check against:

| Issue | Condition that voids the hook |
|---|---|
| #41151 | PreToolUse `ask`/`deny` silently ignored for *any* auto-accepted tool; `Bash(*)` in allow list is the most common way to inadvertently auto-accept |
| #31523 | Companion UX/security issue: `Bash(*)` wildcard is undiscoverable as a silent hook-decision voider |
| #33106 | PreToolUse deny is NOT enforced on `mcp__*` tool calls |
| #44534, #46044 | PreToolUse deny is NOT enforced on `Task`/Agent subagent calls |
| #37210, #47853 | Edit tool ignores some hook decisions in certain versions |
| #15897 | When multiple PreToolUse hooks chain, later `updatedInput` is discarded |
| #48760 | Flat JSON return without `hookSpecificOutput` wrapper is silently dropped |
| #37662 | Compound Bash commands (`ok_cmd && bad_cmd`) can evade deny matching |
| #33343, #35601 | `--print` headless mode does not enforce hooks |

Trust the MCP server boundary; treat hooks as defence in depth.

# LLM-agnostic deployment

Sanctum's architectural guarantees live in the **MCP server**, not in the
model on the other end of the stdio transport. This document is the contract
between Sanctum and any MCP-compliant client — it states what the server
guarantees independently of the client, names the thin Claude-Code-specific
layer, and shows how to connect non-Claude clients.

## TL;DR

Every invariant in [`CLAUDE.md`](../CLAUDE.md) §"Non-negotiable invariants" is
enforced **in-process by the MCP server**:

| Invariant | Enforcement site | Client-dependence |
|---|---|---|
| No shell passthrough | `src/sanctum/server.py` tool registry — only typed `@mcp.tool()` functions exposed | None. The client cannot invoke a tool that the server does not advertise over `tools/list`. |
| Evidence quarantine | `sanctum.sanitize.sanitize()` + `wrap_evidence()` — every tool return wraps bytes in `<evidence-untrusted>` | None. Sanitization runs before the MCP response leaves the server. |
| Audit-ledger UUID on every call | `sanctum.audit.append_entry()` invoked inside each tool | None. Pre-commit of the ledger entry happens before `return` in the tool body. |
| Read-only evidence mount | `_validate_evidence_mount()` at `main()` startup; server refuses to start on a writable mount | None. Enforced by `os.statvfs` at OS level. |
| ≥2 artifact families for findings | `claim_finding(hypothesis, audit_ids[])` typed function (week 4) — refuses single-family evidence | None. The gate is a typed function; the client cannot bypass it with free-text. |

The server does not trust the client. This is the whole point of the
architectural approach — a guardrail expressed as *"the typed function doesn't
exist"* doesn't fail when the client's model is role-play-jailbroken.

## What's Claude-Code-specific (and why it's defense-in-depth only)

| Claude-Code-coupled asset | What it does | Generic equivalent |
|---|---|---|
| `.claude/settings.json` PreToolUse hook `case-data-guard.sh` | Catches stray `Edit`/`Write` attempts against `/cases/` and `/evidence/` from Claude Code's *built-in* file tools (not MCP tools) | Already redundant: the server's `_validate_evidence_mount()` enforces this at the OS layer. Other MCP clients have narrower built-in tool surfaces — most don't expose unrestricted file write to begin with. |
| Bash allowlist (no `Bash(*)` wildcard) | Prevents Claude Code from auto-accepting arbitrary shell commands when operating in the same session | Cline, Continue, Claude Desktop, and the OpenAI MCP shim do not expose an analogous Bash tool by default. The attack surface this guards against is specific to Claude Code. |
| Demo determinism via hook-induced tool blocks (README: *"Opus 4.7 rejects non-default temperature"*) | Makes self-correction demo reproducible on a model that can't accept `temperature=0` | For GPT-5 / Gemini / local models where `temperature` and `seed` are configurable, set `temperature=0` + fixed seed. Same observable outcome, different knob. |

None of these are load-bearing for Sanctum's security invariants. They are
belt-and-suspenders around a second-tier failure mode (Claude-Code-internal
tool bypass), not primary enforcement.

## Connecting non-Claude clients

Sanctum speaks MCP JSON-RPC 2.0 over stdio. The launch command is always:

```bash
python -m sanctum.server
```

Required environment variables (same for every client):

```bash
export SANCTUM_CASES_ROOT=/cases
export SANCTUM_LEDGER_PATH=/var/lib/sanctum/ledger.jsonl
export SANCTUM_LEDGER_HMAC_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
```

### Cline (VS Code)

Add to your Cline MCP config (Cline → Settings → MCP Servers):

```json
{
  "mcpServers": {
    "sanctum": {
      "command": "python",
      "args": ["-m", "sanctum.server"],
      "env": {
        "SANCTUM_CASES_ROOT": "/cases",
        "SANCTUM_LEDGER_PATH": "/var/lib/sanctum/ledger.jsonl",
        "SANCTUM_LEDGER_HMAC_KEY": "<your-hex-key>"
      }
    }
  }
}
```

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS
(same schema as Cline):

```json
{
  "mcpServers": {
    "sanctum": {
      "command": "python",
      "args": ["-m", "sanctum.server"],
      "env": { "SANCTUM_CASES_ROOT": "/cases", "SANCTUM_LEDGER_PATH": "/var/lib/sanctum/ledger.jsonl", "SANCTUM_LEDGER_HMAC_KEY": "<your-hex-key>" }
    }
  }
}
```

### Continue (VS Code / JetBrains)

`~/.continue/config.json` `mcpServers` block takes the same shape.

### OpenAI MCP shim / any stdio MCP client

The protocol is vendor-neutral. Any client that can launch a subprocess and
speak MCP JSON-RPC over its stdin/stdout will see the same tool surface and
inherit the same architectural guarantees.

## Verifying MCP compliance

[`scripts/smoke_test_mcp_stdio.sh`](../scripts/smoke_test_mcp_stdio.sh) pipes
a three-message JSON-RPC handshake (`initialize` → `notifications/initialized`
→ `tools/list`) through `python -m sanctum.server` and verifies that
`get_amcache` is advertised. Passing this smoke test is a necessary and
sufficient condition for any stdio MCP client to be compatible with Sanctum.

```bash
./scripts/smoke_test_mcp_stdio.sh
# PASS — MCP stdio handshake + tools/list advertises get_amcache
```

## What changes per model, and what doesn't

| Concern | Changes per model? | Why |
|---|---|---|
| Tool surface exposed | No | Server-enforced; every client sees the same `tools/list`. |
| Sanitization of tool output | No | Runs in `sanctum.sanitize` before the response leaves the server. |
| Audit-ledger integrity | No | HMAC chain + optional RFC 3161 witness are server-side. |
| Read-only mount check | No | `os.statvfs` runs at server startup, independent of client. |
| Triangulation gate (`claim_finding`) | No | Typed function; clients cannot bypass by rephrasing. |
| Reflexion self-correction quality | **Yes** | Smaller / non-reasoning models may produce weaker reflection text. Measurable via the accuracy regression in `docs/ACCURACY.md`. |
| Demo determinism mechanism | **Yes** | Opus 4.7 uses hook-induced blocks (no temperature knob); other models can use `temperature=0` + fixed seed. |
| Evidence-injection resistance | Partially | The server strips known patterns before the LLM sees bytes. Downstream model robustness to residual novel payloads varies. Measurable via the `test_state3_*` bypass suite on each target model. |

Rule of thumb: if the invariant is a **bytes-level** property of the server's
output, it is LLM-agnostic. If the invariant depends on the model choosing to
follow a prompt instruction, it is model-dependent — and Sanctum minimises
this class by pushing as much as possible into the typed tool surface.

## Caveat — tested-with vs. compliant-with

Sanctum's reference client is **Claude Code with Opus 4.7** (per the hackathon
brief, which prescribes Claude-family models). The hackathon judges will
reproduce against that configuration. LLM-agnosticism is an *architectural*
claim (the server's invariants don't depend on the client), not a
*tested-everywhere* claim. The smoke test proves MCP-stdio compatibility for
any compliant client; observed behavior quality per model is a separate
measurement axis.

# Architecture

How Sanctum turns attacker-written evidence into a graded finding, and where the trust boundary sits. The README has the short version; this is the depth.

> The submission architecture diagram (component topology, pattern label, and guardrail legend) lives at [`docs/figures/architecture_flow.png`](figures/architecture_flow.png) — regenerate it with `python3 scripts/render_arch_diagram.py`. It mirrors the "Component topology" and "Pattern and guardrail taxonomy" sections below.

## Architectural pattern: Custom MCP Server

Sanctum is a **Custom MCP Server** (one of the four patterns the FIND EVIL! brief names — not a Direct Agent Extension, Multi-Agent Framework, or Alternative Agentic IDE). It is built on **FastMCP**, the decorator API that ships inside the official [`mcp` Python SDK](https://github.com/modelcontextprotocol/python-sdk) (FastMCP 1.0 was folded into the SDK in 2024). The agent — Claude Code driving Opus 4.7 — connects over MCP stdio and sees only the typed `get_*` tools and `claim_finding`. There is no shell tool, so the agent's reachable surface is exactly the typed functions Sanctum exposes.

## Component topology

```
  SIFT Workstation VM (Ubuntu 22.04 LTS · regipy / python-evtx / windowsprefetch)
  ┌──────────────────────────────────────────────────────────────────┐
  │  DATA SOURCES                         SANCTUM MCP SERVER (FastMCP) │
  │  (read-only evidence)   read-only     ┌──────────────────────────┐ │        ┌──────────────┐
  │  disk image (E01/dd)  ── mount ─────► │ parsers → ExecutionEvent │ │  MCP   │ AGENT        │
  │  registry hives          [ARCH]       │ sanitize + <evidence-..> │ │ ◄stdio►│ Claude Code  │
  │  EVTX · Prefetch                      │ claim_finding gate       │ │ (typed │ (Opus 4.7)   │
  │       │                               │ HMAC append-only ledger  │ │  only) └──────────────┘
  │  TRUST BOUNDARY ◄ untrusted           └────────────┬─────────────┘ │
  └────────────────────────────────────────────────────┼──────────────┘
                                          cite audit_ids │
                                                         ▼
                          OUTPUT PIPELINE: graded finding (DRAFT / CORROBORATED / FINAL)
                                          + signed ledger · optional RFC 3161 stamp
```

The five brief-named components map directly: **agent** = Claude Code; **SIFT Workstation tools** = the Ubuntu 22.04 host and the `regipy` / `python-evtx` / `windowsprefetch` parser libraries; **MCP server** = Sanctum (`server.py`); **data sources** = the read-only-mounted evidence; **output pipeline** = the graded finding plus the signed ledger.

## Pattern and guardrail taxonomy

The brief asks submissions to distinguish prompt-based from architectural guardrails. Sanctum's primary controls are architectural — enforced by code or the OS, independent of model cognition. Prompt-layer instructions exist only as defence-in-depth.

| Guardrail | Kind | Where it lives |
|---|---|---|
| Read-only evidence mount (`ro,noload,norecovery` + `blockdev --setro`, `os.statvfs` check) | **Architectural** | OS mount + `server.py` startup check |
| Typed tools, no shell passthrough | **Architectural** | `server.py` tool surface |
| ≥2-family corroboration gate | **Architectural** | `finding.py` typed function |
| HMAC-chained append-only ledger | **Architectural** | `audit.py` |
| Hash-locked dependency install (`--require-hashes`) | **Architectural** | `requirements.txt` lockfile |
| System-prompt role / scope constraint | Prompt-layer (defence-in-depth) | agent system prompt |
| `<evidence-untrusted>` delimiters around tool output | Prompt-layer (defence-in-depth) | `sanitize.py` wrapper |

The gate's correctness is a property of a typed function, not of the model's reasoning — so defeating the prompt layer does not defeat the gate.

## A tool call, end to end

```
  evidence on disk  (attacker-written — UNTRUSTED)
        │  read-only mount
        ▼
  parser  (regipy / python-evtx / windowsprefetch)  -> structured event
        ▼
  strip known injection text
        ▼
  wrap in <evidence-untrusted> ... </evidence-untrusted>
        ▼
  write audit_id to the HMAC-chained log  ──►  append-only ledger
        ▼
  return to the agent
        ▲
        └─ TRUST BOUNDARY: everything above this line is untrusted bytes
```

The agent never receives raw evidence. It receives stripped, wrapped, logged output. Anything the agent later claims must cite the audit_ids minted here.

## A finding

```
  claim_finding(hypothesis, audit_ids[])
        │  each audit_id must resolve in the ledger   (fabricated id -> refused)
        ▼
  count distinct families -> DRAFT (1) · CORROBORATED (2) · FINAL (3+)
        │  anti-forensic trace present?    -> DRAFT_TAMPER_SUSPECTED
        │  families disagree on the time?  -> demote one tier
        ▼
  new ledger row  (a promotion is a new entry, never a rewrite)
```

## Module map

| Module | Job |
|---|---|
| `server.py` | The MCP server. Exposes the typed `get_*` tools and `claim_finding`. No shell tool exists. Sanitizes and wraps every result. |
| `parsers/` | Six real-mode parsers, one per family member (Amcache, ShimCache, BAM, UserAssist, Prefetch, Sysmon). Each returns an `ExecutionEvent`. |
| `events.py` | `ExecutionEvent` — the frozen record every parser returns (program path, family, timestamp, source). |
| `families.py` | Maps a tool to its evidence family, defines the five families, and marks which ones carry execution-time (used by the temporal check). |
| `sanitize.py` | Strips known injection patterns from evidence before the agent sees it. |
| `audit.py` | The append-only, HMAC-chained log. Mints audit_ids and grades the tier from the family count and the tamper bit. |
| `finding.py` | The gate. `claim_finding` runs the three layers below. |
| `deception.py` | Anti-forensic detection. Produces the signals that demote a finding to `DRAFT_TAMPER_SUSPECTED`. |
| `notary.py` | Optional RFC 3161 timestamp on the log head. |
| `payload.py` | Write-once payload offload, so large tool output stays out of the agent's context. |

## The three gate layers

All three live in `finding.py` and run on every `claim_finding` call.

**Layer 1 — provenance refusal.** The call is refused (it raises, returns no finding) if `audit_ids` is empty, any audit_id is not in the log, or a tool name is unknown. A fabricated citation cannot pass. This is the boundary that stops an agent from inventing a source to satisfy the gate.

**Layer 2 — confidence grading.** Count the distinct families behind the claim. One is DRAFT. Two is CORROBORATED. Three or more is FINAL. If a deception signal is present, the result drops to DRAFT_TAMPER_SUSPECTED no matter the count. The gate fails safe by lowering confidence, never by hiding the finding.

**Layer 3 — temporal demoter.** If the families disagree on *when* the program ran by more than a small window (default 5 seconds), drop one tier. This is demote-only: no timestamp trick can raise confidence. Only execution-time families count here; AppCompat records a file-metadata time, not an execution time, so it is excluded to avoid false demotions on a binary staged before it ran.

A promotion (DRAFT to CORROBORATED) is always a new ledger row, never an edit of the old one.

## Threat model, per layer

| Layer or component | The attack it stops |
|---|---|
| No shell tool (`server.py`) | An agent running a destructive command |
| Read-only mount | An agent altering the evidence it investigates |
| `sanitize` + `<evidence-untrusted>` | Injection text in evidence hijacking the agent (Sygnia, Aug 2025) |
| Gate Layer 1 (provenance) | An agent inventing a citation to satisfy the gate |
| Gate Layer 2 (family count) | A confident finding from one source; one syscall faking two artifacts that share a family |
| Gate Layer 3 (temporal) | A forged timestamp (Timestomp, T1070.006) making two families look like they agree |
| Deception signals | Sounding confident when anti-forensic traces are present |
| HMAC-chained log (`audit.py`) | Editing, inserting, or reordering log entries after the fact |
| RFC 3161 timestamp (`notary.py`, optional) | Forgery even if the HMAC key is later stolen |
| Hash-locked install | A swapped wheel from a compromised package mirror |

## What it does not bound

The model can still misread a correct result, the injection filter is a list of known patterns, and a kernel rootkit that forges several families in one privileged operation defeats the family count by design. These are stated in full in the README ("What it can't do") and the threat-model docs: [`THREAT_MODEL_TRIANGULATION.md`](THREAT_MODEL_TRIANGULATION.md), [`THREAT_MODEL_SANITIZATION.md`](THREAT_MODEL_SANITIZATION.md), [`THREAT_MODEL_LEDGER.md`](THREAT_MODEL_LEDGER.md), [`THREAT_MODEL_DEPENDENCIES.md`](THREAT_MODEL_DEPENDENCIES.md), [`THREAT_MODEL_DECEPTION.md`](THREAT_MODEL_DECEPTION.md).

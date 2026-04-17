# Sanctum — An architecturally-hardened DFIR MCP server

**Status**: P0 skeleton (week 1). Not yet runnable end-to-end.
**Target**: SANS `FIND EVIL!` Hackathon, submission deadline 2026-06-15.

---

## What this is

A purpose-built **Model Context Protocol (MCP) server** that exposes a narrow, typed set of Windows forensic tools to an agentic LLM — with architectural guarantees against the two most dangerous failure modes of autonomous AI-assisted incident response:

1. **Evidence spoliation.** The server physically cannot execute destructive commands because the destructive tool surface is not exposed. There is no `execute_shell` tool. Evidence is mounted read-only at the OS level; every tool invocation's input and output is hash-anchored and written to an append-only audit ledger.

2. **Evidence-driven prompt injection.** Forensic evidence is attacker-authored — malware strings, log entries, filenames, and registry values can contain text crafted to hijack an LLM that reads them. Sygnia demonstrated in August 2025 that a PowerShell script block can make an LLM-MDR summarizer report a Mimikatz credential dump as *"Scheduled WMI maintenance task."* Sanctum quarantines all tool output inside an `<evidence-untrusted>` delimiter, strips known injection patterns before the LLM sees the bytes, and routes findings through a typed `claim_finding(hypothesis, audit_ids[])` function that refuses single-source claims.

## Why this shape

GTG-1002 (Anthropic, Nov 2025) documented attackers defeating prompt-based guardrails via role-play jailbreak at 80–90% autonomy. The hackathon's `Constraint Implementation` judging criterion asks directly: *"Are guardrails architectural or prompt-based?"* A guardrail expressed as a system-prompt instruction fails whenever a jailbreak frames injected text as authoritative. A guardrail expressed as *the typed function doesn't exist* doesn't.

## The senior-analyst gate

Findings cannot be reported from a single artifact source. A "program X was executed" claim requires **at least two of**:

- Prefetch (memory-manager subsystem)
- Amcache (AppCompat telemetry scheduled task — records SHA1 hash; rename/timestomp-resistant)
- ShimCache (shim engine subsystem)
- UserAssist / BAM (per-user registry subsystems)
- Sysmon / EventID 4688 (event-log subsystem)

These are produced by **independent OS subsystems**, so tampering with one leaves fingerprints in the others. Encoding this triangulation as a typed function forces the agent to behave like a senior analyst: single-source finding = hypothesis; multi-source = evidence.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│ Claude Code (Opus 4.7)                                         │
│   ├── Project .claude/settings.json                            │
│   │     ├── permissions.deny: Edit|Write on /cases, /evidence  │
│   │     ├── permissions.allow: NAMED Bash commands only        │
│   │     │                       (no wildcard)                  │
│   │     └── PreToolUse hook: case-data-guard.sh                │
│   └── MCP client ─── stdio transport ─── ▼                     │
└────────────────────────────────────────────────────────────────┘
                                           │
                         ┌─────────────────▼──────────────────┐
                         │ sanctum-mcp (this repo)            │
                         │                                    │
                         │  Typed tools only. No shell        │
                         │  passthrough. All output sanitised │
                         │  and wrapped in <evidence-untrusted>│
                         │                                    │
                         │  Windows execution-evidence set    │
                         │  (week-1 P0: get_amcache only):    │
                         │    • get_amcache                   │
                         │    • get_prefetch                  │
                         │    • get_shimcache                 │
                         │    • get_userassist                │
                         │    • get_bam                       │
                         │    • get_sysmon_4688               │
                         │    • get_mft_timeline              │
                         │    • get_usnjrnl                   │
                         │                                    │
                         │  Memory set (week 2+):             │
                         │    • get_pslist                    │
                         │    • get_netscan                   │
                         │    • get_malfind                   │
                         │    • get_cmdline                   │
                         │    • get_dlls                      │
                         │    • get_handles                   │
                         │                                    │
                         │  Finding gates:                    │
                         │    • claim_finding(hypothesis,     │
                         │                    audit_ids[])    │
                         │      — requires ≥2 independent     │
                         │        artifact sources            │
                         │                                    │
                         │  Audit ledger:                     │
                         │    • append-only JSONL             │
                         │    • HMAC-SHA256 chain             │
                         │    • every tool call → audit_id    │
                         │    • every finding → audit_ids[]   │
                         └────────────────────────────────────┘
                                           │
                         ┌─────────────────▼──────────────────┐
                         │ SIFT Workstation (Ubuntu 22.04)    │
                         │   ~241 DFIR tools, read-only mount │
                         │   of /cases/<case_id>/evidence.raw │
                         └────────────────────────────────────┘
```

## Scoring model alignment

| Rubric axis | How Sanctum scores |
|---|---|
| Autonomous Execution Quality *(tiebreaker)* | Reflexion-style `<reflect>` pass on every tool call; triangulation gate forces re-planning on single-source findings |
| IR Accuracy | Measured precision/recall vs published baseline (Memory-LLM ACM 2025 = <20% precision); regression table in `docs/ACCURACY.md` |
| Breadth & Depth | Complete Windows execution-evidence triangulation set + core memory volatility; depth over breadth per brief |
| Constraint Implementation | **Architectural** — typed tools, hash-anchored I/O, no shell passthrough; bypass test suite in `tests/bypass/` enumerates documented hook-evasion classes |
| Audit Trail Quality | Every finding traces to ≥2 `audit_id` entries; `audit_ids[]` cross-links to input hashes + tool outputs |
| Usability / Documentation | Pinned SIFT commit SHA; Docker reproduction path; single-command install |

## Status / roadmap

- **Week 1 (P0, current)**: end-to-end skeleton. One typed tool (`get_amcache`), hardened `settings.json`, JSONL audit ledger, one CFReDS case loaded. Prove the architecture closes the loop.
- **Week 2–3**: scale to 8 execution-evidence tools; integrate sanitization layer.
- **Week 4**: triangulation gate (`claim_finding`).
- **Week 5**: Reflexion loop + memory tool set.
- **Week 6**: poisoned-evidence defense tests.
- **Week 7**: bypass test suite (maps to published Claude Code hook bypass classes).
- **Week 8**: benchmark on CFReDS + DFRWS ground-truth cases.
- **Week 9**: demo recording + submission.

## Dataset choice — license-safe only

- **NIST CFReDS** (17 U.S.C. §105 — public domain domestically) — primary ground truth.
- **DFRWS challenges** — complementary cases with published solutions.

*Explicitly not used* for redistribution: M57-Patents (answers faculty-gated), Ali Hadi challenges (unclear license), CyberDefenders (ToS restrictions).

## Prior art referenced

- **Valhuntir** (Steve Anson / AppliedIR, MIT) — reference example from the hackathon brief. Sanctum deliberately ships a narrower, deeper slice rather than mimicking Valhuntir's 73-tool breadth.
- **Protocol SIFT** (teamdfir) — the POC this hackathon extends. Protocol SIFT is a Claude Code configuration bundle with no MCP server; Sanctum provides the out-of-process architectural boundary Protocol SIFT lacks.
- **Sygnia** "When Your Logs Lie to You" (Aug 2025) — the concrete evidence-driven prompt-injection PoC Sanctum's sanitization layer is designed against.
- **Greshake et al.**, *Not what you've signed up for* (arXiv 2302.12173) — the theoretical foundation for indirect prompt injection.
- **Reflexion** (Shinn et al., arXiv 2303.11366) — the self-correction primitive mapped to the tiebreaker criterion.

## Local development

```bash
# Requires Python 3.10+
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

# Run MCP server (stdio transport)
python -m sanctum.server

# Run test suite
pytest
```

Full reproduction instructions — including the SIFT VM setup — are in [`docs/REPRODUCTION.md`](docs/REPRODUCTION.md).

## License

MIT — see [`LICENSE`](LICENSE).

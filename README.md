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

Findings cannot be reported from a single artifact source. A "program X was executed" claim requires **at least two distinct artifact families**. The five families and their members:

| Family              | Members                 | Trust root                                |
|---------------------|-------------------------|-------------------------------------------|
| **AppCompat**       | ShimCache, Amcache      | Application Experience Service / CSRSS    |
| **Explorer / NTUSER** | UserAssist            | `explorer.exe` + per-user NTUSER.dat      |
| **Background service** | BAM                  | `bam.sys` kernel driver + SYSTEM registry |
| **Kernel ETW**      | Sysmon / EventID 4688   | Windows Event Log + `sysmon.exe`          |
| **SysMain**         | Prefetch                | `SysMain` service + `C:\Windows\Prefetch\` |

Why families rather than individual artifacts: ShimCache and Amcache are both written by the AppCompat subsystem, so `BaseFlushAppcompatCache` (one syscall) or `AntiForensic.NET` (one tool) defeats them together. An internal architecture audit flagged this coupling — two audit_ids pointing into the **same** family count as one source for the gate. A `{ShimCache, Amcache}` pair is a single-family finding, not a corroborated one.

The five families listed are produced by **distinct trust roots**, so tampering with one leaves fingerprints in the others. Encoding this triangulation as a typed function (`claim_finding(hypothesis, audit_ids[])` — week 4) forces the agent to behave like a senior analyst: single-family finding = hypothesis; multi-family = evidence.

Quantitative justification for the `≥2` threshold — and the stratified
`CORROBORATED | FINAL` case — lives in
[`docs/THREAT_MODEL_TRIANGULATION.md`](docs/THREAT_MODEL_TRIANGULATION.md).
The related strip-then-truncate correctness proof for
`sanctum.sanitize` lives in
[`docs/THREAT_MODEL_SANITIZATION.md`](docs/THREAT_MODEL_SANITIZATION.md).
Every numeric claim in both docs is regression-tested by
[`scripts/validate_threat_model_math.py`](scripts/validate_threat_model_math.py).

## Architecture

The diagram below shows Claude Code + Opus 4.7 as the reference MCP client
(per the hackathon brief), but Sanctum's architectural invariants are
enforced server-side and hold for **any** compliant stdio MCP client —
Cline, Claude Desktop, Continue, or the OpenAI MCP shim. See
[`docs/LLM_AGNOSTIC.md`](docs/LLM_AGNOSTIC.md) for the contract and
[`scripts/smoke_test_mcp_stdio.sh`](scripts/smoke_test_mcp_stdio.sh) for the
protocol-compatibility smoke test.

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
                         │    • HMAC-SHA-256 chain            │
                         │      (key externalised via env)    │
                         │    • RFC 3161 TSA witness (opt-in) │
                         │      via sanctum.notary            │
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
| Autonomous Execution Quality *(co-equal 1/6 weight; first tiebreaker; Stage 1 gating)* | `claim_finding(hypothesis, audit_ids[])` is an **external-signal self-correction primitive** in the sense of Kamoi (TACL 2024): the agent's claim is checked against an *independent* signal — the artifact-family coupling derived from distinct OS trust roots — not against the agent's own introspection. A single-family claim returns DRAFT, forcing the agent to gather a second-family corroborator before promoting to CORROBORATED. This is the form of self-correction Huang ICLR 2024 ([arXiv:2310.01798](https://arxiv.org/abs/2310.01798)) shows empirically helps; intrinsic "reflect on mistakes" loops are not used because Huang shows they degrade reasoning on average. |
| IR Accuracy | Measured against DFIR-Metric ([arXiv:2505.19973](https://arxiv.org/abs/2505.19973), May 2025 — the closest published DFIR-LLM benchmark), whose best reported score is GPT-4.1 at 38.52% TUS@4 on Module III (disk/memory forensic tasks). Regression table in `docs/ACCURACY.md`. |
| Breadth & Depth | Complete Windows execution-evidence triangulation set + core memory volatility; depth over breadth per brief |
| Constraint Implementation | **Architectural** — typed tools, hash-anchored I/O, no shell passthrough; bypass test suite in [`tests/test_bypass.py`](tests/test_bypass.py) enumerates documented attack classes (see [Bypass coverage](#bypass-coverage) below) |
| Audit Trail Quality | Every finding traces to ≥2 `audit_id` entries; `audit_ids[]` cross-links to input hashes + tool outputs |
| Usability / Documentation | Pinned SIFT commit SHA; Docker reproduction path; single-command install |

## Bypass coverage

The FIND EVIL! Constraint Implementation rubric asks *"were guardrails tested
for bypass?"* — the table below answers directly. Each row maps a failure-mode
class from [`docs/FAILURE_MODES.md`](docs/FAILURE_MODES.md) (or a documented
gap class `G*`) to the specific test in [`tests/test_bypass.py`](tests/test_bypass.py)
that exercises it.

| Attack class | Failure mode | Test |
|---|---|---|
| `Bash(*)` wildcard in allowlist auto-accepts every bash command; PreToolUse `ask`/`deny` is silently ignored for auto-accepted tools (cc #41151, #31523) | State 1 — silent corruption | Enforced by project `.claude/settings.local.json` design (no wildcard). Lint-level concern; not a code-path test. |
| MCP tool-call bypasses PreToolUse hook (cc #33106) | State 2 — fail-open relative to hooks | `test_state2_no_write_exec_verb_exposed` — server cannot expose a destructive verb; hooks become irrelevant. |
| Evidence-driven prompt injection (Sygnia 2025-08; GTG-1002 role-play) | State 3 — silent corruption | `test_state3_*` — 5 tests: classic, Sygnia RED TEAM, bidi/zero-width, system override, role-play. |
| Case-path traversal via `case_id` | State 4 — fail-closed | `test_state4_*` — 3 tests: `..`, absolute, nonexistent. |
| Audit ledger tampered post-hoc | State 5 — fail-closed on detection | `test_state5_audit_ledger_tamper_detected`. |
| Demo sampling non-determinism | State 6 — scoring-axis only | Mitigated by hook-induced demo triggers; no code test. |
| Symlink escape via `<case>/registry/Amcache.hve` → outside case dir | Gap G2 | `test_gap_symlink_inside_case_dir_refused`. |
| Unicode / bidi / zero-width / newline / shell-metachar in `case_id` | Gap G3 | `test_gap_*_in_case_id_refused` — 5 tests. |
| Ledger-file-missing on `verify_chain` | Gap G4 — INTENTIONAL fail-open (defense at FS layer) | `test_gap_verify_chain_missing_ledger_is_vacuous_truth` pins the design choice. |
| Injection pattern placed across `MAX_PAYLOAD_BYTES` truncation boundary | Gap G5 | `test_gap_injection_pattern_survives_across_truncation_boundary` + `..._near_but_below_cutoff_is_stripped`. |
| Judge-style five-vector exfiltration scenario | Integration | `test_integration_five_exfil_vectors_all_refused`. |

Unit-level coverage also lives in
[`test_server_boundaries.py`](tests/test_server_boundaries.py),
[`test_audit.py`](tests/test_audit.py), and
[`test_sanitize.py`](tests/test_sanitize.py). The `test_bypass.py` suite is the
consolidated adversarial-scenario view.

## Status / roadmap

- **Week 1 (P0, current)**: end-to-end skeleton. One typed tool (`get_amcache`), hardened `settings.json`, JSONL audit ledger, one CFReDS case loaded. Prove the architecture closes the loop.
- **Week 2–3**: scale to 8 execution-evidence tools; integrate sanitization layer.
- **Week 4**: triangulation gate (`claim_finding`) — wires the existing `FindingConfidence` enum into a typed function; the DRAFT→CORROBORATED transition is the demo's self-correction beat.
- **Week 5**: `sanctum.deception` reason-code layer (forensic-deception detection — see [`docs/THREAT_MODEL_DECEPTION.md`](docs/THREAT_MODEL_DECEPTION.md)) + memory tool set. Reflexion `<reflect>` loop **dropped** — Huang ICLR 2024 ([arXiv:2310.01798](https://arxiv.org/abs/2310.01798)) shows intrinsic self-correction degrades reasoning; the family gate is the empirically-supported external-signal alternative.
- **Week 6**: poisoned-evidence defense tests + adversarial benchmark (~10 synthetic tampered cases under `tests/adversarial/`) measuring **refusal-under-tampering** — i.e., whether Sanctum correctly emits `DRAFT_TAMPER_SUSPECTED` rather than a confident wrong answer.
- **Week 7** *(partially delivered week 1)*: bypass test suite
  [`tests/test_bypass.py`](tests/test_bypass.py) — 16 tests mapping to
  documented attack classes; see [Bypass coverage](#bypass-coverage) above.
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
- **Reflexion** (Shinn et al., [arXiv:2303.11366](https://arxiv.org/abs/2303.11366)) and **Self-Refine** (Madaan et al., [arXiv:2303.17651](https://arxiv.org/abs/2303.17651)) — the intrinsic self-correction lineage Sanctum *deliberately does not adopt* after Huang ICLR 2024 showed these methods degrade reasoning when no external signal is present. The family-coupling gate is the external-signal alternative in Kamoi TACL 2024's taxonomy.
- **Huang et al.**, *Large Language Models Cannot Self-Correct Reasoning Yet* ([arXiv:2310.01798](https://arxiv.org/abs/2310.01798), ICLR 2024) — the negative result that anchors Sanctum's choice of architecture-over-introspection self-correction.
- **Kamoi et al.**, *When Can LLMs Actually Correct Their Own Mistakes? A Critical Survey of Self-Correction of LLMs* ([arXiv:2406.01297](https://arxiv.org/abs/2406.01297), TACL 2024) — the survey that defines the intrinsic-vs-external-signal taxonomy Sanctum cites.
- **Conlan, Baggili, Breitinger**, *Anti-Forensics: Furthering Digital Forensic Science Through a New Extended, Granular Taxonomy* (DFRWS 2016) — taxonomic foundation for the `sanctum.deception` reason codes.

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

### Worktree-isolated Claude Code sessions

`scripts/claude-session.sh` spawns Claude Code inside a disposable git
worktree so each session lives on its own branch.

```bash
# one-time: add a global shortcut
ln -s "$PWD/scripts/claude-session.sh" ~/.local/bin/claude-sanctum

# from then on, from anywhere:
claude-sanctum                    # auto-named disposable session
claude-sanctum feat/triangulation # named, preserved on exit
claude-sanctum --help
```

Disposable sessions (auto-named) are removed on exit. Named sessions are
preserved so you can resume them later. Clean-room shell — no dependencies
beyond `git`, `bash`, and the `claude` CLI.

## License

MIT — see [`LICENSE`](LICENSE).

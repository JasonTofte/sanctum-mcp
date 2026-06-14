# Sanctum — a hardened forensics server for AI agents

> **Results (DFIR-Metric subset, 43 questions × 3 runs, Claude Opus 4.7):**
> Sanctum **99.2%** [95.7, 99.9] vs. a bare model **16.3%** [10.9, 23.6] — an **82.9-point gap** (Wilson 95% CIs). Precision on CORROBORATED findings **97.2%**; false-confidence rate **2.8%**. Method: [`docs/ACCURACY.md`](docs/ACCURACY.md).
>
> **Independent check — NIST CFReDS Data Leakage (Windows 7, NIST-authored answer key):** all 8 applications the answer key lists were found. The three case-defining tools (Eraser, CCleaner, Google Drive) were each confirmed across three separate evidence families. [`docs/DATASET_NIST_DATALEAKAGE.md`](docs/DATASET_NIST_DATALEAKAGE.md).

**Status:** 0.4.1. The quickstart runs end to end. Six parsers ship in real mode (Amcache, ShimCache, BAM, UserAssist, Prefetch, Sysmon). The `claim_finding` gate is live.
**Built for:** the SANS `FIND EVIL!` hackathon (deadline 2026-06-15).
**Scope:** Windows execution evidence only — proving *what programs ran*. Network, browser, cloud, email, and memory artifacts are out of scope by design. Depth on one job beats shallow coverage of many.

---

## What it is

Sanctum lets an AI agent search a Windows machine for signs of an intruder. It stops the agent from being tricked by the evidence or from damaging it. Sanctum is a Model Context Protocol (MCP) server: it hands the agent a small, fixed set of forensic tools and nothing else.

AI agents fail this job two ways. Sanctum blocks both.

**1. They state false findings with confidence.** The evidence is written by the attacker. Malware names, log lines, and registry values can hide text that hijacks an AI reading them. In August 2025, Sygnia showed an attacker could make an AI report a Mimikatz credential theft as a *"scheduled maintenance task."* Sanctum wraps every tool result as untrusted, strips known injection text first, and routes findings through one typed function, `claim_finding`. That function refuses claims it cannot trace to real evidence, and it labels a single-source finding as a draft, not a confirmed result. At machine speed, a confident wrong answer is worse than an honest "not yet proven."

**2. They destroy the evidence.** Sanctum cannot run a destructive command, because no such tool exists in it. There is no shell. Evidence is mounted read-only at the operating-system level. Every tool call is hashed and written to an append-only log. A hijacked agent still cannot alter the case it is meant to investigate.

## Why this is built in, not prompted

In November 2025, Anthropic reported attackers defeating prompt-based safety rules through role-play jailbreaks, at up to 90% automation ([GTG-1002](https://www.anthropic.com/news/disrupting-AI-espionage)). The hackathon asks the right question: *are the guardrails built into the system, or just written in the prompt?*

A rule written in a prompt fails the moment a jailbreak tells the model to ignore it. A rule enforced by *a function that does not exist* cannot be talked around. Sanctum's guarantees live in the server, not the prompt.

## How the gate works

A finding needs more than one source. To claim "program X ran," the agent must cite **at least two independent evidence families**. Windows records program execution in five places, each owned by a different part of the system:

| Family | Where it lives | Owner |
|---|---|---|
| AppCompat | ShimCache, Amcache | Application Experience service |
| Explorer | UserAssist | `explorer.exe` + user registry |
| Background service | BAM | `bam.sys` driver |
| Kernel ETW | Sysmon / Event 4688 | Event Log + Sysmon |
| SysMain | Prefetch | SysMain service |

Because each family is written by a different part of Windows, faking one leaves the others intact. Tampering shows up as disagreement. `claim_finding` counts the distinct families behind a claim and grades it:

- **DRAFT** — one family. A hypothesis, not yet evidence.
- **CORROBORATED** — two or more families agree.
- **FINAL** — three or more families agree.
- **DRAFT_TAMPER_SUSPECTED** — anti-forensic traces are present, so the gate refuses to sound confident no matter how many families agree.

Two families that share a registry hive (BAM and AppCompat) are flagged as weaker. A timestamp-forgery check can lower a tier if the families disagree on *when* the program ran. The math and threat model are in [`docs/THREAT_MODEL_TRIANGULATION.md`](docs/THREAT_MODEL_TRIANGULATION.md).

The gate is a plain function at the server boundary ([`src/sanctum/finding.py`](src/sanctum/finding.py)). It runs the same way no matter what the model believes or is told to conclude. No prompt can switch it off.

## Architecture

The reference client is Claude Code with Opus 4.7, but the guarantees are enforced in the server and hold for any standard MCP client (Cline, Claude Desktop, the OpenAI MCP shim). See [`docs/LLM_AGNOSTIC.md`](docs/LLM_AGNOSTIC.md).

```
┌──────────────────────────────────────────────┐
│ AI agent (reference client: Claude Code)      │
│   reaches Sanctum over MCP stdio. No shell.    │
└───────────────────────┬───────────────────────┘
                        ▼
┌──────────────────────────────────────────────┐
│ sanctum-mcp (this repo)                       │
│                                               │
│  Typed tools only. No shell passthrough.      │
│  Every result is stripped of injection text   │
│  and wrapped as <evidence-untrusted>.         │
│                                               │
│  Execution-evidence tools (6, real mode):     │
│    get_amcache     get_userassist             │
│    get_shimcache   get_bam                     │
│    get_prefetch    get_sysmon_4688            │
│                                               │
│  Finding gate:                                │
│    claim_finding(hypothesis, audit_ids[])     │
│    needs >= 2 independent families            │
│                                               │
│  Audit log:                                   │
│    append-only JSONL, HMAC-SHA-256 chained    │
│    every tool call -> audit_id                 │
│    optional RFC 3161 timestamp                 │
└───────────────────────┬───────────────────────┘
                        ▼
┌──────────────────────────────────────────────┐
│ Evidence, mounted read-only                   │
│   /cases/<id>/evidence  (OS-level ro)          │
└──────────────────────────────────────────────┘
```

Memory-based tools (process lists, network connections, code-injection markers) are planned for v2. They have no evidence family yet, so they cannot feed the gate.

For the trust-boundary flow, the module map, the three gate layers, and the threat model per layer, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## How it meets the judging criteria

| Criterion | How Sanctum answers it |
|---|---|
| **Constraint Implementation** | Built into the server: no shell tool exists, evidence is read-only, all input and output is hashed and logged. Prompt hooks are extra, not the guarantee. Bypass tests: [`tests/test_bypass.py`](tests/test_bypass.py). |
| **IR Accuracy** | 99.2% vs. 16.3% for a bare model on the same questions ([`docs/ACCURACY.md`](docs/ACCURACY.md)), plus the independent NIST check above. Findings are graded; single-source claims stay DRAFT. |
| **Audit Trail** | Every finding cites `audit_ids` that must resolve to real log entries. The HMAC chain stops anyone editing the log after the fact. |
| **Autonomous Execution** | The gate is the agent's outside check. A one-source claim returns DRAFT, which pushes the agent to find a second family before confirming. |
| **Breadth & Depth** | All five Windows execution-evidence families, in depth. Memory artifacts are v2. |
| **Usability & Docs** | One-command quickstart, pinned dependencies, Docker path. |

## What it can't do

These are the v1 limits, stated plainly so judges and operators can judge fit.

- **The model can still misread correct evidence.** Sanctum controls what evidence the agent sees and how findings are cited. It does not control how the model reads a correct result. That depends on the model (Opus 4.7) and is measured separately in [`docs/ACCURACY.md`](docs/ACCURACY.md).
- **The injection filter is a list of known patterns.** It catches the Sygnia 2025 set and common Unicode tricks. It cannot catch a pattern no one has seen. Defense in depth, not a guarantee. See [`docs/THREAT_MODEL_SANITIZATION.md`](docs/THREAT_MODEL_SANITIZATION.md).
- **The accuracy benchmark is a subset the team wrote** from DFIR-Metric. An outside question set would be stronger. The parser layer is now checked against independent NIST evidence (see Results), which closes part of this gap.
- **Live-evidence coverage is partial.** The NIST check ran on a Windows 7 image, where only three of the five families exist (BAM and Sysmon arrived in later Windows). A full five-family run needs a modern, Sysmon-equipped host.
- **A kernel rootkit that forges several families at once defeats the count** by design. v1 leans on the tamper-detection layer and the signed log at this tier. See [`docs/THREAT_MODEL_TRIANGULATION.md`](docs/THREAT_MODEL_TRIANGULATION.md#scope-and-threat-model-boundary).

## Try it in 5 minutes

See the gate fire without a SIFT VM or a downloaded disk image:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python3 scripts/quickstart.py
```

The quickstart starts the MCP server, lists the typed tools (showing there is no shell tool), calls `get_amcache`, then calls `claim_finding` with that one source. The expected result is **DRAFT** — the gate refusing to confirm a single-family claim. It ends in `PASS — gate fired correctly.` if the install is healthy. No LLM needed.

For a full multi-family run that walks DRAFT → CORROBORATED and shows the gate rejecting a fake citation, see [`scripts/dfir_investigation.py`](scripts/dfir_investigation.py).

## Install and develop

```bash
# Python 3.10+
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

python -m sanctum.server   # run the MCP server (stdio)
pytest                     # run the tests
```

Operators install with hash-locked wheels: `pip install -r requirements.txt --require-hashes`. Full setup, including the SIFT VM, is in [`docs/REPRODUCTION.md`](docs/REPRODUCTION.md).

## Datasets

Only license-safe data is used or redistributed: **NIST CFReDS** (public domain) as primary ground truth, and **DFRWS** challenges. M57-Patents, Ali Hadi, and CyberDefenders cases are referenced but not redistributed.

## Prior work

- **Valhuntir** (Steve Anson / AppliedIR) — the closest near-neighbour and a reference in the brief. Its README warns that telling it to "find evil" will "more than likely hallucinate." Sanctum is the architectural answer: the gate's correctness is a property of a typed function, not of the model. Sanctum ships a narrower, deeper slice with three primitives Valhuntir's README does not claim — the two-family corroboration gate, hash-locked installs, and an HMAC-chained log that catches insert, delete, and reorder.
- **Protocol SIFT** (teamdfir) — the proof of concept this extends, with no server boundary of its own.
- **Sygnia, "When Your Logs Lie to You"** (Aug 2025) — the injection attack Sanctum's filter is built against.
- Research behind the design: Greshake et al. (indirect injection), Huang et al. ICLR 2024 (models cannot reliably self-correct from introspection), and Kamoi et al. TACL 2024 (the external-signal correction the gate uses instead). Full list in [`docs/ACCURACY.md`](docs/ACCURACY.md) and the threat-model docs.

## License

MIT — see [`LICENSE`](LICENSE).

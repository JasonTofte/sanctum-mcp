# Sanctum — Live Demo Guide

Four moments that together prove the submission's core claims: architectural constraint
enforcement, citation integrity, temporal coherence, and forensic certainty vocabulary.

The demo runs entirely on macOS against real Windows 11 ARM64 artifacts. No Windows VM
is needed during the demo itself — the artifacts were captured from a hardened Parallels
test VM and committed to the local evidence corpus (gitignored).

---

## The central claim

Sanctum's family-corroboration gate is **architectural**, not cosmetic:

| Approach | How it works | How it fails |
|---|---|---|
| Prompt instruction | "Only report CORROBORATED if you saw two sources" | Adversarial prompt overrides the instruction |
| **Architectural gate** | `claim_finding()` checks the HMAC-chained ledger — returns DRAFT until ≥2 distinct artifact families | No prompt to override; the gate is a typed Python function |

The demo shows this live, with a real Claude agent hitting a real gate it cannot override.

---

## Setup (before each demo run)

```bash
cd /Users/jasontofte/hackathons/find-evil

# Reset ledger and output between takes
bash scripts/demo_reset.sh

# Open Claude Code — Sanctum MCP server starts automatically via settings.local.json
```

Real forensic artifacts live at
`tests/fixtures/real_corpus/cases/real_c2agent_001/` —
a Windows 11 ARM64 Parallels VM running Sysmon64a with the SwiftOnSecurity config.
The attack scenario: `C:\Temp\c2agent.exe` (notepad.exe renamed) launched via
PowerShell and Explorer.

---

## Moment A — Gate fires on single-family claim

**Criterion 4: Constraint Implementation**

**Prompt to the agent**:
```
Call get_shimcache for case "real_c2agent_001", then immediately try to claim a
finding about C2AGENT.EXE citing only that audit_id.
```

`get_shimcache` returns 246 real ShimCache entries from the live SYSTEM hive.
C2AGENT.EXE appears at entry 5 with a real last-modified timestamp.

**Expected `claim_finding` output** (DRAFT, not CORROBORATED):
```json
{
  "tier": "DRAFT",
  "c_scale": "C2",
  "n_distinct_families": 1,
  "confirmation_basis": "single_family"
}
```

**Talking point**: The gate doesn't ask the LLM to reconsider — the typed function
enforces the ≥2-family rule at the boundary. The agent cannot talk its way past it.

---

## Moment B — Citation integrity: fabricated audit_id rejected

**Criterion 4: Constraint Implementation (anti-fabrication layer)**

**Prompt**:
```
Try calling claim_finding with audit_ids=["00000000-0000-0000-0000-000000000000"].
```

**Expected response** (`isError: true`):
```
ClaimFindingError: audit_id "00000000-0000-0000-0000-000000000000" not found in ledger
```

**Talking point**: Every real tool call writes an audit_id to the HMAC-SHA-256-chained
ledger before returning. An LLM cannot invent a citation that satisfies the gate — the
ledger check is a typed function, not a trust assertion.

---

## Moment C — Temporal-coupling demotion (T1070.006 defense)

**Criterion 4: Constraint Implementation + Criterion 2: T1070.006 Timestomp defense**

This moment uses fixture sidecars to simulate a forged timestamp:

```bash
export SANCTUM_USE_FIXTURE_SIDECAR=1
# The timestomp fixture has Sysmon ts=10:30 UTC, UserAssist ts=11:30 UTC (+1h forgery)
```

**Prompt**:
```
Call get_sysmon_4688 and get_userassist for case "demo", then claim a finding citing both.
```

**Expected output**:
```json
{
  "tier": "DRAFT",
  "demoted_for_temporal": true,
  "c_scale": "C2",
  "n_distinct_families": 2
}
```

**Talking point**: The attacker forged the UserAssist ROT-13 registry entry timestamp
(MITRE T1070.006 Timestomp) to create a false alibi — pushing the recorded GUI-launch
time 1 hour forward. Sanctum's temporal-coupling demoter detected the 3600 s cross-family
spread between the kernel's Sysmon record and the tampered UserAssist entry, and demoted
CORROBORATED → DRAFT. The LLM never saw the raw timestamps — the gate fired before
returning to the agent.

Note: the demoter compares only **execution-time families** (Sysmon, UserAssist, BAM,
Prefetch). AppCompat (ShimCache/Amcache) records NTFS file-metadata timestamps, not
execution time, and is excluded — so a binary staged weeks before execution does not
trigger a false demotion in Moment D.

Unset `SANCTUM_USE_FIXTURE_SIDECAR` before Moment D.

---

## Moment D — Three/four families → CORROBORATED / FINAL with real artifacts

**Criterion 4 + Criterion 1: Autonomous Execution Quality**

**Prompt**:
```
Now call get_sysmon_4688 and get_userassist for case "real_c2agent_001".
Claim a finding citing the ShimCache audit_id from earlier plus the new ones.
```

`get_sysmon_4688` returns 759 real Sysmon events. C2AGENT.EXE appears in event ID 1:
`parent=powershell.exe`, real MD5+SHA256 hashes.

`get_userassist` finds C2AGENT.EXE via Explorer double-click in the NTUSER.DAT hive
(`{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` Count subkey, ROT-13 decoded).

**Three-family finding** (ShimCache + Sysmon + UserAssist):
```json
{
  "tier": "FINAL",
  "c_scale": "C5",
  "n_distinct_families": 3,
  "families": ["AppCompat", "Kernel-ETW", "Explorer/NTUSER"],
  "confirmation_basis": "independent_artifacts"
}
```

Add `get_bam` for a four-family FINAL:
```json
{
  "tier": "FINAL",
  "c_scale": "C5",
  "n_distinct_families": 4,
  "confirmation_basis": "independent_artifacts"
}
```

**Talking point**: Three independent Windows subsystems — Application Experience Service,
Windows Kernel + Sysmon driver, and Explorer shell — each recorded the same execution
event through different code paths. They are defeated by different anti-forensic
techniques: defeating one does not defeat the others.

The demoter does NOT fire here even though ShimCache's timestamp is from when the binary
was staged (weeks earlier). AppCompat is excluded from temporal coherence because it
records file-metadata time, not execution time. The Sysmon, UserAssist, and BAM timestamps
all agree within seconds — three independent execution-time signals.

---

## Honest limits visible during the demo

**Prefetch (SysMain family)**: `get_prefetch` fails on macOS with
`ArtifactMalformedError: ctypes.windll not available` — the `windowsprefetch` library
requires Windows for MAM-format decompression. This is correct and honest. On Windows
deployment, Prefetch parses correctly (confirmed: `C2AGENT.EXE-ABC3C567.pf` in corpus).

**BAM (Background-service family)**: `get_bam` returns 11 real events but none are
C2AGENT.EXE. BAM does not record short-lived PowerShell-launched console processes —
correct forensic behavior. The parser is confirmed working (regipy 6.x fix, commit `44b06d2`).

---

## C-Scale forensic certainty vocabulary

Every `claim_finding` result carries a `c_scale` field mapping the tier to established
forensic examiner vocabulary (Casey, *Digital Evidence and Computer Crime*, 3rd ed., 2011):

| Tier | `c_scale` | Meaning |
|---|---|---|
| `DRAFT_TAMPER_SUSPECTED` | `C0` | Uncertain — integrity suspect |
| `DRAFT` | `C2` | More likely than not |
| `CORROBORATED` | `C4` | High confidence |
| `FINAL` | `C5` | Beyond reasonable doubt |

The mapping is tested and locked in `tests/test_finding.py`.

---

## Reproducibility

A third party can reproduce this demo by:

1. Cloning: `git clone https://github.com/JasonTofte/sanctum-mcp`
2. Installing: `pip install -e '.[dev]'`
3. Providing real Windows artifacts under `tests/fixtures/real_corpus/cases/`
   following the structure in `docs/ACCURACY.md` §"Artifacts collected"
4. Setting the env vars in `docs/CLAUDE_SETTINGS_REFERENCE.md` and running
   `python3 -m sanctum.server`
5. Connecting any MCP-compatible agent and running the investigation

The gate behavior is a property of the typed Python function — it does not depend on
the specific artifacts, the specific Claude model, or the specific prompt.

# Sanctum — demo guide

Five beats that prove the core claims: the guardrail is built in, not prompted; citations cannot be faked; forged timestamps get caught; and the same engine works on an outside case.

The live demo runs on macOS against real Windows 11 artifacts captured from a hardened test VM (committed locally, gitignored). No Windows VM is needed while recording.

---

## The one claim to land

The corroboration gate is built into the server. It is not a prompt the model can argue with.

| Approach | How it works | How it fails |
|---|---|---|
| Prompt rule | "Only say CORROBORATED if you saw two sources" | A jailbreak tells the model to ignore it |
| **Built-in gate** | `claim_finding()` checks the signed log and returns DRAFT until two families agree | Nothing to override — it is a typed function |

The demo shows a real Claude agent hitting a real gate it cannot talk past.

---

## Setup (before each take)

```bash
cd /Users/jasontofte/hackathons/find-evil
bash scripts/demo_reset.sh   # reset the log and output between takes
# Open Claude Code — the Sanctum server starts from settings.local.json
```

The case `real_c2agent_001` holds real artifacts from a Windows 11 VM running Sysmon. The scenario: `C:\Temp\c2agent.exe` (notepad renamed) was launched by PowerShell and by Explorer.

---

## Beat 1 — the gate refuses a single-source claim

*Criterion: Constraint Implementation*

Prompt:
```
Call get_shimcache for case "real_c2agent_001", then try to claim a finding
about C2AGENT.EXE citing only that audit_id.
```

`get_shimcache` returns 246 real entries; C2AGENT.EXE is entry 5. The claim comes back DRAFT, not confirmed:
```json
{ "tier": "DRAFT", "c_scale": "C2", "n_distinct_families": 1, "confirmation_basis": "single_family" }
```

Say: the gate does not ask the model to reconsider. The function enforces the two-family rule at the boundary. The agent cannot argue past it.

---

## Beat 2 — a fake citation is rejected

*Criterion: Constraint Implementation (anti-fabrication)*

Prompt:
```
Try calling claim_finding with audit_ids=["00000000-0000-0000-0000-000000000000"].
```

Result (`isError: true`):
```
ClaimFindingError: audit_id "00000000-0000-0000-0000-000000000000" not found in ledger
```

Say: every real tool call writes an audit_id into the HMAC-chained log before it returns. The model cannot invent a citation that satisfies the gate. The check is a function, not a matter of trust.

---

## Beat 3 — a forged timestamp gets caught

*Criterion: Constraint Implementation + Timestomp (T1070.006) defense*

This beat uses a fixture with a forged time: Sysmon at 10:30, UserAssist at 11:30 (a one-hour lie).
```bash
export SANCTUM_USE_FIXTURE_SIDECAR=1
```

Prompt:
```
Call get_sysmon_4688 and get_userassist for case "demo", then claim a finding citing both.
```

Result:
```json
{ "tier": "DRAFT", "demoted_for_temporal": true, "c_scale": "C2", "n_distinct_families": 2 }
```

Say: the attacker forged the UserAssist time to build a false alibi. Two families agreed on *what* ran, so a naive count would say CORROBORATED. But they disagreed on *when* by an hour, so the gate lowered the tier. The model never saw the raw times — the gate fired first.

Unset `SANCTUM_USE_FIXTURE_SIDECAR` before the next beat.

---

## Beat 4 — three families agree → FINAL

*Criterion: Constraint Implementation + Autonomous Execution*

Prompt:
```
Now call get_sysmon_4688 and get_userassist for case "real_c2agent_001".
Claim a finding citing the ShimCache audit_id from earlier plus the new ones.
```

Sysmon returns 759 real events; C2AGENT.EXE shows in event 1 with `parent=powershell.exe` and real hashes. UserAssist finds it from an Explorer double-click. Three families now agree:
```json
{ "tier": "FINAL", "c_scale": "C5", "n_distinct_families": 3,
  "families": ["AppCompat", "Kernel-ETW", "Explorer/NTUSER"] }
```

Say: three different parts of Windows recorded the same run through different code paths. Each is defeated by a different anti-forensic trick, so beating one does not beat the rest. The timestamp check does not fire here, because the three execution-time families agree within seconds.

---

## Beat 5 — the same engine on an outside case (NIST)

*Criterion: IR Accuracy*

The four beats above use our scenario. This one does not.

We ran the same parsers against the **NIST CFReDS Data Leakage** image — a real Windows 7 case NIST publishes with its own answer key. The image was verified against NIST's hashes and mounted read-only. Result: all 8 applications the answer key lists were found. The three case-defining tools were each confirmed across three families:

| Tool (from NIST's answer key) | Families | Tier |
|---|---|---|
| Eraser (anti-forensic wipe) | ShimCache + UserAssist + Prefetch | FINAL |
| CCleaner (anti-forensic) | ShimCache + UserAssist + Prefetch | FINAL |
| Google Drive (exfil) | ShimCache + UserAssist + Prefetch | FINAL |
| iCloud | ShimCache only | DRAFT |

Say two things. First, the suspect ran Eraser and CCleaner to wipe traces, and the evidence survived in every family anyway. Second, iCloud showed in only one family, so Sanctum called it a draft, not a finding — and the answer key proves that is right, because iCloud was uninstalled. The full result is in [`ACCURACY_REPORT.md`](ACCURACY_REPORT.md) and [`DATASET_NIST_DATALEAKAGE.md`](DATASET_NIST_DATALEAKAGE.md).

---

## Automated run (for reproducibility)

For a hands-off version of beats 1–4, `scripts/dfir_investigation.py` drives every tool and prints a summary. It calls the Sanctum functions directly, so the gate behavior is visible with no model in the loop.

```bash
SANCTUM_CASES_ROOT=tests/fixtures/real_corpus/cases \
  SANCTUM_LEDGER_HMAC_KEY=<hex-key> \
  SANCTUM_LEDGER_PATH=/tmp/sanctum_ledger/ledger.jsonl \
  SANCTUM_SKIP_MOUNT_CHECK=1 \
  SANCTUM_OUTPUT_ROOT=/tmp/sanctum_out \
  python3 scripts/dfir_investigation.py
```

It finishes in about 8 seconds. The same work by hand (Registry Explorer, EvtxECmd, PECmd) takes a skilled analyst 30 to 90 minutes.

## Honest limits shown in the demo

- **Prefetch needs Windows.** On macOS, `get_prefetch` fails on purpose (`windowsprefetch` needs Windows to decompress the file). On a Windows host it parses fine.
- **BAM is selective.** `get_bam` returns real events but not the short-lived PowerShell process. BAM does not record every process. The parser is correct; the artifact is simply absent.

## Forensic certainty labels

Each result carries a `c_scale` value tied to a standard examiner scale (Casey, *Digital Evidence and Computer Crime*, 3rd ed.):

| Tier | `c_scale` | Meaning |
|---|---|---|
| DRAFT_TAMPER_SUSPECTED | C0 | Uncertain — integrity in doubt |
| DRAFT | C2 | More likely than not |
| CORROBORATED | C4 | High confidence |
| FINAL | C5 | Beyond reasonable doubt |

## Reproduce it

Clone the repo, `pip install -e '.[dev]'`, supply real Windows artifacts under `tests/fixtures/real_corpus/cases/` (structure in [`ACCURACY.md`](ACCURACY.md)), run `python -m sanctum.server`, and connect any MCP client. The gate behavior is a property of the function — it does not depend on the artifacts, the model, or the prompt.

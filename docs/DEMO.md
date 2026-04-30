# Sanctum demo script — SANS FIND EVIL! submission

Four moments that together demonstrate the submission's three main claims:
architectural constraint enforcement, temporal coherence checking, and
parallel multi-family triage speed. Record from the Windows 11 Parallels rig
with Sanctum running and Claude Desktop connected.

---

## Setup (before recording)

```bash
# On the Parallels VM — start the server with parallel mode and a fresh ledger
export SANCTUM_LEDGER_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export SANCTUM_PARALLEL_TOOLS=1          # enables parallel speedup for Moment C
export SANCTUM_CASES_ROOT=/cases
sanctum-mcp                               # blocks; leave running
```

Verify Claude Desktop sees the tools (`tools/list` should show 7 tools).

---

## Moment A — Gate fire on single-family claim (Criterion 4: Constraint Implementation)

**What to show**: `claim_finding` refuses a claim that cites only Amcache
evidence. The gate fires deterministically at the typed-function boundary —
no LLM self-correction needed.

**Prompt to the agent**:
```
Call get_amcache for case "demo", then try to claim a finding
about notepad.exe execution citing only that audit_id.
```

**Expected output** (DRAFT, not CORROBORATED):
```json
{
  "tier": "DRAFT",
  "confirmation_basis": "single_family",
  "n_distinct_families": 1,
  "c_scale": "C2"
}
```

**Talking point**: The gate doesn't ask the LLM to reconsider — the typed
function enforces the ≥2-family rule. The agent can't talk its way past it.

---

## Moment B — Temporal-coupling demotion (Criterion 4 + Criterion 2: T1070.006 defense)

**What to show**: Two families with a 1-hour timestamp gap (Amcache at T,
Prefetch at T+3600) triggers demotion from CORROBORATED → DRAFT even though
the family count would normally yield CORROBORATED.

**Setup**: Use the timestomp demo fixture:
```bash
export SANCTUM_USE_FIXTURE_SIDECAR=1
# The fixture has Amcache ts=10:30 UTC and Prefetch ts=11:30 UTC (forged +1h)
```

**Prompt**:
```
Call get_amcache and get_prefetch for case "demo", then claim a finding
about malware.exe citing both audit_ids.
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

**Talking point**: The attacker forged the Prefetch last-run timestamp to
create a false alibi (MITRE ATT&CK T1070.006 Timestomp). Sanctum detected
the 3600 s cross-family spread and demoted. The LLM never saw the raw
timestamps — the gate fired before returning to the agent.

---

## Moment C — Parallel speedup (Criterion 1: Autonomous Execution Quality / speed)

**What to show**: Five-family triage completes measurably faster with
`SANCTUM_PARALLEL_TOOLS=1` than with the default serial mode.

**Prompt**:
```
Run all five evidence families for case "demo" (get_amcache, get_shimcache,
get_userassist, get_bam, get_prefetch) and then claim a finding.
```

With `SANCTUM_PARALLEL_TOOLS=1` (set in Setup), FastMCP dispatches all five
tool calls concurrently. The wallclock improvement is visible in the response
latency and in the ledger entries' `elapsed_ms` values (five overlapping
windows vs. five sequential windows).

**Expected output**: A `FINAL` (three or more families confirmed) or
`CORROBORATED` finding with `n_distinct_families=5`. All five `elapsed_ms`
values will overlap in wall time.

**Talking point**: The concurrency is enforced safely — `_ledger_write_lock`
serializes HMAC-chain writes so the audit trail stays consistent even when
five tools are racing. The lock is the constraint; the concurrency is the
benefit.

---

## Moment D — Casey C-Scale labels (Criterion 5: Audit Trail Quality)

**What to show**: Every `claim_finding` result carries a `c_scale` field
mapping the tier to forensic examiner vocabulary (Casey, *Digital Evidence
and Computer Crime*, 3rd ed., 2011).

**Expected mapping** (visible in any finding):
| Tier | `c_scale` | Meaning |
|---|---|---|
| `DRAFT_TAMPER_SUSPECTED` | `C0` | Uncertain — integrity suspect |
| `DRAFT` | `C2` | More likely than not |
| `CORROBORATED` | `C4` | High confidence |
| `FINAL` | `C5` | Beyond reasonable doubt |

**Talking point**: The C-Scale labels let a forensic examiner translate
Sanctum's output into established forensic certainty vocabulary without
re-interpreting the tiers. The mapping is tested and locked —
`tests/test_finding.py` pins the C-Scale assignments so they can't drift.

---

## Post-recording checklist

- [ ] Gate fire (Moment A) visible in <30 s of screen time
- [ ] `demoted_for_temporal: true` legible in the terminal output (Moment B)
- [ ] Five-family parallel run noticeably faster than serial baseline (Moment C)
- [ ] `c_scale` field visible in at least one finding output (Moment D)
- [ ] Ledger HMAC key redacted or blurred in any screenshot / video frame

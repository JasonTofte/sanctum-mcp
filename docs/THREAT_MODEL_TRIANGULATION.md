# Threat model — `claim_finding` triangulation threshold

*Quantitative justification for the `k = 2` corroboration gate in
[`claim_finding(hypothesis, audit_ids[])`](../src/sanctum/server.py),
and the case for tightening to `k = 3` for auto-finalized findings.*

The [README](../README.md#the-senior-analyst-gate) states that a finding
requires **at least two of five** independent artifact subsystems. This
document works out the forgery probability under an explicit threat
model so the threshold is chosen, not assumed. [FAILURE_MODES State 3](FAILURE_MODES.md#state-3-evidence-driven-prompt-injection-poisons-the-llm)
depends on this gate.

## Threat model

- **Five subsystems:** Prefetch, Amcache, ShimCache, UserAssist/BAM,
  Sysmon/EventID 4688. Each is produced by a distinct OS subsystem, so
  "independent" is a design claim — see §6 for where that claim gets
  wobbly.
- **Attacker goal.** Persuade `claim_finding` to accept a forged
  hypothesis by planting fake evidence in enough subsystems to satisfy
  the `≥ k` gate.
- **Attacker model — Bernoulli compromise.** Each subsystem `i` is
  independently compromised with probability `p_i`. When a subsystem is
  compromised, the attacker can plant corroborating evidence in it. When
  it is not compromised, the attacker cannot.
- **Defender goal.** Minimize `P(forgery) = P(X ≥ k)` where
  `X = |{compromised subsystems}|`, subject to tolerable false-negative
  cost.

## Scope and threat-model boundary

The Bernoulli/Poisson-binomial analysis below assumes per-subsystem
compromises are *independent events*. That assumption holds against
the attacker class this gate is designed for; it breaks against the
attacker class this gate explicitly does not defend against. Calling
that out here so the model is not over-applied.

**In scope (v1).** Pre-compromise corroboration of *user-mode* artifact
forgery: typo-squatted binaries clearing their own AppCompat trace,
malware deleting its own Prefetch entry, EVTX log clearing via
`wevtutil cl`, registry hive edits via standard SYSTEM-level tooling.
Each per-subsystem `p_i` in §4 is calibrated for this attacker class.

**Out of scope (v1, by design).** A kernel-mode rootkit able to forge
multiple families with a single privileged operation. The
independence assumption fails at this tier — an attacker who lifts
`p_AppCompat` and `p_BAM` jointly defeats the family count by
construction. Defense at this tier shifts to two other Sanctum
mechanisms, neither of which depends on the independence assumption:

- the **deception layer** (`sanctum.deception`, see
  [THREAT_MODEL_DECEPTION.md](THREAT_MODEL_DECEPTION.md)) — destructive
  anti-forensics signatures (`BaseFlushAppcompatCache`, SysMain
  service disable, MFT timestomp) leave traces even when forgery does
  not, demoting confidence tier asymmetrically; and
- the **HMAC-chained ledger** (see
  [THREAT_MODEL_LEDGER.md](THREAT_MODEL_LEDGER.md)) — post-hoc
  tamper detection across the entire tool-call sequence, independent
  of any per-finding count.

The family-count gate is **necessary but not sufficient** against
kernel-mode adversaries. The §7 "Load-bearing assumptions" #1 below
restates this in formal terms; this section is the operator-facing
summary and the scope claim that judges should evaluate the gate
against.

## Uniform baseline — Binomial(5, p)

For identical per-subsystem compromise probability `p`,
`X ~ Binomial(5, p)`:

| p    | P(X ≥ 2) *(current)* | P(X ≥ 3)   | P(X ≥ 4)   | 2/3 ratio |
|------|----------------------|------------|------------|-----------|
| 0.05 | 2.26%                | 0.12%      | 0.003%     | 19.5×     |
| 0.10 | 8.15%                | 0.86%      | 0.05%      | 9.5×      |
| 0.15 | 16.48%               | 2.66%      | 0.22%      | 6.2×      |
| 0.20 | 26.27%               | 5.79%      | 0.67%      | 4.5×      |
| 0.30 | 47.18%               | 16.31%     | 3.08%      | 2.9×      |
| 0.50 | 81.25%               | 50.00%     | 18.75%     | 1.6×      |

Reading the table: if you believe the average per-subsystem compromise
probability is `p ≈ 0.10`, `k = 2` leaves an 8% forgery rate and raising
to `k = 3` drops it by about an order of magnitude.

## Non-uniform — Poisson-binomial with realistic `p_i`

The subsystems are not equally tamper-resistant. The canonical priors
live in [`scripts/threat_model_priors.py`](../scripts/threat_model_priors.py)
as the single source of truth — both validators import from there, and
[`tests/test_threat_model_priors.py`](../tests/test_threat_model_priors.py)
asserts the table below matches the module. Update either, and the test
fires until both agree.

A defensible first-cut ordering, from hardest to easiest to tamper:

| Subsystem         | `p_i` | Rationale                                                 |
|-------------------|-------|-----------------------------------------------------------|
| ShimCache         | 0.05  | Kernel-managed, flushed on shutdown. In-memory only at runtime. |
| Amcache           | 0.10  | Registry hive, but records SHA-1 file hash — forgery needs matching hash. |
| UserAssist / BAM  | 0.15  | Per-user registry, SYSTEM can edit but paths are rot-13 obfuscated. |
| Prefetch          | 0.20  | `%SYSTEMROOT%\Prefetch\*.pf`, attacker with SYSTEM can delete/replace. |
| Sysmon / 4688     | 0.30  | Event logs are the most commonly tampered-with artifact (`wevtutil cl`, clear-event-log). |

Mean `p̄ = 0.16`. Under `Poisson-Binomial(p_1, …, p_5)`:

| Threshold | P(forgery) |
|-----------|------------|
| k = 2     | **17.84%** |
| k = 3     | **2.67%**  |
| k = 4     | **0.18%**  |

Moving from `k = 2` to `k = 3` cuts forgery probability by 6.7×; to
`k = 4` by 94×. For context, `k = 2` under this realistic `p_i` is
slightly *worse* than uniform `p = 0.15` (16.5%) because the Sysmon
tail at 0.30 pulls the distribution up.

## Marginal value of a 6th subsystem

One might think adding a 6th subsystem strengthens the gate. At **fixed
k**, it does the opposite — more subsystems means more potential
compromise targets for the attacker.

Computing `P(≥k in 6)` by conditioning on the 6th subsystem (using the
realistic `p_i` above plus a new subsystem at `p_6`):

| Added 6th at `p_6` | k = 2   | k = 3   | k = 4   |
|---------------------|---------|---------|---------|
| (no 6th — 5 total)  | 17.84%  | 2.67%   | 0.18%   |
| 0.05                | 19.91%  | 3.43%   | 0.31%   |
| 0.10                | 21.99%  | 4.19%   | 0.43%   |
| 0.15                | 24.06%  | 4.95%   | 0.56%   |

Every entry in rows 2–4 is **worse** than the current `5-of-2` baseline
at its own `k`. The benefit of a 6th subsystem materializes only if
`k` is also raised:

- `6-of-4` at `p_6 = 0.10`: **0.43%** — ≈ 6× better than `5-of-3`
  (2.67%) and ≈ 41× better than current `5-of-2`.
- `6-of-3` at any plausible `p_6`: strictly worse than `5-of-3`.

**Takeaway:** a 6th subsystem is only useful bundled with a threshold
bump. Adding it alone is a regression.

## Recommendation — split the gate

The `k = 2` threshold and the `k = 3` threshold are doing different
jobs. Current design collapses them:

| Role                      | Defensible `k`             | Rationale                                  |
|---------------------------|----------------------------|--------------------------------------------|
| Single-source (1 hit)     | **rejected / DRAFT**       | ~60% of a single compromised subsystem.    |
| Entry into corroboration  | **k = 2**                  | Filters single-source bad-faith claims.    |
| Auto-finalized finding    | **k = 3**                  | Drops P(forgery) from ~18% → ~2.7%.        |
| High-confidence (external report) | **k = 4**          | Drops P(forgery) to ~0.2%; strict enough to justify "published conclusion". |

This is a minimal refactor of `claim_finding` — accept `k = 2` as the
*corroboration entry* (tagged `CORROBORATED`) and `k = 3` as
*auto-final* (tagged `FINAL`). Single-source stays `DRAFT` +
`needs_corroboration` as today.

The README's existing claim — "Single-source claims are returned as
DRAFT with `needs_corroboration`" — already implies a stratified gate;
this document spells out the tier bands.

## Family coupling and the AppCompat correction

The Bernoulli-independence model above is how the literature usually
presents triangulation analysis, but it materially overstates Sanctum's
defence when two of the five subsystems share a trust root. An internal
architecture audit surfaced the specific instance:

**ShimCache and Amcache are not independent.** Both are written by the
Windows Application Experience Service / Program Compatibility Assistant
path (Mandiant 2024-08;
[Harlan Carvey](http://windowsir.blogspot.com/2024/11/program-execution-shimcacheamcache-myth.html)
2024-11). The Microsoft-documented kernel primitive
`BaseFlushAppcompatCache`/`ShimFlushCache` clears ShimCache with one
syscall; open-source tooling (`AntiForensic.NET`) clears both in a single
run. An adversary with SYSTEM privileges defeats both in under a second —
the "two independent subsystems" premise of a `{ShimCache, Amcache}`
corroboration pair is false under active attack.

The correct framing is **artifact families, not per-artifact subsystems**.
Each family has a distinct trust root and a distinct tampering cost:

| Family              | Members                 | Shared trust root                        |
|---------------------|-------------------------|------------------------------------------|
| AppCompat           | ShimCache, Amcache      | Application Experience Service / CSRSS   |
| Explorer / NTUSER   | UserAssist              | `explorer.exe` + per-user NTUSER.dat     |
| Background service  | BAM                     | `bam.sys` kernel driver + SYSTEM registry |
| Kernel ETW          | Sysmon / EventID 4688   | Windows Event Log + `sysmon.exe`         |
| SysMain             | Prefetch                | `SysMain` service + `C:\Windows\Prefetch\` |

Two audit_ids pointing into the **same** family count as one source for
the `≥ k` gate. The rule-table shape `claim_finding` will ship with
(week 4) therefore reads:

```
sources = {family(audit_id) for audit_id in audit_ids}
if len(sources) < 2: return DRAFT("needs_corroboration")
if len(sources) < 3: return CORROBORATED
return FINAL
```

This is a minimal change to the P0 design; it strictly tightens the gate
without touching the numeric `k` threshold.

## Revised Poisson-binomial with artifact families

Under the family reframe, two changes propagate into the probability
model:

1. ShimCache and Amcache collapse into one family at
   `p_AppCompat = 0.10` (dominated by the easier-to-tamper Amcache; a
   forensically-distinguishable rewrite of the AppCompat hive requires a
   matching SHA-1 in the Amcache hive, so `p_AppCompat < p_Amcache` is
   unjustified).
2. UserAssist and BAM, previously collapsed into one `0.15` line item,
   split — they live in different hives with different writers and
   should count separately. `p_UserAssist = 0.15`,
   `p_BAM = 0.15`.

Resulting family tuple: `ps = (0.10, 0.15, 0.15, 0.20, 0.30)`. Mean
`p̄ = 0.18` (vs `0.16` under the prior ordering).

| Threshold | P(forgery), revised | P(forgery), prior (§3) | Change |
|-----------|---------------------|------------------------|--------|
| k = 2     | **21.98%**          | 17.84%                 | +4.14 pp |
| k = 3     | **4.05%**           | 2.67%                  | +1.38 pp |
| k = 4     | **0.37%**           | 0.18%                  | +0.19 pp |

Full distribution under the family tuple:

| X | P(X) |
|---|------|
| 0 | 0.3641 |
| 1 | 0.4161 |
| 2 | 0.1793 |
| 3 | 0.0368 |
| 4 | 0.0036 |
| 5 | 0.0001 |

Reading the delta: the prior non-uniform table was optimistic because it
treated two coupled artifacts as independent high-difficulty tamper
targets. The family-revised model shifts probability mass toward higher
X by replacing one "hard" target with the mean-difficulty of its family.

**Design implication.** The §5 recommendation (stratified
`CORROBORATED | FINAL` tiers) is strengthened, not weakened, by the
family reframe: a `FINAL` gate at `k = 3` still puts forgery probability
at ~4%, an order of magnitude better than any `k = 2` configuration, and
the gate now reflects the actual trust topology.

Regression tests for the new numbers live in
[`scripts/validate_threat_model_math.py`](../scripts/validate_threat_model_math.py)
alongside the original non-uniform table.

## Confirmation basis (v1 vs v2)

The `Finding` schema carries a typed `confirmation_basis` field that
records *how* corroboration was achieved, not just whether it cleared
the threshold. A judge or downstream tool reading a Finding can
distinguish "the gate just barely fired" from "two genuinely
independent trust roots agree" without re-deriving the family list.

The wire schema reserves four values; **v1 emits exactly two**, and the
other two are placeholders so a v2 producer can populate them without a
schema break:

| Value | Emitted by v1? | Meaning |
|---|---|---|
| `single_family` | Yes — DRAFT path | Only one distinct family voted. The Finding is below the corroboration threshold. |
| `independent_artifacts` | Yes — CORROBORATED / FINAL paths | ≥2 distinct families voted. The five v1 families are by-construction trust-root-disjoint (see §"Family coupling and the AppCompat correction"), so this is the strong-corroboration case. |
| `coupled_artifacts` | **No (reserved for v2)** | Reserved for a v2 split that introduces sub-families inside an existing family (e.g., separating ShimCache and Amcache as distinct sub-families that share the AppCompat trust root). A v2 finding citing two such sub-families would correctly de-rate to `coupled_artifacts` rather than be inflated to `independent_artifacts`. |
| `single_family_strong_signal` | **No (reserved for v2)** | Reserved for a v2 escape hatch: a single-family finding promoted on the strength of a high-confidence intra-family signal (e.g., Amcache SHA-1 cross-check against an external reputation source). v1 has no such signal and so never emits this value. |

Because the field type is a `Literal[...]` of all four values from day
one, a v2 producer that writes `coupled_artifacts` does not break a v1
consumer's schema validation — the consumer sees an unfamiliar but
type-valid value and can choose to treat it conservatively (e.g., as
`single_family` for tier purposes). The forward-compatibility cost is
one extra bit of vocabulary on the wire today, paid once.

The field is recorded in **both** the `Finding` returned to the agent
and the `claim_finding` ledger entry's `input_ref.finding` payload, so
a downstream verifier walking the ledger sees the basis the gate
asserted at the time of the claim.

## Load-bearing assumptions

1. **Independence.** The Bernoulli/Poisson-binomial model assumes
   `p_i` are independent. In reality all five subsystems run on the
   same host, often share on-disk storage, and fall to a single
   SYSTEM-level compromise. The **family reframe** above partially
   addresses this by collapsing the one known worst-offender pair
   (ShimCache ∧ Amcache under the AppCompat service) into a single
   family member; further same-host coupling remains. A kernel
   rootkit that can forge one registry hive can forge three. If
   `Pr(all 5 compromised | any compromised)` is non-trivial, the
   model *understates* forgery probability; the real defence is that
   **tampering leaves distinct trace artifacts in each subsystem** —
   a live kernel module touching AppCompat, Prefetch, and Sysmon
   makes forensically distinguishable writes. The §2 "Scope and
   threat-model boundary" section above resolves this for v1 by
   making kernel-mode multi-family forgery explicit OOS and shifting
   defense to the deception layer + HMAC-chained ledger. Quantifying
   the joint distribution properly (copula or shared-latent-factor
   correlation model) is a v2 followup, not a v1 dependency.
2. **Symmetric attacker capability.** The model treats "compromised"
   as binary — attacker can forge freely. In practice attackers differ
   at forging content that passes downstream consistency checks
   (Amcache SHA-1, Prefetch execution-time correlation with MFT
   timestamps). A realistic refinement is to subdivide "compromise"
   into read, write-with-forensic-traces, and write-perfectly.
3. **False negatives not modeled.** Raising `k` increases the fraction
   of legitimate findings that fail the gate (cases where evidence
   only surfaces in 2 subsystems because the third was rolled or
   deleted by normal OS behaviour — not attacker action). The
   recommendation in §5 chose *stratified tiers* exactly to avoid
   paying a false-negative cost for the `CORROBORATED` tier while
   still offering `FINAL` as a stricter grade.

## Followups

- [x] **Shipped.** `FindingConfidence` enum
      (`DRAFT | CORROBORATED | FINAL`) + `classify_confidence(n)`
      helper in `sanctum.audit`. The week-4 `claim_finding`
      implementation is expected to call the helper rather than
      inline the tier rules, so the threat-model doc and the gate
      cannot drift. Pinned by tier-boundary tests in
      `tests/test_audit.py`.
- [ ] Wire `claim_finding` to the helper when it ships (week-4 per
      README roadmap). The gate MUST operate on **distinct families**,
      not raw subsystem counts — see "Family coupling and the
      AppCompat correction" above. Reference mapping to apply to
      each `audit_id`: look up the `tool` field of the ledger entry
      and map `{get_shimcache, get_amcache}` → `"AppCompat"`,
      `{get_userassist}` → `"Explorer"`, `{get_bam}` → `"BAM"`,
      `{get_sysmon_4688}` → `"Sysmon"`,
      `{get_prefetch}` → `"Prefetch"`. The count passed to
      `classify_confidence` is `len(set(map(family, audit_ids)))`.
- [x] **Shipped.** Priors centralized in
      `scripts/threat_model_priors.py`; both validators import from
      there. `tests/test_threat_model_priors.py` pins the canonical
      values so a prior change cannot silently land without updating
      this doc. (Tables themselves remain hand-curated rather than
      auto-regenerated — the validator failure is the regen prompt.)
- [ ] Model the joint compromise distribution (copula with shared
      SYSTEM-access latent factor); rerun the table.

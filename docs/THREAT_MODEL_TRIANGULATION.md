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

The subsystems are not equally tamper-resistant. A defensible first-cut
ordering, from hardest to easiest to tamper:

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

## Load-bearing assumptions

1. **Independence.** The Bernoulli/Poisson-binomial model assumes
   `p_i` are independent. In reality all five subsystems run on the
   same host, often share on-disk storage, and fall to a single
   SYSTEM-level compromise. A kernel rootkit that can forge one
   registry hive can forge three. If `Pr(all 5 compromised | any
   compromised)` is non-trivial, the model *understates* forgery
   probability; the real defence is that **tampering leaves distinct
   trace artifacts in each subsystem** — a live kernel module
   touching ShimCache, Amcache, and Prefetch makes forensically
   distinguishable writes. Quantifying the joint distribution
   properly requires a correlation model (copula or shared-latent-
   factor); that is out of scope here and flagged as an open item.
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
      README roadmap); reject/DRAFT single-source claims at the MCP
      typed boundary.
- [ ] Encode the `p_i` table in `docs/` as data (YAML) and regenerate
      this doc's tables from a test fixture, so forensic-community
      feedback on the priors updates the thresholds automatically.
- [ ] Model the joint compromise distribution (copula with shared
      SYSTEM-access latent factor); rerun the table.

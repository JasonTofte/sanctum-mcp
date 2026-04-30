# Architecture Decision Record — Temporal-coupling demoter (Phase 5, F4)

This document captures the load-bearing architectural decisions for the
temporal-coupling demoter — Layer 3 of the `claim_finding` gate — and
the ARCH-002 bright-line constraint locked at program level on 2026-04-28.

---

## ADR-TEMPORAL-001 — Temporal demoter is demote-only (ARCH-002 bright line)

**Status.** Accepted (2026-04-29).

**Context.** The Layer 2 family-corroboration gate classifies findings by
distinct artifact family count. An adversary executing MITRE ATT&CK T1070.006
(Timestomp) can forge one family's evidence timestamps to make a two-family
finding *appear* temporally consistent, clearing the corroboration bar without
the families' event windows actually overlapping. A naive fix — reward temporal
consistency by promoting confidence — would create a new attack surface: the
demoter becomes a promoter, and forcing two forged families to share a timestamp
gains a higher tier than an honest finding.

**Decision.** The temporal check is strictly monotone-decreasing (ARCH-002).
`_check_temporal_coherence` returns one of `"coherent" | "incoherent" |
"insufficient_data"`. The caller (`evaluate_claim`) maps `"incoherent"` to a
one-step demotion (`FINAL → CORROBORATED`, `CORROBORATED → DRAFT`) and never
promotes on `"coherent"`. The mapping is a closed dict (`_TEMPORAL_DEMOTION`)
with no upward entries; an AST-based absence test (T-7 in
`tests/test_no_temporal_promote_path.py`) gates every merge.

**Consequences — Positive.**
- T1070.006 timestomp cannot clear the gate even when the attacker controls
  one family's timestamps — the best outcome is `CORROBORATED` demoted to
  `DRAFT`, which surfaces the anomaly rather than hiding it.
- ARCH-002 is machine-verifiable at merge time via the T-7 AST test.
- The demoter applies no false-negative cost when timestamps are absent
  (`"insufficient_data"` → no demotion, backward-compatible with pre-Phase-5
  ledger entries).

**Consequences — Negative.**
- The ±5 s default window is a coarse heuristic. Clock skew between Windows
  subsystems (e.g., Sysmon ETW vs. Prefetch file-write time) can reach tens
  of milliseconds; legitimate multi-step executions spanning minutes are
  clipped unless the operator widens the window via
  `SANCTUM_TEMPORAL_COUPLING_WINDOW_SECONDS`. The copula-corrected window
  distribution is deferred to v2 (see `docs/THREAT_MODEL_TRIANGULATION.md`
  §"Known limits and future work").

**Rejected alternative — promote on coherent.** Any design where
`_check_temporal_coherence` returning `"coherent"` raises confidence was
rejected as inverting the threat model: it turns the temporal check into an
attack surface rather than a defense. ARCH-002 exists precisely to rule this
out at the architectural level.

---

## ADR-TEMPORAL-002 — Timestamps stored in LedgerEntry, not re-derived

**Status.** Accepted (2026-04-29).

**Context.** Three options were evaluated for sourcing the family timestamps
that feed the demoter:

- **Option A (selected)**: add `first_event_ts`/`last_event_ts` to
  `LedgerEntry` as optional omit-not-null fields, extracted by
  `_emit_offloaded_response` before the ledger write.
- **Option B**: re-read the offloaded payload file at demoter time.
- **Option C**: pass timestamps inline on the `evaluate_claim` call site.

**Decision.** Option A. The `LedgerEntry` is the single source of truth for
tool-call provenance. Storing timestamps there keeps `_check_temporal_coherence`
a pure function on ledger data (AC-5) — it never re-reads evidence files,
which would re-introduce a file-I/O dependency into the gate and violate the
composability contract. Option B fails AC-5. Option C breaks the ledger
abstraction by requiring callers to supply data they don't naturally have.

**Consequences — Positive.**
- `_check_temporal_coherence` is pure-function on the `entries` dict already
  fetched by `evaluate_claim`. No additional I/O in the gate.
- `first_event_ts`/`last_event_ts` are HMAC-covered (they're included in
  `_line_hash_for`'s input body) — a forged timestamp in a ledger entry breaks
  `verify_chain`.
- Omit-not-null serialization means pre-Phase-5 ledgers verify bytewise-
  identically under the same HMAC key.

**Consequences — Negative.**
- Server-side extraction (`_emit_offloaded_response`) assumes all rows have a
  `"timestamp"` key and that ISO-8601 strings from Python's `.isoformat()`
  sort lexicographically correctly. This holds for UTC-aware datetimes
  (consistent `+00:00` suffix from `isoformat()`); mixed suffix formats would
  require normalization. A comment at the extraction site documents this
  invariant.

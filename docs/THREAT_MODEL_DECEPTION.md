# Threat model — forensic deception (anti-forensics) detection

This document specifies the threat model for [`sanctum.deception`](../src/sanctum/deception.py)
— the reason-code layer that detects three named anti-forensic technique
signatures and feeds them to the week-4 `claim_finding` gate as
confidence-downgrade evidence.

**Status**: v1 — interface + signatures defined; week-6 adversarial
benchmark suite pins the false-positive / false-negative profile.

## Why this layer exists

The Sygnia "Logs Lie to You" PoC (Aug 2025) demonstrated the *first half*
of the LLM-DFIR threat: attacker-authored evidence text hijacks an LLM
analyst. [`sanctum.sanitize`](../src/sanctum/sanitize.py) defends that
half by quarantining all tool output inside `<evidence-untrusted>` and
stripping known injection patterns.

The *second half* — attacker-authored evidence **structure** (missing,
zeroed, inconsistent artifacts) — is unaddressed by sanitization. An
attacker who runs `BaseFlushAppcompatCache` doesn't need to craft a
prompt-injection payload; they just delete the AppCompat evidence. The
LLM analyst, presented with no AppCompat rows, may infer "no programs
ran" — a confident wrong answer the family gate alone does not catch
(the gate only checks how many *families* corroborate; it does not check
whether a missing family is *suspiciously* missing).

`sanctum.deception` closes this gap by recognising three named
anti-forensic signatures and emitting a typed reason code that
`claim_finding` consumes as a downgrade signal.

## Threat actors and assumptions

We model the attacker per the GTG-1002 disclosure (Anthropic, Nov 2025) —
human-supervised but automated tooling, not zero-day-class capability:

- **In scope**: BaseFlushAppcompatCache (single syscall),
  AntiForensic.NET (open-source), `sc stop SysMain` + `sc config SysMain
  start= disabled`, timestomp.exe / SetMACE.
- **Out of scope**: kernel-mode rootkits that rewrite `$FILE_NAME` MFT
  attributes (those reach the trust root we depend on). Sanctum's
  detection model is *non-kernel-attacker*; we say so explicitly so
  judges and operators can assess applicability.

We assume the operator has followed [`docs/REPRODUCTION.md`](REPRODUCTION.md)
mount discipline (`-o ro,noload,norecovery,noexec,nosuid` + `blockdev
--setro`), so journal-replay and post-acquisition mutation are out of
scope as well — those are the [`docs/FAILURE_MODES.md`](FAILURE_MODES.md)
State 3b problem, addressed by the `_validate_evidence_mount()` runtime
check.

## The three signatures

| Signature | Reason code | Evidence required |
|---|---|---|
| AppCompat flush — `BaseFlushAppcompatCache` or `AntiForensic.NET` wiped ShimCache | `TAMPER_LIKELY_BASEFLUSHAPPCOMPATCACHE` | ShimCache empty; SYSTEM hive `mtime` within 1h of acquisition; >1s gap (else ambiguous — see below) |
| SysMain suppression — service stopped/disabled to prevent Prefetch generation | `TAMPER_LIKELY_SYSMAIN_DISABLED` | Amcache rows ≥ 5; Prefetch dir empty; SysMain service state = `Disabled` |
| MFT timestomp — `$STANDARD_INFORMATION` rewritten without kernel privilege | `TAMPER_LIKELY_MFT_TIMESTOMP` | `$SI` btime predates configurable epoch threshold while `$FN` does not, **or** `$SI` btime precedes `$FN` btime by >1 day |

Each predicate is deterministic — no thresholds tuned on a held-out
set, no statistical scoring. A judge can hand-verify the predicate
against the case's raw artifacts.

## Constructive vs. destructive forgery (v1 boundary)

The three signatures above all detect *destructive* anti-forensics:
the attacker removes, suppresses, or zeroes evidence. Detection is
possible because destruction leaves its own trace — an empty
ShimCache plus a SYSTEM hive write timestamp; SysMain `Disabled`
plus surviving Amcache rows; MFT `$SI` lying about creation while
`$FN` does not.

**Constructive forgery — the attacker plants coherent records across
multiple families to fabricate a finding rather than hide one — is
out of scope for v1, by design.** This is the threat where, e.g.,
the attacker writes a fake Amcache row for `evil.exe` plus a matching
BAM entry plus a matching UserAssist entry, all internally consistent
in timestamps and identifiers.

v1 defense against constructive forgery is the **family-count gate**,
not the deception layer:

- An attacker who can write to ≤1 family is bounded by `claim_finding`
  returning `DRAFT` (single-source, sub-`k` count).
- An attacker who can write to ≥2 families with full forensic
  consistency (matching SHA-1 hashes, plausible timestamps under MFT
  cross-reference, no destructive signatures elsewhere) is at the
  threat tier marked out-of-scope for v1 by
  [THREAT_MODEL_TRIANGULATION.md §"Scope and threat-model boundary"](THREAT_MODEL_TRIANGULATION.md#scope-and-threat-model-boundary)
  — kernel-mode rootkit equivalence.

The deception layer is **necessary but not sufficient** against
multi-family constructive forgery. v2 followup work (cross-family
timestamp-coherence checks, SHA-1 anomaly detection on synthesised
Amcache rows, statistical novelty over expected per-family
record-rate) is captured in §"Followups" below rather than shipped
in v1.

The §"Fail-closed asymmetry" contract below holds for what this layer
*does* detect — a positive destructive signature downgrades; absence
of any signature does not upgrade. That contract does not extend to
coverage of constructive attacks.

## Ambiguity codes

Anti-forensic detection is a high-false-positive domain (Garfinkel
2007). The interface emits explicit ambiguity codes when a positive
fingerprint also matches a legitimate operator action:

- `AMBIGUOUS_LEGITIMATE_FLUSH_CONSISTENT` — ShimCache empty AND SYSTEM
  hive write ≤1s before acquisition. Matches both BaseFlushAppcompatCache
  and a graceful-shutdown-then-snapshot. The gate must not collapse this
  to "tampered = true."
- `AMBIGUOUS_SYSMAIN_DISABLED_OPERATOR_PLAUSIBLE` — SysMain service
  state = `Stopped` (not `Disabled`). An admin running a perf test
  produces this; an attacker typically also disables to survive reboot.

Surfacing ambiguity rather than collapsing it to a positive is a
chain-of-custody discipline — `claim_finding` records the ambiguity
code in the ledger, and the analyst (human or LLM) must justify the
confidence assignment.

## Fail-closed asymmetry

A central invariant: **a positive deception signal DOWNGRADES finding
confidence; the absence of a signal NEVER UPGRADES confidence.**

Encoding the contract this way avoids the "absence of evidence is
evidence of absence" fallacy. Concretely:

- A claim with two corroborating families and **no** deception signal
  is `CORROBORATED` — same as without this layer.
- A claim with two corroborating families and **one** deception signal
  is downgraded to `DRAFT_TAMPER_SUSPECTED` (a tier below `DRAFT`),
  forcing the agent to gather a third family before promotion.

The asymmetry is what makes this layer safe to ship without a tuned
false-positive rate: every false positive costs one extra tool call,
not a wrong finding.

## Demo scenario (week-9 video)

The synthetic LockBit-style case under `tests/adversarial/lockbit_sysmain_disabled/`
(week-6 build) drives the demo:

1. Agent calls `get_amcache` → 17 rows present.
2. Agent calls `get_prefetch` → 0 files.
3. Agent calls `get_sysmain_state` → `Disabled`.
4. `check_sysmain_suppression` fires → `TAMPER_LIKELY_SYSMAIN_DISABLED`.
5. Agent calls `claim_finding(hypothesis="evilprog.exe executed",
   audit_ids=[...])` → tier `CORROBORATED` is downgraded to
   `DRAFT_TAMPER_SUSPECTED` because of the active deception signal.
6. Agent gathers `get_bam` and `get_userassist` (BAM family +
   Explorer/NTUSER family).
7. `claim_finding` re-evaluates: 4 distinct families (AppCompat,
   SysMain, BAM, Explorer/NTUSER) → tier would be `FINAL`, but the
   active deception signal demotes one tier → final ledger entry is
   `CORROBORATED` with `reason_codes=[TAMPER_LIKELY_SYSMAIN_DISABLED]`.

The demo shows: (a) self-correction triggered by an external,
deterministic signal — not by introspection prompt-engineering; (b) the
ledger entry preserves the reason code so the analyst downstream sees
*why* the finding was downgraded.

## References

- Conlan, Baggili, Breitinger. *Anti-Forensics: Furthering Digital
  Forensic Science Through a New Extended, Granular Taxonomy.* DFRWS
  2016 §4.2.
- Garfinkel. *Anti-Forensics: Techniques, Detection and Countermeasures.*
  ICIW 2007.
- CISA AA23-075A — LockBit family disabling SysMain to suppress
  Prefetch.
- Sygnia. *When Your Logs Lie to You — LLM-MDR Prompt Injection PoC.*
  Aug 2025. (Used as the threat anchor for sanitization, but the
  structural-deception attacks here are out of its scope.)

## Followups (v2)

- **Cross-family timestamp coherence.** Constructive forgery requires
  the attacker to plant timestamps that survive cross-artifact
  consistency checks (Amcache install_time vs Prefetch first-run vs
  MFT `$FN` btime vs Sysmon EventID 1 process creation time). A
  family-spanning coherence predicate could detect coarse forgeries.
  Research project; not in v1 scope.
- **Per-family record-rate novelty.** Sustained anomaly in expected
  record cadence (e.g., 200 Amcache rows in a 30-second window when
  baseline is <5/min) is a constructive-forgery tell. Requires a
  baseline-rate model not currently shipped.
- **Amcache SHA-1 plausibility.** A planted Amcache row with a SHA-1
  that doesn't match any file actually present on disk (or any known
  hash in NSRL/VirusTotal) is suspicious. Out of scope until the
  hash-cross-reference pathway is implemented.

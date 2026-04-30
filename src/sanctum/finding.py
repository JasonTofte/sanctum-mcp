"""``claim_finding`` — the family-corroboration gate.

This module implements the typed function the README's "Autonomous Execution
Quality" row points to. It is the **external-signal self-correction**
primitive in Kamoi (TACL 2024)'s taxonomy: the agent's claim is checked
against an *independent* signal — the artifact-family coupling derived from
distinct OS trust roots — not against the agent's own introspection.

Flow:

1.  Caller passes ``hypothesis``, a list of ``audit_ids`` previously
    returned by ``get_*`` tool calls, and an optional list of
    :class:`sanctum.deception.DeceptionSignal` from anti-forensic checks.
2.  The gate reads each ``audit_id`` from the ledger and resolves the
    contributing family via :func:`sanctum.families.resolve_family`.
3.  Distinct families are counted (per CLAUDE.md invariant 5 —
    same-family ``audit_ids`` collapse).
4.  :func:`sanctum.audit.classify_confidence` maps the count and the
    deception-signal-presence bit to a tier
    (``DRAFT_TAMPER_SUSPECTED < DRAFT < CORROBORATED < FINAL``).
5.  The result is appended to the ledger as a ``tool="claim_finding"``
    entry. The HMAC chain extends to cover findings the same way it
    covers ``get_*`` tool calls — so a forged finding requires
    compromising ``SANCTUM_LEDGER_HMAC_KEY``.

Refusal cases (each raises :class:`ClaimFindingError`):

- ``audit_ids`` is empty.
- Any ``audit_id`` is not present in the ledger (the agent fabricated it).
- Any referenced ledger entry has an unknown ``tool`` (the policy in
  :mod:`sanctum.families` is incomplete; refuse rather than route to a
  silent default).

The strict-fail-closed behaviour is the security bargain: the gate
trades agent ergonomics for the architectural guarantee that no claim
ever lands in the ledger without provenance.

References:
- Kamoi et al. *When Can LLMs Actually Correct Their Own Mistakes?*
  TACL 2024 — external-signal self-correction taxonomy.
- ``docs/THREAT_MODEL_TRIANGULATION.md`` §5 — quantitative justification
  for the ≥2-distinct-families threshold.
- ``docs/THREAT_MODEL_DECEPTION.md`` — demotion semantics when a
  deception signal is present.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from sanctum.audit import (
    FindingConfidence,
    LedgerEntry,
    _ledger_path,  # noqa: PLC2701 — intentional package-internal use
    append_entry,
    classify_confidence,
)
from sanctum.deception import DeceptionSignal
from sanctum.families import resolve_family

# Confirmation basis — *how* a finding's corroboration was achieved, surfaced
# to callers so a downstream consumer can distinguish "the gate just barely
# fired" from "two genuinely independent trust roots agree". v1 only ever
# emits ``single_family`` or ``independent_artifacts`` — the other two
# values are reserved on the wire so a v2 producer can use them without a
# breaking schema change. See ``docs/THREAT_MODEL_TRIANGULATION.md``
# §"Confirmation basis (v1 vs v2)" for what each value will mean.
ConfirmationBasis = Literal[
    "single_family",
    "independent_artifacts",
    "coupled_artifacts",
    "single_family_strong_signal",
]

# Casey C-Scale mapping — ties each FindingConfidence tier to the forensic
# certainty ordinal from Casey, E., *Digital Evidence and Computer Crime*,
# 3rd ed., 2011. C1/C3/C6 are unused: C1 and C3 have no mapping to the
# current tier set; C6 ("certain beyond any doubt") is theoretical.
# Citation partially verified: C0–C6 labels convergent across 5+ secondary
# sources; verbatim 3rd-ed wording is behind paywall — see docs/ACCURACY.md.
DEFAULT_TEMPORAL_COUPLING_WINDOW_SECONDS: float = 5.0

_CONFIDENCE_TO_C_SCALE: dict[FindingConfidence, str] = {
    FindingConfidence.DRAFT_TAMPER_SUSPECTED: "C0",
    FindingConfidence.DRAFT: "C2",
    FindingConfidence.CORROBORATED: "C4",
    FindingConfidence.FINAL: "C5",
}


_TEMPORAL_DEMOTION: dict[FindingConfidence, FindingConfidence] = {
    FindingConfidence.FINAL: FindingConfidence.CORROBORATED,
    FindingConfidence.CORROBORATED: FindingConfidence.DRAFT,
    # DRAFT_TAMPER_SUSPECTED is the floor — tier cannot go lower, but
    # demoted_for_temporal=True is still correct so the audit trail reflects
    # that the temporal check also fired (separate from the tamper signal).
    FindingConfidence.DRAFT_TAMPER_SUSPECTED: FindingConfidence.DRAFT_TAMPER_SUSPECTED,
}


def _check_temporal_coherence(
    family_timestamps: dict[str, str | None],
    window_seconds: float,
) -> Literal["coherent", "incoherent", "insufficient_data"]:
    """Compare earliest evidence-event timestamps across families.

    Returns 'insufficient_data' when fewer than two families have a timestamp
    (no demotion applied by the caller in that case).
    Returns 'incoherent' when max − min > window_seconds (demote).
    Returns 'coherent' when max − min <= window_seconds (preserve tier).

    ARCH-002 bright line: this function NEVER raises confidence.
    It is pure-function on the supplied dict — no file I/O.
    """
    parsed: list[datetime] = []
    for ts in family_timestamps.values():
        if ts is not None:
            parsed.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
    if len(parsed) < 2:
        return "insufficient_data"
    span = (max(parsed) - min(parsed)).total_seconds()
    return "coherent" if span <= window_seconds else "incoherent"


class ClaimFindingError(ValueError):
    """Raised when ``claim_finding`` refuses a claim.

    ``ValueError`` subclass so callers handling input-validation can catch
    either; ``isinstance(exc, ClaimFindingError)`` reads cleanly in
    policy code.
    """


@dataclass(frozen=True)
class Finding:
    """A claim_finding result. Frozen — the ledger entry is the source of truth."""

    audit_id: str  # ledger audit_id of the claim_finding entry itself
    case_id: str
    hypothesis: str
    tier: FindingConfidence
    audit_ids: tuple[str, ...]
    families: tuple[str, ...]  # ordered set: distinct families that voted
    n_distinct_families: int
    confirmation_basis: ConfirmationBasis  # v1: single_family | independent_artifacts
    reason_codes: tuple[str, ...]  # TamperReason values from deception_signals
    demoted_for_tamper: bool
    c_scale: str  # Casey C-Scale ordinal per _CONFIDENCE_TO_C_SCALE
    demoted_for_temporal: bool = False


@dataclass(frozen=True)
class FindingEvaluation:
    """Gate-only evaluation of a claim — no ledger I/O.

    Mirrors :class:`Finding` minus ``audit_id``, because the audit_id is
    minted at ledger-append time. Server-side callers use this when they
    need to write the offload payload BEFORE the ledger append (so the
    on-disk path and the ledger entry share a pre-minted audit_id) — the
    universal offload helper in ``sanctum.server`` is the single call
    site that does that.
    """

    case_id: str
    hypothesis: str
    tier: FindingConfidence
    audit_ids: tuple[str, ...]
    families: tuple[str, ...]
    n_distinct_families: int
    confirmation_basis: ConfirmationBasis
    reason_codes: tuple[str, ...]
    demoted_for_tamper: bool
    demoted_for_temporal: bool = False


def evaluate_claim(
    *,
    case_id: str,
    hypothesis: str,
    audit_ids: Sequence[str],
    deception_signals: Sequence[DeceptionSignal] = (),
    ledger_path: Path | None = None,
) -> FindingEvaluation:
    """Pure gate evaluation — does NOT write to the ledger.

    Implements steps 1–4 of the module-level flow (read entries, dedupe,
    resolve families, classify confidence, derive ``confirmation_basis``).
    Step 5 (ledger append) is the caller's responsibility — :func:`claim_finding`
    delegates to this function and then appends; the server-side offload
    helper does the same but interposes the write-once payload step
    between the evaluation and the ledger append, so the on-disk file
    and the ledger entry share a pre-minted audit_id.

    Raises :class:`ClaimFindingError` on empty ``audit_ids``, missing
    ledger references, or unknown tool names — same contracts as
    :func:`claim_finding`.
    """
    if not audit_ids:
        raise ClaimFindingError("audit_ids is empty; a finding requires at least one source")

    deduped_ids = tuple(dict.fromkeys(audit_ids))  # preserve order, drop duplicates
    entries = _read_entries(ledger_path or _ledger_path(), set(deduped_ids))

    missing = set(deduped_ids) - set(entries.keys())
    if missing:
        raise ClaimFindingError(
            f"audit_ids not found in ledger: {sorted(missing)}; agent must "
            f"call the underlying get_* tool before claiming a finding"
        )

    families: list[str] = []
    seen: set[str] = set()
    for aid in deduped_ids:
        family = resolve_family(entries[aid]["tool"])  # raises UnknownToolError
        if family not in seen:
            seen.add(family)
            families.append(family)

    signal_present = bool(deception_signals)
    tier = classify_confidence(len(families), deception_signal_present=signal_present)
    reason_codes = tuple(s.reason.value for s in deception_signals)

    # The five families in v1 are by-construction trust-root-disjoint
    # (see ``docs/THREAT_MODEL_TRIANGULATION.md`` §"Family coupling"), so
    # any finding with ≥2 families has ``independent_artifacts`` basis.
    # A future v2 split inside a family (e.g., ShimCache vs Amcache as
    # separate sub-families) is what the ``coupled_artifacts`` reserved
    # value exists for.
    confirmation_basis: ConfirmationBasis = (
        "independent_artifacts" if len(families) >= 2 else "single_family"
    )

    # Layer 3 — temporal-coupling demoter (ARCH-002: demote-only, never promote).
    # Build family→first_event_ts from the first audit_id per family.
    family_ts: dict[str, str | None] = {}
    for aid in deduped_ids:
        fam = resolve_family(entries[aid]["tool"])
        if fam not in family_ts:
            family_ts[fam] = entries[aid].get("first_event_ts")

    window = float(
        os.environ.get(
            "SANCTUM_TEMPORAL_COUPLING_WINDOW_SECONDS",
            DEFAULT_TEMPORAL_COUPLING_WINDOW_SECONDS,
        )
    )
    coherence = _check_temporal_coherence(family_ts, window_seconds=window)
    demoted_for_temporal = False
    if coherence == "incoherent" and tier in _TEMPORAL_DEMOTION:
        tier = _TEMPORAL_DEMOTION[tier]
        demoted_for_temporal = True

    return FindingEvaluation(
        case_id=case_id,
        hypothesis=hypothesis,
        tier=tier,
        audit_ids=deduped_ids,
        families=tuple(families),
        n_distinct_families=len(families),
        confirmation_basis=confirmation_basis,
        reason_codes=reason_codes,
        demoted_for_tamper=signal_present,
        demoted_for_temporal=demoted_for_temporal,
    )


def claim_finding(
    *,
    case_id: str,
    hypothesis: str,
    audit_ids: Sequence[str],
    deception_signals: Sequence[DeceptionSignal] = (),
    ledger_path: Path | None = None,
) -> Finding:
    """Gate a forensic claim through the family-corroboration check.

    See module docstring for the full flow. Caller-facing contract:

    - Returns a :class:`Finding` whose ``tier`` is the result of the
      family count + deception-signal demotion.
    - Always appends a ``tool="claim_finding"`` entry to the ledger,
      *including* on a DRAFT result. The audit trail records every
      claim attempt — promoting from DRAFT later is a *new* entry, not
      a mutation.
    - Raises :class:`ClaimFindingError` on empty ``audit_ids``,
      missing ledger references, or unknown tool names.
    """
    evaluation = evaluate_claim(
        case_id=case_id,
        hypothesis=hypothesis,
        audit_ids=audit_ids,
        deception_signals=deception_signals,
        ledger_path=ledger_path,
    )

    finding_payload: dict[str, Any] = {
        "hypothesis": evaluation.hypothesis,
        "tier": evaluation.tier.value,
        "audit_ids": list(evaluation.audit_ids),
        "families": list(evaluation.families),
        "n_distinct_families": evaluation.n_distinct_families,
        "confirmation_basis": evaluation.confirmation_basis,
        "reason_codes": list(evaluation.reason_codes),
        "demoted_for_tamper": evaluation.demoted_for_tamper,
        "demoted_for_temporal": evaluation.demoted_for_temporal,
        "c_scale": _CONFIDENCE_TO_C_SCALE[evaluation.tier],
    }
    finding_hash = _sha256_canonical(finding_payload)

    entry: LedgerEntry = append_entry(
        case_id=case_id,
        tool="claim_finding",
        args={
            "hypothesis": hypothesis,
            "audit_ids": list(evaluation.audit_ids),
            "deception_signal_count": len(deception_signals),
        },
        input_ref={"finding": finding_payload},
        # Findings carry no payload that needs sanitization — the
        # hypothesis string is agent-authored, not evidence-authored —
        # but the schema requires both fields as content fingerprints.
        # Use the canonical-encoded finding hash for both.
        pre_sanitization_sha256=finding_hash,
        post_sanitization_sha256=finding_hash,
        rowcount=len(evaluation.audit_ids),
    )

    return Finding(
        audit_id=entry.audit_id,
        case_id=evaluation.case_id,
        hypothesis=evaluation.hypothesis,
        tier=evaluation.tier,
        audit_ids=evaluation.audit_ids,
        families=evaluation.families,
        n_distinct_families=evaluation.n_distinct_families,
        confirmation_basis=evaluation.confirmation_basis,
        reason_codes=evaluation.reason_codes,
        demoted_for_tamper=evaluation.demoted_for_tamper,
        c_scale=_CONFIDENCE_TO_C_SCALE[evaluation.tier],
        demoted_for_temporal=evaluation.demoted_for_temporal,
    )


def _read_entries(path: Path, wanted: set[str]) -> dict[str, dict[str, Any]]:
    """Return ``{audit_id: ledger_entry_dict}`` for every wanted audit_id.

    Walks the ledger linearly. The P0-scale ledger is small (one entry per
    tool call); when this becomes a bottleneck it is a candidate for an
    in-memory index rebuilt on startup. Until then, linear scan keeps
    the implementation auditable.
    """
    if not path.exists() or not wanted:
        return {}
    found: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            aid = entry.get("audit_id")
            if aid in wanted:
                found[aid] = entry
                if len(found) == len(wanted):
                    break
    return found


def _sha256_canonical(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()

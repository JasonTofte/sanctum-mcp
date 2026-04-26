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
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sanctum.audit import (
    FindingConfidence,
    LedgerEntry,
    _ledger_path,  # noqa: PLC2701 — intentional package-internal use
    append_entry,
    classify_confidence,
)
from sanctum.deception import DeceptionSignal
from sanctum.families import resolve_family


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
    reason_codes: tuple[str, ...]  # TamperReason values from deception_signals
    demoted_for_tamper: bool


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

    finding_payload: dict[str, Any] = {
        "hypothesis": hypothesis,
        "tier": tier.value,
        "audit_ids": list(deduped_ids),
        "families": families,
        "n_distinct_families": len(families),
        "reason_codes": list(reason_codes),
        "demoted_for_tamper": signal_present,
    }
    finding_hash = _sha256_canonical(finding_payload)

    entry: LedgerEntry = append_entry(
        case_id=case_id,
        tool="claim_finding",
        args={
            "hypothesis": hypothesis,
            "audit_ids": list(deduped_ids),
            "deception_signal_count": len(deception_signals),
        },
        input_ref={"finding": finding_payload},
        # Findings carry no payload that needs sanitization — the
        # hypothesis string is agent-authored, not evidence-authored —
        # but the schema requires both fields as content fingerprints.
        # Use the canonical-encoded finding hash for both.
        pre_sanitization_sha256=finding_hash,
        post_sanitization_sha256=finding_hash,
        rowcount=len(deduped_ids),
    )

    return Finding(
        audit_id=entry.audit_id,
        case_id=case_id,
        hypothesis=hypothesis,
        tier=tier,
        audit_ids=deduped_ids,
        families=tuple(families),
        n_distinct_families=len(families),
        reason_codes=reason_codes,
        demoted_for_tamper=signal_present,
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

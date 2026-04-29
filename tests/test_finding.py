"""Tests for :mod:`sanctum.finding` — the family-corroboration gate.

Covers the three dimensions of the gate:

1. **Family count** — same-family audit_ids collapse; ≥2 distinct families
   promotes to CORROBORATED; ≥3 to FINAL.
2. **Deception demotion** — a non-empty ``deception_signals`` argument
   demotes one tier, with ``DRAFT_TAMPER_SUSPECTED`` as the floor.
3. **Refusal contracts** — empty audit_ids, missing ledger entries, and
   unknown tool names all raise :class:`ClaimFindingError` rather than
   silently producing a finding.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from sanctum import audit
from sanctum.deception import DeceptionSignal, TamperReason
from sanctum.families import FAMILY_APPCOMPAT
from sanctum.finding import ClaimFindingError, claim_finding


@pytest.fixture
def ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv(audit.LEDGER_ENV, str(path))
    monkeypatch.setenv(audit.HMAC_KEY_ENV, secrets.token_hex(32))
    return path


def _record(tool: str, case_id: str = "case-1") -> str:
    """Append a fake get_* entry and return its audit_id."""
    entry = audit.append_entry(
        case_id=case_id,
        tool=tool,
        args={"case_id": case_id},
        input_ref={"path": f"/cases/{case_id}/{tool}", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=1,
    )
    return entry.audit_id


# ─── family count → tier ─────────────────────────────────────────────────────


def test_single_family_returns_draft(ledger: Path) -> None:
    aid = _record("get_amcache")
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=[aid])
    assert f.tier is audit.FindingConfidence.DRAFT
    assert f.n_distinct_families == 1
    assert f.families == (FAMILY_APPCOMPAT,)
    assert f.c_scale == "C2"


def test_two_families_returns_corroborated(ledger: Path) -> None:
    aids = [_record("get_amcache"), _record("get_prefetch")]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.tier is audit.FindingConfidence.CORROBORATED
    assert f.n_distinct_families == 2
    assert f.c_scale == "C4"


def test_three_families_returns_final(ledger: Path) -> None:
    aids = [
        _record("get_amcache"),
        _record("get_prefetch"),
        _record("get_userassist"),
    ]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.tier is audit.FindingConfidence.FINAL
    assert f.n_distinct_families == 3
    assert f.c_scale == "C5"


def test_same_family_collapses(ledger: Path) -> None:
    """get_amcache + get_shimcache are both AppCompat — single-family claim."""
    aids = [_record("get_amcache"), _record("get_shimcache")]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.tier is audit.FindingConfidence.DRAFT
    assert f.n_distinct_families == 1


def test_duplicate_audit_ids_collapse(ledger: Path) -> None:
    aid = _record("get_amcache")
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=[aid, aid, aid])
    assert f.audit_ids == (aid,)
    assert f.n_distinct_families == 1


# ─── confirmation_basis (v1 emits two of four reserved values) ───────────────


def test_single_family_basis_is_single_family(ledger: Path) -> None:
    """One family voting → ``single_family`` basis, regardless of how many
    same-family audit_ids are stacked."""
    aid = _record("get_amcache")
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=[aid])
    assert f.confirmation_basis == "single_family"


def test_two_families_basis_is_independent_artifacts(ledger: Path) -> None:
    """Two distinct families → ``independent_artifacts``. The five v1
    families are trust-root-disjoint by construction (see
    docs/THREAT_MODEL_TRIANGULATION.md §"Family coupling")."""
    aids = [_record("get_amcache"), _record("get_prefetch")]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.confirmation_basis == "independent_artifacts"


def test_three_families_basis_is_independent_artifacts(ledger: Path) -> None:
    """≥2 families is the threshold; a third doesn't change the basis."""
    aids = [
        _record("get_amcache"),
        _record("get_prefetch"),
        _record("get_userassist"),
    ]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.confirmation_basis == "independent_artifacts"


def test_same_family_collapse_keeps_basis_single_family(ledger: Path) -> None:
    """Two AppCompat audit_ids still count as one family — and so the
    basis stays ``single_family`` even though two get_* calls voted."""
    aids = [_record("get_amcache"), _record("get_shimcache")]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.confirmation_basis == "single_family"


# ─── deception-signal demotion ───────────────────────────────────────────────


def _signal() -> DeceptionSignal:
    return DeceptionSignal(
        reason=TamperReason.TAMPER_LIKELY_SYSMAIN_DISABLED,
        family="SysMain",
        audit_ids=("dummy",),
        rationale="test",
    )


def test_deception_signal_demotes_final_to_corroborated(ledger: Path) -> None:
    aids = [
        _record("get_amcache"),
        _record("get_prefetch"),
        _record("get_userassist"),
    ]
    f = claim_finding(
        case_id="case-1",
        hypothesis="X ran",
        audit_ids=aids,
        deception_signals=[_signal()],
    )
    assert f.tier is audit.FindingConfidence.CORROBORATED
    assert f.demoted_for_tamper is True
    assert f.reason_codes == (TamperReason.TAMPER_LIKELY_SYSMAIN_DISABLED.value,)
    assert f.c_scale == "C4"


def test_deception_signal_demotes_corroborated_to_draft(ledger: Path) -> None:
    aids = [_record("get_amcache"), _record("get_prefetch")]
    f = claim_finding(
        case_id="case-1",
        hypothesis="X ran",
        audit_ids=aids,
        deception_signals=[_signal()],
    )
    assert f.tier is audit.FindingConfidence.DRAFT
    assert f.c_scale == "C2"


def test_deception_signal_demotes_draft_to_tamper_suspected(ledger: Path) -> None:
    aid = _record("get_amcache")
    f = claim_finding(
        case_id="case-1",
        hypothesis="X ran",
        audit_ids=[aid],
        deception_signals=[_signal()],
    )
    assert f.tier is audit.FindingConfidence.DRAFT_TAMPER_SUSPECTED
    assert f.c_scale == "C0"


def test_multiple_deception_signals_demote_only_one_tier(ledger: Path) -> None:
    """Demotion is binary in signal count by design — see
    docs/THREAT_MODEL_DECEPTION.md. A second signal in the same case is
    not independent evidence; treating it as such would correlation-
    double-count."""
    aids = [
        _record("get_amcache"),
        _record("get_prefetch"),
        _record("get_userassist"),
    ]
    f = claim_finding(
        case_id="case-1",
        hypothesis="X ran",
        audit_ids=aids,
        deception_signals=[_signal(), _signal(), _signal()],
    )
    assert f.tier is audit.FindingConfidence.CORROBORATED  # one tier down, not three


# ─── refusal contracts ───────────────────────────────────────────────────────


def test_empty_audit_ids_refused(ledger: Path) -> None:
    with pytest.raises(ClaimFindingError, match="empty"):
        claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=[])


def test_missing_audit_id_refused(ledger: Path) -> None:
    """Agent fabricating an audit_id is the prompt-injection-driven attack
    most directly defeated by this gate. Refuse, do not silently route
    past it."""
    real = _record("get_amcache")
    with pytest.raises(ClaimFindingError, match="not found in ledger"):
        claim_finding(
            case_id="case-1",
            hypothesis="X ran",
            audit_ids=[real, "00000000-0000-0000-0000-000000000000"],
        )


def test_unknown_tool_in_referenced_entry_refused(
    ledger: Path,
) -> None:
    """Recorded entry whose tool isn't in TOOL_TO_FAMILY surfaces as
    UnknownToolError — refuse rather than silent-default to a sentinel
    family. Caught here for the demo flow's sake (the test asserts the
    raised type)."""
    from sanctum.families import UnknownToolError

    fake_aid = audit.append_entry(
        case_id="case-1",
        tool="get_unmapped_tool",
        args={"case_id": "case-1"},
        input_ref={"path": "/x", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=1,
    ).audit_id
    with pytest.raises(UnknownToolError):
        claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=[fake_aid])


# ─── ledger integration ──────────────────────────────────────────────────────


def test_finding_appends_a_ledger_entry_and_extends_chain(ledger: Path) -> None:
    aids = [_record("get_amcache"), _record("get_prefetch")]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    # Position 2 of verify_chain's return is "first_bad_line_1based" (None on
    # clean), not a line count, after the AC-4/AC-10 contract change. The
    # 2-get + 1-claim count is now asserted via direct file read below.
    ok, first_bad, bad = audit.verify_chain(ledger)
    assert ok is True
    assert bad is None
    assert first_bad is None
    with ledger.open("r", encoding="utf-8") as fh:
        lines = [line for line in fh if line.strip()]
    assert len(lines) == 3, "2 get_* entries + 1 claim_finding entry"
    last_entry_audit_id = __import__("json").loads(lines[-1])["audit_id"]
    assert last_entry_audit_id == f.audit_id


def test_finding_ledger_entry_has_finding_metadata(ledger: Path) -> None:
    """Per the design: claim_finding entries pack the finding payload
    into ``input_ref.finding`` and set ``tool="claim_finding"``."""
    aids = [_record("get_amcache"), _record("get_prefetch")]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    with ledger.open("r", encoding="utf-8") as fh:
        lines = [line for line in fh if line.strip()]
    entry = __import__("json").loads(lines[-1])
    assert entry["tool"] == "claim_finding"
    assert entry["input_ref"]["finding"]["hypothesis"] == "X ran"
    assert entry["input_ref"]["finding"]["tier"] == f.tier.value
    assert entry["input_ref"]["finding"]["n_distinct_families"] == 2
    # confirmation_basis is recorded in the ledger payload, not just the
    # in-memory Finding — so a downstream verifier walking the ledger
    # sees what kind of corroboration was claimed.
    assert entry["input_ref"]["finding"]["confirmation_basis"] == "independent_artifacts"
    assert entry["input_ref"]["finding"]["c_scale"] == f.c_scale


def test_draft_findings_still_appear_in_ledger(ledger: Path) -> None:
    """The audit trail records every claim attempt — promoting from DRAFT
    later is a *new* entry, not a mutation of an old one."""
    aid = _record("get_amcache")
    f1 = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=[aid])
    aid2 = _record("get_prefetch")
    f2 = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=[aid, aid2])
    assert f1.tier is audit.FindingConfidence.DRAFT
    assert f2.tier is audit.FindingConfidence.CORROBORATED
    assert f1.audit_id != f2.audit_id


# ─── Casey C-Scale mapping (AC-4, AC-5) ──────────────────────────────────────


def test_draft_tamper_suspected_maps_to_c0(ledger: Path) -> None:
    """DRAFT_TAMPER_SUSPECTED tier → C0 (no evidentiary value; Casey 2011 §3rd ed.)."""
    aid = _record("get_amcache")
    f = claim_finding(
        case_id="case-1",
        hypothesis="X ran",
        audit_ids=[aid],
        deception_signals=[_signal()],
    )
    assert f.tier is audit.FindingConfidence.DRAFT_TAMPER_SUSPECTED
    assert f.c_scale == "C0"


def test_draft_maps_to_c2(ledger: Path) -> None:
    """DRAFT tier (single family) → C2 (unconfirmed; Casey 2011 §3rd ed.)."""
    aid = _record("get_amcache")
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=[aid])
    assert f.tier is audit.FindingConfidence.DRAFT
    assert f.c_scale == "C2"


def test_corroborated_maps_to_c4(ledger: Path) -> None:
    """CORROBORATED tier (≥2 families) → C4 (corroborated; Casey 2011 §3rd ed.)."""
    aids = [_record("get_amcache"), _record("get_prefetch")]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.tier is audit.FindingConfidence.CORROBORATED
    assert f.c_scale == "C4"


def test_final_maps_to_c5(ledger: Path) -> None:
    """FINAL tier (≥3 families) → C5 (beyond reasonable doubt; Casey 2011 §3rd ed.)."""
    aids = [
        _record("get_amcache"),
        _record("get_prefetch"),
        _record("get_userassist"),
    ]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.tier is audit.FindingConfidence.FINAL
    assert f.c_scale == "C5"

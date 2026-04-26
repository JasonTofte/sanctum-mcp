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


def test_two_families_returns_corroborated(ledger: Path) -> None:
    aids = [_record("get_amcache"), _record("get_prefetch")]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.tier is audit.FindingConfidence.CORROBORATED
    assert f.n_distinct_families == 2


def test_three_families_returns_final(ledger: Path) -> None:
    aids = [
        _record("get_amcache"),
        _record("get_prefetch"),
        _record("get_userassist"),
    ]
    f = claim_finding(case_id="case-1", hypothesis="X ran", audit_ids=aids)
    assert f.tier is audit.FindingConfidence.FINAL
    assert f.n_distinct_families == 3


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


def test_deception_signal_demotes_corroborated_to_draft(ledger: Path) -> None:
    aids = [_record("get_amcache"), _record("get_prefetch")]
    f = claim_finding(
        case_id="case-1",
        hypothesis="X ran",
        audit_ids=aids,
        deception_signals=[_signal()],
    )
    assert f.tier is audit.FindingConfidence.DRAFT


def test_deception_signal_demotes_draft_to_tamper_suspected(ledger: Path) -> None:
    aid = _record("get_amcache")
    f = claim_finding(
        case_id="case-1",
        hypothesis="X ran",
        audit_ids=[aid],
        deception_signals=[_signal()],
    )
    assert f.tier is audit.FindingConfidence.DRAFT_TAMPER_SUSPECTED


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
    ok, n, bad = audit.verify_chain(ledger)
    assert ok is True
    assert bad is None
    # 2 get_* entries + 1 claim_finding entry
    assert n == 3
    # The Finding's audit_id is the ledger entry it wrote
    with ledger.open("r", encoding="utf-8") as fh:
        lines = [line for line in fh if line.strip()]
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

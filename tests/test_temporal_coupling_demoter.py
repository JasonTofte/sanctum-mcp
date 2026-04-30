"""Phase 5 — AC-1, AC-2, AC-4, AC-6, AC-8: temporal-coupling demoter.

T-1   _check_temporal_coherence returns "coherent" within window          [P0]
T-2   evaluate_claim preserves CORROBORATED when within window            [P0]
T-3   evaluate_claim demotes CORROBORATED→DRAFT when outside window       [P0]
T-4   _check_temporal_coherence returns "incoherent" outside window       [P1]
T-5   FINAL (3 families) + incoherent → CORROBORATED                     [P1]
T-6   boundary: ts delta == window → "coherent" (inclusive)               [P1]
T-8   SANCTUM_TEMPORAL_COUPLING_WINDOW_SECONDS=30 overrides default       [P0]
T-9   unset env var → 5.0s default                                        [P0]
T-14  insufficient_data when all timestamps None                          [P0]
T-15  insufficient_data when only 1 family has a timestamp                [P0]
T-16  regression: no first_event_ts in entries → no demotion              [P0]

Run with: pytest tests/test_temporal_coupling_demoter.py -v
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sanctum import audit
from sanctum.finding import (
    FindingConfidence,
    _check_temporal_coherence,
    evaluate_claim,
)

# ─── helpers ─────────────────────────────────────────────────────────────────


def _iso(unix_ts: float) -> str:
    """Convert a Unix timestamp (float seconds) to an ISO-8601 UTC string."""
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_ledger_entry(
    ledger_path: Path,
    *,
    case_id: str,
    tool: str,
    first_event_ts: str | None = None,
    last_event_ts: str | None = None,
) -> str:
    """Write one ledger entry and return its audit_id."""
    entry = audit.append_entry(
        case_id=case_id,
        tool=tool,
        args={"case_id": case_id},
        input_ref=None,
        pre_sanitization_sha256="a" * 64,
        post_sanitization_sha256="b" * 64,
        rowcount=1,
        first_event_ts=first_event_ts,
        last_event_ts=last_event_ts,
    )
    return entry.audit_id


# ─── T-1: _check_temporal_coherence coherent path ────────────────────────────


def test_check_temporal_coherence_returns_coherent_within_window() -> None:
    """T-1 (P0): two families 3s apart with 5s window → coherent."""
    base = 1700000000.0
    result = _check_temporal_coherence(
        {"AppCompat": _iso(base), "Prefetch": _iso(base + 3.0)},
        window_seconds=5.0,
    )
    assert result == "coherent"


def test_check_temporal_coherence_returns_coherent_exact_boundary() -> None:
    """T-6 (P1): ts delta == window exactly → coherent (inclusive boundary)."""
    base = 1700000000.0
    result = _check_temporal_coherence(
        {"AppCompat": _iso(base), "Prefetch": _iso(base + 5.0)},
        window_seconds=5.0,
    )
    assert result == "coherent"


# ─── T-4: _check_temporal_coherence incoherent path ─────────────────────────


def test_check_temporal_coherence_returns_incoherent_outside_window() -> None:
    """T-4 (P1): two families 1 hour apart with 5s window → incoherent."""
    base = 1700000000.0
    result = _check_temporal_coherence(
        {"AppCompat": _iso(base), "Prefetch": _iso(base + 3600.0)},
        window_seconds=5.0,
    )
    assert result == "incoherent"


# ─── T-14, T-15: insufficient_data ───────────────────────────────────────────


def test_check_temporal_coherence_insufficient_data_all_none() -> None:
    """T-14 (P0): all timestamps None → insufficient_data (no demotion)."""
    result = _check_temporal_coherence(
        {"AppCompat": None, "Prefetch": None},
        window_seconds=5.0,
    )
    assert result == "insufficient_data"


def test_check_temporal_coherence_insufficient_data_one_family() -> None:
    """T-15 (P0): only 1 family has timestamp → insufficient_data."""
    base = 1700000000.0
    result = _check_temporal_coherence(
        {"AppCompat": _iso(base), "Prefetch": None},
        window_seconds=5.0,
    )
    assert result == "insufficient_data"


def test_check_temporal_coherence_insufficient_data_single_family() -> None:
    """T-15 variant: single family → insufficient_data (need ≥2 to compare)."""
    result = _check_temporal_coherence(
        {"AppCompat": "2024-01-15T10:30:00Z"},
        window_seconds=5.0,
    )
    assert result == "insufficient_data"


# ─── T-2, T-3: evaluate_claim integration ────────────────────────────────────


@pytest.fixture()
def ledger_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set up a minimal ledger environment and return the ledger path."""
    ledger_path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(ledger_path))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", secrets.token_hex(32))
    monkeypatch.delenv("SANCTUM_TEMPORAL_COUPLING_WINDOW_SECONDS", raising=False)
    return ledger_path


def test_evaluate_claim_preserves_corroborated_within_window(
    ledger_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-2 (P0): two families, timestamps 3s apart → CORROBORATED preserved."""
    base = 1700000000.0
    aid1 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_amcache",
        first_event_ts=_iso(base), last_event_ts=_iso(base + 1.0),
    )
    aid2 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_prefetch",
        first_event_ts=_iso(base + 3.0), last_event_ts=_iso(base + 4.0),
    )

    result = evaluate_claim(
        case_id="c1",
        hypothesis="notepad.exe executed at T",
        audit_ids=[aid1, aid2],
    )

    assert result.tier == FindingConfidence.CORROBORATED
    assert result.demoted_for_temporal is False


def test_evaluate_claim_demotes_corroborated_outside_window(
    ledger_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-3 (P0): two families, 1-hour timestamp gap → DRAFT, demoted_for_temporal=True."""
    base = 1700000000.0
    aid1 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_amcache",
        first_event_ts=_iso(base), last_event_ts=_iso(base + 1.0),
    )
    aid2 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_prefetch",
        first_event_ts=_iso(base + 3600.0), last_event_ts=_iso(base + 3601.0),
    )

    result = evaluate_claim(
        case_id="c1",
        hypothesis="notepad.exe executed at T",
        audit_ids=[aid1, aid2],
    )

    assert result.tier == FindingConfidence.DRAFT
    assert result.demoted_for_temporal is True


def test_evaluate_claim_final_demotes_to_corroborated_outside_window(
    ledger_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-5 (P1): three families, timestamp spread > window → FINAL demotes to CORROBORATED."""
    base = 1700000000.0
    aid1 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_amcache",
        first_event_ts=_iso(base),
    )
    aid2 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_prefetch",
        first_event_ts=_iso(base + 3600.0),
    )
    aid3 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_bam",
        first_event_ts=_iso(base + 2.0),
    )

    result = evaluate_claim(
        case_id="c1",
        hypothesis="hypothesis requiring 3 families",
        audit_ids=[aid1, aid2, aid3],
    )

    assert result.tier == FindingConfidence.CORROBORATED
    assert result.demoted_for_temporal is True


# ─── T-8, T-9: env var configuration ─────────────────────────────────────────


def test_evaluate_claim_uses_configured_window(
    ledger_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-8 (P0): SANCTUM_TEMPORAL_COUPLING_WINDOW_SECONDS=30 → 25s delta is coherent."""
    monkeypatch.setenv("SANCTUM_TEMPORAL_COUPLING_WINDOW_SECONDS", "30")
    base = 1700000000.0
    aid1 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_amcache",
        first_event_ts=_iso(base),
    )
    aid2 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_prefetch",
        first_event_ts=_iso(base + 25.0),
    )

    result = evaluate_claim(
        case_id="c1",
        hypothesis="test",
        audit_ids=[aid1, aid2],
    )

    assert result.tier == FindingConfidence.CORROBORATED
    assert result.demoted_for_temporal is False


def test_evaluate_claim_default_window_5s(
    ledger_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-9 (P0): env var unset → 5s default; 10s delta demotes."""
    monkeypatch.delenv("SANCTUM_TEMPORAL_COUPLING_WINDOW_SECONDS", raising=False)
    base = 1700000000.0
    aid1 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_amcache",
        first_event_ts=_iso(base),
    )
    aid2 = _write_ledger_entry(
        ledger_env, case_id="c1", tool="get_prefetch",
        first_event_ts=_iso(base + 10.0),
    )

    result = evaluate_claim(
        case_id="c1",
        hypothesis="test",
        audit_ids=[aid1, aid2],
    )

    assert result.tier == FindingConfidence.DRAFT
    assert result.demoted_for_temporal is True


# ─── T-16: AC-8 regression — no first_event_ts in entries ────────────────────


def test_evaluate_claim_no_demotion_without_event_timestamps(
    ledger_env: Path,
) -> None:
    """T-16 (P0): entries without first_event_ts → insufficient_data → no demotion."""
    aid1 = _write_ledger_entry(ledger_env, case_id="c1", tool="get_amcache")
    aid2 = _write_ledger_entry(ledger_env, case_id="c1", tool="get_prefetch")

    result = evaluate_claim(
        case_id="c1",
        hypothesis="existing behavior unaffected",
        audit_ids=[aid1, aid2],
    )

    assert result.tier == FindingConfidence.CORROBORATED
    assert result.demoted_for_temporal is False


# ─── T-AC6: AC-6 demo fixture — end-to-end timestomp detection ───────────────

_DEMO_FIXTURE = Path("tests/fixtures/timestomp_injection_demo")


def test_timestomp_demo_fixture_demotes_to_draft(
    ledger_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-6 (P1): timestomp demo fixture triggers demotion end-to-end.

    Scenario (MITRE ATT&CK T1070.006 — Timestomp):
    - Amcache records C:\\Temp\\malware.exe at T = 2024-01-15T10:30 UTC (real).
    - Prefetch last-run was FORGED to T+3600 = 2024-01-15T11:30 UTC.
    - Cross-family spread = 3600 s >> 5 s default window.
    - Gate should demote CORROBORATED → DRAFT, demoted_for_temporal=True.

    Exercises the full path: fixture parser → timestamp extraction → ledger →
    evaluate_claim temporal demoter.
    """
    from sanctum.parsers.amcache import parse_amcache
    from sanctum.parsers.prefetch import parse_prefetch

    monkeypatch.setenv("SANCTUM_USE_FIXTURE_SIDECAR", "1")
    monkeypatch.delenv("SANCTUM_TEMPORAL_COUPLING_WINDOW_SECONDS", raising=False)

    amcache_path = _DEMO_FIXTURE / "cases/demo/registry/Amcache.hve"
    prefetch_path = _DEMO_FIXTURE / "cases/demo/Prefetch/MALWARE.EXE-AABBCCDD.pf"

    amcache_events = parse_amcache(amcache_path)
    prefetch_events = parse_prefetch(prefetch_path)

    assert amcache_events, "demo fixture: Amcache sidecar must have at least one event"
    assert prefetch_events, "demo fixture: Prefetch sidecar must have at least one event"

    # Mirror _emit_offloaded_response's extraction: min(timestamp) per family.
    amcache_first_ts = min(e.timestamp.isoformat() for e in amcache_events)
    prefetch_first_ts = min(e.timestamp.isoformat() for e in prefetch_events)

    aid1 = _write_ledger_entry(
        ledger_env, case_id="demo", tool="get_amcache",
        first_event_ts=amcache_first_ts,
    )
    aid2 = _write_ledger_entry(
        ledger_env, case_id="demo", tool="get_prefetch",
        first_event_ts=prefetch_first_ts,
    )

    result = evaluate_claim(
        case_id="demo",
        hypothesis="C:\\Temp\\malware.exe executed — Amcache+Prefetch corroboration with forged Prefetch timestamp",
        audit_ids=[aid1, aid2],
    )

    assert result.tier == FindingConfidence.DRAFT, (
        f"Expected DRAFT (timestomp demotion), got {result.tier}. "
        f"Amcache ts={amcache_first_ts}, Prefetch ts={prefetch_first_ts}"
    )
    assert result.demoted_for_temporal is True

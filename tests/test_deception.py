"""Tests for :mod:`sanctum.deception` — anti-forensic signature detection.

The contract enforced here:

1. Positive signature → ``TAMPER_LIKELY_*`` reason code.
2. Operator-plausible confounder → ``AMBIGUOUS_*`` reason code (NOT a
   downgrade to ``None`` — analysts need the ambiguity surfaced).
3. Absence of signature → ``None`` (fail-closed asymmetry: never positive
   without explicit evidence).
4. Returned ``DeceptionSignal`` is frozen and carries the audit_ids the
   caller passed in (so ``claim_finding`` can re-resolve provenance).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from sanctum.deception import (
    DeceptionSignal,
    TamperReason,
    check_appcompat_flush,
    check_mft_timestomp,
    check_sysmain_suppression,
)

UTC = timezone.utc


# ─── check_appcompat_flush ──────────────────────────────────────────────────


def test_appcompat_flush_fires_on_empty_shimcache_with_recent_hive_write() -> None:
    acquired = datetime(2026, 4, 25, 12, 0, 0, tzinfo=UTC)
    signal = check_appcompat_flush(
        shimcache_rowcount=0,
        system_hive_last_write_utc=acquired - timedelta(minutes=10),
        image_acquisition_utc=acquired,
        audit_ids=("a1",),
    )
    assert signal is not None
    assert signal.reason is TamperReason.TAMPER_LIKELY_BASEFLUSHAPPCOMPATCACHE
    assert signal.family == "AppCompat"
    assert signal.audit_ids == ("a1",)


def test_appcompat_flush_returns_none_when_shimcache_populated() -> None:
    acquired = datetime(2026, 4, 25, 12, 0, 0, tzinfo=UTC)
    signal = check_appcompat_flush(
        shimcache_rowcount=42,
        system_hive_last_write_utc=acquired - timedelta(minutes=10),
        image_acquisition_utc=acquired,
        audit_ids=("a1",),
    )
    assert signal is None


def test_appcompat_flush_returns_none_when_hive_write_too_old() -> None:
    acquired = datetime(2026, 4, 25, 12, 0, 0, tzinfo=UTC)
    signal = check_appcompat_flush(
        shimcache_rowcount=0,
        system_hive_last_write_utc=acquired - timedelta(days=30),
        image_acquisition_utc=acquired,
        audit_ids=("a1",),
    )
    assert signal is None


def test_appcompat_flush_returns_none_on_negative_delta_clock_skew() -> None:
    """Hive write timestamp in the future of acquisition — clock skew, not an attacker."""
    acquired = datetime(2026, 4, 25, 12, 0, 0, tzinfo=UTC)
    signal = check_appcompat_flush(
        shimcache_rowcount=0,
        system_hive_last_write_utc=acquired + timedelta(minutes=5),
        image_acquisition_utc=acquired,
        audit_ids=("a1",),
    )
    assert signal is None


def test_appcompat_flush_emits_ambiguous_on_graceful_shutdown_pattern() -> None:
    """Hive write within 1s of acquisition matches the graceful-shutdown-then-snapshot
    operator pattern — surface the ambiguity rather than asserting tamper."""
    acquired = datetime(2026, 4, 25, 12, 0, 0, tzinfo=UTC)
    signal = check_appcompat_flush(
        shimcache_rowcount=0,
        system_hive_last_write_utc=acquired - timedelta(milliseconds=500),
        image_acquisition_utc=acquired,
        audit_ids=("a1",),
    )
    assert signal is not None
    assert signal.reason is TamperReason.AMBIGUOUS_LEGITIMATE_FLUSH_CONSISTENT


# ─── check_sysmain_suppression ──────────────────────────────────────────────


def test_sysmain_suppression_fires_when_disabled_with_amcache_no_prefetch() -> None:
    signal = check_sysmain_suppression(
        amcache_rowcount=20,
        prefetch_filecount=0,
        sysmain_service_state="Disabled",
        audit_ids=("a1", "a2"),
    )
    assert signal is not None
    assert signal.reason is TamperReason.TAMPER_LIKELY_SYSMAIN_DISABLED
    assert signal.family == "SysMain"
    assert signal.audit_ids == ("a1", "a2")


def test_sysmain_suppression_returns_none_when_prefetch_populated() -> None:
    signal = check_sysmain_suppression(
        amcache_rowcount=20,
        prefetch_filecount=137,
        sysmain_service_state="Disabled",
        audit_ids=("a1",),
    )
    assert signal is None


def test_sysmain_suppression_returns_none_when_service_running() -> None:
    signal = check_sysmain_suppression(
        amcache_rowcount=20,
        prefetch_filecount=0,
        sysmain_service_state="Running",
        audit_ids=("a1",),
    )
    assert signal is None


def test_sysmain_suppression_returns_none_below_amcache_significance_threshold() -> None:
    signal = check_sysmain_suppression(
        amcache_rowcount=2,
        prefetch_filecount=0,
        sysmain_service_state="Disabled",
        audit_ids=("a1",),
    )
    assert signal is None


def test_sysmain_suppression_emits_ambiguous_when_stopped_not_disabled() -> None:
    """Stopped (vs Disabled) is the operator-plausible case — admin stopped the
    service for perf testing. Surface ambiguity, do not collapse to TAMPER_LIKELY."""
    signal = check_sysmain_suppression(
        amcache_rowcount=20,
        prefetch_filecount=0,
        sysmain_service_state="Stopped",
        audit_ids=("a1",),
    )
    assert signal is not None
    assert signal.reason is TamperReason.AMBIGUOUS_SYSMAIN_DISABLED_OPERATOR_PLAUSIBLE


def test_sysmain_suppression_emits_ambiguous_when_state_unknown() -> None:
    signal = check_sysmain_suppression(
        amcache_rowcount=20,
        prefetch_filecount=0,
        sysmain_service_state="Unknown",
        audit_ids=("a1",),
    )
    assert signal is not None
    assert signal.reason is TamperReason.AMBIGUOUS_SYSMAIN_DISABLED_OPERATOR_PLAUSIBLE


# ─── check_mft_timestomp ────────────────────────────────────────────────────


def test_mft_timestomp_fires_on_si_predating_epoch_threshold() -> None:
    """timestomp.exe sentinel: $SI set to FILETIME epoch (1601-01-01)."""
    signal = check_mft_timestomp(
        si_btime=datetime(1601, 1, 1, tzinfo=UTC),
        fn_btime=datetime(2025, 6, 15, tzinfo=UTC),
        audit_ids=("a1",),
    )
    assert signal is not None
    assert signal.reason is TamperReason.TAMPER_LIKELY_MFT_TIMESTOMP


def test_mft_timestomp_fires_on_si_backdated_more_than_window() -> None:
    """SetMACE-style backdating — $SI rewritten to predate $FN by years."""
    signal = check_mft_timestomp(
        si_btime=datetime(2020, 1, 1, tzinfo=UTC),
        fn_btime=datetime(2025, 6, 15, tzinfo=UTC),
        audit_ids=("a1",),
    )
    assert signal is not None
    assert signal.reason is TamperReason.TAMPER_LIKELY_MFT_TIMESTOMP


def test_mft_timestomp_returns_none_within_backdate_window() -> None:
    """Mid-second write skew between $SI and $FN — legitimate, do not fire."""
    si = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)
    signal = check_mft_timestomp(
        si_btime=si,
        fn_btime=si + timedelta(milliseconds=200),
        audit_ids=("a1",),
    )
    assert signal is None


def test_mft_timestomp_returns_none_when_si_after_fn() -> None:
    """$SI later than $FN is the legitimate steady-state — do not fire."""
    fn = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)
    signal = check_mft_timestomp(
        si_btime=fn + timedelta(days=1),
        fn_btime=fn,
        audit_ids=("a1",),
    )
    assert signal is None


# ─── DeceptionSignal contract ───────────────────────────────────────────────


def test_deception_signal_is_frozen() -> None:
    s = DeceptionSignal(
        reason=TamperReason.TAMPER_LIKELY_MFT_TIMESTOMP,
        family="AppCompat",
        audit_ids=("a1",),
        rationale="x",
    )
    with pytest.raises(FrozenInstanceError):
        s.reason = TamperReason.TAMPER_LIKELY_SYSMAIN_DISABLED  # type: ignore[misc]


def test_tamper_reason_string_values_are_stable() -> None:
    """Reason codes land in the audit ledger — renaming a member is a
    backwards-incompatible ledger-format change. Pin the string values
    so a careless rename trips this test."""
    assert TamperReason.TAMPER_LIKELY_BASEFLUSHAPPCOMPATCACHE.value == (
        "tamper_likely_baseflushappcompatcache"
    )
    assert TamperReason.TAMPER_LIKELY_SYSMAIN_DISABLED.value == "tamper_likely_sysmain_disabled"
    assert TamperReason.TAMPER_LIKELY_MFT_TIMESTOMP.value == "tamper_likely_mft_timestomp"
    assert TamperReason.AMBIGUOUS_LEGITIMATE_FLUSH_CONSISTENT.value == (
        "ambiguous_legitimate_flush_consistent"
    )
    assert TamperReason.AMBIGUOUS_SYSMAIN_DISABLED_OPERATOR_PLAUSIBLE.value == (
        "ambiguous_sysmain_disabled_operator_plausible"
    )

"""Unit tests for the eval_llm_injection SCENARIOS — no API calls required.

These tests verify:
- N4 (cross-row payload split) evades the sanitizer regex (patterns_stripped == 0)
- N5 (NFKC-equivalent delimiter forgery) evades the sanitizer regex
- N6 (AppCompat-collapse bait) evades the sanitizer regex
- All 13 scenarios build without error (smoke)
- q_id uniqueness (no two scenarios share an id)
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

# Allow running from repo root without pip install.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Import lazily so the test file is importable even if anthropic SDK is absent.
_inj = importlib.import_module("scripts.eval_llm_injection")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_scenario(sid: str) -> object:
    matches = [s for s in _inj.SCENARIOS if s.id == sid]
    assert matches, f"Scenario {sid!r} not found in SCENARIOS"
    assert len(matches) == 1, f"Duplicate scenario id {sid!r}"
    return matches[0]


def _sanitizer_stats(scenario: object) -> dict[str, int | str]:
    _wrapped, meta = _inj._build_evidence(scenario)
    return meta


# ---------------------------------------------------------------------------
# Scenario count + id uniqueness
# ---------------------------------------------------------------------------


def test_scenario_count() -> None:
    """SCENARIOS must contain exactly 13 entries (7 state3 + 6 novel)."""
    assert len(_inj.SCENARIOS) == 13, (
        f"Expected 13 scenarios, got {len(_inj.SCENARIOS)}. "
        "Update this count when adding new scenarios."
    )


def test_scenario_ids_unique() -> None:
    """Every Scenario must have a distinct id."""
    ids = [s.id for s in _inj.SCENARIOS]
    dupes = {sid for sid in ids if ids.count(sid) > 1}
    assert not dupes, f"Duplicate scenario id(s): {dupes}"


def test_all_scenarios_build_without_error() -> None:
    """_build_evidence must not raise for any scenario (no API needed)."""
    for s in _inj.SCENARIOS:
        try:
            _inj._build_evidence(s)
        except Exception as exc:
            pytest.fail(f"_build_evidence raised for scenario {s.id!r}: {exc}")


# ---------------------------------------------------------------------------
# N4 — cross-row payload split
# ---------------------------------------------------------------------------


def test_n4_payload_split_has_two_rows() -> None:
    """N4 uses rows_override with exactly 2 rows."""
    s = _get_scenario("N4")
    assert s.rows_override is not None, "N4 must set rows_override"
    assert len(s.rows_override) == 2, f"Expected 2 rows, got {len(s.rows_override)}"


def test_n4_payload_split_evades_regex() -> None:
    """N4: sanitizer must NOT fire (patterns_stripped == 0).

    The injection is split across two rows so no single-row field value
    contains the complete 'ignore all prior instructions' pattern.
    The regex requires ignore...(whitespace)...instructions but JSON
    structural characters break contiguity between rows.
    """
    s = _get_scenario("N4")
    meta = _sanitizer_stats(s)
    assert meta["patterns_stripped"] == 0, (
        f"N4: expected 0 patterns stripped (cross-row split should evade regex), "
        f"got {meta['patterns_stripped']}"
    )


def test_n4_neither_row_alone_triggers_regex() -> None:
    """N4: neither row in isolation triggers the sanitizer."""
    s = _get_scenario("N4")
    import json

    from sanctum.sanitize import sanitize

    for i, row in enumerate(s.rows_override):
        payload = json.dumps({"case_id": "case_eval_001", "rows": [row]}, ensure_ascii=False)
        result = sanitize(payload)
        assert result.patterns_stripped == 0, (
            f"N4 row {i} triggers the regex when processed alone — "
            "the split attack relies on NEITHER row being individually caught"
        )


# ---------------------------------------------------------------------------
# N5 — NFKC-equivalent delimiter forgery
# ---------------------------------------------------------------------------


def test_n5_nfkc_delimiter_forgery_evades_regex() -> None:
    """N5: sanitizer must NOT fire (patterns_stripped == 0).

    Fullwidth lookalike characters (U+FF1C, U+FF0F, U+FF1E) are VISIBLE,
    not invisible — the invisibles-strip pass leaves them intact, and the
    known-pattern list doesn't include NFKC-expanded variants.
    """
    s = _get_scenario("N5")
    meta = _sanitizer_stats(s)
    assert meta["patterns_stripped"] == 0, (
        f"N5: expected 0 patterns stripped (fullwidth chars should evade regex), "
        f"got {meta['patterns_stripped']}"
    )


def test_n5_uses_fullwidth_chars() -> None:
    """N5 injection must contain FULLWIDTH LESS-THAN (U+FF1C) or FULLWIDTH SOLIDUS (U+FF0F)."""
    s = _get_scenario("N5")
    assert "＜" in s.injection or "／" in s.injection, (
        "N5 injection must contain fullwidth lookalike characters"
    )


# ---------------------------------------------------------------------------
# N6 — AppCompat-collapse bait
# ---------------------------------------------------------------------------


def test_n6_appcompat_collapse_bait_evades_regex() -> None:
    """N6: sanitizer must NOT fire (patterns_stripped == 0).

    AppCompat-collapse bait is pure semantic deception — no regex-catchable
    frame. The injection claims ShimCache + Amcache = two families (false).
    """
    s = _get_scenario("N6")
    meta = _sanitizer_stats(s)
    assert meta["patterns_stripped"] == 0, (
        f"N6: expected 0 patterns stripped (semantic injection should evade regex), "
        f"got {meta['patterns_stripped']}"
    )


def test_n6_mentions_shimcache_and_amcache() -> None:
    """N6 injection must reference both ShimCache and Amcache (the false-family claim)."""
    s = _get_scenario("N6")
    lower = s.injection.lower()
    assert "shimcache" in lower, "N6 must reference ShimCache"
    assert "amcache" in lower, "N6 must reference Amcache"


# ---------------------------------------------------------------------------
# Novel scenario count
# ---------------------------------------------------------------------------


def test_novel_scenario_count() -> None:
    """Exactly 6 novel scenarios (N1..N6) must be present."""
    novel = [s for s in _inj.SCENARIOS if s.novel]
    assert len(novel) == 6, (
        f"Expected 6 novel scenarios, got {len(novel)}: {[s.id for s in novel]}"
    )

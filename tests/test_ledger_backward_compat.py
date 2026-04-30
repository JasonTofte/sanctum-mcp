"""Phase 3 — AC-8: pre-async ledgers must verify with post-async verify_chain.

These tests prove that the async migration does NOT change the JSONL ledger
format.  A ledger written by the pre-migration sync append_entry must be
verifiable by the (unchanged) verify_chain after migration.

The tests use:
1. Hardcoded JSONL strings representing pre-migration ledger content.
2. Entries written with the current append_entry (which becomes async in
   Phase 3 GREEN), then verified immediately — regression guard that the
   HMAC chain logic is unaltered by the coroutine wrapper.

These tests should be GREEN before AND after migration (they are regression
guards, not RED tests — the format compatibility invariant is already true
and must remain true).
"""

from __future__ import annotations

import json
import secrets
import tempfile
from pathlib import Path

import pytest

from sanctum import audit


# ─── helpers ─────────────────────────────────────────────────────────────────


def _mint_key() -> tuple[bytes, str]:
    """Return (key_bytes, hex_string) for a fresh random HMAC key."""
    hex_key = secrets.token_hex(32)
    return bytes.fromhex(hex_key), hex_key


def _build_entry(
    *,
    prev_hash: str,
    case_id: str = "test-case",
    tool: str = "get_amcache",
    key: bytes,
) -> dict:
    """Construct a minimal but valid ledger entry dict."""
    raw: dict = {
        "audit_id": "00000000-0000-0000-0000-000000000001",
        "ts": "2026-04-29T00:00:00Z",
        "case_id": case_id,
        "tool": tool,
        "args_hash": "a" * 64,
        "input_ref": None,
        "pre_sanitization_sha256": "b" * 64,
        "post_sanitization_sha256": "c" * 64,
        "rowcount": 1,
        "prev_hash": prev_hash,
    }
    raw["line_hash"] = audit._line_hash_for(raw, key=key)
    return raw


# ─── AC-8: pre-async ledger format compatibility ──────────────────────────────


def test_verify_chain_accepts_pre_async_format_single_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A single-entry ledger in pre-async JSONL format verifies without error.

    The entry has no payload_ref, no elapsed_ms, no token_estimate — all
    the omit-not-null optional fields that were added incrementally.
    verify_chain must handle their absence (they would have been absent in
    ledgers written before each feature landed).
    """
    key_bytes, hex_key = _mint_key()
    monkeypatch.setenv(audit.HMAC_KEY_ENV, hex_key)

    ledger = tmp_path / "ledger.jsonl"
    entry = _build_entry(prev_hash=audit._GENESIS_PREV, key=key_bytes)
    ledger.write_text(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    ok, bad_line, bad_id = audit.verify_chain(ledger)
    assert ok is True
    assert bad_line is None
    assert bad_id is None


def test_verify_chain_accepts_pre_async_format_chain_of_three(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Three-entry pre-async chain verifies — tests prev_hash linking."""
    key_bytes, hex_key = _mint_key()
    monkeypatch.setenv(audit.HMAC_KEY_ENV, hex_key)

    ledger = tmp_path / "ledger.jsonl"
    lines: list[str] = []
    prev = audit._GENESIS_PREV
    for i in range(3):
        e = _build_entry(prev_hash=prev, case_id=f"case-{i}", key=key_bytes)
        e["audit_id"] = f"00000000-0000-0000-0000-00000000000{i + 1}"
        e["line_hash"] = audit._line_hash_for(e, key=key_bytes)
        lines.append(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
        prev = e["line_hash"]
    ledger.write_text("".join(lines))

    ok, bad_line, bad_id = audit.verify_chain(ledger)
    assert ok is True


def test_verify_chain_detects_tampered_pre_async_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Tampered pre-async entry is rejected — chain integrity enforced regardless of format age."""
    key_bytes, hex_key = _mint_key()
    monkeypatch.setenv(audit.HMAC_KEY_ENV, hex_key)

    ledger = tmp_path / "ledger.jsonl"
    entry = _build_entry(prev_hash=audit._GENESIS_PREV, key=key_bytes)
    # Tamper the case_id after signing — would break the HMAC
    entry["case_id"] = "tampered"
    ledger.write_text(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    ok, bad_line, bad_id = audit.verify_chain(ledger)
    assert ok is False
    assert bad_line == 1


def test_empty_ledger_verifies_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Empty ledger (no entries written yet) is a valid clean state."""
    _, hex_key = _mint_key()
    monkeypatch.setenv(audit.HMAC_KEY_ENV, hex_key)

    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("")

    ok, bad_line, bad_id = audit.verify_chain(ledger)
    assert ok is True
    assert bad_line is None


def test_missing_ledger_file_verifies_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Non-existent ledger file returns ok=True (genesis state)."""
    _, hex_key = _mint_key()
    monkeypatch.setenv(audit.HMAC_KEY_ENV, hex_key)

    ok, bad_line, bad_id = audit.verify_chain(tmp_path / "nonexistent.jsonl")
    assert ok is True


# ─── AC-8: mixed pre/post-async entries co-exist in a chain ──────────────────


def test_sync_written_then_verified_chain_survives(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Entries written via the current (sync) append_entry form a verifiable chain.

    After the async migration, append_entry becomes a coroutine but produces
    the same JSONL bytes — this test verifies that the sync-written format
    is a stable baseline, so we can detect any accidental format drift during
    the async conversion.
    """
    _, hex_key = _mint_key()
    ledger_path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv(audit.LEDGER_ENV, str(ledger_path))
    monkeypatch.setenv(audit.HMAC_KEY_ENV, hex_key)

    # Write 3 entries via the current sync code path
    for i in range(3):
        audit.append_entry(
            case_id=f"case-{i}",
            tool="get_amcache",
            args={"case_id": f"case-{i}"},
            input_ref=None,
            pre_sanitization_sha256="a" * 64,
            post_sanitization_sha256="b" * 64,
        )

    ok, bad_line, bad_id = audit.verify_chain(ledger_path)
    assert ok is True, f"Chain invalid at line {bad_line} (audit_id={bad_id})"

    # Confirm 3 entries exist
    lines = [l for l in ledger_path.read_text().splitlines() if l.strip()]
    assert len(lines) == 3

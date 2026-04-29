"""Tests for :mod:`sanctum.audit` — append-only ledger with HMAC-chain verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from pathlib import Path

import pytest

from sanctum import audit


@pytest.fixture
def ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv(audit.LEDGER_ENV, str(path))
    # Every test gets its own fresh HMAC key — verifies key isolation and
    # rules out test-pollution from a cached key.
    monkeypatch.setenv(audit.HMAC_KEY_ENV, secrets.token_hex(32))
    return path


def _append(case_id: str = "case-1", tool: str = "get_amcache") -> audit.LedgerEntry:
    return audit.append_entry(
        case_id=case_id,
        tool=tool,
        args={"case_id": case_id},
        input_ref={"path": "/cases/x/Amcache.hve", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=10,
    )


def test_first_entry_uses_genesis_prev_hash(ledger: Path) -> None:
    e = _append()
    assert e.prev_hash == "0" * 64
    assert Path(ledger).exists()


def test_second_entry_chains_to_first(ledger: Path) -> None:
    e1 = _append()
    e2 = _append()
    assert e2.prev_hash == e1.line_hash


def test_verify_chain_passes_on_clean_ledger(ledger: Path) -> None:
    for _ in range(5):
        _append()
    # Position 2 of the verify_chain return changed from "lines_scanned" to
    # "first_bad_line_1based" as part of the payload_ref forward-compat work
    # (AC-4 + AC-10). On a clean ledger the value is None, not the count.
    ok, first_bad, bad = audit.verify_chain(ledger)
    assert ok is True
    assert first_bad is None
    assert bad is None


def test_verify_chain_catches_tampered_entry(ledger: Path) -> None:
    for _ in range(3):
        _append()
    # Tamper with line 2: change rowcount.
    lines = ledger.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["rowcount"] = 9999
    lines[1] = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, _, bad = audit.verify_chain(ledger)
    assert ok is False
    assert bad == entry["audit_id"]


def test_each_audit_id_is_unique(ledger: Path) -> None:
    ids = {_append().audit_id for _ in range(50)}
    assert len(ids) == 50


def test_missing_hmac_key_refuses_append(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without ``SANCTUM_LEDGER_HMAC_KEY``, append MUST refuse.

    The ledger never silently downgrades to plain SHA-256 — that was the
    prior behaviour and was the biggest inaccuracy in Sanctum's
    architecture docs (README claimed "HMAC-chained" while the code
    computed unsalted SHA-256). Refusing to start is the correct failure
    mode.
    """
    monkeypatch.setenv(audit.LEDGER_ENV, str(tmp_path / "ledger.jsonl"))
    monkeypatch.delenv(audit.HMAC_KEY_ENV, raising=False)
    with pytest.raises(RuntimeError, match="HMAC"):
        audit.append_entry(
            case_id="c",
            tool="t",
            args={},
            input_ref=None,
            pre_sanitization_sha256="a" * 64,
            post_sanitization_sha256="b" * 64,
        )


def test_short_hmac_key_refuses_append(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An HMAC key shorter than 16 bytes MUST be refused.

    128-bit is the NIST-recommended minimum for HMAC-SHA256. A too-short key
    at startup is more likely a misconfiguration (e.g., truncated copy/paste)
    than an intentional choice — refuse loudly.
    """
    monkeypatch.setenv(audit.LEDGER_ENV, str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv(audit.HMAC_KEY_ENV, "deadbeef")  # 4 bytes
    with pytest.raises(RuntimeError, match="at least"):
        audit.append_entry(
            case_id="c",
            tool="t",
            args={},
            input_ref=None,
            pre_sanitization_sha256="a" * 64,
            post_sanitization_sha256="b" * 64,
        )


def test_verify_chain_fails_with_wrong_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Swapping the HMAC key between write and verify MUST break verification.

    This is the property that distinguishes HMAC from plain SHA-256: the
    attacker needs the key, not just disk-write access. A forger who mutates
    the ledger cannot produce a matching line_hash without the key.
    """
    path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv(audit.LEDGER_ENV, str(path))
    monkeypatch.setenv(audit.HMAC_KEY_ENV, secrets.token_hex(32))
    audit.append_entry(
        case_id="c",
        tool="t",
        args={},
        input_ref=None,
        pre_sanitization_sha256="a" * 64,
        post_sanitization_sha256="b" * 64,
    )
    # Swap the key as if an attacker tried to recompute the chain.
    monkeypatch.setenv(audit.HMAC_KEY_ENV, secrets.token_hex(32))
    ok, _, bad = audit.verify_chain(path)
    assert ok is False
    assert bad is not None


def test_args_hash_is_canonical(ledger: Path) -> None:
    e1 = audit.append_entry(
        case_id="c",
        tool="t",
        args={"a": 1, "b": 2},
        input_ref=None,
        pre_sanitization_sha256="x",
        post_sanitization_sha256="y",
    )
    e2 = audit.append_entry(
        case_id="c",
        tool="t",
        args={"b": 2, "a": 1},  # different insertion order, same content
        input_ref=None,
        pre_sanitization_sha256="x",
        post_sanitization_sha256="y",
    )
    assert e1.args_hash == e2.args_hash


# --- FindingConfidence tier classifier ---


def test_classify_confidence_draft_for_zero_and_one() -> None:
    """n <= 1 is DRAFT — single-source or none, hypothesis only."""
    assert audit.classify_confidence(0) == audit.FindingConfidence.DRAFT
    assert audit.classify_confidence(1) == audit.FindingConfidence.DRAFT


def test_classify_confidence_corroborated_at_exactly_two() -> None:
    """n == 2 is CORROBORATED — docs/THREAT_MODEL_TRIANGULATION.md §5."""
    assert audit.classify_confidence(2) == audit.FindingConfidence.CORROBORATED


def test_classify_confidence_final_at_three_and_above() -> None:
    """n >= 3 is FINAL — P(forgery) drops ~7x vs CORROBORATED."""
    assert audit.classify_confidence(3) == audit.FindingConfidence.FINAL
    assert audit.classify_confidence(5) == audit.FindingConfidence.FINAL
    assert audit.classify_confidence(100) == audit.FindingConfidence.FINAL


def test_classify_confidence_negative_raises() -> None:
    """Negative subsystem count is a programmer error, not a tier."""
    with pytest.raises(ValueError, match="must be >= 0"):
        audit.classify_confidence(-1)


def test_finding_confidence_values_are_ledger_stable_strings() -> None:
    """Enum values are ledger-stable — renaming a member is a format change.

    Pinning the exact string values here makes accidental renames fail CI
    before they ship into the append-only ledger.
    """
    assert audit.FindingConfidence.DRAFT.value == "DRAFT"
    assert audit.FindingConfidence.CORROBORATED.value == "CORROBORATED"
    assert audit.FindingConfidence.FINAL.value == "FINAL"
    assert audit.FindingConfidence.DRAFT_TAMPER_SUSPECTED.value == "DRAFT_TAMPER_SUSPECTED"


# --- deception-signal demotion table ---


def test_classify_confidence_no_signal_unchanged() -> None:
    """deception_signal_present=False reproduces the legacy 3-tier mapping."""
    assert (
        audit.classify_confidence(0, deception_signal_present=False)
        == audit.FindingConfidence.DRAFT
    )
    assert (
        audit.classify_confidence(2, deception_signal_present=False)
        == audit.FindingConfidence.CORROBORATED
    )
    assert (
        audit.classify_confidence(3, deception_signal_present=False)
        == audit.FindingConfidence.FINAL
    )


def test_classify_confidence_signal_demotes_final_to_corroborated() -> None:
    assert (
        audit.classify_confidence(3, deception_signal_present=True)
        == audit.FindingConfidence.CORROBORATED
    )
    assert (
        audit.classify_confidence(10, deception_signal_present=True)
        == audit.FindingConfidence.CORROBORATED
    )


def test_classify_confidence_signal_demotes_corroborated_to_draft() -> None:
    assert (
        audit.classify_confidence(2, deception_signal_present=True) == audit.FindingConfidence.DRAFT
    )


def test_classify_confidence_signal_demotes_draft_to_tamper_suspected() -> None:
    assert (
        audit.classify_confidence(1, deception_signal_present=True)
        == audit.FindingConfidence.DRAFT_TAMPER_SUSPECTED
    )
    assert (
        audit.classify_confidence(0, deception_signal_present=True)
        == audit.FindingConfidence.DRAFT_TAMPER_SUSPECTED
    )


# --- payload_ref / audit_id kwargs and verify_chain forward-compat (AC-4, AC-10) ---
#
# These tests pin the contract introduced by the payload-offload reimplementation:
#
#   * ``LedgerEntry`` gains a ``payload_ref: dict | None`` field.
#   * ``append_entry`` gains ``payload_ref=`` and ``audit_id=`` keyword arguments.
#   * ``payload_ref`` is HMAC-covered (mutating it post-write breaks ``verify_chain``).
#   * The canonical JSON shape MUST omit the ``"payload_ref"`` key entirely when the
#     value is None — emitting ``"payload_ref": null`` would break bytewise hash
#     compatibility with pre-feature ledgers (AC-10).
#   * ``verify_chain`` returns ``tuple[bool, int | None, str | None]`` —
#     position 2 is the 1-based line number of the first bad entry, or None on a
#     clean ledger. (Old contract returned a line *count*; existing call-sites
#     have been updated alongside this RED batch.)
#
# A useful mental model: legacy entries are exactly those whose canonical bytes
# never had a ``payload_ref`` field, so re-hashing them post-feature must produce
# the same digest. The forward-compat hazard is "did we accidentally inject
# `null` into the hash input." Test 7 / 8 below pin that explicitly.


_PAYLOAD_REF_SAMPLE = {
    "path": "/var/sanctum/output/case-1/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/get_amcache.json",
    "sha256": "d" * 64,
    "bytes": 4096,
    "format": "application/json",
}


def _legacy_canonical_bytes(entry_without_line_hash: dict) -> bytes:
    """Hash input that pre-feature ledgers used (no ``payload_ref`` field).

    Mirrors :func:`sanctum.audit._line_hash_for`'s serialization on entries
    written before this PR — exact same JSON canonicalization, no
    ``payload_ref`` key in the dict at all.
    """
    return json.dumps(
        entry_without_line_hash,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")


def test_append_entry_accepts_payload_ref_kwarg(ledger: Path) -> None:
    """``append_entry`` MUST accept a ``payload_ref=`` keyword and persist it."""
    entry = audit.append_entry(
        case_id="case-1",
        tool="get_amcache",
        args={"case_id": "case-1"},
        input_ref={"path": "/cases/x/Amcache.hve", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=10,
        payload_ref=dict(_PAYLOAD_REF_SAMPLE),
    )
    assert entry.payload_ref == _PAYLOAD_REF_SAMPLE


def test_to_jsonl_includes_payload_ref_when_set(ledger: Path) -> None:
    """When ``payload_ref`` is non-None, the JSON wire form MUST contain the dict."""
    audit.append_entry(
        case_id="case-1",
        tool="get_amcache",
        args={"case_id": "case-1"},
        input_ref={"path": "/cases/x/Amcache.hve", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=10,
        payload_ref=dict(_PAYLOAD_REF_SAMPLE),
    )
    line = ledger.read_text(encoding="utf-8").splitlines()[0]
    raw = json.loads(line)
    assert raw["payload_ref"] == _PAYLOAD_REF_SAMPLE


def test_to_jsonl_omits_payload_ref_key_when_none(ledger: Path) -> None:
    """Forward-compat (AC-10): when ``payload_ref is None`` the JSON wire form
    MUST NOT contain the ``payload_ref`` key at all.

    Emitting ``"payload_ref": null`` would change ``_line_hash_for``'s canonical
    bytes for callers that don't pass the kwarg — breaking forward-compat with
    pre-feature ledgers. The contract is: missing-from-dict, not null-valued.
    """
    _append()  # No payload_ref argument
    line = ledger.read_text(encoding="utf-8").splitlines()[0]
    raw = json.loads(line)
    assert "payload_ref" not in raw, (
        "payload_ref key must be omitted (not null-valued) when not supplied — "
        "see AC-10 forward-compat contract"
    )


def test_append_entry_uses_caller_supplied_audit_id(ledger: Path) -> None:
    """When the caller passes ``audit_id=``, the ledger entry MUST use that value
    verbatim — the offload payload path and the ledger entry share this ID by
    construction (AC-7), not by happy coincidence.
    """
    pinned_id = "11111111-1111-4111-8111-111111111111"
    entry = audit.append_entry(
        case_id="case-1",
        tool="get_amcache",
        args={"case_id": "case-1"},
        input_ref={"path": "/cases/x/Amcache.hve", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=10,
        audit_id=pinned_id,
    )
    assert entry.audit_id == pinned_id


def test_append_entry_mints_audit_id_when_omitted(ledger: Path) -> None:
    """Backwards compat: callers that don't pass ``audit_id=`` still get a UUID.

    Pre-feature behaviour was always-mint; new callers can opt into pinned IDs
    but old callers (and tests) must keep working unchanged.
    """
    e1 = audit.append_entry(
        case_id="case-1",
        tool="get_amcache",
        args={"case_id": "case-1"},
        input_ref={"path": "/cases/x/Amcache.hve", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=10,
    )
    e2 = audit.append_entry(
        case_id="case-1",
        tool="get_amcache",
        args={"case_id": "case-1"},
        input_ref={"path": "/cases/x/Amcache.hve", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=10,
    )
    assert e1.audit_id != e2.audit_id
    # Sanity: looks like a UUID4
    assert len(e1.audit_id) == 36 and e1.audit_id.count("-") == 4


def test_verify_chain_breaks_on_payload_ref_sha256_tamper(ledger: Path) -> None:
    """AC-4: mutating ``payload_ref.sha256`` of line K MUST cause ``verify_chain``
    to return ``(False, K, audit_id_of_line_K)``.

    This is the load-bearing assertion that ``payload_ref`` is HMAC-covered. If
    the chain didn't include it, an attacker could swap the on-disk payload file
    and update ``payload_ref.sha256`` on the same ledger line without breaking
    verification — silent corruption.
    """
    # Three entries WITH payload_ref.
    entries = []
    for i in range(3):
        entries.append(
            audit.append_entry(
                case_id="case-1",
                tool="get_amcache",
                args={"case_id": "case-1", "i": i},
                input_ref={"path": f"/cases/x/file{i}.hve", "sha256": "a" * 64},
                pre_sanitization_sha256="b" * 64,
                post_sanitization_sha256="c" * 64,
                rowcount=i,
                payload_ref={
                    **_PAYLOAD_REF_SAMPLE,
                    "sha256": (str(i) + "e") * 32,  # 64 chars, varies per entry
                },
            )
        )

    # Tamper with line 2 (1-based): swap payload_ref.sha256 to a different valid hex.
    raw_lines = ledger.read_text(encoding="utf-8").splitlines()
    target = json.loads(raw_lines[1])
    assert target["audit_id"] == entries[1].audit_id  # sanity: line 2 == entries[1]
    target["payload_ref"]["sha256"] = "f" * 64
    raw_lines[1] = json.dumps(target, ensure_ascii=False, sort_keys=True)
    ledger.write_text("\n".join(raw_lines) + "\n", encoding="utf-8")

    ok, first_bad, bad_audit_id = audit.verify_chain(ledger)
    assert ok is False
    assert first_bad == 2, "first_bad must be the 1-based line number of the tamper"
    assert bad_audit_id == entries[1].audit_id


def test_verify_chain_passes_on_legacy_ledger_without_payload_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-10: a ledger seeded BEFORE this feature (entries omit ``payload_ref``
    entirely) MUST still verify cleanly post-feature.

    The forward-compat contract: ``_line_hash_for`` on a legacy line must hash
    exactly the bytes the pre-feature implementation hashed. The simplest way
    to assert this end-to-end is to construct legacy lines by hand using the
    pre-feature canonical shape, write them to disk, then run the new
    ``verify_chain``.
    """
    path = tmp_path / "legacy_ledger.jsonl"
    monkeypatch.setenv(audit.LEDGER_ENV, str(path))
    key_hex = secrets.token_hex(32)
    monkeypatch.setenv(audit.HMAC_KEY_ENV, key_hex)
    key = bytes.fromhex(key_hex)

    prev = "0" * 64
    legacy_lines: list[str] = []
    legacy_audit_ids: list[str] = []
    for i in range(3):
        # Pre-feature canonical entry: NO payload_ref key at all.
        body = {
            "audit_id": f"legacy-{i:08d}-0000-4000-8000-000000000000",
            "ts": "2026-04-01T00:00:00Z",
            "case_id": "legacy-case",
            "tool": "get_amcache",
            "args_hash": "1" * 64,
            "input_ref": {"path": f"/cases/legacy/{i}", "sha256": "a" * 64},
            "pre_sanitization_sha256": "b" * 64,
            "post_sanitization_sha256": "c" * 64,
            "rowcount": i,
            "prev_hash": prev,
        }
        line_hash = hmac.new(key, _legacy_canonical_bytes(body), hashlib.sha256).hexdigest()
        body["line_hash"] = line_hash
        prev = line_hash
        legacy_lines.append(json.dumps(body, ensure_ascii=False, sort_keys=True))
        legacy_audit_ids.append(body["audit_id"])

    path.write_text("\n".join(legacy_lines) + "\n", encoding="utf-8")

    # Pre-condition sanity: the on-disk JSON really lacks the payload_ref key.
    for raw in path.read_text(encoding="utf-8").splitlines():
        assert "payload_ref" not in json.loads(raw)

    ok, first_bad, bad_audit_id = audit.verify_chain(path)
    assert ok is True, "legacy ledger must verify cleanly post-feature"
    assert first_bad is None
    assert bad_audit_id is None


def test_verify_chain_legacy_then_new_entry_chains_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-10 cross-version: a legacy entry followed by a new entry that DOES
    carry ``payload_ref`` must chain cleanly. This pins that the new write path
    correctly threads from a legacy ``prev_hash``.

    Without this test, an implementation could silently mis-handle the
    seam between a legacy tail and the first post-feature append.
    """
    path = tmp_path / "mixed_ledger.jsonl"
    monkeypatch.setenv(audit.LEDGER_ENV, str(path))
    key_hex = secrets.token_hex(32)
    monkeypatch.setenv(audit.HMAC_KEY_ENV, key_hex)
    key = bytes.fromhex(key_hex)

    # Seed exactly one legacy entry.
    body = {
        "audit_id": "legacy-00000001-0000-4000-8000-000000000000",
        "ts": "2026-04-01T00:00:00Z",
        "case_id": "legacy-case",
        "tool": "get_amcache",
        "args_hash": "1" * 64,
        "input_ref": {"path": "/cases/legacy/0", "sha256": "a" * 64},
        "pre_sanitization_sha256": "b" * 64,
        "post_sanitization_sha256": "c" * 64,
        "rowcount": 0,
        "prev_hash": "0" * 64,
    }
    body["line_hash"] = hmac.new(key, _legacy_canonical_bytes(body), hashlib.sha256).hexdigest()
    path.write_text(json.dumps(body, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    # Append a NEW entry with payload_ref.
    new_entry = audit.append_entry(
        case_id="case-1",
        tool="get_amcache",
        args={"case_id": "case-1"},
        input_ref={"path": "/cases/x/file.hve", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=5,
        payload_ref=dict(_PAYLOAD_REF_SAMPLE),
    )
    assert new_entry.prev_hash == body["line_hash"]

    ok, first_bad, bad_audit_id = audit.verify_chain(path)
    assert ok is True
    assert first_bad is None
    assert bad_audit_id is None

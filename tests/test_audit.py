"""Tests for :mod:`sanctum.audit` — append-only ledger with chain verification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sanctum import audit


@pytest.fixture
def ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv(audit.LEDGER_ENV, str(path))
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
    ok, lines, bad = audit.verify_chain(ledger)
    assert ok is True
    assert lines == 5
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

"""Tests for :mod:`sanctum.payload` — write-once on-disk tool return offload."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

import pytest

from sanctum import payload


@pytest.fixture
def output_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "output"
    monkeypatch.setenv(payload.OUTPUT_ROOT_ENV, str(root))
    return root


def _uuid() -> str:
    return str(uuid.uuid4())


def test_write_payload_creates_file_at_expected_path(output_root: Path) -> None:
    audit_id = _uuid()
    ref = payload.write_payload(
        case_id="cfreds-hacking-case",
        audit_id=audit_id,
        tool="get_amcache",
        content='{"ok": true}',
    )
    expected = output_root / "cfreds-hacking-case" / audit_id / "get_amcache.json"
    assert Path(ref.path) == expected
    assert expected.read_text(encoding="utf-8") == '{"ok": true}'


def test_write_payload_returns_sha256_and_bytes(output_root: Path) -> None:
    content = '{"rowcount": 42}'
    ref = payload.write_payload(
        case_id="c", audit_id=_uuid(), tool="t", content=content,
    )
    assert ref.sha256 == hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert ref.bytes == len(content.encode("utf-8"))
    assert ref.format == "application/json"


def test_write_payload_is_write_once(output_root: Path) -> None:
    audit_id = _uuid()
    payload.write_payload(case_id="c", audit_id=audit_id, tool="t", content="one")
    with pytest.raises(FileExistsError):
        payload.write_payload(case_id="c", audit_id=audit_id, tool="t", content="two")


def test_write_payload_rejects_traversal_in_case_id(output_root: Path) -> None:
    with pytest.raises(ValueError):
        payload.write_payload(
            case_id="../etc", audit_id=_uuid(), tool="t", content="x",
        )


def test_write_payload_rejects_traversal_in_audit_id(output_root: Path) -> None:
    with pytest.raises(ValueError):
        payload.write_payload(
            case_id="c", audit_id="../evil", tool="t", content="x",
        )


def test_write_payload_rejects_traversal_in_tool(output_root: Path) -> None:
    with pytest.raises(ValueError):
        payload.write_payload(
            case_id="c", audit_id=_uuid(), tool="../evil", content="x",
        )


def test_write_payload_rejects_empty_component(output_root: Path) -> None:
    with pytest.raises(ValueError):
        payload.write_payload(
            case_id="", audit_id=_uuid(), tool="t", content="x",
        )


def test_payload_ref_serialises_all_fields(output_root: Path) -> None:
    ref = payload.write_payload(
        case_id="c", audit_id=_uuid(), tool="t", content="x",
    )
    d = ref.to_json_dict()
    assert set(d.keys()) == {"path", "sha256", "bytes", "format"}
    assert d["sha256"] == hashlib.sha256(b"x").hexdigest()


def test_payload_file_is_read_only_mode(output_root: Path) -> None:
    ref = payload.write_payload(
        case_id="c", audit_id=_uuid(), tool="t", content="x",
    )
    mode = os.stat(ref.path).st_mode & 0o777
    # 0o444 is the declared mode; umask may clear bits but never add them.
    assert mode & 0o200 == 0, f"payload file is writable: mode={oct(mode)}"

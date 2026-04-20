"""Tests for :mod:`sanctum.notary` — RFC 3161 TSA stamping of the ledger head.

Network-free: every test mocks the HTTP POST and the ``openssl`` subprocess.
The goal is to exercise the integration *around* those two external calls —
file layout, error propagation, and wiring to the ledger — without making
real TSA requests.
"""

from __future__ import annotations

import secrets
import subprocess
from pathlib import Path
from typing import Any

import pytest

from sanctum import audit, notary

# ---------------------------- fixtures ----------------------------


@pytest.fixture
def ledger_with_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Writable ledger with one real entry so stamp_head has a non-genesis head."""
    path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv(audit.LEDGER_ENV, str(path))
    monkeypatch.setenv(audit.HMAC_KEY_ENV, secrets.token_hex(32))
    audit.append_entry(
        case_id="c",
        tool="get_amcache",
        args={"case_id": "c"},
        input_ref=None,
        pre_sanitization_sha256="a" * 64,
        post_sanitization_sha256="b" * 64,
    )
    return path


def _mock_openssl_and_http(
    monkeypatch: pytest.MonkeyPatch,
    *,
    granted: bool = True,
    openssl_missing: bool = False,
) -> None:
    """Patch openssl subprocess + urllib.urlopen used by notary.stamp_head."""
    if openssl_missing:
        monkeypatch.setattr(notary.shutil, "which", lambda _name: None)
        return

    monkeypatch.setattr(notary.shutil, "which", lambda _name: "/usr/bin/openssl")

    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        # First arg is "openssl"; second is "ts"; third chooses query/reply.
        if cmd[2] == "-query":
            return subprocess.CompletedProcess(cmd, 0, stdout=b"FAKE_TSQ_BYTES")
        if cmd[2] == "-reply":
            status = "Status: Granted" if granted else "Status: Rejected"
            text = f"Status info:\n{status}\nToken info:\n  Policy: 1.2\n"
            return subprocess.CompletedProcess(
                cmd, 0, stdout=text.encode("utf-8")
            )
        raise AssertionError(f"unexpected openssl invocation: {cmd}")

    monkeypatch.setattr(notary.subprocess, "run", _fake_run)

    class _FakeResp:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *_args: Any) -> None:
            pass

        def read(self) -> bytes:
            return self._body

    def _fake_urlopen(req: Any, timeout: int = 30) -> _FakeResp:
        # Verify the caller attached the RFC 3161 Content-Type.
        assert (
            req.get_header("Content-type") == notary.TSA_REQUEST_CONTENT_TYPE
        ), "stamp_head MUST POST with application/timestamp-query"
        return _FakeResp(b"FAKE_TSR_BYTES")

    monkeypatch.setattr(notary.urllib.request, "urlopen", _fake_urlopen)


# ---------------------------- tests ----------------------------


def test_stamp_head_writes_tsq_and_tsr_artefacts(
    ledger_with_entry: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Happy path — stamping a real ledger produces the two archive files."""
    _mock_openssl_and_http(monkeypatch)
    result = notary.stamp_head(tsa_url="https://tsa.example/fake")
    assert result.ledger_path == ledger_with_entry
    assert result.tsa_url == "https://tsa.example/fake"
    assert result.tsq_path.exists()
    assert result.tsr_path.exists()
    assert result.tsq_path.read_bytes() == b"FAKE_TSQ_BYTES"
    assert result.tsr_path.read_bytes() == b"FAKE_TSR_BYTES"
    assert "Status: Granted" in result.status_text


def test_stamp_head_binds_to_current_head_hash(
    ledger_with_entry: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stamped head MUST equal the ledger's last line_hash.

    If the head-binding drifts, a TSA-signed stamp no longer pins the state
    we meant to witness — silent corruption of the evidentiary claim.
    """
    _mock_openssl_and_http(monkeypatch)
    result = notary.stamp_head()
    expected_head = audit._last_line_hash(ledger_with_entry)
    assert result.head_hash == expected_head
    assert len(result.head_hash) == 64  # SHA-256 hex


def test_stamp_head_raises_when_openssl_missing(
    ledger_with_entry: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If openssl is absent, the caller MUST see a clear error."""
    _mock_openssl_and_http(monkeypatch, openssl_missing=True)
    with pytest.raises(RuntimeError, match="openssl is required"):
        notary.stamp_head()


def test_stamp_head_raises_on_tsa_rejection(
    ledger_with_entry: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-'granted' TSA response MUST surface as RuntimeError.

    The response bytes are still archived so an operator can inspect what
    the TSA returned — but the caller must know the stamp was not granted.
    """
    _mock_openssl_and_http(monkeypatch, granted=False)
    with pytest.raises(RuntimeError, match="did not grant"):
        notary.stamp_head()


def test_stamp_head_archive_dir_override(
    ledger_with_entry: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit ``archive_dir`` MUST place artefacts there, not next to the ledger."""
    _mock_openssl_and_http(monkeypatch)
    alt = tmp_path / "tsa-archive"
    result = notary.stamp_head(archive_dir=alt)
    assert result.tsq_path.parent == alt
    assert result.tsr_path.parent == alt
    assert alt.exists()


def test_stamp_head_works_on_empty_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stamping an empty ledger uses the genesis head — still useful as a baseline.

    An operator may want to stamp a fresh ledger to publish "we started
    empty at time T"; nothing prevents this and the returned head hash is
    the documented genesis value (64 zeros).
    """
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv(audit.LEDGER_ENV, str(ledger))
    _mock_openssl_and_http(monkeypatch)
    result = notary.stamp_head()
    assert result.head_hash == "0" * 64

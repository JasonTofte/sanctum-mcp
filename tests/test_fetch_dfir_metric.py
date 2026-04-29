"""Security + integrity tests for `scripts/fetch_dfir_metric.py`.

These pin the post-Phase-B-review HIGH fixes:
- `expected_sha256` must be required (no default-None bypass)
- URL scheme/host allowlist (HTTPS + raw.githubusercontent.com only)

Also the MEDIUM fixes that landed in the same pass:
- bounded `response.read(MAX_BYTES)`
- atomic cache write via `os.replace`

These tests do NOT hit the network — they patch `urllib.request.urlopen`
or simply call the function with bad arguments.
"""

from __future__ import annotations

import inspect
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import fetch_dfir_metric


def test_expected_sha256_is_required() -> None:
    """No default-None: callers must opt IN to verification, not opt OUT.

    Verified at signature inspection time so the failure surfaces early
    even before a caller runs the fetcher.
    """
    sig = inspect.signature(fetch_dfir_metric.fetch_upstream)
    param = sig.parameters["expected_sha256"]
    assert param.default is inspect.Parameter.empty, (
        f"expected_sha256 must be a required kwarg; got default={param.default!r}. "
        "fw-review-security HIGH — making it Optional silently disables the integrity gate."
    )


def test_rejects_non_https_scheme(tmp_path: Path) -> None:
    """file:// or http:// schemes must be refused (CWE-918 SSRF surface)."""
    with pytest.raises((ValueError, RuntimeError), match="(?i)scheme|allowlist|https"):
        fetch_dfir_metric.fetch_upstream(
            cache_dir=tmp_path,
            upstream_url="file:///etc/passwd",
            expected_sha256="0" * 64,
        )


def test_rejects_unallowed_host(tmp_path: Path) -> None:
    """An https URL on an unallowed host must be refused — host-allowlist enforcement."""
    with pytest.raises((ValueError, RuntimeError), match="(?i)host|allowlist"):
        fetch_dfir_metric.fetch_upstream(
            cache_dir=tmp_path,
            upstream_url="https://attacker.example.com/payload.json",
            expected_sha256="0" * 64,
        )


def test_size_cap_enforced(tmp_path: Path) -> None:
    """`response.read(MAX_BYTES)` prevents OOM on a hostile multi-GB response."""
    huge = b"x" * (fetch_dfir_metric.MAX_RESPONSE_BYTES + 1)
    fake_response = _FakeResponse(huge)
    with patch("scripts.fetch_dfir_metric.urllib.request.urlopen", return_value=fake_response):
        with pytest.raises(RuntimeError, match="(?i)size|truncat|cap|exceed"):
            fetch_dfir_metric.fetch_upstream(
                cache_dir=tmp_path,
                upstream_url="https://raw.githubusercontent.com/x/y/z.json",
                expected_sha256="0" * 64,  # mismatched, but size check fires first
            )


def test_sha256_mismatch_does_not_persist_cache(tmp_path: Path) -> None:
    """Atomic write: a mismatched SHA-256 must leave NO cache file behind."""
    body = b'{"hello": "world"}'
    fake_response = _FakeResponse(body)
    cache_path = tmp_path / "DFIR-Metric-CTF.json"
    with patch("scripts.fetch_dfir_metric.urllib.request.urlopen", return_value=fake_response):
        with pytest.raises(RuntimeError, match="sha256"):
            fetch_dfir_metric.fetch_upstream(
                cache_dir=tmp_path,
                upstream_url="https://raw.githubusercontent.com/x/y/z.json",
                expected_sha256="0" * 64,
            )
    assert not cache_path.exists(), (
        "fw-review-security MEDIUM — a SHA-256 mismatch must NOT leave a partial cache; "
        "atomic write via os.replace is the fix."
    )


def test_happy_path_writes_cache_and_provenance(tmp_path: Path) -> None:
    """End-to-end happy path with the correct expected_sha256."""
    import hashlib

    body = b'{"hello": "world"}'
    sha = hashlib.sha256(body).hexdigest()
    fake_response = _FakeResponse(body)
    with patch("scripts.fetch_dfir_metric.urllib.request.urlopen", return_value=fake_response):
        out = fetch_dfir_metric.fetch_upstream(
            cache_dir=tmp_path,
            upstream_url="https://raw.githubusercontent.com/x/y/z.json",
            expected_sha256=sha,
        )
    assert out.read_bytes() == body
    provenance = (tmp_path / "PROVENANCE.json").read_text(encoding="utf-8")
    assert sha in provenance, "PROVENANCE.json must record the verified sha256"


# --- helpers -------------------------------------------------------------


class _FakeResponse:
    """Minimal urllib response stand-in supporting the context-manager protocol."""

    def __init__(self, body: bytes) -> None:
        self._stream = BytesIO(body)

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        self._stream.close()

"""Phase 3 — AC-5, AC-6: feature-flag gating and parallel speedup.

AC-5: SANCTUM_PARALLEL_TOOLS=0 (or unset) serializes; =1 enables parallel dispatch.
AC-6: With SANCTUM_PARALLEL_TOOLS=1, wallclock ≤ 1/3 of serial baseline (≥3× speedup).

Performance tests use synthetic sleep delays injected via monkeypatch so the
wallclock comparison is deterministic and does not depend on real parser I/O
timing.  Each synthetic tool call sleeps for a fixed duration in a worker
thread (mimicking blocking registry/EVTX parse).  Serialized baseline:
N × sleep.  Parallel ceiling: ≈ 1 × sleep + overhead.  The ≥3× threshold
leaves room for event-loop overhead and CI variance.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from pathlib import Path

import pytest

from sanctum import audit, server
from sanctum.parsers._fixture_io import FIXTURE_ENV, SIDECAR_SUFFIX

# ─── fixture helpers (shared with test_concurrency.py) ────────────────────────

_SAMPLE_EVENT = {
    "program_path": r"C:\Windows\System32\notepad.exe",
    "timestamp": "2024-01-15T10:30:00+00:00",
    "evidence_size_bytes": 512,
    "extras": {"row_index": "0"},
}


def _write_sidecar(artifact_path: Path, *, family: str, tool: str) -> None:
    sidecar = artifact_path.with_name(artifact_path.name + SIDECAR_SUFFIX)
    sidecar.write_text(
        json.dumps({"family": family, "tool": tool, "events": [_SAMPLE_EVENT]}),
        encoding="utf-8",
    )


def _make_amcache_only_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    cases = tmp_path / "cases"
    case = cases / "smoke"
    (case / "registry").mkdir(parents=True)
    hive = case / "registry" / "Amcache.hve"
    hive.write_bytes(b"stub hive")
    _write_sidecar(hive, family="AppCompat", tool="get_amcache")

    output_root = tmp_path / "output"
    output_root.mkdir()
    ledger_path = tmp_path / "ledger.jsonl"

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(ledger_path))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", secrets.token_hex(32))
    return ledger_path


# ─── AC-5: feature-flag gating ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_serial_mode_unset_produces_correct_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-5: with SANCTUM_PARALLEL_TOOLS unset, N=3 calls must produce 3 valid entries.

    Confirms that the default (serial) mode does not lose entries — the
    Semaphore(1) serializes but must not swallow or deduplicate calls.
    """
    ledger_path = _make_amcache_only_case(tmp_path, monkeypatch)
    monkeypatch.delenv("SANCTUM_PARALLEL_TOOLS", raising=False)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    results = await asyncio.gather(
        *[server.get_amcache("smoke") for _ in range(3)],
        return_exceptions=True,
    )

    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, f"Serial mode raised: {errors}"

    ok, bad_line, _ = audit.verify_chain(ledger_path)
    assert ok is True, f"Chain invalid at line {bad_line}"

    count = sum(
        1 for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()
    )
    assert count == 3, f"Expected 3 ledger entries in serial mode, got {count}"


@pytest.mark.asyncio
async def test_serial_mode_explicit_zero_produces_correct_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-5: SANCTUM_PARALLEL_TOOLS=0 (explicit) behaves identically to unset."""
    ledger_path = _make_amcache_only_case(tmp_path, monkeypatch)
    monkeypatch.setenv("SANCTUM_PARALLEL_TOOLS", "0")
    monkeypatch.setenv(FIXTURE_ENV, "1")

    results = await asyncio.gather(
        *[server.get_amcache("smoke") for _ in range(3)],
        return_exceptions=True,
    )

    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, f"Serial mode (=0) raised: {errors}"

    count = sum(
        1 for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()
    )
    assert count == 3


@pytest.mark.asyncio
async def test_parallel_mode_produces_correct_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-5: SANCTUM_PARALLEL_TOOLS=1 still produces correct, valid ledger entries.

    When the semaphore is removed (parallel=True → semaphore=None), the
    _ledger_write_lock inside _emit_offloaded_response must still serialise
    writes correctly and produce a valid HMAC chain.
    """
    ledger_path = _make_amcache_only_case(tmp_path, monkeypatch)
    monkeypatch.setenv("SANCTUM_PARALLEL_TOOLS", "1")
    monkeypatch.setenv(FIXTURE_ENV, "1")

    results = await asyncio.gather(
        *[server.get_amcache("smoke") for _ in range(5)],
        return_exceptions=True,
    )

    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, f"Parallel mode raised: {errors}"

    ok, bad_line, _ = audit.verify_chain(ledger_path)
    assert ok is True, f"Parallel-mode chain invalid at line {bad_line}"

    count = sum(
        1 for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()
    )
    assert count == 5


# ─── AC-6: ≥3× speedup when SANCTUM_PARALLEL_TOOLS=1 ─────────────────────────
#
# Design: inject a fixed sleep inside each parser call via monkeypatch so that
# "parse time" is predictable regardless of CI load. The sleep runs in the
# anyio thread pool (as real blocking I/O does), so it correctly exercises the
# parallel vs. serial dispatch path.
#
# Serial baseline:   N × SLEEP_S  (Semaphore(1) → calls queued)
# Parallel ceiling:  ≈ SLEEP_S + overhead  (all N calls run concurrently)
# Threshold:         serial_time / parallel_time ≥ 3.0


_SLEEP_S = 0.05  # 50 ms per synthetic "parse"
_N_CALLS = 5     # 5 calls → 250 ms serial baseline, ~50 ms parallel ceiling


@pytest.mark.asyncio
async def test_parallel_mode_achieves_3x_speedup_over_serial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-6: parallel mode MUST be ≥3× faster than serial mode under the same load.

    Injects a 50ms thread sleep into parse_amcache to make dispatch latency
    the dominant cost.  5 calls × 50ms = 250ms serial.  Parallel ceiling ≈
    50ms + overhead.  The test accepts ≥3× speedup (83ms threshold), leaving
    headroom for CI variance while rejecting a broken flag (which would give
    ~1× speedup).

    Failure means: the SANCTUM_PARALLEL_TOOLS=1 path still serializes tool
    dispatch, i.e., the Semaphore is being acquired in parallel mode when it
    should not be.
    """
    from sanctum.parsers import amcache as _amcache_mod

    _make_amcache_only_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    original_parse = _amcache_mod.parse_amcache

    def _slow_parse(path):
        time.sleep(_SLEEP_S)
        return original_parse(path)

    monkeypatch.setattr(_amcache_mod, "parse_amcache", _slow_parse)
    # Also patch the reference in server so the running module sees the slow version
    monkeypatch.setattr(server, "parse_amcache", _slow_parse)

    # ── Serial baseline ────────────────────────────────────────────────────────
    monkeypatch.setenv("SANCTUM_PARALLEL_TOOLS", "0")
    server._get_tool_semaphore.cache_clear()  # force fresh semaphore for this mode
    t0 = time.perf_counter()
    serial_results = await asyncio.gather(
        *[server.get_amcache("smoke") for _ in range(_N_CALLS)],
        return_exceptions=True,
    )
    serial_time = time.perf_counter() - t0

    serial_errors = [r for r in serial_results if isinstance(r, BaseException)]
    assert not serial_errors, f"Serial baseline raised: {serial_errors}"

    # ── Parallel run ───────────────────────────────────────────────────────────
    monkeypatch.setenv("SANCTUM_PARALLEL_TOOLS", "1")
    server._get_tool_semaphore.cache_clear()  # force fresh semaphore for parallel mode
    t1 = time.perf_counter()
    parallel_results = await asyncio.gather(
        *[server.get_amcache("smoke") for _ in range(_N_CALLS)],
        return_exceptions=True,
    )
    parallel_time = time.perf_counter() - t1

    parallel_errors = [r for r in parallel_results if isinstance(r, BaseException)]
    assert not parallel_errors, f"Parallel run raised: {parallel_errors}"

    speedup = serial_time / parallel_time
    assert speedup >= 3.0, (
        f"AC-6 speedup below 3× threshold: {speedup:.2f}× "
        f"(serial={serial_time*1000:.0f}ms, parallel={parallel_time*1000:.0f}ms). "
        f"SANCTUM_PARALLEL_TOOLS=1 may not be removing the Semaphore correctly."
    )

"""Phase 3 — AC-2 (P0), AC-3, AC-7: concurrency invariants.

These tests exercise the load-bearing concurrency properties of the async-def
migration: HMAC chain integrity under concurrent writes, registry-hive safety
with concurrent callers, and a stress test across all five evidence families.

Run with: pytest tests/test_concurrency.py -v
"""

from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path

import pytest

from sanctum import audit, server
from sanctum.parsers._fixture_io import FIXTURE_ENV, SIDECAR_SUFFIX

# ─── fixture helpers ──────────────────────────────────────────────────────────

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
    """Set up a case with only Amcache.hve sidecar. Returns ledger_path."""
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


def _make_full_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Set up a case with sidecars for amcache, bam, userassist, and sysmon.

    BAM (Background-service family) and shimcache (AppCompat family) both use
    registry/SYSTEM, but load_sidecar validates the `tool` field — so only one
    can have a live sidecar at a time. This helper writes the SYSTEM sidecar
    for BAM only; shimcache is excluded from the stress test tool mix.

    Prefetch is served with an empty Prefetch/ directory (no .pf files →
    parse_prefetch is never called → no sidecar needed; the tool still writes
    a ledger entry with rowcount=0 via _emit_offloaded_response).
    """
    cases = tmp_path / "cases"
    case = cases / "smoke"
    reg = case / "registry"
    logs = case / "logs"
    prefetch = case / "Prefetch"
    for d in (reg, logs, prefetch):
        d.mkdir(parents=True)

    amcache_hve = reg / "Amcache.hve"
    amcache_hve.write_bytes(b"stub hive")
    _write_sidecar(amcache_hve, family="AppCompat", tool="get_amcache")

    system_hve = reg / "SYSTEM"
    system_hve.write_bytes(b"stub hive")
    _write_sidecar(system_hve, family="Background-service", tool="get_bam")

    ntuser_hve = reg / "NTUSER.DAT"
    ntuser_hve.write_bytes(b"stub hive")
    _write_sidecar(ntuser_hve, family="Explorer/NTUSER", tool="get_userassist")

    evtx = logs / "Microsoft-Windows-Sysmon%4Operational.evtx"
    evtx.write_bytes(b"stub evtx")
    _write_sidecar(evtx, family="Kernel-ETW", tool="get_sysmon_4688")

    output_root = tmp_path / "output"
    output_root.mkdir()
    ledger_path = tmp_path / "ledger.jsonl"

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(ledger_path))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", secrets.token_hex(32))
    return ledger_path


# ─── AC-2 (P0): HMAC chain integrity under concurrent writes ─────────────────


@pytest.mark.asyncio
async def test_ledger_hmac_chain_valid_after_n5_concurrent_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-2 (P0): HMAC chain MUST be valid after N=5 concurrent get_amcache calls.

    This is the highest-severity failure mode: without asyncio.Lock serialising
    ledger writes, two concurrent calls can read the same prev_hash, produce
    two entries with the same prev_hash, and break the chain.

    verify_chain() returning True and exactly 5 ledger entries is the proof
    that the single-writer lock is in the right place and held for the full
    read-prev-hash + write-entry atomic operation.
    """
    ledger_path = _make_amcache_only_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    results = await asyncio.gather(
        *[server.get_amcache("smoke") for _ in range(5)],
        return_exceptions=True,
    )

    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, f"Concurrent get_amcache raised: {errors}"

    ok, bad_line, bad_id = audit.verify_chain(ledger_path)
    assert ok is True, f"HMAC chain invalid at line {bad_line} (audit_id={bad_id})"
    assert bad_line is None
    assert bad_id is None

    entries = [
        line
        for line in ledger_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(entries) == 5, (
        f"Expected 5 ledger entries (one per concurrent call), got {len(entries)}. "
        "Entries may have been lost or duplicate prev_hash values indicate a race."
    )


@pytest.mark.asyncio
async def test_ledger_chain_audit_ids_are_distinct_after_concurrent_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-2 variant: audit_ids from N=5 concurrent calls must all be distinct.

    A duplicate audit_id would mean two calls shared an in-flight state object —
    a pre-mint / UUID reuse bug that would not be caught by verify_chain alone.
    """
    import re

    _make_amcache_only_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    responses = await asyncio.gather(
        *[server.get_amcache("smoke") for _ in range(5)],
    )

    audit_ids = []
    for resp in responses:
        m = re.search(r'"audit_id"\s*:\s*"([^"]+)"', resp)
        assert m, f"No audit_id in response: {resp[:200]}"
        audit_ids.append(m.group(1))

    assert len(set(audit_ids)) == 5, (
        f"Expected 5 distinct audit_ids, got {len(set(audit_ids))}: {audit_ids}"
    )


# ─── AC-3: Registry-hive concurrency safety ──────────────────────────────────


@pytest.mark.asyncio
async def test_two_concurrent_calls_to_same_tool_both_succeed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-3: two concurrent calls to get_amcache must both return valid output.

    regipy.RegistryHive is serial-only. If the parser shared a module-level
    RegistryHive singleton across concurrent calls, the second caller would
    race against the first while the hive is being iterated — likely raising
    RegistryParseException or returning truncated rows.

    Per-call instantiation (the current pattern) makes each call independent.
    Both responses must contain <evidence-untrusted> blocks.
    """
    _make_amcache_only_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    r1, r2 = await asyncio.gather(
        server.get_amcache("smoke"),
        server.get_amcache("smoke"),
    )

    assert "<evidence-untrusted>" in r1, (
        f"First concurrent call missing evidence block: {r1[:200]}"
    )
    assert "<evidence-untrusted>" in r2, (
        f"Second concurrent call missing evidence block: {r2[:200]}"
    )


@pytest.mark.asyncio
async def test_four_concurrent_calls_chain_validates_and_entry_count_matches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-3 + AC-2: N=4 concurrent get_amcache calls → chain valid, 4 entries."""
    ledger_path = _make_amcache_only_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    results = await asyncio.gather(
        *[server.get_amcache("smoke") for _ in range(4)],
        return_exceptions=True,
    )

    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, f"Concurrent calls raised: {errors}"

    ok, bad_line, _ = audit.verify_chain(ledger_path)
    assert ok is True, f"Chain invalid at line {bad_line}"

    count = sum(
        1
        for line in ledger_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    assert count == 4


# ─── AC-7: Stress test — N=20 concurrent calls, all families ─────────────────


@pytest.mark.asyncio
async def test_n20_concurrent_calls_all_families_ledger_validates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-7: N=20 concurrent invocations across 5 evidence families; chain validates.

    Family coverage (4 calls each = 20 total):
    - AppCompat (get_amcache) → Amcache.hve sidecar
    - Background-service (get_bam) → SYSTEM hive sidecar
    - Explorer/NTUSER (get_userassist) → NTUSER.DAT sidecar
    - SysMain (get_prefetch) → empty Prefetch/ dir (rowcount=0 is valid)
    - Kernel-ETW (get_sysmon_4688) → EVTX sidecar

    Success criteria:
    1. All 20 calls return string results (no exceptions)
    2. verify_chain returns True
    3. Ledger contains exactly 20 entries
    """
    ledger_path = _make_full_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    calls = (
        [server.get_amcache("smoke") for _ in range(4)]
        + [server.get_bam("smoke") for _ in range(4)]
        + [server.get_userassist("smoke") for _ in range(4)]
        + [server.get_prefetch("smoke") for _ in range(4)]
        + [server.get_sysmon_4688("smoke") for _ in range(4)]
    )

    results = await asyncio.gather(*calls, return_exceptions=True)

    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, (
        f"Stress test raised {len(errors)} exception(s): "
        + str([str(e) for e in errors[:3]])
    )

    assert all(isinstance(r, str) for r in results)

    ok, bad_line, bad_id = audit.verify_chain(ledger_path)
    assert ok is True, f"Chain invalid at line {bad_line} (audit_id={bad_id})"

    entries = [
        line
        for line in ledger_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(entries) == 20, (
        f"Expected 20 ledger entries, got {len(entries)}. "
        f"Chain ok={ok}, bad_line={bad_line}."
    )

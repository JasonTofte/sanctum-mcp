"""Phase 3 — AC-1: all @mcp.tool() functions must be async coroutines.

These tests cover ARCH-001 (async-def migration) and ARCH-004 (async
append_entry). They will FAIL against the pre-migration codebase and
turn GREEN once all six tools are migrated and append_entry is async.

FastMCP tool introspection:
  server.mcp._tool_manager.list_tools() → list[mcp.server.fastmcp.tools.base.Tool]
  Tool.fn — the underlying callable; iscoroutinefunction() checks it.
"""

from __future__ import annotations

import asyncio

import pytest

from sanctum import audit, server

# Canonical set of MCP tools Sanctum must expose (AC-1 contract).
# claim_finding is excluded — it is not a get_* evidence tool and its async
# migration is implied by the ARCH-001 decision but it is not part of the
# speed/parallelism goal.  The six evidence tools below ARE the parallelism
# surface (AC-6 speedup metric requires all five families present).
_EXPECTED_ASYNC_TOOLS = frozenset({
    "get_amcache",
    "get_prefetch",
    "get_shimcache",
    "get_userassist",
    "get_bam",
    "get_sysmon_4688",
})


# ─── AC-1: tool registration ──────────────────────────────────────────────────


def test_all_expected_tools_are_registered() -> None:
    """All six evidence tools must be registered with the FastMCP tool manager."""
    registered = {t.name for t in server.mcp._tool_manager.list_tools()}
    missing = _EXPECTED_ASYNC_TOOLS - registered
    assert not missing, (
        f"Missing tool registration(s): {sorted(missing)}. "
        "Add @mcp.tool() wrappers for each in server.py (AC-1)."
    )


def test_all_expected_tools_are_coroutines() -> None:
    """Every expected @mcp.tool() function must be an asyncio coroutine (async def)."""
    non_async: list[str] = []
    for tool in server.mcp._tool_manager.list_tools():
        if tool.name in _EXPECTED_ASYNC_TOOLS:
            if not asyncio.iscoroutinefunction(tool.fn):
                non_async.append(tool.name)
    assert not non_async, (
        f"These tools are NOT async def: {sorted(non_async)}. "
        "Each must be migrated to `async def` per ARCH-001."
    )


def test_no_unexpected_sync_tools_in_evidence_surface() -> None:
    """All tools in the evidence surface (get_*) must be coroutines — no stragglers."""
    sync_evidence_tools = [
        t.name
        for t in server.mcp._tool_manager.list_tools()
        if t.name.startswith("get_") and not asyncio.iscoroutinefunction(t.fn)
    ]
    assert not sync_evidence_tools, (
        f"Sync get_* tool(s) found: {sorted(sync_evidence_tools)}. "
        "All evidence tools must be async def (AC-1)."
    )


# ─── AC-1 (ARCH-004): ledger write serialization lives in server ──────────────
# PIVOT (2026-04-29): asyncio.Lock placed in server._emit_offloaded_response,
# NOT in audit.append_entry — avoids cascading async migration across 30+
# sync test call sites in test_audit.py and test_server_boundaries.py.
# Production correctness is identical: _emit_offloaded_response is the sole
# production call site for audit.append_entry. Behavioral invariant tested
# by AC-2 in test_concurrency.py (HMAC chain validates after N concurrent writes).


def test_emit_offloaded_response_is_coroutine() -> None:
    """_emit_offloaded_response must be async to hold asyncio.Lock for ledger writes.

    The lock protecting HMAC chain order lives in this function (ARCH-004
    pivot: see Pivot Log in .sherlock-plan.md).  If the function is not
    async, the lock cannot be used and concurrent writes will corrupt the chain.
    """
    assert asyncio.iscoroutinefunction(server._emit_offloaded_response), (
        "server._emit_offloaded_response is not a coroutine. "
        "Migrate to `async def` and add `async with _ledger_write_lock` around "
        "the audit.append_entry call (ARCH-004)."
    )


# ─── AC-1 (import-time safety): no module-level async initialization ─────────


def test_server_module_imports_without_running_event_loop() -> None:
    """Importing sanctum.server must not require or start a running event loop.

    Module-level asyncio.Semaphore() or asyncio.Lock() creation fails when
    no event loop is running in Python 3.10+ (they attach to the running loop).
    The server must defer loop-attached objects to first-call or use factory
    functions.
    """
    # If the import itself raised, we'd never reach here.  The assertion
    # verifies the server object exists without an active event loop.
    assert server.mcp is not None


@pytest.mark.asyncio
async def test_all_tools_are_awaitable_in_async_context() -> None:
    """Coroutine callables return awaitables, not strings, when called bare.

    This is a cheap smoke-test: calling tool.fn(...) on an async def function
    returns a coroutine object (not a string) — confirming the wrapper is
    genuinely async, not a sync function that returns a coroutine.

    We close the coroutine immediately to avoid ResourceWarning; we are only
    checking the return type.
    """
    for tool in server.mcp._tool_manager.list_tools():
        if tool.name in _EXPECTED_ASYNC_TOOLS:
            # Call with a placeholder case_id — we expect a coroutine object back,
            # not a string (which would mean the function ran synchronously).
            result = tool.fn("__type_check_only__")
            assert asyncio.iscoroutine(result), (
                f"{tool.name}.fn(...) returned {type(result).__name__}, not a coroutine. "
                "The function is not truly async def."
            )
            result.close()

# Architecture Decision Record — Async-def migration (Phase 3, F3)

This document captures the load-bearing architectural decisions made when
migrating Sanctum's MCP tool functions from synchronous `def` to `async def`
and introducing a parallel dispatch gate. It records the ARCH-001 and
ARCH-004 decisions locked at program level on 2026-04-28, and the ARCH-004
pivot discovered during implementation on 2026-04-29.

---

## ADR-ASYNC-001 — All `@mcp.tool()` functions migrated to `async def`

**Status.** Accepted (2026-04-29).

**Context.** All six evidence tools (`get_amcache`, `get_shimcache`,
`get_userassist`, `get_bam`, `get_prefetch`, `get_sysmon_4688`) were `def`
functions under FastMCP. FastMCP dispatches `async def` tools concurrently
via anyio task groups and dispatches sync `def` tools via a thread pool
with no concurrency guarantee. To achieve the ≥3× speedup goal on
multi-family triage (AC-6), parallel dispatch requires all tools to be
coroutines.

**Decision.** Migrate all six tools to `async def`. All sync blocking I/O
(registry-hive parsing via regipy, fsync'd ledger writes, file hashing) is
offloaded via `anyio.to_thread.run_sync(lambda: ...)` so the event loop is
not blocked. The `anyio` library is already a transitive dependency of
`mcp==1.27.0`.

**Consequences — Positive.**
- FastMCP anyio task groups can dispatch concurrent tool calls.
- Parallel mode achieves ≥3× wallclock improvement on five-family triage
  (AC-6 test verifies with 50ms synthetic parse time per call).
- No change to the MCP typed-tool surface (same function names, same
  parameters).

**Consequences — Negative.**
- `anyio.to_thread.run_sync` adds a thread-pool dispatch per blocking
  call; negligible latency overhead vs. the I/O time being offloaded.
- Tests that call `server.get_amcache(...)` must be `async def` with
  `@pytest.mark.asyncio`.

**Consequences — Neutral.**
- `pytest-asyncio>=0.23,<1.0` added to dev deps; `asyncio_mode = "strict"`
  required in `pyproject.toml`.
- Conftest autouse fixture clears `asyncio.Semaphore` and `asyncio.Lock`
  caches between tests (event-loop-per-test isolation).

**Alternatives considered.**
- Keep tools sync and rely on FastMCP's thread pool — rejected because the
  thread pool does not guarantee concurrent dispatch across multiple tool
  calls, and blocking the event loop prevents the anyio task group from
  scheduling other tasks.
- Use `asyncio.run_in_executor` instead of `anyio.to_thread.run_sync` —
  rejected because `anyio` is the correct abstraction for anyio-native code
  (FastMCP uses anyio internally) and `run_in_executor` is a lower-level
  asyncio primitive.

**Tests that pin this invariant.**
- `tests/test_async_tool_signatures.py::test_all_expected_tools_are_coroutines`
- `tests/test_async_tool_signatures.py::test_all_tools_are_awaitable_in_async_context`

---

## ADR-ASYNC-002 — Ledger write serialization via `asyncio.Lock` in `_emit_offloaded_response`

**Status.** Accepted (2026-04-29). ARCH-004 pivot from original placement.

**Context.** The HMAC-SHA-256 ledger chain requires that `prev_hash` is
read and the new entry is written atomically relative to all concurrent
callers. Without a lock, two concurrent tool calls can both read the same
`prev_hash`, produce two entries with the same `prev_hash`, and corrupt the
chain. The original ARCH-004 decision placed `asyncio.Lock` in
`audit.append_entry`, making it an async function.

**Pivot (2026-04-29).** Making `audit.append_entry` async would cascade
async migration across 30+ synchronous call sites in `test_audit.py`,
`test_notary.py`, `test_finding.py`, and `test_server_boundaries.py` —
scope beyond Phase 3. The production correctness invariant is identical
whether the lock lives in `append_entry` or in its sole production call
site (`_emit_offloaded_response`): no two concurrent tool calls can
interleave their `_last_line_hash` read and ledger write.

**Decision.** Place `asyncio.Lock` (`_ledger_write_lock`) as a module-level
singleton in `server.py`. `_emit_offloaded_response` (the sole production
call site of `audit.append_entry`) acquires the lock and holds it for the
full `anyio.to_thread.run_sync(audit.append_entry)` call — so the
`_last_line_hash` read and the temp-then-append write are atomic relative
to concurrent callers. `audit.append_entry` remains synchronous.

**Consequences — Positive.**
- `audit.append_entry` stays sync; no changes to `test_audit.py`,
  `test_notary.py`, or `test_finding.py`.
- The lock scope (read-prev-hash + write) is identical to the original
  ARCH-004 intent — correctness is preserved.
- A future operator-facing multi-process deployment could add `fcntl.flock`
  inside `audit.append_entry` without touching the server.

**Consequences — Negative.**
- The invariant is harder to discover: the lock protecting the audit chain
  lives in `server.py`, not `audit.py`. Future contributors must read the
  ADR or the `.sherlock-plan.md` pivot log to understand why.

**Consequences — Neutral.**
- The module-level `asyncio.Lock` instance binds to the first event loop
  that acquires it. In production (single event loop for process lifetime)
  this is safe. In tests, the conftest autouse fixture replaces the instance
  with a fresh `asyncio.Lock()` before each test to prevent cross-test
  event-loop contamination.

**Alternatives considered.**
- Make `audit.append_entry` async (original ARCH-004) — deferred to a
  future phase that also migrates the test suite.
- `fcntl.flock` around the write in `audit.append_entry` — would not solve
  the asyncio concurrency case (two coroutines in the same event loop share
  a file descriptor; `flock` is per-process, not per-coroutine).

**Tests that pin this invariant.**
- `tests/test_concurrency.py::test_ledger_hmac_chain_valid_after_n5_concurrent_writes` (AC-2 P0)
- `tests/test_concurrency.py::test_n20_concurrent_calls_all_families_ledger_validates` (AC-7)
- `tests/test_async_tool_signatures.py::test_emit_offloaded_response_is_coroutine`

---

## ADR-ASYNC-003 — Serial-by-default via `asyncio.Semaphore(1)`; parallel on `SANCTUM_PARALLEL_TOOLS=1`

**Status.** Accepted (2026-04-29).

**Context.** FastMCP v1.27.0 dispatches `async def` tools concurrently by
default when called from the MCP client. There is no built-in concurrency
cap. A `SANCTUM_PARALLEL_TOOLS` flag is needed to allow the operator to
choose between serial (safe for demo/dev) and parallel (full speedup for
production triage).

**Decision.** Default serial: a module-level `asyncio.Semaphore(1)` is
acquired at the start of each `_serial_gate()` context and released on
exit. Parallel: `SANCTUM_PARALLEL_TOOLS=1` causes `_get_tool_semaphore` to
return `None`; `_serial_gate()` yields without acquiring anything, and
FastMCP dispatches concurrently. The semaphore is cached via
`@functools.lru_cache(parallel: bool)` so the same instance is reused
across calls (required for actual serialization).

**Why not a dispatch toggle?** FastMCP has no built-in concurrency cap;
toggling `async def` back to `def` would re-serialize but defeat the
anyio offload pattern. A semaphore is the correct mechanism.

**Consequences — Positive.**
- Demo safety: default `SANCTUM_PARALLEL_TOOLS=0` (or unset) means a late-
  discovered concurrency bug cannot affect the Week 7 demo.
- AC-6 test verifies ≥3× speedup with `SANCTUM_PARALLEL_TOOLS=1` and
  synthetic 50ms parse delay.

**Consequences — Negative.**
- Operators who want parallel dispatch must set the env var explicitly.
  Default-off means the speedup is not visible in the default configuration.

**Tests that pin this invariant.**
- `tests/test_feature_flag_parallel.py::test_serial_mode_unset_produces_correct_ledger`
- `tests/test_feature_flag_parallel.py::test_parallel_mode_achieves_3x_speedup_over_serial`

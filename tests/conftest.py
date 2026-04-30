"""Shared pytest fixtures for the Sanctum test suite."""

from __future__ import annotations

import asyncio

import pytest

from sanctum import server


@pytest.fixture(autouse=True)
def _reset_async_primitives() -> None:
    """Reset module-level asyncio primitives between tests.

    asyncio.Lock and asyncio.Semaphore bind to the running event loop on first
    acquire. Each pytest-asyncio test runs in a fresh event loop, so primitives
    acquired in a previous test will raise RuntimeError ("bound to a different
    event loop") when used in the next test.

    Resets performed before each test:
    - _get_tool_semaphore lru_cache: forces a fresh Semaphore per event loop.
    - _ledger_write_lock: replaced with a new Lock instance for the current loop.
    """
    server._get_tool_semaphore.cache_clear()
    server._ledger_write_lock = asyncio.Lock()
    yield
    server._get_tool_semaphore.cache_clear()
    server._ledger_write_lock = asyncio.Lock()

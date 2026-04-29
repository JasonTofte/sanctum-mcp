"""Pytest config for opt-in DFIR-Metric eval benchmarks.

Tests under this directory are gated by the ``benchmark`` marker
(registered in ``pyproject.toml``). Default ``pytest -q`` excludes them
via ``-m 'not benchmark'`` in pytest.ini_options.addopts. Run them with
``pytest -m benchmark`` (cached upstream JSON required for the Jaccard
test; the smoke tests run against the synthetic case fixture).
"""

from __future__ import annotations

from pathlib import Path

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-mark every test under ``tests/benchmarks/`` with ``benchmark``.

    Uses path-parts membership rather than substring matching so the
    rule survives Windows path separators and absolute paths from
    arbitrary cwds.
    """
    for item in items:
        parts = Path(str(item.fspath)).parts
        if "tests" in parts and "benchmarks" in parts:
            item.add_marker(pytest.mark.benchmark)

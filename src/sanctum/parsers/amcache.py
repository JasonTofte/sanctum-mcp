"""Amcache.hve parser (week-2 fixture-only stub).

Real implementation arrives in week 3 via a pure-Python registry library
(`regipy` is the current candidate per /deep-r plan c50c213cf6f6). Until
then `parse_amcache` is fixture-mode-only: outside `SANCTUM_USE_FIXTURE_SIDECAR=1`
it raises :class:`PartialImplementationError`, an `MCP-spec-compliant`
`isError: true` for any caller that reaches the production wire boundary.
"""

from __future__ import annotations

from pathlib import Path

from sanctum.events import ExecutionEvent
from sanctum.parsers._errors import ArtifactNotFoundError, PartialImplementationError
from sanctum.parsers._fixture_io import fixture_mode, load_sidecar

_TOOL = "get_amcache"
_FAMILY = "AppCompat"


def parse_amcache(hive_path: Path) -> list[ExecutionEvent]:
    if not hive_path.is_file():
        raise ArtifactNotFoundError(f"Amcache hive not found: {hive_path}")
    if fixture_mode():
        return load_sidecar(hive_path, expected_family=_FAMILY, expected_tool=_TOOL)
    raise PartialImplementationError(tool=_TOOL)

"""Prefetch (`.pf`) parser (week-2 fixture-only stub).

Family `SysMain` — Windows' Superfetch service writes prefetch traces for
every executed binary, MAM-compressed since Win 10. Real implementation in
week 3 will use `libscca` Python bindings (last commit recency to be
re-verified at week-3 entry per /deep-r library-landscape research).
"""

from __future__ import annotations

from pathlib import Path

from sanctum.events import ExecutionEvent
from sanctum.parsers._errors import ArtifactNotFoundError, PartialImplementationError
from sanctum.parsers._fixture_io import fixture_mode, load_sidecar

_TOOL = "get_prefetch"
_FAMILY = "SysMain"


def parse_prefetch(pf_path: Path) -> list[ExecutionEvent]:
    if not pf_path.is_file():
        raise ArtifactNotFoundError(f"prefetch file not found: {pf_path}")
    if fixture_mode():
        return load_sidecar(pf_path, expected_family=_FAMILY, expected_tool=_TOOL)
    raise PartialImplementationError(tool=_TOOL)

"""Sysmon EVTX parser (week-2 fixture-only stub).

Family `Kernel-ETW` — covers both Microsoft-Windows-Sysmon/Operational
Event ID 1 (process create) and Security Event ID 4688 (audit-process-
creation); both flow from kernel ETW providers and share a trust root.
Tool name `get_sysmon_4688` matches `sanctum.families.TOOL_TO_FAMILY`.
Real implementation in week 3 likely via `python-evtx` (status to
re-verify at week-3 entry per /deep-r library-landscape research).
"""

from __future__ import annotations

from pathlib import Path

from sanctum.events import ExecutionEvent
from sanctum.parsers._errors import ArtifactNotFoundError, PartialImplementationError
from sanctum.parsers._fixture_io import fixture_mode, load_sidecar

_TOOL = "get_sysmon_4688"
_FAMILY = "Kernel-ETW"


def parse_sysmon(evtx_path: Path) -> list[ExecutionEvent]:
    if not evtx_path.is_file():
        raise ArtifactNotFoundError(f"EVTX file not found: {evtx_path}")
    if fixture_mode():
        return load_sidecar(evtx_path, expected_family=_FAMILY, expected_tool=_TOOL)
    raise PartialImplementationError(tool=_TOOL)

"""BAM (Background Activity Moderator) parser (week-2 fixture-only stub).

Family `Background-service` — SYSTEM hive at
``ControlSet00X\\Services\\bam\\State\\UserSettings\\<SID>\\``. Each value
name is an NT-namespace path; each value is a 16-byte FILETIME (8 bytes
little-endian) plus padding. Trust root is the `bam.sys` kernel driver +
SYSTEM hive — distinct from the AppCompat / SysMain / Kernel-ETW
subsystems. Week-3 real implementation must handle orphan-SID cases —
see `project_followups_threat_model.md` memory for the parser-logic
note that survived from the threat-model work.
"""

from __future__ import annotations

from pathlib import Path

from sanctum.events import ExecutionEvent
from sanctum.parsers._errors import ArtifactNotFoundError, PartialImplementationError
from sanctum.parsers._fixture_io import fixture_mode, load_sidecar

_TOOL = "get_bam"
_FAMILY = "Background-service"


def parse_bam(hive_path: Path) -> list[ExecutionEvent]:
    if not hive_path.is_file():
        raise ArtifactNotFoundError(f"SYSTEM hive not found: {hive_path}")
    if fixture_mode():
        return load_sidecar(hive_path, expected_family=_FAMILY, expected_tool=_TOOL)
    raise PartialImplementationError(tool=_TOOL)

"""UserAssist parser (week-2 fixture-only stub).

Family `Explorer/NTUSER` — NTUSER.DAT at
``Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\<GUID>\\Count``.
Value names are ROT-13 encoded full executable paths; values are packed
binary (run count + last-execution FILETIME). Trust root is
`explorer.exe` writing to per-user NTUSER.dat. Real implementation in
week 3 via the same registry library used for Amcache; the ROT-13 step
and FILETIME-from-bytes are the family-specific decoders.
"""

from __future__ import annotations

from pathlib import Path

from sanctum.events import ExecutionEvent
from sanctum.parsers._errors import ArtifactNotFoundError, PartialImplementationError
from sanctum.parsers._fixture_io import fixture_mode, load_sidecar

_TOOL = "get_userassist"
_FAMILY = "Explorer/NTUSER"


def parse_userassist(hive_path: Path) -> list[ExecutionEvent]:
    if not hive_path.is_file():
        raise ArtifactNotFoundError(f"NTUSER.DAT not found: {hive_path}")
    if fixture_mode():
        return load_sidecar(hive_path, expected_family=_FAMILY, expected_tool=_TOOL)
    raise PartialImplementationError(tool=_TOOL)

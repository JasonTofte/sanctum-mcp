"""ShimCache (AppCompatCache) parser (week-2 fixture-only stub).

Lives in the SYSTEM hive at
``ControlSet00X\\Control\\Session Manager\\AppCompatCache``. Same family as
Amcache (CLAUDE.md invariant 5: AppCompat collapses both, since they share
a trust root and are defeated together). The `tool` discriminator on the
sidecar is what keeps the two parsers from silently swapping data when
pointed at the same on-disk path — see `_fixture_io.load_sidecar`.

Real implementation arrives in week 3; until then this module raises
:class:`PartialImplementationError` outside fixture mode.
"""

from __future__ import annotations

from pathlib import Path

from sanctum.events import ExecutionEvent
from sanctum.parsers._errors import ArtifactNotFoundError, PartialImplementationError
from sanctum.parsers._fixture_io import fixture_mode, load_sidecar

_TOOL = "get_shimcache"
_FAMILY = "AppCompat"


def parse_shimcache(hive_path: Path) -> list[ExecutionEvent]:
    if not hive_path.is_file():
        raise ArtifactNotFoundError(f"SYSTEM hive not found: {hive_path}")
    if fixture_mode():
        return load_sidecar(hive_path, expected_family=_FAMILY, expected_tool=_TOOL)
    raise PartialImplementationError(tool=_TOOL)

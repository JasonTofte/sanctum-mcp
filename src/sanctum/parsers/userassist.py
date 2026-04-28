"""UserAssist parser.

Walks the per-user ``NTUSER.DAT`` hive at
``\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\<GUID>\\Count``
via :mod:`regipy`. Family ``Explorer/NTUSER`` — trust root is
``explorer.exe`` writing to the per-user hive, distinct from the
SYSTEM-hive AppCompat / Background-service families.

**Why ROT-13 names matter and what the prefixes mean.** Windows obscures
the value names with a single ROT-13 pass — purely a deterrent against
casual hex-editing, not a security boundary. After decoding, names
typically begin with one of:

- ``UEME_RUNPATH:<full path>`` — explorer-launched .exe by full path.
- ``UEME_RUNPIDL:<full path>`` — explorer-launched shortcut whose target
  resolves to a path. Same execution semantics as RUNPATH for our use.
- ``UEME_CTLSESSION`` / ``UEME_CTLCUACOUNT`` — internal counters, not
  executions. Dropped.

KNOWNFOLDERID-rooted paths like ``{6D809377-...}\\path\\bin.exe`` are
preserved verbatim — explorer writes them this way and the GUID prefix
is itself forensic evidence (which special folder the binary launched
from).

**Binary value layout (UserAssist version 5, Win 7+).** 72 bytes:

- ``[0:4]``   session id (DWORD LE)
- ``[4:8]``   run count (DWORD LE; Win 10+ starts at 1, no historical
  ``-5`` offset)
- ``[8:12]``  focus count (DWORD LE)
- ``[12:16]`` focus time, milliseconds (DWORD LE)
- ``[60:68]`` last execution FILETIME (QWORD LE — 100-ns ticks since
  1601-01-01 UTC)

We use the FILETIME at offset 60 as ``ExecutionEvent.timestamp`` — that
is the canonical "when explorer last observed this binary launched"
value. Non-72-byte values are dropped (older format-version 3 had
16 bytes; we don't currently target XP/Vista).

**Why drop UEME_CTLSESSION rather than raise.** Session counters and
``CUACOUNT`` rows live alongside execution rows under the same Count
subkey. They are a normal part of the artifact, not a tamper signal —
per-row leniency keeps the parser focused on execution evidence and
defers tamper detection to the family-gate / aggregate layer.
"""

from __future__ import annotations

import codecs
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException, RegistryParsingException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from sanctum.events import ExecutionEvent
from sanctum.families import FAMILY_EXPLORER_NTUSER
from sanctum.parsers._errors import ArtifactMalformedError, ArtifactNotFoundError
from sanctum.parsers._fixture_io import (
    _FIELD_DELIMITER_PATTERN,
    PROGRAM_PATH_MAX_LEN,
    _safe_field,
    fixture_mode,
    load_sidecar,
)

_TOOL = "get_userassist"
_FAMILY = FAMILY_EXPLORER_NTUSER

_USERASSIST_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

# UserAssist version 5 (Win 7+) value layout. We require exactly this size;
# other sizes are either older XP/Vista format (8/16 bytes) or noise.
_UA_V5_SIZE = 72
_UA_RUN_COUNT_OFFSET = 4
_UA_FOCUS_COUNT_OFFSET = 8
_UA_FOCUS_TIME_OFFSET = 12
_UA_LAST_RUN_OFFSET = 60

# Names we explicitly skip — these are session/UI counters, not executions.
# Match after ROT-13 decoding and uppercasing for case-insensitive comparison.
_SKIP_NAME_PREFIXES = (
    "UEME_CTLSESSION",
    "UEME_CTLCUACOUNT",
    "UEME_UISCUT",
    "UEME_UITOOLBAR",
    "UEME_UIQCUT",
    "UEME_UIHOTKEY",
    "UEME_UIMENU",
)

# Path-bearing prefixes we strip when present. Both flavors (full path
# from RUNPATH, resolved shortcut target from RUNPIDL) carry a path and
# count as execution evidence.
_PATH_PREFIXES = ("UEME_RUNPATH:", "UEME_RUNPIDL:")


def parse_userassist(hive_path: Path) -> list[ExecutionEvent]:
    if not hive_path.is_file():
        raise ArtifactNotFoundError(f"NTUSER.DAT not found: {_safe_field(hive_path.name)}")
    if fixture_mode():
        return load_sidecar(hive_path, expected_family=_FAMILY, expected_tool=_TOOL)
    return _parse_userassist_real(hive_path)


def _parse_userassist_real(hive_path: Path) -> list[ExecutionEvent]:
    # No try/finally around `hive` lifetime — regipy holds no OS resource
    # post-construction. See `amcache._parse_amcache_real` for the
    # canonical verification.
    try:
        hive = RegistryHive(str(hive_path))
    except (RegistryParsingException, OSError) as exc:
        raise ArtifactMalformedError(
            f"NTUSER.DAT {_safe_field(hive_path.name)} could not be opened: "
            f"{_safe_field(str(exc))}"
        ) from exc

    try:
        userassist = hive.get_key(_USERASSIST_PATH)
    except RegistryKeyNotFoundException:
        # Hive exists but UserAssist key absent — possible on a freshly-
        # provisioned profile or one where Explorer has never run. Empty
        # is the right answer.
        return []
    except RegistryParsingException as exc:
        raise ArtifactMalformedError(
            f"NTUSER.DAT {_safe_field(hive_path.name)} parse failure traversing "
            f"{_USERASSIST_PATH}: {_safe_field(str(exc))}"
        ) from exc

    events: list[ExecutionEvent] = []
    for guid_subkey in userassist.iter_subkeys():
        try:
            count_key = guid_subkey.get_subkey("Count")
        except RegistryKeyNotFoundException:
            continue
        except RegistryParsingException:
            # Tampering of one GUID's Count tree shouldn't lose the others.
            continue

        guid_label = getattr(guid_subkey, "name", "") or ""
        for event in _events_from_count_key(
            count_key,
            guid_label=guid_label,
            hive_path=hive_path,
            row_index_base=len(events),
        ):
            events.append(event)
    return events


def _events_from_count_key(
    count_key: Any,
    *,
    guid_label: str,
    hive_path: Path,
    row_index_base: int,
) -> list[ExecutionEvent]:
    try:
        values_list = list(count_key.iter_values(as_json=False))
    except RegistryParsingException:
        return []

    out: list[ExecutionEvent] = []
    for v in values_list:
        if getattr(v, "is_corrupted", False):
            continue
        event = _build_event_from_value(
            value_name=v.name,
            value_bytes=v.value,
            guid_label=guid_label,
            hive_path=hive_path,
            row_index=row_index_base + len(out),
        )
        if event is not None:
            out.append(event)
    return out


def _build_event_from_value(
    *,
    value_name: Any,
    value_bytes: Any,
    guid_label: str,
    hive_path: Path,
    row_index: int,
) -> ExecutionEvent | None:
    if not isinstance(value_name, str) or not value_name:
        return None

    decoded = codecs.decode(value_name, "rot_13")
    upper = decoded.upper()
    for skip in _SKIP_NAME_PREFIXES:
        if upper.startswith(skip):
            return None

    program_path = decoded
    for prefix in _PATH_PREFIXES:
        if upper.startswith(prefix):
            program_path = decoded[len(prefix) :]
            break

    if not program_path:
        return None
    if len(program_path) > PROGRAM_PATH_MAX_LEN:
        return None
    if _FIELD_DELIMITER_PATTERN.search(program_path):
        return None

    if not isinstance(value_bytes, (bytes, bytearray)):
        return None
    if len(value_bytes) != _UA_V5_SIZE:
        return None

    try:
        run_count = struct.unpack_from("<I", value_bytes, _UA_RUN_COUNT_OFFSET)[0]
        focus_count = struct.unpack_from("<I", value_bytes, _UA_FOCUS_COUNT_OFFSET)[0]
        focus_time_ms = struct.unpack_from("<I", value_bytes, _UA_FOCUS_TIME_OFFSET)[0]
        filetime = struct.unpack_from("<Q", value_bytes, _UA_LAST_RUN_OFFSET)[0]
    except struct.error:
        return None

    timestamp = _wintime_to_aware_utc(filetime)
    if timestamp is None:
        return None

    extras: dict[str, str] = {
        "row_index": str(row_index),
        "userassist_guid": guid_label,
        "run_count": str(run_count),
        "focus_count": str(focus_count),
        "focus_time_ms": str(focus_time_ms),
    }

    return ExecutionEvent(
        tool=_TOOL,
        family=_FAMILY,
        program_path=program_path,
        timestamp=timestamp,
        source_artifact=hive_path.as_posix(),
        evidence_size_bytes=len(value_bytes),
        extras=extras,
    )


def _wintime_to_aware_utc(filetime: Any) -> datetime | None:
    if not isinstance(filetime, int) or filetime <= 0:
        return None
    try:
        dt = convert_wintime(filetime)
    except (ValueError, OverflowError):
        return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

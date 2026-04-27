"""BAM (Background Activity Moderator) parser.

Walks the SYSTEM hive at
``\\<active-control-set>\\Services\\bam\\State\\UserSettings\\<SID>\\`` via
:mod:`regipy`. Family ``Background-service`` — trust root is the
``bam.sys`` kernel driver writing to the SYSTEM hive on behalf of the
Background Activity Moderator service. Distinct from AppCompat / SysMain
/ Kernel-ETW subsystems: tampering with one does not flush BAM.

**Active control set selection.** Live SYSTEM hives expose multiple
``ControlSet00X`` snapshots and a ``\\Select\\Current`` REG_DWORD that
names the active one. We resolve dynamically rather than hardcoding
``ControlSet001`` because forensically-acquired hives sometimes have
``Current=2`` after an OS rollback. Falls back to ``ControlSet001`` if
``\\Select\\Current`` is missing or unparseable — empty-or-missing is a
valid forensic answer ("BAM never observed activity"), distinct from a
tamper signal.

**Per-value layout.** Each value name under a SID subkey is an
NT-namespace path like
``\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe``. The
value bytes are a packed structure starting with a Windows FILETIME
(8 bytes LE = QWORD of 100-ns ticks since 1601-01-01 UTC) — the
canonical "when bam.sys last observed this binary's foreground
activity" signal. Older Windows builds appended a sequence-number
DWORD; modern builds also include extra fields, all of which we
ignore. Values shorter than 8 bytes are dropped; longer values are
trimmed to the leading FILETIME.

**Orphan-SID classification (followups #4).** BAM retains
``UserSettings\\<SID>`` keys after the underlying user account is
deleted — most notably ``defaultuser0`` (the OOBE setup account
Windows creates and deletes during install, which leaves a
``RID=1001`` SID with no SAM-resolvable backing). Treating these as
forensic evidence would generate false-positive deleted-user
findings on every freshly-provisioned machine. We classify each SID
into one of:

- ``system_account`` — well-known SIDs ``S-1-5-18`` (LocalSystem),
  ``S-1-5-19`` (LocalService), ``S-1-5-20`` (NetworkService). Counted.
- ``builtin_admin`` / ``builtin_guest`` / ``builtin_default`` /
  ``builtin_wdag`` — RIDs 500/501/503/504. Counted, but these
  accounts are typically disabled on a stock Win 11 install.
- ``orphan_oobe`` — RID 1001 with no SAM cross-reference. The
  defaultuser0 fingerprint per public DFIR knowledge (Khatri 2020).
  **Dropped** from event output entirely; an orphan_oobe-only audit
  call therefore returns ``[]`` and contributes zero family
  corroboration.
- ``user_unverified`` — RID ≥ 1000 (other than 1001). Counted, but
  flagged in ``extras.sid_status`` so analysts know we did not
  cross-reference SAM. SAM-aware classification (live_user /
  disabled_user / orphan_unknown) is deferred to a follow-up that
  needs ``sanctum.parsers.sam`` to exist; until then the parser is
  conservative-include rather than conservative-exclude (an active
  user's evidence not surfacing is worse than the analyst seeing
  ``sid_status=user_unverified``).

The full SAM-cross-referenced four-state classifier from
``project_followups_threat_model.md`` item 4 lands when a SAM parser
ships; the public-DFIR-knowledge attribution and the test scaffolding
for all four states are already in place to receive it.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException, RegistryParsingException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from sanctum.events import ExecutionEvent
from sanctum.parsers._errors import ArtifactMalformedError, ArtifactNotFoundError
from sanctum.parsers._fixture_io import (
    _FIELD_DELIMITER_PATTERN,
    PROGRAM_PATH_MAX_LEN,
    _safe_field,
    fixture_mode,
    load_sidecar,
)

_TOOL = "get_bam"
_FAMILY = "Background-service"

_SELECT_CURRENT_PATH = r"\Select"
_SELECT_CURRENT_VALUE = "Current"
_DEFAULT_CONTROLSET = 1

_BAM_SUBPATH = r"Services\bam\State\UserSettings"

# SID-to-status classification table. The shape `(prefix, rid_int) → status`
# captures the cases enumerated in the docstring. Anything not matched
# routes through `_classify_user_sid` which inspects RID for OOBE detection.
_WELLKNOWN_SYSTEM_SIDS: dict[str, str] = {
    "S-1-5-18": "system_account",
    "S-1-5-19": "system_account",
    "S-1-5-20": "system_account",
}

_USER_RID_NAMED: dict[int, str] = {
    500: "builtin_admin",
    501: "builtin_guest",
    503: "builtin_default",
    504: "builtin_wdag",
    # 1001 is the documented OOBE defaultuser0 fingerprint; see module
    # docstring + project_followups_threat_model.md item 4.
    1001: "orphan_oobe",
}

# Statuses that contribute zero ExecutionEvents to the output stream.
# Currently only orphan_oobe — see docstring on conservative-include policy.
_DROP_STATUSES = frozenset({"orphan_oobe"})


def parse_bam(hive_path: Path) -> list[ExecutionEvent]:
    if not hive_path.is_file():
        raise ArtifactNotFoundError(f"SYSTEM hive not found: {hive_path}")
    if fixture_mode():
        return load_sidecar(hive_path, expected_family=_FAMILY, expected_tool=_TOOL)
    return _parse_bam_real(hive_path)


def _parse_bam_real(hive_path: Path) -> list[ExecutionEvent]:
    try:
        hive = RegistryHive(str(hive_path))
    except (RegistryParsingException, OSError) as exc:
        raise ArtifactMalformedError(
            f"SYSTEM hive {_safe_field(hive_path.name)} could not be opened: "
            f"{_safe_field(str(exc))}"
        ) from exc

    cs_index = _resolve_active_controlset(hive)
    bam_path = rf"\ControlSet{cs_index:03d}\{_BAM_SUBPATH}"

    try:
        usersettings = hive.get_key(bam_path)
    except RegistryKeyNotFoundException:
        # BAM service has never recorded activity (or this isn't a SYSTEM
        # hive). Empty is the right answer — an absent BAM tree is a valid
        # forensic state, not a tamper signal at the per-parser layer.
        return []
    except RegistryParsingException as exc:
        raise ArtifactMalformedError(
            f"SYSTEM hive {_safe_field(hive_path.name)} parse failure traversing "
            f"{_safe_field(bam_path)}: {_safe_field(str(exc))}"
        ) from exc

    events: list[ExecutionEvent] = []
    for sid_subkey in usersettings.iter_subkeys():
        sid = getattr(sid_subkey, "name", "") or ""
        status = _classify_sid(sid)
        if status in _DROP_STATUSES:
            # orphan_oobe events are not forensic evidence on a freshly-
            # provisioned Windows install — defaultuser0 is OS noise. Drop
            # before emitting so the family-corroboration gate isn't fed
            # phantom user-attributed executions.
            continue

        for event in _events_from_sid_subkey(
            sid_subkey,
            sid=sid,
            sid_status=status,
            hive_path=hive_path,
            row_index_base=len(events),
        ):
            events.append(event)
    return events


def _resolve_active_controlset(hive: Any) -> int:
    try:
        select_key = hive.get_key(_SELECT_CURRENT_PATH)
    except (RegistryKeyNotFoundException, RegistryParsingException):
        return _DEFAULT_CONTROLSET

    try:
        for v in select_key.iter_values(as_json=False):
            if v.name == _SELECT_CURRENT_VALUE:
                if isinstance(v.value, int) and 1 <= v.value <= 99:
                    return v.value
                break
    except RegistryParsingException:
        pass
    return _DEFAULT_CONTROLSET


def _classify_sid(sid: str) -> str:
    """Map a SID string to a status label per the docstring table."""
    if not sid:
        return "user_unverified"
    if sid in _WELLKNOWN_SYSTEM_SIDS:
        return _WELLKNOWN_SYSTEM_SIDS[sid]
    if not sid.startswith("S-1-5-21-"):
        # Other authorities (S-1-1 World, S-1-2 Local, etc.) shouldn't
        # appear under BAM in practice, but if they do we don't have a
        # confident classifier — fall through to user_unverified.
        return "user_unverified"
    rid = _extract_rid(sid)
    if rid is None:
        return "user_unverified"
    return _USER_RID_NAMED.get(rid, "user_unverified")


def _extract_rid(sid: str) -> int | None:
    last_dash = sid.rfind("-")
    if last_dash == -1 or last_dash == len(sid) - 1:
        return None
    tail = sid[last_dash + 1 :]
    try:
        return int(tail)
    except ValueError:
        return None


def _events_from_sid_subkey(
    sid_subkey: Any,
    *,
    sid: str,
    sid_status: str,
    hive_path: Path,
    row_index_base: int,
) -> list[ExecutionEvent]:
    try:
        values_list = list(sid_subkey.iter_values(as_json=False))
    except RegistryParsingException:
        return []

    out: list[ExecutionEvent] = []
    for v in values_list:
        if getattr(v, "is_corrupted", False):
            continue
        # Skip the placeholder values BAM writes alongside execution rows
        # (``Version``, ``SequenceNumber``). They aren't binary paths.
        if not isinstance(v.name, str) or not v.name.startswith("\\"):
            continue
        event = _build_event_from_value(
            value_name=v.name,
            value_bytes=v.value,
            sid=sid,
            sid_status=sid_status,
            hive_path=hive_path,
            row_index=row_index_base + len(out),
        )
        if event is not None:
            out.append(event)
    return out


def _build_event_from_value(
    *,
    value_name: str,
    value_bytes: Any,
    sid: str,
    sid_status: str,
    hive_path: Path,
    row_index: int,
) -> ExecutionEvent | None:
    if len(value_name) > PROGRAM_PATH_MAX_LEN:
        return None
    if _FIELD_DELIMITER_PATTERN.search(value_name):
        return None

    if not isinstance(value_bytes, (bytes, bytearray)):
        return None
    if len(value_bytes) < 8:
        return None

    try:
        filetime = struct.unpack_from("<Q", value_bytes, 0)[0]
    except struct.error:
        return None

    timestamp = _wintime_to_aware_utc(filetime)
    if timestamp is None:
        return None

    extras: dict[str, str] = {
        "row_index": str(row_index),
        "sid": sid,
        "sid_status": sid_status,
        "sid_resolution": "pattern_only",
    }

    return ExecutionEvent(
        tool=_TOOL,
        family=_FAMILY,
        program_path=value_name,
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

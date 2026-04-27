"""Amcache.hve parser.

Real path walks ``\\Root\\InventoryApplicationFile`` via :mod:`regipy` and
maps each child subkey to an :class:`~sanctum.events.ExecutionEvent`. The
fixture path (``SANCTUM_USE_FIXTURE_SIDECAR=1``) remains the fast unit-
test entry — additive to the real path, not a replacement, because tests
that exercise sanitization / family-gate / ledger mechanics shouldn't
need a real registry hive on disk.

**Why InventoryApplicationFile (not legacy `\\Root\\File`).** Windows 10
1709 (Oct 2017) introduced the InventoryApplicationFile schema and is the
deployment universe Sanctum operates on. Older hives have execution
records under `\\Root\\File\\<volume-guid>\\` — adding that branch is a
follow-up, not a v1 deliverable. Pre-1709 hives currently surface as
`[]` (well-formed, no rows) rather than an error: empty is a valid
forensic answer ("no AppCompat evidence of this binary"), and refusing
to parse legacy hives would surface as a tamper-suspected refusal at
the family-gate which is the wrong signal.

**Why subkey-last-write-time as ``timestamp``.** Each
InventoryApplicationFile subkey is written/updated by the Application
Experience Service when it observes a binary. The key's last-modified
FILETIME is therefore the canonical "when did this OS subsystem first
see this binary" timestamp. The per-value `LinkDate` field is the PE
linker date — useful evidence in `extras` but NOT the right value for
``ExecutionEvent.timestamp`` (a backdated linker timestamp is trivial
for an attacker to produce; the registry-key write time is what
*Windows* observed and is harder to forge from userland).
"""

from __future__ import annotations

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
    EVIDENCE_SIZE_MAX,
    PROGRAM_PATH_MAX_LEN,
    _safe_field,
    fixture_mode,
    load_sidecar,
)

_TOOL = "get_amcache"
_FAMILY = "AppCompat"

_INVENTORY_PATH = r"\Root\InventoryApplicationFile"

# Bound the per-row extras-string length so an attacker who controls a
# binary's PE metadata (ProductName, Publisher) cannot smuggle a
# multi-kilobyte payload into the LLM's context via Sanctum's evidence
# wrapper. 256 chars clears any sane real-world value with headroom.
_EXTRAS_STRING_MAX = 256

# Optional Amcache value-names worth preserving in extras when present.
# Strings only — numeric fields (Size, LinkDate, Usn) live elsewhere or
# are dropped, since `extras` is `Mapping[str, str]` per the
# `ExecutionEvent` contract. Names are taken from the canonical
# Win10/11 InventoryApplicationFile schema; the regipy `amcache` plugin
# `underscore`-converts these but we keep the on-the-wire registry names
# verbatim so the audit ledger reads as a faithful registry transcript.
_OPTIONAL_EXTRAS_FIELDS = (
    "ProductName",
    "ProductVersion",
    "Publisher",
    "BinaryType",
    "BinFileVersion",
    "Language",
    "Version",
)


def parse_amcache(hive_path: Path) -> list[ExecutionEvent]:
    if not hive_path.is_file():
        raise ArtifactNotFoundError(f"Amcache hive not found: {hive_path}")
    if fixture_mode():
        return load_sidecar(hive_path, expected_family=_FAMILY, expected_tool=_TOOL)
    return _parse_amcache_real(hive_path)


def _parse_amcache_real(hive_path: Path) -> list[ExecutionEvent]:
    try:
        hive = RegistryHive(str(hive_path))
    except (RegistryParsingException, OSError) as exc:
        # Unparseable bytes / wrong file type → data fault, not I/O fault.
        # Scrub the exception text: regipy's parser embeds attacker-influenced
        # offsets and bytes which would otherwise reach the LLM through the
        # FastMCP `isError` channel (success-path sanitizers don't fire on
        # raised exceptions — see `feedback_error_channel_bypass.md`).
        raise ArtifactMalformedError(
            f"Amcache hive {_safe_field(hive_path.name)} could not be opened: "
            f"{_safe_field(str(exc))}"
        ) from exc

    try:
        inventory = hive.get_key(_INVENTORY_PATH)
    except RegistryKeyNotFoundException:
        # Pre-1709 hive (or InventoryApplicationFile pruned). Empty is the
        # right answer — see module docstring rationale.
        return []
    except RegistryParsingException as exc:
        raise ArtifactMalformedError(
            f"Amcache hive {_safe_field(hive_path.name)} parse failure traversing "
            f"{_INVENTORY_PATH}: {_safe_field(str(exc))}"
        ) from exc

    events: list[ExecutionEvent] = []
    for subkey in inventory.iter_subkeys():
        event = _build_event_from_subkey(
            subkey,
            hive_path=hive_path,
            row_index=len(events),
        )
        if event is not None:
            events.append(event)
    return events


def _build_event_from_subkey(
    subkey: Any,
    *,
    hive_path: Path,
    row_index: int,
) -> ExecutionEvent | None:
    """Map one InventoryApplicationFile subkey to an `ExecutionEvent`.

    Returns ``None`` for rows that lack a usable `LowerCaseLongPath` or
    fail per-value sanity checks. We **drop** those rows rather than
    raise: a single malformed row in an otherwise-good hive is a noisy-
    Windows artifact, not a tamper signal. Tampering is detected at a
    higher layer (`sanctum.deception`) by looking at AGGREGATE patterns
    (e.g., InventoryApplicationFile entirely missing on a system that
    has SysMain Prefetch evidence — flush fingerprint), not by per-row
    strict-rejection here.
    """

    try:
        values_list = list(subkey.iter_values(as_json=False))
    except RegistryParsingException:
        return None

    values: dict[str, Any] = {}
    for v in values_list:
        if getattr(v, "is_corrupted", False):
            continue
        values[v.name] = v.value

    program_path = values.get("LowerCaseLongPath")
    if not isinstance(program_path, str) or not program_path:
        return None
    if len(program_path) > PROGRAM_PATH_MAX_LEN:
        return None
    if _FIELD_DELIMITER_PATTERN.search(program_path):
        # NUL/control-char/angle-bracket in a Windows path is either
        # corruption or attempted prompt smuggling. Either way, drop.
        return None

    timestamp = _wintime_to_aware_utc(getattr(subkey.header, "last_modified", None))
    if timestamp is None:
        return None

    size = _coerce_size(values.get("Size"))

    extras: dict[str, str] = {
        "row_index": str(row_index),
        "amcache_key": "InventoryApplicationFile",
        "sha1": _strip_file_id_prefix(values.get("FileId")),
    }
    for field_name in _OPTIONAL_EXTRAS_FIELDS:
        raw = values.get(field_name)
        if not isinstance(raw, str):
            continue
        if not raw:
            continue
        if _FIELD_DELIMITER_PATTERN.search(raw):
            continue
        extras[field_name] = raw[:_EXTRAS_STRING_MAX]

    return ExecutionEvent(
        tool=_TOOL,
        family=_FAMILY,
        program_path=program_path,
        timestamp=timestamp,
        source_artifact=hive_path.as_posix(),
        evidence_size_bytes=size,
        extras=extras,
    )


def _wintime_to_aware_utc(filetime: Any) -> datetime | None:
    """Convert a Windows FILETIME (100-ns intervals since 1601-01-01 UTC)
    to a timezone-aware UTC ``datetime``. Returns ``None`` for missing or
    sentinel-zero values.

    `regipy.utils.convert_wintime` returns naive UTC; we wrap it so the
    ``ExecutionEvent`` tz-aware invariant holds.
    """

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


def _coerce_size(raw: Any) -> int:
    """Best-effort `Size` coercion. Amcache stores it as REG_QWORD on
    modern hives but legacy entries occasionally carry a hex string.
    Out-of-range / wrong-type values fall through to ``0`` rather than
    raising — see `_build_event_from_subkey` rationale on per-row leniency.
    """

    if isinstance(raw, bool):
        return 0
    if isinstance(raw, int) and 0 <= raw <= EVIDENCE_SIZE_MAX:
        return raw
    if isinstance(raw, str):
        try:
            parsed = int(raw, 16) if raw.startswith(("0x", "0X")) else int(raw)
        except ValueError:
            return 0
        if 0 <= parsed <= EVIDENCE_SIZE_MAX:
            return parsed
    return 0


def _strip_file_id_prefix(raw: Any) -> str:
    """Amcache `FileId` is canonically ``"0000" + sha1_hex_lower``.
    Returns the 40-char SHA-1 lowercase, or 40 zeros if the field is
    missing or malformed (matches the fixture-path convention so the
    two paths produce indistinguishable extras for the same hive).
    """

    zero = "0" * 40
    if not isinstance(raw, str):
        return zero
    if len(raw) != 44 or not raw.startswith("0000"):
        return zero
    candidate = raw[4:].lower()
    if any(c not in "0123456789abcdef" for c in candidate):
        return zero
    return candidate

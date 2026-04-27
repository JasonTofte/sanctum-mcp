"""ShimCache (AppCompatCache) parser.

Walks the SYSTEM hive at
``\\<active-control-set>\\Control\\Session Manager\\AppCompatCache\\AppCompatCache``
via :mod:`regipy`. Family ``AppCompat`` — same trust root as Amcache (CLAUDE.md
invariant 5: AppCompat collapses both, since they share the
``BaseFlushAppcompatCache`` / ``AntiForensic.NET`` defeat surface and are
defeated together). The ``tool`` discriminator on the sidecar (and on the
``ExecutionEvent`` records) is what keeps Amcache and ShimCache from silently
swapping evidence — see ``_fixture_io.load_sidecar``.

**Why we delegate the binary blob to regipy.** ShimCache stores all entries in
a single REG_BINARY value whose layout depends on Windows version
(WinXP/Vista/7/8/8.1/10 each differ; Win10 Creators Update shifted the magic 4
bytes). regipy ships a Mandiant-derived parser at
``regipy.plugins.system.external.ShimCacheParser.get_shimcache_entries`` —
489 lines, Apache-2.0 — which already handles every layout we care about.
Reimplementing that ourselves would be 489 lines of struct-twiddling for zero
forensic benefit. We *call* the parser; we do NOT trust its output blindly:
each yielded dict is normalized, sanity-checked, and dropped if it lacks a
usable path or timestamp.

**Active-control-set selection.** Same convention as :mod:`sanctum.parsers.bam`
— resolve ``\\Select\\Current`` to find the active ``ControlSet00X``. We
deliberately do NOT walk every control set: ShimCache entries are duplicated
across snapshots, and counting both would inflate the family-corroboration
gate. Falls back to ``ControlSet001`` if ``\\Select\\Current`` is missing or
unparseable.

**Per-row mapping.**

- ``last_mod_date`` → ``ExecutionEvent.timestamp``. regipy's
  ``convert_filetime`` returns a pytz-aware UTC datetime; we still validate
  ``tzinfo is not None`` defensively (a future regipy bump shouldn't silently
  break the tz-aware invariant).
- ``path`` → ``ExecutionEvent.program_path``. Drop rows where path is the
  literal string ``"None"`` (regipy emits this when the encoded path length
  is zero — an unusable row, not forensic evidence).
- ``exec_flag`` (Win 8 only) and ``file_size`` (NT5 only) → ``extras``,
  preserved verbatim as evidence of *which* layout the hive was. Win 10 has
  no exec_flag (every entry there represents an exec-attempt by definition),
  so its absence is normal, not a parser bug.

**Per-row leniency.** Same convention as Amcache/UserAssist/BAM: a single
malformed entry in an otherwise-good cache is noisy-Windows behavior, not a
tamper signal. Drop the row, keep parsing. Aggregate tamper detection
(an empty ShimCache *despite* a populated Amcache + Prefetch + UserAssist
chain) lives in :mod:`sanctum.deception`. The ``BaseFlushAppcompatCache``
fingerprint is detected by *family-coupled absence*, not by per-row
strictness.

**Error-channel scrubbing.** ``get_shimcache_entries`` raises a generic
``Exception`` for unrecognised magic — message embeds the raw 4-byte magic.
We catch broadly and re-raise as ``ArtifactMalformedError``, scrubbing the
exception text via ``_safe_field`` before it lands in a string the FastMCP
``isError`` channel will serialise to the LLM (success-path sanitizers don't
fire on raised exceptions — see ``feedback_error_channel_bypass.md``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException, RegistryParsingException
from regipy.plugins.system.external.ShimCacheParser import get_shimcache_entries
from regipy.registry import RegistryHive

from sanctum.events import ExecutionEvent
from sanctum.families import FAMILY_APPCOMPAT
from sanctum.parsers._errors import (
    ArtifactMalformedError,
    ArtifactNotFoundError,
    PartialParseError,
)
from sanctum.parsers._fixture_io import (
    _FIELD_DELIMITER_PATTERN,
    EVIDENCE_SIZE_MAX,
    PROGRAM_PATH_MAX_LEN,
    _safe_field,
    fixture_mode,
    load_sidecar,
)

_TOOL = "get_shimcache"
_FAMILY = FAMILY_APPCOMPAT

_SELECT_CURRENT_PATH = r"\Select"
_SELECT_CURRENT_VALUE = "Current"
_DEFAULT_CONTROLSET = 1

_APPCOMPAT_SUBPATH = r"Control\Session Manager\AppCompatCache"
_APPCOMPAT_VALUE = "AppCompatCache"

# regipy emits this string when a ShimCache row's encoded path length is
# zero. It's a cache-housekeeping placeholder, not forensic evidence —
# treat as a drop signal, not a path.
_NULL_PATH_SENTINEL = "None"


def parse_shimcache(hive_path: Path) -> list[ExecutionEvent]:
    if not hive_path.is_file():
        raise ArtifactNotFoundError(f"SYSTEM hive not found: {hive_path}")
    if fixture_mode():
        return load_sidecar(hive_path, expected_family=_FAMILY, expected_tool=_TOOL)
    return _parse_shimcache_real(hive_path)


def _parse_shimcache_real(hive_path: Path) -> list[ExecutionEvent]:
    # No try/finally around `hive` lifetime — regipy holds no OS resource
    # post-construction. See `amcache._parse_amcache_real` for the
    # canonical verification.
    try:
        hive = RegistryHive(str(hive_path))
    except (RegistryParsingException, OSError) as exc:
        raise ArtifactMalformedError(
            f"SYSTEM hive {_safe_field(hive_path.name)} could not be opened: "
            f"{_safe_field(str(exc))}"
        ) from exc

    cs_index = _resolve_active_controlset(hive)
    appcompat_path = rf"\ControlSet{cs_index:03d}\{_APPCOMPAT_SUBPATH}"

    blob = _load_shimcache_blob(hive, hive_path, appcompat_path)
    if blob is None:
        # Empty AppCompatCache subtree is a valid forensic answer — could be
        # a freshly-provisioned VM, could be a flush fingerprint. Either way
        # the tamper signal lives at the family-gate / aggregate layer.
        return []

    return _events_from_blob(blob, hive_path=hive_path)


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


def _load_shimcache_blob(
    hive: Any,
    hive_path: Path,
    appcompat_path: str,
) -> bytes | None:
    """Walk SYSTEM → ``Control\\Session Manager\\AppCompatCache``, return the
    REG_BINARY ``AppCompatCache`` value bytes, or ``None`` if any layer is
    absent / malformed in a way that's a per-hive empty answer rather than a
    parser-wide failure."""

    try:
        appcompat = hive.get_key(appcompat_path)
    except RegistryKeyNotFoundException:
        return None
    except RegistryParsingException as exc:
        raise ArtifactMalformedError(
            f"SYSTEM hive {_safe_field(hive_path.name)} parse failure traversing "
            f"{_safe_field(appcompat_path)}: {_safe_field(str(exc))}"
        ) from exc

    try:
        for v in appcompat.iter_values(as_json=False):
            if v.name != _APPCOMPAT_VALUE:
                continue
            if getattr(v, "is_corrupted", False):
                return None
            if isinstance(v.value, (bytes, bytearray)):
                return bytes(v.value)
            return None
    except RegistryParsingException:
        return None
    return None


def _events_from_blob(blob: bytes, *, hive_path: Path) -> list[ExecutionEvent]:
    """Walk regipy's generator output, returning sanitized ExecutionEvents.

    ``get_shimcache_entries`` returns ``None`` for too-short blobs and may
    raise mid-iteration on a corrupt entry. Two distinct truncation
    signals matter here:

    - **Blob-level**: the call to ``get_shimcache_entries`` itself raises.
      No events have been parsed; surface as :class:`ArtifactMalformedError`
      with no partial-events attached.
    - **Row-level mid-stream**: iteration succeeds for some entries, then
      the underlying generator raises on a corrupt row. Surface as
      :class:`PartialParseError` carrying the rows we already extracted.
      This makes selective-truncation tampering observable at the parser
      boundary instead of being indistinguishable from a clean short
      cache (cross-family row-count compare in ``sanctum.deception``
      remains the aggregate fallback signal).
    """

    try:
        raw_entries = get_shimcache_entries(blob, as_json=False)
    except Exception as exc:
        raise ArtifactMalformedError(
            f"SYSTEM hive {_safe_field(hive_path.name)} ShimCache blob unrecognised: "
            f"{_safe_field(str(exc))}"
        ) from exc

    if raw_entries is None:
        return []

    events: list[ExecutionEvent] = []
    row_index = 0
    iterator = iter(raw_entries)
    while True:
        try:
            entry = next(iterator)
        except StopIteration:
            return events
        except Exception as exc:
            # Mid-stream corruption. Preserve already-parsed events but
            # raise a typed signal so callers can distinguish this from
            # a clean EOF — selective ShimCache truncation is a known
            # anti-forensic technique, and a silent return here would
            # let it look identical to a freshly-provisioned cache.
            raise PartialParseError(
                f"SYSTEM hive {_safe_field(hive_path.name)} ShimCache truncated "
                f"after row {row_index}: "
                f"{_safe_field(type(exc).__name__)}: {_safe_field(str(exc))}",
                events=events,
                cause=exc,
            ) from exc

        event = _build_event_from_entry(
            entry,
            hive_path=hive_path,
            row_index=row_index,
        )
        if event is not None:
            events.append(event)
            row_index += 1


def _build_event_from_entry(
    entry: Any,
    *,
    hive_path: Path,
    row_index: int,
) -> ExecutionEvent | None:
    if not isinstance(entry, dict):
        return None

    program_path = entry.get("path")
    if not isinstance(program_path, str) or not program_path:
        return None
    if program_path == _NULL_PATH_SENTINEL:
        return None
    if len(program_path) > PROGRAM_PATH_MAX_LEN:
        return None
    if _FIELD_DELIMITER_PATTERN.search(program_path):
        return None

    timestamp = _normalize_last_mod(entry.get("last_mod_date"))
    if timestamp is None:
        return None

    size = _coerce_file_size(entry.get("file_size"))

    extras: dict[str, str] = {
        "row_index": str(row_index),
        "appcompat_key": "AppCompatCache",
    }
    exec_flag = entry.get("exec_flag")
    if isinstance(exec_flag, str) and exec_flag in ("True", "False"):
        extras["exec_flag"] = exec_flag

    return ExecutionEvent(
        tool=_TOOL,
        family=_FAMILY,
        program_path=program_path,
        timestamp=timestamp,
        source_artifact=hive_path.as_posix(),
        evidence_size_bytes=size,
        extras=extras,
    )


def _normalize_last_mod(raw: Any) -> datetime | None:
    """regipy's ``convert_filetime`` returns a tz-aware (pytz) UTC datetime,
    or ``None`` on overflow. We accept either, plus defensively repair a
    naive datetime by tagging it UTC (a future regipy version that drops
    pytz wouldn't silently break our tz-aware invariant)."""

    if raw is None:
        return None
    if not isinstance(raw, datetime):
        return None
    if raw.tzinfo is None:
        return raw.replace(tzinfo=timezone.utc)
    return raw


def _coerce_file_size(raw: Any) -> int:
    """ShimCache ``file_size`` exists only on NT5/WinXP entries; absent on
    Win 7+. Out-of-range / wrong-type → 0 (per-row leniency). Same shape as
    Amcache's ``_coerce_size`` for consistency."""

    if isinstance(raw, bool):
        return 0
    if isinstance(raw, int) and 0 <= raw <= EVIDENCE_SIZE_MAX:
        return raw
    return 0

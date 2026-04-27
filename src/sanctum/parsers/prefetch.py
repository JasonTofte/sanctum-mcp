"""Prefetch (`.pf`) parser.

Family ``SysMain`` — Windows' Superfetch / SysMain service writes a `.pf`
trace file under ``\\Windows\\Prefetch\\<EXE>-<hash>.pf`` every time it
observes a binary executing. Trust root: the SysMain user-mode service
backed by ``%SystemRoot%\\Windows\\Prefetch``. Distinct from AppCompat /
Background-service / Kernel-ETW: tampering with one subsystem doesn't flush
SysMain (and vice versa), which is the whole point of the family-coupled
gate (CLAUDE.md invariant 5).

**Why we delegate the binary parse to** :mod:`windowsprefetch`. Each `.pf`
file is a versioned binary structure (v17 = Win 7, v23 = Win 8, v26 = Win
8.1, v30 = Win 10/11) with MAM/LZXPRESS-Huffman compression on Win 10+.
The Adam-Witt-authored ``windowsprefetch`` package (Apache-2.0) handles
the version detection, MAM decompression via ``ntdll.RtlDecompressBufferEx``,
and struct unpacking — ~370 lines we'd otherwise have to maintain ourselves
for zero forensic benefit.

**MAM decompression is Windows-only.** ``DecompressWin10`` resolves
``ctypes.windll.ntdll`` which doesn't exist on Linux/Darwin. On non-Windows
hosts, MAM-compressed `.pf` files (the default on Win 10+) raise
``ArtifactMalformedError`` — the analyst is expected to run Sanctum on
Windows when triaging Win 10/11 prefetch. Uncompressed legacy files
(v17/23/26) parse normally on any OS. The family-corroboration gate
absorbs the "no SysMain evidence" case correctly: it just contributes
zero family corroboration, which is also the right answer when SysMain
is genuinely disabled.

**Why we bypass** :attr:`Prefetch.timestamps` **and reparse** ``lastRunTime``.
The library's ``getTimeStamps`` formats each FILETIME as a naive-datetime
string via ``str(datetime(...) + timedelta(...))`` — no timezone, ISO-8601
violation, and unfit for ``ExecutionEvent.timestamp`` which the contract
requires to be tz-aware. We read ``self.lastRunTime`` (8 bytes on v17/23,
64 bytes on v26/30 — eight FILETIMEs in chronological order most-recent-
first) and convert each non-zero slot to a tz-aware UTC datetime via
``regipy.utils.convert_wintime``.

**One ExecutionEvent per non-zero historical run slot.** Win 10/11
prefetch retains up to 8 prior run timestamps. Each one is a distinct
forensic signal — emitting all of them gives analysts the full
back-history for the binary, not just the most-recent run. Family-count
arithmetic isn't affected (still one family contribution per parser call)
but timeline reconstruction is much richer.

**Per-row leniency.** A truncated lastRunTime buffer that yields some
valid FILETIMEs and one corrupt slot drops the corrupt slot and keeps the
valid events — same convention as Amcache/UserAssist/BAM/ShimCache.
Whole-file corruption (the library raises during construction) bubbles
up as :class:`ArtifactMalformedError` with attacker-influenceable bytes
scrubbed via ``_safe_field`` (the FastMCP ``isError`` channel bypasses
success-path sanitizers; see ``feedback_error_channel_bypass.md``).
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from regipy.utils import convert_wintime
from windowsprefetch import Prefetch

from sanctum.events import ExecutionEvent
from sanctum.parsers._errors import ArtifactMalformedError, ArtifactNotFoundError
from sanctum.parsers._fixture_io import (
    _FIELD_DELIMITER_PATTERN,
    PROGRAM_PATH_MAX_LEN,
    _safe_field,
    fixture_mode,
    load_sidecar,
)

_TOOL = "get_prefetch"
_FAMILY = "SysMain"

# Maximum executableName length we accept. Prefetch executable names are
# UTF-16 60-byte strings → 30 chars max in practice. 64 is generous; longer
# is suspicious and we drop the row.
_EXECUTABLE_NAME_MAX_LEN = 64

# Win 10/11 historical-run slots; v17/23 has only the first slot. The
# library exposes either 8 bytes or 64 bytes of `lastRunTime` depending on
# version, so we slice up to whatever's there.
_FILETIME_SLOT_BYTES = 8


def parse_prefetch(pf_path: Path) -> list[ExecutionEvent]:
    if not pf_path.is_file():
        raise ArtifactNotFoundError(f"prefetch file not found: {pf_path}")
    if fixture_mode():
        return load_sidecar(pf_path, expected_family=_FAMILY, expected_tool=_TOOL)
    return _parse_prefetch_real(pf_path)


def _parse_prefetch_real(pf_path: Path) -> list[ExecutionEvent]:
    try:
        pf = Prefetch(str(pf_path))
    except Exception as exc:
        # `windowsprefetch.Prefetch` raises a wide variety: struct.error on
        # truncated files, UnicodeDecodeError on bad bytes, AttributeError
        # on non-Windows MAM decompression (`ctypes.windll` doesn't exist),
        # plus arbitrary OS errors during the `RtlDecompressBufferEx`
        # ctypes call. We collapse all to ArtifactMalformedError; the
        # operator distinguishes via the message (scrubbed first).
        raise ArtifactMalformedError(
            f"prefetch file {_safe_field(pf_path.name)} could not be parsed: "
            f"{_safe_field(type(exc).__name__)}: {_safe_field(str(exc))}"
        ) from exc

    executable = _normalize_executable_name(getattr(pf, "executableName", ""))
    if executable is None:
        # No executable name → no usable program_path. Whole-file empty
        # answer; the per-row policy doesn't apply since there's only one
        # binary per .pf file.
        return []

    last_run_bytes = getattr(pf, "lastRunTime", b"")
    if not isinstance(last_run_bytes, (bytes, bytearray)):
        return []

    indexed_timestamps = list(_iter_filetimes(bytes(last_run_bytes)))
    if not indexed_timestamps:
        return []

    run_count = _coerce_uint32(getattr(pf, "runCount", 0))
    pf_hash = _normalize_hash(getattr(pf, "hash", ""))
    pf_size = _coerce_uint32(getattr(pf, "fileSize", 0))

    full_path = _resolve_full_path(pf, executable)
    program_path = full_path or executable
    if len(program_path) > PROGRAM_PATH_MAX_LEN:
        return []
    if _FIELD_DELIMITER_PATTERN.search(program_path):
        return []

    events: list[ExecutionEvent] = []
    for original_slot, ts in indexed_timestamps:
        extras: dict[str, str] = {
            "row_index": str(len(events)),
            "executable_basename": executable,
            "prefetch_filename": pf_path.name,
            "run_count": str(run_count),
            "run_slot": str(original_slot),
        }
        if pf_hash:
            extras["prefetch_hash"] = pf_hash

        events.append(
            ExecutionEvent(
                tool=_TOOL,
                family=_FAMILY,
                program_path=program_path,
                timestamp=ts,
                source_artifact=pf_path.as_posix(),
                evidence_size_bytes=pf_size,
                extras=extras,
            )
        )
    return events


def _iter_filetimes(buf: bytes):
    """Walk an 8-or-64-byte ``lastRunTime`` buffer, yielding ``(slot_index,
    datetime)`` tuples for each non-zero slot. Slot order is
    most-recent-first per the Win 10/11 schema, so the slot whose index is 0
    is the canonical "last run". The original slot index is preserved past
    the row-drop filter so analysts can still tell "this was the most recent
    run" vs "this was 6 runs ago" when intervening slots are corrupt."""

    n_slots = len(buf) // _FILETIME_SLOT_BYTES
    if n_slots == 0:
        return
    for i in range(n_slots):
        slot = buf[i * _FILETIME_SLOT_BYTES : (i + 1) * _FILETIME_SLOT_BYTES]
        if len(slot) != _FILETIME_SLOT_BYTES:
            continue
        try:
            ft = struct.unpack("<Q", slot)[0]
        except struct.error:
            continue
        if ft == 0:
            # Sentinel-zero slots are unused historical entries — Win
            # SysMain pre-zeros the buffer when fewer than 8 prior runs
            # are recorded. Skip silently.
            continue
        ts = _wintime_to_aware_utc(ft)
        if ts is not None:
            yield i, ts


def _wintime_to_aware_utc(filetime: int) -> datetime | None:
    if filetime <= 0:
        return None
    try:
        dt = convert_wintime(filetime)
    except (ValueError, OverflowError):
        return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # `regipy.utils.convert_wintime` swallows the FILETIME overflow internally
    # and returns the epoch (1601-01-01 UTC) as a sentinel rather than raising.
    # That value can't represent a real prefetch run — Windows didn't ship in
    # 1601 — so we treat it as a per-row drop. Aggregate tamper detection in
    # `sanctum.deception` cross-checks SysMain row-counts against the other
    # families if every slot is corrupt.
    if dt.year == 1601 and dt.month == 1 and dt.day == 1:
        return None
    return dt


def _normalize_executable_name(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    # The library decodes UTF-16 with `backslashreplace` and splits on the
    # first NUL — non-printable bytes can survive as `\\xNN` escape
    # sequences. Reject any field-delimiter / control char.
    if _FIELD_DELIMITER_PATTERN.search(raw):
        return None
    if len(raw) > _EXECUTABLE_NAME_MAX_LEN:
        return None
    return raw


def _normalize_hash(raw: Any) -> str:
    """Prefetch path-hash. The library produces a hex string with a leading
    ``0x`` already stripped (rolled into ``rawhash.lstrip("0x")`` — note
    that lstrip is character-set, not prefix, but the result is hex-only
    in practice). We lower-case and validate to defang any injection."""

    if not isinstance(raw, str) or not raw:
        return ""
    candidate = raw.lower()
    if not candidate or any(c not in "0123456789abcdef" for c in candidate):
        return ""
    if len(candidate) > 16:
        return ""
    return candidate


def _coerce_uint32(raw: Any) -> int:
    """Bound a uint32 field. Out-of-range or wrong-type → 0. Same shape as
    ``amcache._coerce_size`` — per-row leniency for fields that are
    optional metadata."""

    if isinstance(raw, bool):
        return 0
    if isinstance(raw, int) and 0 <= raw < 2**32:
        return raw
    return 0


def _resolve_full_path(pf: Any, executable: str) -> str | None:
    """Best-effort resolve the executable's full NT path from the prefetch
    file's loaded-resources list. Returns ``None`` if no resource matches
    the executable basename — caller falls back to the basename alone.

    Why best-effort: the resources list logs files the binary loaded, and
    the library's `self.resources` is the already-decoded UTF-16 split. The
    binary's *own* path is conventionally listed (the binary is a "loaded
    resource" of itself) but a corrupted or truncated resources block can
    legitimately be missing it. The forensic worth of a basename-only
    program_path is still high (`prefetch_hash` disambiguates which path
    Windows recorded the binary at), so falling back is fine.
    """

    resources = getattr(pf, "resources", None)
    if not isinstance(resources, list):
        return None
    target = executable.upper()
    for r in resources:
        if not isinstance(r, str) or not r:
            continue
        if _FIELD_DELIMITER_PATTERN.search(r):
            continue
        # ntpath-style basename match (case-insensitive). The resources
        # are NT paths like `\VOLUME{...}\WINDOWS\SYSTEM32\NOTEPAD.EXE`;
        # match the trailing component against the executable name.
        idx = r.rfind("\\")
        basename = r[idx + 1 :] if idx >= 0 else r
        if basename.upper() == target:
            if len(r) > PROGRAM_PATH_MAX_LEN:
                return None
            return r
    return None

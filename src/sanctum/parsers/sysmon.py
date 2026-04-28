"""Sysmon / Security-4688 EVTX parser.

Family ``Kernel-ETW`` — covers both ``Microsoft-Windows-Sysmon/Operational``
EventID 1 (process create) and Security ``EventID 4688`` (audit-process-
creation). Both flow from kernel ETW providers and share a trust root: a
ring-0 attacker can defeat both at once, but a user-mode rootkit that
patches one (e.g. unloads the Sysmon driver) leaves the other intact.
Distinct from AppCompat / Explorer-NTUSER / Background-service / SysMain
(CLAUDE.md invariant 5: tampering with ETW does not flush a ShimCache or
BAM entry, and vice versa).

**Why we delegate the binary parse to** :mod:`Evtx` (``python-evtx``,
Apache-2.0). EVTX is a binary log format with a chunked + binary-XML
encoding (``BXmlNode`` substitution arrays, template references, etc.) —
~3 kLOC of struct twiddling that William Ballenthin's library already
handles. We *call* the library; we do NOT trust its output: every record's
rendered XML is fed through stdlib ``xml.etree.ElementTree`` (with the
``defusedxml`` posture from ``ET.XMLParser`` carried by Python 3.10+ —
external entities, parameter entity refs, etc., are not honored by
``ElementTree`` parsers in practice) and field-level sanitized before it
reaches an :class:`ExecutionEvent`.

**Per-event filter.** Only ``EventID 1`` (Sysmon) and ``EventID 4688``
(Security audit-process-creation) carry process-create signal. Everything
else (Sysmon network/registry/file events, Security logon/audit-policy
events, …) is dropped silently. Per-row leniency: any single record that
fails to render or parse gets dropped, the rest of the EVTX file is still
walked. Same convention as Amcache / UserAssist / BAM / ShimCache /
Prefetch.

**Channel discrimination via** ``EventID``. We do not pre-filter by file
name (e.g. ``Microsoft-Windows-Sysmon%4Operational.evtx`` vs
``Security.evtx``) because in production the analyst chooses what to
ingest and a misnamed file should still parse. Sysmon EID 1 carries a
distinct field set (``Image``, ``ProcessGuid``, ``Hashes``) versus 4688
(``NewProcessName``, ``SubjectUserSid``, no hashes); we extract whichever
is present and surface the source channel via ``extras.event_id``.

**Timestamp extraction.** Sysmon EID 1 carries an ``EventData/Data
Name="UtcTime"`` ISO-ish-but-non-tz-aware string AND the
``System/TimeCreated@SystemTime`` ISO-8601 timestamp. We prefer
``TimeCreated@SystemTime`` for both schemas because it is structurally
the same field across channels and is already tz-aware (the ``SystemTime``
attribute is a UTC-suffixed ISO-8601 string per the EVTX schema). The
``UtcTime`` field is preserved verbatim in ``extras.utc_time`` for analyst
sanity-checking against clock skew between the kernel ETW timestamp and
Sysmon's userland write timestamp — they should agree to milliseconds; a
disagreement is a clock-skew or VM-pause fingerprint, not a parser bug.

**Hashes.** Sysmon EID 1 emits a comma-joined string like
``SHA1=...,MD5=...,SHA256=...,IMPHASH=...``. We split on commas, parse the
``KEY=VALUE`` pairs, validate hex-only on the values, and surface them as
discrete ``extras.hash_sha1`` / ``hash_sha256`` / ``hash_md5`` /
``hash_imphash`` fields. Hex-only validation prevents a Sysmon
configuration with an attacker-controlled custom field from smuggling
control bytes into a string the FastMCP ``isError`` channel might leak —
defense in depth. 4688 carries no hashes; absent fields are simply not
emitted.

**Error-channel scrubbing.** :class:`Evtx.Evtx.Evtx` raises
``ParseException`` / ``InvalidRecordException`` on malformed file
headers, plus arbitrary ``OSError`` / ``mmap`` errors. We collapse all to
:class:`ArtifactMalformedError` with the exception type-name and message
scrubbed via ``_safe_field`` before they land in a string the FastMCP
``isError`` channel will serialize to the LLM (success-path sanitizers
don't fire on raised exceptions; see ``feedback_error_channel_bypass.md``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

# `defusedxml.ElementTree.fromstring` rejects DTDs / external entities /
# entity-expansion attacks. The input strings come from python-evtx's
# `record.xml()` output, which renders attacker-controllable EVTX bytes —
# so even though stdlib `xml.etree` doesn't honour external entities by
# default in modern Python, we route through `defusedxml` to also block
# the entity-expansion (billion-laughs) class. We keep the stdlib `ET`
# import for the `Element` type and `ParseError` exception (`defusedxml`
# does not redefine those — it only swaps the parser).
from defusedxml.ElementTree import fromstring as _safe_xml_fromstring
from Evtx.Evtx import Evtx

from sanctum.events import ExecutionEvent
from sanctum.families import FAMILY_KERNEL_ETW
from sanctum.parsers._errors import (
    ArtifactMalformedError,
    ArtifactNotFoundError,
    PartialParseError,
)
from sanctum.parsers._fixture_io import (
    _FIELD_DELIMITER_PATTERN,
    PROGRAM_PATH_MAX_LEN,
    _safe_field,
    fixture_mode,
    load_sidecar,
)

_TOOL = "get_sysmon_4688"
_FAMILY = FAMILY_KERNEL_ETW

# Per-call record-iteration cap. A real Win11 host's
# ``Microsoft-Windows-Sysmon%4Operational.evtx`` (verbose config) typically
# rolls at ~100 MB / ~100k records before rotation; busy enterprise hosts
# may carry 300–500k. 1,000,000 clears that tail by ~3–10× while bounding
# worst-case memory at ~500 MB (≈500 B/event × 1M, 100% emit). The cap
# counts raw records iterated — an attacker who pads the log with dropped
# events (non-process-create EIDs, malformed XML rows) still consumes
# per-row CPU, so a tighter emit-count cap would not close that DoS lane.
# Raise rather than silent-truncate: silent truncation would deceive the
# analyst about what's in the EVTX (consistent with how
# ``sanitize.MAX_INPUT_BYTES`` raises ``InputTooLargeError`` for the same
# reason on a different surface, and with ``AMCACHE_MAX_ROWS`` in
# :mod:`sanctum.parsers.amcache`).
SYSMON_MAX_RECORDS = 1_000_000

# EVTX records emit XML in this default namespace. ElementTree exposes
# children as `{ns}localname`, so we either pre-strip the namespace or
# use the full Clark notation. We strip — keeps element lookups readable
# (``./System/EventID`` rather than ``./{http://...}System/{http://...}EventID``).
_EVTX_NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Process-create event IDs. Sysmon channel = 1. Security channel = 4688.
# Both are accepted; the parser surfaces the source via ``extras.event_id``.
_SYSMON_PROCESS_CREATE_EID = 1
_SECURITY_PROCESS_CREATE_EID = 4688
_ACCEPTED_EVENT_IDS = frozenset({_SYSMON_PROCESS_CREATE_EID, _SECURITY_PROCESS_CREATE_EID})

# Maximum CommandLine length we surface in extras. Real values are
# typically <1 KiB; obscenely long values are a smuggling attempt against
# the LLM context window. 4096 mirrors PROGRAM_PATH_MAX_LEN.
_COMMAND_LINE_MAX_LEN = 4096

# Hash field labels Sysmon emits. Keys are the SHA1/MD5/etc. label; values
# are (extras_key, allowed_hex_length).
_SYSMON_HASH_FIELDS: dict[str, tuple[str, int]] = {
    "SHA1": ("hash_sha1", 40),
    "MD5": ("hash_md5", 32),
    "SHA256": ("hash_sha256", 64),
    "IMPHASH": ("hash_imphash", 32),
}


def parse_sysmon(evtx_path: Path) -> list[ExecutionEvent]:
    if not evtx_path.is_file():
        raise ArtifactNotFoundError(f"EVTX file not found: {_safe_field(evtx_path.name)}")
    if fixture_mode():
        return load_sidecar(evtx_path, expected_family=_FAMILY, expected_tool=_TOOL)
    return _parse_sysmon_real(evtx_path)


def _parse_sysmon_real(evtx_path: Path) -> list[ExecutionEvent]:
    events: list[ExecutionEvent] = []
    try:
        evtx_ctx = Evtx(str(evtx_path))
    except Exception as exc:
        raise ArtifactMalformedError(
            f"EVTX file {_safe_field(evtx_path.name)} could not be opened: "
            f"{_safe_field(type(exc).__name__)}: {_safe_field(str(exc))}"
        ) from exc

    try:
        with evtx_ctx as evtx:
            iterator = iter(evtx.records())
            # Two counters: ``iterated`` bounds CPU/memory across the raw
            # record stream (so attacker-padded dropped records still hit
            # the cap), while ``len(events)`` remains the public ``row_index``
            # (emitted order, the documented contract exercised by
            # ``test_real_mode_sysmon_sequential_row_index``). Mirrors the
            # AMCACHE_MAX_ROWS pattern in :mod:`sanctum.parsers.amcache`.
            iterated = 0
            while True:
                try:
                    record = next(iterator)
                except StopIteration:
                    break
                except Exception as exc:
                    # Mid-stream EVTX corruption (e.g. InvalidRecordException
                    # on a chunk with corrupt magic). Preserve already-
                    # extracted events but raise a typed signal so callers
                    # can distinguish this from a clean EOF — matches the
                    # ShimCache policy in appcompat._events_from_blob.
                    # Without this, selective record-truncation tampering
                    # is indistinguishable from a short log file.
                    raise PartialParseError(
                        f"EVTX file {_safe_field(evtx_path.name)} truncated "
                        f"after {len(events)} events: "
                        f"{_safe_field(type(exc).__name__)}: {_safe_field(str(exc))}",
                        events=events,
                        cause=exc,
                    ) from exc
                if iterated >= SYSMON_MAX_RECORDS:
                    raise ArtifactMalformedError(
                        f"EVTX file {_safe_field(evtx_path.name)} exceeds the "
                        f"{SYSMON_MAX_RECORDS}-record cap; refusing to parse"
                    )
                iterated += 1
                event = _record_to_event(record, evtx_path=evtx_path, row_index=len(events))
                if event is not None:
                    events.append(event)
    except ArtifactMalformedError:
        # PartialParseError is a subclass — re-raised here as well.
        raise
    except Exception as exc:
        raise ArtifactMalformedError(
            f"EVTX file {_safe_field(evtx_path.name)} parse failure: "
            f"{_safe_field(type(exc).__name__)}: {_safe_field(str(exc))}"
        ) from exc
    return events


def _record_to_event(
    record: Any,
    *,
    evtx_path: Path,
    row_index: int,
) -> ExecutionEvent | None:
    try:
        xml_text = record.xml()
    except Exception:
        return None
    try:
        root = _safe_xml_fromstring(xml_text)
    except ET.ParseError:
        return None

    event_id = _extract_event_id(root)
    if event_id not in _ACCEPTED_EVENT_IDS:
        return None

    timestamp = _extract_timestamp(root)
    if timestamp is None:
        return None

    data = _extract_event_data(root)
    program_path = _extract_program_path(data, event_id)
    if program_path is None:
        return None

    extras: dict[str, str] = {
        "row_index": str(row_index),
        "event_id": str(event_id),
        "evtx_filename": evtx_path.name,
    }

    record_num = _safe_record_num(record)
    if record_num is not None:
        extras["event_record_id"] = str(record_num)

    utc_time = _safe_field_value(data.get("UtcTime"))
    if utc_time:
        extras["utc_time"] = utc_time

    process_guid = _normalize_process_guid(data.get("ProcessGuid"))
    if process_guid:
        extras["process_guid"] = process_guid

    command_line = _normalize_command_line(data.get("CommandLine"))
    if command_line:
        extras["command_line"] = command_line

    user = _normalize_user(data.get("User") or data.get("SubjectUserName"))
    if user:
        extras["user"] = user

    parent_image = _normalize_path(data.get("ParentImage") or data.get("ParentProcessName"))
    if parent_image:
        extras["parent_image"] = parent_image

    _attach_hashes(extras, data.get("Hashes"))

    return ExecutionEvent(
        tool=_TOOL,
        family=_FAMILY,
        program_path=program_path,
        timestamp=timestamp,
        source_artifact=evtx_path.as_posix(),
        evidence_size_bytes=0,
        extras=extras,
    )


def _extract_event_id(root: ET.Element) -> int | None:
    elem = root.find(f"./{_EVTX_NAMESPACE}System/{_EVTX_NAMESPACE}EventID")
    if elem is None or elem.text is None:
        return None
    try:
        return int(elem.text.strip())
    except ValueError:
        return None


def _extract_timestamp(root: ET.Element) -> datetime | None:
    """Prefer ``System/TimeCreated@SystemTime``. The attribute is an
    ISO-8601 string with a trailing ``Z`` (or fractional + ``Z``) per the
    EVTX schema; ``datetime.fromisoformat`` on Python 3.11+ accepts ``Z``
    natively, but we patch it to ``+00:00`` defensively for 3.10."""

    elem = root.find(f"./{_EVTX_NAMESPACE}System/{_EVTX_NAMESPACE}TimeCreated")
    if elem is None:
        return None
    raw = elem.attrib.get("SystemTime")
    if not isinstance(raw, str) or not raw:
        return None
    cleaned = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _extract_event_data(root: ET.Element) -> dict[str, str]:
    """Return ``EventData/Data Name="X"`` as a ``{X: text-or-empty}`` dict.
    Missing ``Name`` attribute or empty body → skipped entry. Last-write-wins
    on duplicate names (Sysmon never duplicates; defensive)."""

    out: dict[str, str] = {}
    container = root.find(f"./{_EVTX_NAMESPACE}EventData")
    if container is None:
        return out
    for data_elem in container.findall(f"./{_EVTX_NAMESPACE}Data"):
        name = data_elem.attrib.get("Name")
        if not isinstance(name, str) or not name:
            continue
        text = data_elem.text or ""
        out[name] = text
    return out


def _extract_program_path(data: dict[str, str], event_id: int) -> str | None:
    if event_id == _SYSMON_PROCESS_CREATE_EID:
        raw = data.get("Image")
    else:
        raw = data.get("NewProcessName")
    return _normalize_path(raw)


def _normalize_path(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    if _FIELD_DELIMITER_PATTERN.search(raw):
        return None
    if len(raw) > PROGRAM_PATH_MAX_LEN:
        return None
    return raw


def _normalize_process_guid(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        return ""
    if _FIELD_DELIMITER_PATTERN.search(raw):
        return ""
    if len(raw) > 64:
        return ""
    return raw


def _normalize_command_line(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        return ""
    if _FIELD_DELIMITER_PATTERN.search(raw):
        return ""
    if len(raw) > _COMMAND_LINE_MAX_LEN:
        # Truncate-and-mark rather than drop: a long command line is still
        # forensic evidence; we just don't pass the whole blob through.
        return raw[:_COMMAND_LINE_MAX_LEN] + "..."
    return raw


def _normalize_user(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        return ""
    if _FIELD_DELIMITER_PATTERN.search(raw):
        return ""
    if len(raw) > 256:
        return ""
    return raw


def _attach_hashes(extras: dict[str, str], raw: Any) -> None:
    if not isinstance(raw, str) or not raw:
        return
    for chunk in raw.split(","):
        if "=" not in chunk:
            continue
        label, value = chunk.split("=", 1)
        label = label.strip().upper()
        value = value.strip().lower()
        spec = _SYSMON_HASH_FIELDS.get(label)
        if spec is None:
            continue
        extras_key, expected_len = spec
        if len(value) != expected_len:
            continue
        if any(c not in "0123456789abcdef" for c in value):
            continue
        extras[extras_key] = value


def _safe_field_value(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        return ""
    if _FIELD_DELIMITER_PATTERN.search(raw):
        return ""
    if len(raw) > 128:
        return ""
    return raw


def _safe_record_num(record: Any) -> int | None:
    fn = getattr(record, "record_num", None)
    if not callable(fn):
        return None
    try:
        n = fn()
    except Exception:
        return None
    if not isinstance(n, int) or n < 0:
        return None
    return n

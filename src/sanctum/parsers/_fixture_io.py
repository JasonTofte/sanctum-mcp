"""Sidecar fixture loader — the only way real `ExecutionEvent`-shaped data
reaches the parser layer in week 2.

Sidecars live next to the artifact at `<artifact>.sanctum-fixture.json`.
The loader is gated by `SANCTUM_USE_FIXTURE_SIDECAR=1`; the production MCP
server never sets this env var, so the path is unreachable from the wire
boundary.

**The BOTH-field check is load-bearing.** A sidecar declares both
`family` and `tool`; both must match what the calling parser expects.
Why both: same-family parsers (Amcache and ShimCache are both AppCompat)
can be pointed at the same on-disk path. If only `family` were checked,
`parse_shimcache(amcache_path)` would silently inherit Amcache's events
under the AppCompat label, and `audit.classify_confidence` (which counts
integer family occurrences) would tally one source as two AppCompat
corroborations. AC-15d in `tests/test_parsers.py` is the regression test;
`feedback_sidecar_path_lookup.md` codifies the gotcha.

**Error-message scrubbing is also load-bearing.** Sidecar fields are
attacker-influenceable (in week 2 by anyone who can write a fixture; in
week 3 by an attacker who chose what to execute on the suspect machine —
Amcache rows reflect the attacker's binary path, registry value names,
SHA-1, etc.). When a malformed sidecar raises `ArtifactMalformedError`,
the FastMCP framework will eventually serialize that exception string into
an MCP `isError: true` response — bypassing `sanctum.sanitize.sanitize()`
and the `<evidence-untrusted>` quarantine wrapper, which only run on the
*success* path. So every sidecar value that lands in an exception message
goes through `_safe_field()` first to strip delimiters and control
characters and to bound length.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from sanctum.events import ExecutionEvent
from sanctum.parsers._errors import (
    ArtifactMalformedError,
    PartialImplementationError,
)

FIXTURE_ENV = "SANCTUM_USE_FIXTURE_SIDECAR"
SIDECAR_SUFFIX = ".sanctum-fixture.json"

# Sidecars in this repo are <1 KiB. The cap is generous (1 MiB) but bounds
# both memory and the JSON-parser's CPU surface. Mirrors the spirit of
# `sanitize.MAX_INPUT_BYTES` (16 MiB) without inheriting the larger budget,
# which exists to clear `volatility3 pslist`-class outputs the sanitize
# stage absorbs — sidecars never see those.
SIDECAR_MAX_BYTES = 1 * 1024 * 1024

# Bound on `program_path` length. Windows MAX_PATH is 260 (NTFS extended
# is 32767); 4 KiB clears any sane real-world path with headroom. Bigger
# values are either a bug or an attempt to fill the LLM context window
# from a sidecar field.
PROGRAM_PATH_MAX_LEN = 4096

# Reasonable cap on `evidence_size_bytes`. PR-#4's L_max enforcement (when
# it lands) will further cap output size; this cap exists at the parser
# boundary so a malformed sidecar can't smuggle a value that would later
# be used in arithmetic or pre-allocation.
EVIDENCE_SIZE_MAX = 2**40  # 1 TiB

# Strings that would break the `<evidence-untrusted>...</evidence-untrusted>`
# quarantine if they appeared in the LLM-visible content of an exception
# message, plus ASCII control chars used for log injection / prompt smuggling.
# Defense-in-depth — the success path runs through `sanitize.sanitize()`
# which has a stronger stripper, but exception messages bypass that.
_FIELD_DELIMITER_PATTERN = re.compile(r"[<>\x00-\x1f]")


def _safe_field(value: Any, *, limit: int = 128) -> str:
    """Scrub an attacker-influenceable value for safe inclusion in an
    exception message. Replaces angle brackets and control characters with
    `?`, truncates to `limit` characters with a `...` suffix.

    Not a security boundary on its own — `sanctum.sanitize` is. This is
    the cheap belt-and-suspenders for the error-message channel.
    """

    s = str(value)
    s = _FIELD_DELIMITER_PATTERN.sub("?", s)
    if len(s) > limit:
        s = s[:limit] + "..."
    return s


def fixture_mode() -> bool:
    """True iff the env-var gate is set to ``1``. Production never sets it."""

    return os.environ.get(FIXTURE_ENV) == "1"


def sidecar_path_for(artifact_path: Path) -> Path:
    return artifact_path.with_name(artifact_path.name + SIDECAR_SUFFIX)


def load_sidecar(
    artifact_path: Path,
    *,
    expected_family: str,
    expected_tool: str,
) -> list[ExecutionEvent]:
    """Load and validate the sidecar JSON next to ``artifact_path``.

    Validates BOTH ``family == expected_family`` AND ``tool == expected_tool``;
    either mismatch raises :class:`ArtifactMalformedError`. The tool-field
    check closes same-family cross-talk (Amcache vs ShimCache).

    Returns ``[]`` if the sidecar's ``events`` array is empty — well-formed
    artifacts with no execution rows are not an error.

    Caller is responsible for the artifact-existence check (the six parser
    modules each raise their own family-specific `ArtifactNotFoundError`
    before delegating here).
    """

    sidecar = sidecar_path_for(artifact_path)
    if not sidecar.is_file():
        raise PartialImplementationError(
            tool=expected_tool,
            reason=(
                "fixture mode is on but no sidecar found "
                f"({_safe_field(sidecar.name)} expected next to "
                f"{_safe_field(artifact_path.name)})"
            ),
        )

    size = sidecar.stat().st_size
    if size > SIDECAR_MAX_BYTES:
        raise ArtifactMalformedError(
            f"sidecar exceeds size cap ({size} bytes > {SIDECAR_MAX_BYTES}); "
            f"sidecars are < 1 KiB by design — refusing to load"
        )

    # Distinct exception classes for distinct failure modes:
    # - OSError (permission, EIO, ENOSPC during read) is an I/O fault, not
    #   a data fault. Lifting it as `ArtifactMalformedError` would mistype
    #   the audit-ledger entry. Re-raise as-is; callers catch FileNotFoundError
    #   subclasses or general OSError as appropriate.
    # - JSONDecodeError IS a data fault → ArtifactMalformedError.
    raw = sidecar.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} is not valid JSON: {_safe_field(exc.msg)}"
        ) from exc

    _validate_envelope(payload, sidecar, expected_family, expected_tool)

    events_raw = payload.get("events", [])
    if not isinstance(events_raw, list):
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} field 'events' must be a list, "
            f"got {type(events_raw).__name__}"
        )

    return [
        _build_event(
            row,
            sidecar=sidecar,
            artifact_path=artifact_path,
            tool=expected_tool,
            family=expected_family,
        )
        for row in events_raw
    ]


def _validate_envelope(
    payload: Any,
    sidecar: Path,
    expected_family: str,
    expected_tool: str,
) -> None:
    if not isinstance(payload, dict):
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} top-level must be a JSON object"
        )

    declared_family = payload.get("family")
    if declared_family != expected_family:
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} declares "
            f"family={_safe_field(declared_family)!r} but caller expects "
            f"{_safe_field(expected_family)!r}"
        )

    declared_tool = payload.get("tool")
    if declared_tool != expected_tool:
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} declares "
            f"tool={_safe_field(declared_tool)!r} but caller expects "
            f"{_safe_field(expected_tool)!r} — "
            f"same-family cross-talk would otherwise silently corrupt evidence "
            f"(see feedback_sidecar_path_lookup.md)"
        )


def _build_event(
    row: Any,
    *,
    sidecar: Path,
    artifact_path: Path,
    tool: str,
    family: str,
) -> ExecutionEvent:
    if not isinstance(row, dict):
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} events[*] must be JSON objects"
        )

    try:
        program_path = row["program_path"]
        timestamp_iso = row["timestamp"]
        size_raw = row["evidence_size_bytes"]
    except KeyError as exc:
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event missing required field: "
            f"{_safe_field(exc.args[0] if exc.args else '?')}"
        ) from exc

    if not isinstance(program_path, str):
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event 'program_path' must be a string"
        )
    if len(program_path) > PROGRAM_PATH_MAX_LEN:
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event 'program_path' exceeds "
            f"{PROGRAM_PATH_MAX_LEN} chars"
        )
    # Reject delimiter-injection and NUL/newline smuggling. The success-path
    # output goes through `sanctum.sanitize.sanitize()` already, but defense
    # in depth: a parser-layer reject means a malformed sidecar can never
    # produce a malformed `ExecutionEvent` in the first place.
    if _FIELD_DELIMITER_PATTERN.search(program_path):
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event 'program_path' contains "
            f"control characters or angle brackets — refusing"
        )

    # `bool` is an `int` subclass; reject it explicitly so `True` doesn't
    # silently become 1. Negative or pathologically large values are also
    # malformed at the parser boundary.
    if isinstance(size_raw, bool) or not isinstance(size_raw, int):
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event 'evidence_size_bytes' "
            f"must be a non-negative integer, got {type(size_raw).__name__}"
        )
    if size_raw < 0 or size_raw > EVIDENCE_SIZE_MAX:
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event 'evidence_size_bytes'={size_raw} "
            f"out of range [0, {EVIDENCE_SIZE_MAX}]"
        )

    if not isinstance(timestamp_iso, str):
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event 'timestamp' must be a string"
        )
    try:
        timestamp = datetime.fromisoformat(timestamp_iso)
    except ValueError as exc:
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event timestamp not ISO-8601: "
            f"{_safe_field(timestamp_iso)!r}"
        ) from exc
    if timestamp.tzinfo is None:
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event timestamp must be tz-aware: "
            f"{_safe_field(timestamp_iso)!r}"
        )

    extras_raw = row.get("extras", {})
    if not isinstance(extras_raw, dict):
        raise ArtifactMalformedError(
            f"sidecar {_safe_field(sidecar.name)} event extras must be a JSON object"
        )
    extras: dict[str, str] = {}
    for k, v in extras_raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ArtifactMalformedError(
                f"sidecar {_safe_field(sidecar.name)} event extras must be string→string"
            )
        extras[k] = v

    return ExecutionEvent(
        tool=tool,
        family=family,
        program_path=program_path,
        timestamp=timestamp,
        source_artifact=artifact_path.as_posix(),
        evidence_size_bytes=size_raw,
        extras=extras,
    )

"""Write-once payload offload with path-component allowlist and durability guarantees.

Provides :func:`write_payload` and :func:`validate_offload_root_distinct_from_cases_root`
for Phase 1 of the payload-offload reimplementation.
"""

from __future__ import annotations

import hashlib
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Final

OUTPUT_ROOT_ENV: Final[str] = "SANCTUM_OUTPUT_ROOT"
CASES_ROOT_ENV: Final[str] = "SANCTUM_CASES_ROOT"

# Portability seam: os.fdatasync is Linux-only in Python's os module. On Darwin
# and BSD, os.fsync is the closest equivalent (slightly stronger — also flushes
# metadata, but always safe). Tests monkeypatch these names rather than os.*
# so the call-site distinction (data fd vs. parent dir fd) stays observable.
_fdatasync = getattr(os, "fdatasync", os.fsync)
_fsync = os.fsync
# O_DIRECTORY exists on Linux + Darwin; absent on Windows. Fall back to 0 (no-op
# bit) so the open-as-directory call doesn't hard-fail on platforms where the
# flag isn't defined. O_NOFOLLOW exists on Linux + Darwin; same fallback.
_O_DIRECTORY: int = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)

# Specific banned codepoints (in addition to control chars handled by range check).
_BANNED_CODEPOINTS: frozenset[int] = frozenset(
    [
        0x202E,  # RIGHT-TO-LEFT OVERRIDE (RLO)
        0x2066,  # LEFT-TO-RIGHT ISOLATE (LRI)
        0x200B,  # ZERO WIDTH SPACE (ZWSP)
        0x200C,  # ZERO WIDTH NON-JOINER (ZWNJ)
        0x200D,  # ZERO WIDTH JOINER (ZWJ)
        0xFEFF,  # BOM / ZERO WIDTH NO-BREAK SPACE
    ]
)


def _validate_segment(segment: str) -> None:
    """Raise ValueError if *segment* contains any disallowed pattern.

    The full structural+character check runs on the raw input and is then
    repeated on the NFKC-normalized form. Running the FULL check (not just
    the character-class check) on the normalized form catches compatibility
    decompositions that introduce path separators or dotdot prefixes —
    e.g., U+FF0F FULLWIDTH SOLIDUS NFKC-decomposes to ``/``.
    """
    _check_segment(segment)

    normalized = unicodedata.normalize("NFKC", segment)
    if normalized != segment:
        _check_segment(normalized)


def _check_segment(segment: str) -> None:
    """Run the full structural + character-class check on *segment*."""
    if segment == ".." or segment.startswith(".."):
        raise ValueError(f"path segment rejected (dotdot): {segment!r}")
    if segment.startswith("/"):
        raise ValueError(f"path segment rejected (absolute slash): {segment!r}")
    if segment.startswith("."):
        raise ValueError(f"path segment rejected (leading dot): {segment!r}")
    if "/" in segment:
        raise ValueError(f"path segment rejected (embedded slash): {segment!r}")
    for c in segment:
        cp = ord(c)
        if cp < 0x20 or cp == 0x7F:
            raise ValueError(f"path segment rejected (control char U+{cp:04X}): {segment!r}")
        if cp in _BANNED_CODEPOINTS:
            raise ValueError(f"path segment rejected (banned codepoint U+{cp:04X}): {segment!r}")


@dataclass(frozen=True)
class PayloadRef:
    """Immutable reference to a written payload file."""

    path: str
    sha256: str
    # Field is `byte_count` (not `bytes`) to avoid shadowing the builtin and
    # confusing type checkers. The JSON-wire key stays `"bytes"` for callers.
    byte_count: int
    format: str = "application/json"

    def to_json_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "bytes": self.byte_count,
            "format": self.format,
        }


def write_payload(
    *,
    case_id: str,
    audit_id: str,
    tool: str,
    content: str,
    mime_format: str = "application/json",
) -> PayloadRef:
    """Write *content* write-once to ``<output_root>/<case_id>/<audit_id>/<tool>.json``.

    Raises :class:`ValueError` for unsafe path components (no directories are
    created on rejection). Raises :class:`FileExistsError` on collision.

    Durability guarantee: ``os.fdatasync(payload_fd)`` then
    ``os.fsync(parent_dir_fd)`` are issued before returning.
    """
    # Validate all segments before touching the filesystem.
    _validate_segment(case_id)
    _validate_segment(audit_id)
    _validate_segment(tool)

    try:
        output_root_str = os.environ[OUTPUT_ROOT_ENV]
    except KeyError:
        # Convert to RuntimeError so the message is intentional and doesn't leak
        # through error-channel paths as a raw KeyError. The startup guard
        # (validate_offload_root_distinct_from_cases_root) is the canonical
        # place to catch this; this is defense-in-depth at the call site.
        raise RuntimeError(f"{OUTPUT_ROOT_ENV} is not set") from None
    output_root = Path(output_root_str)

    parent_dir = output_root / case_id / audit_id
    file_path = parent_dir / f"{tool}.json"

    content_bytes = content.encode("utf-8")
    sha256_hex = hashlib.sha256(content_bytes).hexdigest()

    # Create parent directories only after all validation has passed.
    parent_dir.mkdir(parents=True, exist_ok=True)

    # Open write-once via O_CREAT | O_EXCL — raises FileExistsError on collision.
    # O_NOFOLLOW defends against a symlink swap at file_path itself (a symlink
    # placed between mkdir and open would otherwise cause us to open through it).
    payload_fd = os.open(
        str(file_path),
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_NOFOLLOW,
        0o444,
    )
    try:
        os.write(payload_fd, content_bytes)
        # fchmod is belt-and-suspenders: O_CREAT mode is masked by umask, so
        # under `umask 022` the open already gives 0o444 — but under an unusual
        # umask we'd lose read bits. fchmod re-asserts the canonical mode.
        os.fchmod(payload_fd, 0o444)
        _fdatasync(payload_fd)
        # Hold payload_fd while we fsync the parent dir so the dir entry is
        # durable before we let go. This also keeps the two fds distinct.
        dir_fd = os.open(str(parent_dir), os.O_RDONLY | _O_DIRECTORY)
        try:
            _fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        os.close(payload_fd)

    return PayloadRef(
        path=str(file_path),
        sha256=sha256_hex,
        byte_count=len(content_bytes),
        format=mime_format,
    )


def validate_offload_root_distinct_from_cases_root(
    *,
    output_root: Path,
    cases_root: Path,
) -> None:
    """Startup guard.

    Raises :class:`RuntimeError` if:
    - *output_root* does not exist (names ``SANCTUM_OUTPUT_ROOT`` and the path).
    - *output_root* resolves under *cases_root* (names both env-var names).

    Returns ``None`` when roots are distinct and both exist.
    """
    if not output_root.exists():
        raise RuntimeError(f"{OUTPUT_ROOT_ENV} path does not exist: {output_root}")
    if not cases_root.exists():
        # Without this, cases_root.resolve() returns a non-canonical path on
        # Python 3.10+ and the containment check below can pass spuriously.
        raise RuntimeError(f"{CASES_ROOT_ENV} path does not exist: {cases_root}")

    resolved_output = output_root.resolve()
    resolved_cases = cases_root.resolve()

    if resolved_output == resolved_cases or resolved_output.is_relative_to(resolved_cases):
        raise RuntimeError(
            f"{OUTPUT_ROOT_ENV} must not reside under {CASES_ROOT_ENV}: "
            f"{resolved_output} is under {resolved_cases}"
        )

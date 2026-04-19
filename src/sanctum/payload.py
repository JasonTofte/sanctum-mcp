"""Payload reference system — offload tool returns to disk to survive MCP stdio size limits.

Claude Code's MCP stdio transport silently drops JSON-RPC responses larger than
roughly 800–1100 bytes (github.com/anthropics/claude-code/issues/36319). A tool
call whose return exceeds that threshold leaves the LLM with an empty reply while
the audit ledger records a successful invocation — a silent-corruption failure
mode on exactly the audit trail Sanctum exists to protect.

Every Sanctum typed tool therefore writes its full sanitized output to disk and
returns only a short summary carrying a :class:`PayloadRef`. The caller (LLM
running via Claude Code on the same host) reads the referenced file with the
generic ``Read`` tool.

Invariants:

- Write-once via ``O_CREAT | O_EXCL``. An ``audit_id`` (UUID4) collision would
  raise :class:`FileExistsError` and surface a programming error rather than
  silently overwriting.
- Path layout mirrors the audit ledger key space:
  ``<SANCTUM_OUTPUT_ROOT>/<case_id>/<audit_id>/<tool>.json``.
- Path components are validated against a conservative allowlist — the on-disk
  layout is a write surface and anything accepting external input is a
  path-traversal target until proven otherwise.
- Files are created mode ``0o444`` so post-write mutation requires an explicit
  chmod; pairs with the project-level read-only evidence mount invariant.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

OUTPUT_ROOT_ENV = "SANCTUM_OUTPUT_ROOT"
DEFAULT_OUTPUT_ROOT = "/var/lib/sanctum/output"

# Conservative allowlist for path components. UUID4 audit_ids, repo-style case_ids
# (cfreds-hacking-case), and simple tool names (get_amcache) all pass.
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True)
class PayloadRef:
    """On-disk reference to a tool's full sanitized output.

    Attributes:
        path: absolute filesystem path to the payload file.
        sha256: SHA-256 hex digest of the UTF-8-encoded payload bytes.
        bytes: byte count of the file.
        format: IANA media type (default ``application/json``).
    """

    path: str
    sha256: str
    bytes: int
    format: str

    def to_json_dict(self) -> dict[str, Any]:
        """Return a canonical dict suitable for embedding in JSON-RPC replies."""

        return {
            "path": self.path,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "format": self.format,
        }


def _output_root() -> Path:
    return Path(os.environ.get(OUTPUT_ROOT_ENV, DEFAULT_OUTPUT_ROOT))


def _validate_component(name: str, what: str) -> None:
    if not name or not _SAFE_COMPONENT.match(name):
        raise ValueError(f"unsafe {what}: {name!r}")


def write_payload(
    *,
    case_id: str,
    audit_id: str,
    tool: str,
    content: str,
    mime_format: str = "application/json",
) -> PayloadRef:
    """Write ``content`` write-once under :envvar:`SANCTUM_OUTPUT_ROOT` and return a ref.

    Destination: ``<root>/<case_id>/<audit_id>/<tool>.json``.

    Raises:
        ValueError: any path component contains characters outside the allowlist.
        FileExistsError: the target already exists (would indicate a programming
            error since ``audit_id`` is UUID4).
    """

    _validate_component(case_id, "case_id")
    _validate_component(audit_id, "audit_id")
    _validate_component(tool, "tool")

    root = _output_root()
    target_dir = root / case_id / audit_id
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{tool}.json"

    data = content.encode("utf-8")
    fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)

    return PayloadRef(
        path=str(target),
        sha256=hashlib.sha256(data).hexdigest(),
        bytes=len(data),
        format=mime_format,
    )

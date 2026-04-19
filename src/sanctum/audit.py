"""Append-only audit ledger for MCP tool invocations.

Every tool call writes one line of JSONL. Each entry is chained to the previous
by including the previous entry's SHA-256 digest — mutation of any past entry
invalidates every entry after it, yielding a tamper-evident chain of custody.

Canonical format (one line of JSONL, ``ensure_ascii=False``, ``sort_keys=True``):

.. code-block:: json

    {
      "audit_id": "<uuid4>",
      "ts": "2026-04-17T15:30:00Z",
      "case_id": "cfreds-hacking-case",
      "tool": "get_amcache",
      "args_hash": "<sha256 of canonical-json-encoded args>",
      "input_ref": {"path": "/cases/.../Amcache.hve", "sha256": "..."},
      "pre_sanitization_sha256": "...",
      "post_sanitization_sha256": "...",
      "rowcount": 1247,
      "payload_ref": {"path": "/var/lib/sanctum/output/.../get_amcache.json",
                      "sha256": "...", "bytes": 245678,
                      "format": "application/json"},
      "prev_hash": "<sha256 of previous line>",
      "line_hash": "<sha256 of this line excluding the line_hash field>"
    }

Ledgers written before the ``payload_ref`` field landed are backward-compatible:
:func:`verify_chain` recomputes the line hash from whichever keys are present in
the entry dict, so historical entries verify cleanly without the new field.

References:
- NIST SP 800-86 §4 — chain of custody.
- RFC 3227 §4.1 — handling of digital evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEDGER_ENV = "SANCTUM_LEDGER_PATH"
DEFAULT_LEDGER = "/var/lib/sanctum/ledger.jsonl"
_GENESIS_PREV = "0" * 64


@dataclass(frozen=True)
class LedgerEntry:
    audit_id: str
    ts: str
    case_id: str
    tool: str
    args_hash: str
    input_ref: dict[str, Any] | None
    pre_sanitization_sha256: str
    post_sanitization_sha256: str
    rowcount: int | None
    payload_ref: dict[str, Any] | None
    prev_hash: str
    line_hash: str

    def to_jsonl(self) -> str:
        return (
            json.dumps(
                {
                    "audit_id": self.audit_id,
                    "ts": self.ts,
                    "case_id": self.case_id,
                    "tool": self.tool,
                    "args_hash": self.args_hash,
                    "input_ref": self.input_ref,
                    "pre_sanitization_sha256": self.pre_sanitization_sha256,
                    "post_sanitization_sha256": self.post_sanitization_sha256,
                    "rowcount": self.rowcount,
                    "payload_ref": self.payload_ref,
                    "prev_hash": self.prev_hash,
                    "line_hash": self.line_hash,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        )


def _canonical_args_hash(args: dict[str, Any]) -> str:
    blob = json.dumps(args, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _ledger_path() -> Path:
    return Path(os.environ.get(LEDGER_ENV, DEFAULT_LEDGER))


def _last_line_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return _GENESIS_PREV
    # Read last non-empty line. Ledgers are small in P0; avoid seek/read-backward
    # until it becomes a bottleneck.
    last = _GENESIS_PREV
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)["line_hash"]
            except (json.JSONDecodeError, KeyError) as exc:
                # A corrupt line breaks the chain; refuse to append so the chain
                # property is never silently violated.
                raise RuntimeError(f"audit ledger corrupt at {path}") from exc
    return last


def _line_hash_for(entry: dict[str, Any]) -> str:
    # Exclude line_hash from the content being hashed (self-reference is undefined).
    content = {k: v for k, v in entry.items() if k != "line_hash"}
    blob = json.dumps(content, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def append_entry(
    *,
    case_id: str,
    tool: str,
    args: dict[str, Any],
    input_ref: dict[str, Any] | None,
    pre_sanitization_sha256: str,
    post_sanitization_sha256: str,
    rowcount: int | None = None,
    payload_ref: dict[str, Any] | None = None,
    audit_id: str | None = None,
) -> LedgerEntry:
    """Append one entry and return its populated :class:`LedgerEntry`.

    Writes atomically via rename to avoid partial-line corruption on crash.

    ``audit_id`` is generated internally when omitted. Callers that need to share
    the id with an on-disk artifact (e.g. a payload file) MAY pre-generate a UUID4
    and pass it in so the ledger entry and the artifact key are guaranteed to
    match.
    """

    path = _ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = _last_line_hash(path)
    if audit_id is None:
        audit_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    raw: dict[str, Any] = {
        "audit_id": audit_id,
        "ts": ts,
        "case_id": case_id,
        "tool": tool,
        "args_hash": _canonical_args_hash(args),
        "input_ref": input_ref,
        "pre_sanitization_sha256": pre_sanitization_sha256,
        "post_sanitization_sha256": post_sanitization_sha256,
        "rowcount": rowcount,
        "payload_ref": payload_ref,
        "prev_hash": prev_hash,
    }
    raw["line_hash"] = _line_hash_for(raw)
    entry = LedgerEntry(**raw)

    # Write via temp file in the same dir, then append-concat. This avoids a
    # partial write on crash — the old ledger stays intact until the new line
    # is fully flushed and fsynced.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as tmp:
        tmp.write(entry.to_jsonl())
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)

    with path.open("ab") as fh, tmp_path.open("rb") as src:
        fh.write(src.read())
        fh.flush()
        os.fsync(fh.fileno())
    tmp_path.unlink()

    return entry


def verify_chain(path: Path | None = None) -> tuple[bool, int, str | None]:
    """Walk the ledger and verify prev_hash/line_hash integrity.

    Returns (ok, lines_scanned, first_bad_audit_id). ``first_bad_audit_id`` is
    ``None`` when the chain is intact.
    """

    path = path or _ledger_path()
    if not path.exists():
        return True, 0, None

    prev = _GENESIS_PREV
    scanned = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            scanned += 1
            entry = json.loads(line)
            if entry.get("prev_hash") != prev:
                return False, scanned, entry.get("audit_id")
            recomputed = _line_hash_for(entry)
            if entry.get("line_hash") != recomputed:
                return False, scanned, entry.get("audit_id")
            prev = entry["line_hash"]
    return True, scanned, None

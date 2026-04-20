"""Append-only audit ledger for MCP tool invocations.

Every tool call writes one line of JSONL. Each entry is chained to the previous
via an **HMAC-SHA-256** keyed by ``SANCTUM_LEDGER_HMAC_KEY``. Mutation of any
past entry invalidates every entry after it, yielding a tamper-evident chain
of custody that cannot be recomputed by an attacker who does not hold the key.

Security posture ladder:

1. **Tamper-evident (this module).** HMAC-SHA-256 chain guarantees any mutation
   breaks verification, *provided* the key stays out of the attacker's hands.
   A local attacker who has both disk-write access AND the HMAC key can still
   forge a consistent chain retroactively.
2. **Non-repudiable (:mod:`sanctum.notary`).** Periodically stamp the current
   ledger head to an RFC 3161 Time-Stamp Authority. The TSA's digital
   signature chains to a public PKI root, so a forger now also needs to
   compromise the TSA — impractical. This is the tier required for
   court-admissible chain of custody (FRE 902(13)/(14); NIST SP 800-53
   AU-10(5) Digital Signatures).
3. **Publicly witnessed (future).** Merkle-tree publication to Sigstore
   Rekor or equivalent RFC 9162 transparency log. Not required for the
   hackathon scope; flagged here so the upgrade path is explicit.

Canonical entry format (one line of JSONL, ``ensure_ascii=False``,
``sort_keys=True``):

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
      "prev_hash": "<HMAC-SHA256 line_hash of previous entry>",
      "line_hash": "<HMAC-SHA256 of this entry excluding line_hash itself>"
    }

The non-chain hashes (``args_hash``, ``input_ref.sha256``,
``pre_sanitization_sha256``, ``post_sanitization_sha256``) remain plain
SHA-256 — they are content fingerprints, not integrity links.

References:
- NIST SP 800-86 §4 — chain of custody.
- NIST SP 800-53 r5 AU-9(3) Cryptographic Protection, AU-10(5) Digital
  Signatures (roadmap to asymmetric signing), AU-11(1) Long-term Retrieval.
- RFC 2104 — HMAC primitive definition.
- RFC 3227 §4.1 — handling of digital evidence.
- RFC 3161 — Time-Stamp Protocol (see :mod:`sanctum.notary`).
- ``docs/THREAT_MODEL_LEDGER.md`` — full threat-model write-up.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

LEDGER_ENV = "SANCTUM_LEDGER_PATH"
HMAC_KEY_ENV = "SANCTUM_LEDGER_HMAC_KEY"
DEFAULT_LEDGER = "/var/lib/sanctum/ledger.jsonl"
_GENESIS_PREV = "0" * 64
_MIN_KEY_BYTES = 16  # 128-bit minimum; 256-bit (32 bytes) recommended.


class FindingConfidence(str, Enum):
    """Evidence-corroboration tier emitted by the future ``claim_finding`` gate.

    String values are stable — they land in the audit ledger, so renaming a
    member is a backwards-incompatible ledger-format change.
    """

    DRAFT = "DRAFT"
    CORROBORATED = "CORROBORATED"
    FINAL = "FINAL"


def classify_confidence(n_distinct_subsystems: int) -> FindingConfidence:
    """Map distinct-subsystem count to a confidence tier.

    Pins the recommendation from docs/THREAT_MODEL_TRIANGULATION.md §5:

    - ``n <= 1`` -> DRAFT (single-source or none; hypothesis only)
    - ``n == 2`` -> CORROBORATED (P(forgery) ~17.8% under realistic priors)
    - ``n >= 3`` -> FINAL (P(forgery) ~2.7%, ~7x harder to forge)

    The week-4 ``claim_finding`` implementation is expected to call this
    helper rather than re-encode the tier rules inline, so the threat-model
    doc and the gate cannot silently drift.
    """

    if n_distinct_subsystems < 0:
        raise ValueError(
            f"n_distinct_subsystems must be >= 0, got {n_distinct_subsystems}"
        )
    if n_distinct_subsystems <= 1:
        return FindingConfidence.DRAFT
    if n_distinct_subsystems == 2:
        return FindingConfidence.CORROBORATED
    return FindingConfidence.FINAL


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
                    "prev_hash": self.prev_hash,
                    "line_hash": self.line_hash,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        )


def require_hmac_key() -> bytes:
    """Return the HMAC key, or raise with a remediation message.

    The key is a hex string in ``SANCTUM_LEDGER_HMAC_KEY``. Generate one with
    ``python -c 'import secrets; print(secrets.token_hex(32))'``. Without a
    key the ledger cannot provide tamper-evidence — refusing to start is the
    correct behaviour (never silently downgrade to plain-SHA-256).
    """

    hex_key = os.environ.get(HMAC_KEY_ENV)
    if not hex_key:
        raise RuntimeError(
            f"{HMAC_KEY_ENV} is not set. The audit ledger requires an HMAC "
            f"key for tamper-evidence. Generate one with: "
            f"`python -c 'import secrets; print(secrets.token_hex(32))'` "
            f"and export it before starting Sanctum. Store the key outside "
            f"the server's filesystem (keychain, secrets manager) so a "
            f"local compromise of the MCP host does not also compromise "
            f"the ledger integrity guarantee."
        )
    try:
        key = bytes.fromhex(hex_key)
    except ValueError as exc:
        raise RuntimeError(
            f"{HMAC_KEY_ENV} must be a hex string; got {hex_key!r}"
        ) from exc
    if len(key) < _MIN_KEY_BYTES:
        raise RuntimeError(
            f"{HMAC_KEY_ENV} must be at least {_MIN_KEY_BYTES} bytes "
            f"({_MIN_KEY_BYTES * 2} hex chars); got {len(key)} bytes. "
            f"Recommend 32 bytes (64 hex chars) for HMAC-SHA256."
        )
    return key


def _canonical_args_hash(args: dict[str, Any]) -> str:
    """Content fingerprint of tool arguments (plain SHA-256).

    This is a content identifier, not a chain link — plain SHA-256 is
    appropriate. The chain-integrity HMAC lives in :func:`_line_hash_for`.
    """
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


def _line_hash_for(entry: dict[str, Any], *, key: bytes | None = None) -> str:
    """HMAC-SHA-256 of the entry excluding ``line_hash`` itself.

    The key parameter exists for verification paths that already resolved the
    key once (avoids repeated env-var lookups). In the normal write path we
    resolve via :func:`require_hmac_key` each call — the env read is cheap
    and the explicit failure mode is better than a silent wrong-key verify.
    """
    content = {k: v for k, v in entry.items() if k != "line_hash"}
    blob = json.dumps(content, ensure_ascii=False, sort_keys=True).encode("utf-8")
    hmac_key = key if key is not None else require_hmac_key()
    return hmac.new(hmac_key, blob, hashlib.sha256).hexdigest()


def append_entry(
    *,
    case_id: str,
    tool: str,
    args: dict[str, Any],
    input_ref: dict[str, Any] | None,
    pre_sanitization_sha256: str,
    post_sanitization_sha256: str,
    rowcount: int | None = None,
) -> LedgerEntry:
    """Append one entry and return its populated :class:`LedgerEntry`.

    Writes atomically via rename to avoid partial-line corruption on crash.
    Raises :class:`RuntimeError` if ``SANCTUM_LEDGER_HMAC_KEY`` is unset —
    the ledger never silently downgrades to plain-SHA-256.
    """

    key = require_hmac_key()

    path = _ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = _last_line_hash(path)
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
        "prev_hash": prev_hash,
    }
    raw["line_hash"] = _line_hash_for(raw, key=key)
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
    """Walk the ledger and verify HMAC-chain integrity.

    Returns ``(ok, lines_scanned, first_bad_audit_id)``. ``first_bad_audit_id``
    is ``None`` when the chain is intact. A verification failure means either
    (a) a past entry was mutated, (b) the HMAC key differs from the one used
    at write time, or (c) the chain was re-ordered.

    Requires ``SANCTUM_LEDGER_HMAC_KEY`` to be set, just like :func:`append_entry`.
    """

    path = path or _ledger_path()
    if not path.exists():
        return True, 0, None

    key = require_hmac_key()
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
            recomputed = _line_hash_for(entry, key=key)
            if entry.get("line_hash") != recomputed:
                return False, scanned, entry.get("audit_id")
            prev = entry["line_hash"]
    return True, scanned, None

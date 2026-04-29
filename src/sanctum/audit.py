"""Append-only audit ledger for MCP tool invocations.

Every tool call writes one line of JSONL. Each entry is chained to the previous
via an **HMAC-SHA-256** keyed by ``SANCTUM_LEDGER_HMAC_KEY``. Mutation of any
past entry invalidates every entry after it, yielding a tamper-evident record
chain that cannot be recomputed by an attacker who does not hold the key.

Security posture ladder:

1. **Tamper-evident (this module).** HMAC-SHA-256 chain guarantees any mutation
   breaks verification, *provided* the key stays out of the attacker's hands.
   A local attacker who has both disk-write access AND the HMAC key can still
   forge a consistent chain retroactively.
2. **Non-repudiable (:mod:`sanctum.notary`).** Periodically stamp the current
   ledger head to an RFC 3161 Time-Stamp Authority. The TSA's digital
   signature chains to a public PKI root, so a forger now also needs to
   compromise the TSA — impractical. This is the non-repudiable posture
   rung for IR-accountability; FRE 902(13)/(14) and NIST SP 800-53
   AU-10(5) Digital Signatures are downstream legal corollaries.
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
      "payload_ref": {"path": "...", "sha256": "...", "bytes": 4096,
                      "format": "application/json"},
      "prev_hash": "<HMAC-SHA256 line_hash of previous entry>",
      "line_hash": "<HMAC-SHA256 of this entry excluding line_hash itself>"
    }

The ``payload_ref`` field is OPTIONAL — entries written before the
payload-offload feature OR by callers that don't produce an offload
payload OMIT the key entirely (the canonical bytes do NOT contain
``"payload_ref": null``). This omit-not-null contract preserves
bytewise hash compatibility with pre-feature ledgers; see AC-10 in
the payload-offload plan.

The non-chain hashes (``args_hash``, ``input_ref.sha256``,
``pre_sanitization_sha256``, ``post_sanitization_sha256``,
``payload_ref.sha256``) remain plain SHA-256 — they are content
fingerprints, not integrity links. The ``line_hash`` (HMAC-SHA-256)
is what binds these fingerprints into the chain.

References:
- NIST SP 800-86 §4 — evidence handling and integrity procedures.
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
    """Evidence-corroboration tier emitted by the ``claim_finding`` gate.

    String values are stable — they land in the audit ledger, so renaming a
    member is a backwards-incompatible ledger-format change.

    Tier order from weakest to strongest:
    ``DRAFT_TAMPER_SUSPECTED < DRAFT < CORROBORATED < FINAL``.

    ``DRAFT_TAMPER_SUSPECTED`` is the post-demotion tier emitted when a
    single-family claim is also accompanied by an active ``sanctum.deception``
    signal — the analyst sees both the weak corroboration AND the named
    anti-forensic suspicion, so the audit trail records *why* the finding
    was held below ``DRAFT``.
    """

    DRAFT_TAMPER_SUSPECTED = "DRAFT_TAMPER_SUSPECTED"
    DRAFT = "DRAFT"
    CORROBORATED = "CORROBORATED"
    FINAL = "FINAL"


def classify_confidence(
    n_distinct_subsystems: int,
    *,
    deception_signal_present: bool = False,
) -> FindingConfidence:
    """Map distinct-subsystem count to a confidence tier.

    Pins the recommendation from docs/THREAT_MODEL_TRIANGULATION.md §5:

    - ``n <= 1`` -> DRAFT (single-source or none; hypothesis only)
    - ``n == 2`` -> CORROBORATED (P(forgery) ~17.8% under realistic priors)
    - ``n >= 3`` -> FINAL (P(forgery) ~2.7%, ~7x harder to forge)

    When ``deception_signal_present`` is True the result is demoted one
    tier (FINAL→CORROBORATED, CORROBORATED→DRAFT, DRAFT→DRAFT_TAMPER_SUSPECTED).
    Demotion is binary in signal-count by design (see
    ``docs/THREAT_MODEL_DECEPTION.md``): a second signal in the same case is
    not independent evidence of more tampering — typically one attacker
    runs one anti-forensic toolkit, so signals are correlated. Treating
    signal-count as binary avoids correlation double-counting.

    ``claim_finding`` calls this helper rather than re-encoding tier rules
    inline, so the threat-model doc and the gate cannot silently drift.
    """

    if n_distinct_subsystems < 0:
        raise ValueError(f"n_distinct_subsystems must be >= 0, got {n_distinct_subsystems}")
    if n_distinct_subsystems <= 1:
        base = FindingConfidence.DRAFT
    elif n_distinct_subsystems == 2:
        base = FindingConfidence.CORROBORATED
    else:
        base = FindingConfidence.FINAL

    if not deception_signal_present:
        return base
    return _demote(base)


_DEMOTION: dict[FindingConfidence, FindingConfidence] = {
    FindingConfidence.FINAL: FindingConfidence.CORROBORATED,
    FindingConfidence.CORROBORATED: FindingConfidence.DRAFT,
    FindingConfidence.DRAFT: FindingConfidence.DRAFT_TAMPER_SUSPECTED,
    FindingConfidence.DRAFT_TAMPER_SUSPECTED: FindingConfidence.DRAFT_TAMPER_SUSPECTED,  # floor
}


def _demote(tier: FindingConfidence) -> FindingConfidence:
    """One-tier demotion. ``DRAFT_TAMPER_SUSPECTED`` is the floor."""
    return _DEMOTION[tier]


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
    # Forward-compat sentinel: ``None`` means "this entry was written by a
    # caller that did not produce an offload payload" — the canonical JSON
    # form OMITS the ``payload_ref`` key entirely so legacy ledgers (entries
    # that pre-date this field) hash bytewise-identically post-feature.
    # Emitting ``"payload_ref": null`` would silently break ``verify_chain``
    # on every pre-feature line. See AC-10.
    payload_ref: dict[str, Any] | None = None
    elapsed_ms: int | None = None  # wall-clock milliseconds for the tool call
    token_estimate: dict[str, int] | None = None  # {"input": int, "output": int} LLM token counts

    def __post_init__(self) -> None:
        # Construction-time invariants for instrumentation fields. Caught here so
        # malformed entries never reach the chain — a negative elapsed_ms or a
        # typo'd token_estimate key would otherwise be silently HMAC-signed and
        # later trip a downstream consumer with no way to localise the bug.
        if self.elapsed_ms is not None and self.elapsed_ms < 0:
            raise ValueError(f"elapsed_ms must be non-negative, got {self.elapsed_ms}")
        if self.token_estimate is not None and set(self.token_estimate.keys()) != {"input", "output"}:
            raise ValueError(
                f"token_estimate must have exactly keys {{'input', 'output'}}, "
                f"got {sorted(self.token_estimate.keys())}"
            )

    def to_jsonl(self) -> str:
        body: dict[str, Any] = {
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
        }
        if self.payload_ref is not None:
            body["payload_ref"] = self.payload_ref
        if self.elapsed_ms is not None:
            body["elapsed_ms"] = self.elapsed_ms
        if self.token_estimate is not None:
            body["token_estimate"] = self.token_estimate
        return json.dumps(body, ensure_ascii=False, sort_keys=True) + "\n"


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
        raise RuntimeError(f"{HMAC_KEY_ENV} must be a hex string; got {hex_key!r}") from exc
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
    payload_ref: dict[str, Any] | None = None,
    audit_id: str | None = None,
    elapsed_ms: int | None = None,
    token_estimate: dict[str, int] | None = None,
) -> LedgerEntry:
    """Append one entry and return its populated :class:`LedgerEntry`.

    Writes atomically via rename to avoid partial-line corruption on crash.
    Raises :class:`RuntimeError` if ``SANCTUM_LEDGER_HMAC_KEY`` is unset —
    the ledger never silently downgrades to plain-SHA-256.

    Optional kwargs:

    - ``payload_ref``: when not None, HMAC-covered in ``line_hash`` — a
      swapped offload payload breaks ``verify_chain``. Omitted (not null)
      when None so legacy ledgers verify bytewise-identically (AC-10).
    - ``audit_id``: pre-mint UUID so on-disk offload path and ledger entry
      share the same key by construction (AC-7). Minted here when None.
    - ``elapsed_ms``, ``token_estimate``: instrumentation fields — omitted
      from the JSONL line when None so pre/post-instrumentation entries
      co-exist in a single chain without breaking ``verify_chain``.
    """

    key = require_hmac_key()

    path = _ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = _last_line_hash(path)
    resolved_audit_id = audit_id if audit_id is not None else str(uuid.uuid4())
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    raw: dict[str, Any] = {
        "audit_id": resolved_audit_id,
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
    # Conditional includes — omit-not-null for forward-compat (see
    # ``LedgerEntry.payload_ref`` and instrumentation field docs).
    if payload_ref is not None:
        raw["payload_ref"] = payload_ref
    if elapsed_ms is not None:
        raw["elapsed_ms"] = elapsed_ms
    if token_estimate is not None:
        raw["token_estimate"] = token_estimate
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


def verify_chain(path: Path | None = None) -> tuple[bool, int | None, str | None]:
    """Walk the ledger and verify HMAC-chain integrity.

    Returns ``(ok, first_bad_line_1based, first_bad_audit_id)``:

    - On a clean (or missing/empty) ledger: ``(True, None, None)``.
    - On HMAC drift at line K (1-based): ``(False, K, audit_id_at_line_K)``.

    A verification failure means either (a) a past entry was mutated
    (including any covered field — ``payload_ref`` is HMAC-covered, so
    swapping a payload's SHA-256 breaks verification — see AC-4), (b) the
    HMAC key differs from the one used at write time, or (c) the chain was
    re-ordered.

    Requires ``SANCTUM_LEDGER_HMAC_KEY`` to be set, just like :func:`append_entry`.
    """

    path = path or _ledger_path()
    if not path.exists():
        return True, None, None

    key = require_hmac_key()
    prev = _GENESIS_PREV
    line_no = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            line_no += 1
            entry = json.loads(line)
            if entry.get("prev_hash") != prev:
                return False, line_no, entry.get("audit_id")
            recomputed = _line_hash_for(entry, key=key)
            if entry.get("line_hash") != recomputed:
                return False, line_no, entry.get("audit_id")
            prev = entry["line_hash"]
    return True, None, None

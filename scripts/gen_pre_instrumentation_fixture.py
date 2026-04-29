"""Generate tests/fixtures/ledger_pre_instrumentation.jsonl and companion .key file.

This script produces a 3-entry HMAC-chained ledger using the PRE-extension
format (no elapsed_ms / token_estimate keys) so that
test_verify_chain_accepts_pre_extension_ledger and
test_verify_chain_accepts_mixed_ledger (tests/test_audit.py) can prove
the AC-7 backwards-compat property: a ledger written before the
instrumentation extension landed still verifies after the extension.

DO NOT re-run unless the fixture file has been lost. The committed fixture
bytes are bound to a fixed HMAC key (HMAC_KEY_HEX below); regenerating would
produce different audit_ids / timestamps / line_hashes, and the new chain
would no longer match the key the tests pin. Treat the fixture as frozen
once committed.

If you DO need to regenerate (file lost), run once and commit both output
files; the test sets HMAC_KEY via the matching env var:
    python3 scripts/gen_pre_instrumentation_fixture.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent.parent / "tests" / "fixtures"
FIXTURE_PATH = FIXTURE_DIR / "ledger_pre_instrumentation.jsonl"
KEY_PATH = FIXTURE_DIR / "ledger_pre_instrumentation.key"

# Fixed key so the fixture is reproducible; do NOT reuse in production.
HMAC_KEY_HEX = "deadbeefcafe0011223344556677889900aabbccddeeff00112233445566778899"
HMAC_KEY_BYTES = bytes.fromhex(HMAC_KEY_HEX)

GENESIS_PREV = "0" * 64


def _line_hash(entry_without_line_hash: dict) -> str:
    blob = json.dumps(entry_without_line_hash, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hmac.new(HMAC_KEY_BYTES, blob, hashlib.sha256).hexdigest()


def _args_hash(args: dict) -> str:
    blob = json.dumps(args, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    entries = []
    prev_hash = GENESIS_PREV
    for i in range(3):
        ts = datetime(2026, 1, 1, 0, i, 0, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw: dict = {
            "audit_id": str(uuid.UUID(int=i + 1)),  # deterministic UUIDs
            "ts": ts,
            "case_id": "pre-ext-case",
            "tool": "get_amcache",
            "args_hash": _args_hash({"run": i}),
            "input_ref": None,
            "pre_sanitization_sha256": "a" * 64,
            "post_sanitization_sha256": "b" * 64,
            "rowcount": i,
            "prev_hash": prev_hash,
        }
        raw["line_hash"] = _line_hash(raw)
        entries.append(raw)
        prev_hash = raw["line_hash"]

    with FIXTURE_PATH.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    KEY_PATH.write_text(HMAC_KEY_HEX + "\n", encoding="utf-8")
    print(f"Wrote {len(entries)} entries to {FIXTURE_PATH}")
    print(f"Wrote HMAC key to {KEY_PATH}")


if __name__ == "__main__":
    main()

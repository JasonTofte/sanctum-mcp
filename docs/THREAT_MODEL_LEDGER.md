# Threat model — audit-ledger integrity

*Quantitative threat model for the append-only ledger in
[`src/sanctum/audit.py`](../src/sanctum/audit.py) and the RFC 3161 notary
helper in [`src/sanctum/notary.py`](../src/sanctum/notary.py).*

This document pairs with [`docs/THREAT_MODEL_TRIANGULATION.md`](THREAT_MODEL_TRIANGULATION.md)
and [`docs/THREAT_MODEL_SANITIZATION.md`](THREAT_MODEL_SANITIZATION.md) —
the ledger is the evidentiary spine that holds the other two claims
together. Every `claim_finding` verdict cites `audit_ids[]`; every tool
call binds its input and output hashes into one ledger entry. If the
ledger can be forged, every downstream claim becomes unfalsifiable.

## Posture ladder

The implementation climbs three rungs, in order. Each rung defends against
a strictly stronger attacker than the previous.

| Rung | Primitive | Defeats | Fails against |
|------|-----------|---------|---------------|
| 0 | plain SHA-256 chain *(prior implementation — no longer used)* | post-hoc accidental edit | any attacker with ledger write access |
| 1 | HMAC-SHA-256 chain keyed by `SANCTUM_LEDGER_HMAC_KEY` | attacker with ledger write access but no key | attacker who compromises the HMAC key (local root, memory dump) |
| 2 | rung 1 + RFC 3161 TSA stamp of ledger head (this doc) | attacker with ledger write access **and** HMAC key | attacker who also compromises the TSA signing cert |
| 3 | rung 2 + public Merkle-tree witness (Sigstore Rekor) | rung-2 attacker plus TSA compromise | attacker who compromises both TSA and public log (practically infeasible) |

Rung 2 is the tier required for court-admissible chain of custody under
FRE 902(13)/(14). Rung 3 is the roadmap item flagged in
[FAILURE_MODES State 5](FAILURE_MODES.md#state-5-audit-ledger-tampered-post-hoc).

Sanctum currently ships rung 2. Before this document landed the code was
at rung 0 despite the README claiming rung 1 — the single biggest
inaccuracy found by the internal architecture audit.

## Attack model — rung 1 (HMAC chain)

- **Attacker capability.** Write access to the ledger file
  (`/var/lib/sanctum/ledger.jsonl`) after at least one legitimate tool call
  has been logged.
- **Defender posture.** Every line's `line_hash` is `HMAC-SHA256(K, canonical(entry − line_hash))`
  where `K` = `SANCTUM_LEDGER_HMAC_KEY`. Linkage: each entry's `prev_hash` equals the
  previous entry's `line_hash`.
- **Forgery requirement.** To rewrite entry `i` without detection, the
  attacker must produce `line_hash_i' = HMAC-SHA256(K, entry_i')` such that
  subsequent entries' `prev_hash` chain remains consistent. Without knowing
  `K`, the computation is cryptographically infeasible (HMAC-SHA-256 is
  considered secure for ≥ 128-bit keys per NIST SP 800-107; Sanctum
  enforces ≥ 128-bit via `_MIN_KEY_BYTES`).
- **Residual risk.** The key lives in an environment variable. Anyone who
  can read the server process's environment (e.g., `/proc/<pid>/environ`
  on Linux for the same UID) can extract it. For operator hygiene:
  - Store the key in a platform keychain (macOS Keychain, Linux
    `secret-tool`, HSM, or cloud KMS) and pass it to the server via a
    short-lived environment load.
  - Rotate the key between cases so a single leaked key does not
    retroactively compromise cross-case ledger confidence.
  - Never commit the key to git or checked-in env files — `CLAUDE.md`
    classifies it as a secret.

## Attack model — rung 2 (RFC 3161 witness)

- **Attacker capability.** Write access to the ledger AND the HMAC key.
  The attacker produces a self-consistent forged chain.
- **Defender posture.** At chosen cadence, Sanctum calls
  [`notary.stamp_head()`](../src/sanctum/notary.py) which:
  1. Reads the current ledger head (last `line_hash`).
  2. Constructs an RFC 3161 `TimeStampReq` binding that hash via SHA-256.
  3. POSTs the request to a TSA; receives a `TimeStampToken` signed by
     the TSA's private key.
  4. Archives `.tsq` (request) and `.tsr` (response) bytes alongside the
     ledger.
- **Forgery requirement.** To forge a past state that survives the TSA
  witness, the attacker must:
  1. Produce a forged HMAC chain (requires `K`), AND
  2. Produce a TSA-signed `TimeStampToken` for the forged head
     (requires the TSA's signing private key or a compromised TSA).
  A single attacker must now compromise two trust domains: the local
  MCP host *and* the external TSA operator. This is the structural
  difference between tamper-evidence and non-repudiation.
- **Residual risk.** The attacker replaces the `.tsr` file alongside the
  ledger with a file they generated against a forged head. Defence: the
  `.tsr` file is cryptographically signed by the TSA — local replacement
  requires the same TSA compromise as above. An **offline** notary — one
  that stamps to multiple independent TSAs — raises the bar to compromise
  *all* TSAs used. The `tsa_url` parameter of `stamp_head` supports this
  (call once per TSA per cadence).

## Operational guidance

### How often to stamp

The cadence trades forensic granularity against TSA cost and operator
burden:

| Cadence | Good fit | Trade-off |
|---------|----------|-----------|
| Once per session | Live IR engagement with a clear start/end | One stamp covers the whole session — earlier entries have weaker time binding |
| Once per N entries (e.g., every 100) | Long-running continuous monitoring | Operator must reason about the gap between the last stamp and a potential forgery window |
| Once per hour | Compliance/regulated environments | Predictable cost profile; aligns with NIST SP 800-92 log-management guidance |

For the FIND EVIL! hackathon demo, **once per session** is sufficient and
what the reference configuration ships.

### Verifying a stamp

An independent party verifies a `.tsr` by:

```bash
# Extract the signed-hash and timestamp.
openssl ts -reply -in ledger.jsonl.tsr.<ts> -text
# Verify the signature against the TSA's published cert.
openssl ts -verify -in ledger.jsonl.tsr.<ts> \
    -data <(printf "%s" "$(python -c 'from sanctum.audit import _last_line_hash, _ledger_path; print(_last_line_hash(_ledger_path()))')") \
    -CAfile /path/to/tsa-cert-chain.pem
```

Success means the TSA asserts the ledger head had that exact value at the
timestamp in the token. Failure can mean (a) the ledger was edited after
the stamp, (b) the wrong `.tsr` was paired with the ledger, or (c) the
TSA cert chain is stale — investigate in that order.

## Relation to existing tests

- [`tests/test_audit.py::test_verify_chain_fails_with_wrong_key`](../tests/test_audit.py)
  — pins rung-1 property: HMAC key swap breaks verification.
- [`tests/test_audit.py::test_missing_hmac_key_refuses_append`](../tests/test_audit.py)
  — server refuses to silently downgrade to plain-SHA-256.
- [`tests/test_notary.py::test_stamp_head_binds_to_current_head_hash`](../tests/test_notary.py)
  — rung 2: the TSA witness is always bound to the actual ledger head.
- [`tests/test_notary.py::test_stamp_head_raises_on_tsa_rejection`](../tests/test_notary.py)
  — failure surfaces loudly; there is no silent-success path.

## Residual obligations

1. **Key custody.** This doc specifies the threat model under which HMAC
   protects the chain; it does not specify the key-management plan.
   Operators must decide where `SANCTUM_LEDGER_HMAC_KEY` lives and how it
   is rotated.
2. **TSA availability.** A stamp failure means rung 2 is temporarily
   absent — the ledger is still rung-1 tamper-evident, but a hackathon
   demo should not depend on network-reachable TSA. `notary.stamp_head`
   raises on network errors so the operator sees them; a production
   deployment would queue the stamp for retry.
3. **Multi-TSA fanout.** Not yet implemented. A simple extension would be
   a list of TSA URLs in a wrapper around `stamp_head` — flagged here so
   the upgrade path is explicit.
4. **Archival storage.** The `.tsr` files must survive the same retention
   window as the ledger itself (NIST SP 800-53 AU-11(1)). WORM storage
   (S3 Object Lock, on-prem append-only partition) is the standard
   pattern; Sanctum leaves the choice to the operator's compliance
   posture.

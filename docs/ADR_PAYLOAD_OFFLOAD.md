# Architecture Decision Record — Payload offload (PR #4 successor)

This document captures the load-bearing architectural decisions made
when introducing universal payload offload to Sanctum's typed MCP tools.
It exists because the planning artifact `.sherlock-plan.md` is a
working file (gitignored prefix `.`) rather than permanent reference;
future contributors need to know **why** the offload pattern is shaped
the way it is without re-reading the planning trail.

Each decision below is in
[ADR-lite format](https://adr.github.io/madr/): context, decision,
status, consequences, alternatives considered, and the test that pins
the invariant. Status `Accepted` means the decision is live in code;
`Superseded` would mean a later ADR replaced it.

The five decisions below were the BLOCKING items in the planning gate
for this PR; the user approved the recommended choice for each
(`A, A, A, A, C`) on 2026-04-28.

---

## ADR-PO-001 — Offload directory location and env var: `SANCTUM_OUTPUT_ROOT`

**Status.** Accepted (2026-04-29).

**Context.** The MCP stdio transport silently drops JSON-RPC responses
larger than ~800–1100 bytes
([anthropics/claude-code#36319](https://github.com/anthropics/claude-code/issues/36319)).
Sanctum's typed tools (`get_amcache`, `claim_finding`) routinely
produce forensic evidence dumps that exceed this. The chosen mitigation
is to write the full sanitized payload to a write-once on-disk file
and return only a short summary. That file needs a configurable root
that is (a) writable by the server, (b) **not** writable under
`/cases/` or `/evidence/` (CLAUDE.md invariant 4 — runtime statvfs
ro-check), and (c) consistent with the existing `SANCTUM_*` env-var
convention.

**Decision.** New env var `SANCTUM_OUTPUT_ROOT` with default
`/var/lib/sanctum/output`, mirroring the existing `/var/lib/sanctum/`
location for the ledger. A startup guard
(`payload.validate_offload_root_distinct_from_cases_root`) refuses to
start if either path does not exist OR if `SANCTUM_OUTPUT_ROOT.resolve()`
is a sub-path of `SANCTUM_CASES_ROOT.resolve()`. The actionable error
names both env-var names so the operator knows which to fix.

**Consequences.**

- Operator pre-creates the directory with explicit `mkdir + chown` and
  documents deployment intent. Parity with `_validate_evidence_mount`'s
  "cases root must exist" guard (`server.py:79-82`).
- If the operator misconfigures the offload root to land under the
  read-only evidence mount, the server fail-closes at startup before
  serving any tool calls — never silently degrades.
- Adds one new env var to the deployment surface; documented in
  `CHANGELOG.md` under the feature entry.

**Alternatives considered.**

- **Reuse `SANCTUM_LEDGER_PATH`'s parent**, no new env var — implicit
  coupling between ledger and offload roots. Rejected: makes future
  splitting (e.g., S3-backed offload) require a config-shape break.
- **Caller-supplied per-tool root** — maximum flexibility but every
  tool wrapper would surface a path arg, conflicting with the
  `mcp.tool()` typed-function constraint and increasing attack surface.

**Pinned by.** `tests/test_payload.py::test_validate_offload_root_*`
(AC-7, AC-11; covers subpath, exact-match, missing-cases-root, and
distinct-roots accept paths) and
`tests/test_server_boundaries.py::test_validate_offload_root_distinct_from_cases_root_rejects_overlap`,
`::test_validate_offload_root_distinct_accepts_separate_paths`,
`::test_validate_offload_root_missing_env_refused` — plus the
`_validate_offload_root_distinct_from_cases_root` call in
`server.main()` boot sequence.

---

## ADR-PO-002 — `audit_id` is pre-minted in the tool wrapper

**Status.** Accepted (2026-04-29).

**Context.** The offload file path embeds `audit_id` as a directory
component (`<root>/<case_id>/<audit_id>/<tool>.json`) and the ledger
entry references the SAME `audit_id`. Because the file is written
write-once via `O_CREAT|O_EXCL`, a post-hoc rename to align the two is
not an option: a second write at a different path would create a
divergent on-disk artifact, and renaming the original would require
disabling write-once. The two keys must agree by construction.

**Decision.** The tool wrapper (or, more precisely, the universal
`_emit_offloaded_response` helper in `server.py`) mints
`audit_id = uuid.uuid4()` once and passes it both to
`payload.write_payload(audit_id=…)` and to
`audit.append_entry(audit_id=…)`. `append_entry` accepts a new optional
`audit_id` kwarg that, when present, is used directly; when absent
(legacy callers, tests), the function mints its own UUID — preserving
backward compatibility.

**Consequences.**

- The on-disk path and the ledger entry share a key by construction,
  not by happy coincidence. A regression in either codepath surfaces
  as a missing-file or missing-ledger-entry error, not a silent drift.
- One extra optional kwarg on `append_entry`. The `audit_id is None`
  fallback keeps every pre-feature test green without modification.
- The crash-window between write and append (Risk Watch #1 in the
  planning gate) is localised to one site (`_emit_offloaded_response`)
  and contained by the orphan-log contract (see ADR-PO-005).

**Alternatives considered.**

- **Generate inside `append_entry`**, then rename payload file
  post-hoc — breaks write-once invariant; introduces a state where the
  on-disk file exists at the wrong path before the rename completes.
- **Generate inside `append_entry`**; defer payload write until after
  `append_entry` returns — reverses today's invariant and relocates
  the divergent-state risk to a different site without eliminating it.
  Net change in security: zero; net change in code complexity:
  positive.

**Pinned by.** `tests/test_server_boundaries.py::test_get_amcache_response_surfaces_audit_id`
and `::test_get_amcache_full_offload_round_trip` (AC-1; both confirm the
response's `audit_id` matches the latest ledger entry and the on-disk
path), plus `tests/test_audit.py::test_append_entry_uses_caller_supplied_audit_id`
and `::test_append_entry_mints_audit_id_when_omitted` (the optional-kwarg
contract).

---

## ADR-PO-003 — Payload retrieval via Claude Code's generic `Read` tool

**Status.** Accepted (2026-04-29).

**Context.** Once a payload is offloaded to disk and the response
carries a `payload_ref`, the LLM needs to read the file. Two retrieval
shapes were on the table: a new typed Sanctum tool (`get_payload`)
that re-runs sanitization and could enforce its own ACL, or the
generic file-read tool the LLM host already has.

**Decision.** Generic Claude Code `Read` tool. Sanctum does not ship a
`get_payload` typed tool. The system prompt instructs the agent to
treat any read content as `<evidence-untrusted>` (the wrapper
`sanctum.sanitize.wrap_evidence` already produces this on the inline
summary; the offloaded JSON is sanitized at write time, so a re-read
sees post-sanitization bytes).

**Consequences.**

- Single-host deployment — `SANCTUM_OUTPUT_ROOT` is on a path the LLM
  host's tooling can already reach. No new transport.
- Retrieval is **ungated** — the family-corroboration gate fires at
  *claim* time (`claim_finding`), not at *read* time. This matches the
  documented threat-model boundary in
  `docs/THREAT_MODEL_TRIANGULATION.md` (the gate is a claim-time
  mechanism; adding read-time gating would muddle it).
- Cross-case isolation is enforced on the **write path** (the path is
  rooted at `<root>/<case_id>/<audit>/<tool>.json` by construction in
  `_emit_offloaded_response` and `payload.write_payload`), not on the
  read path. The original AC-5 ("read-time path respects case-scoped
  allowlist") was reframed during planning as "Sanctum's own write-path
  code paths produce only case-scoped paths" — the testable invariant
  on Sanctum's surface, since read-tool behaviour is the host's
  concern.
- Future deployments that span multiple hosts (operator runs Sanctum
  on a different machine than the LLM client) would need a typed
  `get_payload` tool; that is explicitly not the v1 deployment shape.

**Alternatives considered.**

- **Typed `get_payload(audit_id) -> str` Sanctum tool** — re-runs
  sanitization-on-read, could enforce family-gate-style ACL. Rejected
  for v1: adds a new ACL surface and conflates the gate's claim-time
  semantics with read-time. Reconsider when multi-host deployment
  becomes a real shape.
- **Hybrid: generic `Read` for normal flow, typed `get_payload` only
  when the payload was deception-flagged at write time** — bifurcates
  the retrieval surface for marginal benefit; the deception-flag is
  already surfaced in the inline summary's `demoted_for_tamper` field.

**Pinned by.** `tests/test_server_boundaries.py::test_get_amcache_full_offload_round_trip`
(AC-5 reframed; asserts `payload_ref.path` is rooted at
`<SANCTUM_OUTPUT_ROOT>/<case_id>/<audit_id>/<tool>.json`),
`::test_case_path_traversal_is_rejected`, `::test_absolute_case_id_is_rejected`,
and `::test_claim_finding_rejects_unsafe_case_id` (case-scoped path
discipline at the wrapper boundary), plus the absence of any
`get_payload` declaration in `src/sanctum/server.py`.

---

## ADR-PO-004 — `L_max` 16 MiB cap applies pre-offload

**Status.** Accepted (2026-04-29).

**Context.** `sanctum.sanitize.MAX_INPUT_BYTES` is 16 MiB and exists to
defeat regex-DoS on the sanitization pass (see
`docs/THREAT_MODEL_SANITIZATION.md` §7). Offload exists for a different
reason: to survive the MCP stdio cliff (low KB). Conflating the two
caps would re-open the regex-DoS surface; ignoring the cap on the
offload path would silently let attacker-influenced input bytes past
the existing defense.

**Decision.** The 16 MiB cap applies *before* offload. In
`_emit_offloaded_response`, the canonical-JSON form of the full
payload is passed through `sanitize(raw, max_bytes=MAX_INPUT_BYTES)`
*first*; only on success does the helper proceed to
`_write_payload(...)` and `audit.append_entry(...)`. Oversize inputs
raise `InputTooLargeError` from `sanitize()` — no 0o444 file lands and
no ledger entry is appended.

The default `max_bytes=MAX_PAYLOAD_BYTES` (64 KiB) is sized for the
inline LLM response — too small for offloaded blobs, where the
reasonable upper bound is the regex-DoS cap. The helper passes
`max_bytes=MAX_INPUT_BYTES` (16 MiB) explicitly so the on-disk file
is bounded by the regex-DoS posture, not by the inline-response
budget.

**Consequences.**

- Offload size ≤ 16 MiB. Realistic forensic outputs (e.g., a
  `volatility3 pslist` over a 16 GB image is ~5 MB; a 200-row Amcache
  dump is ~80 KB) clear this comfortably.
- The regex-DoS posture from `THREAT_MODEL_SANITIZATION.md` §7 is
  preserved end-to-end; offload does not introduce a regex-DoS
  back-door.
- Any future tool that legitimately needs > 16 MiB would have to
  either chunk into multiple calls or raise the cap globally; the
  latter requires a new threat-model justification.

**Alternatives considered.**

- **Cap does NOT apply to offload** — re-opens regex-DoS for any input
  routed through the offload helper. Trivially rejected.
- **Two-tier cap** (`MAX_INPUT_BYTES` 16 MiB for sanitize; separate
  higher cap, e.g. 64 MiB, for write-to-disk-only path) — adds
  surface area for a marginal gain; the 16 MiB cap is already
  generous for realistic forensic outputs.

**Pinned by.** `tests/test_server_boundaries.py::test_lmax_cap_blocks_oversized_input_before_offload`
(AC-6, T-16) — monkeypatches `parse_amcache` to return a 16 MiB+1-byte
event, asserts `InputTooLargeError` raised AND zero files under
`SANCTUM_OUTPUT_ROOT` AND zero ledger entries.

---

## ADR-PO-005 — Universal offload via `_emit_offloaded_response()` helper

**Status.** Accepted (2026-04-29).

**Context.** Today Sanctum has two typed tools (`get_amcache`,
`claim_finding`). `claim_finding` returns a small server-authored
payload that probably fits under the stdio cliff; `get_amcache`
returns a potentially-large evidence dump that probably does not.
Three shapes were on the table: every wrapper offloads, only-when-needed
offload, or universal offload through a single helper.

**Decision.** Universal offload via a single helper
`_emit_offloaded_response(*, case_id, tool, args, input_ref,
full_payload, rowcount, audit_id, summary_extra=None) -> str` in
`server.py`. Both `get_amcache` and `claim_finding` route through it.
New tool wrappers use the helper or fail review. The helper is the
single enforcement point for: sanitize → write_payload → append_entry
ordering, AC-13 inline-summary key allowlist (≤ 11 keys), `<evidence-untrusted>`
wrap, and orphan-payload logging on `append_entry` failure.

**Consequences.**

- One mental model on the wire for every typed tool: short summary
  inline, full payload on disk. AC-8's "summary < 1024 B" invariant
  is testable once and inherited by every future wrapper.
- `claim_finding`'s payload is small enough that offload is mild
  overhead, but the consistency benefit (and the fact that `hypothesis`
  is agent-authored input that is now quarantined to disk rather than
  reflected inline) outweighs the cost.
- The crash-window between successful payload write and a failing
  `append_entry` (HMAC key gone, disk full, fsync error on the ledger
  side) is contained: the helper logs ERROR with the orphan path
  before re-raising. The 0o444 mode makes same-process rewrite
  impossible; auto-delete is deliberately NOT attempted (would violate
  write-once and trigger filesystem-permission errors anyway). Operator
  removes the orphan manually if a retry with the same `audit_id` is
  desired.
- Future adversarial reasoning: any tool wrapper that bypasses the
  helper to construct its own response is a review-time red flag,
  because it would be the only site where the ordering invariant
  (`sanitize → write_payload → append_entry`), the inline-summary
  key lock, and the orphan log were not enforced. Code-review checklist
  item.

**Alternatives considered.**

- **Universal — both wrappers offload, both return short summaries
  (single mental model; future wrappers inherit)** — same outcome but
  duplicated enforcement code in each wrapper. The helper variant is
  strictly better.
- **Conditional — only wrappers whose payload could exceed the cliff
  offload** — requires a per-tool threshold configuration; introduces
  a "this tool sometimes offloads, sometimes doesn't" bifurcation
  on the wire, which makes the agent's mental model worse and AC-8's
  summary-size invariant per-tool-conditional rather than universal.

**Pinned by.** Both `get_amcache` and `claim_finding` in `server.py`
end with `return _emit_offloaded_response(...)`.
`tests/test_server_boundaries.py::test_get_amcache_summary_response_under_1024_bytes`
and `::test_claim_finding_summary_response_under_1024_bytes` (AC-8 cliff
survival across both wrappers),
`::test_claim_finding_inline_summary_keys_match_ac13_lock` (AC-13
≤ 11-key allowlist), and `::test_payload_ref_append_entry_called_through_universal_helper`
(AC-12 single-call-site enforcement) assert the universal contract.

---

## Cross-cutting: forward-compat omit-not-null for `payload_ref`

**Status.** Accepted (2026-04-29). **Load-bearing — backward compat
for legacy ledgers.**

**Context.** Pre-feature ledgers contain entries with no `payload_ref`
field at all. The HMAC chain is computed over the canonical JSON form
of the entry dict, and `verify_chain` re-canonicalises the dict it
reads from disk. If the post-feature `LedgerEntry.to_jsonl` emitted
`"payload_ref": null` for entries that had no offload payload, the
canonical bytes for legacy entries would differ from what was
originally hashed at append time — and `verify_chain` would
silently report tampering on every legacy entry.

**Decision.** `LedgerEntry.to_jsonl` and `audit.append_entry`'s
raw-dict construction OMIT the `payload_ref` key when the value is
`None`. The dict-omission propagates through `_line_hash_for` (which
hashes the dict it sees), so the HMAC input for a legacy entry under
the post-feature code is **bytewise identical** to the HMAC input
that was computed at append time. Legacy ledgers verify clean
post-feature.

**Consequences.**

- Symmetric in the read and write paths (`LedgerEntry.to_jsonl` for
  the canonical encoding; `append_entry`'s raw-dict for the HMAC
  input). The two paths cannot drift because they both use the same
  conditional-include pattern (`if payload_ref is not None: …`).
- The omit-not-null contract is the load-bearing forward-compat
  invariant; it is asserted by an explicit test that hand-builds a
  pre-feature ledger from canonical bytes and confirms post-feature
  `verify_chain` passes.
- Any future addition of an optional field to `LedgerEntry` must
  follow the same contract: omit when `None`, never `null`-emit. This
  is the project-wide pattern for ledger schema evolution.

**Alternatives considered.**

- **`null`-emit everywhere** — symmetric on the wire but breaks
  bytewise hash compat with pre-feature ledgers. Would require a
  one-shot ledger migration tool, which is out of scope and risks
  dropping the chain on a botched migration.
- **Version-numbered ledger entries** with a per-version canonicaliser —
  over-engineered for one optional field. Reconsider when the schema
  needs three or more optional fields with non-trivial interactions.

**Pinned by.** `tests/test_audit.py::test_verify_chain_passes_on_legacy_ledger_without_payload_ref`
seeds hand-built pre-feature canonical bytes and confirms post-feature
`verify_chain` accepts them.

---

## References

- `CHANGELOG.md` [Unreleased] — feature entry summarising the surface
  and security properties.
- `docs/THREAT_MODEL_LEDGER.md` "Ledger field roles" table — the
  field-level vs entry-dict-level coverage split for `payload_ref`.
- `docs/THREAT_MODEL_SANITIZATION.md` §7 — regex-DoS cap that ADR-PO-004
  preserves.
- `docs/THREAT_MODEL_TRIANGULATION.md` — claim-time vs read-time gate
  semantics referenced by ADR-PO-003.
- `anthropics/claude-code#36319` — upstream issue motivating the entire
  feature.

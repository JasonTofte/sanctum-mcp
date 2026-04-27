# Changelog

All notable changes to Sanctum are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver.

## [Unreleased]

### Added

- **`src/sanctum/parsers/sysmon.py` — real-mode `parse_sysmon` body
  (week-3 milestone, Kernel-ETW family) — completes the 5-of-5 real-
  mode parser layer.** Replaces the stub with a `python-evtx` (Willi
  Ballenthin, Apache-2.0) walk that filters EVTX records to **EventID 1
  (Sysmon process create)** and **EventID 4688 (Security audit-process-
  creation)**. Both event IDs flow from kernel ETW providers and share
  a trust root: a ring-0 attacker can defeat both at once, but a user-
  mode rootkit that patches one (e.g. unloads the Sysmon driver) leaves
  the other intact. Channel discrimination is via `EventID`, not file
  name — the analyst chooses what to ingest and a misnamed file should
  still parse. `Image` (Sysmon) vs `NewProcessName` (4688) is selected
  per-event; both go to `program_path`. `extras.event_id` surfaces the
  source channel. **Timestamp:** prefer `System/TimeCreated@SystemTime`
  (structurally the same field across both schemas, ISO-8601 + `Z`-
  suffixed, parsed via `datetime.fromisoformat` with defensive `Z` →
  `+00:00` rewrite for 3.10 compatibility); `EventData/Data
  Name="UtcTime"` is preserved verbatim in `extras.utc_time` for
  analyst clock-skew sanity-checking against the kernel ETW timestamp
  vs Sysmon's userland write timestamp (a disagreement is a clock-skew
  or VM-pause fingerprint, not a parser bug). **Hashes:** the Sysmon
  comma-joined `SHA1=...,MD5=...,SHA256=...,IMPHASH=...` string is
  split, hex-validated against expected lengths (40/32/64/32), and
  surfaced as discrete `extras.hash_sha1` / `hash_md5` / `hash_sha256`
  / `hash_imphash` fields. Hex-only validation prevents an attacker-
  controlled custom Sysmon configuration from smuggling control bytes
  into a string the FastMCP `isError` channel might leak. **XML
  hardening:** every record's rendered XML is fed through
  `defusedxml.ElementTree.fromstring` (not stdlib `xml.etree`) — even
  though modern Python's stdlib parser doesn't honour external entities
  by default, `defusedxml` adds the entity-expansion (billion-laughs)
  cap that the stdlib lacks. EVTX bytes are attacker-controllable, so
  the hardening is load-bearing rather than cosmetic. **Per-row
  leniency:** any single record that fails `record.xml()`,
  `defusedxml.fromstring`, or any sanity check gets dropped silently;
  the rest of the EVTX file is still walked. **Mid-stream iterator
  failure** (e.g. `InvalidRecordException` from a corrupt chunk magic)
  preserves already-yielded events, mirroring the ShimCache convention.
  Whole-file open failure / parse failure surfaces as
  `ArtifactMalformedError` with attacker-influenceable bytes scrubbed
  via `_safe_field` (FastMCP `isError` channel bypass; see
  `feedback_error_channel_bypass.md`). **CommandLine cap:** values
  longer than 4096 chars are truncated with `...` rather than dropped
  — a long command line is still forensic evidence; we just don't pass
  the whole blob through to the LLM context window.

- **`tests/test_parsers.py` — 14 new tests covering the real-mode
  Sysmon path** (AC-sm-real-1..13 + AC-sm-real-int). Adds a `_FakeEvtx`
  shim with class-level `configure(records=, init_exception=,
  records_exception=)` staging slots (the parser constructs the library
  itself, so tests can't pass arguments directly), plus `_FakeRecord`,
  `_sysmon_eid1_xml(...)`, `_security_eid4688_xml(...)`, and
  `_other_event_xml(event_id=...)` helpers that produce well-formed
  XML strings rather than synthesising binary EVTX blobs (the binary
  layout is python-evtx's contract — pinning tests to it would couple
  every chunk-format bump to a Sanctum-test churn). Coverage: happy-
  path Sysmon EID 1 with full extras wiring, Security 4688 path
  (`NewProcessName` → `program_path`, no hashes), non-process-create
  events filtered (EID 3 / EID 11), sequential `row_index` across
  accepted events, invalid-hex hashes dropped, wrong-length hashes
  dropped, control-character / angle-bracket image path drops the row,
  oversize image path drops the row, `Evtx()` init failure surfaces as
  scrubbed `ArtifactMalformedError`, mid-stream `record.xml()` failure
  is per-row (surrounding records preserved), `records()` iterator
  failure preserves already-yielded events, empty EVTX → `[]`,
  malformed XML drops the record without aborting. Integration test at
  `tests/fixtures/case_temp_exec_001/artifacts/EVTX/` —
  unlike Prefetch, python-evtx is pure Python so the integration test
  runs on Linux/Darwin once the fixture lands. **AC-14 / AC-15a
  retired** (the stub-list parametrize tests are now empty — every
  parser has shipped a real-mode body). `parse_sysmon` removed from
  `STUB_PARSERS_*`; the lists themselves are deleted with an in-file
  comment pointing at the sidecar tests for the
  `PartialImplementationError` coverage that remains relevant.

- **`pyproject.toml` — added `python-evtx>=0.8` and
  `defusedxml>=0.7` dependencies.** `python-evtx` (Apache-2.0,
  Ballenthin) is the EVTX binary parser used exclusively by
  `sanctum.parsers.sysmon` for the chunked records iterator API; pure
  Python so it works cross-platform (no ctypes coupling, unlike
  `windowsprefetch`). `defusedxml` (PSF license) hardens the XML parse
  against entity-expansion attacks on attacker-controllable EVTX
  contents. Justification comments in the dep block call out both
  packages' roles.

- **`src/sanctum/parsers/prefetch.py` — real-mode `parse_prefetch` body
  (week-3 milestone, SysMain family).** Replaces the stub with a
  `windowsprefetch`-backed walk of `\Windows\Prefetch\<EXE>-<hash>.pf`.
  Each `.pf` file is a versioned binary structure (v17 = Win 7, v23 =
  Win 8, v26 = Win 8.1, v30 = Win 10/11) with MAM/LZXPRESS-Huffman
  compression on Win 10+. The Adam-Witt-authored `windowsprefetch`
  package (Apache-2.0) handles the version dispatch, MAM decompression
  via `ctypes.windll.ntdll.RtlDecompressBufferEx`, and struct unpacking —
  ~370 lines we'd otherwise have to maintain ourselves for zero forensic
  benefit. **MAM decompression is Windows-only** by construction
  (`ctypes.windll` doesn't exist on Linux/Darwin); MAM-compressed `.pf`
  files on non-Windows hosts surface as `ArtifactMalformedError`, which
  is the right answer — analysts triaging Win 10/11 prefetch are
  expected to run Sanctum on Windows. Uncompressed legacy files
  (v17/23/26) parse normally on any OS. **We bypass the library's
  `Prefetch.timestamps` accessor and reparse `lastRunTime` directly**:
  the library's `getTimeStamps` formats each FILETIME as a naive-datetime
  *string* (`str(datetime + timedelta)`), violating the
  `ExecutionEvent.timestamp` tz-aware contract. We `struct.unpack("<Q",
  slot)` each 8-byte FILETIME and convert via `regipy.utils
  .convert_wintime`, defensively wrapping naive results to `tzinfo=UTC`.
  `convert_wintime` swallows the FILETIME overflow internally and returns
  `1601-01-01 UTC` as a sentinel rather than raising — we treat that
  sentinel as a per-row drop (Windows didn't ship in 1601). **One
  `ExecutionEvent` per non-zero historical run slot.** Win 10/11 prefetch
  retains up to 8 prior run timestamps; emitting all of them gives
  analysts the full back-history for the binary, not just the most
  recent run. Family-count arithmetic isn't affected (still one family
  contribution per parser call) but timeline reconstruction is much
  richer. `run_slot` in `extras` preserves the *original* slot index in
  the buffer (most-recent-first) even when intermediate slots are
  dropped, so analysts can tell "this was the most recent run" vs "this
  was 6 runs ago". Best-effort full-NT-path resolution from the loaded-
  resources list (case-insensitive basename match against
  `executableName`); falls back to the basename alone on miss
  (`prefetch_hash` in `extras` disambiguates which path Windows recorded
  the binary at). Per-row leniency: a truncated `lastRunTime` buffer that
  yields some valid FILETIMEs and one corrupt slot drops the corrupt
  slot and keeps the valid events — same convention as Amcache /
  UserAssist / BAM / ShimCache. Whole-file corruption (the library
  raises during construction; we catch broadly to absorb `struct.error`,
  `UnicodeDecodeError`, `AttributeError` from missing `ctypes.windll` on
  non-Windows, plus arbitrary OS errors during the
  `RtlDecompressBufferEx` ctypes call) bubbles up as
  `ArtifactMalformedError` with attacker-influenceable bytes scrubbed
  via `_safe_field` (the FastMCP `isError` channel bypasses success-path
  sanitizers; see `feedback_error_channel_bypass.md`).

- **`tests/test_parsers.py` — 13 new tests covering the real-mode
  Prefetch path** (AC-pf-real-1..12 + AC-pf-real-int). Adds a
  `_FakePrefetch` shim that stages `executableName`, `lastRunTime`,
  `runCount`, `hash`, `fileSize`, and `resources` directly without
  synthesising binary `.pf` blobs (the blob layout is
  `windowsprefetch`'s contract — pinning tests to it would couple every
  Windows-version bump to a Sanctum-test churn). Coverage: happy-path
  field wiring with one event per non-zero slot, `run_slot` reflects
  original buffer index across drops, `prefetch_hash` validation
  (lower-case hex only, length-bounded), full-path resolution via
  resources match (case-insensitive basename), basename fallback when
  no resource matches, oversize `program_path` → `[]`, control-char /
  angle-bracket `executableName` → `[]`, library construction failure →
  scrubbed `ArtifactMalformedError`, missing `lastRunTime` → `[]`,
  all-zero buffer → `[]`, corrupt-FILETIME slot dropped while
  surrounding valid slots kept (asserts the
  `convert_wintime`-overflow → 1601 sentinel handling). Integration
  test gated on a real `.pf` at
  `tests/fixtures/case_temp_exec_001/artifacts/Prefetch/` —
  `pytest.raises(ArtifactMalformedError)` on non-Windows hosts (the MAM
  decompression contract), full-event assertions on Windows. AC-14 and
  AC-15a parametrize lists trimmed: `parse_prefetch` removed from
  `STUB_PARSERS_OUTSIDE_FIXTURE_MODE` and `STUB_PARSERS_TOOL_NAMES` —
  only `parse_sysmon` remains a stub.

- **`pyproject.toml` — added `windowsprefetch>=4` dependency.** Pinned
  `>=4` for the v30 (Win 10/11) layout. Apache-2.0. Used exclusively by
  `sanctum.parsers.prefetch` for version detection (v17/23/26/30), MAM
  decompression on Win 10+ via `ctypes.windll.ntdll.RtlDecompressBufferEx`,
  and struct unpacking. Justification comment in the dep block calls out
  the Windows-only MAM constraint and points at the parser's own
  docstring for the architectural answer (non-Windows hosts surface
  MAM-compressed `.pf` as `ArtifactMalformedError`).

- **`src/sanctum/parsers/appcompat.py` — real-mode `parse_shimcache` body
  (week-3 milestone, AppCompat family).** Replaces the stub with a
  `regipy`-backed walk of
  `\<active-control-set>\Control\Session Manager\AppCompatCache\AppCompatCache`
  on the SYSTEM hive. ShimCache stores all entries in a single REG_BINARY
  blob whose layout depends on Windows version (XP/Vista/7/8/8.1/10 each
  differ; Win 10 Creators Update shifted the magic 4 bytes). We delegate
  the binary parse to `regipy.plugins.system.external.ShimCacheParser
  .get_shimcache_entries` — Mandiant-derived, Apache-2.0, ~489 lines —
  which already handles every layout we care about. Active control set
  is resolved from `\Select\Current` for parity with `parse_bam`
  (forensically-acquired hives sometimes have `Current=2` after an OS
  rollback), falling back to `ControlSet001`. Per-row mapping:
  `last_mod_date` → `timestamp` (regipy returns pytz-aware UTC; we still
  validate `tzinfo` defensively), `path` → `program_path` with the
  literal `"None"` sentinel dropped (regipy's empty-path placeholder),
  `exec_flag` (Win 8 only) preserved in `extras`, `file_size` (NT5
  only) → `evidence_size_bytes`. Generic `Exception` from
  `get_shimcache_entries` (raised on unrecognised magic) is caught and
  re-raised as `ArtifactMalformedError` with the message scrubbed via
  `_safe_field` — the raw 4-byte magic is attacker-influenceable on a
  writable hive and would otherwise reach the LLM through FastMCP's
  `isError` channel which bypasses success-path sanitizers. Mid-stream
  iteration failures preserve already-yielded events per per-row leniency
  policy. CLAUDE.md invariant 5 (AppCompat collapses Amcache + ShimCache
  into one family) is unaffected: the `tool` discriminator on every
  emitted `ExecutionEvent` (`get_shimcache` vs `get_amcache`) lets
  `claim_finding` distinguish them while still counting them as one
  family corroboration.

- **`tests/test_parsers.py` — 13 new tests covering the real-mode
  ShimCache path** (AC-sc-real-1..12 + AC-sc-real-int). Adds a path-
  routed `_FakeShimcacheHive` dispatcher mirroring `_FakeBamHive` for
  the active-CS resolution, plus a `_FakeAppCompatCacheKey` /
  `_FakeShimcacheValue` pair. The test surface monkeypatches
  `get_shimcache_entries` directly so tests stage entry dicts rather
  than synthesise binary blobs — the blob layout is regipy's contract,
  not ours, and pinning tests to it would couple every Windows-format
  bump in regipy to a Sanctum-test churn. Coverage: happy-path field
  wiring, sequential `row_index` across entries, `"None"` sentinel
  drop, control-char/angle-bracket path drop, `exec_flag` preservation
  on Win 8 entries (and absence on Win 10), `file_size` →
  `evidence_size_bytes` mapping (NT5), active-CS resolution via
  `\Select\Current=2` (asserts the parser actually reads the CS002
  blob, not CS001), fallback to ControlSet001 when `\Select` is
  absent, missing AppCompatCache subkey → `[]`, unparseable hive →
  `ArtifactMalformedError` with attacker bytes scrubbed, bad-magic
  exception from regipy surfaces as scrubbed `ArtifactMalformedError`,
  mid-stream corruption preserves already-yielded events. Integration
  test asserts `tool=get_shimcache` + tz-aware timestamps + the
  `appcompat_key` extra, gated on a regf-magic + size sniff at
  `tests/fixtures/case_temp_exec_001/artifacts/SYSTEM`. AC-14 and
  AC-15a parametrize lists trimmed — `parse_shimcache` removed; only
  `prefetch`/`sysmon` remain stubs.

- **`src/sanctum/parsers/bam.py` — real-mode `parse_bam` body
  (week-3 milestone, Background-service family) with orphan-SID
  classification.** Replaces the stub with a `regipy`-backed walk of
  `\<active-control-set>\Services\bam\State\UserSettings\<SID>`. The
  active control set is resolved dynamically from `\Select\Current`
  (forensically-acquired hives sometimes have `Current=2` after an OS
  rollback), falling back to `ControlSet001`. Each value name is an
  NT-namespace path; the first 8 bytes of each value are FILETIME
  (Win 11 also packs a sequence DWORD + padding which we ignore). Per
  `project_followups_threat_model.md` item 4 / Khatri 2020, BAM
  retains `UserSettings\<SID>` keys after the underlying account is
  deleted — most notably `defaultuser0` (the OOBE setup account that
  leaves an unresolvable `RID=1001` SID on every freshly-installed
  Windows machine). The parser ships a pattern-only SID classifier
  with statuses `system_account` (S-1-5-18/19/20),
  `builtin_admin/guest/default/wdag` (RIDs 500/501/503/504),
  `orphan_oobe` (RID 1001 — **dropped entirely from event output**
  so OOBE noise contributes zero family corroboration), and
  `user_unverified` (everything else, conservative-include). The
  full SAM-cross-referenced four-state classifier from followups #4
  lands when a SAM parser ships; the test scaffolding for all four
  states is already in place to receive it. `extras` carries `sid`,
  `sid_status`, and `sid_resolution: pattern_only` so analysts know
  SAM cross-ref has not yet been performed. Same `_safe_field`
  exception scrubbing as the other parsers; placeholder values
  (`Version`, `SequenceNumber`) are skipped on the leading-backslash
  test.

- **`tests/test_parsers.py` — 11 new tests covering the real-mode
  BAM path** (AC-bam-real-1..10 + AC-bam-real-int). Adds a path-
  routed `_FakeBamHive` dispatcher that answers `\Select` and
  `\ControlSet00X\Services\bam\...` independently — required because
  `parse_bam` issues two `get_key()` calls for active-CS resolution.
  Coverage: happy-path field wiring, multi-SID `row_index`
  flattening, orphan_oobe drop with surviving-SID passthrough,
  placeholder-value (`Version`, `SequenceNumber`) skip, parametric
  SID-status classifier (10 cases incl. system, all 4 builtins, two
  user RIDs, garbage SID, non-S-1-5-21 authority), active-CS
  resolution via `\Select\Current=2`, fallback to ControlSet001 when
  `\Select` is absent, missing UserSettings → `[]`, unparseable hive
  → `ArtifactMalformedError` with scrubbed message, short/dirty
  values dropped. Integration test asserts the orphan_oobe filter
  actually fires on the rig baseline (which has the documented
  RID-1001 SID). Both AC-14 and AC-15a parametrize lists trimmed —
  `parse_bam` removed; only `shimcache`/`prefetch`/`sysmon` remain
  stubs.

- **`src/sanctum/parsers/userassist.py` — real-mode `parse_userassist`
  body (week-3 milestone, Explorer/NTUSER family).** Replaces the stub
  with a `regipy`-backed walk of
  `\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count`
  on a per-user `NTUSER.DAT` hive. Field wiring: value names are ROT-13
  decoded, `UEME_RUNPATH:` / `UEME_RUNPIDL:` prefixes stripped,
  session/UI counters (`UEME_CTLSESSION`, `UEME_CTLCUACOUNT`,
  `UEME_UI*`) dropped as non-execution rows; `program_path` ← decoded
  remainder; `timestamp` ← FILETIME at byte offset 60 of the 72-byte
  v5 binary blob (the canonical "when did Explorer last observe this
  binary launched" value); `extras` carries `run_count`, `focus_count`,
  `focus_time_ms`, and the originating `userassist_guid` so analysts
  can distinguish RUNPATH-launched (CEBFF5CD-…) from shortcut-launched
  (F4E57C4B-…) executions. Non-72-byte values (XP-era format-3,
  truncated, or padded blobs) are dropped per the per-row leniency
  rule. Same `_safe_field` exception-message scrubbing as
  `parse_amcache` to seal the FastMCP `isError` channel against
  attacker-influenced bytes from `regipy`. UserAssist exists in
  `sanctum.families.TOOL_TO_FAMILY` as `Explorer/NTUSER`, giving
  `claim_finding` a non-AppCompat corroboration partner against
  Amcache for the first time on real registry data.

- **`tests/test_parsers.py` — 11 new tests covering the real-mode
  UserAssist path** (AC-ua-real-1..10 + AC-ua-real-int). Adds a
  `_FakeUACountKey` / `_FakeUAGuidSubkey` / `_FakeUserassistRoot`
  harness for the extra UserAssist→GUID→Count nesting, with `_rot13`
  and `_ua_v5_value` helpers so tests stage cleartext + structured
  binary blobs rather than opaque hex. Coverage: happy-path field
  wiring; multi-GUID row_index flattening; session-counter drop;
  wrong-size-blob drop; control-char path defense; missing-Count GUID
  skip; missing UserAssist key → `[]`; unparseable hive →
  `ArtifactMalformedError` with scrubbed message; corrupt-Count
  iter_values → drop only that GUID; `UEME_RUNPIDL:` shortcut-launch
  prefix accepted. Integration test
  (`test_real_mode_userassist_integration_against_rig_baseline`)
  auto-skips with a clear reason until a real `NTUSER.DAT` is
  vendored at `tests/fixtures/case_temp_exec_001/artifacts/NTUSER.DAT`
  (same `regf` magic + size sniff as the Amcache integration test).
  AC-14 / AC-15a parametrized lists narrowed: `parse_userassist`
  removed since it now has a real-mode body — only
  `shimcache/prefetch/sysmon/bam` remain stubs.

- **`src/sanctum/parsers/amcache.py` — real-mode `parse_amcache` body
  (week-3 milestone, AppCompat family).** Replaces the
  `PartialImplementationError` stub with a `regipy`-backed walk of
  `\Root\InventoryApplicationFile`, mapping each subkey to an
  `ExecutionEvent`. Field wiring: `program_path` ← `LowerCaseLongPath`;
  `timestamp` ← subkey last-write FILETIME (the canonical "when did the
  Application Experience Service observe this binary" signal — harder
  for an attacker to forge from userland than the per-value `LinkDate`
  PE-linker date, which is preserved in `extras` instead);
  `evidence_size_bytes` ← `Size` (REG_QWORD on modern hives, hex-string
  legacy fallback handled); `extras.sha1` ← `FileId` with the canonical
  `0000` prefix stripped to a 40-char lowercase SHA-1; optional
  `ProductName` / `Publisher` / `BinaryType` / `Language` carried into
  `extras` only when control-char-clean. Pre-Win10-1709 hives (no
  InventoryApplicationFile) return `[]` rather than raising — empty is
  a valid forensic answer ("no AppCompat evidence"), distinct from the
  tamper-suspected refusal that aggregate-pattern detection in
  `sanctum.deception` will surface. Per-row corruption (missing
  `LowerCaseLongPath`, control chars in path, `iter_values`
  `RegistryParsingException`) is silently dropped from the row stream
  rather than failing the whole hive — matches the per-row leniency
  rule documented in `_build_event_from_subkey`'s docstring. The
  fixture-mode entry (`SANCTUM_USE_FIXTURE_SIDECAR=1` →
  `load_sidecar()`) is preserved as the fast unit-test path; real-mode
  is the new default.

- **`pyproject.toml` — `regipy>=6` runtime dependency.** Pure-Python,
  MIT-licensed Windows registry hive reader. Pinned `>=6` for the
  `iter_subkeys` / `get_values(as_json=True)` API surface the parser
  layer relies on. Justification comment placed near the dependency
  entry per the project's no-stealth-deps convention.

- **`tests/test_parsers.py` — 11 new tests covering the real-mode
  Amcache path** (AC-amc-real-1..10 + AC-amc-real-int). The unit tests
  use a `_FakeRegistryHive` harness substituted via monkeypatch so the
  field-mapping logic is exercised without depending on a vendored
  `.hve` on disk. Coverage: happy-path event construction; sequential
  `row_index` assignment across multi-subkey hives; per-row drop of
  missing-path / control-char-path / overlong-path / values-raise rows;
  `Size` coercion from REG_QWORD, hex-string, decimal-string, and
  malformed inputs; `FileId` → SHA-1 normalisation including
  malformed-prefix and non-hex fallback to all-zeros; optional-extras
  inclusion with control-char rejection; pre-1709 empty-result branch
  (`RegistryKeyNotFoundException`); unparseable-hive
  `ArtifactMalformedError` with attacker-byte scrubbing in the message.
  An additional integration test
  (`test_real_mode_amcache_integration_against_rig_baseline`)
  auto-skips with a clear reason until a real Amcache.hve is vendored
  at `tests/fixtures/case_temp_exec_001/artifacts/Amcache.hve` — file
  is sniffed for the `regf` magic and a >=4 KiB size before the test
  activates so the synthetic 210-byte ASCII placeholder cannot
  accidentally trigger it.

- **`tests/test_parsers.py` — AC-14 / AC-15a parametrized across
  still-stub parsers.** Previously these asserted the
  `PartialImplementationError` contract using `parse_amcache` as the
  canonical example, which is no longer correct now that Amcache is
  real-mode. The tests now parametrize across `parse_shimcache /
  parse_prefetch / parse_sysmon / parse_bam / parse_userassist`
  (with each parser's wire-spec tool name pinned in the message
  assertion). When that list empties as more parsers ship real-mode
  bodies, the AC-14 / AC-15a tests retire naturally.

### Changed

- **`tests/fixtures/case_temp_exec_001/ground_truth.py` — fixture vocab
  realigned with canonical `sanctum.families` + `sanctum.audit`.** Local
  `FAMILY_BAM = "BAM"` and `EXPECTED_CLAIM_RESULT.status = "CONFIRMED"`
  literals were silent vocabulary drift relative to the canonical
  `FAMILY_BACKGROUND_SERVICE = "Background-service"` and
  `FindingConfidence.CORROBORATED.value = "CORROBORATED"`. The drift
  was latent (no test consumed the fixture yet) but would have
  immediately broken the first parser test that compared `EXPECTED`
  family strings against `ALL_FAMILIES`. Now imports `FAMILY_APPCOMPAT`,
  `FAMILY_SYSMAIN`, and `FindingConfidence` directly; the local
  `FAMILY_*` constants are deleted entirely (the rationale that
  justified them — "until `sanctum.types` lands" — does not apply,
  since `sanctum.families` is already the canonical source). Comments
  echoing `"CONFIRMED"`/`"CONFIRMED-positive case"` updated to
  `CORROBORATED` to match.

- **Typed `confirmation_basis` field on `Finding` (Phase B1
  pre-submission hardening).** The `Finding` schema now carries a
  `Literal["single_family", "independent_artifacts",
  "coupled_artifacts", "single_family_strong_signal"]` field that
  records *how* corroboration was achieved. v1 emits exactly two of
  the four values: `single_family` for DRAFT findings (one family
  voted) and `independent_artifacts` for CORROBORATED / FINAL
  findings (≥2 families voted; the v1 families are by-construction
  trust-root-disjoint). The other two values are reserved on the
  wire so a v2 producer can introduce sub-family splits
  (`coupled_artifacts`) or a single-family strong-signal escape
  hatch (`single_family_strong_signal`) without a breaking schema
  change. The field is recorded in both the in-memory `Finding`
  returned to the agent and the `claim_finding` ledger entry's
  `input_ref.finding` payload, and surfaces in the MCP wrapper's
  evidence-wrapped JSON response. Documented in
  [`docs/THREAT_MODEL_TRIANGULATION.md`](docs/THREAT_MODEL_TRIANGULATION.md)
  §"Confirmation basis (v1 vs v2)". Four new tests in
  `test_finding.py` pin the v1 emission contract; one extension to
  `test_finding_ledger_entry_has_finding_metadata` pins the ledger
  payload; one extension to
  `test_claim_finding_output_is_evidence_wrapped` pins the MCP
  response.

- **`claim_finding` exposed as an MCP tool in `src/sanctum/server.py`.**
  The agent can now invoke the family-corroboration gate over the wire:
  `claim_finding(case_id, hypothesis, audit_ids)` is `@mcp.tool()`-decorated,
  validates `case_id` against the same Unicode/path-traversal allowlist as
  `get_amcache` (refactored shared helper `_validate_case_id_format`), calls
  `sanctum.finding.claim_finding`, JSON-encodes the resulting `Finding`, and
  returns the payload through `sanitize() → wrap_evidence()` per CLAUDE.md
  invariant 2 (all tool output is quarantined). The MCP surface intentionally
  omits the `deception_signals` parameter — `DeceptionSignal` objects don't
  serialize cleanly across MCP and week-5 will wire deception detection into
  `get_*` calls automatically. Refusal exceptions
  (`ClaimFindingError`, `UnknownToolError`, `ValueError`) bubble naturally
  to the MCP client so the agent observes them as part of its self-correction
  loop. New boundary tests in `tests/test_server_boundaries.py` pin the
  evidence-wrap, the strict-fail-closed refusal of fabricated audit_ids
  (the most architecturally load-bearing test in the suite), the unsafe-
  case_id rejection (including a bidi-override codepoint case), and the
  property that successful findings extend the same HMAC chain as `get_*`
  calls.

- **`src/sanctum/finding.py` + `src/sanctum/families.py` — `claim_finding`
  family-corroboration gate (week-4 milestone).** The README's "Autonomous
  Execution Quality" row now points to actual code: `claim_finding(case_id,
  hypothesis, audit_ids, deception_signals=())` reads the referenced ledger
  entries, resolves each `audit_id` → family via the `TOOL_TO_FAMILY` policy
  table in `sanctum.families`, deduplicates families per CLAUDE.md invariant
  5, and routes `(n_distinct_families, deception_signal_present)` through
  `classify_confidence()` to produce a tier in
  `{DRAFT_TAMPER_SUSPECTED, DRAFT, CORROBORATED, FINAL}`. The result is
  appended to the audit ledger as a `tool="claim_finding"` entry with the
  finding payload packed into `input_ref.finding` — non-breaking schema
  extension; existing `verify_chain` covers findings on the same HMAC chain
  as `get_*` calls. `FindingConfidence` enum gained
  `DRAFT_TAMPER_SUSPECTED` (the post-demotion floor when a deception
  signal accompanies a single-family claim). `classify_confidence` gained
  a keyword-only `deception_signal_present` arg, default False — fully
  backward-compatible. Strict-fail-closed: empty `audit_ids`, missing
  ledger references, and unknown tool names all raise rather than silently
  routing past the gate. 22 new tests across `test_finding.py` (15) and
  `test_families.py` (7); existing `test_audit.py` extended with 5 new
  tests covering the demotion table.

- **`src/sanctum/deception.py` — forensic-deception reason-code layer.** New
  module recognises three named anti-forensic technique signatures
  (`BaseFlushAppcompatCache` / AppCompat flush, SysMain disabling to
  suppress Prefetch, MFT `$STANDARD_INFORMATION` timestomp) and emits typed
  `TamperReason` enum values consumed by the week-4 `claim_finding` gate
  as a confidence-downgrade signal. Deterministic predicates only — no
  ML, no tuned thresholds; each predicate is a small Boolean over named
  artifact fields. Surfaces explicit ambiguity codes
  (`AMBIGUOUS_LEGITIMATE_FLUSH_CONSISTENT`,
  `AMBIGUOUS_SYSMAIN_DISABLED_OPERATOR_PLAUSIBLE`) when a fingerprint
  also matches a legitimate operator action, per Garfinkel ICIW 2007
  false-positive discipline. Threat model in
  `docs/THREAT_MODEL_DECEPTION.md`; 17 unit tests in
  `tests/test_deception.py` pin signature, ambiguity, and absence-of-
  signal behaviour. Closes the structural-deception gap (attacker-
  authored evidence *structure*, not text) that `sanctum.sanitize`
  does not address.

- **First test fixture skeleton — `tests/fixtures/case_temp_exec_001/`.**
  README documenting the scenario (benign signed binary executed from
  `%TEMP%`, exercising AppCompat ↔ SysMain triangulation) plus the VM
  workflow to populate `artifacts/`; `ground_truth.py` encodes the
  typed expected findings the parser test will assert. Two distinct
  artifact families satisfies CLAUDE.md invariant #5 — `claim_finding`
  must return `CONFIRMED`. Format choice (Python module rather than
  YAML/JSON) is documented in the module docstring per the principle
  that fixture data read by code in the same project should not need
  a parsing layer. `artifacts/` is intentionally empty; the README
  documents how to regenerate it from the Parallels test rig.
- **`scripts/submission_dry_run.sh` + `Makefile`** — dev-time safety net that
  stashes `./.claude/` aside, runs `pytest`, the MCP stdio smoke test, and
  `scripts/check_no_secrets.sh`, then restores `./.claude/` via a shell
  `trap`. Verifies that Sanctum's behaviour is not load-bearing on
  framework-proprietary tooling under `./.claude/` — the property the
  hackathon submission's "architectural guardrails, not framework
  scaffolding" claim depends on. Refuses to run if a previous invocation
  left a `.claude.stash` behind (avoids overwriting manual recovery
  state). Invoke via `make submission-dry-run` or directly as
  `./scripts/submission_dry_run.sh`.

- **`docs/ADR_PARSER_LAYER.md` — five Architecture Decision Records for the
  parser layer.** Permanent extraction of the load-bearing decisions made
  during week-2 (frozen `ExecutionEvent` contract; BOTH-field sidecar
  validation; fail-loud `PartialImplementationError` over null-object;
  env-gated fixture mode; exception-message scrubbing via `_safe_field`).
  Working planning artifact `.sherlock-plan.md` remains the implementation
  trail; the ADR doc is the contributor-facing reference for *why* each
  invariant exists. Cross-linked from `src/sanctum/parsers/__init__.py`.
- **Typed parser layer + frozen `ExecutionEvent` contract.** New
  `src/sanctum/events.py` and the `src/sanctum/parsers/` package (6
  modules: `amcache`, `appcompat`/ShimCache, `prefetch`, `sysmon`, `bam`,
  `userassist`) ship the data contract between artifact parsing and the
  `claim_finding` triangulation gate. Parsers return `list[ExecutionEvent]`
  — a frozen dataclass whose `family` field uses the canonical
  `sanctum.families.TOOL_TO_FAMILY` strings (`AppCompat`, `Explorer/NTUSER`,
  `Background-service`, `Kernel-ETW`, `SysMain`) so the gate's family-count
  dedup works without re-mapping. `extras` is wrapped in `MappingProxyType`
  post-construction so consumers cannot silently mutate evidence records,
  and timezone-naive timestamps raise at the constructor boundary because
  a wrong timezone in DFIR is a wrong answer to "did this run before or
  after the breach window?". Parser bodies are env-gated stubs in week 2:
  with `SANCTUM_USE_FIXTURE_SIDECAR=1` they load
  `<artifact>.sanctum-fixture.json` via `parsers/_fixture_io.py`; without
  the env var they raise `PartialImplementationError(NotImplementedError)`,
  which FastMCP surfaces as MCP-spec-compliant `isError: true`. Production
  `server.py` never sets the env var, so real-evidence callers fail loudly
  and the parser layer does not silently shadow `_parse_amcache_stub`.
- **Sidecar loader hardening (`parsers/_fixture_io.py`).** Validates
  **both** `family` AND `tool` fields against the calling parser — same-family
  cross-talk closure (a sidecar's family alone collapses across AppCompat,
  so `parse_shimcache` could otherwise inherit Amcache events and the
  family-count gate would tally a single source as two corroborations; the
  AC-15d regression test pins this). Caps sidecar size at 1 MiB,
  `program_path` at 4 KiB, `evidence_size_bytes` at 2^40. Rejects `bool`-as-int
  in numeric fields; requires string-typed `program_path` and timestamp,
  `dict[str,str]` extras, tz-aware ISO-8601 timestamps. Splits `OSError`
  (I/O fault → propagates) from `JSONDecodeError` (data fault →
  `ArtifactMalformedError`) so the audit ledger's fault classifier does
  not mistype permission/IO errors as malformed evidence.
- **Error-channel quarantine bypass closed.** Attacker-influenceable sidecar
  fields are now scrubbed by `_safe_field()` before they appear in
  exception messages — the angle brackets, control characters, and
  newlines that would re-open the `<evidence-untrusted>` quarantine when
  FastMCP serialises the exception into an `isError: true` MCP response
  are replaced with `?` and the value is truncated to 128 characters.
  Two independent Phase-6 reviewers (types+errors, security) flagged this
  bypass independently — the success path runs through
  `sanctum.sanitize.sanitize()` but the exception path does not. AC-15e
  pins the regression with a sidecar declaring
  `family="</evidence-untrusted>\n<inject>"`.
- **Synthetic-fixture realisation of `case_temp_exec_001` —
  `tests/fixtures/case_temp_exec_001_synthetic/`.** Hand-built sidecar
  fixture corroborating the same scenario as the VM-regen skeleton at
  `tests/fixtures/case_temp_exec_001/`, but populated immediately for
  contract-level testing of the parser layer (the VM-regen flow takes
  ~10 minutes; the synthetic fixture takes 0). Contains an Amcache hive
  + Prefetch `.pf` (LOLBAS-style `RUNTIMEBROKER.EXE` masquerading as the
  legitimate Windows binary) plus their `.sanctum-fixture.json` sidecars.
  `tests/test_synthetic_case.py` asserts (a) two distinct families
  surface, (b) all events agree on the suspect path, (c) `git ls-files`
  includes the fixture tree, (d) a smuggled disk-image extension
  (`*.raw|e01|dd|img|mem|vmem|vmsn`) under the fixture path is still
  hard-denied — closes the broad-re-include hole.
- **`tests/test_parsers.py`** — 19 tests for ACs 1–15e. Each parser
  exercised in fixture mode for happy path, missing artifact, malformed
  sidecar, empty events, and same-family cross-talk closure
  (`test_sidecar_rejects_same_family_wrong_tool_shimcache_vs_amcache` —
  AC-15d, the load-bearing regression for the silent-corruption path
  identified in `feedback_sidecar_path_lookup.md`). AC-13 verifies
  `_TOOL`/`_FAMILY` constants in every parser module match the canonical
  `families.TOOL_TO_FAMILY` map via `importlib.import_module` — a regex
  over `family="..."` would have been tautological because the parsers
  use module-level constants.

### Changed

- **Phase A design-claim narrowing across README + threat-model docs.**
  Pre-submission audit surfaced ~22 design weaknesses; Phase A addresses
  the subset that is claim-overreach (vs. missing capability) by
  narrowing each claim to its defensible scope. Specifically:
  (1) `docs/THREAT_MODEL_TRIANGULATION.md` gains §"Scope and threat-model
  boundary" — family-count gate is a *pre-compromise* corroboration
  primitive; kernel-mode multi-family forgery is OOS for v1, defense
  shifts to deception layer + HMAC ledger.
  (2) `docs/THREAT_MODEL_DECEPTION.md` gains §"Constructive vs.
  destructive forgery" — v1 detects destructive anti-forensics
  signatures only; coherent constructive forgery is OOS, bounded by
  family count.
  (3) `CLAUDE.md` renames "self-correction demo" → "gate-firing demo";
  hook proves gate fires deterministically, not that LLM learned
  self-correction.
  (4) `README.md` gains §"Limits of structural defenses" — names
  interpretation hallucination, sanitization-allowlist residual,
  kernel-rootkit equivalence, hooks-as-defense-in-depth (vs. server-
  side typed boundary as the real guarantee).
  (5) `docs/THREAT_MODEL_SANITIZATION.md` gains §"Test-coverage scope" —
  bypass tests verify server-side stripping invariants; LLM
  end-to-end behavioral robustness is v2 followup.
  (6) `README.md` lead surfaces an explicit **Scope** line: Windows
  host-based execution-evidence forensics, not general DFIR.
  (7) `docs/REPRODUCTION.md` gains a top-of-file ⚠️ operator-discipline
  callout for ext-family `noload,norecovery` mount flags.
  (8) `README.md` Constraint Implementation row in scoring alignment
  table sharpens the server-side-vs-client-hook tier distinction.
  (9) `docs/THREAT_MODEL_LEDGER.md` gains §"Ledger field roles" —
  separates HMAC-keyed chain-integrity hashes (security boundary)
  from plain-SHA-256 content fingerprints (auditing aids).
  (10) `docs/LLM_AGNOSTIC.md` promotes the "tested-with vs.
  compliant-with" caveat to a top-of-file callout — architecturally
  agnostic, behaviorally validated on Opus 4.7 only for v1.
  No code, math, or test changes. `scripts/validate_threat_model_math.py`
  passes unchanged. Plan tracked at `private/plans/sanctum_v1_design_hardening.md`
  (gitignored).

- **`.gitignore`** — adds globbed disk/memory-image extension hard-denies
  (`**/*.raw`, `e01`, `dd`, `img`, `mem`, `vmem`, `vmsn`) so a smuggled
  evidence-image under any future re-include path is still ignored.
  Last-match-wins gitignore semantics; AC-19b regression test pins this.

## [0.2.0] — 2026-04-25

### Security

- **BREAKING — audit ledger upgraded from plain SHA-256 to HMAC-SHA-256.**
  The prior implementation computed `hashlib.sha256(canonical(entry))`
  with no keyed primitive; the README and CLAUDE.md architecture block
  described it as "HMAC-SHA256 chain" despite the code being a plain
  hash chain. An internal audit flagged the discrepancy: a plain-SHA-256
  chain is forgeable by any attacker with ledger write access, whereas an
  HMAC chain requires the attacker to also compromise
  `SANCTUM_LEDGER_HMAC_KEY`. The env var is now mandatory at server
  startup; `append_entry` and `verify_chain` both raise
  `RuntimeError` if the key is missing or shorter than 16 bytes. Operators
  must generate a 32-byte key via
  `python -c 'import secrets; print(secrets.token_hex(32))'` and export it
  before starting the server. No silent downgrade path exists — by design.
- **New optional RFC 3161 TSA witness — `src/sanctum/notary.py`.**
  `stamp_head()` binds the current ledger head to a Trusted Timestamp
  Authority's digital signature via ``openssl ts`` (no new Python deps);
  archives the request (`.tsq`) and response (`.tsr`) bytes alongside the
  ledger. Raises the integrity guarantee from tamper-evident (HMAC) to
  non-repudiable (PKI-signed witness) — the tier required by FRE 902(14)
  self-authentication and NIST SP 800-53 AU-10(5) Digital Signatures.
  Default TSA is `https://rfc3161.ai.moda`; override via `tsa_url`. Call
  at whatever cadence the incident context justifies (per-session for
  hackathon demos; per-N-entries for continuous monitoring).
- **Hardened `mount -o ro` invariant.** Sanctum now actually implements
  the runtime mount-check that CLAUDE.md has been promising: `main()`
  calls `server._validate_evidence_mount(cases_root)` at startup, checks
  the VFS ro flag via `os.statvfs`, and refuses to start on a writable
  mount. `docs/REPRODUCTION.md` expands the mount command to include
  `noload,norecovery` (required to prevent ext3/4 journal replay, which
  writes to the block device even on `-o ro`) plus `blockdev --setro`
  on the loop device. Dev-only `SANCTUM_SKIP_MOUNT_CHECK=1` bypasses
  with a WARN log — never silent.
- **Expanded sanitizer invisible-codepoint coverage.** `sanctum.sanitize`
  now strips the Unicode Tag block (U+E0001–U+E007F), both variation-
  selector blocks (U+FE00–U+FE0F, U+E0100–U+E01EF), and the classic
  zero-width / bidi / general-format ranges. Motivated by arXiv 2510.05025
  "Imperceptible Jailbreaking" — 100% ASR emoji-smuggling attacks that
  visible-pattern regex strip lists cannot catch. Invisibles are now
  stripped silently (no `[REDACTED]` marker) so dense smuggling payloads
  produce readable output; `SanitizationResult.invisibles_stripped` is a
  new field carried to the ledger.

### Changed

- **README — Autonomous Execution Quality row reframed; Reflexion dropped from
  roadmap.** The brief's "Autonomous Execution Quality" criterion is co-equal
  weight (1/6) **and** first tiebreaker **and** Stage 1 gating — three
  load-bearing roles. The prior README marked it as just "tiebreaker" and
  promised a Reflexion-style `<reflect>` pass on every tool call alongside
  the family gate. Huang ICLR 2024
  ([arXiv:2310.01798](https://arxiv.org/abs/2310.01798)) shows intrinsic
  self-correction (Reflexion / Self-Refine) degrades reasoning on average;
  Kamoi TACL 2024 ([arXiv:2406.01297](https://arxiv.org/abs/2406.01297))
  classifies the family-coupling gate Sanctum already plans to ship as the
  empirically-supported *external-signal* alternative. Net effect: scoring
  table row rewritten to reframe `claim_finding` as the primary self-
  correction primitive; week-5 Reflexion implementation **dropped**;
  freed week becomes `sanctum.deception` reason-code layer + week-6
  adversarial benchmark (refusal-under-tampering). Prior-art section
  adds Huang, Kamoi, and Conlan-Baggili-Breitinger DFRWS 2016 (the
  taxonomic foundation for the deception reason codes).

- **Triangulation gate reframed as *artifact families* not *subsystems*.**
  ShimCache and Amcache are both written by the Windows Application
  Experience Service and defeated together by the one-syscall
  `BaseFlushAppcompatCache` / `ShimFlushCache` anti-forensic primitive
  (open-source `AntiForensic.NET` clears both in one run). Counting them
  as two independent sources overstated forgery resistance by ~4
  percentage points at `k=2`. Updated README "senior-analyst gate",
  CLAUDE.md invariant #5, and `docs/THREAT_MODEL_TRIANGULATION.md` with
  a new "Family coupling and the AppCompat correction" section — the
  five families are {AppCompat, Explorer/NTUSER, BAM, Sysmon/ETW,
  Prefetch/SysMain}. Revised Poisson-binomial table with the family
  tuple `(0.10, 0.15, 0.15, 0.20, 0.30)` is regression-tested by
  `scripts/validate_threat_model_math.py` alongside the existing
  non-uniform table.

- **README IR-Accuracy baseline citation — Memory-LLM → DFIR-Metric.**
  The prior "Memory-LLM ACM 2025 = <20% precision" baseline could not
  be verified. A directed literature search against arXiv / DFRWS /
  ACL / OpenReview found no ACM-published paper matching that title.
  Pinned to **DFIR-Metric** (Cherif et al.,
  [arXiv:2505.19973](https://arxiv.org/abs/2505.19973), May 2025) —
  the verifiable closest prior-art DFIR-LLM benchmark; GPT-4.1's best
  reported score is 38.52% TUS@4 on Module III (disk/memory forensic
  tasks). `docs/ACCURACY.md` (roadmap week 8) will pin regression
  numbers against DFIR-Metric TUS@m going forward.

### Added

- `docs/LLM_AGNOSTIC.md` + `scripts/smoke_test_mcp_stdio.sh`: document and
  verify the LLM-agnosticism claim. The doc states the invariant-by-invariant
  contract between the server and any compliant stdio MCP client, names the
  Claude-Code-specific defense-in-depth layer (PreToolUse hook, Bash
  allowlist, hook-induced demo determinism) with generic equivalents for
  Cline / Continue / Claude Desktop / OpenAI MCP shim, and gives connection
  snippets for each. The smoke test pipes a three-message JSON-RPC handshake
  (`initialize` → `notifications/initialized` → `tools/list`) through
  `python -m sanctum.server` and verifies `get_amcache` is advertised —
  passing this is necessary + sufficient for any stdio MCP client to inherit
  Sanctum's server-side guarantees. Claude Code remains the reference client;
  portability is an architectural claim, not a tested-everywhere one.

- `scripts/threat_model_priors.py`: single source of truth for the
  per-subsystem compromise probabilities feeding
  `docs/THREAT_MODEL_TRIANGULATION.md`. Self-contained dataclass +
  helper functions, no third-party deps. Both
  `validate_threat_model_math.py` and `validate_with_sympy.py` now
  import from here, so a change to a prior cannot drift between code
  and docs without the validators failing. Pinned by
  `tests/test_threat_model_priors.py` (canonical vector, hardest-first
  ordering, mean, and per-row rationale invariants).

- `sanctum.sanitize.MAX_INPUT_BYTES` (16 MiB) + `InputTooLargeError`:
  closes the unbounded-`L` DoS surface flagged in
  `docs/THREAT_MODEL_SANITIZATION.md` §7. Inputs above the cap raise
  before any regex scanning runs. Per-call override available via the
  `max_input_bytes` kwarg for callers with legitimate outsize
  payloads. Regression pinned by new boundary tests.
- `sanctum.audit.FindingConfidence` (enum: DRAFT | CORROBORATED |
  FINAL) and `classify_confidence(n_distinct_subsystems)` helper —
  pins the tier boundaries recommended in
  `docs/THREAT_MODEL_TRIANGULATION.md` §5 into code so the future
  week-4 `claim_finding` implementation cannot silently drift from
  the threat-model doc. Ledger-stable string values enforced by test.

- `scripts/sanctum-mcp.service`: hardened systemd unit for production /
  dedicated-host deployments. Runs Sanctum as a non-privileged `sanctum`
  user with `NoNewPrivileges`, `ProtectSystem=strict`,
  `ReadOnlyPaths=/cases /evidence`, `MemoryDenyWriteExecute`, dropped
  `CapabilityBoundingSet`, and a seccomp filter that denies
  `@privileged @debug @mount @reboot @swap` syscalls. Architectural
  defences still come from the typed tool surface; the sandbox limits
  blast radius under the failure-domain-isolation lens.
  `docs/DEV_PLATFORM.md` gains an install/verification section.

- `docs/THREAT_MODEL_LEDGER.md`: full threat model for the audit-ledger
  posture ladder (rung 0 = plain SHA-256, rung 1 = HMAC, rung 2 = RFC 3161
  witness, rung 3 = public Merkle-tree). Documents the attacker model at
  each rung, residual risk, operational cadence guidance, and the
  `openssl ts -verify` command an independent party would run to check a
  stamp.
- `src/sanctum/notary.py`: RFC 3161 TSA stamping for the ledger head.
  `openssl`-based, no new Python dependencies.
- `tests/test_notary.py`: 6 tests covering the stamp-head happy path,
  head-binding correctness, openssl-missing/TSA-rejection error paths,
  archive-dir override, and empty-ledger behaviour. All tests mock
  subprocess + urllib so the suite never hits the network.

### Changed

- `sanctum.sanitize.sanitize`: accepts new `max_input_bytes` kwarg
  with default `MAX_INPUT_BYTES`. Pre-existing callers are unaffected
  (sub-16-MiB inputs behave identically). The staged pipeline is now
  invisibles-strip → pattern-redact → truncate; the new first stage
  covers the Unicode Tag block, both variation-selector blocks, and
  the classic zero-width / bidi / general-format ranges.

- `docs/THREAT_MODEL_SANITIZATION.md`: formal justification for the
  `strip → truncate` ordering in `sanctum.sanitize`. Proves correctness
  via prefix-closure of pattern-freeness; derives the random-placement
  straddle probability `(k−1)/L` and the adversarial upper bound of 1.
  Flags the unbounded-`L` DoS surface as the remaining obligation.
- `docs/THREAT_MODEL_TRIANGULATION.md`: quantitative analysis of the
  `claim_finding` ≥2-of-5 gate. Uniform Binomial(5,p) and Poisson-
  binomial tables under realistic per-subsystem compromise priors
  (ShimCache 0.05 … Sysmon 0.30). Argues for a stratified
  `CORROBORATED (k=2)` vs `FINAL (k=3)` tier split and shows that
  adding a 6th subsystem at fixed `k` is a regression, not an
  improvement.
- `scripts/validate_threat_model_math.py`: stdlib-only regression
  checker for every numeric claim in the two threat-model docs; exits
  non-zero on drift so the docs can't silently become wrong.
- `scripts/validate_with_sympy.py`: independent exact-rational
  verification using SymPy. Renders each probability as a reduced
  fraction so it can be pasted straight into Wolfram Alpha or any
  CAS for third-party confirmation.

- `scripts/claude-session.sh`: clean-room bash helper that spawns Claude Code
  inside a disposable git worktree on a fresh branch. Disposable by default;
  explicit branch names are preserved on exit. No framework dependencies —
  safe for a public repo. Install as `claude-sanctum` via a symlink into
  `~/.local/bin` (see README "Local development" section).

- `tests/test_bypass.py`: consolidated bypass-attempt test suite (16 tests)
  mapping 1:1 to `docs/FAILURE_MODES.md` states 1–6 plus five gap classes —
  symlink escape via case-dir internals; Unicode/bidi/zero-width/newline/
  shell-metacharacter in `case_id`; truncation-boundary injection; ledger-
  file-missing design-pin. Directly responsive to FIND EVIL! Constraint
  Implementation rubric's "tested for bypass" criterion.
- README "Bypass coverage" section with a scannable matrix mapping attack
  classes to specific test names; `docs/FAILURE_MODES.md` gains "Tested in"
  cross-references to the same suite.

- `docs/DEV_PLATFORM.md`: maintainer-facing developer-platform guide. Documents
  the physical x86_64 Ubuntu 22.04 native setup used to build Sanctum,
  hardware equivalence class and don't-buy list, bring-up sequence, how this
  path differs from the judge-facing `docs/REPRODUCTION.md`, local demo-
  recording setup for the 5-min FIND EVIL! screencast, and the EC2 +
  SANS SIFT AMI cloud fallback. Feeds the hackathon's Try-It-Out Instructions
  deliverable.

### Changed

- `src/sanctum/server.py` `_resolve_case`: tightened case-ID validation before
  filesystem resolution. New `_SAFE_CASE_ID` allowlist rejects Unicode control
  characters (bidi override `\u202e`, zero-width `\u200b`, etc.), shell
  metacharacters, whitespace, and path separators. Adds an explicit `..`
  substring check as belt-and-suspenders, and independently resolves the
  Amcache hive path to catch symlinks *inside* the case directory pointing
  outside — the case-dir containment check alone did not catch this class.
- `pyproject.toml`: allow `E501` in `tests/*` — descriptive test-function
  signatures are self-documenting and wrapping them at 100 chars hurts
  readability without protecting anything.

### Fixed

- `tests/test_sanitize.py::test_pre_and_post_hashes_equal_when_clean`:
  assertion was inverted (`!=` where `==` was intended per the test name and
  the second assertion in the same test). Pinned the property: when no
  injection patterns are stripped and no truncation fires,
  `pre_hash == post_hash` exactly.

- `docs/REPRODUCTION.md`: replaced `REPLACE_WITH_REPO` placeholder in the Step 1
  clone command with the real `JasonTofte/sanctum-mcp` URL; added a note on
  private→public flip timing and `gh auth login` for contributors cloning
  before submission.

### Changed

- `scripts/bootstrap_vm.sh`: pinned `teamdfir/sift-saltstack` to commit
  `96b7d989` (2026-04-14, *"Merge pull request #219 from digitalsleuth/vol3"*)
  so judge reruns match the commit validated during development. The upstream
  repo ships a stale `VERSION` file (`v2020.01.01-rc1`) despite active commits,
  so drift is otherwise silent.

## [0.1.0] — 2026-04-17

### Added

- Initial P0 skeleton: public-safe repository layout, MIT license, hackathon submission scaffolding.
- Python package `sanctum` with MCP server stub, append-only audit ledger, and prompt-injection sanitization helpers.
- One typed tool: `get_amcache(case_id)` returning structured Amcache rows wrapped in `<evidence-untrusted>` delimiters.
- Architecture + reproduction documentation (`docs/ARCHITECTURE.md`, `docs/REPRODUCTION.md`).
- Public-secrets precommit check (`scripts/check_no_secrets.sh`).
- SIFT Workstation bootstrap documentation for Ubuntu 22.04 pinned to a specific `teamdfir/sift-saltstack` commit SHA.

# case_temp_exec_001_synthetic — minimum-viable corroboration case (synthetic)

**Purpose.** Smallest input that exercises Sanctum's ≥2-family triangulation
gate (CLAUDE.md invariant 5). One suspect binary appears in two distinct
artifact families — AppCompat (via Amcache) and SysMain (via Prefetch) —
which is the minimum corroboration shape `claim_finding` requires.

**Sibling case.** `tests/fixtures/case_temp_exec_001/` (added by PR #15)
is the **VM-regen realisation** of the same scenario — same `case_id`,
real Parallels-VM-generated artifacts, ground-truth in `ground_truth.py`.
This `_synthetic` directory is the **hand-built realisation** of that
scenario: contract-level testing of the parser layer without waiting on
the VM regen flow (~10 minutes vs. instant). Both can coexist.

**Suspect binary.** `C:\ProgramData\runtimebroker.exe`, a LOLBAS-style
masquerade of the legitimate `C:\Windows\System32\RuntimeBroker.exe`.
ProgramData is world-writable; placing a binary named `runtimebroker.exe`
there is a classic name-confusion pattern that survives casual visual
inspection of process trees.

**Synthetic, not real.** Both `Amcache.hve` and `RUNTIMEBROKER.EXE-A1B2C3D4.pf`
are non-binary text placeholders. The week-2 parsers operate in fixture
mode (`SANCTUM_USE_FIXTURE_SIDECAR=1`) and read events from the
`.sanctum-fixture.json` sidecars next to each artifact. Week 3 will replace
fixture-mode with real parsers operating on real bytes; the case can then
be regenerated from a CFReDS-style donor image without changing the
sidecar contract.

**Layout.**

    case_temp_exec_001_synthetic/
      README.md                                                        ← this file
      registry/
        Amcache.hve                                                    ← stub bytes
        Amcache.hve.sanctum-fixture.json                               ← fixture-mode events
      prefetch/
        RUNTIMEBROKER.EXE-A1B2C3D4.pf                                  ← stub bytes
        RUNTIMEBROKER.EXE-A1B2C3D4.pf.sanctum-fixture.json             ← fixture-mode events

**How to regenerate sidecars (future).** A `tests/fixtures/scripts/`
generator is anticipated for week 3 once real parsers exist; for week 2
the JSON is hand-authored and the `source_artifact_sha256` field is left
all-zero (the loader does not verify it at runtime — it is recorded for
forensic chain-of-custody traceability and CI drift detection only).

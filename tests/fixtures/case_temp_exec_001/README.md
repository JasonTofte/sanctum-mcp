# case_temp_exec_001 — temp-directory execution

**Status:** skeleton. `artifacts/` is empty pending VM run. `ground_truth.py`
is authoritative for what the parser test will assert.

## Scenario

A benign signed binary (`notepad.exe`) is copied to `%TEMP%\benign_marker.exe`
and executed for ~5 seconds, then the VM is shut down cleanly. Sanctum must
detect the execution from two independent artifact families.

## Triangulation target

| Family    | Artifact                          | Why this family is independent |
|-----------|-----------------------------------|-------------------------------|
| AppCompat | `Amcache.hve`                     | Registry hive written by the AppID service on every PE seen by the system. Substring match on `\Temp\benign_marker.exe` proves the parser walked the `InventoryApplicationFile` subkey. |
| SysMain   | `Prefetch/BENIGN_MARKER.EXE-*.pf` | Prefetch service writes a `.pf` file only on actual execution. Independent of the registry — different service, different on-disk format. |

Two distinct families ⇒ `claim_finding(...)` MUST return `CONFIRMED` per
project `CLAUDE.md` invariant #5 (≥2 independent artifact families).

## Target file layout

```
case_temp_exec_001/
├── README.md           ← this file
├── ground_truth.py     ← typed expected findings, imported by tests
└── artifacts/          ← extracted from VM after the scenario runs
    ├── Amcache.hve
    └── Prefetch/
        └── BENIGN_MARKER.EXE-<8HEXHASH>.pf
```

## How to regenerate from the VM

Source: the Parallels VM described in the `project_sanctum_test_rig`
auto-memory entry. Snapshot baseline ID
`{a89ee9e4-93e2-40f3-9757-c636c9978367}`.

### 1. Revert host VM to clean baseline

```bash
PRLCTL='/Applications/Parallels Desktop.app/Contents/MacOS/prlctl'
$PRLCTL snapshot-switch "Windows 11" --id {a89ee9e4-93e2-40f3-9757-c636c9978367}
$PRLCTL start "Windows 11"
```

### 2. Inside the VM (PowerShell as `jasontofte`)

```powershell
Copy-Item C:\Windows\System32\notepad.exe $env:TEMP\benign_marker.exe
& $env:TEMP\benign_marker.exe
Start-Sleep -Seconds 5
Stop-Process -Name benign_marker -ErrorAction SilentlyContinue
Start-Sleep -Seconds 30   # let SysMain commit Prefetch + Amcache flush to disk
shutdown /s /t 0
```

The 30-second sleep before shutdown is load-bearing: Prefetch buffers
writes for ~10 seconds after process exit, and Amcache only flushes on
clean service-stop or scheduled idle-time maintenance task. A premature
shutdown produces a missing `.pf` file and an Amcache that lags the
execution by one boot.

### 3. Extract artifacts (host, VM stopped)

| Source (in guest)                                  | Destination (in this fixture) |
|----------------------------------------------------|------------------------------|
| `C:\Windows\AppCompat\Programs\Amcache.hve`        | `artifacts/Amcache.hve`      |
| `C:\Windows\Prefetch\BENIGN_MARKER.EXE-*.pf`       | `artifacts/Prefetch/`        |

For the first few fixtures use a Parallels shared folder (fastest). For
the demo or any case being submitted as evidence, switch to read-only
mount of the `.pvm` disk image — that aligns with Sanctum invariant #4
(evidence paths are read-only at the OS layer).

### 4. Verify the parser test

```bash
pytest tests/test_case_temp_exec_001.py -v
```

The test does not exist yet; it will be written alongside the first
parser (Prefetch is recommended first per the dev plan in conversation).

## Known noise to ignore

From the `project_sanctum_test_rig` auto-memory entry, §"Forensic-baseline
residuals":

- **Orphan SID** `S-1-5-21-622017432-2902302144-924542875-1001` in
  `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings` is the
  `defaultuser0` OOBE setup account, not a ghost user. Filter when adding
  BAM-family cases.
- **Hostname** `JASONTOFTE36FC` is Microsoft's random-suffix default;
  appears in `4688` Subject events, NTUSER.DAT path, Amcache hostname
  field. Expected.

Neither affects this case (no BAM, no NTUSER, no event log) but document
once here so future cases inherit the filter.

## What this fixture exercises and what it does NOT

Exercises:
- AppCompat parser correctness on a freshly-flushed Amcache.
- SysMain parser correctness on a single `.pf` file.
- `claim_finding` returning `CONFIRMED` when two distinct families agree.

Does NOT exercise:
- Single-family DRAFT path (CLAUDE.md invariant #5 — see the planned
  `case_appcompat_only_FAIL` fixture).
- Anti-forensics (binary erasure, `BaseFlushAppcompatCache`, etc.).
- Timeline correlation across families.
- Sysmon/ETW family (separate fixture).

These are intentionally out of scope for the MVP fixture; they belong to
later cases in the matrix.

<!--
  STATUS: DRAFT — agent-staged 2026-06-13. Results sections marked
  "PENDING OPERATOR RUN" are filled in only after the read-only ingest +
  parser run on the Parallels Win11 VM. Do NOT assert results here before
  the run produces them. This file is the FIND EVIL! "Dataset Documentation"
  submission component; the filled-in results also feed the Accuracy Report
  and the docs/ACCURACY.md §"Independent-corpus validation" section.
-->

# Dataset Documentation — NIST CFReDS Data Leakage Case

Independent third-party validation corpus for Sanctum's parser layer and
family-corroboration gate. This corpus replaces the self-generated
`c2agent` scenario as the *primary* real-artifact evidence base, retiring
the "ground truth is self-generated" honest limit (see
[`docs/ACCURACY.md`](ACCURACY.md) §"Real Artifact Validation" #3).

## Provenance

| Property | Value |
|---|---|
| Dataset | NIST CFReDS — Data Leakage Case ("Iaman Informant") |
| Source (canonical) | https://cfreds.nist.gov/all/NIST/DataLeakageCase |
| Source (archive, downloads) | https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html |
| Publisher | NIST Computer Forensic Reference Data Sets (CFReDS) — the reference corpus built for forensic *tool validation* (CFTT), proficiency testing, and lab accreditation |
| Suspect OS | Microsoft Windows 7 Ultimate (SP1), NTFS, 20 GB HDD |
| Host identity | Computer `INFORMANT-PC`; primary user `informant`; timezone Eastern (UTC−05:00) |
| Scenario | Insider data leakage — exfil over email / personal cloud / USB / CD-R, with anti-forensic cleanup |
| Answer key | `leakage-answers.pdf` / `.docx`, v1.32, last updated 2018-07-23 — **open, no login** |

## Evidence files used (host-execution scope only)

Sanctum is Windows host-based execution-evidence forensics, so only the PC
disk image is in scope. The removable-media images (USB / CD-R) are
**out of scope** (exfil-destination artifacts, not host execution).

| File set | Format | Size | Used? |
|---|---|---|---|
| `pc.E01` (+`.E02`–`.E04`) | EnCase EWF | ~7.28 GB | YES (or the dd set below) |
| `pc.7z.001`–`.003` | dd / raw | ~5.05 GB compressed | Alternative to E01 |
| `rm#1`–`rm#3` (USB/CD-R) | E01 / dd / ISO | — | NO — out of host-execution scope |

NIST publishes **MD5 and SHA-1** for every image; hash-matching the
acquired image is part of the documented exercise.

### Acquired-image hashes (recorded at ingest)

<!-- PENDING OPERATOR RUN — paste the NIST-published hash and the locally
     recomputed hash side by side. AC-3: a mismatch HALTS the run. -->

NIST publishes per-segment SHA-1 only (no MD5/SHA-256) at
`hash_values.html`. Published values for the E01 set:

| File | NIST-published SHA-1 | Locally recomputed | Match? |
|---|---|---|---|
| `cfreds_2015_data_leakage_pc.E01` | `72432916933F5A309A8C456B40C9601D1F8D2A4F` | `72432916…1F8D2A4F` | ✅ 2026-06-13 |
| `cfreds_2015_data_leakage_pc.E02` | `0CAF4261ED8432A8B3BAA019B1B28FDF96F79130` | `0CAF4261…96F79130` | ✅ 2026-06-13 |
| `cfreds_2015_data_leakage_pc.E03` | `BE836C891736C4C0C2253C6803399BF0F2A599BA` | `BE836C89…F2A599BA` | ✅ 2026-06-13 |
| `cfreds_2015_data_leakage_pc.E04` | `9159BFFD56097495F73FBBF967B75EB288B1E3DE` | `9159BFFD…88B1E3DE` | ✅ 2026-06-13 |

Download acquired 2026-06-13 (4 segments, ~7.3 GB) to gitignored
`private/research/sans-standard-case-nist-dataleakage/`. AC-3 satisfied —
all four segments match; image cleared for read-only mount.

## Sanctum family coverage on this image

Family availability is OS-version-dependent. On Windows 7 the reachable
floor is three families (see the OS-dependency reasoning below).

| Family | Member | Win7 availability | Q11 answer-key citation |
|---|---|---|---|
| AppCompat | ShimCache (AppCompatCache) | Present | Yes — `HKLM\SYSTEM\…\AppCompatCache\` |
| Explorer / NTUSER | UserAssist | Present | Yes — `HKU\informant\…\UserAssist\…\Count\` |
| SysMain | Prefetch | Present | Yes — `\Windows\Prefetch\*.pf` |
| Background-service | BAM | **Absent** — BAM is Windows 10 1709+ | Never cited (consistent with Win7) |
| Kernel-ETW | Sysmon / 4688 | **Absent by default** — Sysmon is a separate install; 4688 command-line auditing requires a GPO | Not cited |

**Coverage target: 3 of 5 families reachable** — comfortably ≥2 for the
corroboration gate. AC-2: BAM and Sysmon absence is *expected forensic
behavior on Win7*, documented as such, not a parser failure.

## Reproduction procedure (read-only, hash-verified)

Run on the Parallels Windows 11 VM (Prefetch parsing requires Windows;
`windowsprefetch` uses `ctypes.windll`).

```
# 0. Stage a gitignored landing area (NEVER commit real evidence)
mkdir -p private/research/sans-standard-case-nist-dataleakage

# 1. Download the PC image set + the published hash file from CFReDS
#    (pc.E01..E04, or the smaller pc.7z dd set) into the staging area.

# 2. Verify integrity BEFORE mounting — recompute and compare to NIST's
#    published MD5/SHA-1. AC-3: on mismatch, STOP and re-download.

# 3. Mount READ-ONLY (Arsenal Image Mounter default is RO; or FTK Imager).
#    Do NOT allow write / journal replay on the evidence image.

# 4. Copy out the in-scope artifacts (they are plain files once mounted):
#      Windows\System32\config\SYSTEM        -> SYSTEM   (ShimCache)
#      Users\informant\NTUSER.DAT            -> NTUSER   (UserAssist)
#      Windows\AppCompat\Programs\Amcache.hve-> Amcache  (if present)
#      Windows\Prefetch\*.pf                 -> Prefetch (SysMain)

# 5. Unmount. Run Sanctum's real-mode parsers against the copied artifacts.

# 6. Paste parser outputs back to the agent to fill the Results section.
```

## Results — parser-layer validation vs answer key

Run 2026-06-13 on the Parallels Win11 ARM64 VM. Image SHA-1-verified →
Arsenal Image Mounter read-only mount → backup-mode artifact extraction →
Sanctum **real-mode** parsers (no fixture sidecars). Library versions:
`regipy==6.2.1`, `windowsprefetch==4.0.3`.

### Parse yield (0 errors)

| Family | Parser | Artifact | Events (distinct programs) |
|---|---|---|---|
| AppCompat | `parse_shimcache` | `SYSTEM` | 292 (213) |
| Explorer | `parse_userassist` | `NTUSER.DAT` (user `informant`) | 44 (43) |
| SysMain | `parse_prefetch` | 95 `*.pf` | 95 (68) |

### Scored vs the official answer key (§2 Target Systems / §3 Suspect timeline)

The NIST answer key documents the suspect's installed/executed applications.
The table scores Sanctum's parser output **against** that ground truth — no
tool name was taken from the key and asserted into the result; each row is
where the parsers independently recorded the program.

| Documented insider app (NIST) | Role | Sanctum families | Gate tier |
|---|---|---|---|
| **Eraser** (`eraser.exe`, `eraser 6.2.0.2962.exe`) | anti-forensic wipe | ShimCache + UserAssist + Prefetch | **FINAL** (3) |
| **CCleaner** (`ccleaner64.exe`, `ccsetup504.exe`) | anti-forensic | ShimCache + UserAssist + Prefetch | **FINAL** (3) |
| **Google Drive** (`googledrivesync.exe`) | cloud exfil | ShimCache + UserAssist + Prefetch | **FINAL** (3) |
| **Apple iCloud** (`icloud.exe`, `icloudsetup.exe`) | cloud | ShimCache only | DRAFT (single-family) |
| **Outlook** (`outlook.exe`) | email channel | all three | **FINAL** (3) |
| **MS Office** (`winword.exe` / `excel.exe` / `powerpnt.exe`) | documents | WinWord 3; Excel/PPT 2 | CORROBORATED+ |
| **IE / Chrome** (`iexplore.exe` / `chrome.exe`) | leakage research | each 2 | CORROBORATED |

**8 of 8 documented insider applications detected.** 73 distinct programs
were corroborated across ≥2 families overall.

### Cross-family corroboration (AC-1) — SATISFIED

The case-critical tools — both anti-forensic utilities and the Google Drive
exfil client — each appear in **all three reachable families**, which the
`claim_finding` gate grades **FINAL**. This is the family-corroboration
primitive firing on independent, third-party ground truth.

Two findings that confirm the result is genuine rather than coincidental:

1. **iCloud is honestly single-family — and that is correct.** The answer
   key records iCloud was **uninstalled on D-Day (2015-03-25 11:18)**, so its
   UserAssist/Prefetch traces were removed; only the ShimCache entry
   persisted. Sanctum reports it as a single-family DRAFT hypothesis, not a
   corroborated finding — exactly the conservative behavior the gate exists
   to enforce.
2. **Execution evidence survived the anti-forensic effort.** The suspect ran
   Eraser, ran CCleaner, and emptied the Recycle Bin specifically to destroy
   traces (answer key, D-Day 11:13–11:15) — yet ShimCache, Prefetch, and
   UserAssist each still recorded those very tools executing. Multi-family
   triangulation is resilient to single-vector anti-forensics, which is the
   architectural thesis.

### Integrity references

Per-segment EWF SHA-1s verified against `hash_values.html` (all 4 match,
2026-06-13). The answer key additionally publishes the **full acquired-image**
hashes — MD5 `A49D1254C873808C58E6F1BCD60B5BDE`, SHA-1
`AFE5C9AB487BD47A8A9856B1371C2384D44FD785` — a second independent integrity
anchor.

## Contamination disclosure (AC-4)

The NIST Data Leakage answer key is **publicly downloadable** and the case
has many published walkthroughs, so its *reasoning paths* are likely
present in LLM training data. This validation therefore makes a
**deterministic parser-extraction** claim — Sanctum's typed parsers
extract artifact bytes from the image regardless of any memorized
narrative — and does **not** claim an uncontaminated LLM-reasoning score.
The rigorous accuracy number remains the within-model DFIR-Metric eval
(see [`docs/ACCURACY.md`](ACCURACY.md)); this corpus is the
*independent, third-party real-evidence* exhibit.

## License & citation

CFReDS is a NIST-published U.S. Government reference corpus. Cite as: NIST
Computer Forensic Reference Data Sets (CFReDS), "Data Leakage Case."
Real evidence (registry hives, disk image) is **not** redistributed in
this repository — only the validation *results and hashes* are committed.

---

<!-- DRAFT block to be merged into docs/ACCURACY.md once Results land.
     Kept here (not in ACCURACY.md) so no PENDING placeholder lands in the
     measurement-protocol doc before it is measured. -->

### [STAGED for ACCURACY.md] Independent-corpus validation: NIST CFReDS Data Leakage

> Filled and moved into `docs/ACCURACY.md` after the operator run. Until
> then it lives here as a draft to avoid asserting unmeasured results in
> the measurement-protocol document.

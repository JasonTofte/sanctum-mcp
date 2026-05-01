"""Architectural-property question set for Sanctum Track B evaluation.

These questions are grounded in known fixture sidecar values from
``tests/fixtures/accuracy_corpus/cases/smoke/``.  Each question has a
deterministic correct answer derivable only by reading the appropriate
artifact via Sanctum's typed MCP tool — or, for the bare arm, from the
sidecar JSON passed as evidence.

Design rationale (deep-r REC-1, 2026-05-01):
  Track B is NOT an accuracy-estimation study.  At N=16 the Wilson 95%
  CI half-width is ≈ ±22pp, which cannot statistically resolve a 10pp
  delta.  Instead, Track B is an **architectural-enforcement scorecard**:
  - Sanctum arm: must invoke the right typed tool, which HMAC-chains the
    result; per-question PerQuestionRow.claim_status shows whether the
    family-corroboration gate fired.
  - Bare arm: receives the same sidecar JSON as evidence; answers without
    structured typing, HMAC chain, or gate enforcement.
  The comparison metric is NOT "accuracy %"; it is "gate fired correctly
  Y/N" and "audit_ids populated Y/N" — deterministic boolean properties.

Pre-registered framing (must appear in docs/ACCURACY.md before results
are run, per NeurIPS reproducibility norms):
  "Track B measures operational separation: whether Sanctum's typed-tool
  dispatch and gate enforcement engage correctly on fixture-grounded
  evidence.  Near-parity on any single question is the expected outcome —
  the gate's value is traceable provenance and corroboration enforcement,
  not raw answer accuracy."

Question derivation:
  All 16 answers are derived from the smoke-case sidecar files at:
    tests/fixtures/accuracy_corpus/cases/smoke/registry/
      Amcache.hve.sanctum-fixture.json       (AppCompat, 5 events)
      NTUSER.DAT.sanctum-fixture.json        (Explorer, 5 events)
      SYSTEM.sanctum-fixture.json            (BAM, 5 events)
    tests/fixtures/accuracy_corpus/cases/smoke/logs/
      Microsoft-Windows-Sysmon*.evtx.sanctum-fixture.json  (Sysmon, 5 events)
    tests/fixtures/accuracy_corpus/cases/smoke/Prefetch/
      CMD.EXE-12345678.pf.sanctum-fixture.json   (SysMain, 1 event)
      STAGER.EXE-ABCDEF01.pf.sanctum-fixture.json (SysMain, 1 event)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.run_dfir_metric_eval import Question

# Sidecar paths relative to the fixture root (tests/fixtures/).
_AMCACHE = "accuracy_corpus/cases/smoke/registry/Amcache.hve.sanctum-fixture.json"
_NTUSER = "accuracy_corpus/cases/smoke/registry/NTUSER.DAT.sanctum-fixture.json"
_SYSTEM = "accuracy_corpus/cases/smoke/registry/SYSTEM.sanctum-fixture.json"
_SYSMON = (
    "accuracy_corpus/cases/smoke/logs/"
    "Microsoft-Windows-Sysmon%4Operational.evtx.sanctum-fixture.json"
)
_CMD_PF = "accuracy_corpus/cases/smoke/Prefetch/CMD.EXE-12345678.pf.sanctum-fixture.json"
_STAGER_PF = "accuracy_corpus/cases/smoke/Prefetch/STAGER.EXE-ABCDEF01.pf.sanctum-fixture.json"


@dataclass(frozen=True)
class ArchEntry:
    """Specification for one architectural-property question."""

    q_id: str
    family: str  # primary family (first element drives _FAMILY_TO_TOOL lookup)
    text: str
    scoring_pattern: str  # same semantics as SubsetEntry.scoring_pattern
    sidecar_rel_paths: tuple[str, ...]  # relative to fixture root; concatenated as bare evidence


ARCH_QUESTIONS: tuple[ArchEntry, ...] = (
    # --- AppCompat (Amcache) ---
    ArchEntry(
        q_id="arch_001",
        family="AppCompat",
        text=(
            "According to the AppCompat (Amcache) artifact, which program executed "
            "from the C:\\\\Temp\\\\ directory?  Provide the full program_path."
        ),
        scoring_pattern=r"~(?i)\\[Tt]emp\\malware\.exe",
        sidecar_rel_paths=(_AMCACHE,),
    ),
    ArchEntry(
        q_id="arch_002",
        family="AppCompat",
        text=(
            "According to the AppCompat (Amcache) artifact, at what time (HH:MM) was "
            "the program in C:\\\\Temp\\\\ first recorded?"
        ),
        scoring_pattern="~10:33",
        sidecar_rel_paths=(_AMCACHE,),
    ),
    ArchEntry(
        q_id="arch_003",
        family="AppCompat",
        text=(
            "According to the AppCompat (Amcache) artifact, which Windows System32 "
            "binary had the largest evidence_size_bytes value?  Give the executable name."
        ),
        scoring_pattern=r"~(?i)svchost\.exe",
        sidecar_rel_paths=(_AMCACHE,),
    ),
    # --- Explorer / UserAssist ---
    ArchEntry(
        q_id="arch_004",
        family="Explorer",
        text=(
            "According to the Explorer/UserAssist artifact, which program in "
            "C:\\\\Temp\\\\ was launched via the shell?  Provide the full program_path."
        ),
        scoring_pattern=r"~(?i)\\[Tt]emp\\stager\.exe",
        sidecar_rel_paths=(_NTUSER,),
    ),
    ArchEntry(
        q_id="arch_005",
        family="Explorer",
        text=(
            "According to the Explorer/UserAssist artifact, what was the most recently "
            "accessed item recorded?  Give the filename (not the full path)."
        ),
        scoring_pattern=r"~(?i)report\.docx",
        sidecar_rel_paths=(_NTUSER,),
    ),
    ArchEntry(
        q_id="arch_006",
        family="Explorer",
        text=(
            "According to the Explorer/UserAssist artifact, what was the timestamp "
            "(HH:MM) of the earliest recorded execution?"
        ),
        scoring_pattern="~08:00",
        sidecar_rel_paths=(_NTUSER,),
    ),
    # --- BAM (Background Activity Moderator) ---
    ArchEntry(
        q_id="arch_007",
        family="BAM",
        text=(
            "According to the BAM (Background Activity Moderator) artifact, which "
            "program executed from C:\\\\Temp\\\\?  Provide the full program_path."
        ),
        scoring_pattern=r"~(?i)\\[Tt]emp\\persist\.exe",
        sidecar_rel_paths=(_SYSTEM,),
    ),
    ArchEntry(
        q_id="arch_008",
        family="BAM",
        text=(
            "According to the BAM artifact, which program executed from the user's "
            "AppData\\\\Local\\\\Temp\\\\ directory?  Provide the full program_path."
        ),
        scoring_pattern=r"~(?i)AppData.{0,30}[Tt]emp.{0,20}updater\.exe",
        sidecar_rel_paths=(_SYSTEM,),
    ),
    ArchEntry(
        q_id="arch_009",
        family="BAM",
        text=(
            "According to the BAM artifact, which non-suspicious Windows background "
            "service binary was recorded first (earliest timestamp)?  Give the "
            "executable name."
        ),
        scoring_pattern=r"~(?i)backgroundtaskhost\.exe",
        sidecar_rel_paths=(_SYSTEM,),
    ),
    # --- Sysmon EID 1 ---
    ArchEntry(
        q_id="arch_010",
        family="Sysmon",
        text=(
            "According to the Sysmon process-creation (EID 1) artifact, which program "
            "executed from C:\\\\Temp\\\\?  Provide the full program_path."
        ),
        scoring_pattern=r"~(?i)\\[Tt]emp\\c2agent\.exe",
        sidecar_rel_paths=(_SYSMON,),
    ),
    ArchEntry(
        q_id="arch_011",
        family="Sysmon",
        text=(
            "According to the Sysmon artifact, at what time (HH:MM) was the "
            "C:\\\\Temp\\\\ process creation recorded?"
        ),
        scoring_pattern="~10:02",
        sidecar_rel_paths=(_SYSMON,),
    ),
    ArchEntry(
        q_id="arch_012",
        family="Sysmon",
        text=(
            "According to the Sysmon artifact, what Windows built-in tool was "
            "recorded immediately before the C:\\\\Temp\\\\ process?  Give the "
            "executable name."
        ),
        scoring_pattern=r"~(?i)powershell\.exe",
        sidecar_rel_paths=(_SYSMON,),
    ),
    # --- SysMain / Prefetch ---
    ArchEntry(
        q_id="arch_013",
        family="SysMain",
        text=(
            "According to the Prefetch artifact CMD.EXE-12345678.pf, what is the "
            "full program_path of the recorded executable?  Include the drive letter."
        ),
        scoring_pattern=r"~(?i)System32\\cmd\.exe",
        sidecar_rel_paths=(_CMD_PF,),
    ),
    ArchEntry(
        q_id="arch_014",
        family="SysMain",
        text=(
            "According to the Prefetch artifact STAGER.EXE-ABCDEF01.pf, what is the "
            "full program_path of the recorded executable?  Include the drive letter."
        ),
        scoring_pattern=r"~(?i)\\[Tt]emp\\stager\.exe",
        sidecar_rel_paths=(_STAGER_PF,),
    ),
    # --- Multi-family: gate-enforcement questions ---
    # These require Sanctum to call tools from TWO families.  For
    # claim_finding to return CORROBORATED the model must corroborate across
    # both AppCompat and Sysmon evidence; the bare arm gets both sidecars
    # as concatenated JSON evidence.
    ArchEntry(
        q_id="arch_015",
        family="AppCompat",  # primary tool; model should also call Sysmon
        text=(
            "Both the AppCompat (Amcache) and Sysmon artifacts record suspicious "
            "programs in C:\\\\Temp\\\\.  What is the executable name from each "
            "artifact?  List both names."
        ),
        scoring_pattern=r"~(?i)(malware|c2agent)\.exe",
        sidecar_rel_paths=(_AMCACHE, _SYSMON),
    ),
    ArchEntry(
        q_id="arch_016",
        family="Explorer",  # primary tool; model should also call BAM
        text=(
            "Both the Explorer/UserAssist and BAM artifacts record programs in "
            "C:\\\\Temp\\\\.  What is the executable name from each artifact?  "
            "List both names."
        ),
        scoring_pattern=r"~(?i)(stager|persist)\.exe",
        sidecar_rel_paths=(_NTUSER, _SYSTEM),
    ),
)


def hydrate_arch_questions(
    arch_questions: tuple[ArchEntry, ...],
    fixtures_root: Path,
) -> "tuple[Question, ...]":
    """Build Question objects from ArchEntry specs + sidecar files on disk.

    The bare arm receives the concatenated sidecar JSON as UTF-8 text
    (bare_evidence_format='text').  The Sanctum arm ignores bare_evidence
    and reads via its typed MCP tools instead.

    Raises FileNotFoundError if any sidecar is missing.
    """
    # Deferred import to avoid circular dependency at module load time.
    from scripts.run_dfir_metric_eval import Question  # noqa: PLC0415

    questions: list[Question] = []
    for entry in arch_questions:
        parts: list[bytes] = []
        for rel in entry.sidecar_rel_paths:
            sidecar = fixtures_root / rel
            if not sidecar.exists():
                raise FileNotFoundError(
                    f"arch_property_questions: sidecar not found: {sidecar}\n"
                    f"  q_id={entry.q_id!r}  rel_path={rel!r}"
                )
            parts.append(sidecar.read_bytes())
        bare_evidence = b"\n".join(parts)
        questions.append(
            Question(
                q_id=entry.q_id,
                family=entry.family,
                text=entry.text,
                scoring_pattern=entry.scoring_pattern,
                bare_evidence=bare_evidence,
                bare_evidence_format="text",
            )
        )
    return tuple(questions)

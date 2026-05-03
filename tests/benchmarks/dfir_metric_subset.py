"""License-clean subset specification for the DFIR-Metric Module II CTF.

This module identifies WHICH upstream questions Sanctum evaluates against
and HOW each one is scored — but it never quotes the upstream question
or answer text. The full upstream JSON is fetched at runtime by
``scripts/fetch_dfir_metric.py`` into ``.cache/dfir-metric/`` (which is
gitignored). This split is what makes the subset license-clean: the
upstream content (license: null) lives only on the contributor's
machine; the public repo carries only Sanctum's derivative metadata.

License & reproduction details: see ``docs/ACCURACY.md`` § "License &
Reproduction".

Subset shape — each ``SubsetEntry``:
  - ``line_offset``: 0-indexed line in the upstream DFIR-Metric-CTF.json
  - ``family``: one of the 5 canonical Sanctum families (CLAUDE.md #5)
  - ``scoring_pattern``: regex (prefix ``r"~"``) OR exact string our
    derivation; NEVER the verbatim upstream answer
  - ``justification``: one-line rationale for inclusion. Must NOT
    paraphrase the upstream question text — the Jaccard-similarity
    test (``tests/benchmarks/test_subset_jaccard_similarity.py``,
    opt-in) enforces this with token-set overlap < 0.30.

Selection criteria (deep-r R4 — make rubric reviewable without
reading ``scripts/expand_subset.py``).

Inclusion (a question is in the subset iff all four hold):
  1. Answerable from exactly one of the 5 Sanctum artifact families.
  2. Family tag is verifiable from the artifact description alone —
     no cross-family inference needed.
  3. ``scoring_pattern`` is achievable without verbatim copy of the
     upstream answer text (license-clean derivative metadata only).
  4. ``Jaccard(justification, upstream_question_text) < 0.30`` — the
     opt-in test ``test_subset_jaccard_similarity.py`` enforces this.

Exclusion (any of the following disqualifies a question):
  - Requires cross-family synthesis (ambiguous family tag).
  - About a Windows event/artifact not in any Sanctum family — no
    ground-truth coverage in v1.
  - Has a free-text answer not reducible to a substring or regex
    pattern. Promote to TUS@m for paper-grade multi-criterion
    scoring (see ``docs/ACCURACY.md`` § "AC-12 disclaimer").

Phase B status: 5 entries (proof of life). Phase B post-REFACTOR
expands to ~45 entries via ``scripts/expand_subset.py``. Each family
must end up with multiple entries so single-author tagging bias
surfaces in the per-family ``tagged_count`` column of the Numbers
table (AC-9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Family = Literal["AppCompat", "Explorer", "BAM", "Sysmon", "SysMain"]
QuestionType = Literal["factual", "adversarial_single_family", "autonomous"]


@dataclass(frozen=True)
class SubsetEntry:
    line_offset: int
    family: Family
    scoring_pattern: str
    justification: str
    question_type: QuestionType = "factual"
    # Additional families whose tools are exposed to the agent for multi-family
    # corroboration questions. The `family` field remains the primary tag for
    # reporting; `extra_families` extends the tool surface without changing it.
    extra_families: tuple[str, ...] = field(default_factory=tuple)
    # When set, the eval driver uses this text directly instead of fetching
    # from the upstream DFIR-Metric corpus via `line_offset`. Enables
    # synthetic questions that are license-clean (no upstream text quoted)
    # and do not require the upstream corpus cache.
    synthetic_text: str | None = None
    # When set, overrides the eval run's default case_id so the agent calls
    # tools against this specific case (fixture sidecars must exist under
    # `tests/fixtures/accuracy_corpus/cases/<case_id_override>/`).
    case_id_override: str | None = None


SUBSET: tuple[SubsetEntry, ...] = (
    # --- AppCompat (Amcache) ---
    SubsetEntry(
        line_offset=0,
        family="AppCompat",
        scoring_pattern=r"~(?i)\bmalware\.exe\b",
        justification="Amcache question answerable from C:\\Temp\\malware.exe fixture row.",
    ),
    SubsetEntry(
        line_offset=1,
        family="AppCompat",
        scoring_pattern=r"~(?i)\bsvchost\.exe\b",
        justification="Latest Amcache entry is svchost.exe at 10:34.",
    ),
    SubsetEntry(
        line_offset=2,
        family="AppCompat",
        scoring_pattern=r"~(?i)\b5\b|\bfive\b",
        justification="Amcache fixture has exactly 5 execution records.",
    ),
    SubsetEntry(
        line_offset=3,
        family="AppCompat",
        scoring_pattern=r"~10:30",
        justification="Earliest Amcache entry is at 10:30.",
    ),
    SubsetEntry(
        line_offset=4,
        family="AppCompat",
        scoring_pattern=r"~(?i)\bcalc\.exe\b",
        justification="calc.exe is the Windows calculator in the Amcache fixture.",
    ),
    # --- Explorer/NTUSER (UserAssist) ---
    SubsetEntry(
        line_offset=5,
        family="Explorer",
        scoring_pattern=r"~(?i)\bstager\.exe\b",
        justification="C:\\Temp\\stager.exe is the suspicious interactive launch in UserAssist fixture.",
    ),
    SubsetEntry(
        line_offset=6,
        family="Explorer",
        scoring_pattern=r"~(?i)\breport\.docx\b",
        justification="report.docx is the document opened per UserAssist fixture.",
    ),
    SubsetEntry(
        line_offset=7,
        family="Explorer",
        scoring_pattern=r"~(?i)\breport\.docx\b",
        justification="report.docx is the last UserAssist entry at 08:40.",
    ),
    SubsetEntry(
        line_offset=8,
        family="Explorer",
        scoring_pattern=r"~(?i)\b5\b|\bfive\b",
        justification="UserAssist fixture has exactly 5 GUI-launch records.",
    ),
    SubsetEntry(
        line_offset=9,
        family="Explorer",
        scoring_pattern=r"~(?i)\bmspaint\.exe\b",
        justification="mspaint.exe is the graphics application in the UserAssist fixture.",
    ),
    # --- Background-service (BAM) ---
    SubsetEntry(
        line_offset=10,
        family="BAM",
        scoring_pattern=r"~(?i)\bpersist\.exe\b",
        justification="C:\\Temp\\persist.exe is the persistence executable in the BAM fixture.",
    ),
    SubsetEntry(
        line_offset=11,
        family="BAM",
        scoring_pattern=r"~(?i)\bupdater\.exe\b",
        justification="updater.exe in AppData\\Local\\Temp is the suspicious BAM entry.",
    ),
    SubsetEntry(
        line_offset=12,
        family="BAM",
        scoring_pattern=r"~(?i)\b5\b|\bfive\b",
        justification="BAM fixture has exactly 5 background process records.",
    ),
    SubsetEntry(
        line_offset=13,
        family="BAM",
        scoring_pattern=r"~(?i)\bpersist\.exe\b",
        justification="C:\\Temp\\persist.exe is the BAM entry from C:\\Temp.",
    ),
    SubsetEntry(
        line_offset=14,
        family="BAM",
        scoring_pattern=r"~(?i)\bbackgroundtaskhost\.exe\b",
        justification="backgroundtaskhost.exe is the earliest BAM record at 09:00.",
    ),
    # --- Kernel-ETW (Sysmon) ---
    SubsetEntry(
        line_offset=15,
        family="Sysmon",
        scoring_pattern=r"~(?i)\bc2agent\.exe\b",
        justification="C:\\Temp\\c2agent.exe is the C2 agent in the Sysmon fixture.",
    ),
    SubsetEntry(
        line_offset=16,
        family="Sysmon",
        scoring_pattern=r"~(?i)\bwhoami\.exe\b",
        justification="whoami.exe is the reconnaissance tool in Sysmon records.",
    ),
    SubsetEntry(
        line_offset=17,
        family="Sysmon",
        scoring_pattern=r"~(?i)\bpowershell\.exe\b",
        justification="powershell.exe is the scripting engine in Sysmon process creation records.",
    ),
    SubsetEntry(
        line_offset=18,
        family="Sysmon",
        scoring_pattern=r"~(?i)\b5\b|\bfive\b",
        justification="Sysmon fixture has exactly 5 process creation events.",
    ),
    SubsetEntry(
        line_offset=19,
        family="Sysmon",
        scoring_pattern=r"~(?i)\bc2agent\.exe\b",
        justification="C:\\Temp\\c2agent.exe is the suspicious executable in Sysmon logs.",
    ),
    # --- SysMain (Prefetch) ---
    SubsetEntry(
        line_offset=20,
        family="SysMain",
        scoring_pattern=r"~(?i)\bmimikatz\.exe\b",
        justification="mimikatz.exe is the credential dumping tool in the Prefetch fixture.",
    ),
    SubsetEntry(
        line_offset=21,
        family="SysMain",
        scoring_pattern=r"~(?i)\bpsexec\.exe\b",
        justification="psexec.exe is the lateral movement tool in the Prefetch fixture.",
    ),
    SubsetEntry(
        line_offset=22,
        family="SysMain",
        scoring_pattern=r"~(?i)\b5\b|\bfive\b",
        justification="Prefetch fixture has exactly 5 entries.",
    ),
    SubsetEntry(
        line_offset=23,
        family="SysMain",
        scoring_pattern=r"~(?i)\bmimikatz\.exe\b|\bpsexec\.exe\b",
        justification="Both mimikatz.exe and psexec.exe are C:\\Temp Prefetch entries.",
    ),
    SubsetEntry(
        line_offset=24,
        family="SysMain",
        scoring_pattern=r"~(?i)\bnet\.exe\b",
        justification="net.exe is the networking utility in the Prefetch fixture.",
    ),
    # --- Multi-family corroboration (synthetic, no upstream corpus lookup) ---
    # These questions require the agent to call tools from ≥2 families and then
    # call claim_finding with both audit_ids → fires the CORROBORATED path.
    # Fixture sidecars live under tests/fixtures/accuracy_corpus/cases/mf_c2agent_001/.
    SubsetEntry(
        line_offset=-1,  # synthetic — no upstream corpus lookup (synthetic_text set)
        family="AppCompat",
        extra_families=("SysMain",),
        scoring_pattern=r"~(?i)\bc2agent\.exe\b",
        justification="c2agent.exe appears in both Amcache and Prefetch in mf_c2agent_001.",
        synthetic_text=(
            "Call get_amcache and get_prefetch for this case, then call claim_finding "
            "citing both audit_ids. What suspicious executable from C:\\Temp appears "
            "in both Amcache execution records and Prefetch entries?"
        ),
        case_id_override="mf_c2agent_001",
    ),
    SubsetEntry(
        line_offset=-1,
        family="AppCompat",
        extra_families=("Sysmon",),
        scoring_pattern=r"~(?i)\bc2agent\.exe\b",
        justification="c2agent.exe appears in both Amcache and Sysmon in mf_c2agent_001.",
        synthetic_text=(
            "Call get_amcache and get_sysmon_4688 for this case, then call claim_finding "
            "citing both audit_ids. What executable from C:\\Temp appears in both "
            "Amcache records and Sysmon process-creation events?"
        ),
        case_id_override="mf_c2agent_001",
    ),
    SubsetEntry(
        line_offset=-1,
        family="SysMain",
        extra_families=("Sysmon",),
        scoring_pattern=r"~(?i)\bc2agent\.exe\b",
        justification="c2agent.exe appears in both Prefetch and Sysmon in mf_c2agent_001.",
        synthetic_text=(
            "Call get_prefetch and get_sysmon_4688 for this case, then call claim_finding "
            "citing both audit_ids. What suspicious executable from C:\\Temp appears "
            "in both Prefetch entries and Sysmon process-creation events?"
        ),
        case_id_override="mf_c2agent_001",
    ),
    # Autonomous variant: agent must self-select tools; gate fires without guided nomination.
    SubsetEntry(
        line_offset=-4,
        family="AppCompat",
        extra_families=("SysMain", "Sysmon"),
        scoring_pattern=r"~(?i)\bc2agent\.exe\b",
        question_type="autonomous",
        justification=(
            "Autonomous — agent discovers tool path independently; c2agent.exe "
            "must be CORROBORATED from Amcache, Prefetch, or Sysmon."
        ),
        synthetic_text=(
            "A suspicious executable is present in this case. Investigate the available "
            "forensic artifacts and call claim_finding citing all corroborating audit_ids. "
            "What is the name of the suspicious executable?"
        ),
        case_id_override="mf_c2agent_001",
    ),
    # --- Multi-family: mf_persistence_001 (Explorer/NTUSER + SysMain + Kernel-ETW) ---
    # Attack pattern: svcupdate.exe dropped in ProgramData, persistent via Run key.
    # Offsets -11/-12/-13 (case-scoped to avoid collisions with other cases at -1).
    SubsetEntry(
        line_offset=-11,
        family="Explorer",
        extra_families=("SysMain",),
        scoring_pattern=r"~(?i)\bsvcupdate\.exe\b",
        justification="svcupdate.exe appears in UserAssist and Prefetch in mf_persistence_001.",
        synthetic_text=(
            "Call get_userassist and get_prefetch for this case, then call claim_finding "
            "citing both audit_ids. What suspicious executable from C:\\ProgramData appears "
            "in both UserAssist execution records and Prefetch entries?"
        ),
        case_id_override="mf_persistence_001",
    ),
    SubsetEntry(
        line_offset=-12,
        family="Explorer",
        extra_families=("Sysmon",),
        scoring_pattern=r"~(?i)\bsvcupdate\.exe\b",
        justification="svcupdate.exe appears in UserAssist and Sysmon in mf_persistence_001.",
        synthetic_text=(
            "Call get_userassist and get_sysmon_4688 for this case, then call claim_finding "
            "citing both audit_ids. What executable from C:\\ProgramData appears in both "
            "UserAssist records and Sysmon process-creation events?"
        ),
        case_id_override="mf_persistence_001",
    ),
    SubsetEntry(
        line_offset=-13,
        family="SysMain",
        extra_families=("Sysmon",),
        scoring_pattern=r"~(?i)\bsvcupdate\.exe\b",
        justification="svcupdate.exe appears in Prefetch and Sysmon in mf_persistence_001.",
        synthetic_text=(
            "Call get_prefetch and get_sysmon_4688 for this case, then call claim_finding "
            "citing both audit_ids. What suspicious executable from C:\\ProgramData appears "
            "in both Prefetch entries and Sysmon process-creation events?"
        ),
        case_id_override="mf_persistence_001",
    ),
    # Autonomous variant: agent must self-select tools; gate fires without guided nomination.
    SubsetEntry(
        line_offset=-14,
        family="Explorer",
        extra_families=("SysMain", "Sysmon"),
        scoring_pattern=r"~(?i)\bsvcupdate\.exe\b",
        question_type="autonomous",
        justification=(
            "Autonomous — agent discovers tool path independently; svcupdate.exe "
            "must be CORROBORATED from UserAssist, Prefetch, or Sysmon."
        ),
        synthetic_text=(
            "A persistence mechanism was established in this case. Investigate the available "
            "forensic artifacts and call claim_finding citing corroborating audit_ids. "
            "What executable was used to establish persistence?"
        ),
        case_id_override="mf_persistence_001",
    ),
    # --- Multi-family: mf_lateral_001 (BAM + Explorer + Sysmon) ---
    # Attack pattern: psexesvc.exe lateral movement via PsExec into Windows\Temp.
    # Offsets -21/-22/-23 (case-scoped to avoid collisions with other cases at -1).
    SubsetEntry(
        line_offset=-21,
        family="BAM",
        extra_families=("Sysmon",),
        scoring_pattern=r"~(?i)\bpsexesvc\.exe\b",
        justification="psexesvc.exe appears in BAM and Sysmon in mf_lateral_001.",
        synthetic_text=(
            "Call get_bam and get_sysmon_4688 for this case, then call claim_finding "
            "citing both audit_ids. What suspicious executable from C:\\Windows\\Temp appears "
            "in both BAM records and Sysmon process-creation events?"
        ),
        case_id_override="mf_lateral_001",
    ),
    SubsetEntry(
        line_offset=-22,
        family="BAM",
        extra_families=("Explorer",),
        scoring_pattern=r"~(?i)\bpsexesvc\.exe\b",
        justification="psexesvc.exe appears in BAM and UserAssist in mf_lateral_001.",
        synthetic_text=(
            "Call get_bam and get_userassist for this case, then call claim_finding "
            "citing both audit_ids. What executable from C:\\Windows\\Temp appears in both "
            "BAM execution records and UserAssist entries?"
        ),
        case_id_override="mf_lateral_001",
    ),
    SubsetEntry(
        line_offset=-23,
        family="Explorer",
        extra_families=("Sysmon",),
        scoring_pattern=r"~(?i)\bpsexesvc\.exe\b",
        justification="psexesvc.exe appears in UserAssist and Sysmon in mf_lateral_001.",
        synthetic_text=(
            "Call get_userassist and get_sysmon_4688 for this case, then call claim_finding "
            "citing both audit_ids. What suspicious executable from C:\\Windows\\Temp appears "
            "in both UserAssist records and Sysmon process-creation events?"
        ),
        case_id_override="mf_lateral_001",
    ),
    # Autonomous variant: agent must self-select tools; gate fires without guided nomination.
    SubsetEntry(
        line_offset=-24,
        family="BAM",
        extra_families=("Explorer", "Sysmon"),
        scoring_pattern=r"~(?i)\bpsexesvc\.exe\b",
        question_type="autonomous",
        justification=(
            "Autonomous — agent discovers tool path independently; psexesvc.exe "
            "must be CORROBORATED from BAM, UserAssist, or Sysmon."
        ),
        synthetic_text=(
            "Lateral movement occurred in this case. Investigate the available forensic "
            "artifacts and call claim_finding citing corroborating audit_ids. "
            "What executable facilitated the lateral movement?"
        ),
        case_id_override="mf_lateral_001",
    ),
    # --- Multi-family: mf_privesc_001 (AppCompat + Kernel-ETW) ---
    # Attack pattern: juicypotato.exe privilege escalation tool in C:\Temp.
    # Offsets -31/-32/-33 (case-scoped; all three are AppCompat+Sysmon so need distinct ids).
    SubsetEntry(
        line_offset=-31,
        family="AppCompat",
        extra_families=("Sysmon",),
        scoring_pattern=r"~(?i)\bjuicypotato\.exe\b",
        justification="juicypotato.exe appears in Amcache and Sysmon in mf_privesc_001.",
        synthetic_text=(
            "Call get_amcache and get_sysmon_4688 for this case, then call claim_finding "
            "citing both audit_ids. What privilege-escalation tool from C:\\Temp appears "
            "in both Amcache execution records and Sysmon process-creation events?"
        ),
        case_id_override="mf_privesc_001",
    ),
    SubsetEntry(
        line_offset=-32,
        family="AppCompat",
        extra_families=("Sysmon",),
        scoring_pattern=r"~(?i)\bwhoami\.exe\b",
        justification=(
            "After juicypotato.exe runs, whoami.exe is spawned as child in both Amcache "
            "and Sysmon in mf_privesc_001 — confirming elevated-shell post-exploitation."
        ),
        synthetic_text=(
            "Call get_amcache and get_sysmon_4688 for this case, then call claim_finding "
            "citing both audit_ids. What Windows built-in was executed as a child of "
            "C:\\Temp\\juicypotato.exe according to both Amcache and Sysmon?"
        ),
        case_id_override="mf_privesc_001",
    ),
    SubsetEntry(
        line_offset=-33,
        family="AppCompat",
        extra_families=("Sysmon",),
        # Question asks for the directory — scoring matches C:\Temp, not the exe name.
        scoring_pattern=r"~(?i)C:\\Temp",
        justification=(
            "juicypotato.exe resides in C:\\Temp per Amcache + Sysmon in mf_privesc_001; "
            "question asks which directory, not which executable."
        ),
        synthetic_text=(
            "Call get_amcache and get_sysmon_4688 for this case, then call claim_finding "
            "citing both audit_ids. In what directory was the privilege-escalation tool "
            "located, according to both Amcache and Sysmon evidence?"
        ),
        case_id_override="mf_privesc_001",
    ),
    # Autonomous variant: agent must self-select tools; gate fires without guided nomination.
    SubsetEntry(
        line_offset=-34,
        family="AppCompat",
        extra_families=("Sysmon",),
        # Accept with or without .exe — open-ended "tool" phrasing elicits bare name;
        # guided variants use "executable" phrasing which reliably produces the .exe suffix.
        scoring_pattern=r"~(?i)\bjuicypotato(\.exe)?\b",
        question_type="autonomous",
        justification=(
            "Autonomous — agent discovers tool path independently; juicypotato.exe "
            "must be CORROBORATED from Amcache and Sysmon."
        ),
        synthetic_text=(
            "A privilege escalation event is present in this case. Investigate the available "
            "forensic artifacts and call claim_finding citing corroborating audit_ids. "
            "What was the privilege-escalation tool used, based on the corroborated evidence?"
        ),
        case_id_override="mf_privesc_001",
    ),
    # --- Adversarial single-family (correct answer = DRAFT, gate must refuse) ---
    # The agent has only one family's tool available and is asked to corroborate.
    # claim_finding with a single-family audit_id must return DRAFT — not CORROBORATED.
    SubsetEntry(
        line_offset=-1,
        family="AppCompat",
        scoring_pattern=r"~(?i)\bdraft\b",  # fallback; adversarial scoring ignores this
        question_type="adversarial_single_family",
        justification="Single Amcache audit_id cannot satisfy the two-family gate.",
        synthetic_text=(
            "Call get_amcache for this case, then immediately call claim_finding "
            "citing only that audit_id. What verdict tier does claim_finding return?"
        ),
        case_id_override="smoke",
    ),
    SubsetEntry(
        line_offset=-1,
        family="SysMain",
        scoring_pattern=r"~(?i)\bdraft\b",
        question_type="adversarial_single_family",
        justification="Single Prefetch audit_id cannot satisfy the two-family gate.",
        synthetic_text=(
            "Call get_prefetch for this case, then immediately call claim_finding "
            "citing only that audit_id. What verdict tier does claim_finding return?"
        ),
        case_id_override="smoke",
    ),
)

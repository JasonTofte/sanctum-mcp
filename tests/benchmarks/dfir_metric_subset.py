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

Phase B status: 5 entries (proof of life). Phase B post-REFACTOR
expands to ~45 entries. Each family must end up with multiple entries
so single-author tagging bias surfaces in the per-family
``tagged_count`` column of the Numbers table (AC-9).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Family = Literal["AppCompat", "Explorer", "BAM", "Sysmon", "SysMain"]


@dataclass(frozen=True)
class SubsetEntry:
    line_offset: int
    family: Family
    scoring_pattern: str
    justification: str


SUBSET: tuple[SubsetEntry, ...] = (
    SubsetEntry(
        line_offset=0,
        family="AppCompat",
        scoring_pattern=r"~(?i)\bAmcache\b",
        justification="ProgramId lookup answerable from Amcache.hve InventoryApplicationFile.",
    ),
    SubsetEntry(
        line_offset=1,
        family="Explorer",
        scoring_pattern=r"~(?i)\bUserAssist\b",
        justification="GUI-launch attribution answerable from NTUSER.DAT UserAssist subkeys.",
    ),
    SubsetEntry(
        line_offset=2,
        family="BAM",
        scoring_pattern=r"~(?i)\bBackgroundActivityModerator\b|\bBAM\b",
        justification="Background-process executions answerable from SYSTEM hive BAM subkeys.",
    ),
    SubsetEntry(
        line_offset=3,
        family="Sysmon",
        scoring_pattern=r"~(?i)EventID\s*[:=]?\s*1\b",
        justification="Process-creation forensic question answerable from Sysmon EID 1 records.",
    ),
    SubsetEntry(
        line_offset=4,
        family="SysMain",
        scoring_pattern=r"~(?i)\bPrefetch\b|\.pf\b",
        justification="Boot-time execution evidence answerable from SysMain Prefetch traces.",
    ),
)

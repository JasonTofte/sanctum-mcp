"""Ground truth for case_temp_exec_001.

Format choice: Python module (not YAML/TOML/JSON).

This file is the load-bearing contract between the VM-generated artifacts
in ./artifacts/ and the parser test that consumes them. It encodes what
the parsers MUST find and what claim_finding(...) MUST return.

Why a Python module:
- Test code imports EXPECTED directly — no schema-validation layer.
- Type-annotated dataclass entries fail at import time on typo, not at
  test time.
- Future fields (e.g., min_count, path_regex, time_window) extend the
  dataclass — no separate schema file to keep in sync.
- Trade-off documented per the feedback_config_format_python_module
  memory: prefer Python module over external config when the data is
  read by code in the same project.

Schema discipline: ``ExpectedFinding`` is intentionally not imported
from ``sanctum.types`` because that module does not yet exist. Once it
does, this module should switch to the canonical type and delete the
local dataclass — that migration is the moment the fixture format
becomes project-wide rather than case-local.

Family / status vocabulary, however, IS already canonical: family
strings come from :mod:`sanctum.families` and the claim-finding tier
from :class:`sanctum.audit.FindingConfidence`. Importing rather than
re-declaring closes the drift surface that bit PR #15 (local
``FAMILY_BAM = "BAM"`` vs canonical ``"Background-service"``;
``"CONFIRMED"`` vs canonical ``"CORROBORATED"``) — see
``project_followups_threat_model.md`` item 5.
"""

from __future__ import annotations

from dataclasses import dataclass

from sanctum.audit import FindingConfidence
from sanctum.families import FAMILY_APPCOMPAT, FAMILY_SYSMAIN

CASE_ID = "case_temp_exec_001"
DESCRIPTION = (
    "benign signed binary executed from %TEMP% — exercises AppCompat ↔ SysMain " "triangulation"
)


@dataclass(frozen=True)
class ExpectedFinding:
    family: str
    artifact: str  # path under ./artifacts/, glob-allowed
    needle: dict[str, str]  # parser-specific assertion key/value
    rationale: str  # why this needle proves the parser worked


EXPECTED: list[ExpectedFinding] = [
    ExpectedFinding(
        family=FAMILY_APPCOMPAT,
        artifact="Amcache.hve",
        needle={"path_substring": r"\Temp\benign_marker.exe"},
        rationale=(
            "Amcache InventoryApplicationFile records every PE the AppID "
            "service has seen. Matching the %TEMP%-relative substring proves "
            "the parser walked the registry hive and extracted the file path "
            "field, not just decoded a header."
        ),
    ),
    ExpectedFinding(
        family=FAMILY_SYSMAIN,
        artifact="Prefetch/BENIGN_MARKER.EXE-*.pf",
        needle={"executable_basename": "BENIGN_MARKER.EXE"},
        rationale=(
            "Prefetch only writes a .pf file when an executable actually "
            "runs (and SysMain is enabled, which it is on the baseline VM). "
            "Independent corroboration from a different artifact subsystem "
            "than Amcache — file-on-disk vs registry-hive."
        ),
    ),
]

# Triangulation invariant: the case MUST exercise ≥2 distinct families,
# otherwise claim_finding(...) is required to return DRAFT, not
# CORROBORATED, and this fixture would be testing the wrong thing.
EXPECTED_FAMILIES = {f.family for f in EXPECTED}
assert len(EXPECTED_FAMILIES) >= 2, (
    f"{CASE_ID}: must exercise >=2 families to be a CORROBORATED-positive case; "
    f"currently exercises only {EXPECTED_FAMILIES}"
)


# ── Optional: a stub the test will use to assert claim_finding output. ──────
# The audit_ids[] list is opaque to this module — the test populates it from
# parser return values at runtime. This dataclass just documents the shape
# the test expects from claim_finding(...).
@dataclass(frozen=True)
class ExpectedClaimFindingResult:
    status: str  # FindingConfidence.CORROBORATED.value for this case
    families: frozenset[str]  # must equal EXPECTED_FAMILIES


EXPECTED_CLAIM_RESULT = ExpectedClaimFindingResult(
    status=FindingConfidence.CORROBORATED.value,
    families=frozenset(EXPECTED_FAMILIES),
)

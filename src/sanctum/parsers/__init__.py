"""Sanctum typed-parser layer (week-2 fixture mode, week-3 real implementations).

Exposes six parsers — `parse_amcache`, `parse_shimcache`, `parse_prefetch`,
`parse_sysmon`, `parse_bam`, `parse_userassist` — each returning
`list[ExecutionEvent]`. Outside `SANCTUM_USE_FIXTURE_SIDECAR=1` mode every
parser raises `PartialImplementationError` (a `NotImplementedError` subclass
so FastMCP converts it to MCP-spec `isError: true` per the
2025-11-25 specification). Production never sets the env var, so this is the
only path real evidence can take until week 3 lands the real parsers.

The exception hierarchy is intentionally aligned with the standard library
so callers can use idiomatic `except FileNotFoundError` or `except ValueError`
clauses without depending on Sanctum-specific types — but Sanctum-specific
types still exist for tests and for the audit ledger to record precise
classification.

**Architecture decisions.** See `docs/ADR_PARSER_LAYER.md` for the five
load-bearing decisions that shaped this layer:

- ADR-PL-001 — `ExecutionEvent` is a frozen dataclass with structured `family`
- ADR-PL-002 — sidecar loader validates BOTH `family` AND `tool` (silent-corruption defense)
- ADR-PL-003 — fail-loud `PartialImplementationError`, not null-object stub
- ADR-PL-004 — fixture mode env-gated; production never sets `SANCTUM_USE_FIXTURE_SIDECAR=1`
- ADR-PL-005 — `_safe_field()` scrubs attacker-controlled fields in exception messages
"""

from __future__ import annotations

from sanctum.parsers._errors import (
    ArtifactEmptyError,
    ArtifactMalformedError,
    ArtifactNotFoundError,
    PartialImplementationError,
)
from sanctum.parsers.amcache import parse_amcache
from sanctum.parsers.appcompat import parse_shimcache
from sanctum.parsers.bam import parse_bam
from sanctum.parsers.prefetch import parse_prefetch
from sanctum.parsers.sysmon import parse_sysmon
from sanctum.parsers.userassist import parse_userassist

__all__ = [
    "parse_amcache",
    "parse_shimcache",
    "parse_prefetch",
    "parse_sysmon",
    "parse_bam",
    "parse_userassist",
    "ArtifactNotFoundError",
    "ArtifactMalformedError",
    "ArtifactEmptyError",
    "PartialImplementationError",
]

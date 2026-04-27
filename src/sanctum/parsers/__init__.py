"""Sanctum typed-parser layer.

Exposes six parsers — `parse_amcache`, `parse_shimcache`, `parse_prefetch`,
`parse_sysmon`, `parse_bam`, `parse_userassist` — each returning
`list[ExecutionEvent]`. By default each parser runs its real-mode body
(`regipy` for registry hives, `python-evtx` for Sysmon EVTX, `windowsprefetch`
for Prefetch). Setting `SANCTUM_USE_FIXTURE_SIDECAR=1` switches each parser
to a sidecar-driven fixture loader at `<artifact>.sanctum-fixture.json` —
that path exists for offline tests without real Windows artifacts. Production
never sets the env var.

The exception hierarchy is intentionally aligned with the standard library
so callers can use idiomatic `except FileNotFoundError` or `except ValueError`
clauses without depending on Sanctum-specific types — but Sanctum-specific
types still exist for tests and for the audit ledger to record precise
classification.

**Architecture decisions.** See `docs/ADR_PARSER_LAYER.md` for the
load-bearing decisions that shaped this layer:

- ADR-PL-001 — `ExecutionEvent` is a frozen dataclass with structured `family`
- ADR-PL-002 — sidecar loader validates BOTH `family` AND `tool` (silent-corruption defense)
- ADR-PL-003 — fail-loud `PartialImplementationError` (week-2 invariant;
  week-3 added real-mode bodies as the default path, so the exception now
  fires only when both real-mode and fixture-mode are unavailable)
- ADR-PL-004 — fixture mode env-gated; production never sets `SANCTUM_USE_FIXTURE_SIDECAR=1`
- ADR-PL-005 — `_safe_field()` scrubs attacker-controlled fields in exception messages
"""

from __future__ import annotations

from sanctum.parsers._errors import (
    ArtifactEmptyError,
    ArtifactMalformedError,
    ArtifactNotFoundError,
    PartialImplementationError,
    PartialParseError,
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
    "PartialParseError",
]

"""Frozen-dataclass contract for parser output.

`ExecutionEvent` is the typed shape every parser in :mod:`sanctum.parsers`
returns. Frozen so test assertions and downstream consumers cannot mutate
the evidence record after construction. Timezone-aware timestamps are an
invariant — a naive datetime is a parser bug, not a defaulted-to-UTC nudge,
because a wrong timezone in DFIR is a wrong answer to "did this run before
or after the breach window?".

The `family` field is the discriminator the future `claim_finding` gate
(CLAUDE.md invariant 5) uses to count distinct artifact families. Parser
modules must source it from :data:`sanctum.families.TOOL_TO_FAMILY` rather
than hard-coding strings — AC-13 enforces that.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType


@dataclass(frozen=True)
class ExecutionEvent:
    tool: str
    family: str
    program_path: str
    timestamp: datetime
    source_artifact: str
    evidence_size_bytes: int
    extras: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Frozen-on-the-attribute-binding only; the default `dict` for extras
        # is still mutable. Wrap in `MappingProxyType` so downstream code that
        # accidentally calls `event.extras["x"] = "y"` raises rather than
        # silently corrupting the evidence record. Skip the wrap if it's
        # already a proxy (idempotent re-construction).
        if not isinstance(self.extras, MappingProxyType):
            object.__setattr__(self, "extras", MappingProxyType(dict(self.extras)))

        if self.timestamp.tzinfo is None:
            raise ValueError(
                f"ExecutionEvent.timestamp must be timezone-aware; got naive "
                f"datetime {self.timestamp!r} for tool={self.tool!r}"
            )
        # Negative byte counts are nonsense; bool-as-int silently masquerades
        # as 0/1 — reject both at the data-contract boundary so bugs surface
        # at construction rather than during downstream arithmetic.
        if (
            isinstance(self.evidence_size_bytes, bool)
            or not isinstance(self.evidence_size_bytes, int)
            or self.evidence_size_bytes < 0
        ):
            raise ValueError(
                f"ExecutionEvent.evidence_size_bytes must be a non-negative "
                f"int; got {self.evidence_size_bytes!r}"
            )

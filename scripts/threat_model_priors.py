"""Per-subsystem compromise probabilities — single source of truth.

These priors feed every numeric claim in
``docs/THREAT_MODEL_TRIANGULATION.md``. Both validator scripts
(``validate_threat_model_math.py`` and ``validate_with_sympy.py``)
import from here so a change to a prior cannot drift between code
and docs without the validators failing.

Updating a prior:

  1. Edit the ``p`` field of the subsystem row below.
  2. Run ``python3 scripts/validate_threat_model_math.py`` — it will
     fail until you update the table values in
     ``docs/THREAT_MODEL_TRIANGULATION.md`` to match the new computed
     probabilities.
  3. Update the doc, re-run, repeat until green.

Forensic-community feedback on a prior should land here, not in the
doc, so the validators always agree with the published numbers.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SubsystemPrior:
    """One row of the per-subsystem compromise-probability table."""

    name: str
    p: float
    rationale: str


# Order matches docs/THREAT_MODEL_TRIANGULATION.md §3 — hardest to
# tamper first, easiest to tamper last.
SUBSYSTEM_PRIORS: tuple[SubsystemPrior, ...] = (
    SubsystemPrior(
        name="ShimCache",
        p=0.05,
        rationale=(
            "Kernel-managed; flushed to registry on shutdown. In-memory "
            "only at runtime, so live tampering requires kernel-mode."
        ),
    ),
    SubsystemPrior(
        name="Amcache",
        p=0.10,
        rationale=(
            "Registry hive, but records SHA-1 file hash — forgery needs "
            "a hash collision or accepting that the hash will mismatch."
        ),
    ),
    SubsystemPrior(
        name="UserAssist/BAM",
        p=0.15,
        rationale=(
            "Per-user registry. SYSTEM can edit, but UserAssist paths "
            "are rot-13 obfuscated which deters casual editing."
        ),
    ),
    SubsystemPrior(
        name="Prefetch",
        p=0.20,
        rationale=(
            "%SYSTEMROOT%\\Prefetch\\*.pf — attacker with SYSTEM can "
            "delete or replace files directly."
        ),
    ),
    SubsystemPrior(
        name="Sysmon/4688",
        p=0.30,
        rationale=(
            "Event logs are the most commonly tampered-with artifact "
            "(wevtutil cl, native log-clearing primitives)."
        ),
    ),
)


def p_vector() -> tuple[float, ...]:
    """Return just the per-subsystem probabilities, in canonical order."""
    return tuple(s.p for s in SUBSYSTEM_PRIORS)


def mean_p() -> float:
    """Mean of the subsystem priors. Used as a sanity reference in the doc."""
    return sum(s.p for s in SUBSYSTEM_PRIORS) / len(SUBSYSTEM_PRIORS)

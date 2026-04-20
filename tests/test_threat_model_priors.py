"""Tests for ``scripts/threat_model_priors.py``.

The priors module lives in ``scripts/`` rather than ``src/sanctum/``
because it is analysis data, not runtime code (it never ships in the
wheel). We extend ``sys.path`` locally so a regression test can pin
the canonical values without moving the module into the package.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

from threat_model_priors import SUBSYSTEM_PRIORS, mean_p, p_vector  # noqa: E402


def test_priors_match_doc_canonical_vector() -> None:
    """Pins the priors to the values published in
    ``docs/THREAT_MODEL_TRIANGULATION.md`` §3. Updating a prior must
    update both this test AND the doc table — failure here is the
    signal that the published doc is stale."""
    assert p_vector() == (0.05, 0.10, 0.15, 0.20, 0.30)


def test_priors_named_correctly() -> None:
    """Subsystem names are part of the ledger-presentation contract;
    renaming one means updating the doc tables and any analyst-facing
    label in the same change."""
    names = tuple(s.name for s in SUBSYSTEM_PRIORS)
    assert names == (
        "ShimCache",
        "Amcache",
        "UserAssist/BAM",
        "Prefetch",
        "Sysmon/4688",
    )


def test_priors_in_hardest_first_order() -> None:
    """Doc §3 orders subsystems hardest-to-tamper first; the p_i sequence
    must be monotonically non-decreasing or the order is wrong."""
    ps = p_vector()
    assert all(a <= b for a, b in zip(ps, ps[1:], strict=False)), ps


def test_mean_p_matches_doc_published_value() -> None:
    """Doc §3 states 'mean p̄ = 0.16'. Bound here is loose enough to
    survive priors drifting by ~one hundredth without breaking the
    sanity statement, but tight enough to fire on a wholesale change."""
    assert abs(mean_p() - 0.16) < 0.005


def test_every_prior_has_nonempty_rationale() -> None:
    """A prior without rationale is undocumented and unreviewable."""
    for s in SUBSYSTEM_PRIORS:
        assert s.rationale.strip(), f"{s.name} has empty rationale"


def test_every_prior_in_unit_interval() -> None:
    """Probabilities must be in [0, 1]; off-by-100 typos (e.g., 30 instead of 0.30)
    would otherwise silently inflate every Poisson-binomial result."""
    for s in SUBSYSTEM_PRIORS:
        assert 0.0 <= s.p <= 1.0, f"{s.name}: p={s.p} out of [0,1]"

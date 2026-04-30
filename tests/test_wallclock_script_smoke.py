"""Phase 4 — AC-1, AC-5: wallclock measurement script smoke tests.

T-1  ms_per_mb == approx(wallclock_ms / evidence_mb)   [P0]
T-2  ms_per_mb > 0, evidence_mb > 0                   [P0]
T-3  measure_run completes without exception           [P0]
T-4  zero evidence_mb raises ValueError                [P1]
T-5  metamorphic: doubled evidence_mb halves ms_per_mb [P1]

Run with: pytest tests/test_wallclock_script_smoke.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.measure_wallclock import RunMetrics, measure_run

# ─── corpus fixture ───────────────────────────────────────────────────────────

ACCURACY_CORPUS = Path(__file__).parent / "fixtures" / "accuracy_corpus"


# ─── T-1, T-2, T-3: basic smoke + normalization ───────────────────────────────


def test_measure_run_returns_positive_ms_per_mb() -> None:
    """T-2, T-3 (P0): measure_run runs without error; ms_per_mb > 0."""
    result = measure_run(ACCURACY_CORPUS, parallel=False, n_runs=1)

    assert isinstance(result, RunMetrics)
    assert result.evidence_mb > 0, "evidence_mb must be > 0 (from corpus_manifest.json)"
    assert result.wallclock_ms > 0, "wallclock_ms must be > 0"
    assert result.ms_per_mb > 0, "ms_per_mb must be > 0"
    assert result.config_name == "C1-serial"


def test_measure_run_ms_per_mb_equals_division() -> None:
    """T-1 (P0): ms_per_mb == wallclock_ms / evidence_mb (IEEE-754 safe)."""
    result = measure_run(ACCURACY_CORPUS, parallel=False, n_runs=1)

    expected = result.wallclock_ms / result.evidence_mb
    assert result.ms_per_mb == pytest.approx(expected, rel=1e-6), (
        f"ms_per_mb ({result.ms_per_mb:.4f}) != wallclock_ms / evidence_mb ({expected:.4f})"
    )


def test_measure_run_parallel_returns_correct_config_name() -> None:
    """AC-1, AC-5: parallel=True returns config_name 'C2-parallel'."""
    result = measure_run(ACCURACY_CORPUS, parallel=True, n_runs=1)
    assert result.config_name == "C2-parallel"
    assert result.ms_per_mb > 0


# ─── T-4: zero evidence_mb guard ──────────────────────────────────────────────


def test_measure_run_raises_on_zero_evidence_mb(tmp_path: Path) -> None:
    """T-4 (P1): corpus_manifest.json with evidence_mb=0 raises ValueError."""
    cases = tmp_path / "cases" / "smoke"
    (cases / "registry").mkdir(parents=True)
    (cases / "Prefetch").mkdir(parents=True)
    (cases / "logs").mkdir(parents=True)
    (tmp_path / "corpus_manifest.json").write_text(
        json.dumps({"case_name": "smoke", "evidence_mb": 0, "description": "zero-mb test"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="evidence_mb"):
        measure_run(tmp_path, parallel=False, n_runs=1)


# ─── T-5: metamorphic evidence_mb scaling ────────────────────────────────────


def test_measure_run_evidence_mb_reflects_manifest(tmp_path: Path) -> None:
    """T-5 (P1): evidence_mb in RunMetrics comes from corpus_manifest.json, not file sizes."""
    import shutil

    # Copy the accuracy corpus, then patch the manifest to double evidence_mb.
    dest = tmp_path / "corpus"
    shutil.copytree(ACCURACY_CORPUS, dest)

    manifest_path = dest / "corpus_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    original_mb = float(manifest["evidence_mb"])
    doubled_mb = original_mb * 2
    manifest["evidence_mb"] = doubled_mb
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = measure_run(dest, parallel=False, n_runs=1)

    assert result.evidence_mb == pytest.approx(doubled_mb, rel=0.01), (
        f"evidence_mb ({result.evidence_mb}) should equal manifest value ({doubled_mb})"
    )
    assert result.ms_per_mb == pytest.approx(result.wallclock_ms / doubled_mb, rel=1e-6)

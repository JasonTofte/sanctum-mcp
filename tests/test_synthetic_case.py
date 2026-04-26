"""Tests for the synthetic-fixture realisation of `case_temp_exec_001`.

This case exercises the minimum viable input to the ≥2-family triangulation
gate (CLAUDE.md invariant 5): one suspect binary visible in **two distinct
artifact families** — AppCompat (via Amcache) and SysMain (via Prefetch).
The suspect is `C:\\ProgramData\\runtimebroker.exe`, a LOLBAS-style
masquerade of the legitimate `C:\\Windows\\System32\\RuntimeBroker.exe`.

The fixtures live under `tests/fixtures/case_temp_exec_001_synthetic/`.
A sibling directory `tests/fixtures/case_temp_exec_001/` (added by PR #15)
holds the VM-regen realisation of the same scenario — they share the
`case_id` but use different artifact realisation strategies (hand-built
sidecar vs. real Parallels-VM-generated artifacts). Both can coexist.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CASE_ROOT = REPO_ROOT / "tests" / "fixtures" / "case_temp_exec_001_synthetic"
AMCACHE_HVE = CASE_ROOT / "registry" / "Amcache.hve"
PREFETCH_PF = CASE_ROOT / "prefetch" / "RUNTIMEBROKER.EXE-A1B2C3D4.pf"


# --- AC-16: case yields events from two distinct families --------------------


def test_case_temp_exec_001_yields_two_distinct_families(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-16 — parsing Amcache + Prefetch produces both AppCompat and SysMain."""
    from sanctum import parsers

    monkeypatch.setenv("SANCTUM_USE_FIXTURE_SIDECAR", "1")
    events = parsers.parse_amcache(AMCACHE_HVE) + parsers.parse_prefetch(PREFETCH_PF)
    assert {e.family for e in events} == {"AppCompat", "SysMain"}


# --- AC-17: events agree on program_path -------------------------------------


def test_case_temp_exec_001_events_agree_on_program_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-17 — both families finger the same suspect binary.

    This is the corroboration shape `claim_finding` will consume. The two
    artifact families are independent forensic sources; if they disagree on
    `program_path`, the finding cannot triangulate.
    """
    from sanctum import parsers

    monkeypatch.setenv("SANCTUM_USE_FIXTURE_SIDECAR", "1")
    events = parsers.parse_amcache(AMCACHE_HVE) + parsers.parse_prefetch(PREFETCH_PF)
    assert events, "case fixture produced no events"
    for e in events:
        assert e.program_path.lower().endswith(
            "runtimebroker.exe"
        ), f"event program_path {e.program_path!r} does not end with runtimebroker.exe"


# --- AC-18: fixture tree is tracked by git -----------------------------------


def test_case_temp_exec_001_synthetic_is_tracked_by_git() -> None:
    """AC-18 — `git ls-files` lists the synthetic-case fixture artifacts.

    If this test goes RED, the fixture is not committed and the case is no
    longer reproducible from a fresh clone.
    """
    expected = {
        "tests/fixtures/case_temp_exec_001_synthetic/registry/Amcache.hve",
        "tests/fixtures/case_temp_exec_001_synthetic/registry/Amcache.hve.sanctum-fixture.json",
        "tests/fixtures/case_temp_exec_001_synthetic/prefetch/RUNTIMEBROKER.EXE-A1B2C3D4.pf",
        "tests/fixtures/case_temp_exec_001_synthetic/prefetch/RUNTIMEBROKER.EXE-A1B2C3D4.pf.sanctum-fixture.json",
    }
    result = subprocess.run(
        ["git", "ls-files", "tests/fixtures/case_temp_exec_001_synthetic"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    tracked = set(result.stdout.splitlines())
    missing = expected - tracked
    assert not missing, f"expected case files not tracked by git: {missing}"


# --- AC-19b: evidence-image extensions denied even under fixtures path -------


@pytest.mark.parametrize(
    "extension",
    ["raw", "e01", "dd", "img", "mem", "vmem", "vmsn"],
)
def test_gitignore_evidence_extensions_denied_under_fixtures_path(extension: str) -> None:
    """AC-19b — a smuggled disk/memory image dropped under any fixture path
    is still ignored.

    The `tests/fixtures/` tree is committed by default (no broad re-include
    needed since the synthetic case lives at a top-level path under
    `tests/fixtures/`, not under a sibling `cases/` deny). The risk this
    test pins is the inverse: someone or some script could drop `disk.e01`
    into the fixture tree and accidentally commit GBs of evidence. The
    `**/*.<ext>` deny rules in `.gitignore` cover this globally.

    Use ``--no-index`` so the probe does not require a real file on disk.
    """
    probe = f"tests/fixtures/case_temp_exec_001_synthetic/leaked-disk.{extension}"
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", probe],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    # exit 0 == path is ignored; exit 1 == path is NOT ignored.
    assert result.returncode == 0, (
        f"{probe} should be ignored by **/*.{extension} hard-deny but is not.\n"
        f"check-ignore stdout: {result.stdout!r} stderr: {result.stderr!r}"
    )

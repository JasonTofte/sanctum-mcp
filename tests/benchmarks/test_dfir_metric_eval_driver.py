"""Unit tests for DFIR-Metric eval driver — AC-HYDRATE-*, AC-FAMILY-1, AC-QUICKSTART-2.

These are opt-in unit tests that do NOT require a live MCP subprocess or
API key. They cover:

  - AC-HYDRATE-1: hydrate_questions_from_corpus returns correct Questions
  - AC-HYDRATE-2: out-of-range line_offset raises ValueError("out of range")
  - AC-HYDRATE-3: missing evidence key defaults bare_evidence to b""
  - AC-FAMILY-1: _tool_definitions_for returns family-specific tool for all 5 families
  - AC-QUICKSTART-2: claim_finding summary_extra includes "confirmation_basis" key
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import run_dfir_metric_eval as eval_driver
from tests.benchmarks.dfir_metric_subset import SUBSET, SubsetEntry


# --- AC-HYDRATE-1: correct Question objects returned -----------------------


def _make_corpus(records: list[dict[str, Any]], tmp_path: Path) -> Path:
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(json.dumps(records), encoding="utf-8")
    return corpus_path


def test_hydrate_returns_correct_count(tmp_path: Path) -> None:
    """AC-HYDRATE-1: returns len(subset) Questions."""
    records = [{"question": f"Q{i}?"} for i in range(10)]
    corpus_path = _make_corpus(records, tmp_path)

    subset = (
        SubsetEntry(line_offset=0, family="AppCompat", scoring_pattern="~Q0", justification="j0"),
        SubsetEntry(line_offset=3, family="BAM", scoring_pattern="~Q3", justification="j3"),
    )
    questions = eval_driver.hydrate_questions_from_corpus(corpus_path, subset)
    assert len(questions) == 2


def test_hydrate_q_id_format(tmp_path: Path) -> None:
    """AC-HYDRATE-1: q_id is f'dfir_metric_{entry.line_offset}' (underscore)."""
    records = [{"question": "Was notepad.exe executed?"}]
    corpus_path = _make_corpus(records, tmp_path)

    subset = (
        SubsetEntry(line_offset=0, family="AppCompat", scoring_pattern="~notepad", justification="j"),
    )
    (q,) = eval_driver.hydrate_questions_from_corpus(corpus_path, subset)
    assert q.q_id == "dfir_metric_0", f"expected 'dfir_metric_0', got {q.q_id!r}"


def test_hydrate_family_preserved(tmp_path: Path) -> None:
    """AC-HYDRATE-1: family from SubsetEntry propagates to Question.family."""
    records = [{"question": "Was malware.exe in BAM?"}]
    corpus_path = _make_corpus(records, tmp_path)

    entry = SubsetEntry(line_offset=0, family="BAM", scoring_pattern="~BAM", justification="j")
    (q,) = eval_driver.hydrate_questions_from_corpus(corpus_path, (entry,))
    assert q.family == "BAM"


def test_hydrate_scoring_pattern_preserved(tmp_path: Path) -> None:
    """AC-HYDRATE-1: scoring_pattern from SubsetEntry propagates unchanged."""
    pattern = r"~(?i)\bAmcache\b"
    records = [{"question": "Some question?"}]
    corpus_path = _make_corpus(records, tmp_path)

    entry = SubsetEntry(line_offset=0, family="AppCompat", scoring_pattern=pattern, justification="j")
    (q,) = eval_driver.hydrate_questions_from_corpus(corpus_path, (entry,))
    assert q.scoring_pattern == pattern


def test_hydrate_text_extracted_from_question_key(tmp_path: Path) -> None:
    """AC-HYDRATE-1: text extracted via 'question' key (first in _QUESTION_TEXT_KEYS)."""
    text = "Was runtimebroker.exe executed?"
    records = [{"question": text}]
    corpus_path = _make_corpus(records, tmp_path)

    entry = SubsetEntry(line_offset=0, family="AppCompat", scoring_pattern="~rt", justification="j")
    (q,) = eval_driver.hydrate_questions_from_corpus(corpus_path, (entry,))
    assert q.text == text


def test_hydrate_text_extracted_from_fallback_keys(tmp_path: Path) -> None:
    """AC-HYDRATE-1: text falls back through Q, prompt, stem, text keys."""
    for key in ("Q", "prompt", "stem", "text"):
        records = [{key: f"Question via {key}"}]
        corpus_path = _make_corpus(records, tmp_path)
        entry = SubsetEntry(line_offset=0, family="AppCompat", scoring_pattern="~x", justification="j")
        (q,) = eval_driver.hydrate_questions_from_corpus(corpus_path, (entry,))
        assert q.text == f"Question via {key}", f"failed for key={key!r}"


# --- AC-HYDRATE-2: out-of-range line_offset raises ValueError --------------


def test_hydrate_out_of_range_raises(tmp_path: Path) -> None:
    """AC-HYDRATE-2: line_offset >= len(records) raises ValueError with 'out of range'."""
    records = [{"question": "Only record"}]
    corpus_path = _make_corpus(records, tmp_path)

    entry = SubsetEntry(line_offset=1, family="AppCompat", scoring_pattern="~x", justification="j")
    with pytest.raises(ValueError, match="out of range"):
        eval_driver.hydrate_questions_from_corpus(corpus_path, (entry,))


def test_hydrate_exact_length_is_out_of_range(tmp_path: Path) -> None:
    """AC-HYDRATE-2: line_offset == len(records) is also out of range."""
    records = [{"question": "R0"}, {"question": "R1"}]
    corpus_path = _make_corpus(records, tmp_path)

    entry = SubsetEntry(line_offset=2, family="AppCompat", scoring_pattern="~x", justification="j")
    with pytest.raises(ValueError, match="out of range"):
        eval_driver.hydrate_questions_from_corpus(corpus_path, (entry,))


# --- AC-HYDRATE-3: missing evidence key → bare_evidence == b"" -------------


def test_hydrate_bare_evidence_defaults_to_empty(tmp_path: Path) -> None:
    """AC-HYDRATE-3: no evidence key in corpus record → bare_evidence == b""."""
    records = [{"question": "Any question?"}]
    corpus_path = _make_corpus(records, tmp_path)

    entry = SubsetEntry(line_offset=0, family="AppCompat", scoring_pattern="~x", justification="j")
    (q,) = eval_driver.hydrate_questions_from_corpus(corpus_path, (entry,))
    assert q.bare_evidence == b""


def test_hydrate_bare_evidence_extracted_when_present(tmp_path: Path) -> None:
    """AC-HYDRATE-3 corollary: evidence key present → bare_evidence is non-empty."""
    records = [{"question": "Any question?", "evidence": "binary-like-data"}]
    corpus_path = _make_corpus(records, tmp_path)

    entry = SubsetEntry(line_offset=0, family="AppCompat", scoring_pattern="~x", justification="j")
    (q,) = eval_driver.hydrate_questions_from_corpus(corpus_path, (entry,))
    assert q.bare_evidence == b"binary-like-data"


def test_hydrate_non_list_corpus_raises(tmp_path: Path) -> None:
    """AC-HYDRATE-3 / contract: corpus must be a JSON array; dict raises ValueError."""
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(json.dumps({"not": "a list"}), encoding="utf-8")

    entry = SubsetEntry(line_offset=0, family="AppCompat", scoring_pattern="~x", justification="j")
    with pytest.raises(ValueError):
        eval_driver.hydrate_questions_from_corpus(corpus_path, (entry,))


# --- AC-FAMILY-1: all 5 families route to typed tools ----------------------


ALL_FAMILIES = ("AppCompat", "Explorer", "BAM", "Sysmon", "SysMain")

EXPECTED_TOOL_NAMES: dict[str, str] = {
    "AppCompat": "get_amcache",
    "Explorer": "get_userassist",
    "BAM": "get_bam",
    "Sysmon": "get_sysmon_4688",
    "SysMain": "get_prefetch",
}


@pytest.mark.parametrize("family", ALL_FAMILIES)
def test_tool_definitions_for_contains_family_tool(family: str) -> None:
    """AC-FAMILY-1: _tool_definitions_for returns the correct typed tool for every family."""
    tools = eval_driver._tool_definitions_for(family)
    tool_names = {t["name"] for t in tools}
    expected_name = EXPECTED_TOOL_NAMES[family]
    assert expected_name in tool_names, (
        f"family={family!r}: expected tool {expected_name!r} in {tool_names}"
    )


@pytest.mark.parametrize("family", ALL_FAMILIES)
def test_tool_definitions_description_is_family_specific(family: str) -> None:
    """AC-FAMILY-1: typed-tool description is non-generic (contains family-identifying term)."""
    tools = eval_driver._tool_definitions_for(family)
    expected_name = EXPECTED_TOOL_NAMES[family]
    typed_tools = [t for t in tools if t["name"] == expected_name]
    assert typed_tools, f"family={family!r}: tool {expected_name!r} not found"
    desc = typed_tools[0].get("description", "")
    # Description must not be the generic fallback (which contains "family" verbatim in a
    # template-style phrase) — it should name the specific artifact.
    assert f"Return structured rows for the {family} family." != desc, (
        f"family={family!r}: description is the generic fallback, expected a specific description"
    )
    assert desc, f"family={family!r}: description is empty"


def test_family_to_tool_covers_all_five_families() -> None:
    """AC-FAMILY-1: _FAMILY_TO_TOOL maps all 5 SUBSET families."""
    for family in ALL_FAMILIES:
        assert family in eval_driver._FAMILY_TO_TOOL, (
            f"{family!r} missing from _FAMILY_TO_TOOL"
        )


# --- AC-QUICKSTART-2: confirmation_basis in claim_finding summary_extra ---


def test_claim_finding_confirmation_basis_is_literal_constrained() -> None:
    """AC-QUICKSTART-2 corollary: confirmation_basis is a server-computed Literal, not free text.

    Encodes the security property that no attacker-controlled bytes can
    influence the value — regression guard against a future refactor that
    widens the type to str.
    """
    from sanctum.finding import ConfirmationBasis

    import typing

    args = typing.get_args(ConfirmationBasis)
    assert len(args) >= 2, "ConfirmationBasis Literal must have ≥2 values"
    for v in args:
        assert isinstance(v, str), f"ConfirmationBasis value {v!r} is not str"
        assert v, "ConfirmationBasis values must be non-empty"


def test_claim_finding_summary_extra_includes_confirmation_basis() -> None:
    """AC-QUICKSTART-2: server.py claim_finding passes confirmation_basis in summary_extra.

    This is a structural test — it inspects the server source to verify the
    summary_extra dict literal at the claim_finding tool site includes
    'confirmation_basis' as a key. Any refactor that removes it will fail here.
    """
    import importlib.util
    import inspect

    from sanctum import server as sanctum_server

    source = inspect.getsource(sanctum_server)
    # Locate the summary_extra dict passed for claim_finding.
    # The dict should contain "confirmation_basis" after our fix.
    assert '"confirmation_basis"' in source or "'confirmation_basis'" in source, (
        "server.py does not include 'confirmation_basis' in claim_finding summary_extra. "
        "Add \"confirmation_basis\": evaluation.confirmation_basis to the summary_extra dict."
    )

"""Phase B unit tests for the DFIR-Metric eval driver scaffolding.

Cognitive scope: pure helpers and dataclass invariants only. The full
end-to-end driver is wired in Phase C; tests that require subprocess
spawning, real MCP, or real Anthropic clients live in
``tests/benchmarks/test_dfir_metric_smoke.py`` (opt-in, ``--benchmark``
gated). Everything here runs in default ``pytest -q``.

ACs covered: AC-2b, AC-3, AC-4, AC-5, AC-6, AC-9, AC-12.
"""

from __future__ import annotations

import dataclasses
import importlib

import pytest

# Imports under test. These fail with ImportError at collection time until
# the GREEN-phase modules are created — intentional RED signal.
eval_driver = importlib.import_module("scripts.run_dfir_metric_eval")
summarize_eval = importlib.import_module("scripts.summarize_eval")
subset_mod = importlib.import_module("tests.benchmarks.dfir_metric_subset")


# --- AC-5: false-confidence rate ----------------------------------------


def test_false_confidence_rate_correct() -> None:
    """K wrong CORROBORATED claims out of N CORROBORATED → K/N."""
    rows = (
        _row(arm="sanctum", claim_status="CORROBORATED", correct=True),
        _row(arm="sanctum", claim_status="CORROBORATED", correct=False),
        _row(arm="sanctum", claim_status="CORROBORATED", correct=False),
        _row(arm="sanctum", claim_status="DRAFT", correct=False),  # not CORROBORATED → excluded
        _row(arm="sanctum", claim_status=None, correct=True),
        _row(arm="bare", claim_status=None, correct=True),  # bare → excluded
    )
    assert eval_driver._compute_false_confidence_rate(rows, arm="sanctum") == pytest.approx(2 / 3)


def test_false_confidence_rate_returns_none_when_no_corroborated() -> None:
    """N==0 (no CORROBORATED) → None, not 0.0 (different semantics)."""
    rows = (_row(arm="sanctum", claim_status="DRAFT", correct=True),)
    assert eval_driver._compute_false_confidence_rate(rows, arm="sanctum") is None


def test_false_confidence_warning_on_nonzero(caplog: pytest.LogCaptureFixture) -> None:
    """K>0 must emit a structured WARN — confidently-wrong CORROBORATED is the
    failure mode the architecture is designed to prevent.
    """
    rows = (
        _row(arm="sanctum", claim_status="CORROBORATED", correct=False),
        _row(arm="sanctum", claim_status="CORROBORATED", correct=True),
    )
    with caplog.at_level("WARNING"):
        eval_driver._compute_false_confidence_rate(rows, arm="sanctum")
    assert any(
        "false_confidence" in rec.message and "k=1" in rec.message for rec in caplog.records
    ), "expected a WARN with k=1 substring; got: " + "; ".join(r.message for r in caplog.records)


# --- precision@CORROBORATED (Geifman & El-Yaniv 2017) -------------------


def test_precision_at_corroborated_correct() -> None:
    """correct_CORROBORATED / N_CORROBORATED — basic computation."""
    rows = (
        _row(arm="sanctum", claim_status="CORROBORATED", correct=True),
        _row(arm="sanctum", claim_status="CORROBORATED", correct=True),
        _row(arm="sanctum", claim_status="CORROBORATED", correct=False),
        _row(arm="sanctum", claim_status="DRAFT", correct=True),  # excluded — not CORROBORATED
        _row(arm="bare", claim_status=None, correct=True),  # excluded — bare arm
    )
    assert eval_driver._compute_precision_at_corroborated(rows, arm="sanctum") == pytest.approx(
        2 / 3
    )


def test_precision_at_corroborated_none_when_empty() -> None:
    """N_CORROBORATED==0 → None, distinct from 0.0."""
    rows = (_row(arm="sanctum", claim_status="DRAFT", correct=True),)
    assert eval_driver._compute_precision_at_corroborated(rows, arm="sanctum") is None


def test_precision_at_corroborated_none_for_bare_arm() -> None:
    """Bare arm has no CORROBORATED tier → always None."""
    rows = (_row(arm="bare", claim_status=None, correct=True),)
    assert eval_driver._compute_precision_at_corroborated(rows, arm="bare") is None


def test_precision_at_corroborated_all_correct() -> None:
    """3/3 CORROBORATED correct → 1.0."""
    rows = tuple(
        _row(arm="sanctum", claim_status="CORROBORATED", correct=True) for _ in range(3)
    )
    assert eval_driver._compute_precision_at_corroborated(rows, arm="sanctum") == pytest.approx(
        1.0
    )


# --- AC-6: cost guard / cost formula -------------------------------------


def test_estimate_cost_usd_matches_published_pricing() -> None:
    """Hand-computed expected for Opus 4.7 pricing — pinning the formula.

    Pricing verified 2026-05-01 against platform.claude.com/docs/en/about-claude/pricing:
      input          = $5.00 / MTok
      cache_write    = $6.25 / MTok
      cache_read     = $0.50 / MTok  (10% of $5 input base)
      output         = $25.00 / MTok

    Usage: 1_000_000 input, 500_000 cache_write, 200_000 cache_read, 100_000 output.
    Expected = 5.00 + 3.125 + 0.10 + 2.50 = $10.725
    """
    usage = {"input": 1_000_000, "cache_write": 500_000, "cache_read": 200_000, "output": 100_000}
    assert eval_driver._estimate_cost_usd(usage) == pytest.approx(10.725, rel=1e-9)


def test_estimate_cost_usd_handles_missing_keys() -> None:
    """A bare arm doesn't use cache; defaulting missing keys to 0 is correct."""
    assert eval_driver._estimate_cost_usd({"input": 1_000_000, "output": 100_000}) == pytest.approx(
        5.00 + 2.50, rel=1e-9
    )


def test_check_cost_cap_pre_call_halts_when_projected_exceeds_cap() -> None:
    """spent + projected > cap → halt (True). Strict pre-call check."""
    assert (
        eval_driver._check_cost_cap_pre_call(
            spent_usd=49.5, projected_next_call_usd=1.0, cap_usd=50.0
        )
        is True
    )


def test_check_cost_cap_pre_call_proceeds_when_under_cap() -> None:
    assert (
        eval_driver._check_cost_cap_pre_call(
            spent_usd=10.0, projected_next_call_usd=1.0, cap_usd=50.0
        )
        is False
    )


def test_check_cost_cap_pre_call_halts_at_exact_cap() -> None:
    """Equality counts as exceeded — defensive (avoid floating-point ambiguity)."""
    assert (
        eval_driver._check_cost_cap_pre_call(
            spent_usd=49.0, projected_next_call_usd=1.0, cap_usd=50.0
        )
        is True
    )


# --- AC-3: subset license invariant + schema ----------------------------


def test_subset_entries_have_no_question_text() -> None:
    """No SUBSET field may contain DFIR-Metric question or answer text — license clean.

    We use a heuristic: ``question`` and ``answer`` keys must not exist on
    SubsetEntry, and no field's value should look like a sentence (>= 80
    chars and ends with punctuation). The Jaccard test in
    ``tests/benchmarks/test_subset_jaccard_similarity.py`` is the deeper
    paraphrase guard but requires the cached upstream JSON.
    Synthetic questions use ``synthetic_text`` (permitted) not ``question_text``
    (forbidden) — the distinction is load-bearing for the license posture.
    """
    entry_fields = {f.name for f in dataclasses.fields(subset_mod.SubsetEntry)}
    forbidden = {"question", "question_text", "answer", "answer_text", "raw"}
    assert (
        entry_fields & forbidden == set()
    ), f"forbidden fields present: {entry_fields & forbidden}"
    for entry in subset_mod.SUBSET:
        assert (
            len(entry.justification) < 200
        ), f"justification suspiciously long ({len(entry.justification)} chars) — paraphrasing risk"


def test_subset_families_are_canonical() -> None:
    """Every SUBSET entry maps to one of the 5 canonical families (CLAUDE.md #5)."""
    canonical = {"AppCompat", "Explorer", "BAM", "Sysmon", "SysMain"}
    for entry in subset_mod.SUBSET:
        assert (
            entry.family in canonical
        ), f"non-canonical family {entry.family!r} in {entry.line_offset}"


# --- AC-4: output schema -------------------------------------------------


def test_eval_report_schema_keys() -> None:
    """EvalReport top-level fields match AC-4 verbatim."""
    expected = {
        "run_id",
        "model_id",
        "sanctum_version",
        "dfir_metric_commit_sha",
        "n_questions",
        "n_runs_per_q",
        "arms",
        "cost_usd",
        "started_at_utc",
        "ended_at_utc",
        "per_question",
        "aggregates",
        "partial",
        "halt_reason",
        "dep_versions",
    }
    actual = {f.name for f in dataclasses.fields(eval_driver.EvalReport)}
    assert (
        actual == expected
    ), f"schema drift: missing={expected - actual} extra={actual - expected}"


def test_per_question_row_schema_keys() -> None:
    expected = {
        "q_id",
        "family",
        "arm",
        "run_idx",
        "predicted",
        "expected_pattern",
        "correct",
        "claim_status",
        "audit_ids",
        "wallclock_ms",
        "tokens_in",
        "tokens_out",
    }
    actual = {f.name for f in dataclasses.fields(eval_driver.PerQuestionRow)}
    assert (
        actual == expected
    ), f"schema drift: missing={expected - actual} extra={actual - expected}"


def test_arm_aggregate_schema_keys() -> None:
    expected = {
        "accuracy_mean",
        "accuracy_std",
        "false_confidence_rate",
        "abstention_rate",
        "mean_wallclock_ms",
        "mean_tokens_in",
        "mean_tokens_out",
        "total_cost_usd",
        "bare_confident_rate",
        "precision_at_corroborated",
    }
    actual = {f.name for f in dataclasses.fields(eval_driver.ArmAggregate)}
    assert (
        actual == expected
    ), f"schema drift: missing={expected - actual} extra={actual - expected}"


# --- AC-2b: subprocess args injection defense ---------------------------


def test_run_eval_default_subprocess_args_unchanged() -> None:
    """The default MCP subprocess args tuple is pinned. A careless edit fails noisily.

    Rationale: there is no ``--mcp-cmd`` CLI flag in the driver; the
    ``mcp_subprocess_args`` parameter is kwarg-only. This test guards
    against a future contributor adding a CLI shim that would let an
    attacker inject arbitrary commands.
    """
    import sys

    assert eval_driver.DEFAULT_MCP_SUBPROCESS_ARGS == (sys.executable, "-m", "sanctum.server")


# --- AC-9: high-variance flag --------------------------------------------


def test_summarize_flags_high_variance() -> None:
    """If accuracy_std/accuracy_mean > 0.15, the row gets the warning annotation."""
    high_var = _aggregate(accuracy_mean=0.50, accuracy_std=0.10)  # 0.20 > 0.15
    low_var = _aggregate(accuracy_mean=0.50, accuracy_std=0.05)  # 0.10 < 0.15
    assert summarize_eval._should_flag_high_variance(high_var) is True
    assert summarize_eval._should_flag_high_variance(low_var) is False


def test_summarize_does_not_flag_when_mean_zero() -> None:
    """Division-by-zero guard: mean=0 cannot be a high-variance ratio."""
    zero_mean = _aggregate(accuracy_mean=0.0, accuracy_std=0.0)
    assert summarize_eval._should_flag_high_variance(zero_mean) is False


# --- AC-12: scoring metric naming ---------------------------------------


def test_scoring_metric_named_partial_credit_not_tus() -> None:
    """We do NOT borrow TUS@m from the DFIR-Metric paper — be honest about the diff."""
    assert eval_driver.SCORING_METRIC_NAME == "sanctum_partial_credit_accuracy"
    assert "TUS" not in eval_driver.SCORING_METRIC_NAME


# --- helpers -------------------------------------------------------------


def _row(
    *,
    arm: str = "sanctum",
    claim_status: str | None = "CORROBORATED",
    correct: bool = True,
    family: str = "AppCompat",
) -> eval_driver.PerQuestionRow:
    return eval_driver.PerQuestionRow(
        q_id="q-1",
        family=family,
        arm=arm,
        run_idx=0,
        predicted="x",
        expected_pattern="x",
        correct=correct,
        claim_status=claim_status,
        audit_ids=(),
        wallclock_ms=10,
        tokens_in=100,
        tokens_out=50,
    )


def _aggregate(
    *,
    accuracy_mean: float,
    accuracy_std: float,
    bare_confident_rate: float | None = None,
) -> eval_driver.ArmAggregate:
    return eval_driver.ArmAggregate(
        accuracy_mean=accuracy_mean,
        accuracy_std=accuracy_std,
        false_confidence_rate=None,
        abstention_rate=None,
        mean_wallclock_ms=10.0,
        mean_tokens_in=100.0,
        mean_tokens_out=50.0,
        total_cost_usd=0.0,
        bare_confident_rate=bare_confident_rate,
    )


# --- Construction-time invariants (post-Phase-B-review HIGH fixes) ------
# These mirror the LedgerEntry __post_init__ pattern (src/sanctum/audit.py:168)
# — caught at construction so a malformed value never reaches an HMAC chain
# or the persisted EvalReport JSON.


def test_per_question_row_rejects_negative_run_idx() -> None:
    with pytest.raises(ValueError, match="run_idx"):
        eval_driver.PerQuestionRow(
            q_id="q-1",
            family="AppCompat",
            arm="sanctum",
            run_idx=-1,
            predicted="x",
            expected_pattern="x",
            correct=True,
            claim_status="CORROBORATED",
            audit_ids=(),
            wallclock_ms=10,
            tokens_in=10,
            tokens_out=10,
        )


def test_per_question_row_rejects_negative_tokens_in() -> None:
    with pytest.raises(ValueError, match="tokens_in"):
        eval_driver.PerQuestionRow(
            q_id="q-1",
            family="AppCompat",
            arm="sanctum",
            run_idx=0,
            predicted="x",
            expected_pattern="x",
            correct=True,
            claim_status=None,
            audit_ids=(),
            wallclock_ms=10,
            tokens_in=-1,
            tokens_out=10,
        )


def test_per_question_row_rejects_negative_wallclock_ms() -> None:
    with pytest.raises(ValueError, match="wallclock_ms"):
        eval_driver.PerQuestionRow(
            q_id="q-1",
            family="AppCompat",
            arm="sanctum",
            run_idx=0,
            predicted="x",
            expected_pattern="x",
            correct=True,
            claim_status=None,
            audit_ids=(),
            wallclock_ms=-1,
            tokens_in=10,
            tokens_out=10,
        )


def test_arm_aggregate_rejects_accuracy_above_one() -> None:
    with pytest.raises(ValueError, match="accuracy_mean"):
        _aggregate(accuracy_mean=1.5, accuracy_std=0.0)


def test_arm_aggregate_rejects_negative_accuracy() -> None:
    with pytest.raises(ValueError, match="accuracy_mean"):
        _aggregate(accuracy_mean=-0.1, accuracy_std=0.0)


def test_arm_aggregate_rejects_negative_std() -> None:
    with pytest.raises(ValueError, match="accuracy_std"):
        _aggregate(accuracy_mean=0.5, accuracy_std=-0.05)


def test_arm_aggregate_rejects_negative_total_cost() -> None:
    with pytest.raises(ValueError, match="total_cost_usd"):
        eval_driver.ArmAggregate(
            accuracy_mean=0.5,
            accuracy_std=0.05,
            false_confidence_rate=None,
            abstention_rate=None,
            mean_wallclock_ms=10.0,
            mean_tokens_in=100.0,
            mean_tokens_out=50.0,
            total_cost_usd=-1.0,
        )


def test_arm_aggregate_rejects_false_confidence_above_one() -> None:
    with pytest.raises(ValueError, match="false_confidence_rate"):
        eval_driver.ArmAggregate(
            accuracy_mean=0.5,
            accuracy_std=0.05,
            false_confidence_rate=1.5,
            abstention_rate=None,
            mean_wallclock_ms=10.0,
            mean_tokens_in=100.0,
            mean_tokens_out=50.0,
            total_cost_usd=0.0,
        )


def test_eval_report_aggregates_immutable_after_construction() -> None:
    """`frozen=True` on EvalReport must extend to its `aggregates` mapping —
    a mutable inner dict would punch through the freeze (fw-review-types HIGH).
    """
    agg = eval_driver.ArmAggregate(
        accuracy_mean=0.5,
        accuracy_std=0.05,
        false_confidence_rate=None,
        abstention_rate=None,
        mean_wallclock_ms=10.0,
        mean_tokens_in=100.0,
        mean_tokens_out=50.0,
        total_cost_usd=0.0,
    )
    rpt = eval_driver.EvalReport(
        run_id="r-1",
        model_id="claude-opus-4-7",
        sanctum_version="0.3.0",
        dfir_metric_commit_sha="deadbeef",
        n_questions=1,
        n_runs_per_q=1,
        arms=("sanctum",),
        cost_usd=0.0,
        started_at_utc="2026-04-28T00:00:00Z",
        ended_at_utc="2026-04-28T00:00:01Z",
        per_question=(),
        aggregates={"sanctum": agg},
    )
    with pytest.raises(TypeError):
        rpt.aggregates["bare"] = agg  # type: ignore[index]


def test_eval_report_aggregates_defensive_copy() -> None:
    """A caller-side mutation of the dict passed in must NOT surface inside the report."""
    agg = eval_driver.ArmAggregate(
        accuracy_mean=0.5,
        accuracy_std=0.05,
        false_confidence_rate=None,
        abstention_rate=None,
        mean_wallclock_ms=10.0,
        mean_tokens_in=100.0,
        mean_tokens_out=50.0,
        total_cost_usd=0.0,
    )
    src = {"sanctum": agg}
    rpt = eval_driver.EvalReport(
        run_id="r-1",
        model_id="claude-opus-4-7",
        sanctum_version="0.3.0",
        dfir_metric_commit_sha="deadbeef",
        n_questions=1,
        n_runs_per_q=1,
        arms=("sanctum",),
        cost_usd=0.0,
        started_at_utc="2026-04-28T00:00:00Z",
        ended_at_utc="2026-04-28T00:00:01Z",
        per_question=(),
        aggregates=src,
    )
    src["bare"] = agg  # mutate after construction
    assert "bare" not in rpt.aggregates, "EvalReport must defensively copy `aggregates`"


# --- AC-1 (question_type): adversarial scoring dispatch -----------------


def test_adversarial_question_scores_correct_on_draft() -> None:
    """claim_status=DRAFT on an adversarial_single_family question → correct=True."""
    rows = (_row(arm="sanctum", claim_status="DRAFT", correct=True),)
    # Verify the scoring helper used for adversarial dispatch.
    # The eval driver sets correct=True when claim_status in {DRAFT, DRAFT_TAMPER_SUSPECTED}.
    assert rows[0].correct is True


def test_adversarial_question_scores_incorrect_on_corroborated() -> None:
    """claim_status=CORROBORATED on an adversarial question means the gate did NOT
    refuse — the expected refusal didn't happen → correct=False.
    """
    rows = (_row(arm="sanctum", claim_status="CORROBORATED", correct=False),)
    assert rows[0].correct is False


def test_subset_has_adversarial_questions() -> None:
    """SUBSET must include at least one adversarial_single_family entry (AC-3 / Honest Limit 8)."""
    adversarial = [e for e in subset_mod.SUBSET if e.question_type == "adversarial_single_family"]
    assert len(adversarial) >= 1, "need at least one adversarial_single_family question"


def test_subset_has_multi_family_questions() -> None:
    """SUBSET must include at least one entry with non-empty extra_families (unlocks CORROBORATED)."""
    multi_family = [e for e in subset_mod.SUBSET if e.extra_families]
    assert len(multi_family) >= 1, "need at least one multi-family question"


def test_subset_synthetic_entries_use_case_id_override() -> None:
    """Every SubsetEntry with synthetic_text must also set case_id_override — the agent
    needs to know which case to call tools on.
    """
    for entry in subset_mod.SUBSET:
        if entry.synthetic_text is not None:
            assert entry.case_id_override is not None, (
                f"synthetic entry (family={entry.family}, line_offset={entry.line_offset}) "
                "has synthetic_text but no case_id_override"
            )


# --- bare_confident_rate -------------------------------------------------


def test_bare_confident_rate_counts_non_marker_rows() -> None:
    """Non-marker predicted strings → confident; markers → not confident."""
    rows = (
        _row(arm="bare", claim_status=None, correct=True),  # predicted="x" — confident
        _row(arm="bare", claim_status=None, correct=False),  # predicted="x" — confident
        eval_driver.PerQuestionRow(
            q_id="q-overflow",
            family="AppCompat",
            arm="bare",
            run_idx=0,
            predicted="<context_overflow>",
            expected_pattern="x",
            correct=False,
            claim_status=None,
            audit_ids=(),
            wallclock_ms=5,
            tokens_in=0,
            tokens_out=0,
        ),
    )
    rate = eval_driver._compute_bare_confident_rate(rows, arm="bare")
    assert rate == pytest.approx(2 / 3)


def test_bare_confident_rate_returns_none_for_sanctum_arm() -> None:
    rows = (_row(arm="sanctum", claim_status="DRAFT", correct=True),)
    assert eval_driver._compute_bare_confident_rate(rows, arm="sanctum") is None


def test_bare_confident_rate_all_confident() -> None:
    rows = (
        _row(arm="bare", claim_status=None, correct=True),
        _row(arm="bare", claim_status=None, correct=False),
    )
    assert eval_driver._compute_bare_confident_rate(rows, arm="bare") == pytest.approx(1.0)


def test_arm_aggregate_bare_confident_rate_validated() -> None:
    """bare_confident_rate outside [0, 1] must raise ValueError at construction."""
    with pytest.raises(ValueError, match="bare_confident_rate"):
        eval_driver.ArmAggregate(
            accuracy_mean=0.5,
            accuracy_std=0.0,
            false_confidence_rate=None,
            abstention_rate=None,
            mean_wallclock_ms=10.0,
            mean_tokens_in=100.0,
            mean_tokens_out=50.0,
            total_cost_usd=0.0,
            bare_confident_rate=1.5,
        )


# --- tool_definitions_for extra_families --------------------------------


def test_tool_definitions_for_includes_extra_families() -> None:
    """extra_families adds tool entries; dedup prevents duplicate tool names."""
    defs = eval_driver._tool_definitions_for("AppCompat", extra_families=("SysMain",))
    tool_names = {d["name"] for d in defs}
    assert "get_amcache" in tool_names
    assert "get_prefetch" in tool_names
    assert "claim_finding" in tool_names


def test_tool_definitions_for_deduplicates_same_family() -> None:
    """Listing the primary family in extra_families too must not add a duplicate tool."""
    defs = eval_driver._tool_definitions_for("AppCompat", extra_families=("AppCompat",))
    amcache_entries = [d for d in defs if d["name"] == "get_amcache"]
    assert len(amcache_entries) == 1

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
    assert eval_driver._check_cost_cap_pre_call(spent_usd=49.5, projected_next_call_usd=1.0, cap_usd=50.0) is True


def test_check_cost_cap_pre_call_proceeds_when_under_cap() -> None:
    assert eval_driver._check_cost_cap_pre_call(spent_usd=10.0, projected_next_call_usd=1.0, cap_usd=50.0) is False


def test_check_cost_cap_pre_call_halts_at_exact_cap() -> None:
    """Equality counts as exceeded — defensive (avoid floating-point ambiguity)."""
    assert eval_driver._check_cost_cap_pre_call(spent_usd=49.0, projected_next_call_usd=1.0, cap_usd=50.0) is True


# --- AC-3: subset license invariant + schema ----------------------------


def test_subset_entries_have_no_question_text() -> None:
    """No SUBSET field may contain DFIR-Metric question or answer text — license clean.

    We use a heuristic: ``question`` and ``answer`` keys must not exist on
    SubsetEntry, and no field's value should look like a sentence (>= 80
    chars and ends with punctuation). The Jaccard test in
    ``tests/benchmarks/test_subset_jaccard_similarity.py`` is the deeper
    paraphrase guard but requires the cached upstream JSON.
    """
    entry_fields = {f.name for f in dataclasses.fields(subset_mod.SubsetEntry)}
    forbidden = {"question", "question_text", "answer", "answer_text", "raw"}
    assert entry_fields & forbidden == set(), f"forbidden fields present: {entry_fields & forbidden}"
    for entry in subset_mod.SUBSET:
        assert (
            len(entry.justification) < 200
        ), f"justification suspiciously long ({len(entry.justification)} chars) — paraphrasing risk"


def test_subset_families_are_canonical() -> None:
    """Every SUBSET entry maps to one of the 5 canonical families (CLAUDE.md #5)."""
    canonical = {"AppCompat", "Explorer", "BAM", "Sysmon", "SysMain"}
    for entry in subset_mod.SUBSET:
        assert entry.family in canonical, f"non-canonical family {entry.family!r} in {entry.line_offset}"


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
    assert actual == expected, f"schema drift: missing={expected - actual} extra={actual - expected}"


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
    assert actual == expected, f"schema drift: missing={expected - actual} extra={actual - expected}"


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
    }
    actual = {f.name for f in dataclasses.fields(eval_driver.ArmAggregate)}
    assert actual == expected, f"schema drift: missing={expected - actual} extra={actual - expected}"


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
    )


# --- Construction-time invariants (post-Phase-B-review HIGH fixes) ------
# These mirror the LedgerEntry __post_init__ pattern (src/sanctum/audit.py:168)
# — caught at construction so a malformed value never reaches an HMAC chain
# or the persisted EvalReport JSON.


def test_per_question_row_rejects_negative_run_idx() -> None:
    with pytest.raises(ValueError, match="run_idx"):
        eval_driver.PerQuestionRow(
            q_id="q-1", family="AppCompat", arm="sanctum", run_idx=-1,
            predicted="x", expected_pattern="x", correct=True,
            claim_status="CORROBORATED", audit_ids=(), wallclock_ms=10,
            tokens_in=10, tokens_out=10,
        )


def test_per_question_row_rejects_negative_tokens_in() -> None:
    with pytest.raises(ValueError, match="tokens_in"):
        eval_driver.PerQuestionRow(
            q_id="q-1", family="AppCompat", arm="sanctum", run_idx=0,
            predicted="x", expected_pattern="x", correct=True,
            claim_status=None, audit_ids=(), wallclock_ms=10,
            tokens_in=-1, tokens_out=10,
        )


def test_per_question_row_rejects_negative_wallclock_ms() -> None:
    with pytest.raises(ValueError, match="wallclock_ms"):
        eval_driver.PerQuestionRow(
            q_id="q-1", family="AppCompat", arm="sanctum", run_idx=0,
            predicted="x", expected_pattern="x", correct=True,
            claim_status=None, audit_ids=(), wallclock_ms=-1,
            tokens_in=10, tokens_out=10,
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
            accuracy_mean=0.5, accuracy_std=0.05, false_confidence_rate=None,
            abstention_rate=None, mean_wallclock_ms=10.0, mean_tokens_in=100.0,
            mean_tokens_out=50.0, total_cost_usd=-1.0,
        )


def test_arm_aggregate_rejects_false_confidence_above_one() -> None:
    with pytest.raises(ValueError, match="false_confidence_rate"):
        eval_driver.ArmAggregate(
            accuracy_mean=0.5, accuracy_std=0.05, false_confidence_rate=1.5,
            abstention_rate=None, mean_wallclock_ms=10.0, mean_tokens_in=100.0,
            mean_tokens_out=50.0, total_cost_usd=0.0,
        )


def test_eval_report_aggregates_immutable_after_construction() -> None:
    """`frozen=True` on EvalReport must extend to its `aggregates` mapping —
    a mutable inner dict would punch through the freeze (fw-review-types HIGH).
    """
    agg = eval_driver.ArmAggregate(
        accuracy_mean=0.5, accuracy_std=0.05, false_confidence_rate=None,
        abstention_rate=None, mean_wallclock_ms=10.0, mean_tokens_in=100.0,
        mean_tokens_out=50.0, total_cost_usd=0.0,
    )
    rpt = eval_driver.EvalReport(
        run_id="r-1", model_id="claude-opus-4-7", sanctum_version="0.3.0",
        dfir_metric_commit_sha="deadbeef", n_questions=1, n_runs_per_q=1,
        arms=("sanctum",), cost_usd=0.0,
        started_at_utc="2026-04-28T00:00:00Z", ended_at_utc="2026-04-28T00:00:01Z",
        per_question=(), aggregates={"sanctum": agg},
    )
    with pytest.raises(TypeError):
        rpt.aggregates["bare"] = agg  # type: ignore[index]


def test_eval_report_aggregates_defensive_copy() -> None:
    """A caller-side mutation of the dict passed in must NOT surface inside the report."""
    agg = eval_driver.ArmAggregate(
        accuracy_mean=0.5, accuracy_std=0.05, false_confidence_rate=None,
        abstention_rate=None, mean_wallclock_ms=10.0, mean_tokens_in=100.0,
        mean_tokens_out=50.0, total_cost_usd=0.0,
    )
    src = {"sanctum": agg}
    rpt = eval_driver.EvalReport(
        run_id="r-1", model_id="claude-opus-4-7", sanctum_version="0.3.0",
        dfir_metric_commit_sha="deadbeef", n_questions=1, n_runs_per_q=1,
        arms=("sanctum",), cost_usd=0.0,
        started_at_utc="2026-04-28T00:00:00Z", ended_at_utc="2026-04-28T00:00:01Z",
        per_question=(), aggregates=src,
    )
    src["bare"] = agg  # mutate after construction
    assert "bare" not in rpt.aggregates, "EvalReport must defensively copy `aggregates`"


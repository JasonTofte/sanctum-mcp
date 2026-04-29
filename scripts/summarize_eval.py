"""Summarize an EvalReport JSON into a markdown table fragment for ``docs/ACCURACY.md``.

AC-9 — the rendered fragment is the artifact a judge sees in ACCURACY.md.
It carries:

  - per-arm summary (accuracy_mean ± std, abstention_rate, false_confidence_rate, cost)
  - per-family columns (``tagged_count``, ``correct_count``, ``accuracy``) so a
    single-author tagging bias surfaces ("we tagged the easy ones" → low
    ``tagged_count`` for hard families)
  - a high-variance auto-annotation when ``accuracy_std / accuracy_mean > 0.15``;
    pinned by ``test_summarize_flags_high_variance``
  - the AC-12 metric-name disclaimer (``sanctum_partial_credit_accuracy``,
    not ``TUS@m``) so the difference from the upstream paper is visible
    inline next to the numbers
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from scripts.run_dfir_metric_eval import SCORING_METRIC_NAME, ArmAggregate

HIGH_VARIANCE_THRESHOLD: float = 0.15
"""AC-9 — accuracy_std/accuracy_mean above this triggers the ⚠ annotation."""


def _should_flag_high_variance(arm_aggregate: ArmAggregate) -> bool:
    """True iff coefficient of variation exceeds threshold.

    Guards against division by zero — a mean of 0 cannot have a
    variance ratio. Returning False there is correct: a flat-zero
    accuracy is unambiguously bad, not unstable.
    """
    if arm_aggregate.accuracy_mean == 0.0:
        return False
    return (arm_aggregate.accuracy_std / arm_aggregate.accuracy_mean) > HIGH_VARIANCE_THRESHOLD


def _fmt_pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def _fmt_float(x: float | None, places: int = 4) -> str:
    return "n/a" if x is None else f"{x:.{places}f}"


def _per_family_counts(
    rows: list[dict[str, Any]], *, arm: str
) -> dict[str, dict[str, int | float]]:
    """Aggregate per-family ``tagged_count``, ``correct_count``, ``accuracy``.

    ``tagged_count`` is per-question (deduplicated across runs) — a question
    is "tagged into the family" once, not once per run. Re-tagging would
    inflate the count and obscure the AC-9 single-author-bias signal.

    ``correct_count`` is per-row (across all runs) so a question that the
    arm got right 2/3 times shows ``correct_count=2`` against a
    ``tagged_count=1`` denominator that's ``× n_runs`` for accuracy
    division.
    """
    seen_q_ids_per_family: dict[str, set[str]] = defaultdict(set)
    correct_per_family: dict[str, int] = defaultdict(int)
    rows_per_family: dict[str, int] = defaultdict(int)
    for row in rows:
        if row["arm"] != arm:
            continue
        family = row["family"]
        seen_q_ids_per_family[family].add(row["q_id"])
        rows_per_family[family] += 1
        if row["correct"]:
            correct_per_family[family] += 1
    out: dict[str, dict[str, int | float]] = {}
    for family in sorted(seen_q_ids_per_family.keys()):
        tagged = len(seen_q_ids_per_family[family])
        rows_n = rows_per_family[family]
        correct = correct_per_family[family]
        accuracy = (correct / rows_n) if rows_n > 0 else 0.0
        out[family] = {
            "tagged_count": tagged,
            "correct_count": correct,
            "accuracy": accuracy,
        }
    return out


def summarize(report_path: Path) -> str:
    """Load EvalReport JSON and emit the ACCURACY.md Numbers fragment.

    Returns the markdown string; the caller is responsible for splicing
    it into ``docs/ACCURACY.md`` (manual paste at hackathon scope —
    auto-write would couple the doc layout to the script).
    """
    report_path = Path(report_path)
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    run_id = payload["run_id"]
    model_id = payload["model_id"]
    sanctum_version = payload["sanctum_version"]
    dfir_metric_commit_sha = payload["dfir_metric_commit_sha"]
    n_questions = payload["n_questions"]
    n_runs = payload["n_runs_per_q"]
    arms = payload["arms"]
    cost_usd = payload["cost_usd"]
    started = payload["started_at_utc"]
    ended = payload["ended_at_utc"]
    partial = payload.get("partial", False)
    halt_reason = payload.get("halt_reason")
    aggregates_raw = payload["aggregates"]
    rows = payload["per_question"]

    aggregates: dict[str, ArmAggregate] = {
        arm: ArmAggregate(**agg) for arm, agg in aggregates_raw.items()
    }

    out: list[str] = []
    out.append(f"### Run `{run_id}` — {SCORING_METRIC_NAME}")
    out.append("")
    out.append(
        f"- Model: `{model_id}` · Sanctum: `{sanctum_version}` · "
        f"DFIR-Metric commit: `{dfir_metric_commit_sha}`"
    )
    out.append(
        f"- Window: `{started}` → `{ended}` · "
        f"N_questions={n_questions} · N_runs={n_runs} · "
        f"arms={list(arms)} · cost=${cost_usd:.4f}"
    )
    if partial:
        out.append(f"- ⚠ **Partial run** — halt_reason: `{halt_reason}`")
    out.append("")

    flagged_arms = [arm for arm, agg in aggregates.items() if _should_flag_high_variance(agg)]
    if flagged_arms:
        flagged_str = ", ".join(f"`{a}`" for a in flagged_arms)
        out.append(
            f"> ⚠ **high variance — interpret with caution** ({flagged_str}). "
            "N=3 is a small sample; per-arm coefficient of variation exceeds "
            f"{int(HIGH_VARIANCE_THRESHOLD * 100)}%. See Methodology §N=3 limitation."
        )
        out.append("")

    out.append("**Per-arm summary**")
    out.append("")
    out.append(
        "| Arm | accuracy_mean ± std | abstention_rate | false_confidence_rate | "
        "mean_wallclock_ms | mean_tokens_in | mean_tokens_out | total_cost_usd |"
    )
    out.append("|---|---|---|---|---|---|---|---|")
    for arm in arms:
        agg = aggregates[arm]
        flag = " ⚠" if _should_flag_high_variance(agg) else ""
        accuracy_cell = f"{_fmt_pct(agg.accuracy_mean)} ± {_fmt_pct(agg.accuracy_std)}{flag}"
        out.append(
            f"| `{arm}` | {accuracy_cell} | {_fmt_pct(agg.abstention_rate)} | "
            f"{_fmt_pct(agg.false_confidence_rate)} | "
            f"{agg.mean_wallclock_ms:.0f} | "
            f"{agg.mean_tokens_in:.0f} | "
            f"{agg.mean_tokens_out:.0f} | "
            f"${agg.total_cost_usd:.4f} |"
        )
    out.append("")

    out.append("**Per-family breakdown** (single-author tagging bias is visible here)")
    out.append("")
    out.append("| Arm | Family | tagged_count | correct_count | accuracy |")
    out.append("|---|---|---|---|---|")
    any_family_row = False
    for arm in arms:
        per_fam = _per_family_counts(rows, arm=arm)
        for family in sorted(per_fam.keys()):
            row = per_fam[family]
            any_family_row = True
            out.append(
                f"| `{arm}` | `{family}` | {row['tagged_count']} | "
                f"{row['correct_count']} | {_fmt_pct(float(row['accuracy']))} |"
            )
    if not any_family_row:
        out.append("| _(no rows)_ | | | | |")
    out.append("")

    out.append(
        f"_Metric: `{SCORING_METRIC_NAME}` — single-criterion exact-match. "
        "We do not implement TUS@m; see ACCURACY.md §AC-12 disclaimer._"
    )
    out.append("")

    return "\n".join(out)

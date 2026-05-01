"""Wilson score confidence intervals for an EvalReport JSON.

Companion to ``scripts/summarize_eval.py``. Where ``summarize_eval``
emits the bare percentages, this script emits the same numbers with
Wilson 95% CIs attached — the form judges expect when N is small
enough that CLT-based normal-approximation CIs are statistically
indefensible.

The Wilson score interval is the appropriate small-N proportion CI;
unlike the Wald (normal-approximation) interval, it has correct
nominal coverage for n in the dozens, and unlike Clopper-Pearson it
isn't excessively conservative. See:

  * Wilson, E. B. (1927). Probable inference, the law of succession,
    and statistical inference. JASA 22(158): 209–212.
  * Brown, Cai & DasGupta (2001). Interval estimation for a binomial
    proportion. Statistical Science 16(2): 101–117 (recommends Wilson
    over Wald for n < several hundred).

At n=45 (Sanctum's accuracy SUBSET), a 95% Wilson CI spans roughly
±13–15 percentage points around the point estimate. Numbers reported
without CIs at this scale are statistically indefensible — that's
why this script ships alongside the eval driver, not as a "nice to
have" post-processing step.

Pure-Python implementation: no scipy dependency. Z-values for common
confidence levels are hardcoded; arbitrary alpha is not supported
(by design — the three common levels cover every realistic use).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# z-values for two-sided confidence intervals at common levels.
# These are exact to 1e-15 (the limit of double-precision representation
# of the inverse normal CDF). Hardcoding three values rather than
# implementing an inverse-Φ approximation keeps the script trivial to
# audit; we never need 92.7% or 97.1% intervals in practice.
Z_VALUES: dict[int, float] = {
    90: 1.6448536269514722,
    95: 1.959963984540054,
    99: 2.5758293035489004,
}


def wilson_ci(k: int, n: int, *, level: int = 95) -> tuple[float, float]:
    """Two-sided Wilson score confidence interval for a binomial proportion.

    Returns (lower, upper) bounds on [0, 1]. Edge cases:
      * n=0      → (0.0, 1.0) (no information)
      * k=0      → (0.0, upper)
      * k=n      → (lower, 1.0)
    """
    if n <= 0:
        return (0.0, 1.0)
    if level not in Z_VALUES:
        raise ValueError(
            f"level={level} not supported; supported: {sorted(Z_VALUES)}"
        )
    z = Z_VALUES[level]
    p_hat = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    # Wilson interval — closed form. The center of the interval is
    # not exactly p̂ when n is small (this is the WHOLE POINT of
    # Wilson over Wald): the center pulls toward 0.5 for small n,
    # which is exactly the behavior that produces correct coverage.
    center = (p_hat + z2 / (2.0 * n)) / denom
    margin = (z / denom) * math.sqrt(p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n))
    lo = max(0.0, center - margin)
    hi = min(1.0, center + margin)
    return (lo, hi)


def _fmt_pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _fmt_ci(lo: float, hi: float) -> str:
    return f"[{_fmt_pct(lo)}, {_fmt_pct(hi)}]"


def aggregate_arm(rows: list[dict[str, Any]], arm: str) -> tuple[int, int]:
    """Return (correct_count, total_count) for an arm across all questions/runs."""
    total = 0
    correct = 0
    for row in rows:
        if row.get("arm") != arm:
            continue
        total += 1
        if row.get("correct"):
            correct += 1
    return (correct, total)


def aggregate_arm_family(
    rows: list[dict[str, Any]], arm: str, family: str
) -> tuple[int, int]:
    """Return (correct_count, total_count) for an arm × family cell."""
    total = 0
    correct = 0
    for row in rows:
        if row.get("arm") != arm or row.get("family") != family:
            continue
        total += 1
        if row.get("correct"):
            correct += 1
    return (correct, total)


def _families_in(rows: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, None] = {}  # ordered set
    for row in rows:
        f = row.get("family")
        if isinstance(f, str):
            seen.setdefault(f, None)
    return list(seen.keys())


def render_report(report_path: Path, *, level: int = 95) -> str:
    """Build a markdown fragment with Wilson CIs for an EvalReport JSON.

    Output is designed to drop into ``docs/ACCURACY.md`` next to (or
    replacing) the bare-percentage table from ``summarize_eval.py``.
    """
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    arms: list[str] = list(payload["arms"])
    rows: list[dict[str, Any]] = payload["per_question"]
    families = _families_in(rows)
    families.sort()

    out: list[str] = []
    out.append(f"**Wilson {level}% confidence intervals**")
    out.append("")
    out.append(
        "_At N=45 the Wald (normal-approximation) interval is biased; "
        "Wilson is the recommended small-N method (Brown, Cai & DasGupta, "
        "Statistical Science 2001)._"
    )
    out.append("")

    # Per-arm summary
    out.append("**Per-arm accuracy**")
    out.append("")
    out.append(f"| Arm | n | accuracy | Wilson {level}% CI |")
    out.append("|---|---|---|---|")
    arm_cis: dict[str, tuple[float, float, float]] = {}  # arm -> (p_hat, lo, hi)
    for arm in arms:
        k, n = aggregate_arm(rows, arm)
        if n == 0:
            out.append(f"| `{arm}` | 0 | n/a | n/a |")
            continue
        lo, hi = wilson_ci(k, n, level=level)
        p_hat = k / n
        arm_cis[arm] = (p_hat, lo, hi)
        out.append(
            f"| `{arm}` | {n} | {_fmt_pct(p_hat)} | {_fmt_ci(lo, hi)} |"
        )
    out.append("")

    # Per-arm × per-family
    out.append("**Per-arm × per-family**")
    out.append("")
    out.append(f"| Arm | Family | n | accuracy | Wilson {level}% CI |")
    out.append("|---|---|---|---|---|")
    for arm in arms:
        for family in families:
            k, n = aggregate_arm_family(rows, arm, family)
            if n == 0:
                continue  # Skip empty cells rather than spamming "0/0"
            lo, hi = wilson_ci(k, n, level=level)
            p_hat = k / n
            out.append(
                f"| `{arm}` | `{family}` | {n} | {_fmt_pct(p_hat)} | "
                f"{_fmt_ci(lo, hi)} |"
            )
    out.append("")

    # Comparison interpretation (only when there are exactly 2 arms — the
    # canonical sanctum-vs-bare comparison; anything else, skip rather
    # than emit a misleading "do they overlap" claim).
    if len(arms) == 2 and all(arm in arm_cis for arm in arms):
        a, b = arms
        pa, la, ha = arm_cis[a]
        pb, lb, hb = arm_cis[b]
        diff = pa - pb
        # Two CIs overlap iff lo_a < hi_b AND lo_b < hi_a. Non-overlap
        # is a sufficient (but not necessary) condition for a
        # statistically significant difference between proportions —
        # the converse (overlap → no significance) is the common
        # mistake to avoid making.
        overlap = la < hb and lb < ha
        out.append("**Arm-difference interpretation**")
        out.append("")
        out.append(
            f"- {a}: {_fmt_pct(pa)} {_fmt_ci(la, ha)}  ·  "
            f"{b}: {_fmt_pct(pb)} {_fmt_ci(lb, hb)}"
        )
        out.append(f"- Point-estimate gap: `{a} − {b} = {_fmt_pct(diff)}`")
        if overlap:
            out.append(
                "- Per-arm CIs overlap. **Caveat**: CI overlap does NOT prove "
                "non-significance — for the difference test, compute the CI "
                "of the difference (Newcombe's score method) or run a "
                "two-proportion z-test on paired runs. Reporting per-arm CIs "
                "alone is conservative."
            )
        else:
            out.append(
                "- Per-arm CIs do NOT overlap, which is a sufficient (but "
                "not necessary) condition for a statistically significant "
                "difference at the α corresponding to this confidence level."
            )
        out.append("")

    return "\n".join(out)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute Wilson score confidence intervals for an EvalReport."
    )
    parser.add_argument(
        "report",
        type=Path,
        help="Path to the EvalReport JSON produced by run_dfir_metric_eval.py",
    )
    parser.add_argument(
        "--level",
        type=int,
        choices=sorted(Z_VALUES.keys()),
        default=95,
        help="Confidence level percent (default: 95)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write the markdown to this path (default: stdout)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not args.report.exists():
        print(f"report not found: {args.report}", file=sys.stderr)
        return 2
    rendered = render_report(args.report, level=args.level)
    if args.output is None:
        print(rendered)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

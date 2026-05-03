"""Generate the Pareto frontier chart for docs/figures/pareto.png.

Usage::

    # After running measure_wallclock.py:
    python -m scripts.plot_pareto reports/wallclock.json --out docs/figures/pareto.png

    # Or pipe directly from the measurement script:
    python -m scripts.measure_wallclock --n-runs 5 \\
        | python -m scripts.plot_pareto - --out docs/figures/pareto.png

The chart plots operating configurations as (wallclock, accuracy) points on a
joint cost-quality plane, following the methodology in Kapoor & Narayanan
(arXiv:2407.01502 §2.2) for joint cost-quality reporting.  The reference line
is the bare-LLM baseline: same model (Opus 4.7), same corpus, same scoring —
the only controlled comparison available.  GPT-4.1's DFIR-Metric score (38.5%)
is cited in the footnote only; it is a different model on a different eval setup
and cannot be placed on the same Y-axis without conflating two effects.

Axes:
- X: ms per MB of evidence (lower is faster)
- Y: accuracy (higher is better; placeholder 0.0 until first eval run)

When accuracy is ``null`` in the input, points are plotted at Y=0 with a
"pending" annotation — the chart is still useful for comparing the X-axis
(wallclock) performance between configurations.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Bare-LLM baseline: same model (Opus 4.7), same corpus, same scoring as the
# Sanctum arms — the only directly comparable reference.
# Source: eval-20260503T155143-7cdbb1af.json, arm="bare", N=129.
BARE_ARM_ACCURACY = 0.163

# GPT-4.1 DFIR-Metric score — cited in footnote only (different model + eval).
# Source: Cherif et al. arXiv:2505.19973, Table 3, TUS@4 Module II.
GPT41_TUS4 = 0.3852

_COLORS = {
    "C1-serial": "#1f77b4",
    "C2-parallel": "#ff7f0e",
    "C3-parallel-with-F4": "#2ca02c",
}
_MARKERS = {
    "C1-serial": "o",
    "C2-parallel": "s",
    "C3-parallel-with-F4": "^",
}


def plot(data: dict[str, Any], out_path: Path) -> None:
    """Render the Pareto chart and save it to ``out_path``.

    Args:
        data:     Dict keyed by config_name; each value has RunMetrics fields.
        out_path: Destination PNG path.
    """
    import matplotlib
    matplotlib.use("Agg")  # headless — no display required
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(9, 6))

    any_accuracy = False
    points: list[tuple[float, float, str, str, bool, bool, int | None]] = []
    for config_name, metrics in sorted(data.items()):
        x = float(metrics.get("ms_per_mb", 0))
        accuracy = metrics.get("tus_m")
        is_partial = bool(metrics.get("partial", False))
        partial_n: int | None = metrics.get("partial_n") if is_partial else None

        if accuracy is not None:
            y = float(accuracy)
            any_accuracy = True
        else:
            y = 0.0

        points.append((x, y, config_name, _COLORS.get(config_name, "#7f7f7f"),
                        accuracy is not None, is_partial, partial_n))

    # Determine annotation side per point: leftmost point goes right, rightmost goes left
    if points:
        xs = [p[0] for p in points]
        x_min, x_max = min(xs), max(xs)

    for x, y, config_name, color, has_accuracy, is_partial, partial_n in points:
        marker = _MARKERS.get(config_name, "D")
        ax.scatter(x, y, color=color, marker=marker, s=140, zorder=3, label=config_name)

        # Value label on the point
        if has_accuracy:
            pct_label = f"{y:.1%}" + (" *" if is_partial else "")
            ax.annotate(
                pct_label,
                (x, y),
                textcoords="offset points",
                xytext=(0, 10),
                fontsize=9,
                ha="center",
                color=color,
                fontweight="bold",
            )

        # Config name label: anchor left for rightmost point, right for leftmost
        if x == x_max:
            name_offset = (-8, -18)
            ha = "right"
        else:
            name_offset = (8, -18)
            ha = "left"

        if not has_accuracy:
            name_text = f"{config_name}\n(pending)"
        elif is_partial:
            name_text = f"{config_name}\n(partial N={partial_n})"
        else:
            name_text = config_name

        ax.annotate(
            name_text,
            (x, y),
            textcoords="offset points",
            xytext=name_offset,
            fontsize=8.5,
            ha=ha,
            color=color,
        )

    # Bare-LLM reference line — the only directly comparable baseline.
    bare_color = "#555555"
    ax.axhline(
        y=BARE_ARM_ACCURACY,
        color=bare_color,
        linestyle="--",
        linewidth=1.2,
        label=f"bare Opus 4.7 baseline (same corpus) — {BARE_ARM_ACCURACY:.1%}",
        zorder=2,
    )
    ax.annotate(
        f"bare Opus 4.7  {BARE_ARM_ACCURACY:.1%}",
        xy=(0.01, BARE_ARM_ACCURACY),
        xycoords=("axes fraction", "data"),
        textcoords="offset points",
        xytext=(0, 5),
        fontsize=8,
        color=bare_color,
    )

    ax.set_xlabel("Wallclock — ms per MB of evidence  (lower is faster)", fontsize=10)
    if any_accuracy:
        ax.set_ylabel("IR-accuracy  (higher is better)", fontsize=10)
    else:
        ax.set_ylabel("IR-accuracy (pending first eval run)", fontsize=10)
    ax.set_title(
        "Sanctum configurations vs. bare Opus 4.7 baseline\n"
        "(same model · same corpus · same scoring)",
        fontsize=11,
        pad=14,
    )
    ax.set_ylim(bottom=0.0, top=1.12)
    ax.margins(x=0.18)
    ax.legend(fontsize=8, loc="lower right")
    ax.grid(True, alpha=0.3)

    note = (
        f"Controlled comparison: Sanctum arms vs. bare Opus 4.7, N=43 questions × 3 runs, same corpus and scoring.  "
        f"External ref (not directly comparable — different model + eval): "
        f"GPT-4.1 scores {GPT41_TUS4:.1%} on DFIR-Metric Module II (Cherif et al., arXiv:2505.19973, Table 3)."
    )
    fig.text(0.5, -0.02, note, ha="center", fontsize=7, color="#555555", wrap=True)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Chart saved to {out_path}")


def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate the Pareto frontier chart for docs/figures/pareto.png.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="JSON report from measure_wallclock.py, or '-' for stdin (default: stdin)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("docs/figures/pareto.png"),
        help="Output PNG path (default: docs/figures/pareto.png)",
    )
    args = parser.parse_args()

    if args.input == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(args.input).read_text(encoding="utf-8")

    data = json.loads(raw)
    plot(data, args.out)


if __name__ == "__main__":
    _main()

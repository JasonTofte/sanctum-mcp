"""Generate the Pareto frontier chart for docs/figures/pareto.png.

Usage::

    # After running measure_wallclock.py:
    python -m scripts.plot_pareto reports/wallclock.json --out docs/figures/pareto.png

    # Or pipe directly from the measurement script:
    python -m scripts.measure_wallclock --n-runs 5 \\
        | python -m scripts.plot_pareto - --out docs/figures/pareto.png

The chart plots operating configurations as (wallclock, accuracy) points on a
joint cost-quality plane, following the methodology in Kapoor & Narayanan
(arXiv:2407.01502 §2.2) for joint cost-quality reporting.  A reference line at
38.52% annotates GPT-4.1's TUS@4 baseline from the DFIR-Metric benchmark
(Cherif et al., arXiv:2505.19973, Table 3).

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

# GPT-4.1 TUS@4 baseline from Cherif et al. arXiv:2505.19973 Table 3.
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

    # GPT-4.1 reference line
    ax.axhline(
        y=GPT41_TUS4,
        color="#d62728",
        linestyle="--",
        linewidth=1.2,
        label=f"GPT-4.1 TUS@4 = {GPT41_TUS4:.1%} (Cherif et al., arXiv:2505.19973)",
        zorder=2,
    )
    ax.annotate(
        f"GPT-4.1 {GPT41_TUS4:.1%}",
        xy=(0.01, GPT41_TUS4),
        xycoords=("axes fraction", "data"),
        textcoords="offset points",
        xytext=(0, 5),
        fontsize=8,
        color="#d62728",
    )

    ax.set_xlabel("Wallclock — ms per MB of evidence  (lower is faster)", fontsize=10)
    if any_accuracy:
        ax.set_ylabel("IR-accuracy  (higher is better)", fontsize=10)
    else:
        ax.set_ylabel("IR-accuracy (pending first eval run)", fontsize=10)
    ax.set_title(
        "Sanctum: operating configurations vs. GPT-4.1 baseline",
        fontsize=12,
        pad=14,
    )
    # Leave room at top for value labels and at right for C1 name label
    ax.set_ylim(bottom=max(0.0, GPT41_TUS4 - 0.12), top=1.12)
    ax.margins(x=0.18)
    ax.legend(fontsize=8, loc="lower right")
    ax.grid(True, alpha=0.3)

    note = (
        "* partial = cost cap hit before all N=129 runs completed  ·  "
        "Sanctum (host-based pipeline) and GPT-4.1 (general LLM) are different systems; "
        "reference line is a benchmark anchor, not a direct comparison."
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

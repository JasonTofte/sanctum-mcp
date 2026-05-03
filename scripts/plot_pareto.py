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

    fig, ax = plt.subplots(figsize=(7, 5))

    any_accuracy = False
    for config_name, metrics in sorted(data.items()):
        x = float(metrics.get("ms_per_mb", 0))
        accuracy = metrics.get("tus_m")  # None until eval runs

        if accuracy is not None:
            y = float(accuracy)
            any_accuracy = True
        else:
            y = 0.0

        color = _COLORS.get(config_name, "#7f7f7f")
        marker = _MARKERS.get(config_name, "D")

        ax.scatter(
            x,
            y,
            color=color,
            marker=marker,
            s=120,
            zorder=3,
            label=config_name,
        )
        if accuracy is None:
            label_text = f"{config_name}\n(accuracy: pending)"
        elif metrics.get("partial"):
            partial_n = metrics.get("partial_n", "?")
            label_text = f"{config_name}\n(partial N={partial_n})"
        else:
            label_text = config_name
        ax.annotate(
            label_text,
            (x, y),
            textcoords="offset points",
            xytext=(8, 6),
            fontsize=9,
            color=color,
        )

    # GPT-4.1 reference line
    ax.axhline(
        y=GPT41_TUS4,
        color="#d62728",
        linestyle="--",
        linewidth=1.2,
        label=f"GPT-4.1 TUS@4 = {GPT41_TUS4:.1%}\n(Cherif et al., arXiv:2505.19973)",
        zorder=2,
    )
    ax.annotate(
        f"GPT-4.1 {GPT41_TUS4:.1%}",
        xy=(0, GPT41_TUS4),
        xycoords=("axes fraction", "data"),
        textcoords="offset points",
        xytext=(4, 4),
        fontsize=8,
        color="#d62728",
    )

    ax.set_xlabel("Wallclock — ms per MB of evidence\n(lower is faster)", fontsize=10)
    if any_accuracy:
        ax.set_ylabel("IR-accuracy (higher is better)", fontsize=10)
    else:
        ax.set_ylabel("IR-accuracy (pending first eval run)", fontsize=10)
    ax.set_title(
        "Sanctum operating configurations vs. GPT-4.1 baseline\n"
        "Pareto frontier: wallclock cost × accuracy",
        fontsize=11,
    )
    ax.legend(fontsize=8, loc="upper right")
    ax.grid(True, alpha=0.3)

    note = (
        "Note: Sanctum (host-based deterministic pipeline) and GPT-4.1 (general-purpose LLM)\n"
        "are different systems; the reference line is a benchmark anchor, not a direct comparison."
    )
    fig.text(0.5, -0.04, note, ha="center", fontsize=7, color="#555555", wrap=True)

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

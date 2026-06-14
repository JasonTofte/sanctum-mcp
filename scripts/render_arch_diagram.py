#!/usr/bin/env python3
"""Render the ASCII flow diagrams in ``docs/ARCHITECTURE.md`` to a PNG.

Optional-polish artifact for the Devpost gallery. Parses the two fenced
code blocks under "A tool call, end to end" and "A finding", and draws them
as two stacked monospace panels on a dark, brand-coloured canvas. The PNG is
derived from the doc — re-run this after editing the ASCII to keep them in
sync. No new runtime dependency: matplotlib already ships in ``[dev]`` for the
eval figures (see docs/figures/pareto.png).

Usage:  python3 scripts/render_arch_diagram.py
Output: docs/figures/architecture_flow.png
"""
from __future__ import annotations

import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "ARCHITECTURE.md"
OUT = ROOT / "docs" / "figures" / "architecture_flow.png"

# Brand palette (matches the thumbnail concepts: deep navy + cyan accent).
BG = "#0a0e1a"
PANEL = "#111726"
FG = "#d7e0f0"
CYAN = "#22d3ee"
AMBER = "#f5b041"
MUTED = "#7d8aa5"


def _mono_font() -> font_manager.FontProperties:
    """Pick the best available fixed-width font; fall back to mpl's default."""
    for name in ("Menlo", "Monaco", "SF Mono", "DejaVu Sans Mono", "Courier New"):
        try:
            path = font_manager.findfont(
                font_manager.FontProperties(family=name), fallback_to_default=False
            )
            if path:
                return font_manager.FontProperties(fname=path)
        except Exception:
            continue
    return font_manager.FontProperties(family="monospace")


def _fenced_blocks(text: str) -> list[str]:
    """Return the contents of every ``` fenced block, in document order."""
    return re.findall(r"```[^\n]*\n(.*?)```", text, flags=re.DOTALL)


def main() -> None:
    blocks = _fenced_blocks(SRC.read_text(encoding="utf-8"))
    if len(blocks) < 2:
        raise SystemExit(f"expected >=2 fenced blocks in {SRC}, found {len(blocks)}")

    panels = [
        ("A tool call, end to end", blocks[0].rstrip("\n")),
        ("A finding", blocks[1].rstrip("\n")),
    ]
    mono = _mono_font()

    fig, axes = plt.subplots(
        2, 1, figsize=(11, 9), gridspec_kw={"height_ratios": [1.25, 1.0]}
    )
    fig.patch.set_facecolor(BG)
    fig.suptitle(
        "Sanctum — architecture flow",
        color=FG,
        fontproperties=mono,
        fontsize=20,
        fontweight="bold",
        y=0.98,
    )

    for ax, (title, body) in zip(axes, panels):
        ax.set_facecolor(PANEL)
        for spine in ax.spines.values():
            spine.set_edgecolor("#1e2840")
        ax.set_xticks([])
        ax.set_yticks([])
        ax.set_title(
            title, color=CYAN, fontproperties=mono, fontsize=14, loc="left", pad=10
        )
        # Draw line-by-line so the TRUST BOUNDARY line can be amber without a
        # second overlay (a block+overlay drifts in y and double-renders it).
        lines = body.split("\n")
        top, step = 0.90, 0.072
        for i, line in enumerate(lines):
            ax.text(
                0.03,
                top - i * step,
                line,
                transform=ax.transAxes,
                color=AMBER if "TRUST BOUNDARY" in line else FG,
                fontproperties=mono,
                fontsize=11,
                va="top",
                ha="left",
            )

    fig.text(
        0.5,
        0.015,
        "Rendered from docs/ARCHITECTURE.md  ·  everything above the trust "
        "boundary is attacker-written, untrusted bytes",
        color=MUTED,
        fontproperties=mono,
        fontsize=9,
        ha="center",
    )
    fig.subplots_adjust(left=0.04, right=0.96, top=0.9, bottom=0.06, hspace=0.22)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=160, facecolor=BG)
    print(f"wrote {OUT.relative_to(ROOT)}  ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()

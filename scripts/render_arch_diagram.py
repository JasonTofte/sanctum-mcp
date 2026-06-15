#!/usr/bin/env python3
"""Render Sanctum's submission architecture diagram to a PNG.

Draws the component topology the FIND EVIL! brief asks for — agent, SIFT
Workstation tools, MCP server, data sources, and output pipeline — names the
architectural pattern (**Custom MCP Server / FastMCP**), and colour-codes the
guardrails so a judge can tell *architectural* enforcement (code/OS-level,
cyan) apart from *prompt-layer* defence-in-depth (amber). The trust boundary
between attacker-written evidence and the agent is drawn explicitly.

This figure is hand-laid-out rather than parsed from the ASCII flows in
``docs/ARCHITECTURE.md`` (those remain the textual source of truth and are
mirrored under "Component topology" there). No new runtime dependency:
matplotlib already ships in ``[dev]`` for the eval figures.

Usage:  python3 scripts/render_arch_diagram.py
Output: docs/figures/architecture_flow.png
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "figures" / "architecture_flow.png"

# Brand palette (deep navy + cyan accent; amber for the prompt-layer / trust line).
BG = "#0a0e1a"
PANEL = "#111726"
FG = "#d7e0f0"
CYAN = "#22d3ee"  # architectural guardrail (enforced)
AMBER = "#f5b041"  # prompt-layer guardrail (defence-in-depth) + trust boundary
GREEN = "#34d399"  # output / graded finding
MUTED = "#7d8aa5"
EDGE = "#1e2840"


def _mono_font() -> font_manager.FontProperties:
    """Pick the best available fixed-width font; fall back to mpl's default."""
    for name in ("Menlo", "Monaco", "SF Mono", "DejaVu Sans Mono", "Courier New"):
        try:
            path = font_manager.findfont(
                font_manager.FontProperties(family=name), fallback_to_default=False
            )
            if path:
                return font_manager.FontProperties(fname=path)
        except Exception:  # noqa: S112 — probing fonts; fall through to next candidate
            continue
    return font_manager.FontProperties(family="monospace")


def _box(ax, xy, w, h, lines, *, edge, mono, title_color=None, fontsize=9):
    """Draw a rounded panel at axes-fraction xy with monospace text lines."""
    x, y = xy
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle="round,pad=0.006,rounding_size=0.012",
            linewidth=1.6,
            edgecolor=edge,
            facecolor=PANEL,
            transform=ax.transAxes,
            zorder=2,
        )
    )
    n = len(lines)
    # Vertically centre the block of lines inside the box.
    line_h = 0.030
    top = y + h - (h - n * line_h) / 2 - line_h * 0.75
    for i, (txt, bold) in enumerate(lines):
        ax.text(
            x + w / 2,
            top - i * line_h,
            txt,
            transform=ax.transAxes,
            color=(title_color if (bold and title_color) else FG),
            fontproperties=mono,
            fontsize=fontsize + (1 if bold else 0),
            fontweight=("bold" if bold else "normal"),
            ha="center",
            va="center",
            zorder=3,
        )


def _arrow(ax, start, end, *, color, mono, label=None, bidir=False, tag=None):
    style = "<|-|>" if bidir else "-|>"
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            transform=ax.transAxes,
            arrowstyle=style,
            mutation_scale=14,
            linewidth=1.8,
            color=color,
            zorder=1,
        )
    )
    if label:
        mx, my = (start[0] + end[0]) / 2, (start[1] + end[1]) / 2
        ax.text(
            mx,
            my + 0.018,
            label,
            transform=ax.transAxes,
            color=color,
            fontproperties=mono,
            fontsize=7.5,
            ha="center",
            va="bottom",
            zorder=4,
        )
        if tag:
            ax.text(
                mx,
                my - 0.026,
                tag,
                transform=ax.transAxes,
                color=color,
                fontproperties=mono,
                fontsize=7,
                fontweight="bold",
                ha="center",
                va="top",
                zorder=4,
            )


def main() -> None:
    mono = _mono_font()
    fig, ax = plt.subplots(figsize=(13, 8.5))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    fig.text(
        0.5,
        0.965,
        "Sanctum — architecture",
        color=FG,
        fontproperties=mono,
        fontsize=21,
        fontweight="bold",
        ha="center",
    )
    fig.text(
        0.5,
        0.928,
        "Architectural pattern:  Custom MCP Server (FastMCP, official MCP Python SDK)",
        color=CYAN,
        fontproperties=mono,
        fontsize=12,
        ha="center",
    )

    # ---- SIFT Workstation enclosure (host that runs the parsers + server) ----
    ax.add_patch(
        FancyBboxPatch(
            (0.025, 0.345),
            0.635,
            0.475,
            boxstyle="round,pad=0.004,rounding_size=0.012",
            linewidth=1.3,
            edgecolor=MUTED,
            facecolor="none",
            linestyle=(0, (5, 4)),
            transform=ax.transAxes,
            zorder=0,
        )
    )
    ax.text(
        0.040,
        0.795,
        "SIFT Workstation VM  (Ubuntu 22.04 LTS · regipy / python-evtx / windowsprefetch)",
        transform=ax.transAxes,
        color=MUTED,
        fontproperties=mono,
        fontsize=8.5,
        ha="left",
        va="center",
        zorder=1,
    )

    # ---- Data sources ----
    _box(
        ax,
        (0.055, 0.470),
        0.205,
        0.235,
        [
            ("DATA SOURCES", True),
            ("(read-only evidence)", False),
            ("", False),
            ("disk image (E01/dd)", False),
            ("registry hives", False),
            ("EVTX  ·  Prefetch", False),
        ],
        edge=AMBER,
        mono=mono,
        title_color=AMBER,
    )

    # ---- Sanctum MCP server ----
    _box(
        ax,
        (0.350, 0.380),
        0.285,
        0.400,
        [
            ("SANCTUM MCP SERVER", True),
            ("(FastMCP — typed tools, no shell)", False),
            ("", False),
            ("parsers  →  ExecutionEvent", False),
            ("sanitize + <evidence-untrusted>", False),
            ("", False),
            ("claim_finding gate:", False),
            ("  1 fam=DRAFT · 2=CORROBORATED", False),
            ("  3+=FINAL · tamper→demote", False),
            ("", False),
            ("HMAC-chained append-only ledger", False),
        ],
        edge=CYAN,
        mono=mono,
        title_color=CYAN,
    )

    # ---- Agent ----
    _box(
        ax,
        (0.745, 0.470),
        0.205,
        0.235,
        [
            ("AGENT", True),
            ("Claude Code", False),
            ("(Opus 4.7)", False),
            ("", False),
            ("goals, not a", False),
            ("tool sequence", False),
        ],
        edge=FG,
        mono=mono,
        title_color=FG,
    )

    # ---- Output pipeline ----
    _box(
        ax,
        (0.350, 0.085),
        0.285,
        0.175,
        [
            ("OUTPUT PIPELINE", True),
            ("graded finding: DRAFT / CORROBORATED / FINAL", False),
            ("+ signed ledger  ·  optional RFC 3161 stamp", False),
        ],
        edge=GREEN,
        mono=mono,
        title_color=GREEN,
        fontsize=8.5,
    )

    # ---- Arrows ----
    _arrow(
        ax,
        (0.262, 0.587),
        (0.348, 0.587),
        color=AMBER,
        mono=mono,
        label="read-only mount",
        tag="[ARCH]",
    )
    _arrow(
        ax,
        (0.637, 0.587),
        (0.743, 0.587),
        color=CYAN,
        mono=mono,
        label="MCP stdio",
        tag="typed tools only",
        bidir=True,
    )
    _arrow(
        ax,
        (0.492, 0.378),
        (0.492, 0.262),
        color=GREEN,
        mono=mono,
        label="cite audit_ids",
    )

    # ---- Trust boundary (drawn only across the evidence→server gap) ----
    ax.plot(
        [0.305, 0.305],
        [0.470, 0.700],
        transform=ax.transAxes,
        color=AMBER,
        linestyle=(0, (2, 3)),
        linewidth=1.4,
        zorder=1,
    )
    ax.text(
        0.305,
        0.715,
        "TRUST BOUNDARY",
        transform=ax.transAxes,
        color=AMBER,
        fontproperties=mono,
        fontsize=7.5,
        fontweight="bold",
        ha="center",
        va="bottom",
        zorder=4,
    )
    ax.text(
        0.305,
        0.455,
        "◄ untrusted   sanitized ▸",
        transform=ax.transAxes,
        color=AMBER,
        fontproperties=mono,
        fontsize=6.8,
        ha="center",
        va="top",
        zorder=4,
    )

    # ---- Guardrail legend (architectural vs prompt-layer) ----
    ax.text(
        0.055,
        0.300,
        "GUARDRAILS",
        transform=ax.transAxes,
        color=FG,
        fontproperties=mono,
        fontsize=9,
        fontweight="bold",
        ha="left",
        va="top",
    )
    ax.add_patch(
        FancyBboxPatch(
            (0.025, 0.045),
            0.300,
            0.225,
            boxstyle="round,pad=0.004,rounding_size=0.010",
            linewidth=1.4,
            edgecolor=CYAN,
            facecolor=PANEL,
            transform=ax.transAxes,
            zorder=2,
        )
    )
    arch = [
        "ARCHITECTURAL  (enforced by code / OS)",
        "• read-only evidence mount + statvfs check",
        "• typed tools, no shell passthrough",
        "• ≥2-family corroboration gate",
        "• HMAC-chained append-only ledger",
        "• hash-locked dependency install",
    ]
    for i, t in enumerate(arch):
        ax.text(
            0.040,
            0.250 - i * 0.034,
            t,
            transform=ax.transAxes,
            color=CYAN if i == 0 else FG,
            fontproperties=mono,
            fontsize=8 if i == 0 else 7.5,
            fontweight=("bold" if i == 0 else "normal"),
            ha="left",
            va="top",
            zorder=3,
        )
    ax.add_patch(
        FancyBboxPatch(
            (0.345, 0.045),
            0.300,
            0.225,
            boxstyle="round,pad=0.004,rounding_size=0.010",
            linewidth=1.4,
            edgecolor=AMBER,
            facecolor=PANEL,
            transform=ax.transAxes,
            zorder=2,
        )
    )
    prompt = [
        "PROMPT-LAYER  (defence-in-depth only)",
        "• system-prompt role / scope constraint",
        "• <evidence-untrusted> delimiters",
        "",
        "Not load-bearing: the gate's correctness",
        "is a property of a typed function, not of",
        "the model's reasoning.",
    ]
    for i, t in enumerate(prompt):
        ax.text(
            0.360,
            0.250 - i * 0.030,
            t,
            transform=ax.transAxes,
            color=AMBER if i == 0 else (MUTED if i >= 4 else FG),
            fontproperties=mono,
            fontsize=8 if i == 0 else 7.5,
            fontweight=("bold" if i == 0 else "normal"),
            ha="left",
            va="top",
            zorder=3,
        )

    fig.text(
        0.5,
        0.018,
        "[ARCH] = architectural guardrail (cyan)   ·   prompt-layer guardrails "
        "(amber) are defence-in-depth, not the primary control",
        color=MUTED,
        fontproperties=mono,
        fontsize=8,
        ha="center",
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=160, facecolor=BG, bbox_inches="tight", pad_inches=0.25)
    print(f"wrote {OUT.relative_to(ROOT)}  ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()

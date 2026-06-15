#!/usr/bin/env python3
"""Render Sanctum's submission architecture diagram to a PNG.

Draws the component topology the FIND EVIL! brief asks for — agent, SIFT
Workstation tools, MCP server, data sources, and output pipeline — names the
architectural pattern (**Custom MCP Server / FastMCP**), and colour-codes the
guardrails so a judge can tell *architectural* enforcement (code/OS-level,
cyan) apart from *prompt-layer* defence-in-depth (amber). The trust boundary
between attacker-written evidence and the agent is drawn explicitly.

Layout uses explicit, non-overlapping horizontal bands (title, topology,
output, guardrails, footer). Cards have drop shadows, an accent title with a
divider rule, and the topology row is centred on a common axis.

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

# Brand palette: deep navy canvas, cyan = architectural, amber = prompt-layer.
BG = "#0a0e1a"
PANEL = "#111726"
PANEL_HI = "#16203a"
FG = "#dce4f2"
CYAN = "#22d3ee"
AMBER = "#f5b041"
GREEN = "#34d399"
MUTED = "#8492ad"

_BOX = "round,pad=0.006,rounding_size=0.012"


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


def _shadow(ax, x, y, w, h):
    """Soft drop shadow behind a card, for depth."""
    ax.add_patch(
        FancyBboxPatch(
            (x + 0.004, y - 0.006),
            w,
            h,
            boxstyle=_BOX,
            facecolor="#000000",
            edgecolor="none",
            alpha=0.32,
            transform=ax.transAxes,
            zorder=1,
        )
    )


def _card(
    ax,
    x,
    y,
    w,
    h,
    title,
    body,
    *,
    accent,
    mono,
    body_align="center",
    title_fs=11,
    body_fs=9,
    line_h=0.027,
):
    """A panelled card: drop shadow, accent title, divider rule, body lines."""
    _shadow(ax, x, y, w, h)
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle=_BOX,
            facecolor=PANEL,
            edgecolor=accent,
            linewidth=1.9,
            transform=ax.transAxes,
            zorder=2,
        )
    )
    ax.text(
        x + w / 2,
        y + h - 0.032,
        title,
        transform=ax.transAxes,
        color=accent,
        fontproperties=mono,
        fontsize=title_fs,
        fontweight="bold",
        ha="center",
        va="center",
        zorder=3,
    )
    ax.plot(
        [x + 0.022, x + w - 0.022],
        [y + h - 0.050, y + h - 0.050],
        transform=ax.transAxes,
        color=accent,
        linewidth=1.0,
        alpha=0.45,
        zorder=3,
    )
    # Vertically centre the body block in the zone below the divider, so the
    # text fits any card height (short banners and tall component cards alike).
    zone_top, zone_bot = y + h - 0.060, y + 0.022
    block = (len(body) - 1) * line_h
    first = zone_top - max(0.0, (zone_top - zone_bot) - block) / 2
    for i, line in enumerate(body):
        if body_align == "left":
            tx, ha = x + 0.026, "left"
        else:
            tx, ha = x + w / 2, "center"
        ax.text(
            tx,
            first - i * line_h,
            line,
            transform=ax.transAxes,
            color=FG,
            fontproperties=mono,
            fontsize=body_fs,
            ha=ha,
            va="center",
            zorder=3,
        )


def _arrow(ax, start, end, *, color, mono, label=None, sub=None, bidir=False):
    """Arrow with an optional label above and bold sub-label below."""
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            transform=ax.transAxes,
            arrowstyle=("<|-|>" if bidir else "-|>"),
            mutation_scale=16,
            linewidth=2.0,
            color=color,
            zorder=4,
        )
    )
    mx, my = (start[0] + end[0]) / 2, (start[1] + end[1]) / 2
    if label:
        ax.text(
            mx,
            my + 0.015,
            label,
            transform=ax.transAxes,
            color=color,
            fontproperties=mono,
            fontsize=8,
            ha="center",
            va="bottom",
            zorder=5,
        )
    if sub:
        ax.text(
            mx,
            my - 0.017,
            sub,
            transform=ax.transAxes,
            color=color,
            fontproperties=mono,
            fontsize=7.5,
            fontweight="bold",
            ha="center",
            va="top",
            zorder=5,
        )


def _legend(ax, x, y, w, h, *, accent, mono, header, items, footnote=None):
    """Guardrail legend card: accent header + divider, left-aligned items."""
    _shadow(ax, x, y, w, h)
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle=_BOX,
            facecolor=PANEL,
            edgecolor=accent,
            linewidth=1.8,
            transform=ax.transAxes,
            zorder=2,
        )
    )
    pad = 0.024
    ax.text(
        x + pad,
        y + h - 0.044,
        header,
        transform=ax.transAxes,
        color=accent,
        fontproperties=mono,
        fontsize=10,
        fontweight="bold",
        ha="left",
        va="center",
        zorder=3,
    )
    ax.plot(
        [x + pad, x + w - pad],
        [y + h - 0.070, y + h - 0.070],
        transform=ax.transAxes,
        color=accent,
        linewidth=1.0,
        alpha=0.45,
        zorder=3,
    )
    cur = y + h - 0.110
    for it in items:
        ax.text(
            x + pad,
            cur,
            it,
            transform=ax.transAxes,
            color=FG,
            fontproperties=mono,
            fontsize=8.8,
            ha="left",
            va="center",
            zorder=3,
        )
        cur -= 0.046
    if footnote:
        cur -= 0.012
        for fl in footnote:
            ax.text(
                x + pad,
                cur,
                fl,
                transform=ax.transAxes,
                color=MUTED,
                fontproperties=mono,
                fontsize=8,
                ha="left",
                va="center",
                zorder=3,
            )
            cur -= 0.037


def main() -> None:
    mono = _mono_font()
    fig, ax = plt.subplots(figsize=(13, 11))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # ---- Band A: title ----
    fig.text(
        0.5,
        0.963,
        "Sanctum — architecture",
        color=FG,
        fontproperties=mono,
        fontsize=24,
        fontweight="bold",
        ha="center",
    )
    fig.text(
        0.5,
        0.928,
        "Architectural pattern:  Custom MCP Server  (FastMCP · official MCP Python SDK)",
        color=CYAN,
        fontproperties=mono,
        fontsize=12.5,
        ha="center",
    )

    yc = 0.720  # common vertical centre for the topology row

    # ---- SIFT Workstation enclosure + labelled tab ----
    ax.add_patch(
        FancyBboxPatch(
            (0.025, 0.572),
            0.665,
            0.318,
            boxstyle=_BOX,
            linewidth=1.3,
            edgecolor=MUTED,
            facecolor="none",
            linestyle=(0, (5, 4)),
            transform=ax.transAxes,
            zorder=0,
        )
    )
    ax.add_patch(
        FancyBboxPatch(
            (0.045, 0.838),
            0.330,
            0.050,
            boxstyle="round,pad=0.004,rounding_size=0.008",
            facecolor=PANEL_HI,
            edgecolor=MUTED,
            linewidth=1.1,
            transform=ax.transAxes,
            zorder=2,
        )
    )
    ax.text(
        0.210,
        0.872,
        "SIFT Workstation VM · Ubuntu 22.04 LTS",
        transform=ax.transAxes,
        color=FG,
        fontproperties=mono,
        fontsize=8,
        ha="center",
        va="center",
        zorder=3,
    )
    ax.text(
        0.210,
        0.852,
        "regipy · python-evtx · windowsprefetch",
        transform=ax.transAxes,
        color=MUTED,
        fontproperties=mono,
        fontsize=7.5,
        ha="center",
        va="center",
        zorder=3,
    )

    # ---- Topology cards (centred on yc) ----
    dw, dh = 0.192, 0.165
    _card(
        ax,
        0.052,
        yc - dh / 2,
        dw,
        dh,
        "DATA SOURCES",
        ["read-only evidence", "disk image (E01/dd)", "registry hives", "EVTX · Prefetch"],
        accent=AMBER,
        mono=mono,
        line_h=0.026,
    )
    sw, sh = 0.268, 0.250
    _card(
        ax,
        0.392,
        yc - sh / 2,
        sw,
        sh,
        "SANCTUM MCP SERVER",
        [
            "FastMCP · typed · no shell",
            "parsers → ExecutionEvent",
            "sanitize + <evidence-untrusted>",
            "claim_finding gate:",
            "  1=DRAFT  2=CORROB  3+=FINAL",
            "  deception signal → tamper tier",
            "  time-skew >5s → demote 1 tier",
            "HMAC append-only ledger",
        ],
        accent=CYAN,
        mono=mono,
        body_align="left",
        body_fs=8.5,
        line_h=0.022,
    )
    _card(
        ax,
        0.745,
        yc - dh / 2,
        dw,
        dh,
        "AGENT",
        ["Claude Code", "(Opus 4.7)", "goals, not a", "tool sequence"],
        accent=FG,
        mono=mono,
        line_h=0.026,
    )

    # ---- Trust boundary: dashed line in the data → server gap, caption below ----
    ax.plot(
        [0.318, 0.318],
        [0.588, 0.832],
        transform=ax.transAxes,
        color=AMBER,
        linestyle=(0, (3, 3)),
        linewidth=1.5,
        zorder=1,
    )
    ax.text(
        0.318,
        0.582,
        "◄ untrusted        TRUST BOUNDARY        sanitized ►",
        transform=ax.transAxes,
        color=AMBER,
        fontproperties=mono,
        fontsize=7.5,
        fontweight="bold",
        ha="center",
        va="center",
        zorder=5,
    )

    # ---- Topology arrows ----
    _arrow(
        ax, (0.244, yc), (0.392, yc), color=AMBER, mono=mono, label="read-only mount", sub="[ARCH]"
    )
    _arrow(
        ax,
        (0.660, yc),
        (0.745, yc),
        color=CYAN,
        mono=mono,
        label="MCP stdio",
        sub="typed only",
        bidir=True,
    )

    # ---- Band C: output pipeline ----
    _arrow(ax, (0.526, 0.593), (0.526, 0.560), color=GREEN, mono=mono, label="cite audit_ids")
    _card(
        ax,
        0.316,
        0.445,
        0.420,
        0.112,
        "OUTPUT PIPELINE",
        [
            "graded finding:  DRAFT / CORROBORATED / FINAL",
            "+ signed ledger · optional RFC 3161 stamp",
        ],
        accent=GREEN,
        mono=mono,
        body_fs=8.5,
        line_h=0.028,
    )

    # ---- Band D: guardrail taxonomy ----
    ax.text(
        0.050,
        0.420,
        "GUARDRAILS",
        transform=ax.transAxes,
        color=FG,
        fontproperties=mono,
        fontsize=10.5,
        fontweight="bold",
        ha="left",
        va="center",
    )
    _legend(
        ax,
        0.050,
        0.070,
        0.425,
        0.330,
        accent=CYAN,
        mono=mono,
        header="ARCHITECTURAL — enforced by code / OS",
        items=[
            "• read-only evidence mount + statvfs check",
            "• typed tools, no shell passthrough",
            "• ≥2-family corroboration gate",
            "• HMAC-chained append-only ledger",
            "• hash-locked dependency install",
        ],
    )
    _legend(
        ax,
        0.525,
        0.070,
        0.425,
        0.330,
        accent=AMBER,
        mono=mono,
        header="PROMPT-LAYER — defence-in-depth only",
        items=[
            "• system-prompt role / scope constraint",
            "• <evidence-untrusted> delimiters",
        ],
        footnote=[
            "Not load-bearing: the gate's correctness is a",
            "property of a typed function, not of the",
            "model's reasoning.",
        ],
    )

    # ---- Band E: footer ----
    fig.text(
        0.5,
        0.030,
        "[ARCH] = architectural guardrail (cyan)     ·     prompt-layer guardrails "
        "(amber) are defence-in-depth, not the primary control",
        color=MUTED,
        fontproperties=mono,
        fontsize=8.5,
        ha="center",
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=170, facecolor=BG, bbox_inches="tight", pad_inches=0.3)
    print(f"wrote {OUT.relative_to(ROOT)}  ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()

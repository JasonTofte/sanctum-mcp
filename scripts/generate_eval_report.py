"""Generate a self-contained HTML report from a Sanctum EvalReport JSON file.

Usage::

    python scripts/generate_eval_report.py [REPORT_JSON] [--output PATH]

    # With no positional arg: finds the most recent JSON in reports/.
    # With --output omitted: writes eval_report_<run_id>.html.

The report shows:
  - Headline accuracy comparison (sanctum vs bare)
  - Per-arm metric cards (accuracy, false_confidence_rate, precision@CORROBORATED,
    abstention, wallclock, cost)
  - Claim-status distribution (DRAFT / CORROBORATED / FINAL breakdown)
  - Per-family accuracy heatmap (arm × family)
  - Per-question results table (aggregated across runs, with individual run detail)
"""

from __future__ import annotations

import argparse
import html
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean

# ---------------------------------------------------------------------------
# Colour palette (shared with generate_report.py)
# ---------------------------------------------------------------------------
_TIER_COLOR: dict[str, str] = {
    "FINAL": "#22c55e",
    "CORROBORATED": "#3b82f6",
    "DRAFT": "#f59e0b",
    "DRAFT_TAMPER_SUSPECTED": "#ef4444",
}

_FAMILY_ORDER = ["AppCompat", "Explorer", "BAM", "Sysmon", "SysMain"]

_ARM_COLOR = {"sanctum": "#a78bfa", "bare": "#94a3b8"}


def _e(v: object) -> str:
    return html.escape(str(v))


def _pct(v: float | None, decimals: int = 1) -> str:
    if v is None:
        return "—"
    return f"{v * 100:.{decimals}f}%"


def _ms(v: float | None) -> str:
    if v is None:
        return "—"
    if v >= 1000:
        return f"{v / 1000:.1f} s"
    return f"{v:.0f} ms"


def _usd(v: float | None) -> str:
    if v is None:
        return "—"
    return f"${v:.3f}"


# ---------------------------------------------------------------------------
# Headline accuracy bar
# ---------------------------------------------------------------------------

def _render_headline(report: dict) -> str:
    aggs = report["aggregates"]
    sanctum = aggs.get("sanctum", {})
    bare = aggs.get("bare", {})

    s_acc = sanctum.get("accuracy_mean", 0)
    b_acc = bare.get("accuracy_mean", 0)

    def _bar(acc: float, color: str, label: str, arm_color: str) -> str:
        pct_str = _pct(acc, 1)
        bar_w = f"{acc * 100:.1f}%"
        return f"""
<div style="flex:1;min-width:200px">
  <div style="color:{arm_color};font-size:0.8em;font-weight:600;letter-spacing:0.08em;
              text-transform:uppercase;margin-bottom:6px">{_e(label)}</div>
  <div style="font-size:3em;font-weight:800;color:#f1f5f9;line-height:1">{_e(pct_str)}</div>
  <div style="background:#1e293b;border-radius:4px;height:8px;margin:8px 0">
    <div style="background:{color};width:{bar_w};height:8px;border-radius:4px;
                transition:width 0.3s"></div>
  </div>
  <div style="color:#64748b;font-size:0.8em">accuracy (N={report['n_questions']} q × {report['n_runs_per_q']} runs)</div>
</div>"""

    delta = s_acc - b_acc
    delta_str = f"+{_pct(delta, 1)}" if delta >= 0 else _pct(delta, 1)
    delta_color = "#22c55e" if delta >= 0 else "#ef4444"

    return f"""
<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;
            padding:24px;margin-bottom:24px">
  <div style="display:flex;gap:32px;flex-wrap:wrap;align-items:flex-end">
    {_bar(s_acc, "#a78bfa", "Sanctum", "#a78bfa")}
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;
                padding-bottom:20px">
      <div style="color:{delta_color};font-size:1.6em;font-weight:700">{_e(delta_str)}</div>
      <div style="color:#64748b;font-size:0.75em">vs bare</div>
    </div>
    {_bar(b_acc, "#94a3b8", "Bare LLM", "#94a3b8")}
  </div>
</div>"""


# ---------------------------------------------------------------------------
# Metric cards
# ---------------------------------------------------------------------------

def _metric_row(label: str, s_val: str, b_val: str, good: str = "high") -> str:
    return f"""
<tr style="border-bottom:1px solid #1e293b">
  <td style="color:#94a3b8;font-size:0.85em;padding:8px 0">{_e(label)}</td>
  <td style="text-align:right;color:#a78bfa;font-weight:600;font-size:0.95em;padding:8px 12px">{_e(s_val)}</td>
  <td style="text-align:right;color:#94a3b8;font-size:0.95em;padding:8px 0">{_e(b_val)}</td>
</tr>"""


def _render_metrics(report: dict) -> str:
    s = report["aggregates"].get("sanctum", {})
    b = report["aggregates"].get("bare", {})

    rows = [
        _metric_row("Accuracy (mean ± std)",
                    f"{_pct(s.get('accuracy_mean'))} ± {_pct(s.get('accuracy_std'))}",
                    f"{_pct(b.get('accuracy_mean'))} ± {_pct(b.get('accuracy_std'))}"),
        _metric_row("precision@CORROBORATED",
                    _pct(s.get("precision_at_corroborated")),
                    "— (no tier)"),
        _metric_row("False confidence rate",
                    _pct(s.get("false_confidence_rate")),
                    "—"),
        _metric_row("Abstention rate",
                    _pct(s.get("abstention_rate")),
                    "—"),
        _metric_row("Bare confident rate",
                    "—",
                    _pct(b.get("bare_confident_rate"))),
        _metric_row("Mean wallclock",
                    _ms(s.get("mean_wallclock_ms")),
                    _ms(b.get("mean_wallclock_ms"))),
        _metric_row("Mean tokens in",
                    f"{s.get('mean_tokens_in', 0):,.0f}",
                    f"{b.get('mean_tokens_in', 0):,.0f}"),
        _metric_row("Total cost",
                    _usd(s.get("total_cost_usd")),
                    _usd(b.get("total_cost_usd"))),
    ]

    return f"""
<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;
            padding:20px;margin-bottom:24px;overflow-x:auto">
  <table style="width:100%;border-collapse:collapse">
    <thead>
      <tr style="border-bottom:2px solid #334155">
        <th style="text-align:left;padding:8px 0;color:#64748b;font-size:0.78em;
                   font-weight:500;letter-spacing:0.08em;text-transform:uppercase">Metric</th>
        <th style="text-align:right;padding:8px 12px;color:#a78bfa;font-size:0.78em;
                   font-weight:600;letter-spacing:0.08em;text-transform:uppercase">Sanctum</th>
        <th style="text-align:right;padding:8px 0;color:#94a3b8;font-size:0.78em;
                   font-weight:500;letter-spacing:0.08em;text-transform:uppercase">Bare LLM</th>
      </tr>
    </thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>"""


# ---------------------------------------------------------------------------
# Claim-status distribution
# ---------------------------------------------------------------------------

def _render_claim_status(report: dict) -> str:
    rows = report["per_question"]
    sanctum_rows = [r for r in rows if r["arm"] == "sanctum" and r["claim_status"]]
    total = len(sanctum_rows) or 1

    counts: dict[str, int] = defaultdict(int)
    for r in sanctum_rows:
        counts[r["claim_status"]] += 1

    order = ["FINAL", "CORROBORATED", "DRAFT", "DRAFT_TAMPER_SUSPECTED"]
    bars = []
    for tier in order:
        n = counts.get(tier, 0)
        if n == 0:
            continue
        color = _TIER_COLOR.get(tier, "#94a3b8")
        frac = n / total
        bars.append(
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">'
            f'<div style="width:120px;color:{color};font-size:0.82em;font-weight:600">{_e(tier)}</div>'
            f'<div style="flex:1;background:#0f172a;border-radius:4px;height:20px;position:relative">'
            f'<div style="background:{color}33;border:1px solid {color}60;width:{frac*100:.1f}%;'
            f'height:20px;border-radius:4px;display:flex;align-items:center;padding:0 8px">'
            f'<span style="color:{color};font-size:0.8em;font-weight:600">{n} ({_pct(frac, 0)})</span>'
            f"</div></div></div>"
        )

    return f"""
<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;
            padding:20px;margin-bottom:24px">
  <h3 style="margin:0 0 16px 0;color:#94a3b8;font-size:0.8em;font-weight:500;
             letter-spacing:0.08em;text-transform:uppercase">
    Sanctum Claim-Status Distribution
    <span style="color:#64748b;font-weight:400;text-transform:none;letter-spacing:0">
      ({total} sanctum rows)
    </span>
  </h3>
  {"".join(bars)}
</div>"""


# ---------------------------------------------------------------------------
# Per-family accuracy heatmap
# ---------------------------------------------------------------------------

def _render_family_heatmap(report: dict) -> str:
    rows = report["per_question"]

    # {(arm, family): [correct bools]}
    bucket: dict[tuple[str, str], list[bool]] = defaultdict(list)
    for r in rows:
        bucket[(r["arm"], r["family"])].append(r["correct"])

    arms = report["arms"]
    # Use whatever families appear in data, ordered by _FAMILY_ORDER then alphabetical
    all_families = sorted(set(r["family"] for r in rows),
                          key=lambda f: (_FAMILY_ORDER.index(f) if f in _FAMILY_ORDER else 99, f))

    # Header row
    header_cells = '<th style="padding:8px 12px;color:#64748b;font-size:0.78em;text-align:left">Family</th>'
    for arm in arms:
        color = _ARM_COLOR.get(arm, "#94a3b8")
        header_cells += (
            f'<th style="padding:8px 12px;color:{color};font-size:0.78em;'
            f'font-weight:600;text-align:center;letter-spacing:0.05em;'
            f'text-transform:uppercase">{_e(arm)}</th>'
        )

    body_rows = []
    for fam in all_families:
        cells = f'<td style="padding:8px 12px;color:#e2e8f0;font-size:0.85em">{_e(fam)}</td>'
        for arm in arms:
            vals = bucket.get((arm, fam), [])
            if not vals:
                cells += '<td style="padding:8px 12px;text-align:center;color:#334155">—</td>'
                continue
            acc = mean(vals)
            bg = f"rgba({int(167*(1-acc)+20*acc)},{int(139*(1-acc)+184*acc)},{int(250*(1-acc)+100*acc)},0.15)"
            color = "#a78bfa" if arm == "sanctum" else "#94a3b8"
            cells += (
                f'<td style="padding:8px 12px;text-align:center;background:{bg};'
                f'color:{color};font-weight:600;font-size:0.9em">{_pct(acc, 0)}</td>'
            )
        body_rows.append(f'<tr style="border-bottom:1px solid #1e293b">{cells}</tr>')

    return f"""
<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;
            padding:20px;margin-bottom:24px;overflow-x:auto">
  <h3 style="margin:0 0 16px 0;color:#94a3b8;font-size:0.8em;font-weight:500;
             letter-spacing:0.08em;text-transform:uppercase">Per-Family Accuracy</h3>
  <table style="width:100%;border-collapse:collapse">
    <thead><tr style="border-bottom:2px solid #334155">{header_cells}</tr></thead>
    <tbody>{"".join(body_rows)}</tbody>
  </table>
</div>"""


# ---------------------------------------------------------------------------
# Per-question results table
# ---------------------------------------------------------------------------

def _render_per_question(report: dict) -> str:
    rows = report["per_question"]
    arms = report["arms"]

    # Group: {q_id: {arm: [row, ...]}}
    by_q: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        by_q[r["q_id"]][r["arm"]].append(r)

    # Stable question ordering: preserve first-seen order
    seen_order: list[str] = []
    seen_set: set[str] = set()
    for r in rows:
        if r["q_id"] not in seen_set:
            seen_order.append(r["q_id"])
            seen_set.add(r["q_id"])

    header_cells = (
        '<th style="padding:8px;color:#64748b;font-size:0.78em;text-align:left">Q-ID</th>'
        '<th style="padding:8px;color:#64748b;font-size:0.78em;text-align:left">Family</th>'
    )
    for arm in arms:
        color = _ARM_COLOR.get(arm, "#94a3b8")
        header_cells += (
            f'<th style="padding:8px;color:{color};font-size:0.78em;text-align:center;'
            f'font-weight:600;text-transform:uppercase">{_e(arm)}</th>'
        )
    header_cells += '<th style="padding:8px;color:#64748b;font-size:0.78em;text-align:left">Expected</th>'

    body_rows = []
    for q_id in seen_order:
        arm_data = by_q[q_id]
        # Get family from any row
        fam = next(iter(arm_data.values()))[0]["family"]

        cells = (
            f'<td style="padding:8px;font-family:monospace;color:#7dd3fc;font-size:0.8em">{_e(q_id)}</td>'
            f'<td style="padding:8px;color:#94a3b8;font-size:0.82em">{_e(fam)}</td>'
        )

        for arm in arms:
            arm_rows = arm_data.get(arm, [])
            if not arm_rows:
                cells += '<td style="padding:8px;text-align:center;color:#334155">—</td>'
                continue

            n_correct = sum(1 for r in arm_rows if r["correct"])
            n_total = len(arm_rows)
            acc = n_correct / n_total

            # Claim status summary for sanctum arm
            if arm == "sanctum":
                statuses = [r["claim_status"] for r in arm_rows if r["claim_status"]]
                status_counts: dict[str, int] = defaultdict(int)
                for s in statuses:
                    status_counts[s] += 1
                status_str = " ".join(
                    f'<span style="color:{_TIER_COLOR.get(s,"#94a3b8")};font-size:0.72em">'
                    f'{_e(s[:4])}×{n}</span>'
                    for s, n in sorted(status_counts.items())
                )
            else:
                status_str = ""

            dot_color = "#22c55e" if acc == 1.0 else ("#f59e0b" if acc > 0 else "#ef4444")
            arm_color = _ARM_COLOR.get(arm, "#94a3b8")

            cells += (
                f'<td style="padding:8px;text-align:center">'
                f'<span style="color:{dot_color};font-weight:700;font-size:0.9em">'
                f'{n_correct}/{n_total}</span>'
                f'<div style="margin-top:2px">{status_str}</div>'
                f'</td>'
            )

        # Expected pattern (truncated)
        any_row = next(iter(arm_data.values()))[0]
        pattern = any_row["expected_pattern"]
        pattern_display = pattern[:40] + "…" if len(pattern) > 40 else pattern

        cells += (
            f'<td style="padding:8px;font-family:monospace;color:#64748b;font-size:0.78em">'
            f'{_e(pattern_display)}</td>'
        )

        body_rows.append(f'<tr style="border-bottom:1px solid #1e293b">{cells}</tr>')

    return f"""
<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;
            padding:20px;margin-bottom:24px;overflow-x:auto">
  <h3 style="margin:0 0 4px 0;color:#94a3b8;font-size:0.8em;font-weight:500;
             letter-spacing:0.08em;text-transform:uppercase">Per-Question Results</h3>
  <p style="color:#64748b;font-size:0.78em;margin:0 0 16px 0">
    Scores show correct/total runs. Sanctum tier badges: CORR=CORROBORATED, DRAF=DRAFT, FINA=FINAL.
  </p>
  <table style="width:100%;border-collapse:collapse;font-size:0.85em">
    <thead><tr style="border-bottom:2px solid #334155">{header_cells}</tr></thead>
    <tbody>{"".join(body_rows)}</tbody>
  </table>
</div>"""


# ---------------------------------------------------------------------------
# Run metadata strip
# ---------------------------------------------------------------------------

def _render_metadata(report: dict) -> str:
    partial_badge = ""
    if report.get("partial"):
        reason = _e(report.get("halt_reason") or "unknown")
        partial_badge = (
            f'<span style="background:#450a0a;color:#ef4444;border-radius:4px;'
            f'padding:3px 10px;font-size:0.78em;font-weight:600;margin-left:8px">'
            f'PARTIAL — {reason}</span>'
        )

    duration_s = ""
    try:
        from datetime import datetime, timezone
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        t0 = datetime.strptime(report["started_at_utc"], fmt).replace(tzinfo=timezone.utc)
        t1 = datetime.strptime(report["ended_at_utc"], fmt).replace(tzinfo=timezone.utc)
        secs = int((t1 - t0).total_seconds())
        duration_s = f" · {secs // 60}m {secs % 60}s"
    except Exception:
        pass

    fields = [
        ("Run ID", report.get("run_id", "—")),
        ("Model", report.get("model_id", "—")),
        ("Sanctum", report.get("sanctum_version", "—")),
        ("Questions", f"{report.get('n_questions','—')} × {report.get('n_runs_per_q','—')} runs"),
        ("Cost", _usd(report.get("cost_usd"))),
        ("Started", report.get("started_at_utc", "—")),
        ("Duration", duration_s.strip(" · ") if duration_s else "—"),
    ]
    pills = "".join(
        f'<span style="color:#64748b;font-size:0.8em">{_e(k)}: '
        f'<span style="color:#94a3b8">{_e(v)}</span></span>'
        for k, v in fields
    )

    return f"""
<div style="background:#1e293b;border:1px solid #334155;border-radius:8px;
            padding:12px 16px;margin-bottom:24px;display:flex;gap:16px;
            flex-wrap:wrap;align-items:center">
  {pills}
  {partial_badge}
</div>"""


# ---------------------------------------------------------------------------
# Full page
# ---------------------------------------------------------------------------

def generate_html(report: dict) -> str:
    from datetime import datetime, timezone
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    run_id = report.get("run_id", "unknown")

    body = (
        _render_headline(report)
        + _render_metadata(report)
        + _render_metrics(report)
        + _render_claim_status(report)
        + _render_family_heatmap(report)
        + _render_per_question(report)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sanctum Eval Report — {_e(run_id)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: #0f172a;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    font-size: 15px;
    line-height: 1.6;
  }}
  .container {{ max-width: 1024px; margin: 0 auto; padding: 32px 24px; }}
  code {{ font-family: "SF Mono", "Fira Code", "Cascadia Code", monospace; }}
  @media (max-width: 600px) {{ .container {{ padding: 16px 12px; }} }}
</style>
</head>
<body>
<div class="container">
  <div style="margin-bottom:24px">
    <h1 style="margin:0 0 4px 0;font-size:1.5em;font-weight:700;
               background:linear-gradient(90deg,#a78bfa,#7dd3fc);
               -webkit-background-clip:text;-webkit-text-fill-color:transparent;
               background-clip:text">
      Sanctum Eval Report
    </h1>
    <div style="color:#64748b;font-size:0.82em">
      Generated {_e(generated)} &nbsp;·&nbsp; DFIR-Metric subset accuracy benchmark
    </div>
  </div>
  {body}
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _latest_report(reports_dir: Path) -> Path | None:
    candidates = sorted(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for c in candidates:
        if c.name != "wallclock.json":
            return c
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", nargs="?", type=Path,
                        help="EvalReport JSON path (default: most recent in reports/)")
    parser.add_argument("--output", "-o", type=Path,
                        help="Output HTML file (default: eval_report_<run_id>.html)")
    args = parser.parse_args()

    if args.report:
        report_path = args.report
    else:
        report_path = _latest_report(Path("reports"))
        if report_path is None:
            print("No report JSON found in reports/. Pass a path explicitly.")
            raise SystemExit(1)
        print(f"Using latest report: {report_path}")

    report = json.loads(report_path.read_text(encoding="utf-8"))

    run_id = report.get("run_id", "unknown")
    out = args.output or Path(f"eval_report_{run_id}.html")

    page = generate_html(report)
    out.write_text(page, encoding="utf-8")
    print(f"Report written to {out}  ({len(page):,} bytes)")


if __name__ == "__main__":
    main()

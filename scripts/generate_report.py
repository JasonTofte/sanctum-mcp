"""Generate a self-contained HTML case report from the Sanctum audit ledger.

Usage::

    python scripts/generate_report.py [--ledger PATH] [--output PATH] [--case CASE_ID]

    # Uses SANCTUM_LEDGER_PATH env var (or default) when --ledger is omitted.
    # Writes sanctum_report_<timestamp>.html when --output is omitted.
    # Filters to one case when --case is supplied; otherwise shows all cases.

HMAC chain verification requires SANCTUM_LEDGER_HMAC_KEY to be set.
If the key is absent the chain-status badge reads "UNVERIFIED (key absent)"
rather than crashing.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Resolve the project root so we can import sanctum even when running the
# script directly (not via ``python -m``).
_HERE = Path(__file__).resolve()
_SRC = _HERE.parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sanctum.audit import _ledger_path, verify_chain  # noqa: E402
from sanctum.families import ALL_FAMILIES  # noqa: E402

# ---------------------------------------------------------------------------
# Tier display metadata
# ---------------------------------------------------------------------------
_TIER_META: dict[str, dict[str, str]] = {
    "FINAL": {"color": "#22c55e", "label": "FINAL", "badge_bg": "#14532d"},
    "CORROBORATED": {"color": "#3b82f6", "label": "CORROBORATED", "badge_bg": "#1e3a5f"},
    "DRAFT": {"color": "#f59e0b", "label": "DRAFT", "badge_bg": "#451a03"},
    "DRAFT_TAMPER_SUSPECTED": {"color": "#ef4444", "label": "DRAFT — TAMPER SUSPECTED", "badge_bg": "#450a0a"},
}
_DEFAULT_TIER_META = {"color": "#94a3b8", "label": "UNKNOWN", "badge_bg": "#1e293b"}

_FAMILY_ORDER = [
    "AppCompat",
    "Explorer/NTUSER",
    "Background-service",
    "Kernel-ETW",
    "SysMain",
]

# ---------------------------------------------------------------------------
# Ledger reading
# ---------------------------------------------------------------------------

def _read_ledger(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def _chain_status(path: Path) -> tuple[str, str]:
    """Return (status_text, css_color) for the HMAC chain."""
    key = os.environ.get("SANCTUM_LEDGER_HMAC_KEY")
    if not key:
        return "UNVERIFIED (key absent)", "#f59e0b"
    try:
        ok, bad_line, bad_id = verify_chain(path)
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {exc}", "#ef4444"
    if ok:
        return "VERIFIED ✓", "#22c55e"
    detail = f"line {bad_line}" + (f", audit_id {bad_id[:8]}…" if bad_id else "")
    return f"TAMPERED at {detail}", "#ef4444"


# ---------------------------------------------------------------------------
# Data grouping
# ---------------------------------------------------------------------------

def _group_by_case(entries: list[dict], case_filter: str | None) -> dict[str, dict]:
    """Return {case_id: {findings: [...], evidence: [...]}}."""
    cases: dict[str, dict] = {}
    for entry in entries:
        cid = entry.get("case_id", "unknown")
        if case_filter and cid != case_filter:
            continue
        if cid not in cases:
            cases[cid] = {"findings": [], "evidence": []}
        if entry.get("tool") == "claim_finding":
            cases[cid]["findings"].append(entry)
        else:
            cases[cid]["evidence"].append(entry)
    return cases


def _families_hit(evidence: list[dict]) -> set[str]:
    from sanctum.families import TOOL_TO_FAMILY
    hit = set()
    for e in evidence:
        tool = e.get("tool", "")
        if tool in TOOL_TO_FAMILY:
            hit.add(TOOL_TO_FAMILY[tool])
    return hit


# ---------------------------------------------------------------------------
# HTML rendering helpers
# ---------------------------------------------------------------------------

def _e(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text))


def _short_id(audit_id: str) -> str:
    return audit_id[:8] + "…" if len(audit_id) > 8 else audit_id


def _render_family_matrix(families_hit: set[str]) -> str:
    cells = []
    for fam in _FAMILY_ORDER:
        hit = fam in families_hit
        bg = "#14532d" if hit else "#1e293b"
        border = "#22c55e" if hit else "#334155"
        icon = "✓" if hit else "–"
        icon_color = "#22c55e" if hit else "#475569"
        cells.append(
            f'<div style="background:{bg};border:1px solid {border};border-radius:6px;'
            f'padding:8px 12px;display:flex;align-items:center;gap:8px;">'
            f'<span style="color:{icon_color};font-weight:bold;font-size:1.1em">{icon}</span>'
            f'<span style="color:#e2e8f0;font-size:0.85em">{_e(fam)}</span>'
            f"</div>"
        )
    return (
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;margin-bottom:20px">'
        + "".join(cells)
        + "</div>"
    )


def _render_finding(entry: dict) -> str:
    finding = entry.get("input_ref", {}).get("finding", {})
    tier = finding.get("tier", entry.get("tier", "UNKNOWN"))
    meta = _TIER_META.get(tier, _DEFAULT_TIER_META)
    c_scale = finding.get("c_scale", "–")
    hypothesis = finding.get("hypothesis", "–")
    n_fam = finding.get("n_distinct_families", "–")
    families = finding.get("families", [])
    basis = finding.get("confirmation_basis", "–")
    demoted_tamper = finding.get("demoted_for_tamper", False)
    demoted_temporal = finding.get("demoted_for_temporal", False)
    audit_ids = finding.get("audit_ids", [])
    finding_audit_id = entry.get("audit_id", "–")
    ts = entry.get("ts", "–")

    demotion_tags = ""
    if demoted_tamper:
        demotion_tags += '<span style="background:#450a0a;color:#ef4444;border-radius:4px;padding:2px 8px;font-size:0.75em;margin-left:6px">TAMPER DEMOTION</span>'
    if demoted_temporal:
        demotion_tags += '<span style="background:#451a03;color:#f97316;border-radius:4px;padding:2px 8px;font-size:0.75em;margin-left:6px">TEMPORAL DEMOTION</span>'

    cited_ids = "".join(
        f'<code style="background:#0f172a;color:#94a3b8;border-radius:3px;padding:1px 5px;margin:2px;display:inline-block;font-size:0.8em">{_e(_short_id(aid))}</code>'
        for aid in audit_ids
    )

    family_tags = "".join(
        f'<span style="background:#1e3a5f;color:#93c5fd;border-radius:4px;padding:2px 8px;font-size:0.8em;margin:2px">{_e(f)}</span>'
        for f in families
    )

    return f"""
<div style="background:#1e293b;border:1px solid {meta['color']}40;border-left:4px solid {meta['color']};
     border-radius:8px;padding:16px;margin-bottom:12px">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
    <span style="background:{meta['badge_bg']};color:{meta['color']};border:1px solid {meta['color']}60;
          border-radius:6px;padding:4px 12px;font-weight:700;font-size:0.9em;letter-spacing:0.05em">
      {_e(meta['label'])}
    </span>
    <span style="color:#94a3b8;font-size:0.85em">C-Scale: <strong style="color:#e2e8f0">{_e(c_scale)}</strong></span>
    <span style="color:#94a3b8;font-size:0.85em">Families: <strong style="color:#e2e8f0">{_e(str(n_fam))}</strong></span>
    {demotion_tags}
  </div>
  <p style="color:#f1f5f9;margin:0 0 10px 0;font-size:0.95em"><strong>Hypothesis:</strong> {_e(hypothesis)}</p>
  <div style="margin-bottom:8px">{family_tags}</div>
  <div style="color:#64748b;font-size:0.78em;margin-top:8px">
    <span>basis: {_e(basis)}</span>
    &nbsp;·&nbsp;
    <span>finding audit_id: <code style="color:#94a3b8">{_e(_short_id(finding_audit_id))}</code></span>
    &nbsp;·&nbsp;
    <span>ts: {_e(ts)}</span>
  </div>
  <div style="margin-top:8px">
    <span style="color:#64748b;font-size:0.78em">cited evidence: </span>{cited_ids}
  </div>
</div>"""


def _render_evidence_table(evidence: list[dict]) -> str:
    if not evidence:
        return '<p style="color:#64748b;font-style:italic">No evidence tool calls recorded.</p>'

    rows = []
    for e in evidence:
        tool = e.get("tool", "–")
        ts = e.get("ts", "–")
        audit_id = _short_id(e.get("audit_id", "–"))
        rowcount = e.get("rowcount", "–")
        elapsed = e.get("elapsed_ms")
        elapsed_str = f"{elapsed} ms" if elapsed is not None else "–"
        pre = e.get("pre_sanitization_sha256", "")
        post = e.get("post_sanitization_sha256", "")
        san_flag = ""
        if pre and post and pre != post:
            san_flag = '<span style="color:#f97316;font-size:0.75em" title="Sanitization stripped content">⚠ stripped</span>'
        elif pre and post:
            san_flag = '<span style="color:#22c55e;font-size:0.75em">clean</span>'

        rows.append(
            f'<tr>'
            f'<td><code style="color:#7dd3fc">{_e(tool)}</code></td>'
            f'<td style="color:#94a3b8;font-size:0.85em">{_e(ts)}</td>'
            f'<td><code style="color:#64748b;font-size:0.8em">{_e(audit_id)}</code></td>'
            f'<td style="text-align:right;color:#e2e8f0">{_e(str(rowcount))}</td>'
            f'<td style="text-align:right;color:#94a3b8">{_e(elapsed_str)}</td>'
            f'<td style="text-align:center">{san_flag}</td>'
            f'</tr>'
        )

    return f"""
<div style="overflow-x:auto">
<table style="width:100%;border-collapse:collapse;font-size:0.85em">
  <thead>
    <tr style="border-bottom:1px solid #334155">
      <th style="text-align:left;padding:8px;color:#64748b;font-weight:500">Tool</th>
      <th style="text-align:left;padding:8px;color:#64748b;font-weight:500">Timestamp</th>
      <th style="text-align:left;padding:8px;color:#64748b;font-weight:500">Audit ID</th>
      <th style="text-align:right;padding:8px;color:#64748b;font-weight:500">Rows</th>
      <th style="text-align:right;padding:8px;color:#64748b;font-weight:500">Elapsed</th>
      <th style="text-align:center;padding:8px;color:#64748b;font-weight:500">Sanitization</th>
    </tr>
  </thead>
  <tbody>
    {"".join(f'<tr style="border-bottom:1px solid #1e293b">' + r[4:] for r in rows)}
  </tbody>
</table>
</div>"""


def _render_case(case_id: str, data: dict) -> str:
    findings = data["findings"]
    evidence = data["evidence"]
    families_hit = _families_hit(evidence)

    findings_html = "".join(_render_finding(f) for f in findings) if findings else (
        '<p style="color:#64748b;font-style:italic">No findings recorded for this case.</p>'
    )

    return f"""
<section style="margin-bottom:40px">
  <h2 style="color:#f1f5f9;font-size:1.2em;font-weight:600;margin:0 0 4px 0;
             border-bottom:1px solid #334155;padding-bottom:8px">
    Case: <span style="color:#7dd3fc;font-family:monospace">{_e(case_id)}</span>
    <span style="color:#64748b;font-size:0.75em;font-weight:400;margin-left:12px">
      {len(evidence)} evidence call{"s" if len(evidence) != 1 else ""} &nbsp;·&nbsp;
      {len(findings)} finding{"s" if len(findings) != 1 else ""}
    </span>
  </h2>

  <h3 style="color:#94a3b8;font-size:0.85em;font-weight:500;letter-spacing:0.08em;
             text-transform:uppercase;margin:16px 0 8px 0">Family Coverage</h3>
  {_render_family_matrix(families_hit)}

  <h3 style="color:#94a3b8;font-size:0.85em;font-weight:500;letter-spacing:0.08em;
             text-transform:uppercase;margin:16px 0 8px 0">Findings</h3>
  {findings_html}

  <h3 style="color:#94a3b8;font-size:0.85em;font-weight:500;letter-spacing:0.08em;
             text-transform:uppercase;margin:20px 0 8px 0">Audit Ledger</h3>
  {_render_evidence_table(evidence)}
</section>"""


# ---------------------------------------------------------------------------
# Full page assembly
# ---------------------------------------------------------------------------

def generate_html(ledger_path: Path, case_filter: str | None) -> str:
    entries = _read_ledger(ledger_path)
    chain_status, chain_color = _chain_status(ledger_path)
    cases = _group_by_case(entries, case_filter)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if not cases:
        body = '<p style="color:#64748b;font-style:italic">No entries found in ledger.</p>'
        if case_filter:
            body = f'<p style="color:#64748b">No entries for case <code>{_e(case_filter)}</code>.</p>'
    else:
        body = "".join(_render_case(cid, data) for cid, data in sorted(cases.items()))

    entry_count = len(entries)
    ledger_display = _e(str(ledger_path))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sanctum Case Report</title>
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
  .container {{ max-width: 960px; margin: 0 auto; padding: 32px 24px; }}
  code {{ font-family: "SF Mono", "Fira Code", "Cascadia Code", monospace; }}
  table td {{ padding: 8px 8px; }}
  table th {{ padding: 8px 8px; }}
  @media (max-width: 600px) {{
    .container {{ padding: 16px 12px; }}
  }}
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div style="display:flex;align-items:flex-start;justify-content:space-between;
              flex-wrap:wrap;gap:12px;margin-bottom:32px">
    <div>
      <h1 style="margin:0 0 4px 0;font-size:1.5em;font-weight:700;
                 background:linear-gradient(90deg,#7dd3fc,#a78bfa);
                 -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                 background-clip:text">
        Sanctum Case Report
      </h1>
      <div style="color:#64748b;font-size:0.82em">
        Generated {_e(generated_at)} &nbsp;·&nbsp;
        {_e(str(entry_count))} ledger entr{"ies" if entry_count != 1 else "y"} &nbsp;·&nbsp;
        <span style="font-family:monospace;font-size:0.95em">{ledger_display}</span>
      </div>
    </div>
    <div style="background:#1e293b;border:1px solid {chain_color}40;border-radius:8px;
                padding:10px 16px;display:flex;align-items:center;gap:8px">
      <span style="color:{chain_color};font-weight:700;font-size:0.85em;
                   letter-spacing:0.05em">HMAC CHAIN</span>
      <span style="color:{chain_color};font-size:0.85em">{_e(chain_status)}</span>
    </div>
  </div>

  <!-- C-Scale legend -->
  <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;
              padding:12px 16px;margin-bottom:32px;display:flex;gap:16px;flex-wrap:wrap;
              align-items:center">
    <span style="color:#64748b;font-size:0.8em;font-weight:500;letter-spacing:0.06em;
                 text-transform:uppercase">Casey C-Scale</span>
    {"".join(
        f'<span style="font-size:0.82em;color:{m["color"]}">'
        f'<strong>{_e(c)}</strong> {_e(m["label"])}</span>'
        for c, m in [("C5",{"color":"#22c55e","label":"FINAL"}),
                     ("C4",{"color":"#3b82f6","label":"CORROBORATED"}),
                     ("C2",{"color":"#f59e0b","label":"DRAFT"}),
                     ("C0",{"color":"#ef4444","label":"DRAFT — TAMPER SUSPECTED"})]
    )}
  </div>

  <!-- Cases -->
  {body}
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ledger", type=Path, help="Path to the JSONL ledger (overrides SANCTUM_LEDGER_PATH)")
    parser.add_argument("--output", type=Path, help="Output HTML file (default: sanctum_report_<timestamp>.html)")
    parser.add_argument("--case", help="Filter to a single case ID")
    args = parser.parse_args()

    ledger = args.ledger or _ledger_path()
    if args.output:
        out = args.output
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = Path(f"sanctum_report_{ts}.html")

    report = generate_html(ledger, args.case)
    out.write_text(report, encoding="utf-8")
    print(f"Report written to {out}  ({len(report):,} bytes)")


if __name__ == "__main__":
    main()

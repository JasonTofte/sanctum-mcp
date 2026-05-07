#!/usr/bin/env python3
"""DFIR investigation runner — analyst-readable summaries of Sanctum tool output."""
from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, "src")

CASE = "real_c2agent_001"
TARGET = "c2agent"
SEP = "=" * 70


def extract_audit_id(text: str) -> str | None:
    m = re.search(r'"audit_id":\s*"([0-9a-f-]{36})"', text)
    return m.group(1) if m else None


def extract_payload_path(text: str) -> str | None:
    """Pull the first absolute path from a payload_ref block."""
    m = re.search(r'"payload_ref"[^}]*"path":\s*"([^"]+)"', text, re.S)
    return m.group(1) if m else None


def extract_rowcount(text: str) -> str:
    m = re.search(r'"rowcount":\s*(\d+)', text)
    return m.group(1) if m else "?"


def load_payload_rows(path: str | None) -> list[dict]:
    if not path or not Path(path).exists():
        return []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"), strict=False)
        return data.get("rows", [])
    except Exception:
        return []


def print_hits(rows: list[dict]) -> None:
    hits = [
        r for r in rows
        if any(TARGET in str(r.get(f, "")).lower() for f in
               ("program_path", "image_path", "image", "path", "raw"))
    ]
    if not hits:
        print(f"  [no {TARGET!r} hits in this artifact]")
        return
    for h in hits:
        path = (h.get("program_path") or h.get("image_path") or
                h.get("image") or h.get("path") or h.get("raw", "?"))
        ts = h.get("timestamp") or h.get("created_time") or h.get("last_run") or ""
        extras = h.get("extras", {})
        print(f"  *** HIT  path  = {path}")
        if ts:
            print(f"           time  = {ts}")
        key = extras.get("appcompat_key") or extras.get("row_index")
        if key:
            print(f"           extra = {key}")


def extract_tier(raw: str) -> str | None:
    m = re.search(r'"tier":\s*"([^"]+)"', raw)
    return m.group(1) if m else None


def extract_n_families(raw: str) -> str | None:
    m = re.search(r'"n_distinct_families":\s*(\d+)', raw)
    return m.group(1) if m else None


def collect_hits(rows: list[dict]) -> list[dict]:
    return [
        r for r in rows
        if any(TARGET in str(r.get(f, "")).lower() for f in
               ("program_path", "image_path", "image", "path", "raw"))
    ]


def print_summary(evidence: list[dict], tier_steps: list[dict], gate_fired: bool) -> None:
    W = 70
    print(f"\n{'#' * W}")
    print(f"  INVESTIGATION SUMMARY — Case {CASE}")
    print(f"{'#' * W}")

    print(f"\n  Hypothesis: C2AGENT.EXE executed on host prior to acquisition\n")

    # Evidence table
    col = [28, 18, 6, 28]
    hdr = f"  {'Tool':<{col[0]}} {'Family':<{col[1]}} {'Hit?':<{col[2]}} {'Timestamp (UTC)':<{col[3]}}"
    print(hdr)
    print(f"  {'-'*col[0]} {'-'*col[1]} {'-'*col[2]} {'-'*col[3]}")
    for e in evidence:
        hit_sym = "YES" if e["hit"] else ("N/A" if e["skipped"] else "no")
        ts = e.get("timestamp", "")[:19].replace("T", " ") if e.get("timestamp") else ""
        print(f"  {e['tool']:<{col[0]}} {e['family']:<{col[1]}} {hit_sym:<{col[2]}} {ts}")

    # Tier progression
    print(f"\n  Confidence tier progression:")
    for step in tier_steps:
        arrow = "-->" if step != tier_steps[-1] else "==>"
        print(f"    {arrow}  {step['label']:<42}  tier = {step['tier']}")

    # Citation gate
    gate_sym = "FIRED (rejected fabricated id)" if gate_fired else "NOT TESTED"
    print(f"\n  Citation-integrity gate: {gate_sym}")

    # Final verdict
    final_tier = tier_steps[-1]["tier"] if tier_steps else "UNKNOWN"
    families_confirmed = [e["family"] for e in evidence if e["hit"]]
    print(f"\n  {'─'*W}")
    print(f"  VERDICT : {final_tier}")
    print(f"  FAMILIES: {', '.join(families_confirmed)} ({len(families_confirmed)} of 5)")
    print(f"  {'─'*W}\n")


async def run_investigation() -> None:
    from sanctum.server import (
        claim_finding,
        get_amcache,
        get_bam,
        get_prefetch,
        get_shimcache,
        get_sysmon_4688,
        get_userassist,
    )

    collected_ids: list[str] = []
    # Accumulated for final summary
    evidence_rows: list[dict] = []
    tier_steps: list[dict] = []
    gate_fired = False

    # ─── STEP 1 ─────────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("STEP 1 — Family 1: AppCompat / ShimCache  (SYSTEM hive)")
    print(SEP)
    raw = await get_shimcache(CASE)
    shim_id = extract_audit_id(raw)
    pp = extract_payload_path(raw)
    shim_rows = load_payload_rows(pp)
    shim_hits = collect_hits(shim_rows)
    print(f"  audit_id : {shim_id}")
    print(f"  rowcount : {extract_rowcount(raw)}")
    print(f"  payload  : {pp}")
    print_hits(shim_rows)
    evidence_rows.append({
        "tool": "get_shimcache", "family": "AppCompat",
        "hit": bool(shim_hits), "skipped": False,
        "timestamp": shim_hits[0].get("timestamp") if shim_hits else None,
    })
    if shim_id:
        collected_ids.append(shim_id)

    # ─── STEP 2 ─────────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("STEP 2 — claim_finding with ONE audit_id (single-family → expect DRAFT/gate block)")
    print(SEP)
    if shim_id:
        print(f"  submitting: [{shim_id}]")
        r = await claim_finding(
            CASE,
            "C2AGENT.EXE executed on host prior to acquisition",
            [shim_id],
        )
        print(r)
        tier_steps.append({"label": "ShimCache only (1 family)", "tier": extract_tier(r) or "?"})

    # ─── STEP 3a — Amcache ──────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("STEP 3a — Amcache  (AppCompat family — SAME trust root as ShimCache)")
    print(SEP)
    try:
        raw = await get_amcache(CASE)
        a_id = extract_audit_id(raw)
        pp = extract_payload_path(raw)
        amc_rows = load_payload_rows(pp)
        amc_hits = collect_hits(amc_rows)
        print(f"  audit_id : {a_id}")
        print(f"  rowcount : {extract_rowcount(raw)}")
        print_hits(amc_rows)
        evidence_rows.append({
            "tool": "get_amcache", "family": "AppCompat (same)",
            "hit": bool(amc_hits), "skipped": False,
            "timestamp": amc_hits[0].get("timestamp") if amc_hits else None,
        })
    except Exception as exc:
        print(f"  [GRACEFUL FAILURE] {type(exc).__name__}: {exc}")
        evidence_rows.append({
            "tool": "get_amcache", "family": "AppCompat (same)",
            "hit": False, "skipped": True, "timestamp": None,
        })
    print("  [gate note] Amcache + ShimCache collapse to ONE family (AppCompat).")
    print("              Adding to claim would not raise the confidence tier.")

    # ─── STEP 3b — BAM ──────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("STEP 3b — BAM  (Background-service family)")
    print(SEP)
    raw = await get_bam(CASE)
    b_id = extract_audit_id(raw)
    pp = extract_payload_path(raw)
    bam_rows = load_payload_rows(pp)
    bam_hits = collect_hits(bam_rows)
    print(f"  audit_id : {b_id}")
    print(f"  rowcount : {extract_rowcount(raw)}")
    print_hits(bam_rows)
    evidence_rows.append({
        "tool": "get_bam", "family": "Background-service",
        "hit": bool(bam_hits), "skipped": False,
        "timestamp": bam_hits[0].get("timestamp") if bam_hits else None,
    })
    if b_id:
        collected_ids.append(b_id)

    # ─── STEP 3c — Prefetch ─────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("STEP 3c — Prefetch  (SysMain family — expected graceful failure on macOS)")
    print(SEP)
    p_id: str | None = None
    try:
        raw = await get_prefetch(CASE)
        p_id = extract_audit_id(raw)
        pp = extract_payload_path(raw)
        print(f"  audit_id : {p_id}")
        print(f"  rowcount : {extract_rowcount(raw)}")
        print_hits(load_payload_rows(pp))
        if p_id:
            collected_ids.append(p_id)
    except BaseException as exc:
        # windowsprefetch calls sys.exit(1) on macOS (SystemExit, not Exception)
        # when MAM decompression fails — ctypes.windll is Windows-only.
        if isinstance(exc, SystemExit):
            print(f"  [GRACEFUL FAILURE — macOS] windowsprefetch called sys.exit({exc.code})")
        else:
            print(f"  [GRACEFUL FAILURE — macOS] {type(exc).__name__}: {exc}")
        print("  Analyst note: SysMain/Prefetch parsing requires Windows host libraries.")
        print("  This family is unavailable in this macOS deployment.")
        evidence_rows.append({
            "tool": "get_prefetch", "family": "SysMain",
            "hit": False, "skipped": True, "timestamp": None,
        })

    # ─── STEP 3d — Sysmon/4688 ──────────────────────────────────────────────
    print(f"\n{SEP}")
    print("STEP 3d — Sysmon / EID 4688  (Kernel-ETW family)")
    print(SEP)
    raw = await get_sysmon_4688(CASE)
    s_id = extract_audit_id(raw)
    pp = extract_payload_path(raw)
    sys_rows = load_payload_rows(pp)
    sys_hits = collect_hits(sys_rows)
    print(f"  audit_id : {s_id}")
    print(f"  rowcount : {extract_rowcount(raw)}")
    print_hits(sys_rows)
    evidence_rows.append({
        "tool": "get_sysmon_4688", "family": "Kernel-ETW",
        "hit": bool(sys_hits), "skipped": False,
        "timestamp": sys_hits[0].get("timestamp") if sys_hits else None,
    })
    if s_id:
        collected_ids.append(s_id)

    # ─── STEP 3e — UserAssist ───────────────────────────────────────────────
    print(f"\n{SEP}")
    print("STEP 3e — UserAssist  (Explorer/NTUSER family)")
    print(SEP)
    raw = await get_userassist(CASE)
    u_id = extract_audit_id(raw)
    pp = extract_payload_path(raw)
    ua_rows = load_payload_rows(pp)
    ua_hits = collect_hits(ua_rows)
    print(f"  audit_id : {u_id}")
    print(f"  rowcount : {extract_rowcount(raw)}")
    print_hits(ua_rows)
    evidence_rows.append({
        "tool": "get_userassist", "family": "Explorer/NTUSER",
        "hit": bool(ua_hits), "skipped": False,
        "timestamp": ua_hits[0].get("timestamp") if ua_hits else None,
    })
    if u_id:
        collected_ids.append(u_id)

    # ─── STEP 4 — multi-family claim ────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"STEP 4 — claim_finding with {len(collected_ids)} distinct-family audit_ids")
    print(f"         ids = {collected_ids}")
    print(SEP)
    if len(collected_ids) >= 2:
        r = await claim_finding(
            CASE,
            "C2AGENT.EXE executed on host prior to acquisition",
            collected_ids,
        )
        print(r)
        tier_steps.append({
            "label": f"{extract_n_families(r)} families (AppCompat+BAM+ETW+NTUSER)",
            "tier": extract_tier(r) or "?",
        })
    else:
        print(f"  [only {len(collected_ids)} ids collected]")

    # ─── STEP 5 — fabricated audit_id ───────────────────────────────────────
    print(f"\n{SEP}")
    print("STEP 5 — claim_finding with FABRICATED audit_id (citation-integrity gate)")
    print(SEP)
    fake_id = "00000000-0000-0000-0000-000000000000"
    print(f"  submitting fabricated id: {fake_id}")
    try:
        r = await claim_finding(
            CASE,
            "C2AGENT.EXE executed on host prior to acquisition",
            [fake_id],
        )
        print(r)
    except Exception as exc:
        print(f"  [GATE FIRED] {type(exc).__name__}: {exc}")
        gate_fired = True

    print_summary(evidence_rows, tier_steps, gate_fired)


if __name__ == "__main__":
    asyncio.run(run_investigation())

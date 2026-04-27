#!/usr/bin/env python3
"""quickstart.py — five-minute Sanctum demo.

Drives the MCP stdio server through the gate-firing demo end-to-end on a
synthetic public-domain fixture (no CFReDS download, no SIFT VM, no API
key required). Demonstrates the family-corroboration gate emitting a
DRAFT verdict for a single-family claim — the architectural primitive
CLAUDE.md invariant 5 promises.

What this proves to a reviewer in five minutes:
  1. The MCP server boots and advertises only the typed tools the
     server registers (no shell-passthrough surface).
  2. ``get_amcache`` returns sanitised, evidence-wrapped output.
  3. The HMAC-chained audit ledger gains an entry for the call.
  4. ``claim_finding`` with a single-family ``audit_id`` returns
     verdict ``DRAFT`` with ``confirmation_basis = "single_family"`` —
     the gate refuses to promote a single-family claim, observable
     deterministically without invoking an LLM.

What this does NOT prove:
  - End-to-end agent behavioural quality (no LLM in the loop).
  - Real .hve parsing (the synthetic fixture uses sidecar mode;
    real ``regipy``/``python-evtx``/``libscca`` decoders ship in
    week 3 — see docs/REPRODUCTION.md §"Known limitations").
  - CORROBORATED / FINAL verdicts. The current MCP surface only
    advertises ``get_amcache`` and ``claim_finding``; the second
    family-providing ``get_*`` tool that would push verdict to
    CORROBORATED ships when its parser body lands. The architectural
    point — single-family → DRAFT — is fully observable today.

Usage:
    python3 scripts/quickstart.py

Prerequisite: ``pip install -e '.[dev]'`` from the repo root.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_CASE_ID = "case_temp_exec_001_synthetic"
FIXTURE_CASES_ROOT = REPO_ROOT / "tests" / "fixtures"
PROTOCOL_VERSION = "2024-11-05"


def _print_step(num: int, title: str) -> None:
    print()
    print(f"━━━ Step {num}: {title} ━━━")


def _print_kv(key: str, value: str) -> None:
    print(f"  {key:.<28} {value}")


def _send(proc: subprocess.Popen[bytes], message: dict[str, Any]) -> None:
    """Write a single JSON-RPC message + newline to the server's stdin."""
    assert proc.stdin is not None
    line = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
    proc.stdin.write(line)
    proc.stdin.flush()


def _recv(proc: subprocess.Popen[bytes], expected_id: int, timeout: float = 10.0) -> dict[str, Any]:
    """Read newline-delimited JSON from the server until we see ``expected_id``.

    The MCP server may emit log lines or unrelated notifications between
    responses; we discard non-matching JSON and surface anything that's
    obviously not JSON to stderr so the user can see startup errors.
    """
    assert proc.stdout is not None
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout before response arrived")
        text = line.decode("utf-8", errors="replace").strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            print(f"  [server stderr] {text}", file=sys.stderr)
            continue
        if isinstance(obj, dict) and obj.get("id") == expected_id:
            return obj
        # else: a notification or unrelated response — keep reading
    raise TimeoutError(f"timed out waiting for response id={expected_id}")


def _strip_evidence_wrap(text: str) -> str:
    """Remove the <evidence-untrusted>...</evidence-untrusted> wrapper.

    The server wraps every tool output per CLAUDE.md invariant 2;
    quick-start needs the inner JSON to extract audit_id and tier.
    """
    m = re.search(r"<evidence-untrusted>(.*)</evidence-untrusted>", text, re.DOTALL)
    return m.group(1).strip() if m else text.strip()


def main() -> int:
    print("Sanctum 5-minute quickstart")
    print(f"Repo:    {REPO_ROOT}")
    print(f"Fixture: {FIXTURE_CASE_ID} (synthetic, public-domain)")

    # Pre-flight: package importable?
    try:
        subprocess.run(
            [sys.executable, "-c", "import sanctum.server"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        print("FAIL — sanctum.server not importable.", file=sys.stderr)
        print("       Run: pip install -e '.[dev]'", file=sys.stderr)
        return 1

    # Pre-flight: fixture present?
    fixture_path = FIXTURE_CASES_ROOT / FIXTURE_CASE_ID / "registry" / "Amcache.hve"
    sidecar_path = fixture_path.with_suffix(fixture_path.suffix + ".sanctum-fixture.json")
    if not fixture_path.exists() or not sidecar_path.exists():
        print(f"FAIL — fixture missing at {fixture_path}", file=sys.stderr)
        print("       Run from a clean checkout.", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="sanctum-quickstart-") as tmp:
        env = os.environ.copy()
        env.update(
            {
                "SANCTUM_LEDGER_HMAC_KEY": secrets.token_hex(32),
                "SANCTUM_LEDGER_PATH": str(Path(tmp) / "ledger.jsonl"),
                "SANCTUM_CASES_ROOT": str(FIXTURE_CASES_ROOT),
                # Quickstart points at a writable repo path; bypass the
                # production ro-mount check. Server emits a WARN so the
                # bypass is never silent.
                "SANCTUM_SKIP_MOUNT_CHECK": "1",
                # Sidecar fixture mode — the parser layer raises
                # PartialImplementationError outside this gate, so without
                # it the quickstart can't show end-to-end output until
                # week 3 parser bodies ship.
                "SANCTUM_USE_FIXTURE_SIDECAR": "1",
                "SANCTUM_LOG_LEVEL": "WARNING",
            }
        )

        _print_step(1, "Launch MCP server (stdio)")
        proc = subprocess.Popen(
            [sys.executable, "-m", "sanctum.server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(REPO_ROOT),
            bufsize=0,
        )
        _print_kv("PID", str(proc.pid))
        _print_kv("Ledger", env["SANCTUM_LEDGER_PATH"])
        _print_kv("Cases root", env["SANCTUM_CASES_ROOT"])

        try:
            _print_step(2, "MCP initialize handshake")
            _send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "sanctum-quickstart", "version": "1.0"},
                    },
                },
            )
            init_resp = _recv(proc, expected_id=1)
            server_info = init_resp.get("result", {}).get("serverInfo", {})
            _print_kv("server name", server_info.get("name", "?"))
            _print_kv("server version", server_info.get("version", "?"))
            _print_kv("protocol version", init_resp.get("result", {}).get("protocolVersion", "?"))
            _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

            _print_step(3, "List advertised tools (the only attack surface)")
            _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            tools_resp = _recv(proc, expected_id=2)
            tools = tools_resp.get("result", {}).get("tools", [])
            for t in tools:
                _print_kv(t["name"], t.get("description", "").split("\n")[0][:60])
            tool_names = {t["name"] for t in tools}
            if "get_amcache" not in tool_names or "claim_finding" not in tool_names:
                print("FAIL — expected typed-tool surface not advertised.", file=sys.stderr)
                return 1
            print(f"  → {len(tools)} typed tools, no shell-passthrough surface.")

            _print_step(4, "Call get_amcache against synthetic fixture")
            _send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "get_amcache",
                        "arguments": {"case_id": FIXTURE_CASE_ID},
                    },
                },
            )
            amcache_resp = _recv(proc, expected_id=3, timeout=20.0)
            content = amcache_resp.get("result", {}).get("content", [])
            if not content or "text" not in content[0]:
                print("FAIL — get_amcache returned no content.", file=sys.stderr)
                print(json.dumps(amcache_resp, indent=2), file=sys.stderr)
                return 1
            wrapped = content[0]["text"]
            if not wrapped.lstrip().startswith("<evidence-untrusted>"):
                print("FAIL — output was not evidence-wrapped.", file=sys.stderr)
                return 1
            _print_kv("output", "<evidence-untrusted>...</evidence-untrusted> (sanitized)")
            inner = _strip_evidence_wrap(wrapped)
            inner_obj = json.loads(inner)
            rows = inner_obj.get("rows", [])
            _print_kv("rows returned", str(len(rows)))
            if rows:
                first = rows[0]
                _print_kv(
                    "first row",
                    str(first.get("source", first.get("program_path", "?"))),
                )

            # NOTE: The current ``get_amcache`` MCP response does not include
            # the ``audit_id``; the ledger entry is appended server-side but
            # the id is not returned to the caller. Workaround for the
            # quickstart: read the ledger file directly to get the most
            # recently appended id. This is *quickstart-only* — a production
            # agent flow needs the id surfaced in the tool response so a
            # subsequent ``claim_finding`` call can cite it. Tracked as a
            # v1 hardening followup.
            ledger_path = Path(env["SANCTUM_LEDGER_PATH"])
            with ledger_path.open() as fh:
                last_line = ""
                for last_line in fh:  # noqa: B007
                    pass
            audit_id = json.loads(last_line)["audit_id"]
            _print_kv("audit_id (from ledger)", audit_id)

            _print_step(5, "Call claim_finding with that single audit_id")
            _send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "claim_finding",
                        "arguments": {
                            "case_id": FIXTURE_CASE_ID,
                            "hypothesis": "runtimebroker.exe was executed on this host",
                            "audit_ids": [audit_id],
                        },
                    },
                },
            )
            finding_resp = _recv(proc, expected_id=4, timeout=20.0)
            f_content = finding_resp.get("result", {}).get("content", [])
            if not f_content or "text" not in f_content[0]:
                print("FAIL — claim_finding returned no content.", file=sys.stderr)
                return 1
            f_inner = _strip_evidence_wrap(f_content[0]["text"])
            f_obj = json.loads(f_inner)
            tier = f_obj.get("tier", "?")
            basis = f_obj.get("confirmation_basis", "?")
            n_fam = f_obj.get("n_distinct_families", "?")
            families = f_obj.get("families", [])
            _print_kv("verdict tier", tier)
            _print_kv("n_distinct_families", str(n_fam))
            _print_kv("families", ", ".join(families))
            _print_kv("confirmation_basis", basis)

            _print_step(6, "Verify ledger HMAC chain")
            ledger_path = Path(env["SANCTUM_LEDGER_PATH"])
            chain_check = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from sanctum.audit import verify_chain; "
                    "ok, n, bad = verify_chain(); "
                    "print('OK' if ok else f'FAIL bad={bad}'); print(f'entries={n}')",
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            for line in chain_check.stdout.splitlines():
                key, _, val = line.partition("=")
                if val:
                    _print_kv(key, val)
                else:
                    _print_kv("verify_chain", line)
            _print_kv("ledger lines", str(sum(1 for _ in ledger_path.open())))

            print()
            print("━" * 60)
            if tier == "DRAFT" and basis == "single_family":
                print("PASS — gate fired correctly.")
                print()
                print("  The family-corroboration gate refused to promote a")
                print("  single-family claim. This is the architectural primitive")
                print("  in CLAUDE.md invariant 5: a Finding with one family →")
                print("  DRAFT, regardless of how confident the LLM is. To see")
                print("  CORROBORATED, a second `get_*` tool from a different")
                print("  family is required (week 3 parser bodies — see")
                print("  docs/REPRODUCTION.md §'Known limitations').")
                return 0
            else:
                print(f"FAIL — expected tier=DRAFT basis=single_family, got tier={tier} basis={basis}")
                return 1

        finally:
            try:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())

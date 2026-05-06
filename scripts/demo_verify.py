#!/usr/bin/env python3
"""Verify the demo MCP server loads cleanly."""
import os, sys

os.environ.update({
    "SANCTUM_CASES_ROOT": "tests/fixtures/real_corpus/cases",
    "SANCTUM_OUTPUT_ROOT": "/tmp/sanctum-demo-output",
    "SANCTUM_LEDGER_PATH": "/tmp/sanctum-demo-ledger.jsonl",
    "SANCTUM_LEDGER_HMAC_KEY": "a225b48f41cbec2a1de6584cf2f730727669028cb60cb4ad16707931107eb850",
    "SANCTUM_SKIP_MOUNT_CHECK": "1",
    "SANCTUM_LOG_LEVEL": "WARNING",
})

from sanctum import server  # noqa: E402

tools = [t for t in dir(server) if t.startswith("get_") or t == "claim_finding"]
print(f"Server module loaded OK — {len(tools)} tools: {tools}")

# Verify case directory is reachable
from pathlib import Path
case = Path("tests/fixtures/real_corpus/cases/real_c2agent_001")
artifacts = {
    "SYSTEM": case / "registry" / "SYSTEM",
    "NTUSER.DAT": case / "registry" / "NTUSER.DAT",
    "Sysmon EVTX": case / "logs" / "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Prefetch dir": case / "Prefetch",
}
print("\nArtifact availability:")
for name, path in artifacts.items():
    exists = path.exists()
    size = f"{path.stat().st_size // 1024} KB" if exists and path.is_file() else "dir" if exists else "MISSING"
    print(f"  {'✓' if exists else '✗'} {name}: {size}")

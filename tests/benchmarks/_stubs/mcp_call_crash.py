"""Stub MCP server: completes handshake, then exits non-zero on tools/call.

Drives AC-11 ``test_smoke_subprocess_crash_during_call``. The driver
must detect the broken pipe / non-zero exit and record a
``<subprocess_crash>`` row WITHOUT aborting the rest of the run.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def _send(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> int:
    while True:
        line = sys.stdin.readline()
        if not line:
            return 0
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "initialize":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "serverInfo": {"name": "stub-call-crash", "version": "0"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": []}})
        elif method == "tools/call":
            return 7  # arbitrary non-zero exit


if __name__ == "__main__":
    sys.exit(main())

"""Stub MCP server: completes handshake, then hangs on tools/call.

Drives AC-11 ``test_smoke_subprocess_hang_during_call``. The driver
must detect the per-question wallclock breach, SIGTERM the stub, and
record a ``<subprocess_timeout>`` row.
"""

from __future__ import annotations

import json
import sys
import time
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
                        "serverInfo": {"name": "stub-call-hang", "version": "0"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": []}})
        elif method == "tools/call":
            # Hang. The driver's per-question wallclock timeout is the
            # primitive under test.
            while True:
                time.sleep(1.0)


if __name__ == "__main__":
    sys.exit(main())

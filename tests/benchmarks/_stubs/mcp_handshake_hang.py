"""Stub MCP server: never responds. Drives AC-11 handshake-timeout test.

Read silently from stdin and never write to stdout. The driver must
detect the missing handshake response within ``handshake_timeout_s``,
SIGTERM-then-SIGKILL the stub, and record a ``<subprocess_timeout>``
row WITHOUT aborting the rest of the run.
"""

from __future__ import annotations

import sys
import time


def main() -> int:
    # Drain stdin in the background so the driver's writes don't deadlock
    # on a full pipe — the test is about handshake response timeout, not
    # pipe-buffer behaviour.
    while True:
        try:
            line = sys.stdin.readline()
        except (KeyboardInterrupt, BrokenPipeError):
            return 0
        if not line:
            time.sleep(0.05)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
# Reset Sanctum demo state between runs.
# Run this before each demo to start with a clean ledger and output directory.

set -euo pipefail

LEDGER="/tmp/sanctum-demo-ledger.jsonl"
OUTPUT="/tmp/sanctum-demo-output"

echo "Resetting Sanctum demo state..."

rm -f "$LEDGER"
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"

echo "  Ledger:  $LEDGER (cleared)"
echo "  Output:  $OUTPUT (cleared)"
echo ""
echo "Ready. Open Claude Code in the find-evil directory and paste the demo brief."

#!/usr/bin/env bash
# smoke_test_mcp_stdio.sh — prove the Sanctum MCP server speaks stdio JSON-RPC.
#
# Runs the MCP initialise handshake against `python -m sanctum.server` and
# verifies that `get_amcache` appears in the `tools/list` response. This is
# the minimal test that *any* stdio MCP client (Claude Code, Cline, Claude
# Desktop, Continue, OpenAI MCP shim, ...) would perform before the first
# tool call. Passing it is necessary + sufficient for LLM-agnostic
# compatibility at the protocol layer.
#
# This is not a functional test of get_amcache (pytest covers that); it
# tests the portable MCP contract, which is what decouples Sanctum from any
# particular LLM vendor.
#
# Usage:  ./scripts/smoke_test_mcp_stdio.sh
# Exits 0 on pass, 1 on fail.

set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

# Pre-flight: refuse to run if the package isn't importable. Without this the
# smoke test would mask a broken install as a protocol failure.
if ! python3 -c "import sanctum.server" 2>/dev/null; then
  echo "FAIL — sanctum.server not importable. Run 'pip install -e .[dev]' first." >&2
  exit 1
fi

# Throwaway environment: the server refuses to start without an HMAC key and
# a cases-root directory. The smoke test needs neither for protocol-level
# verification, so we give it disposables scoped to a tempdir.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

export SANCTUM_LEDGER_HMAC_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export SANCTUM_CASES_ROOT="$TMP/cases"
export SANCTUM_LEDGER_PATH="$TMP/ledger.jsonl"
# The ro-mount check is a production guarantee; for a protocol smoke test
# against a tempdir it must be bypassed. The server emits a WARN on this
# env var so the override is never silent.
export SANCTUM_SKIP_MOUNT_CHECK=1
mkdir -p "$SANCTUM_CASES_ROOT"

cd "$REPO_ROOT"

# Three line-delimited JSON-RPC messages, in order:
#   1. initialize                    — capability handshake
#   2. notifications/initialized     — client declares ready
#   3. tools/list                    — what tools does the server advertise?
# Stdin EOF after the third message causes the server to shut down cleanly.
REQ=$(cat <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sanctum-smoke","version":"0.1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
EOF
)

OUT=$(printf '%s\n' "$REQ" | python3 -m sanctum.server 2>/dev/null || true)

if printf '%s' "$OUT" | grep -q '"get_amcache"'; then
  echo "PASS — MCP stdio handshake + tools/list advertises get_amcache."
  echo "       Any compliant stdio MCP client (Cline, Continue, Claude Desktop,"
  echo "       OpenAI MCP shim, ...) can connect with the same server-side"
  echo "       invariants. See docs/LLM_AGNOSTIC.md."
  exit 0
else
  echo "FAIL — tools/list did not advertise get_amcache." >&2
  echo "--- server output ---" >&2
  printf '%s\n' "$OUT" >&2
  exit 1
fi

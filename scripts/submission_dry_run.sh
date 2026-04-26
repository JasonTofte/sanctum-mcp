#!/usr/bin/env bash
# submission_dry_run.sh — verify Sanctum stands alone without the parent
# dev-framework's local scaffolding (rules / skills / agents / hooks under
# .claude/).
#
# The hackathon submission claims Sanctum's guardrails are architectural,
# not prompt-/scaffolding-based. .claude/ is gitignored so private framework
# tooling never ships, but a judge or contributor cloning the public repo
# is operating *exactly* as if .claude/ were absent. This script replicates
# that condition locally and runs the green-build checks. If they pass,
# Sanctum's claim survives the absence of the framework.
#
# Usage:  ./scripts/submission_dry_run.sh
# Run before every submission cut and any time you want to confirm a piece
# of behaviour isn't being subsidised by framework tooling.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if [ -e .claude.stash ]; then
  echo "ERROR: .claude.stash already exists from a previous run." >&2
  echo "       Inspect, then either restore with 'mv .claude.stash .claude'" >&2
  echo "       or remove with 'rm -rf .claude.stash' before retrying." >&2
  exit 1
fi

stashed=0
restore() {
  if [ "$stashed" -eq 1 ] && [ -e .claude.stash ]; then
    echo ">>> Restoring .claude/"
    mv .claude.stash .claude
  fi
}
trap restore EXIT INT TERM

if [ -e .claude ]; then
  echo ">>> Stashing .claude/ to verify Sanctum stands alone..."
  mv .claude .claude.stash
  stashed=1
else
  echo ">>> .claude/ not present — running checks against bare repo state."
fi

echo ">>> pytest"
pytest -q

echo ">>> MCP stdio smoke test"
./scripts/smoke_test_mcp_stdio.sh

echo ">>> Secret / framework-leak scan"
./scripts/check_no_secrets.sh

echo
echo "OK — Sanctum passed all checks without .claude/ present."
echo "     The submission's architectural-guardrails claim stands."

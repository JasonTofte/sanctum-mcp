#!/bin/bash
# check_no_secrets.sh — block commits containing obvious secrets or private data.
#
# Runs locally (pre-commit) and in CI. Fast and conservative — false positives
# are preferred to false negatives. Extend the REGEX array as new patterns appear.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

# Patterns that must NEVER appear in tracked files.
REGEX=(
  # API keys / tokens
  'sk-[A-Za-z0-9]{20,}'                        # OpenAI-style
  'sk-ant-[A-Za-z0-9\-]{20,}'                  # Anthropic
  'ghp_[A-Za-z0-9]{30,}'                       # GitHub PAT
  'xox[baprs]-[A-Za-z0-9\-]{10,}'              # Slack
  'AKIA[0-9A-Z]{16}'                           # AWS access key
  # Private SSH / PEM
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
  # Absolute user paths (leak dev machine identity in public repo)
  '/Users/[a-z][a-zA-Z0-9_.-]+/'
  '/home/[a-z][a-zA-Z0-9_.-]+/'
  # Framework-IP signals
  'sherlock-methodology'
  'fw-sync\.sh'
  'templates-dev'
)

PATHS=(
  # Never committed, but defense-in-depth if gitignore is removed.
  '.claude/'
  '.env'
  'cases/'
  'evidence/'
)

FAILED=0

# Staged or committed files only — ignore .gitignored content entirely.
CHECK_FILES=$(git ls-files 2>/dev/null)
[[ -z "$CHECK_FILES" ]] && CHECK_FILES=$(find . -type f \! -path './.git/*' \! -path './.venv/*' \! -path './node_modules/*')

for pattern in "${REGEX[@]}"; do
  matches=$(echo "$CHECK_FILES" | xargs grep -lE "$pattern" 2>/dev/null | grep -v 'scripts/check_no_secrets\.sh' || true)
  if [[ -n "$matches" ]]; then
    echo "FAIL: pattern '$pattern' found in:"
    echo "$matches" | sed 's/^/    /'
    FAILED=1
  fi
done

for path in "${PATHS[@]}"; do
  matches=$(echo "$CHECK_FILES" | grep "^$path" || true)
  if [[ -n "$matches" ]]; then
    echo "FAIL: path '$path' should not be tracked:"
    echo "$matches" | sed 's/^/    /'
    FAILED=1
  fi
done

if [[ "$FAILED" -eq 0 ]]; then
  echo "OK: no public-safety violations detected."
fi

exit "$FAILED"

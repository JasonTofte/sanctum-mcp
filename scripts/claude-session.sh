#!/bin/bash
# claude-session.sh — worktree-isolated Claude Code session for sanctum-mcp.
#
# Spawns a fresh git worktree on a new branch so Claude Code work stays off
# the main branch and off each other. Disposable by default — an explicit
# branch name signals "I want to come back to this" and the worktree is
# preserved on exit.
#
# Usage:
#   ./scripts/claude-session.sh                  # auto-named disposable session
#   ./scripts/claude-session.sh feat/my-thing    # named, preserved on exit
#   ./scripts/claude-session.sh --keep           # preserve auto-named session
#   ./scripts/claude-session.sh --help
#
# Install as a global shortcut (post-clone, one-time):
#   ln -s "$PWD/scripts/claude-session.sh" ~/.local/bin/claude-sanctum
#   claude-sanctum --help
#
# Design: clean-room, no framework deps, pure bash. Safe to ship in a public
# repo. If you extend it with project-specific knowledge, keep the shell
# surface small — the MCP server is where real architecture lives.

set -euo pipefail

# Resolve this script's real directory even when invoked via symlink. macOS's
# readlink lacks `-f`, hence the loop. Without this, a `~/.local/bin` symlink
# would resolve SCRIPT_DIR to the bin dir and `git -C` would fail.
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
REPO_NAME="$(basename "$REPO_ROOT")"
WORKTREE_ROOT="${REPO_ROOT}/../${REPO_NAME}-worktrees"

# --- Args ---------------------------------------------------------------
KEEP_OVERRIDE=false
BRANCH=""
EXPLICIT_BRANCH=false
NO_SYNC=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep)     KEEP_OVERRIDE=true; shift;;
    --no-sync)  NO_SYNC=true; shift;;
    --help|-h)
      sed -n '2,18p' "$SOURCE"
      exit 0;;
    -*)
      echo "unknown flag: $1" >&2
      echo "try --help" >&2
      exit 2;;
    *)
      BRANCH="$1"
      EXPLICIT_BRANCH=true
      shift;;
  esac
done

if [[ -z "$BRANCH" ]]; then
  BRANCH="session/claude-$(date +%Y%m%d-%H%M%S)"
fi

# Filesystem-safe worktree name — `session/claude-xxx` → `session-claude-xxx`
WT_NAME="$(echo "$BRANCH" | tr '/' '-')"
WT="${WORKTREE_ROOT}/${WT_NAME}"

# --- Sanity checks ------------------------------------------------------
if ! command -v claude >/dev/null 2>&1; then
  echo "ERROR: 'claude' CLI not found on PATH." >&2
  echo "Install Claude Code: https://claude.com/code" >&2
  exit 1
fi

if [[ -d "$WT" ]]; then
  echo "ERROR: worktree path already exists: $WT" >&2
  echo "Remove it with: git worktree remove \"$WT\"" >&2
  exit 1
fi

# --- Sync main (unless --no-sync) ---------------------------------------
cd "$REPO_ROOT"
if ! $NO_SYNC; then
  echo "==> Fetching origin (use --no-sync to skip)"
  git fetch --quiet origin main || true
fi

# --- Create the worktree -----------------------------------------------
mkdir -p "$WORKTREE_ROOT"

if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  echo "==> Reusing existing local branch '$BRANCH'"
  git worktree add "$WT" "$BRANCH"
elif git show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then
  echo "==> Checking out remote branch 'origin/$BRANCH'"
  git worktree add --track -b "$BRANCH" "$WT" "origin/$BRANCH"
else
  echo "==> Creating new branch '$BRANCH' from origin/main"
  git worktree add -b "$BRANCH" "$WT" origin/main
fi

# The `.claude/` directory is gitignored, so `git worktree add` does not
# copy it. Mirror it into the worktree so MCP server config + hardened
# perms apply to the new session.
if [[ -d "$REPO_ROOT/.claude" ]]; then
  cp -R "$REPO_ROOT/.claude" "$WT/.claude"
fi

# --- Cleanup trap -------------------------------------------------------
# Disposable (auto-named) sessions are removed on exit. Named sessions are
# preserved by default. `--keep` forces preservation for any session.
preserve_worktree() {
  if $KEEP_OVERRIDE; then return 0; fi
  if $EXPLICIT_BRANCH; then return 0; fi
  return 1
}

cleanup() {
  local status=$?
  cd "$REPO_ROOT"
  if preserve_worktree; then
    echo ""
    echo "==> Worktree preserved: $WT"
    echo "    branch: $BRANCH"
    echo "    remove when done: git worktree remove \"$WT\" && git branch -D \"$BRANCH\""
  else
    echo ""
    echo "==> Removing disposable worktree: $WT"
    git worktree remove --force "$WT" >/dev/null 2>&1 || true
    git branch -D "$BRANCH" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

# --- Launch Claude Code in the worktree --------------------------------
cd "$WT"
echo "==> Claude Code session"
echo "    cwd:     $WT"
echo "    branch:  $BRANCH"
echo ""
claude "$@"

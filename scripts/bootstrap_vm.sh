#!/bin/bash
# bootstrap_vm.sh — reproducible SIFT Workstation setup on Ubuntu 22.04.
#
# This script documents the exact commands needed for a judge — or any
# contributor — to reproduce the dev environment end to end. DO NOT run this
# on your host; run it inside a fresh Ubuntu 22.04 VM.
#
# Stale-VERSION defense: `teamdfir/sift-saltstack` publishes its VERSION file
# as `v2020.01.01-rc1` despite daily commits (verified 2026-04-17). A judge
# running `cast install teamdfir/sift-saltstack` at Time X may get a different
# salt-state set than the developer had at Time Y. Pin to a specific commit SHA
# of the salt-state repo for reproducibility.

set -euo pipefail

# --- PINNED VERSIONS ------------------------------------------------------
# Update this block whenever you intentionally upgrade. Commit SHAs resolve
# what "now" meant for the CI run that validated the build.
#
# To update, rerun:
#   gh api repos/teamdfir/sift-saltstack/commits/master \
#     --jq '{sha: .sha, date: .commit.committer.date, message: .commit.message | split("\n")[0]}'
# then paste the new sha + date below, and note the last commit message so
# the pin carries provenance.
SIFT_SALTSTACK_SHA="96b7d9898bc55264679b9ea50949ddc919f76f59"
SIFT_SALTSTACK_PINNED_AT="2026-04-14T03:53:03Z"   # commit date of pinned SHA
SIFT_SALTSTACK_PIN_NOTE="Merge pull request #219 from digitalsleuth/vol3"
CFREDS_HACKING_CASE_URL="https://cfreds-archive.nist.gov/FileSystems/hacking-case.html"
# --------------------------------------------------------------------------

# Confirm Ubuntu 22.04. SIFT does not support 24.04 or 26.04 as of 2026-04-17.
if ! grep -q '22\.04' /etc/os-release; then
  echo "ERROR: SIFT supports only Ubuntu 22.04 (or 20.04)." >&2
  echo "Current OS:" >&2
  cat /etc/os-release >&2
  exit 1
fi

# Baseline deps
sudo apt-get update
sudo apt-get install -y curl git build-essential python3-pip python3-venv jq

# Cast (SIFT's replacement for the old install.sh)
if ! command -v cast >/dev/null 2>&1; then
  curl -fsSL https://getcast.info | sudo bash
fi

# Pin sift-saltstack to a specific commit — avoid drift
if [[ "$SIFT_SALTSTACK_SHA" == "REPLACE_WITH_COMMIT_SHA" ]]; then
  echo "ERROR: pin SIFT_SALTSTACK_SHA in this script before running." >&2
  echo "  gh api repos/teamdfir/sift-saltstack/commits/master --jq '.sha'" >&2
  exit 1
fi
mkdir -p "$HOME/sift-src"
cd "$HOME/sift-src"
if [[ ! -d sift-saltstack ]]; then
  git clone https://github.com/teamdfir/sift-saltstack.git
fi
cd sift-saltstack
git fetch --all
git checkout "$SIFT_SALTSTACK_SHA"

# Run the SIFT install
sudo cast install "$PWD"

# Protocol SIFT reference (read-only clone, for comparison only)
cd "$HOME"
if [[ ! -d protocol-sift ]]; then
  git clone https://github.com/teamdfir/protocol-sift.git
fi

# Pull down the CFReDS Hacking Case (public-domain per 17 USC §105) into /cases
sudo mkdir -p /cases
sudo chown "$USER:$USER" /cases
mkdir -p /cases/cfreds-hacking-case
echo "Download the Hacking Case manually from: $CFREDS_HACKING_CASE_URL"
echo "Place the image under /cases/cfreds-hacking-case/ and re-run smoke tests."

cat <<'DONE'

Bootstrap complete. Next steps:
  1. Download the CFReDS Hacking Case image into /cases/cfreds-hacking-case/
  2. Mount it read-only:
       sudo mount -o ro,loop,noexec,nosuid /cases/cfreds-hacking-case/*.dd /mnt/hacking-case
  3. Extract the registry hives to /cases/cfreds-hacking-case/registry/
  4. Install sanctum-mcp locally:
       cd path/to/find-evil
       python3 -m venv .venv && source .venv/bin/activate
       pip install -e '.[dev]'
  5. Smoke test:
       pytest -v
  6. Wire Sanctum into Claude Code (see docs/REPRODUCTION.md).

DONE

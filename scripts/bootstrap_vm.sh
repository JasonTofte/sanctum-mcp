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
#
# Known upstream issue: teamdfir/sift-saltstack#226 "Broken install conflicting
# SLS IDs" (opened 2026-04-17, still open/unassigned at the time this pin was
# set). The duplicate ID sift-ubuntu-ports-repo lives in both
# sift.repos.ubuntu-multiverse and sift.repos.ubuntu-universe and halts
# salt-call. The bug was present at v2026.03.24 (2026-03-24) and no fix has
# been merged; this pin (2026-04-14) sits on master after v2026.03.24, so the
# install may fail with "Detected conflicting IDs" on fresh VMs. The
# post-install sanity check below detects that exact failure and prints the
# documented workaround. Track upstream issue for a merged fix; bump the pin
# when one ships.
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

# Run the SIFT install. Capture output so we can detect the #226 failure mode
# and emit a specific pointer instead of letting the generic cast error fly.
sift_install_log=$(mktemp)
if ! sudo cast install "$PWD" 2>&1 | tee "$sift_install_log"; then
  if grep -q "Detected conflicting IDs" "$sift_install_log" \
     || grep -qE "sift-ubuntu-ports-repo.*(multiverse|universe)" "$sift_install_log"; then
    cat >&2 <<'SIFT226'

==== known upstream issue: teamdfir/sift-saltstack#226 ====
The install failed with a conflicting-SLS-ID error. This is the documented
upstream bug; track https://github.com/teamdfir/sift-saltstack/issues/226
for a merged fix.

Workaround (until upstream fixes): rename one of the duplicate occurrences
of 'sift-ubuntu-ports-repo' in the cloned sift-saltstack tree, e.g.:

  cd "$HOME/sift-src/sift-saltstack"
  sed -i 's/^sift-ubuntu-ports-repo:/sift-ubuntu-ports-repo-universe:/' \
      sift/repos/ubuntu-universe.sls
  sudo cast install "$PWD"

If the workaround succeeds, record the sed edit in the CHANGELOG of the VM so
reviewers know you diverged from upstream.
SIFT226
    rm -f "$sift_install_log"
    exit 1
  fi
  rm -f "$sift_install_log"
  exit 1
fi
rm -f "$sift_install_log"

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

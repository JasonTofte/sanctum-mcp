# Reproduction guide

This document is for **hackathon judges** and contributors who want to run
Sanctum end-to-end against a real CFReDS case on a clean machine.

## Host requirements

- 16 GB RAM minimum (SIFT + evidence mount + MCP + Claude Code)
- 40 GB free disk (SIFT footprint + one CFReDS case)
- **Ubuntu 22.04** as the SIFT guest. *SIFT does NOT support 24.04/26.04 as of 2026-04-17.*
- A virtualization stack that can host Linux on your OS:
  - macOS: UTM (Apple Silicon), VMware Fusion, or Parallels
  - Windows: VMware Workstation, VirtualBox, or Hyper-V
  - Linux: any KVM/QEMU setup
- A Claude API key with access to Opus 4.7 or Sonnet 4.6

## Step 1 — Stand up the SIFT Workstation VM

1. Create an Ubuntu 22.04 LTS VM (2 vCPU, 8 GB RAM, 40 GB disk).
2. Inside the VM:

   ```bash
   git clone https://github.com/JasonTofte/sanctum-mcp.git find-evil
   cd find-evil
   bash scripts/bootstrap_vm.sh
   ```

   > The repo is private during development and flips to public ahead of the
   > 2026-06-15 submission deadline. Judges reproducing after that date will
   > clone anonymously; contributors before that date need `gh auth login` or
   > an HTTPS token with repo-scope access.

   `bootstrap_vm.sh` pins `teamdfir/sift-saltstack` to a specific commit SHA so
   your build matches the one validated in CI. Expected runtime: 30–45 minutes
   (APT install is the dominant cost).

## Step 2 — Download the CFReDS Hacking Case

1. Visit the CFReDS archive:
   <https://cfreds-archive.nist.gov/FileSystems/hacking-case.html>
2. Download the evidence image (public domain in the US per 17 U.S.C. §105).
3. Place the image under `/cases/cfreds-hacking-case/`.
4. Mount read-only and extract registry hives:

   ```bash
   sudo mount -o ro,loop,noexec,nosuid \
       /cases/cfreds-hacking-case/SCHARDT.dd \
       /mnt/hacking-case
   mkdir -p /cases/cfreds-hacking-case/registry
   sudo cp /mnt/hacking-case/Windows/AppCompat/Programs/Amcache.hve \
       /cases/cfreds-hacking-case/registry/
   sudo chmod 0444 /cases/cfreds-hacking-case/registry/Amcache.hve
   ```

## Step 3 — Install Sanctum

```bash
cd find-evil
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -v
```

All tests must pass before wiring into Claude Code. Tests cover sanitization,
audit-ledger chain verification, and path-traversal rejection.

## Step 4 — Wire Sanctum into Claude Code

Create `.claude/settings.json` at the project root (this file is gitignored
so it does not ship to the public repo). The canonical shape lives at
[`docs/CLAUDE_SETTINGS_REFERENCE.md`](CLAUDE_SETTINGS_REFERENCE.md).

Then:

```bash
claude
# Inside Claude Code:
# > /mcp list      -- verifies sanctum is registered
# > analyse cfreds-hacking-case: what programs ran?
```

## Step 5 — Smoke test the end-to-end pipeline

Expected behaviour in the week-1 P0 skeleton:

- Agent invokes `get_amcache(case_id="cfreds-hacking-case")`
- MCP server resolves the case path, hashes the Amcache.hve file
- Stub parser returns a placeholder row (real parser ships in week 2)
- Sanitization layer emits pre/post SHA-256
- Audit entry appended to `/var/lib/sanctum/ledger.jsonl`
- Tool output arrives in the LLM context wrapped in `<evidence-untrusted>`

Verify the audit chain integrity:

```bash
python -c "from sanctum.audit import verify_chain; ok, n, bad = verify_chain(); print(ok, n, bad)"
# Expected: True <n> None
```

## Step 6 — Bypass smoke test

Attempt architectural bypasses and confirm each is blocked:

```bash
# Path traversal — expect ValueError
python -c "from sanctum.server import _resolve_case; _resolve_case('../etc')"

# Non-existent case — expect FileNotFoundError
python -c "from sanctum.server import _resolve_case; _resolve_case('fake-case')"
```

In the Claude Code session, attempt:
- `write a file /cases/cfreds-hacking-case/evidence.tamper` — expect PreToolUse deny.
- `execute shell: ls /cases` — expect Bash rule miss (only explicit named commands allowed).

## Troubleshooting

- **`cast install` hangs** — usually GPG-key drift on one of the 11 external
  apt repos. See `teamdfir/sift/issues` for current workarounds.
- **`Amcache.hve` missing after mount** — the CFReDS image is NTFS; confirm the
  mount with `ls -la /mnt/hacking-case/Windows/AppCompat/Programs/`.
- **Tests fail with `ModuleNotFoundError: mcp`** — activate the venv first.

## Known limitations

This is a **week-1 P0 skeleton**. The Amcache parser is a stub. The full
triangulation gate, Reflexion loop, and bypass test suite ship in weeks 4–7
per the roadmap in [`../README.md`](../README.md).

# Developer platform — maintainer guide

This document is for **contributors developing Sanctum itself** — distinct from
[`REPRODUCTION.md`](REPRODUCTION.md), which targets hackathon judges running
the code on a fresh machine with maximum hypervisor compatibility.

The two environments intentionally differ. REPRODUCTION.md assumes a guest VM
(UTM, VMware Fusion, Parallels, VirtualBox, any KVM) for broad compatibility.
The maintainer setup optimizes for dev velocity + demo-recording on the
specific rig used to build Sanctum, and makes hardware + software decisions
that judges shouldn't be forced to match.

## Maintainer reference platform

Sanctum is developed on a **physical x86_64 laptop running Ubuntu 22.04 LTS
native** — not a Mac running Linux in a VM, not a cloud instance, not a
container.

Reference hardware (as of 2026-04):

- Lenovo ThinkPad T14 Gen 1 **Intel** (i5-10310U, 16 GB DDR4, 512 GB SSD).

Alternatives in the same equivalence class (same setup steps work):

- ThinkPad T480, T490, T14 Gen 1 Intel — Linux gold-standard lineage.
- Dell Latitude 7490, 7400, 5490, 5420 — business-laptop Linux-certified line.
- Dell OptiPlex 7070, 7080 Micro — mini-desktop form factor.
- Lenovo ThinkCentre M720q, M920q Tiny — ThinkPad DNA in a desktop.

Minimum spec: Intel 8th-gen or later CPU, 16 GB RAM, 256 GB SSD, Intel AX200 /
AX201 / AX210 Wi-Fi. TPM 2.0 recommended (standard on all listed models).

**Hardware to avoid:**

- ThinkPad T14 Gen 2/3/4/5 AMD — documented iwlwifi/Realtek Wi-Fi crashes on
  Ubuntu 22.04/24.04.
- Mac Mini 2018 / 2020 (T2 chip) — Linux requires the `t2linux` custom kernel
  fork; Wi-Fi and audio remain flaky.
- Anything newer than 13th-gen Intel / Meteor Lake / Lunar Lake — may require
  mainline kernel 6.10+ on top of Ubuntu 22.04.
- AMD Ryzen AI / Strix Point / Phoenix Point — Zen 4/5 kernel support on
  Ubuntu 22.04 HWE (kernel 6.8) is brittle.

### Why physical hardware over a VM or cloud

The FIND EVIL! hackathon mandates SIFT Workstation + Protocol SIFT. SIFT is
amd64-only; running it under translation on Apple Silicon introduces SIMD gaps
(AVX2 / BMI1 / BMI2 / F16C still missing from Rosetta-for-Linux as of macOS 15)
that matter for Volatility3 and YARA dispatch paths. Native x86_64 hardware
removes that risk surface completely.

Claude Code's current SSH-remote MCP path is unreliable (see
[anthropics/claude-code#25664](https://github.com/anthropics/claude-code/issues/25664)
and related), which rules out running Claude Code on a laptop with Sanctum MCP
exposed over a tunnel to a cloud VM — the cloud fallback below runs Claude Code
inside the cloud instance instead.

The 5-min FIND EVIL! demo video is a screencast; local screen capture shows
the full SIFT desktop + MCP server + Claude Code UI cleanly, where a remote
SSH capture reduces to a terminal window. Local hardware keeps the demo
dimension simple.

## Bring-up on a fresh T14 (or equivalent)

1. Download **Ubuntu 22.04.5 LTS Desktop** from
   <https://releases.ubuntu.com/22.04/>. Flash to a USB drive with Balena
   Etcher or `dd`.

2. Boot the laptop via F12 → USB. Install Ubuntu with:
   - "Erase disk and install Ubuntu"
   - "Encrypt the new Ubuntu installation" (LUKS — evidence-integrity hygiene for
     any dev-time case data that lands on disk).

3. First boot:

   ```bash
   sudo apt update && sudo apt -y upgrade && sudo reboot
   ```

4. Plan wired Ethernet for demo day regardless of the Wi-Fi chipset. Linux
   Wi-Fi is the most common source of demo-day flakiness on refurb laptops.

5. Install baseline tooling + GitHub auth:

   ```bash
   sudo apt install -y git curl gh
   gh auth login   # HTTPS, PAT or browser flow
   ```

6. Clone Sanctum (the repo flips public before the 2026-06-15 submission
   deadline; contributors before that date need `gh auth login`):

   ```bash
   cd ~
   gh repo clone JasonTofte/sanctum-mcp find-evil
   cd find-evil
   ```

7. Run the SIFT bootstrap:

   ```bash
   bash scripts/bootstrap_vm.sh
   ```

   The script name is a legacy artifact from the pre-bare-metal plan; it only
   asserts Ubuntu 22.04 and runs equally well on a host Ubuntu install. It
   pins `teamdfir/sift-saltstack` to a specific commit SHA for reproducibility.
   Expected runtime on bare metal (i5-10310U, SSD): **30–45 minutes** — APT
   install dominates.

8. Install Protocol SIFT Package on top of SIFT Workstation (hackathon
   requirement — the submission must improve how Protocol SIFT processes case
   data). A dedicated installer script is tracked as a follow-up task.

9. Install Sanctum dev dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e '.[dev]'
   ```

10. Set dev-friendly ledger + output paths (the defaults land under
    `/var/lib/sanctum/*`, which requires root to create):

    ```bash
    export SANCTUM_LEDGER_PATH="$HOME/sanctum/ledger.jsonl"
    export SANCTUM_OUTPUT_ROOT="$HOME/sanctum/output"
    ```

11. Smoke-test:

    ```bash
    pytest -v
    ```

    Tests do not touch `/cases/` — they use fixtures only. A green `pytest`
    here proves the sanitize + audit-chain + server-boundary invariants but
    **does not** validate end-to-end tool execution against real evidence;
    that's the next step.

12. End-to-end smoke against a CFReDS case (full walkthrough in
    [`REPRODUCTION.md`](REPRODUCTION.md) Steps 2, 5, 6).

## How this differs from REPRODUCTION.md

| Axis | DEV_PLATFORM.md (this doc) | REPRODUCTION.md (judge path) |
|---|---|---|
| Target host | Physical x86_64 Ubuntu 22.04 native | Ubuntu 22.04 guest VM inside any hypervisor |
| Hypervisor | None | UTM, VMware Fusion, Parallels, VirtualBox, KVM |
| `cast install` runtime | ~30–45 min (native amd64) | 30–45 min native / 90–120 min Apple Silicon emulation |
| Host OS flexibility | Restricted to x86_64 Linux | Any host (macOS / Windows / Linux) |
| Primary optimization | Maintainer velocity + local demo recording | Judge reproducibility across hardware |
| Authoritative test target | Yes (CI + pre-merge verification) | No — judges run on their own hardware |

Both paths install the same SIFT Workstation, the same Protocol SIFT, and the
same Sanctum codebase. They differ only in how the host Linux kernel gets
there.

## Demo recording (5-min FIND EVIL! screencast)

The hackathon requires a 5-minute screencast with audio narration showing the
agent working against real case data including at least one self-correction
sequence.

Recommended local-recording setup on the dev T14:

- **OBS Studio** (apt-installable) for screen + microphone capture.
- **Window layout**: three panes — (1) Claude Code terminal, (2) SIFT desktop
  with the forensic tool in use (Autopsy / Volatility / AmcacheParser output),
  (3) `tail -f $SANCTUM_LEDGER_PATH` so audit entries appear live on camera.
  The ledger tail is the single most compelling visual proof of the
  architectural invariant.
- **Recording target**: 1080p, 30 fps, h264 video, AAC audio. Stay under the
  hackathon's 5-min ceiling.

This layout is awkward inside a VM (X11 forwarding, window-manager
compatibility) and unusable over remote SSH. The maintainer path is bare-metal
specifically to keep the recording setup one step.

## Cloud fallback

If the maintainer hardware is unavailable (failure, travel), the break-glass
path is AWS EC2:

- **AMI**: `sans-sift-workstation-server-YYYYMMDDHHMMSS` published by the
  official SIFT team under AWS account `469658012540` — 15 regions for Ubuntu
  22.04 Jammy. Skips `cast install` entirely; SIFT is pre-built.
- **Instance**: `m7i.xlarge` (4 vCPU, 16 GB). Idle-stop discipline keeps a
  59-day hackathon window near $80 total.
- **Critical topology constraint**: run Claude Code *inside* the EC2 instance
  via `ssh -t ec2... claude`. Do **not** run Claude Code on a laptop with
  Sanctum MCP tunneled over SSH —
  [anthropics/claude-code#25664](https://github.com/anthropics/claude-code/issues/25664)
  makes that path unreliable as of 2026-04.
- **Recording**: `asciinema rec` for the terminal portion; add an OBS capture
  of a desktop VNC session to the EC2 only if a graphical panel is essential.

## Hardened systemd unit (production-posture sandbox)

For non-interactive deployments (a SOC running Sanctum as a service, not a
hackathon demo), [`scripts/sanctum-mcp.service`](../scripts/sanctum-mcp.service)
ships a systemd unit with defense-in-depth confinement: `NoNewPrivileges`,
`ProtectSystem=strict`, `ReadOnlyPaths=/cases /evidence`, `ReadWritePaths=/var/lib/sanctum`,
`MemoryDenyWriteExecute`, `PrivateTmp`, dropped `CapabilityBoundingSet`,
seccomp `SystemCallFilter=@system-service ~@privileged @debug @mount @reboot @swap`.

Sanctum's architectural guarantees come from the typed tool surface (CLAUDE.md
invariants #1–#2) — **not** from this unit. The sandbox tightens the
[failure-domain-isolation](../.claude/lenses/failure-domain-isolation.md) lens:
if a typed tool body is ever compromised, the confinement limits the blast
radius to the cases path the tool was designed to read.

### When to use

- **Hackathon demo / single-shot analysis**: skip this unit. Run
  `python -m sanctum.server` directly from the venv — simpler, and the
  stdio MCP client (Claude Code) manages lifetime naturally.
- **Production or judge-facing reproduction on a dedicated host**: install
  the unit. Then the MCP server runs under a dedicated `sanctum` user with
  no privileges to spare.

### Install

```bash
# 1. Create the dedicated user.
sudo useradd --system --home-dir /var/lib/sanctum --shell /usr/sbin/nologin sanctum
sudo install -d -o sanctum -g sanctum -m 0750 /var/lib/sanctum

# 2. Place the venv where the unit expects it.
sudo install -d -o root -g root -m 0755 /opt/sanctum
sudo python3 -m venv /opt/sanctum/.venv
sudo /opt/sanctum/.venv/bin/pip install /path/to/find-evil

# 3. Populate the environment file with the HMAC key.
sudo install -d -o root -g sanctum -m 0750 /etc/sanctum
sudo tee /etc/sanctum/env > /dev/null <<ENV
SANCTUM_LEDGER_HMAC_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
ENV
sudo chmod 0640 /etc/sanctum/env
sudo chown root:sanctum /etc/sanctum/env

# 4. Install and enable the unit.
sudo install -o root -g root -m 0644 \
    scripts/sanctum-mcp.service /etc/systemd/system/sanctum-mcp.service
sudo systemctl daemon-reload
sudo systemctl enable --now sanctum-mcp.service
sudo systemctl status sanctum-mcp.service
```

### Verification

`systemd-analyze security sanctum-mcp` reports the sandbox strength. The
unit targets `OK` for every confinement line — audit the output after
install:

```bash
systemd-analyze security sanctum-mcp
```

Exposure score should be well below the default `5.0` threshold (typical
value with this unit: `~1.6`). Anything materially higher than the stock
unit is a regression — treat as a security bug.

## Follow-up work

- Rename `scripts/bootstrap_vm.sh` → `scripts/bootstrap_host.sh` to remove the
  legacy-VM framing.
- Ship `scripts/install_protocol_sift.sh` as a separate PR so step 8 above is
  one command, not a manual process.
- Commit measured `cast install` timings to `docs/MEASURED_TIMINGS.md` once
  the bootstrap runs on the reference T14.
- Add a separate systemd timer unit for `sanctum.notary.stamp_head()` so the
  RFC 3161 witness runs on a schedule (e.g., every 30 minutes during an
  active case) without leaving the TSA network allowlist on the main server
  unit.

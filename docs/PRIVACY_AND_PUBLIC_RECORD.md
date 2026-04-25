# What is — and is not — in this repository

*This document explains the boundary between Sanctum's public artifacts and
the maintainer's private development process. It exists so reviewers,
contributors, and judges can understand what they are looking at without
asking "where is the rest of it?"*

## What this repository contains

This is a **claims-and-implementation** repository. Every artifact in it
is intended to be falsifiable by inspection:

- **Code** under [`src/sanctum/`](../src/sanctum/), released MIT.
- **Architectural invariants** in [`CLAUDE.md`](../CLAUDE.md) and
  [`README.md`](../README.md) — including the no-shell-passthrough,
  evidence-quarantine, audit-id, read-only-mount, and family-corroboration
  guarantees.
- **Threat models** under [`docs/THREAT_MODEL_*.md`](.) — quantitative,
  rung-laddered, citing primary sources.
- **Test surfaces** under [`tests/`](../tests) — every architectural
  invariant has a test that fails if the invariant is violated.
- **Reproduction harness** in [`docs/REPRODUCTION.md`](REPRODUCTION.md)
  and [`scripts/`](../scripts).

Every claim in [`README.md`](../README.md) is required to be traceable to
a source file, a cited paper, or a test (per project convention in
[`CLAUDE.md`](../CLAUDE.md) §"Hackathon-specific norms"). Claims that
cannot be traced this way are not made.

## What this repository deliberately does not contain

The following are **outside scope** and intentionally excluded:

| Excluded | Reason |
|----------|--------|
| Maintainer development-rig configuration (host OS, hypervisor, IDE, editor settings, local agent harness) | Not load-bearing. The repo's claims must be reproducible on any reviewer's hardware (see [`docs/REPRODUCTION.md`](REPRODUCTION.md)); the maintainer's specific rig is one of many environments that satisfy the reproduction prerequisites. |
| Trial-and-error investigation notes, hypothesis-testing logs, dead-end attempts | Process is not the artifact. The conclusion of an investigation belongs in a doc, a code change, or a citation; the path that led there does not. Including process notes would invite reviewers to litigate the path rather than the result. |
| Vendor-specific findings about third-party software the maintainer happens to use | Naming a specific vendor in a generic claim invites "what about $other_vendor?" review thrash, which is unproductive when the claim itself is vendor-neutral. The threat models phrase deployment-environment assumptions generically (see [`docs/REPRODUCTION.md`](REPRODUCTION.md)) for this reason. |
| Strategic decisions, roadmap prioritization, hackathon-specific tactics | Not part of the security model. Roadmap items that have shipped are visible in `git log`; items that have not yet shipped are visible as open issues. The *order* in which they land is not a security claim. |
| Secrets: API keys, the ledger HMAC salt (`SANCTUM_LEDGER_HMAC_KEY`), test-case ground-truth answers | Per [`CLAUDE.md`](../CLAUDE.md) §"What does NOT go in this repo". These are gate-able data — making them public would defeat the test invariants they protect. |
| Framework-proprietary skills, agents, rules, or hooks from the maintainer's parent dev framework | Out of scope and not relicensable. The local Claude Code settings (`.claude/`) are gitignored; the recommended *shape* is documented in [`docs/CLAUDE_SETTINGS_REFERENCE.md`](CLAUDE_SETTINGS_REFERENCE.md). |

## How to verify a claim when the process is not public

The claim ↔ verification path runs through the repo, not through the
maintainer:

1. Read the claim in [`README.md`](../README.md) or
   [`docs/THREAT_MODEL_*.md`](.).
2. Follow the citation. Every claim is cross-linked to one of:
   - a primary source (paper, RFC, NIST publication),
   - a source file (with `file:line` precision where the code is the
     authority),
   - a test under [`tests/`](../tests) that exercises the invariant.
3. If the claim is quantitative (e.g., probability of forgery under
   the family-corroboration rule), the math is laid out in the threat
   model with the assumptions named, and the calculation is reproducible
   from those assumptions alone.
4. If a claim cannot be traced this way, that is a bug — open an issue
   citing the un-traceable claim and a reviewer will treat it as such.

The maintainer's belief that a claim is true is not part of the evidence
chain. The artifacts above are.

## Contribution norms

External contributors should expect that the maintainer's private process
will not become public. Pull requests, issues, and review comments
**are** public and become part of the project's record. Bug reports and
security disclosures follow standard practice — see
[`SECURITY.md`](../SECURITY.md) once it ships, or open a private
GitHub Security Advisory in the meantime.

---

*Cross-references:
[`CLAUDE.md`](../CLAUDE.md) §"What does NOT go in this repo" (project
convention),
[`docs/REPRODUCTION.md`](REPRODUCTION.md) (how to reproduce claims
without access to the maintainer's rig),
[`docs/THREAT_MODEL_*.md`](.) (the public claims this document declines
to supplement with private dev notes).*

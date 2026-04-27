# Threat model — vendored-library trust boundary

*Quantitative threat model for the runtime dependencies declared in
[`pyproject.toml`](../pyproject.toml) and pinned in
[`requirements.txt`](../requirements.txt). Pairs with
[`docs/ADR_PARSER_LAYER.md`](ADR_PARSER_LAYER.md) ADR-PL-006 ("vendored-
library delegation, real-mode parser layer") which records the design
decision; this document records the threat model that justified it.*

The Sanctum parser layer delegates binary file-format parsing to five
vendored libraries. Each library is the trust boundary at which
attacker-influenced bytes (registry values, EVTX records, Prefetch blobs)
first enter Sanctum-owned code. The wrapper around each library is
Sanctum's responsibility (typed errors, scrubbed exception messages,
`ExecutionEvent` shaping); the binary walk itself is delegated.

This document names the attackers we defend against, the attackers we
don't, and the specific rung on the supply-chain ladder we currently
ship. It is the framing referenced from
[`CLAUDE.md` → "Pinning policy"](../CLAUDE.md), from per-dependency
comments in [`pyproject.toml`](../pyproject.toml), and from
[`docs/ADR_PARSER_LAYER.md`](ADR_PARSER_LAYER.md) ADR-PL-006.

## The dependency surface

Five runtime dependencies are vendored. Three of them parse attacker-
influenced bytes; two are infrastructure.

| Package           | Version (==) | License   | Maintainer profile                        | Last release | Parses attacker bytes? | What this layer relies on |
|-------------------|--------------|-----------|-------------------------------------------|--------------|------------------------|---------------------------|
| `regipy`          | 6.2.1        | MIT       | Active, multi-contributor, Mandiant-pedigree pre-fork | 2026 series active | **Yes** — registry hives | `iter_subkeys`, `get_values`, `ShimCacheParser`, `convert_wintime`, `convert_filetime` |
| `python-evtx`     | 0.8.1        | Apache-2.0 | Single maintainer (Willi Ballenthin)      | 2024-09 | **Yes** — EVTX records | chunked records iterator, XML rendering of EID 1 / EID 4688 |
| `windowsprefetch` | 4.0.3        | Apache-2.0 | **Single maintainer; abandoned (last release 2021-04-29)** | 2021-04-29 | **Yes** — Prefetch v17/23/26/30 incl. LZXPRESS-Huffman | version detection, MAM decompression via `ctypes.windll.ntdll`, struct unpacking |
| `defusedxml`      | 0.7.1        | PSF       | PSF-stewarded                             | 2021-12 (stable) | Indirectly — XML rendered by `python-evtx` | XML-entity hardening (billion-laughs cap stdlib `xml.etree` does not provide) |
| `mcp`             | 1.27.0       | MIT       | Anthropic-backed                          | 2026 series active | No — wire transport | FastMCP decorator API, stdio transport |

Plus one transitive that deserves naming: **`construct==2.10.70`** is
the binary-struct DSL that backs both `regipy` and `windowsprefetch`.
The lockfile pins it with hashes; same threat surface as a primary dep.

## Threat model

### Attacker capability

The attacker is **not** the analyst running Sanctum and **not** the
suspect whose disk is being analyzed. Both are already part of
Sanctum's primary threat model
([`THREAT_MODEL_SANITIZATION.md`](THREAT_MODEL_SANITIZATION.md),
[`THREAT_MODEL_LEDGER.md`](THREAT_MODEL_LEDGER.md)). The attacker named
here is one rung further out: a party who can **influence the bytes
that arrive at the operator's `pip install` invocation**. Specifically:

- **Mirror operator.** Operates a PyPI mirror, a corporate proxy, a
  malicious internal index, or a man-in-the-middle on a non-HTTPS
  fallback. Goal: substitute a wheel.
- **Account-takeover attacker.** Compromised the credentials of an
  upstream maintainer, particularly for a single-maintainer project.
  Goal: publish a new version (or a hotfix patch release) carrying a
  malicious payload.
- **Successor-maintainer attacker.** A new "maintainer" who inherits an
  abandoned project (via PyPI ownership transfer, a "we'll keep it
  alive!" PR) and uses the implicit trust of the existing version
  history to publish a malicious bump. The 2018 `event-stream` /
  `flatmap-stream` incident is the canonical example.
- **Transitive-smuggling attacker.** Pushes a malicious update to a
  transitive dep (e.g., `construct`, `pydantic`, `pytz`) that the
  primary deps will pull in on the next resolve. Goal: code execution
  inside Sanctum's process without touching any primary dep.

### Asset

What the attacker wants to compromise:

1. **Evidence integrity.** A planted finding via a parser that lies
   about the bytes it walked. An attacker with code-exec inside the
   parser process can fabricate `ExecutionEvent` records, defeating the
   family-corroboration gate by writing two events into different
   families from the same library.
2. **Ledger key extraction.** `SANCTUM_LEDGER_HMAC_KEY` lives in the
   process environment (the server refuses to start without it; see
   [`THREAT_MODEL_LEDGER.md`](THREAT_MODEL_LEDGER.md) rung 1). A
   malicious dep with code-exec at import time can read it. The TSA
   stamp (rung 2) limits the post-extraction blast radius — the
   attacker can no longer rewrite already-stamped entries — but the
   key compromise is unrecoverable for new entries.
3. **Operator host pivot.** Sanctum runs on the operator's analyst host
   alongside SIFT-style live evidence and case directories. Code-exec
   in the Sanctum process is code-exec on a high-value DFIR machine.

The asset hierarchy is **ledger key > evidence integrity > host
pivot** in terms of incident severity, because key compromise
falsifies all chain-of-custody claims, evidence fabrication can be
caught by the family-corroboration gate (one library cannot fabricate
two families' worth of corroborating events), and host pivot is
recoverable via the read-only mount + audit ledger (CLAUDE.md
invariant 4).

## Posture ladder

Sanctum's defense climbs a rung-ladder identical in shape to the
ledger's
([`THREAT_MODEL_LEDGER.md`](THREAT_MODEL_LEDGER.md) §"Posture ladder").
Each rung defends against a strictly stronger attacker than the
previous.

| Rung | Primitive | Defeats | Fails against |
|------|-----------|---------|---------------|
| 0 | `dep>=N` constraints, no lockfile *(prior implementation, pre-PR #38)* | nothing — `pip install` resolves whatever the index serves at install time | mirror operator, account-takeover, transitive-smuggling, successor-maintainer |
| 1 | `dep==X.Y.Z` exact pin in `pyproject.toml`, no lockfile | accidental bump from a `>=` constraint silently picking up a malicious release | mirror operator (wheel substitution under same version number), transitive-smuggling |
| 2 | rung 1 + hash-locked `requirements.txt` via `pip-compile --generate-hashes`, install with `--require-hashes` (**this doc — current**) | mirror operator, account-takeover (cannot ship a wheel matching an existing pinned hash), transitive-smuggling (every transitive is hash-pinned too) | successor-maintainer who publishes a *new version* the operator chooses to bump to; in-tree compromise of the operator's lockfile generation tooling |
| 3 | rung 2 + signed wheels (PEP 740 / Sigstore attestations) verified at install | rung-2 attacker plus a malicious lockfile push to the Sanctum repo (the signed-wheel attestation is a second trust anchor) | attacker who compromises both the upstream signing identity and the lockfile-generating workflow |
| 4 | rung 3 + vendored under `third_party/<library>/` | upstream existence-of-package attacks (account takeover post-vendoring is moot) | attacker who compromises Sanctum's own repo write access |

Rung 2 is what PR #38 shipped (exact-pin + hash-locked
`requirements.txt`). Rungs 3 and 4 are roadmap items contingent on
specific failure modes:

- **Promote to rung 4 for `windowsprefetch`** if a CVE drops with no
  upstream patch, or if the upstream ownership transfers to a party
  we don't trust. The contingency is named in
  [`CLAUDE.md` → "Pinning policy"](../CLAUDE.md) and in this
  package's per-dep comment in `pyproject.toml`.
- **Promote to rung 3 wholesale** when PEP 740 is broadly supported
  by upstream publishers (it's still rolling out as of 2026). At that
  point `pip install --require-hashes` should be supplemented with
  attestation verification.

## Why hash-locking ≠ vendoring

A common reflex is "if you don't trust the upstream, vendor it." That
trade-off doesn't hold for the threat we actually defend against.
Vendoring **does not** prevent the realistic attacks:

- The mirror-operator attack is mitigated by `--require-hashes`, not by
  vendoring. Vendoring would just move the install path from "PyPI
  download" to "Sanctum's own clone of the upstream repo at version-
  freeze time" — but if the freeze itself was a malicious version,
  vendoring locks that in permanently.
- The account-takeover-then-bump attack is mitigated by exact-pinning
  to a known-good version *and* hash-locking that version. Vendoring is
  a stronger form of this (the bump is impossible because the dep is
  in-tree), but the cost is the maintenance burden of keeping the
  vendored copy patched against newly-discovered upstream bugs without
  the upstream's release cadence as a forcing function.

Vendoring **is** the right call when:

1. Upstream is abandoned **and** a CVE requires a patch we have to
   author ourselves. Today this is hypothetical for `windowsprefetch`;
   the mitigation is "pin and watch," not "vendor preemptively."
2. The library is small enough that maintaining a fork is cheaper than
   the dependency-resolution overhead. None of the five vendored deps
   meet this bar today.

## What we explicitly do not defend against

Out of scope — named here so the threat model is honest about its
limits, not silent.

- **Operator host compromise.** If the analyst host is already
  compromised, the attacker can swap any wheel post-install, edit the
  lockfile, or replace the Sanctum binary. The TSA-stamped ledger
  (rung 2 of the ledger ladder) catches post-hoc tampering of *prior*
  evidence, but cannot defend new evidence collection on a
  compromised host. Mitigation lives at the host-isolation layer
  (read-only `/cases/` and `/evidence/` mounts; running Sanctum
  inside a hardened VM such as the one documented in
  [`docs/DEV_PLATFORM.md`](DEV_PLATFORM.md)), not at the dependency
  layer.
- **Index-level metadata attacks.** The `pip-compile` step trusts PyPI
  metadata (declared transitive constraints, package names) at the
  moment the lockfile is generated. A type-confusion attack at lockfile-
  generation time (e.g., a typosquat dep name in a downstream
  dependency's metadata) would be caught only if the operator manually
  audits the resolved tree. Mitigation: lockfile diffs in PRs are
  reviewed, and the `--require-hashes` install path defends the
  *runtime* trust anchor even if the metadata at lockfile-gen time was
  manipulated (the hashes are over wheel content).
- **Compromised CI/CD.** A malicious GitHub Actions workflow that
  rewrites the lockfile during PR merge would defeat the rung-2
  defense. This is the failure mode rung 3 (PEP 740 attestation
  verification) addresses — the wheel signature is a second trust
  anchor independent of the lockfile.
- **Pre-import malicious behavior.** Some packages execute code in
  `__init__.py` or via setuptools `post_install` hooks. None of the
  five vendored deps do, audited at the pinned version
  (verified by `python -c "import <package>"` not producing
  side-effecting output beyond imports). This is a static property of
  the pinned version, not a dynamic guarantee — a future bump would
  need re-verification.
- **Hardware supply chain.** Out of scope at every threat model in
  this directory; the attacker who controls the operator's hardware
  has already won.

## Operational guarantees

Three concrete properties the rung-2 defense provides:

1. **Identical wheel content across all install hosts.** Two operators
   running `pip install -r requirements.txt --require-hashes` get
   byte-identical wheels. A compromised mirror cannot serve different
   bytes to different operators.
2. **Visible bumps in PR review.** Any change to `pyproject.toml`'s
   `==X.Y.Z` pins forces a regeneration of `requirements.txt`. The
   diff is hundreds of lines (every transitive's hashes change) and is
   trivially reviewable for "did the operator intend this bump?"
   Stealth bumps are not a category in rung 2.
3. **No silent drift.** A `pip install` against an out-of-date
   `requirements.txt` either resolves to the pinned version (good) or
   raises a hash-mismatch (good — operator notices). The "I rebuilt
   the venv and now nothing works" failure mode of `>=` pinning is
   absent at rung 2.

## Cross-references

- **Operational docs.** [`CLAUDE.md` → "Pinning policy"](../CLAUDE.md)
  documents the regen flow (`pip-compile pyproject.toml
  --generate-hashes -o requirements.txt`) and the operator install
  path (`pip install -r requirements.txt --require-hashes`).
- **Architectural rationale.**
  [`docs/ADR_PARSER_LAYER.md`](ADR_PARSER_LAYER.md) ADR-PL-006 records
  why we delegate binary parsing to vendored libraries rather than
  reimplementing them in-tree.
- **Per-dep justification.** Block comments in
  [`pyproject.toml`](../pyproject.toml) carry the per-library
  trust-boundary justification (license, what API surface this layer
  relies on, OS-coupling notes). Read at every dependency review.
- **Error-channel scrubbing.**
  [`docs/THREAT_MODEL_SANITIZATION.md`](THREAT_MODEL_SANITIZATION.md)
  defines the success-path quarantine; the `_safe_field` exception-
  channel scrubber (ADR-PL-005) ensures library-raised exception
  bytes don't reach the LLM unscrubbed if a vendored library decides
  to embed attacker-influenced offsets in its error messages.
- **Family-gate independence.**
  [`docs/THREAT_MODEL_TRIANGULATION.md`](THREAT_MODEL_TRIANGULATION.md)
  §"Family coupling and the AppCompat correction" explains why a
  single-library compromise cannot fabricate two families' worth of
  corroborating events — the family-corroboration gate is an
  independent cross-check on parser correctness.
- **Deception-mode integration.**
  [`docs/THREAT_MODEL_DECEPTION.md`](THREAT_MODEL_DECEPTION.md)
  documents the aggregate-tamper-detection layer that catches
  selective truncation of vendored-library output even when the
  per-row sanitization passes.

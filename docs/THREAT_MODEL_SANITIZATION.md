# Threat model — sanitization ordering

*Formal justification for the `strip → truncate` ordering in
[`src/sanctum/sanitize.py`](../src/sanctum/sanitize.py).*

This document pins a design decision that is load-bearing for
[FAILURE_MODES State 3](FAILURE_MODES.md#state-3-evidence-driven-prompt-injection-poisons-the-llm)
and is already exercised by bypass tests G5 in
[`tests/test_bypass.py`](../tests/test_bypass.py). Prose here makes the
argument an auditor can check without reading the code.

## Threat model

- **Attacker capability.** The attacker authors the content of forensic
  evidence (a string in malware, a log line in Sysmon, a registry value,
  a filename on disk). The attacker chooses both the bytes **and the
  byte position** at which their payload appears in the unstructured blob
  returned by a forensic tool.
- **Defender pipeline.** `sanitize(raw)` applies three local full-stream
  transforms in this order:
  1. `strip-invisibles` — silent removal of every codepoint in the
     invisible-control set (zero-width, bidi, general-format, Tag block
     U+E0001–U+E007F, variation selectors U+FE00–U+FE0F and
     U+E0100–U+E01EF). No visible marker because a dense Tag-block payload
     would otherwise produce an unreadable wall of `[REDACTED]` tokens; the
     count is preserved in `SanitizationResult.invisibles_stripped` for the
     audit ledger.
  2. `strip-patterns` — regex pass that replaces every match of
     `_INJECTION_PATTERNS` with `[REDACTED:injection-candidate]`.
  3. `truncate` — reject payload bytes past `MAX_PAYLOAD_BYTES` (64 KiB),
     appending a visible `[TRUNCATED: …]` marker.
  Stages 1 and 2 are both local full-stream passes, so the prefix-closure
  argument below applies to their composition as a single pattern-freeness
  operation. The Tag-block coverage (stage 1) is the load-bearing defense
  against arXiv 2510.05025-class smuggling; without it the visible-pattern
  regex is structurally bypassable at near-100% ASR.
- **Secondary error-message channel.** The success-path `sanitize()`
  pipeline above only covers payloads returned to the LLM through the
  normal tool-result channel. FastMCP-style `isError` serialization sends
  raw exception strings to the LLM **without** the
  `<evidence-untrusted>` wrapper, bypassing the success-path stripper.
  Stage-1's codepoint inventory is therefore exported as a public
  character-class string `INVISIBLE_CODEPOINT_CLASS` and composed into
  `sanctum.parsers._fixture_io._FIELD_DELIMITER_PATTERN` (parser-boundary
  reject) and into `_safe_field()` (the exception-message scrubber every
  parser uses before raising). The two surfaces share one inventory: any
  range added here propagates automatically. Without this composition,
  a malformed sidecar field carrying U+202E or U+E0054 would land
  verbatim in `ArtifactMalformedError(...)` and reach the LLM through
  the error channel. See `tests/test_parsers.py` for the parser-boundary
  regressions and `tests/test_sanitize.py` for the constant-export
  contract.
- **Asset.** The bytes the LLM eventually sees inside
  `<evidence-untrusted>…</evidence-untrusted>` must not contain any
  pattern in the injection set.

## Boundary-straddle probability

Let `B = MAX_PAYLOAD_BYTES = 65 536`, let `L` be the raw input length, and
let `k` be the length of an injection pattern (`k ≪ B`).

A pattern occupying bytes `[i, i+k−1]` **straddles** the truncation
boundary when `i < B` and `i + k − 1 ≥ B` — equivalently
`B − k + 1 ≤ i ≤ B − 1`. That is `k − 1` qualifying positions out of
`L − k + 1` possible placements.

**Random-placement probability.** For an attacker who does not control
position:

```
P_straddle  =  (k − 1) / (L − k + 1)  ≈  (k − 1) / L     (L ≫ k)
```

Example: `k = 30`, `L = 200 KiB = 204 800` →
`P ≈ 29 / 204 771 ≈ 1.42 × 10⁻⁴` (≈ 0.014%).

**Adversarial upper bound.** For an attacker who controls position
(our actual threat model, since evidence is attacker-authored):

```
P_straddle  =  1  whenever  L > B + k − 1
```

The attacker places the pattern starting at byte `B − k + 1`. Any
defence that scans only the first 64 KiB is therefore **trivially
bypassable** — the straddle is not a probabilistic edge case, it is a
deterministic primitive.

## Why `strip → truncate` is correct

Let `S` be the raw input with `|S| = L`. Let `f : Σ* → Σ*` be
`strip_known_injection_patterns` (a local, full-stream regex pass). Let
`t_B : Σ* → Σ*` be truncate-to-`B`.

**Claim.** The pipeline `t_B ∘ f` produces output that contains no
complete occurrence of any pattern `P ∈ 𝒫`, for every adversarial input
`S`.

**Proof.**

1. By definition of `f`, the string `f(S)` contains no occurrence of any
   `P ∈ 𝒫`: every match is rewritten to the literal
   `[REDACTED:injection-candidate]`, which is not itself a member of the
   pattern set.
2. `t_B(f(S))` is a **prefix** of `f(S)`.
3. Pattern-freeness is *prefix-closed*: if a string `T` contains no
   occurrence of `P`, then every prefix of `T` also contains none. The
   contrapositive is immediate — an occurrence of `P` at positions
   `[i, i+k−1]` inside a prefix `T[0:n]` (with `n ≥ i + k`) is equally an
   occurrence in `T` at the same positions.
4. Therefore `t_B(f(S))` contains no occurrence of any `P ∈ 𝒫`. ∎

## Why `truncate → strip` fails

**Counter-claim.** The pipeline `f ∘ t_B` does not satisfy the property
above.

**Adversarial witness.** Choose any `P ∈ 𝒫` with `|P| = k ≥ 2`. Construct
`S` so that `P` begins at position `B − k + 1` (straddling the
boundary).

- `t_B(S) = S[0:B]` ends with `P[0 : k − 1]` — the first `k − 1` bytes
  of the pattern.
- `f` scans only `S[0:B]`. A strict regex match requires the full
  `k` bytes of `P`; the prefix `P[0 : k − 1]` is not itself a match, so
  `f` does not redact it.
- The output retains `P[0 : k − 1]` unchanged.

Whether the retained prefix is *exploitable* depends on the pattern
set and the downstream consumer. Two realistic escalations apply in
Sanctum:

- **Pattern-set subsumption.** If two patterns `P` and `P'` share a
  common prefix (e.g., `P = "System: override"` and
  `P' = "System: "`), the straddle leaks the shorter variant.
- **Downstream reassembly.** The MCP server is not the final reader;
  large payloads can be paginated across multiple calls. Concatenated
  partial scans reassemble the full pattern.

Neither escalation is required to falsify the correctness claim —
step 3's prefix-closure argument is one-way; `f ∘ t_B` does not inherit
it — but both demonstrate the attack has real downstream teeth.

## Residual obligations

The proof above guarantees pattern-freeness; it does **not** guarantee
the full security property on its own. Three obligations remain:

1. **Pattern coverage.** `f` only defeats patterns enumerated in
   `_INJECTION_PATTERNS` **plus** the codepoints enumerated in
   `_INVISIBLE_CODEPOINTS`. A novel *visible* injection outside the
   regex set slips through independent of ordering. Mitigated by the
   `<evidence-untrusted>` wrapper (Hines et al. 2024 show delimiting
   alone is ≈ 50% ASR reduction — defense in depth, not primary) and
   the downstream `claim_finding` triangulation gate.
2. **Invisible-codepoint coverage.** The Tag block (U+E0001–U+E007F)
   and variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF) are the
   currently-known high-ASR smuggling vectors (arXiv 2510.05025
   reports 100% ASR via Tag block against untrained guardrails).
   `INVISIBLE_CODEPOINT_CLASS` (consumed by `_INVISIBLE_CODEPOINTS` on
   the success path **and** by `_FIELD_DELIMITER_PATTERN` /
   `_safe_field` on the parser/error-channel boundary) covers them plus
   the classic zero-width and bidi ranges. The single source of truth
   means new invisible-smuggling vectors (e.g., future Unicode
   categories whose semantics permit presentation but not semantics)
   need only be added here to propagate to both surfaces; regressions
   are gated by
   `tests/test_sanitize.py::test_unicode_tag_block_is_stripped`,
   `tests/test_sanitize.py::test_invisible_codepoint_class_*`, and
   sibling parser-boundary tests in `tests/test_parsers.py`.
3. **DoS via unbounded `L`.** `f` runs in `Θ(L)` (regex engine worst
   case is higher for some patterns, but the current set is linear on
   non-pathological input). A caller that submits a 10 GB evidence
   blob forces a 10 GB scan. **Closed** as of
   `sanctum.sanitize.MAX_INPUT_BYTES = 16 MiB`: inputs above the cap
   raise `InputTooLargeError` before any regex work runs. The cap is
   configurable per-call via the `max_input_bytes` kwarg for callers
   with legitimate outsize payloads, but the default is strict —
   matching this document's "reject, don't silently feed" principle.
   Regression pinned by
   `tests/test_sanitize.py::test_input_over_max_input_bytes_is_rejected`.

## Test-coverage scope (what bypass tests do and don't verify)

The bypass tests below verify **server-side invariants**: that
pattern-bearing inputs produce pattern-free outputs, that oversized
inputs are rejected, that invisibles are stripped before truncation.
They are property tests against the sanitizer implementation.

**Out of scope for v1.** End-to-end LLM behavioural robustness —
whether Opus 4.7 still misinterprets evidence after sanitization
removes a known pattern, or whether a novel pattern outside
`_INJECTION_PATTERNS` succeeds against the downstream model — is a
distinct class of test requiring the LLM in-context against
attacker-authored evidence. Tracked as a v2 followup, not shipped in
v1.

The §"Residual obligations" above name *what the sanitizer cannot
guarantee*; this section names *what the test suite cannot verify*.
They are different boundaries; both are surfaced explicitly so judges
can assess what the bypass suite does and does not establish.

## Relation to existing tests

- [`test_gap_injection_pattern_survives_across_truncation_boundary`](../tests/test_bypass.py)
  — constructive test of the adversarial scenario in §3: pattern
  placed past the 64 KiB cut. Asserts output contains no pattern
  match, which is exactly what §3's proof guarantees.
- [`test_gap_injection_pattern_near_but_below_cutoff_is_stripped`](../tests/test_bypass.py)
  — pins the companion property: strip is unconditional on size, so
  patterns *before* the cutoff are stripped whether or not truncation
  fires.
- [`test_truncation_at_64kib`](../tests/test_sanitize.py) — pins the
  truncation length bound that `t_B` must satisfy for the prefix
  argument to apply.

If any of those tests are ever relaxed, this proof stops applying —
review the tests and this doc together.

**Named-incident coverage tests** (assert specific published attack classes are covered):
- [`test_sygnia_attack_coverage.py`](../tests/test_sygnia_attack_coverage.py) — Sygnia
  August 2025 Mimikatz mis-narration pattern; dual-path (success: `sanitize` +
  `wrap_evidence`; error: `_safe_field` exception-channel scrubber).
- [`test_mcp_cve_coverage.py`](../tests/test_mcp_cve_coverage.py) — CVE-2025-49596
  (MCP Inspector unauth injection class) and CVE-2025-53109 (symlink path-traversal);
  both verified against NVD primary 2026-04-29.

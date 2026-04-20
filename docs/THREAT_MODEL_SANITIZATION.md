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
- **Defender pipeline.** `sanitize(raw)` applies two transforms:
  1. `strip` — regex pass that replaces every match of
     `_INJECTION_PATTERNS` with `[REDACTED:injection-candidate]`.
  2. `truncate` — reject payload bytes past `MAX_PAYLOAD_BYTES` (64 KiB),
     appending a visible `[TRUNCATED: …]` marker.
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
the full security property on its own. Two obligations remain:

1. **Pattern coverage.** `f` only defeats patterns enumerated in
   `_INJECTION_PATTERNS`. A novel injection outside the set slips
   through independent of ordering. Mitigated by the
   `<evidence-untrusted>` wrapper and the downstream `claim_finding`
   triangulation gate (defense-in-depth, not this document's concern).
2. **DoS via unbounded `L`.** `f` runs in `Θ(L)` (regex engine worst
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

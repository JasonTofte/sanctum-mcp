# Architecture Decision Record — DFIR-Metric eval driver (Phase 2.1)

Captures the load-bearing decisions made when building the quantitative
IR-accuracy measurement infrastructure in `scripts/run_dfir_metric_eval.py`
and `scripts/summarize_eval.py`. The planning artifact (`.sherlock-plan.md`)
is a transient working file; this ADR is the permanent rationale record.

---

## ADR-ED-001 — Prompt-cache strategy: `STRATEGY="interleave"`, not `"ttl_1h_beta"`

**Status.** Accepted (2026-04-29).

**Context.** The two-arm eval (Sanctum vs bare-LLM) processes each question
twice per run. Naively interleaving these calls means the system prompt
enters the prompt cache on arm-A and then must be re-warmed for arm-B if the
cache TTL expires between calls. Two strategies were on the table:

- `"ttl_1h_beta"` — request `cache_control: {"type":"ephemeral","ttl":"1h"}`
  so the cache stays warm for up to 60 minutes between calls.
- `"interleave"` — run arm-A Q1 immediately followed by arm-B Q1 (then
  arm-A Q2 / arm-B Q2, ...) so both calls hit the same 5-minute default TTL
  window. The system prompt cache is populated on arm-A and reused on arm-B
  before it expires.

**Decision.** `STRATEGY="interleave"`. The question-interleaved order keeps
the system prompt in the default 5-minute cache window, eliminating cache
misses on the second arm without requiring any beta API features.

**Consequences (positive).**

- No dependency on the `ttl` extended-cache beta; the eval runs on any GA
  Anthropic SDK version.
- Cost savings are fully realized: both arms share the same cache-warm
  system prompt within a question pair.
- The interleave order is a module-level constant (`STRATEGY`) and is
  documented in the driver docstring and `docs/ACCURACY.md` Methodology so
  readers can reproduce the cost accounting.

**Consequences (negative).**

- If a question pair takes >5 minutes to process (e.g., due to MCP server
  latency), the cache will miss on the second arm. Acceptable at hackathon
  scope — N=3 runs over a small subset.

**Alternative considered.** `"ttl_1h_beta"` — rejected because it adds a
beta API dependency and complicates the reproduction instructions.

**Test pin.** `tests/test_eval_driver_unit.py::test_strategy_constant_is_interleave`
asserts the module-level constant equals `"interleave"`.

---

## ADR-ED-002 — Metric named `sanctum_partial_credit_accuracy`, not `TUS@m`

**Status.** Accepted (2026-04-29).

**Context.** The DFIR-Metric paper (Cherif et al., arXiv:2505.19973) defines
`TUS@m` as partial credit averaged over `m` scoring criteria per question.
Sanctum's eval uses single-criterion exact-match (binary per question):
`score(q) = 1.0 if scoring_pattern matches predicted else 0.0`. Labelling
this `TUS@m` in `docs/ACCURACY.md` would overstate comparability with the
upstream paper's multi-criterion numbers.

**Decision.** Name the metric `sanctum_partial_credit_accuracy` in all code
and documentation (`SCORING_METRIC_NAME` module constant, summarizer output,
ACCURACY.md Numbers table header, per-run JSON `metric` field). Include an
explicit disclaimer in ACCURACY.md §AC-12 explaining the difference.

**Consequences (positive).**

- Readers and judges cannot mistake the single-criterion numbers for a
  direct TUS@m comparison, which would be misleading.
- The formula is explicit in the driver docstring; a judge who wants to
  understand the scoring can read it in <30 seconds.

**Consequences (negative).**

- The metric name is non-standard; cross-paper comparison requires manual
  mapping. Acceptable — the disclaimer in ACCURACY.md addresses this.

**Promotion path.** Switch to multi-criterion `TUS@m` for paper-grade
reporting by replacing `_score_predicted` with a per-criterion scorer.
The `sanctum_partial_credit_accuracy` name then becomes a forward-compat
alias.

**Test pin.** `tests/test_eval_driver_unit.py::test_scoring_metric_name_constant`
asserts `SCORING_METRIC_NAME == "sanctum_partial_credit_accuracy"`.

---

## ADR-ED-003 — Cost-cap check is pre-call (halt before), not post-call

**Status.** Accepted (2026-04-29).

**Context.** The eval runs against the live Anthropic API with a real dollar
budget. Two enforcement points were considered: (a) check cost cap *after*
each call and stop before the *next* call, or (b) project the next call's
estimated cost and stop *before* issuing the call if the projection would
exceed the cap.

**Decision.** Pre-call check in `_check_cost_cap_pre_call`. The projection
uses a conservative worst-case usage dict (`{"input": 200_000,
"cache_write": 200_000, "cache_read": 200_000, "output": 4_000}`) that
overestimates typical token counts. If `total_cost_usd + projected >
max_cost_usd`, the driver halts before the call and writes a partial report
with `partial: true` and `halt_reason: "cost_cap_exceeded"`.

**Consequences (positive).**

- A single expensive call cannot blow past the cap by orders of magnitude
  (e.g., a 500K-token system prompt interaction that the post-call check
  would have allowed).
- The cap is structurally enforced; it cannot be bypassed by a question
  whose actual cost turns out to exceed the projection.

**Consequences (negative).**

- The conservative projection means the last few questions before the cap
  may be skipped even though their actual cost would have fit. Acceptable
  — we err on the side of not overspending.

**Test pin.** `tests/test_eval_driver_unit.py::test_cost_guard_halts_before_next_call`.

---

## ADR-ED-004 — Anthropic SDK errors convert to `<api_error>` row markers

**Status.** Accepted (2026-04-29).

**Context.** The per-question driver functions (`_run_one_sanctum_question`,
`_run_one_bare_question`) catch `_MCPSubprocessError` for subprocess
failures. The outer `run_eval` loop writes the `EvalReport` JSON only *after*
the question loop completes. An unhandled `anthropic.APIError` (or
`RateLimitError`, `APIConnectionError`, etc.) escaping from either helper
would abort the entire eval run and skip the report write — losing all data
collected up to the point of failure.

**Decision.** Both per-question helpers contain an `except Exception` clause
guarded by `_is_api_error(exc)` (module-name sentinel — avoids hard-importing
the `anthropic` package in smoke paths). SDK errors are converted to
`<api_error>` predicted values with `correct=False`, logged at ERROR level,
and the question loop continues. The operator sees the count of `<api_error>`
rows in the per-arm aggregate and can re-run affected questions selectively.

**Consequences (positive).**

- A transient API failure (rate limit, 5xx) cannot destroy a partially
  completed run. The partial data is written and is usable.
- The `_is_api_error` sentinel works without the `anthropic` package
  installed, so smoke tests (which use `MockAnthropicClient`) are unaffected.

**Consequences (negative).**

- Genuine non-API exceptions that happen to come from a submodule whose
  `__module__` starts with `"anthropic."` would be silently swallowed.
  Acceptable — the `anthropic` package's error hierarchy is well-defined and
  internal to that module; non-error exceptions from it are not a realistic
  concern.

**Test pin.** Covered implicitly by `test_api_error_produces_api_error_row`
in `tests/test_eval_driver_unit.py` (injects a mock exception with
`__module__ = "anthropic"` and asserts the row gets `predicted="<api_error>"`
rather than raising).

# IR-accuracy methodology

This document is the **measurement protocol** for Sanctum's
IR-Accuracy axis (one of the six FIND EVIL! judging criteria,
weighted 1/6 and a Stage 1 gate). It pins what we measure, what we
measure *against*, how we score, and how a third party reproduces
the evaluation.

The methodology section comes **before** the Numbers section
(AC-9). This is deliberate: a judge or contributor reading the
IR-accuracy claim in [`README.md`](../README.md) should be able to
answer *"how would Sanctum prove it?"* without scrolling past a
single number first. Numbers without methodology are unfalsifiable;
methodology without numbers is at least honest.

> ⚠️ **Scope of this document — read first.** This methodology
> measures the *agent-mediated* IR-accuracy of Sanctum's typed-tool
> outputs against a bare-LLM baseline on a Sanctum-relevant subset
> of the public DFIR-Metric Module II (CTF) corpus. It does **not**
> measure end-to-end agent behavioural quality (whether the model
> chooses the right `get_*` tools across a long IR engagement,
> whether it interprets multi-artifact narratives correctly, or
> whether it falls for novel evidence-injection that survives the
> sanitizer). Those are separate axes — the sanitization residual
> is treated in
> [`docs/THREAT_MODEL_SANITIZATION.md`](THREAT_MODEL_SANITIZATION.md);
> the agent-cognition surface is OOS for v1 per the **Limits of
> structural defenses** section in `README.md`.

## Methodology

### Why DFIR-Metric

[DFIR-Metric (Cherif et al., arXiv:2505.19973, May
2025)](https://arxiv.org/abs/2505.19973) is the closest published
DFIR-LLM benchmark to Sanctum's domain. We use **Module II — the
CTF subset**, which contains hands-on Windows host-based execution
and persistence questions over CFReDS-derived images. Module I
(multiple-choice DFIR knowledge recall) and the survey-style
modules are out of scope; Sanctum is not a knowledge-recall
system.

We deliberately do **not** benchmark against:

- **CFReDS-only ground-truth questions in isolation**, because the
  questions are not standardised and a per-case scoring rubric is
  not published. CFReDS is excellent as input data; it is not a
  benchmark.
- **CTF challenge sites with non-public answer keys (M57-Patents,
  CyberDefenders)** — see [`README.md`](../README.md) §"Dataset
  choice — license-safe only".

### Subset-selection rationale

We score on a **Sanctum-relevant subset** of DFIR-Metric Module II,
not the full module. Three filters apply, each documented and
reviewable in
[`tests/benchmarks/dfir_metric_subset.py`](../tests/benchmarks/dfir_metric_subset.py):

| Filter | Reason | Effect on N |
|---|---|---|
| **Five-family-coverable** | Tasks must be answerable from the AppCompat / Explorer / BAM / Sysmon / SysMain families that Sanctum's typed tools cover today. Tasks requiring browser history, network capture, memory-resident artifacts, or other out-of-family evidence are excluded. | Reduces N to the family-coverable subset. |
| **Windows-only** | Sanctum is Windows host-based per [Scope](../README.md). Linux-rooted CTF tasks are excluded. | Reduces N to the Windows subset. |
| **Single-criterion ground truth** | Sanctum's per-question scorer matches one expected pattern per question; tasks with multi-criterion compound answers are excluded (rather than partial-credited under a different metric, which would be apples-to-oranges with the bare arm). | Reduces N marginally. |

We also report the Jaccard similarity of the subset against the
upstream task list as a sanity check that the filter list is
reproducible (see
[`tests/benchmarks/test_subset_jaccard_similarity.py`](../tests/benchmarks/test_subset_jaccard_similarity.py),
opt-in).

### Bare-arm fairness

The "bare" arm gives the same model the same question against the
same evidence bytes — but as raw `<evidence-untrusted>...
</evidence-untrusted>`-wrapped bytes in the prompt, with no MCP
tool surface. This is the direct comparison the README claim turns
on: *"a forensic system whose hardness comes from the architecture,
not from the model"*. To keep it fair:

- Same model, same temperature (Opus 4.7, default sampling).
- Same wall-clock and per-question token cap.
- Same scoring pattern.
- Same case fixture.
- Bare arm receives evidence as bytes, hex-encoded if necessary; if
  the evidence exceeds the bare-arm context budget
  (`BARE_ARM_TOKEN_LIMIT` in `scripts/run_dfir_metric_eval.py`), the
  driver emits `<context_overflow>` for that row rather than
  truncating silently.

The bare arm has **no** abstention vocabulary and no audit-ledger
context, so its per-row `claim_status` is `null` and its
`audit_ids` are `()`. The Sanctum arm reports both and the family
gate drives whether a CORROBORATED, DRAFT, or
DRAFT_TAMPER_SUSPECTED tier appears.

### Scoring construction

The scorer uses a **single criterion per question** — either a
case-insensitive substring match or, when prefixed with `~`, a
regex match (e.g., `~(?i)\bAmcache\b` matches the word `Amcache`
case-insensitively). Construction rules:

- The expected pattern is the smallest substring that uniquely
  identifies the correct answer in the upstream task corpus.
- A pattern is "good" if it matches every documented correct
  answer string for the task and rejects every documented incorrect
  answer string. Patterns are reviewed in
  [`tests/benchmarks/dfir_metric_subset.py`](../tests/benchmarks/dfir_metric_subset.py).

### Cost cap and prompt-cache strategy

- **Cost cap**: `--max-cost-usd` (default `$50`). The driver checks
  the **projected next-call cost** against the cap **before** issuing
  the call (`_check_cost_cap_pre_call`); if the next call would
  push spent + projected ≥ cap, the run halts with
  `partial=True` and `halt_reason="cost_cap_exceeded"`. This
  guards against a single expensive call blowing past the cap by
  orders of magnitude.
- **Prompt-cache strategy**: `STRATEGY = "interleave"`. We run the
  arms question-interleaved (arm-A Q1, arm-B Q1, arm-A Q2, …) so
  the system prompt stays in the 5-minute default cache TTL across
  both arms. The alternative (`ttl_1h_beta`) requires the
  `extended-cache-ttl-2025-04-11` beta header and is deferred to
  avoid a beta dependency for the hackathon submission.

### N=3 limitation caveat

Each question is run **N=3 times per arm**, mean and standard
deviation reported. N=3 is the smallest sample that produces a
non-degenerate standard deviation; it is **not** sufficient to
make confident inferences about model variance. The Numbers
section auto-flags any per-arm `accuracy_std / accuracy_mean >
0.15` with a `⚠ high variance — interpret with caution` annotation
(see `scripts/summarize_eval.py::_should_flag_high_variance` and
`tests/test_eval_driver_unit.py::test_summarize_flags_high_variance`).

### Family-tagging procedure

The five-family tag on each question (AppCompat / Explorer / BAM /
Sysmon / SysMain) is the load-bearing input to both the subset
filter and the per-family breakdown in the Numbers table.
Procedure:

1. **One author** reads each upstream Module II task and assigns
   one family tag based on the artifact the question primarily
   asks about (the artifact whose evidence answers the question
   most directly).
2. **One pass** — tags are committed in
   `tests/benchmarks/dfir_metric_subset.py` and not revised after
   the eval is run. Re-tagging after seeing results would let the
   scorer re-classify the easy ones into a "Sanctum is good at"
   family and the hard ones into a "Sanctum is bad at" family,
   which is exactly the bias the per-family columns exist to
   surface.
3. **Single-author bias is visible**: per-family `tagged_count`
   columns in the Numbers table show the distribution. A tagger
   who avoided hard families ("we tagged the easy ones") shows up
   as low `tagged_count` for those families. The reader can spot
   this without trusting our self-report.

### AC-12 disclaimer — we do not implement TUS@m

We report `sanctum_partial_credit_accuracy`, **not** TUS@m. The
DFIR-Metric paper defines TUS@m (Cherif et al. §3) as partial
credit averaged over m scoring criteria per question. We use
single-criterion exact-match for clarity at hackathon scope; the
formula is:

    score(q) = 1.0 if scoring_pattern matches predicted else 0.0
    arm_accuracy = mean(score(q) for q in subset)

This is **binary correctness per question**. Promote to TUS@m for
paper-grade reporting (multiple criteria per question, partial
credit averaged). The metric name in the Numbers table is
`sanctum_partial_credit_accuracy` so the difference from the
upstream paper is visible inline next to the numbers.

## License & Reproduction

### License posture

DFIR-Metric upstream
([`github.com/Cherifa-Cherif/DFIR-Metric`](https://github.com/Cherifa-Cherif/DFIR-Metric),
arXiv:2505.19973) currently ships **without a `LICENSE` file**.
That's not the same as "all rights reserved" but it's not the same
as a permissive grant either; we treat it as license-unspecified
and decline to redistribute the corpus.

Therefore the eval is **runtime-fetch only**:

- The driver does not vendor the DFIR-Metric task corpus into this
  repo.
- The fetcher (`scripts/fetch_dfir_metric.py`) downloads the
  upstream file from the canonical raw URL into a local cache
  (default: `.cache/dfir-metric/`, gitignored).
- The fetcher records the upstream `commit_sha` and content
  `sha256` into the EvalReport JSON so reproductions are
  identifiable.
- A judge/reviewer who wants to re-run the eval downloads the
  upstream corpus themselves; nothing in this repo redistributes
  it.

If the DFIR-Metric authors prefer a different posture (mirroring
restrictions, takedown, license clarification), the contact path
is **`jason.tofte@gmail.com`** — this repo will adjust within 48h
of a written request.

### Reproduction

```bash
# 1. Bootstrap (one-time per host)
git clone https://github.com/JasonTofte/sanctum-mcp.git find-evil
cd find-evil
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

# 2. Fetch the upstream corpus into the local cache
python -m scripts.fetch_dfir_metric

# 3. Run the eval (interleaved arms; N=3; cost cap $50)
python -m scripts.run_dfir_metric_eval \
    --arm both --n-runs 3 --max-cost-usd 50 \
    --output-dir reports/

# 4. Render the markdown fragment for ACCURACY.md
python -m scripts.summarize_eval reports/eval-*.json
```

The report JSON is the source of truth; the markdown fragment in
the Numbers section below is generated from it via
`scripts/summarize_eval.py::summarize`. Every Sanctum-arm row
carries the `audit_ids` list emitted by the typed-tool calls — a
reviewer can spot-check by reading the audit ledger directly (see
[`docs/THREAT_MODEL_LEDGER.md`](THREAT_MODEL_LEDGER.md)).

## Numbers

> The first eval run will paste here. **Until that run completes,
> the table below is a placeholder and the absence of numbers is
> the message** — the methodology is the artifact.

<!-- BEGIN: pasted from `python -m scripts.summarize_eval reports/eval-*.json` -->

| Arm | accuracy_mean ± std | abstention_rate | false_confidence_rate | mean_wallclock_ms | mean_tokens_in | mean_tokens_out | total_cost_usd |
|---|---|---|---|---|---|---|---|
| `sanctum` | `pending` | `pending` | `pending` | `pending` | `pending` | `pending` | `pending` |
| `bare`    | `pending` | n/a | n/a | `pending` | `pending` | `pending` | `pending` |

| Arm | Family | tagged_count | correct_count | accuracy |
|---|---|---|---|---|
| `sanctum` | `AppCompat` | `pending` | `pending` | `pending` |
| `sanctum` | `Explorer`  | `pending` | `pending` | `pending` |
| `sanctum` | `BAM`       | `pending` | `pending` | `pending` |
| `sanctum` | `Sysmon`    | `pending` | `pending` | `pending` |
| `sanctum` | `SysMain`   | `pending` | `pending` | `pending` |
| `bare`    | `AppCompat` | `pending` | `pending` | `pending` |
| `bare`    | `Explorer`  | `pending` | `pending` | `pending` |
| `bare`    | `BAM`       | `pending` | `pending` | `pending` |
| `bare`    | `Sysmon`    | `pending` | `pending` | `pending` |
| `bare`    | `SysMain`   | `pending` | `pending` | `pending` |

<!-- END pasted fragment -->

## Honest limits

1. **N=3.** Three runs per question is the smallest sample that
   surfaces a non-zero standard deviation; it is not statistically
   sufficient. Cells with `accuracy_std / accuracy_mean > 0.15`
   are auto-flagged with `⚠ high variance — interpret with
   caution`. Promote to N≥10 for paper-grade reporting.
2. **Subset bias.** The five-family / Windows-only /
   single-criterion filter reduces N. If the filter accidentally
   removes tasks Sanctum would have solved, the reported number
   under-states the system's accuracy. The filter list is
   committed and reviewable.
3. **Single-author tagging.** Family tags are assigned by one
   author in one pass. The per-family `tagged_count` column makes
   the distribution visible so a reader can spot a "we tagged the
   easy ones" pattern. Promote to multi-author adjudication for
   paper-grade reporting.
4. **Model coupling.** Numbers are for **Claude Opus 4.7 only**.
   Other models inherit the architectural guarantees but produce
   different accuracy numbers; v1 does not run a multi-model
   matrix. See [`docs/LLM_AGNOSTIC.md`](LLM_AGNOSTIC.md).
5. **Single-criterion scoring.** We do not implement TUS@m. A
   question that has multiple acceptable answer phrasings or
   multi-criterion compound answers is filtered out of the subset
   rather than partial-credited. Promote to TUS@m for paper-grade
   comparison against the upstream baseline.
6. **Bare-arm context overflow.** The bare arm receives evidence
   as bytes; if the evidence exceeds `BARE_ARM_TOKEN_LIMIT`, the
   driver records `<context_overflow>` for that row. This is a
   correctness-preserving choice (we report what happened) but
   means very large evidence files systematically penalise the
   bare arm in the comparison.

## Followups

- [ ] Run the first eval; populate the Numbers table.
- [ ] Multi-model matrix (v2) — re-run against Sonnet 4.6 and
      Haiku 4.5 to surface the model-quality dependence.
- [ ] Multi-author family tagging (v2) — adjudicate disagreements,
      report Cohen's κ.
- [ ] Promote to TUS@m (v2) — multi-criterion partial credit, for
      apples-to-apples comparison against the upstream paper's
      published baselines.
- [ ] N≥10 (v2) — statistically sufficient sample for variance
      claims.

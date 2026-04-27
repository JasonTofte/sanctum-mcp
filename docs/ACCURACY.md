# IR-accuracy methodology

This document is the **measurement protocol** for Sanctum's
IR-Accuracy axis (one of the six FIND EVIL! judging criteria, weighted
1/6 and a Stage 1 gate). It pins what we measure, what we measure
*against*, how we score, and how a third party reproduces the
evaluation. The actual numbers — Sanctum's TUS@k score, family-gate
abstention rate, deception-signal correctness — fill in when the
real parser bodies ship in week 3 (`regipy` for `.hve` hives,
`python-evtx` for Sysmon, `libscca` / native-Python for Prefetch);
until then this doc is methodology-only and the §"Numbers" table
flags every cell as `pending`.

The methodology lands first because the IR-Accuracy claim in
[`README.md`](../README.md) is on record from the v0.2.0 release: a
judge or contributor reading that claim today should be able to
answer *"how would Sanctum prove it?"* without waiting for the
benchmark run.

> ⚠️ **Scope of this document — read first.** This methodology
> measures the *server-side* IR-accuracy of Sanctum's typed-tool
> outputs and the family-gate's verdict tier. It does **not**
> measure end-to-end agent behavioural quality (whether Opus 4.7
> chooses the right `get_*` tools, whether it interprets evidence
> correctly, whether it falls for novel evidence-injection that
> survives the sanitizer). Those are separate axes — the
> sanitization residual is treated in
> [`docs/THREAT_MODEL_SANITIZATION.md`](THREAT_MODEL_SANITIZATION.md);
> the agent-cognition surface is OOS for v1 per the **Limits of
> structural defenses** section in `README.md`. This doc is the
> *bytes-out-of-the-server* benchmark only.

## Why DFIR-Metric

[DFIR-Metric (Cherif et al., arXiv:2505.19973, May
2025)](https://arxiv.org/abs/2505.19973) is the closest published
DFIR-LLM benchmark to Sanctum's domain. Three reasons it is the
right yardstick:

1. **Domain match.** Module III ("Disk Forensics CTF") covers Windows
   host-based execution-evidence questions — the exact scope claim
   Sanctum makes in its [Scope](../README.md) line. Module I
   (multiple-choice DFIR knowledge) and Module II ("Linux Forensics
   CTF") are out of scope; Sanctum is not a general DFIR knowledge
   recall system and does not handle Linux artifacts.
2. **Published baseline numbers.** DFIR-Metric reports per-model
   scores including GPT-4.1 at **38.52% TUS@4** on Module III as the
   best disclosed score at publication. Having a frontier-model
   baseline at hand means Sanctum's number is interpretable on day
   one — *better than 38.52%*, *worse than 38.52%*, or *similar*
   are all meaningful answers.
3. **Adversarial-aware metric design.** DFIR-Metric's Task
   Understanding Score (TUS@k) explicitly samples k completions per
   task and counts a task as solved only if *all k* succeed — the
   benchmark design is robust to lucky-sample noise and aligned with
   the family-corroboration gate's "consistent answer across
   independent attempts" philosophy. Pure pass@1 single-shot
   benchmarks would mask sampling variance that the family gate
   exists to suppress.

We deliberately do **not** benchmark against:

- **CFReDS-only ground-truth questions in isolation**, because the
  questions are not standardised and a per-case scoring rubric is
  not published. CFReDS is excellent as input data; it is not a
  benchmark.
- **DFIR-Metric Module II (Linux)** — Sanctum's tool surface and
  family scheme are Windows-specific.
- **CTF challenge sites with non-public answer keys (M57-Patents,
  CyberDefenders)** — see [`README.md`](../README.md) §"Dataset
  choice — license-safe only".

## What TUS@k means

DFIR-Metric defines **TUS@k** (Task Understanding Score at k) as a
strict-consistency variant of pass@k: for each task, the model is
sampled k independent times; the task is counted as solved only if
**all k samples** produce the correct answer. The benchmark's
headline GPT-4.1 score of 38.52% on Module III is TUS@4 — i.e.,
GPT-4.1 produced the correct answer on every one of four
independent samples for 38.52% of Module III tasks.

The strict-consistency framing is what makes TUS@k a useful
yardstick for an architecturally-hardened system like Sanctum:
- A pure pass@1 metric rewards lucky samples — useless for a
  forensic system where one correct answer mixed with three
  hallucinated alternatives is *worse* than a consistent
  abstention.
- pass@k (any of k correct) rewards breadth at the cost of
  reliability — also useless for forensics, where evidence quality
  is the whole game.
- TUS@k punishes inconsistency. A model that flips between two
  different "correct" answers across samples scores 0; a model
  that consistently abstains scores 0; a model that consistently
  produces the right answer scores 1.

For full formal details consult Cherif et al. §3 ("Metrics");
the description above is a summary, not the canonical
definition.

## Module III scope and what we measure

DFIR-Metric Module III contains **N tasks** spanning disk
forensics CTF questions over CFReDS-derived images. The
public-domain test set is published with the paper. Three subset
filters apply to Sanctum's eval:

| Filter | Reason | Effect on N |
|---|---|---|
| **Windows-only tasks** | Sanctum is Windows host-based per [Scope](../README.md). Linux-rooted Module III tasks (if any) are excluded. | Reduces N to the Windows subset (`pending — count when filter is applied to the published task list`). |
| **Memory-resident artifacts excluded** | Memory tools are v2 per Phase B4 descope ([`CHANGELOG.md`](../CHANGELOG.md) `[Unreleased]`). Tasks that require live process listings, network connections, or code-injection markers as the *primary* evidence are excluded. Tasks that mention memory artifacts incidentally but are answerable from on-disk evidence are *included*. | Reduces N by the memory-primary-evidence count (`pending`). |
| **Five-family-coverable tasks** | Tasks that require artifacts outside Sanctum's five v1 families (e.g., browser history, network capture) are excluded — those are out of scope per [Scope](../README.md). | Reduces N by the cross-family count (`pending`). |

The filtered subset, **N_sanctum**, is the denominator for
Sanctum's TUS@k score. The filter list is committed alongside
the eval driver (planned location: `tests/benchmarks/dfir_metric_subset.py`)
so the reduction is reviewable.

We also report N_sanctum as a fraction of the full Module III N —
so a reader can tell at a glance whether Sanctum is benchmarking
on 95% of Module III or 5%.

## Sanctum's verdict-tier adaptation

DFIR-Metric expects a single string answer per task. Sanctum
returns a typed `Finding` with a four-valued tier
(`DRAFT_TAMPER_SUSPECTED < DRAFT < CORROBORATED < FINAL`). The
mapping to TUS@k scoring is explicit:

| Sanctum tier | TUS@k treatment | Rationale |
|---|---|---|
| `FINAL` (≥3 families) | Counted as a committed answer; correctness checked. | Strongest corroboration; the system stands behind the answer. |
| `CORROBORATED` (2 families) | Counted as a committed answer; correctness checked. | Cross-family agreement = the family gate's success case. |
| `DRAFT` (1 family) | Counted as **abstention**, not as a wrong answer. | The gate explicitly tells the agent "you don't have enough corroboration to commit"; treating this as a wrong answer would punish honest uncertainty. |
| `DRAFT_TAMPER_SUSPECTED` (deception signal demoted any tier) | Counted as **abstention**, not as a wrong answer. | Same rationale as DRAFT — the deception layer is signalling "don't trust your own corroboration". |

This produces **two reportable numbers** instead of one:

1. **TUS@k (strict)** — abstention counted as wrong. This is the
   apples-to-apples comparison against DFIR-Metric's published
   GPT-4.1 38.52% baseline (which has no abstention vocabulary).
2. **TUS@k (coverage-adjusted)** — abstention separated from
   incorrect. We report **precision** (correct ÷ committed) and
   **coverage** (committed ÷ N_sanctum) separately. A high
   precision with low coverage is a perfectly reasonable
   forensic posture; a high coverage with low precision is the
   GTG-1002 / Sygnia failure mode the architecture is designed
   against.

Both numbers are reported. The strict number is the headline; the
coverage-adjusted pair is the honest expansion.

## Reproducing the evaluation

The eval driver (planned, **not yet shipped**) lives at:

```
scripts/run_dfir_metric_eval.py
tests/benchmarks/dfir_metric_subset.py   # the filter list
tests/benchmarks/expected_outputs/        # per-task expected answers
```

The expected reproduction flow:

```bash
# 1. Bootstrap (one-time per host)
git clone https://github.com/JasonTofte/sanctum-mcp.git find-evil
cd find-evil
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

# 2. Place the DFIR-Metric Module III task corpus at the canonical path
#    (the corpus is published with the arXiv paper; not redistributed
#     in this repo to respect upstream licensing).
export SANCTUM_DFIR_METRIC_CORPUS=/path/to/dfir_metric_module_iii/

# 3. Run the eval — k=4 to match the published GPT-4.1 baseline
python scripts/run_dfir_metric_eval.py --k 4 --model claude-opus-4-7 \
    --output reports/eval-$(date +%Y%m%d).json

# 4. Inspect the report
python scripts/summarize_eval.py reports/eval-*.json
```

Expected runtime: **`pending`** — depends on Module III task count
post-filter and per-task wall-clock for the MCP loop. Order-of-
magnitude estimate: 30–90 minutes for k=4 on the filtered subset
on a typical laptop, dominated by parser execution + Anthropic API
latency.

The report JSON is a list of per-task records:

```json
{
  "task_id": "module-iii-task-042",
  "expected_answer": "psexec.exe",
  "k": 4,
  "samples": [
    {"finding": {"tier": "CORROBORATED", "answer": "psexec.exe", ...}, "audit_ids": [...]},
    {"finding": {"tier": "CORROBORATED", "answer": "psexec.exe", ...}, "audit_ids": [...]},
    {"finding": {"tier": "FINAL",        "answer": "psexec.exe", ...}, "audit_ids": [...]},
    {"finding": {"tier": "DRAFT",        "answer": null,         ...}, "audit_ids": [...]}
  ],
  "tus_k_strict": false,
  "tus_k_coverage_adjusted": {
    "committed": 3,
    "correct": 3,
    "abstained": 1
  }
}
```

A third party can verify the report by spot-checking individual
`audit_ids` against the audit ledger committed alongside the
report — every Sanctum answer is traceable to the underlying
parser output via the HMAC-chained ledger ([`docs/THREAT_MODEL_LEDGER.md`](THREAT_MODEL_LEDGER.md)).

## Numbers — pending

The headline table will fill in once the week-3 parser bodies ship
and the first eval run completes. **Every cell below is currently
`pending`; do not infer a hidden number.** This is methodology
publication, not results publication.

| Metric | Sanctum (Opus 4.7) | DFIR-Metric baseline (GPT-4.1) | Notes |
|---|---|---|---|
| **TUS@4 (strict)** | `pending` | 38.52% | Abstention = wrong. Direct apples-to-apples. |
| **TUS@4 precision** | `pending` | n/a | Correct ÷ committed. No abstention vocabulary in the GPT-4.1 baseline. |
| **TUS@4 coverage** | `pending` | n/a | Committed ÷ N_sanctum. |
| **Family-gate abstention rate** | `pending` | n/a | Fraction of tasks where the gate emitted DRAFT or DRAFT_TAMPER_SUSPECTED. |
| **Deception-signal precision** | `pending` | n/a | Of cases where Sanctum emits DRAFT_TAMPER_SUSPECTED, fraction where the underlying CFReDS image is in fact tampered. Measured against the synthetic adversarial corpus in `tests/adversarial/` (week 6). |
| **N_sanctum / N_module_iii** | `pending` | n/a | Filter ratio after Windows-only / no-memory / five-family-coverable filters. |

The eval driver will be added in a separate PR once parser bodies
land — that PR will overwrite this table with real numbers and
attach the per-task report JSON as evidence. **Until then, the
absence of numbers is the message** — the methodology is the
artifact, and the numbers will be published as soon as they exist.

## Honest limits

1. **Parser blocker.** No numbers can be produced before week 3
   parser bodies ship. The current parser layer raises
   `PartialImplementationError` in production and only accepts
   sidecar fixtures under `SANCTUM_USE_FIXTURE_SIDECAR=1` — see
   [`docs/REPRODUCTION.md`](REPRODUCTION.md) §"Known limitations".
   Running this methodology against the fixture-sidecar path
   would produce numbers that reflect the fixtures, not real
   parsing.
2. **Model coupling.** Numbers reported here are for **Claude
   Opus 4.7 only**, the reference configuration per
   [`docs/LLM_AGNOSTIC.md`](LLM_AGNOSTIC.md). Other models would
   inherit the architectural guarantees but produce different
   accuracy numbers; v1 does not run a multi-model accuracy
   comparison. The DFIR-Metric paper reports multiple models
   (GPT-4.1, Llama, Gemini); apples-to-apples cross-model claims
   require running the full multi-model matrix, which is a v2
   followup.
3. **Subset bias.** The Windows-only / no-memory /
   five-family-coverable filter reduces N. If the filter
   accidentally removes tasks that *would* be solvable by
   Sanctum's surface, the reported number under-states the
   system's accuracy. The filter list is committed and reviewable
   so this bias is auditable. A v2 followup would expand the
   five-family scheme to cover what the filter currently excludes.
4. **TUS@k consistency assumption.** The TUS@k metric assumes
   k independent samples; with `temperature=0` (Opus 4.7
   reference configuration) the four samples are nearly
   identical, which inflates TUS@k toward pass@1 semantics. The
   DFIR-Metric paper notes the same assumption holds for any
   greedy-decoding configuration in its baseline; the comparison
   stays fair as long as both sides use the same sampling regime.
   We will report the sampling configuration alongside the
   number.
5. **Question coverage.** DFIR-Metric Module III's task
   distribution may not match the question distribution Sanctum
   sees in real IR engagements. The benchmark is a *proxy* for
   in-the-wild accuracy, not a guarantee of it. Sanctum's
   architectural posture (refuse rather than guess; surface
   provenance for every claim) is designed to degrade gracefully
   on out-of-distribution questions; the eval cannot prove that
   directly.

## Followups

- [ ] Ship the eval driver alongside week-3 parser bodies. Single
      PR — driver + filter list + first run's report JSON
      committed under `reports/`.
- [ ] Populate the §"Numbers" table; revise this section's
      "pending" cells to actual values; add a paragraph
      summarising the headline finding.
- [ ] Multi-model matrix (v2). Re-run the eval against Sonnet
      4.6 and Haiku 4.5 to surface the model-quality dependence
      that [`docs/LLM_AGNOSTIC.md`](LLM_AGNOSTIC.md) flags as
      currently un-validated.
- [ ] Cross-benchmark sanity check (v2). Re-run against a second
      forensic-LLM benchmark if one ships before submission;
      single-benchmark numbers are inherently fragile.

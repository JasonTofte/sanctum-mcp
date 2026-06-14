# Accuracy Report

A short, judge-facing summary. The full method, tables, and statistics are in [`ACCURACY.md`](ACCURACY.md).

## Headline

| Measure (43 questions × 3 runs, Opus 4.7) | Sanctum | Bare model |
|---|---|---|
| Accuracy | **99.2%** [95.7, 99.9] | **16.3%** [10.9, 23.6] |
| Precision on CORROBORATED findings | 97.2% | — |
| False-confidence rate | 2.8% | — |

Same model, same questions, same evidence bytes. The only difference is the Sanctum server. The 82.9-point gap is the server's contribution. Confidence intervals are Wilson 95%.

## What we measured, and what we did not

We measured whether the agent gives the right answer on Windows execution-evidence questions, with and without Sanctum. We did not measure long open-ended investigations or how well the model reads a correct result; those depend on the model.

The benchmark is a 43-question subset we selected from DFIR-Metric, the closest published DFIR-LLM benchmark. Because we wrote the subset, an outside question set would be a stronger signal. The independent check below addresses part of that.

## Independent check — NIST CFReDS Data Leakage

We ran Sanctum's parsers against a real Windows 7 disk image that NIST publishes with its own answer key. This tests the parser layer against ground truth we did not write.

- The image was verified against NIST's published SHA-1 hashes and mounted read-only.
- All 8 applications the answer key documents were found.
- The three case-defining tools (Eraser, CCleaner, Google Drive) were each confirmed across three families — FINAL.
- iCloud appeared in one family and was reported as a single-source draft. That is correct: the answer key shows iCloud was uninstalled, which removed its other traces.
- Three of the five families are present on Windows 7 (BAM and Sysmon arrived in later Windows). Coverage is reported honestly as 3 of 5, not dressed up as 5.

The answer key is public, so this is a parser-extraction result, not a clean test of model memory. Full detail and the ingestion procedure are in [`DATASET_NIST_DATALEAKAGE.md`](DATASET_NIST_DATALEAKAGE.md).

## Reproduce it

The within-model benchmark:

```bash
export ANTHROPIC_API_KEY=<key>
python3 -m scripts.run_dfir_metric_eval --arm both --n-runs 3 --output-dir reports/
```

The NIST parser check follows the read-only mount and extraction steps in [`DATASET_NIST_DATALEAKAGE.md`](DATASET_NIST_DATALEAKAGE.md). Real evidence is not committed to this repository; only results and hashes are.

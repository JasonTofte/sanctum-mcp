"""Opt-in license-paraphrase guard for the SUBSET justifications (AC-3).

This test fails if any ``SubsetEntry.justification`` token-set-overlaps
the corresponding upstream DFIR-Metric question text by more than 30%.
Threshold rationale: 0.30 Jaccard tolerates routine technical-vocab
overlap (e.g. "Amcache", "Sysmon", "EID") while rejecting paraphrases
that re-encode the upstream question text. See ``docs/ACCURACY.md`` §
"License & Reproduction" for the full rationale.

Skipped when ``.cache/dfir-metric/DFIR-Metric-CTF.json`` is absent — this
runs only on contributor machines that have explicitly fetched
upstream via ``python -m scripts.fetch_dfir_metric``. Default
``pytest -q`` skips this entire directory via the ``benchmark`` marker.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.benchmarks.dfir_metric_subset import SUBSET

CACHE_PATH = Path(".cache/dfir-metric/DFIR-Metric-CTF.json")
JACCARD_THRESHOLD = 0.30
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")


def _tokenize(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _question_text_for(line_offset: int, upstream: list[dict]) -> str:
    """Return the upstream question text at ``line_offset``.

    The exact key is determined by inspecting the first record at runtime —
    upstream may use ``question``, ``Q``, ``prompt``, etc. We fail loudly
    if no plausible key is found rather than silently treating an
    unknown shape as zero-text.
    """
    record = upstream[line_offset]
    for key in ("question", "Q", "prompt", "stem", "text"):
        if key in record and isinstance(record[key], str):
            return record[key]
    raise RuntimeError(
        f"upstream record at line {line_offset} has no recognized question-text key; "
        f"observed keys: {sorted(record.keys())}"
    )


def test_subset_justifications_are_not_paraphrases() -> None:
    if not CACHE_PATH.exists():
        pytest.skip(f"upstream cache not present at {CACHE_PATH}; run scripts/fetch_dfir_metric.py")
    upstream = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    if not isinstance(upstream, list):
        pytest.skip(f"upstream JSON shape unexpected (got {type(upstream).__name__}); skipping")
    for entry in SUBSET:
        if entry.line_offset >= len(upstream):
            pytest.fail(f"SUBSET line_offset {entry.line_offset} out of range (upstream len={len(upstream)})")
        upstream_text = _question_text_for(entry.line_offset, upstream)
        sim = _jaccard(_tokenize(entry.justification), _tokenize(upstream_text))
        assert sim < JACCARD_THRESHOLD, (
            f"justification at line_offset={entry.line_offset} (family={entry.family}) "
            f"has Jaccard similarity {sim:.2f} ≥ {JACCARD_THRESHOLD} with upstream question — "
            f"likely a paraphrase; rewrite from a different angle"
        )

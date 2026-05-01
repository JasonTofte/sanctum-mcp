"""AI-assisted expansion of ``tests/benchmarks/dfir_metric_subset.py`` from
the seed 5 entries to ~45 entries (≥5 per Sanctum family).

This is a maintenance tool, NOT a runtime dependency. It reads the
gitignored ``.cache/dfir-metric/DFIR-Metric-CTF.json`` corpus, asks
Claude to (a) classify each upstream question into one of the 5 Sanctum
artifact families (or skip), and (b) draft a ``scoring_pattern`` +
``justification`` that satisfies the AC-3 license-paraphrase guard
(``test_subset_jaccard_similarity.py`` enforces Jaccard < 0.30 against
the upstream question text).

Two-pass design:

  Pass 1 — Classification (cheap)
    Batch ~15 records per call. Output: line_offset → family-or-skip.
    Low temperature, structured JSON output.

  Pass 2 — Drafting (one call per accepted record)
    For each classified record, draft the regex + justification with
    inline Jaccard validation. Up to 3 retries per record with
    increasingly sharp "rewrite from a different angle" prompts. Records
    that fail all retries are dropped (logged) — we ship correct, not
    complete.

Safety posture:
  * Default output is ``tests/benchmarks/dfir_metric_subset.py.proposed``;
    overwriting the live file requires ``--write``. Reviewer eyeballs
    the diff before commit (humans-in-the-loop on AI-generated code is
    the Sanctum norm).
  * Existing 5 SUBSET entries are preserved by default (seed); pass
    ``--no-preserve-seed`` to start from scratch.
  * Cost ceiling enforced via ``--max-cost-usd``. Halts mid-run with a
    partial proposal rather than blowing through the budget silently.
  * Every emitted entry is validated (regex compiles, line_offset in
    range, Jaccard < 0.30) before the script exits 0. A validation
    failure refuses to write the proposal file.

Cost estimate at default settings (~100 corpus records):
  Pass 1: ~10K input + 2K output across ~7 batches → ~$0.10
  Pass 2: ~50 drafts × 2K input + 500 output → ~$0.40
  Headroom for retries: ~$0.50
  Total budget recommended: ``--max-cost-usd 1.5`` (default).

Reproducibility caveat: Anthropic API does NOT support deterministic
seeds on Opus 4.7 as of 2026-04. Two runs with identical input will
produce different SUBSET entries. The Jaccard test gates correctness,
but the *exact* line_offsets selected per family are not reproducible
across runs. This is an accepted limitation — the SUBSET is a one-time
authored artifact; reviewers approve the diff before commit.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

# Reuse the eval driver's pricing constants — single source of truth so
# a future Opus pricing change updates both the eval runner and this
# script in one place.
from scripts.run_dfir_metric_eval import OPUS_4_7_PRICING

# Local copy of the family Literal — importing from the actual subset
# module is fine, but keeping a local mirror documents the contract
# this script honors.
FAMILIES: tuple[str, ...] = ("AppCompat", "Explorer", "BAM", "Sysmon", "SysMain")

# Mirror tokenizer/threshold from test_subset_jaccard_similarity.py so
# this script enforces the SAME guard the test enforces. Drifting these
# two would make the script generate entries that fail their own test.
JACCARD_THRESHOLD: float = 0.30
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")

DEFAULT_CORPUS_PATH = Path(".cache/dfir-metric/DFIR-Metric-CTF.json")
DEFAULT_OUTPUT_PATH = Path("tests/benchmarks/dfir_metric_subset.py.proposed")
DEFAULT_LIVE_PATH = Path("tests/benchmarks/dfir_metric_subset.py")
DEFAULT_MODEL = "claude-opus-4-5"
DEFAULT_BATCH_SIZE = 15
DEFAULT_RETRIES = 3
DEFAULT_TARGET_PER_FAMILY = 9  # 5 × 9 = 45
DEFAULT_MAX_COST_USD = 1.5
QUESTION_TEXT_KEYS: tuple[str, ...] = ("question", "Q", "prompt", "stem", "text")
ANSWER_KEYS: tuple[str, ...] = ("answer", "A", "gold", "label", "ground_truth")


# --- Family rules (the prompt's classification rubric) -------------------

FAMILY_RULES = """\
The five Sanctum artifact families:

  • AppCompat — Amcache.hve InventoryApplicationFile (program execution
    metadata: ProgramId, FileId, install/first-run/last-run timestamps,
    SHA1, publisher).
  • Explorer — NTUSER.DAT UserAssist subkeys (GUI-launched programs,
    focus time, last-run, run-count attribution per user).
  • BAM — SYSTEM hive BackgroundActivityModerator subkeys (background
    process executions, last-launch timestamps keyed by user SID).
  • Sysmon — Sysmon EventID 1 OR Windows Security EventID 4688 (process
    creation events with command line, parent process, user context,
    image hash).
  • SysMain — Prefetch .pf files (boot-time / scheduled execution
    traces; volume serial, file paths accessed during process startup,
    run-count, last-8-runtimes).

Skip the question (family=null) if any of the following:
  - Requires more than one family to answer correctly.
  - Asks about Windows artifacts NOT listed: $MFT, $LogFile, $UsnJrnl,
    Outlook .pst, browser history, network packet captures, IIS logs,
    memory images, ShellBags, Jump Lists, LNK files, Recycle Bin, RDP
    cache, ScheduledTasks XML, hardware/PnP keys, Hibernation/pagefile.
  - Asks about Linux/macOS/mobile artifacts.
  - Stem is too ambiguous to commit a single family.
"""

CLASSIFY_SYSTEM = f"""\
You are a forensic-artifact classifier for the Sanctum DFIR-Metric eval.

{FAMILY_RULES}

For each numbered question, output one classification line.

Output format — exact JSON, no preamble, no markdown fences:
{{"classifications": [
  {{"line_offset": 0, "family": "AppCompat" | "Explorer" | "BAM" | "Sysmon" | "SysMain" | null, "reason": "<≤15 words>"}},
  ...
]}}

Rules:
  - One entry per input line_offset. Order doesn't matter; line_offset is the key.
  - "family" is null when the question is out of scope per the skip list.
  - "reason" is a brief technical pointer (≤15 words) — not a paraphrase
    of the question.
"""

DRAFT_SYSTEM = f"""\
You draft a SubsetEntry for Sanctum's license-clean DFIR-Metric subset.
The upstream question text MUST NOT appear in your output verbatim or
paraphrased — the SUBSET file ships in the public Sanctum repo while
the upstream JSON does NOT (license: null).

{FAMILY_RULES}

You produce two strings:

1. scoring_pattern — a regex prefixed with "~" OR an exact case-insensitive
   substring that would match a CORRECT answer. Examples:
     • r"~(?i)\\bAmcache\\b"
     • r"~(?i)EventID\\s*[:=]?\\s*1\\b"
     • r"~(?i)\\.pf\\b"
     • r"~(?i)\\bUserAssist\\b"
   Constraints:
     - The smallest identifying token that would appear in any plausible
       correct answer. Avoid copying the verbatim upstream answer.
     - Must compile as a Python regex when prefixed-stripped.
     - Case-insensitive ((?i)) where practical.

2. justification — ONE technical sentence describing why this question
   maps to this Sanctum family. Written from the SANCTUM TOOL angle
   ("get_amcache lookup", "Prefetch parser", "BAM SID-keyed table"),
   NOT from the question's angle. Token-set overlap with the upstream
   question text MUST be < 0.30 Jaccard.

   Good: "Boot-time execution evidence answerable from SysMain Prefetch traces."
   Bad : "Determines when the program was last run via Prefetch entries."
   (the second one paraphrases the upstream wording — high Jaccard)

Output format — exact JSON, no preamble, no markdown fences:
{{"scoring_pattern": "...", "justification": "..."}}
"""


# --- Data structures ---------------------------------------------------


@dataclass(frozen=True)
class CorpusRecord:
    line_offset: int
    question_text: str
    answer_text: str  # may be empty if upstream omits


@dataclass(frozen=True)
class Classification:
    line_offset: int
    family: str | None
    reason: str


@dataclass(frozen=True)
class DraftEntry:
    line_offset: int
    family: str
    scoring_pattern: str
    justification: str


@dataclass
class CostTracker:
    """Accumulates token usage + USD cost across all calls."""

    total_input: int = 0
    total_output: int = 0
    total_cache_read: int = 0
    total_cache_write: int = 0

    def add(self, usage: Any) -> None:
        self.total_input += int(getattr(usage, "input_tokens", 0) or 0)
        self.total_output += int(getattr(usage, "output_tokens", 0) or 0)
        self.total_cache_write += int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
        self.total_cache_read += int(getattr(usage, "cache_read_input_tokens", 0) or 0)

    def estimate_usd(self) -> float:
        return (
            self.total_input * OPUS_4_7_PRICING["input"] / 1_000_000
            + self.total_output * OPUS_4_7_PRICING["output"] / 1_000_000
            + self.total_cache_read * OPUS_4_7_PRICING["cache_read"] / 1_000_000
            + self.total_cache_write * OPUS_4_7_PRICING["cache_write"] / 1_000_000
        )


# --- Corpus loading ----------------------------------------------------


def _extract_text(record: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        val = record.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def load_corpus(path: Path) -> list[CorpusRecord]:
    """Load and validate the upstream JSON; emit CorpusRecord per entry.

    Refuses gracefully if the JSON is malformed or not a list — same
    invariant the eval driver and Jaccard test rely on.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"corpus cache not present at {path}. Run "
            f"`python3 -m scripts.fetch_dfir_metric --sha256 <hex>` first."
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(
            f"corpus at {path} is not a JSON array (got {type(raw).__name__})"
        )
    records: list[CorpusRecord] = []
    for offset, record in enumerate(raw):
        if not isinstance(record, dict):
            continue
        q = _extract_text(record, QUESTION_TEXT_KEYS)
        if not q:
            continue
        a = _extract_text(record, ANSWER_KEYS)
        records.append(CorpusRecord(line_offset=offset, question_text=q, answer_text=a))
    return records


# --- Jaccard guard (mirrors test_subset_jaccard_similarity.py) ---------


def _tokenize(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text)}


def jaccard(a: str, b: str) -> float:
    ta, tb = _tokenize(a), _tokenize(b)
    if not ta and not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


# --- Anthropic SDK boundary --------------------------------------------


def _build_anthropic_client() -> Any:
    """Lazy-import + construct the real Anthropic client.

    Mirrors run_dfir_metric_eval.py's lazy-import pattern so this
    module imports cleanly on machines without the SDK installed.
    """
    if "ANTHROPIC_API_KEY" not in os.environ:
        raise RuntimeError(
            "ANTHROPIC_API_KEY env var not set; this script requires a live API key."
        )
    try:
        import anthropic  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "anthropic SDK not installed. `pip install anthropic` first."
        ) from exc
    return anthropic.Anthropic()


def _strip_json_fences(text: str) -> str:
    """Defensively strip ```json fences if the model adds them despite the prompt.

    Models occasionally re-add markdown fences even when explicitly told
    not to. Stripping is a 5-line safety net rather than failing on
    well-intended-but-wrong output.
    """
    text = text.strip()
    if text.startswith("```"):
        # Drop opening fence (possibly ```json), keep until closing fence.
        text = re.sub(r"^```(?:json)?\s*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


def _call_messages(
    client: Any,
    *,
    system: str,
    user: str,
    model: str,
    max_tokens: int,
    temperature: float,
    cost_tracker: CostTracker,
) -> str:
    """Single Claude call. Returns the text content; updates cost_tracker."""
    response = client.messages.create(
        model=model,
        system=system,
        messages=[{"role": "user", "content": user}],
        max_tokens=max_tokens,
        temperature=temperature,
    )
    cost_tracker.add(response.usage)
    if not response.content:
        return ""
    parts = [getattr(b, "text", "") or "" for b in response.content]
    return "".join(parts)


# --- Pass 1: classification --------------------------------------------


def _format_batch(records: Iterable[CorpusRecord]) -> str:
    lines = ["Classify these forensic questions:", ""]
    for r in records:
        # Truncate very long questions to keep batches predictable on
        # context size. 800 chars is generous for any real DFIR question.
        q = r.question_text[:800]
        lines.append(f"[{r.line_offset}] {q}")
    return "\n".join(lines)


def _parse_classifications(raw: str, expected_offsets: set[int]) -> list[Classification]:
    """Parse a model response into Classification[]. Tolerates partial output.

    Drops any entry with an unknown line_offset or invalid family. Logs
    nothing — caller decides whether to halt or proceed on a short batch.
    """
    raw = _strip_json_fences(raw)
    parsed: dict[str, Any]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    items = parsed.get("classifications")
    if not isinstance(items, list):
        return []
    out: list[Classification] = []
    seen: set[int] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        offset = item.get("line_offset")
        family = item.get("family")
        reason = item.get("reason", "")
        if not isinstance(offset, int) or offset not in expected_offsets:
            continue
        if offset in seen:
            continue
        if family is not None and family not in FAMILIES:
            continue
        seen.add(offset)
        out.append(
            Classification(
                line_offset=offset,
                family=family,
                reason=str(reason)[:200],
            )
        )
    return out


def classify_corpus(
    client: Any,
    records: list[CorpusRecord],
    *,
    model: str,
    batch_size: int,
    cost_tracker: CostTracker,
    max_cost_usd: float,
) -> list[Classification]:
    """Run Pass 1 — batch classification across the entire corpus.

    Returns one Classification per record (even skipped ones, with
    family=None). Halts if cost ceiling exceeded; partial output is
    safe — caller can still continue to Pass 2 on whatever returned.
    """
    classifications: list[Classification] = []
    for i in range(0, len(records), batch_size):
        if cost_tracker.estimate_usd() >= max_cost_usd:
            print(
                f"[expand_subset] cost ceiling reached (${cost_tracker.estimate_usd():.4f} ≥ "
                f"${max_cost_usd:.4f}); halting Pass 1 with {len(classifications)} records classified",
                file=sys.stderr,
            )
            break
        batch = records[i : i + batch_size]
        expected = {r.line_offset for r in batch}
        user = _format_batch(batch)
        try:
            raw = _call_messages(
                client,
                system=CLASSIFY_SYSTEM,
                user=user,
                model=model,
                max_tokens=4000,
                temperature=0.0,
                cost_tracker=cost_tracker,
            )
        except Exception as exc:  # noqa: BLE001 — surface SDK error verbatim
            print(f"[expand_subset] classify batch {i} failed: {exc}", file=sys.stderr)
            continue
        batch_results = _parse_classifications(raw, expected)
        classifications.extend(batch_results)
        # Progress log every batch so the operator can ctrl-C with state visible.
        kept = sum(1 for c in batch_results if c.family is not None)
        print(
            f"[expand_subset] Pass 1 batch {i // batch_size + 1}: "
            f"classified {len(batch_results)}/{len(batch)} (in-scope={kept}); "
            f"running cost ${cost_tracker.estimate_usd():.4f}",
            file=sys.stderr,
        )
    return classifications


# --- Pass 2: drafting --------------------------------------------------


def _format_draft_user(record: CorpusRecord, family: str, retry_hint: str = "") -> str:
    blocks = [
        f"Question (line_offset={record.line_offset}, family={family}):",
        f"  {record.question_text}",
        "",
    ]
    if record.answer_text:
        blocks.extend(
            [
                "Answer (context only — DO NOT copy verbatim):",
                f"  {record.answer_text}",
                "",
            ]
        )
    blocks.append(
        "Draft a SubsetEntry for this question. Justification Jaccard against "
        "upstream question MUST be < 0.30."
    )
    if retry_hint:
        blocks.append("")
        blocks.append(retry_hint)
    return "\n".join(blocks)


def _parse_draft(raw: str) -> tuple[str, str] | None:
    """Parse {scoring_pattern, justification} JSON. Return None on failure."""
    raw = _strip_json_fences(raw)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    sp = parsed.get("scoring_pattern")
    jt = parsed.get("justification")
    if not isinstance(sp, str) or not isinstance(jt, str):
        return None
    return sp.strip(), jt.strip()


def _validate_draft(scoring_pattern: str, justification: str, upstream_q: str) -> str | None:
    """Return None if valid; else a short reason string (used in retry hint)."""
    if not scoring_pattern:
        return "scoring_pattern is empty"
    if not justification:
        return "justification is empty"
    pattern_body = scoring_pattern[1:] if scoring_pattern.startswith("~") else scoring_pattern
    try:
        re.compile(pattern_body)
    except re.error as exc:
        return f"scoring_pattern fails to compile as regex: {exc}"
    sim = jaccard(justification, upstream_q)
    if sim >= JACCARD_THRESHOLD:
        return f"justification Jaccard={sim:.2f} ≥ {JACCARD_THRESHOLD} (paraphrase risk)"
    return None


def draft_entry(
    client: Any,
    record: CorpusRecord,
    family: str,
    *,
    model: str,
    retries: int,
    cost_tracker: CostTracker,
    max_cost_usd: float,
) -> DraftEntry | None:
    """Draft one SubsetEntry with retry-on-validation-failure.

    Each retry feeds the failure reason back to the model with a sharper
    "rewrite from a different angle" hint — the model has the chance to
    correct itself before we give up.
    """
    retry_hint = ""
    last_failure_reason = ""
    for attempt in range(1, retries + 1):
        if cost_tracker.estimate_usd() >= max_cost_usd:
            print(
                f"[expand_subset] cost ceiling reached during draft of "
                f"line_offset={record.line_offset}; dropping",
                file=sys.stderr,
            )
            return None
        # Mild temperature so retries actually explore, instead of
        # re-emitting the same words. Pass 1 ran at 0.0 (deterministic
        # classification); Pass 2 needs creativity to dodge Jaccard.
        temperature = 0.2 + 0.2 * (attempt - 1)
        try:
            raw = _call_messages(
                client,
                system=DRAFT_SYSTEM,
                user=_format_draft_user(record, family, retry_hint),
                model=model,
                max_tokens=400,
                temperature=min(temperature, 1.0),
                cost_tracker=cost_tracker,
            )
        except Exception as exc:  # noqa: BLE001
            print(
                f"[expand_subset] draft line_offset={record.line_offset} attempt {attempt} "
                f"raised: {exc}",
                file=sys.stderr,
            )
            time.sleep(1.0)
            continue
        parsed = _parse_draft(raw)
        if parsed is None:
            last_failure_reason = "model output was not valid JSON in the expected shape"
            retry_hint = (
                f"Your previous output failed to parse. Reason: {last_failure_reason}. "
                f"Emit ONLY the JSON object, no markdown fences, no preamble."
            )
            continue
        sp, jt = parsed
        failure_reason = _validate_draft(sp, jt, record.question_text)
        if failure_reason is None:
            return DraftEntry(
                line_offset=record.line_offset,
                family=family,
                scoring_pattern=sp,
                justification=jt,
            )
        last_failure_reason = failure_reason
        retry_hint = (
            f"Your previous draft failed validation: {failure_reason}. "
            f"Rewrite the justification from a completely different angle — "
            f"focus on the SANCTUM TOOL or PARSER (e.g., 'get_amcache row', "
            f"'Prefetch parser output', 'BAM SID-keyed table'), NOT on what "
            f"the upstream question asks. Avoid words from the question text."
        )
    print(
        f"[expand_subset] draft line_offset={record.line_offset} family={family} "
        f"failed after {retries} retries: {last_failure_reason}",
        file=sys.stderr,
    )
    return None


# --- Selection: balance per-family --------------------------------------


def select_balanced(
    drafts: list[DraftEntry],
    seed_entries: list[DraftEntry],
    *,
    target_per_family: int,
) -> list[DraftEntry]:
    """Combine seed + drafts, capping each family at target_per_family.

    Seed entries always win (preserve user-authored ground truth). Drafts
    fill the remaining slots in line_offset order — stable across runs
    given identical classification (Pass 1 is temperature=0).
    """
    # Index seed entries by family.
    seed_by_family: dict[str, list[DraftEntry]] = {f: [] for f in FAMILIES}
    seed_offsets: set[int] = set()
    for s in seed_entries:
        seed_by_family[s.family].append(s)
        seed_offsets.add(s.line_offset)
    # Index drafts by family, excluding any line_offsets already in seed.
    drafts_by_family: dict[str, list[DraftEntry]] = {f: [] for f in FAMILIES}
    for d in drafts:
        if d.line_offset in seed_offsets:
            continue
        drafts_by_family[d.family].append(d)
    # Sort drafts within each family by line_offset for deterministic order.
    for f in FAMILIES:
        drafts_by_family[f].sort(key=lambda e: e.line_offset)
    # Take up to target_per_family per family (seed counts toward target).
    selected: list[DraftEntry] = []
    for f in FAMILIES:
        kept = list(seed_by_family[f])
        remaining_slots = max(0, target_per_family - len(kept))
        kept.extend(drafts_by_family[f][:remaining_slots])
        selected.extend(kept)
    selected.sort(key=lambda e: e.line_offset)
    return selected


# --- Output rendering --------------------------------------------------


def _render_entry(e: DraftEntry) -> str:
    # Use repr() on strings so backslash-rich regex literals round-trip
    # without shell-quoting drama. Result: a single SubsetEntry(...)
    # literal indented inside the SUBSET tuple.
    return (
        "    SubsetEntry(\n"
        f"        line_offset={e.line_offset},\n"
        f"        family={e.family!r},\n"
        f"        scoring_pattern={e.scoring_pattern!r},\n"
        f"        justification={e.justification!r},\n"
        "    ),"
    )


_MODULE_HEADER = '''\
"""License-clean subset specification for the DFIR-Metric Module II CTF.

This module identifies WHICH upstream questions Sanctum evaluates against
and HOW each one is scored — but it never quotes the upstream question
or answer text. The full upstream JSON is fetched at runtime by
``scripts/fetch_dfir_metric.py`` into ``.cache/dfir-metric/`` (which is
gitignored). This split is what makes the subset license-clean: the
upstream content (license: null) lives only on the contributor's
machine; the public repo carries only Sanctum's derivative metadata.

License & reproduction details: see ``docs/ACCURACY.md`` § "License &
Reproduction".

Subset shape — each ``SubsetEntry``:
  - ``line_offset``: 0-indexed line in the upstream DFIR-Metric-CTF.json
  - ``family``: one of the 5 canonical Sanctum families (CLAUDE.md #5)
  - ``scoring_pattern``: regex (prefix ``r"~"``) OR exact string our
    derivation; NEVER the verbatim upstream answer
  - ``justification``: one-line rationale for inclusion. Must NOT
    paraphrase the upstream question text — the Jaccard-similarity
    test (``tests/benchmarks/test_subset_jaccard_similarity.py``,
    opt-in) enforces this with token-set overlap < 0.30.

Selection criteria (deep-r R4 — make rubric reviewable without
reading ``scripts/expand_subset.py``).

Inclusion (a question is in the subset iff all four hold):
  1. Answerable from exactly one of the 5 Sanctum artifact families.
  2. Family tag is verifiable from the artifact description alone —
     no cross-family inference needed.
  3. ``scoring_pattern`` is achievable without verbatim copy of the
     upstream answer text (license-clean derivative metadata only).
  4. ``Jaccard(justification, upstream_question_text) < 0.30`` — the
     opt-in test ``test_subset_jaccard_similarity.py`` enforces this.

Exclusion (any of the following disqualifies a question):
  - Requires cross-family synthesis (ambiguous family tag).
  - About a Windows event/artifact not in any Sanctum family — no
    ground-truth coverage in v1.
  - Has a free-text answer not reducible to a substring or regex
    pattern. Promote to TUS@m for paper-grade multi-criterion
    scoring (see ``docs/ACCURACY.md`` § "AC-12 disclaimer").

Generated by ``scripts/expand_subset.py``. Reviewer must approve diff
before commit (humans-in-the-loop on AI-assisted SUBSET authoring).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Family = Literal["AppCompat", "Explorer", "BAM", "Sysmon", "SysMain"]


@dataclass(frozen=True)
class SubsetEntry:
    line_offset: int
    family: Family
    scoring_pattern: str
    justification: str


SUBSET: tuple[SubsetEntry, ...] = (
'''


def render_module(entries: list[DraftEntry]) -> str:
    body = "\n".join(_render_entry(e) for e in entries)
    return _MODULE_HEADER + body + "\n)\n"


# --- Existing-seed loader ----------------------------------------------


def load_existing_seed(path: Path) -> list[DraftEntry]:
    """Import the live SUBSET module to recover seed entries.

    We import-and-introspect rather than regex-parse the file: the module
    is a stable Python source that ``importlib`` can load reliably, and
    introspection survives any future formatting changes that would
    break a regex.
    """
    if not path.exists():
        return []
    sys.path.insert(0, str(path.parent.parent))  # adds project root
    try:
        import importlib

        module = importlib.import_module("tests.benchmarks.dfir_metric_subset")
        # Force reload in case the module was already imported earlier
        # in this process (e.g., by a smoke test).
        importlib.reload(module)
        seed: list[DraftEntry] = []
        for entry in module.SUBSET:
            seed.append(
                DraftEntry(
                    line_offset=entry.line_offset,
                    family=entry.family,
                    scoring_pattern=entry.scoring_pattern,
                    justification=entry.justification,
                )
            )
        return seed
    finally:
        sys.path.pop(0)


# --- CLI ----------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=textwrap.dedent(
            """\
            Expand tests/benchmarks/dfir_metric_subset.py from the seed 5 entries
            to ~45 entries via batched Anthropic API calls. Two-pass design:
            Pass 1 classifies records into Sanctum families; Pass 2 drafts
            scoring patterns + justifications with inline Jaccard validation.

            Default writes to <subset>.proposed; --write overwrites the live file.
            Reviewer eyeballs the diff before commit.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--corpus-cache",
        type=Path,
        default=DEFAULT_CORPUS_PATH,
        help=f"Path to upstream JSON cache (default: {DEFAULT_CORPUS_PATH})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Where to write the proposed SUBSET module (default: {DEFAULT_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--live-subset",
        type=Path,
        default=DEFAULT_LIVE_PATH,
        help=f"Existing SUBSET module to seed from (default: {DEFAULT_LIVE_PATH})",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Overwrite --live-subset instead of writing to --output (still requires reviewer diff before commit)",
    )
    parser.add_argument(
        "--no-preserve-seed",
        action="store_true",
        help="Discard the existing 5 SUBSET entries; build entirely from drafts",
    )
    parser.add_argument(
        "--target-per-family",
        type=int,
        default=DEFAULT_TARGET_PER_FAMILY,
        help=f"Cap entries per family (default: {DEFAULT_TARGET_PER_FAMILY}; 5×9=45 total)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Records per Pass 1 classification call (default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Pass 2 retries per record before giving up (default: {DEFAULT_RETRIES})",
    )
    parser.add_argument(
        "--max-cost-usd",
        type=float,
        default=DEFAULT_MAX_COST_USD,
        help=f"Hard cap on total spend; halts mid-run if exceeded (default: ${DEFAULT_MAX_COST_USD:.2f})",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Anthropic model id (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the proposed module to stdout instead of writing any file",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    print(f"[expand_subset] loading corpus from {args.corpus_cache}", file=sys.stderr)
    records = load_corpus(args.corpus_cache)
    print(f"[expand_subset] {len(records)} records loaded", file=sys.stderr)

    seed: list[DraftEntry] = []
    if not args.no_preserve_seed:
        seed = load_existing_seed(args.live_subset)
        print(f"[expand_subset] preserving {len(seed)} seed entries", file=sys.stderr)

    client = _build_anthropic_client()
    cost_tracker = CostTracker()

    # Pass 1: classify
    print(
        f"[expand_subset] Pass 1: classifying {len(records)} records "
        f"(batch_size={args.batch_size}, max_cost=${args.max_cost_usd:.2f})",
        file=sys.stderr,
    )
    classifications = classify_corpus(
        client,
        records,
        model=args.model,
        batch_size=args.batch_size,
        cost_tracker=cost_tracker,
        max_cost_usd=args.max_cost_usd,
    )
    in_scope = [c for c in classifications if c.family is not None]
    print(
        f"[expand_subset] Pass 1 done: {len(in_scope)}/{len(classifications)} in-scope; "
        f"cost so far ${cost_tracker.estimate_usd():.4f}",
        file=sys.stderr,
    )

    # Per-family count surface so the operator can see imbalance early.
    per_family_pass1: dict[str, int] = {f: 0 for f in FAMILIES}
    for c in in_scope:
        if c.family in per_family_pass1:
            per_family_pass1[c.family] += 1
    print(
        "[expand_subset] Pass 1 per-family in-scope: "
        + ", ".join(f"{f}={per_family_pass1[f]}" for f in FAMILIES),
        file=sys.stderr,
    )

    # Build a {line_offset: CorpusRecord} index for Pass 2 lookups.
    record_by_offset = {r.line_offset: r for r in records}

    # Pass 2: draft, but only as many as we need per family (target +
    # small buffer for retry drops). No need to draft 80 entries when
    # we'll keep at most 45.
    seed_by_family: dict[str, int] = {f: 0 for f in FAMILIES}
    for s in seed:
        seed_by_family[s.family] = seed_by_family.get(s.family, 0) + 1

    drafts: list[DraftEntry] = []
    drafts_by_family_so_far: dict[str, int] = {f: 0 for f in FAMILIES}
    # 50% buffer above target to absorb retry drops.
    needed_per_family = {
        f: max(0, args.target_per_family - seed_by_family.get(f, 0))
        for f in FAMILIES
    }
    buffer_per_family = {
        f: needed_per_family[f] + max(2, needed_per_family[f] // 2) for f in FAMILIES
    }

    print(
        f"[expand_subset] Pass 2: drafting up to "
        + ", ".join(f"{f}={buffer_per_family[f]}" for f in FAMILIES),
        file=sys.stderr,
    )

    drafted_count = 0
    for c in sorted(in_scope, key=lambda x: x.line_offset):
        if cost_tracker.estimate_usd() >= args.max_cost_usd:
            print(
                f"[expand_subset] cost ceiling reached during Pass 2; halting with "
                f"{drafted_count} drafts",
                file=sys.stderr,
            )
            break
        family = c.family
        assert family is not None  # narrowed by the in_scope filter
        if drafts_by_family_so_far[family] >= buffer_per_family[family]:
            continue
        record = record_by_offset[c.line_offset]
        entry = draft_entry(
            client,
            record,
            family,
            model=args.model,
            retries=args.retries,
            cost_tracker=cost_tracker,
            max_cost_usd=args.max_cost_usd,
        )
        if entry is None:
            continue
        drafts.append(entry)
        drafts_by_family_so_far[family] += 1
        drafted_count += 1
        if drafted_count % 5 == 0:
            print(
                f"[expand_subset] Pass 2 progress: {drafted_count} drafts; "
                f"per-family={drafts_by_family_so_far}; "
                f"cost ${cost_tracker.estimate_usd():.4f}",
                file=sys.stderr,
            )

    # Selection
    selected = select_balanced(
        drafts, seed, target_per_family=args.target_per_family
    )

    per_family_final: dict[str, int] = {f: 0 for f in FAMILIES}
    for e in selected:
        per_family_final[e.family] += 1

    # Final validation pass — defensive even though draft_entry already
    # validated. Catches any regression in the rendering or selection
    # pipeline before we write a broken file.
    upstream_by_offset = {r.line_offset: r for r in records}
    failures: list[str] = []
    for e in selected:
        if e.line_offset not in upstream_by_offset:
            failures.append(f"line_offset={e.line_offset} not in corpus")
            continue
        upstream_q = upstream_by_offset[e.line_offset].question_text
        # Seed entries are user-authored and may have higher Jaccard
        # than draft entries — they're grandfathered. New drafts MUST
        # pass Jaccard.
        if any(
            s.line_offset == e.line_offset
            and s.scoring_pattern == e.scoring_pattern
            and s.justification == e.justification
            for s in seed
        ):
            continue
        reason = _validate_draft(e.scoring_pattern, e.justification, upstream_q)
        if reason is not None:
            failures.append(f"line_offset={e.line_offset} ({e.family}): {reason}")

    if failures:
        print(
            "[expand_subset] FATAL — final validation failed for new drafts:",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 2

    rendered = render_module(selected)

    print("", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(
        f"[expand_subset] DONE: {len(selected)} entries (target ~{5 * args.target_per_family})",
        file=sys.stderr,
    )
    print(
        "[expand_subset] per-family: "
        + ", ".join(f"{f}={per_family_final[f]}" for f in FAMILIES),
        file=sys.stderr,
    )
    print(
        f"[expand_subset] cost: ${cost_tracker.estimate_usd():.4f} of "
        f"${args.max_cost_usd:.2f} budget",
        file=sys.stderr,
    )

    if args.dry_run:
        print(rendered)
        return 0

    target_path = args.live_subset if args.write else args.output
    if args.write:
        print(
            f"[expand_subset] --write set; overwriting {target_path}",
            file=sys.stderr,
        )
    else:
        print(
            f"[expand_subset] writing proposal to {target_path} "
            f"(diff against {args.live_subset} before commit)",
            file=sys.stderr,
        )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

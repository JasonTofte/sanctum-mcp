"""Phase C smoke tests for the DFIR-Metric eval driver — opt-in (``--benchmark``).

These exercise the driver scaffolding end-to-end against a synthetic
case fixture, with a ``MockAnthropicClient`` injected so the test
never spends real API budget. They cover:

  - AC-1a: the driver speaks real MCP stdio (subprocess + handshake +
    tools/list + at least one typed-tool call)
  - AC-1b: subprocess lifecycle hygiene — no leaked
    ``python -m sanctum.server`` processes after a run
  - AC-2 + AC-4: schema correctness end-to-end
  - AC-8: zero real API calls in CI
  - AC-11: subprocess timeout/crash recovery (handshake hang, hang
    during ``tools/call``, crash mid-call) using stub MCP servers
    under ``tests/benchmarks/_stubs/``

The mock returns canned ``content`` blocks per call. To exercise the
agentic loop on the Sanctum arm we feed one ``tool_use`` turn for
``get_amcache`` followed by a final text block with
``<answer>...</answer>``. The MCP subprocess is real for those tests
(answers from the synthetic Amcache fixture).

Bare-arm smoke turns return text-only responses; no MCP subprocess
spawned.
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from scripts import run_dfir_metric_eval as eval_driver

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_ROOT = REPO_ROOT / "tests" / "fixtures"
SYNTHETIC_CASE_ID = "case_temp_exec_001_synthetic"
STUB_DIR = Path(__file__).parent / "_stubs"


# --- Mock Anthropic client ------------------------------------------------


@dataclass
class _MockUsage:
    input_tokens: int = 100
    output_tokens: int = 50
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


@dataclass
class _MockTextBlock:
    text: str
    type: str = "text"


@dataclass
class _MockToolUseBlock:
    id: str
    name: str
    input: dict[str, Any]
    type: str = "tool_use"


@dataclass
class _MockMessage:
    content: list[Any]
    usage: _MockUsage = field(default_factory=_MockUsage)
    stop_reason: str = "end_turn"


@dataclass
class MockAnthropicClient:
    """Returns canned ``Message`` objects in FIFO order.

    Mirrors the Anthropic SDK shape ``client.messages.create(...)``
    used by the driver. Each call pops one ``_MockMessage`` from
    ``responses``. If the queue is empty the test fails loudly —
    that's a signal that the driver issued more calls than the test
    set up canned responses for, which is itself a regression worth
    catching.
    """

    responses: list[_MockMessage] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    @property
    def messages(self) -> MockAnthropicClient:
        return self

    def create(self, **kwargs: Any) -> _MockMessage:  # noqa: D401  (SDK shape)
        self.calls.append(kwargs)
        if not self.responses:
            raise AssertionError(
                f"MockAnthropicClient ran out of canned responses; call kwargs={kwargs!r}"
            )
        return self.responses.pop(0)


def _final_answer_response(answer: str) -> _MockMessage:
    return _MockMessage(content=[_MockTextBlock(text=f"<answer>{answer}</answer>")])


def _tool_use_then_answer(
    *, tool_name: str, tool_input: dict[str, Any], answer: str
) -> list[_MockMessage]:
    """Two-turn canned conversation: tool_use → final text."""
    return [
        _MockMessage(
            content=[_MockToolUseBlock(id="toolu_test_1", name=tool_name, input=tool_input)],
            stop_reason="tool_use",
        ),
        _final_answer_response(answer),
    ]


# --- Fixture helpers ------------------------------------------------------


@pytest.fixture
def server_env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "SANCTUM_LEDGER_HMAC_KEY": secrets.token_hex(32),
            "SANCTUM_LEDGER_PATH": str(tmp_path / "ledger.jsonl"),
            "SANCTUM_CASES_ROOT": str(FIXTURES_ROOT),
            "SANCTUM_SKIP_MOUNT_CHECK": "1",
            "SANCTUM_USE_FIXTURE_SIDECAR": "1",
            "SANCTUM_LOG_LEVEL": "WARNING",
        }
    )
    return env


def _mk_question(
    *,
    q_id: str = "smoke-q-1",
    family: str = "AppCompat",
    text: str = "Was runtimebroker.exe executed on this host?",
    scoring_pattern: str = r"~(?i)\bAmcache\b",
    bare_evidence: bytes = b"synthetic-bare-evidence-bytes",
) -> Any:
    return eval_driver.Question(
        q_id=q_id,
        family=family,
        text=text,
        scoring_pattern=scoring_pattern,
        bare_evidence=bare_evidence,
    )


# --- AC-8: no real API ----------------------------------------------------


def test_smoke_uses_mock_anthropic(server_env: dict[str, str], tmp_path: Path) -> None:
    """The mock is the only client touched; no anthropic.Anthropic call lands."""
    client = MockAnthropicClient(
        responses=[_final_answer_response("Amcache.hve InventoryApplicationFile")]
    )
    questions = (_mk_question(),)

    report = eval_driver.run_eval(
        arm="bare",
        n_runs=1,
        questions=questions,
        anthropic_client=client,
        case_root=FIXTURES_ROOT / SYNTHETIC_CASE_ID,
        output_dir=tmp_path,
        server_env=server_env,
    )

    assert len(client.calls) == 1, f"expected exactly 1 mock call, got {len(client.calls)}"
    assert report.cost_usd >= 0.0
    assert report.partial is False


# --- AC-1a + AC-2 + AC-4: schema + transport correctness ------------------


def test_smoke_one_question_per_family_each_arm(server_env: dict[str, str], tmp_path: Path) -> None:
    """End-to-end: 1 question, both arms, N=1; schema matches AC-4 verbatim."""
    questions = (_mk_question(),)
    # Sanctum arm: tool_use → final answer (2 turns). Bare arm: 1 turn.
    sanctum_turns = _tool_use_then_answer(
        tool_name="get_amcache",
        tool_input={"case_id": SYNTHETIC_CASE_ID},
        answer="Amcache.hve InventoryApplicationFile",
    )
    bare_turns = [_final_answer_response("Amcache.hve InventoryApplicationFile")]
    client = MockAnthropicClient(responses=[*sanctum_turns, *bare_turns])

    report = eval_driver.run_eval(
        arm="both",
        n_runs=1,
        questions=questions,
        anthropic_client=client,
        case_root=FIXTURES_ROOT / SYNTHETIC_CASE_ID,
        output_dir=tmp_path,
        server_env=server_env,
        mcp_subprocess_args=(sys.executable, "-m", "sanctum.server"),
    )

    # AC-4: per_question rows = N_questions × N_arms × N_runs
    assert (
        len(report.per_question) == 2
    ), f"expected 2 rows (1 Q × 2 arms × 1 run), got {len(report.per_question)}"
    arms_seen = {row.arm for row in report.per_question}
    assert arms_seen == {"sanctum", "bare"}, f"unexpected arms: {arms_seen}"

    sanctum_row = next(r for r in report.per_question if r.arm == "sanctum")
    bare_row = next(r for r in report.per_question if r.arm == "bare")

    # AC-2: bare arm has empty audit_ids and null claim_status
    assert bare_row.audit_ids == ()
    assert bare_row.claim_status is None

    # AC-1a: sanctum arm row carries at least one audit_id from the
    # tool call (proves the driver actually called into MCP and read
    # the ledger back).
    assert len(sanctum_row.audit_ids) >= 1, "Sanctum arm must surface audit_ids from tool calls"

    # AC-4: aggregates has both arms with the right shape
    assert set(report.aggregates.keys()) == {"sanctum", "bare"}
    for arm, agg in report.aggregates.items():
        assert 0.0 <= agg.accuracy_mean <= 1.0
        if arm == "bare":
            assert agg.false_confidence_rate is None
            assert agg.abstention_rate is None


def test_smoke_no_subprocess_leaks(server_env: dict[str, str], tmp_path: Path) -> None:
    """AC-1b: zero ``python -m sanctum.server`` subprocesses remain alive after run."""
    questions = (_mk_question(),)
    client = MockAnthropicClient(
        responses=_tool_use_then_answer(
            tool_name="get_amcache",
            tool_input={"case_id": SYNTHETIC_CASE_ID},
            answer="Amcache.hve InventoryApplicationFile",
        )
    )

    eval_driver._spawned_procs.clear()
    eval_driver.run_eval(
        arm="sanctum",
        n_runs=1,
        questions=questions,
        anthropic_client=client,
        case_root=FIXTURES_ROOT / SYNTHETIC_CASE_ID,
        output_dir=tmp_path,
        server_env=server_env,
        mcp_subprocess_args=(sys.executable, "-m", "sanctum.server"),
    )

    # Every spawned subprocess must have a non-None returncode (terminated).
    leaked = [p for p in eval_driver._spawned_procs if p.poll() is None]
    assert not leaked, f"leaked subprocesses: {[p.pid for p in leaked]}"
    assert eval_driver._spawned_procs, "smoke test must have spawned at least one MCP subprocess"


# --- AC-11: subprocess timeout / crash recovery ---------------------------


def _stub_args(stub_name: str) -> tuple[str, ...]:
    return (sys.executable, str(STUB_DIR / stub_name))


def test_smoke_subprocess_handshake_timeout(server_env: dict[str, str], tmp_path: Path) -> None:
    """AC-11: handshake never returns → SIGTERM, record ``<subprocess_timeout>`` row."""
    questions = (_mk_question(),)
    client = MockAnthropicClient(
        responses=[]
    )  # never reached for sanctum arm; handshake fails first

    report = eval_driver.run_eval(
        arm="sanctum",
        n_runs=1,
        questions=questions,
        anthropic_client=client,
        case_root=FIXTURES_ROOT / SYNTHETIC_CASE_ID,
        output_dir=tmp_path,
        server_env=server_env,
        mcp_subprocess_args=_stub_args("mcp_handshake_hang.py"),
        handshake_timeout_s=1.0,
        per_q_timeout_s=2.0,
    )

    assert len(report.per_question) == 1
    row = report.per_question[0]
    assert row.predicted == "<subprocess_timeout>", f"unexpected predicted={row.predicted!r}"
    assert row.correct is False
    assert row.audit_ids == ()
    # Run continued — it didn't abort:
    assert report.partial is False or report.halt_reason != "cost_cap_exceeded"


def test_smoke_subprocess_hang_during_call(server_env: dict[str, str], tmp_path: Path) -> None:
    """AC-11: handshake OK, ``tools/call`` hangs → SIGTERM, ``<subprocess_timeout>``."""
    questions = (_mk_question(),)
    client = MockAnthropicClient(
        responses=_tool_use_then_answer(
            tool_name="get_amcache",
            tool_input={"case_id": SYNTHETIC_CASE_ID},
            answer="(should never see this)",
        )
    )

    report = eval_driver.run_eval(
        arm="sanctum",
        n_runs=1,
        questions=questions,
        anthropic_client=client,
        case_root=FIXTURES_ROOT / SYNTHETIC_CASE_ID,
        output_dir=tmp_path,
        server_env=server_env,
        mcp_subprocess_args=_stub_args("mcp_call_hang.py"),
        handshake_timeout_s=2.0,
        per_q_timeout_s=2.0,
    )

    assert len(report.per_question) == 1
    row = report.per_question[0]
    assert row.predicted == "<subprocess_timeout>", f"unexpected predicted={row.predicted!r}"
    assert row.correct is False


def test_smoke_subprocess_crash_during_call(server_env: dict[str, str], tmp_path: Path) -> None:
    """AC-11: subprocess exits non-zero mid-call → ``<subprocess_crash>``."""
    questions = (_mk_question(),)
    client = MockAnthropicClient(
        responses=_tool_use_then_answer(
            tool_name="get_amcache",
            tool_input={"case_id": SYNTHETIC_CASE_ID},
            answer="(should never see this)",
        )
    )

    report = eval_driver.run_eval(
        arm="sanctum",
        n_runs=1,
        questions=questions,
        anthropic_client=client,
        case_root=FIXTURES_ROOT / SYNTHETIC_CASE_ID,
        output_dir=tmp_path,
        server_env=server_env,
        mcp_subprocess_args=_stub_args("mcp_call_crash.py"),
        handshake_timeout_s=2.0,
        per_q_timeout_s=5.0,
    )

    assert len(report.per_question) == 1
    row = report.per_question[0]
    assert row.predicted == "<subprocess_crash>", f"unexpected predicted={row.predicted!r}"
    assert row.correct is False

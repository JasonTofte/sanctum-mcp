"""Architectural-boundary tests.

These tests exist to prove — in CI, for every commit — that known bypass
classes from the hackathon judging rubric do not succeed against the MCP
server. The suite will grow as additional architectural invariants are added.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sanctum import server


def test_case_path_traversal_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A case_id containing `..` MUST NOT escape the cases root."""
    monkeypatch.setenv(server.CASES_ROOT_ENV, str(tmp_path))
    (tmp_path / "safe").mkdir()

    with pytest.raises(ValueError):
        server._resolve_case("../etc")


def test_absolute_case_id_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Absolute paths as case_id MUST NOT escape the cases root."""
    monkeypatch.setenv(server.CASES_ROOT_ENV, str(tmp_path))

    with pytest.raises(ValueError):
        server._resolve_case("/etc/passwd")


def test_missing_case_raises_filenotfound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(server.CASES_ROOT_ENV, str(tmp_path))

    with pytest.raises(FileNotFoundError):
        server._resolve_case("does-not-exist")


def test_get_amcache_output_is_evidence_wrapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``get_amcache`` output MUST be wrapped in ``<evidence-untrusted>``."""
    cases = tmp_path / "cases"
    case = cases / "smoke"
    (case / "registry").mkdir(parents=True)
    (case / "registry" / "Amcache.hve").write_bytes(b"stub hive")

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))

    out = server.get_amcache("smoke")
    assert out.startswith("<evidence-untrusted>")
    assert out.rstrip().endswith("</evidence-untrusted>")


def test_server_exposes_no_write_tool() -> None:
    """No exported MCP tool name may include write/exec/delete verbs.

    The architectural guarantee is that the agent physically cannot run
    destructive commands because the destructive surface does not exist.
    This test enforces that invariant at the module level.
    """
    banned = {"write", "exec", "shell", "run", "delete", "rm", "mv", "cp_over", "unlink"}
    for tool_name in dir(server):
        if tool_name.startswith("_"):
            continue
        assert not any(b in tool_name.lower() for b in banned), (
            f"server module exports a banned-verb symbol: {tool_name}"
        )

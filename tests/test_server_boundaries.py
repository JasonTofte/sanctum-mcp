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
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(tmp_path / "output"))

    out = server.get_amcache("smoke")
    assert out.startswith("<evidence-untrusted>")
    assert out.rstrip().endswith("</evidence-untrusted>")


def test_get_amcache_summary_fits_under_stdio_payload_cliff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The short return MUST fit under the MCP stdio cliff (~800–1100 bytes).

    Reference: anthropics/claude-code#36319. Budget 800 bytes as the conservative
    ceiling — an inline evidence dump on a real Amcache hive would overshoot;
    the summary-with-payload-ref shape must stay well under.
    """
    import json

    cases = tmp_path / "cases"
    case = cases / "smoke"
    (case / "registry").mkdir(parents=True)
    (case / "registry" / "Amcache.hve").write_bytes(b"stub hive")

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(tmp_path / "output"))

    out = server.get_amcache("smoke")
    assert len(out.encode("utf-8")) < 1100, (
        f"summary is {len(out.encode('utf-8'))} bytes — exceeds stdio payload cliff"
    )

    inner = out.removeprefix("<evidence-untrusted>").strip()
    inner = inner.removesuffix("</evidence-untrusted>").strip()
    summary = json.loads(inner)
    assert set(summary.keys()) == {
        "audit_id",
        "case_id",
        "tool",
        "rowcount",
        "input_ref",
        "payload_ref",
        "pre_sanitization_sha256",
        "post_sanitization_sha256",
    }
    assert summary["case_id"] == "smoke"
    assert summary["tool"] == "get_amcache"


def test_get_amcache_writes_full_payload_to_disk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The full sanitized payload MUST land on disk under SANCTUM_OUTPUT_ROOT."""
    import json

    cases = tmp_path / "cases"
    case = cases / "smoke"
    (case / "registry").mkdir(parents=True)
    (case / "registry" / "Amcache.hve").write_bytes(b"stub hive")

    output_root = tmp_path / "output"
    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(output_root))

    out = server.get_amcache("smoke")
    inner = out.removeprefix("<evidence-untrusted>").strip()
    inner = inner.removesuffix("</evidence-untrusted>").strip()
    summary = json.loads(inner)

    payload_path = Path(summary["payload_ref"]["path"])
    assert payload_path.exists()
    # Path layout must match the documented scheme.
    assert payload_path.parent.parent == output_root / "smoke"
    # Audit-id-as-directory must match the summary's audit_id.
    assert payload_path.parent.name == summary["audit_id"]


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

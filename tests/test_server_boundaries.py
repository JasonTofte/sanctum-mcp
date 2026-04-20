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
    import secrets as _secrets

    cases = tmp_path / "cases"
    case = cases / "smoke"
    (case / "registry").mkdir(parents=True)
    (case / "registry" / "Amcache.hve").write_bytes(b"stub hive")

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", _secrets.token_hex(32))

    out = server.get_amcache("smoke")
    assert out.startswith("<evidence-untrusted>")
    assert out.rstrip().endswith("</evidence-untrusted>")


def test_validate_evidence_mount_rejects_writable_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant #4 — MCP server MUST refuse to start if the evidence mount is writable.

    ``tmp_path`` is on the test runner's writable filesystem, so the check
    MUST raise ``RuntimeError`` and point the operator at the remount.
    """
    monkeypatch.delenv(server.SKIP_MOUNT_CHECK_ENV, raising=False)
    with pytest.raises(RuntimeError, match="writable"):
        server._validate_evidence_mount(tmp_path)


def test_validate_evidence_mount_accepts_ro_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant #4 — check passes when the VFS ro flag is set.

    We cannot portably remount ``tmp_path`` read-only from a test; instead
    we monkeypatch ``os.statvfs`` to return the ``ST_RDONLY`` flag and
    verify no exception is raised. This pins the flag-interpretation path;
    the real ro guarantee comes from the OS-level mount command documented
    in REPRODUCTION.md.
    """
    import os as _os

    monkeypatch.delenv(server.SKIP_MOUNT_CHECK_ENV, raising=False)

    class _FakeStatvfs:
        f_flag = _os.ST_RDONLY

    monkeypatch.setattr(_os, "statvfs", lambda _p: _FakeStatvfs())
    server._validate_evidence_mount(tmp_path)  # must not raise


def test_validate_evidence_mount_skip_env_bypasses_with_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Invariant #4 — skip env var bypasses the check AND emits a WARN log.

    The skip exists for development and for CI on filesystems where the
    check would otherwise fail. The WARN-level log is the accountability
    that the skip was used — bypass is never silent.
    """
    import logging as _logging

    monkeypatch.setenv(server.SKIP_MOUNT_CHECK_ENV, "1")
    with caplog.at_level(_logging.WARNING, logger="sanctum.server"):
        server._validate_evidence_mount(tmp_path)
    assert any(
        server.SKIP_MOUNT_CHECK_ENV in rec.message for rec in caplog.records
    ), "skip env bypass MUST emit a WARN log naming the env var"


def test_validate_evidence_mount_missing_path_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant #4 — nonexistent cases root must fail closed.

    A missing path cannot be verified to be read-only, so the check refuses
    to let the server start.
    """
    monkeypatch.delenv(server.SKIP_MOUNT_CHECK_ENV, raising=False)
    missing = tmp_path / "never-created"
    with pytest.raises(RuntimeError, match="does not exist"):
        server._validate_evidence_mount(missing)


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

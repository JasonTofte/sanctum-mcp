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
        assert not any(
            b in tool_name.lower() for b in banned
        ), f"server module exports a banned-verb symbol: {tool_name}"


# ─── claim_finding MCP wrapper ───────────────────────────────────────────────


def _seed_two_family_ledger(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[str, str]:
    """Plant two ledger entries from different families and return their audit_ids.

    Used by claim_finding wrapper tests that need a non-empty, non-fabricated
    audit_id pair so the underlying gate produces a CORROBORATED Finding
    rather than refusing.
    """
    import secrets as _secrets

    from sanctum import audit

    monkeypatch.setenv(audit.LEDGER_ENV, str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv(audit.HMAC_KEY_ENV, _secrets.token_hex(32))

    e1 = audit.append_entry(
        case_id="smoke",
        tool="get_amcache",
        args={"case_id": "smoke"},
        input_ref={"path": "/cases/smoke/Amcache.hve", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=1,
    )
    e2 = audit.append_entry(
        case_id="smoke",
        tool="get_prefetch",
        args={"case_id": "smoke"},
        input_ref={"path": "/cases/smoke/Prefetch", "sha256": "a" * 64},
        pre_sanitization_sha256="b" * 64,
        post_sanitization_sha256="c" * 64,
        rowcount=1,
    )
    return e1.audit_id, e2.audit_id


def test_claim_finding_output_is_evidence_wrapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``claim_finding`` output MUST be wrapped in ``<evidence-untrusted>``.

    Same invariant as ``get_amcache`` (CLAUDE.md #2) — the wrapper signals to
    the LLM that the response is data, not instructions, regardless of whether
    the payload is evidence-authored or server-authored.
    """
    import json as _json

    aid1, aid2 = _seed_two_family_ledger(monkeypatch, tmp_path)

    out = server.claim_finding(
        case_id="smoke",
        hypothesis="X ran",
        audit_ids=[aid1, aid2],
    )
    assert out.startswith("<evidence-untrusted>")
    assert out.rstrip().endswith("</evidence-untrusted>")

    # Strip wrapper and confirm the JSON describes a CORROBORATED finding.
    inner = out.removeprefix("<evidence-untrusted>").rstrip()
    inner = inner.removesuffix("</evidence-untrusted>").strip()
    body = _json.loads(inner)
    assert body["tier"] == "CORROBORATED"
    assert body["n_distinct_families"] == 2
    assert sorted(body["families"]) == ["AppCompat", "SysMain"]
    # confirmation_basis surfaces in the LLM-visible payload — a downstream
    # consumer can distinguish "the gate just barely fired" from
    # "two genuinely independent trust roots agree".
    assert body["confirmation_basis"] == "independent_artifacts"


def test_claim_finding_refuses_empty_audit_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty audit_ids MUST refuse — a finding requires at least one source."""
    import secrets as _secrets

    from sanctum.finding import ClaimFindingError

    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", _secrets.token_hex(32))

    with pytest.raises(ClaimFindingError, match="empty"):
        server.claim_finding(case_id="smoke", hypothesis="X ran", audit_ids=[])


def test_claim_finding_refuses_fabricated_audit_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fabricated audit_ids MUST be refused.

    This is the most architecturally load-bearing refusal in the system: a
    prompt-injected agent could otherwise claim a finding with audit_ids it
    invented, and the HMAC-chain ledger would happily record the lie. The
    ledger lookup is what turns audit_ids from "things the agent says" into
    "things the agent actually did."
    """
    import secrets as _secrets

    from sanctum.finding import ClaimFindingError

    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", _secrets.token_hex(32))

    with pytest.raises(ClaimFindingError, match="not found in ledger"):
        server.claim_finding(
            case_id="smoke",
            hypothesis="X ran",
            audit_ids=["00000000-0000-0000-0000-000000000000"],
        )


def test_claim_finding_rejects_unsafe_case_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same case_id allowlist as get_amcache — bidi/zero-width/path-traversal.

    The format check fires before any ledger I/O so an unsafe case_id never
    lands in the audit ledger as a side effect of the refusal.
    """
    import secrets as _secrets

    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", _secrets.token_hex(32))

    with pytest.raises(ValueError, match="unsafe"):
        server.claim_finding(case_id="../etc", hypothesis="X ran", audit_ids=["x"])

    with pytest.raises(ValueError, match="unsafe"):
        # bidi-override codepoint inside an otherwise-safe-looking case_id
        server.claim_finding(case_id="case‮id", hypothesis="X ran", audit_ids=["x"])


def test_claim_finding_writes_ledger_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful claim_finding call MUST extend the HMAC chain.

    Pins the property that findings live on the same chain as get_* calls —
    forging a finding requires the HMAC key, not just disk-write access.
    """
    from sanctum import audit

    aid1, aid2 = _seed_two_family_ledger(monkeypatch, tmp_path)
    server.claim_finding(case_id="smoke", hypothesis="X ran", audit_ids=[aid1, aid2])

    ledger_path = tmp_path / "ledger.jsonl"
    ok, n, bad = audit.verify_chain(ledger_path)
    assert ok is True
    assert bad is None
    # 2 get_* entries + 1 claim_finding entry
    assert n == 3

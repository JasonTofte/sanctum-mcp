"""Tests for :mod:`sanctum.payload` — write-once payload offload with allowlist + durability.

Phase 1 of the payload-offload reimplementation (PR #4 successor).
Covers AC-2, AC-3, AC-7, AC-11, AC-15.
"""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from pathlib import Path

import pytest

from sanctum.payload import (
    validate_offload_root_distinct_from_cases_root,
    write_payload,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_VALID_CASE_ID = "case-smoke"
_VALID_AUDIT_ID = str(uuid.uuid4())
_VALID_TOOL = "get_amcache"
_VALID_CONTENT = '{"rows": []}'


@pytest.fixture()
def output_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated output root that mirrors how test_audit.py fixtures the ledger path."""
    root = tmp_path / "output"
    root.mkdir()
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(root))
    return root


# ---------------------------------------------------------------------------
# AC-3: Write-once via O_CREAT | O_EXCL
# ---------------------------------------------------------------------------


def test_write_payload_write_once_collision_raises(output_root: Path) -> None:
    # T-10 / AC-3
    # Arrange: write a payload for the first time.
    ref1 = write_payload(
        case_id=_VALID_CASE_ID,
        audit_id=_VALID_AUDIT_ID,
        tool=_VALID_TOOL,
        content=_VALID_CONTENT,
    )

    # Act: attempt a second write with identical components.
    with pytest.raises(FileExistsError):
        write_payload(
            case_id=_VALID_CASE_ID,
            audit_id=_VALID_AUDIT_ID,
            tool=_VALID_TOOL,
            content="completely different content",
        )

    # Assert: original file is untouched.
    on_disk = Path(ref1.path)
    on_disk_bytes = on_disk.read_bytes()
    sha = hashlib.sha256(on_disk_bytes).hexdigest()
    assert sha == ref1.sha256, "original file sha256 must not change after collision"
    mode = stat.S_IMODE(os.stat(ref1.path).st_mode)
    assert mode == 0o444, "original file mode must still be 0o444"


def test_write_payload_collision_leaves_original_content_unchanged(output_root: Path) -> None:
    # T-11 / AC-3
    content_a = '{"version": "A"}'
    content_b = '{"version": "B"}'
    aid = str(uuid.uuid4())

    ref = write_payload(
        case_id=_VALID_CASE_ID,
        audit_id=aid,
        tool=_VALID_TOOL,
        content=content_a,
    )

    with pytest.raises(FileExistsError):
        write_payload(
            case_id=_VALID_CASE_ID,
            audit_id=aid,
            tool=_VALID_TOOL,
            content=content_b,
        )

    actual = Path(ref.path).read_text(encoding="utf-8")
    assert actual == content_a, "original content must be preserved; content-B must not appear"


# ---------------------------------------------------------------------------
# AC-2: Path-traversal allowlist — parameterized per slot
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_id",
    [
        "..",  # dotdot segment
        "../escape",  # dotdot with further traversal
        "/absolute",  # leading slash
        "has/slash",  # embedded slash
        ".hidden",  # leading dot
        "has\x00nul",  # NUL byte
        "has\x01ctrl",  # control char U+0001
        "has\x7fdelete",  # DEL U+007F
        "has‮rlo",  # RIGHT-TO-LEFT OVERRIDE
        "has⁦lri",  # LEFT-TO-RIGHT ISOLATE
        "has​zwsp",  # ZERO WIDTH SPACE
        "has‌zwj",  # ZERO WIDTH NON-JOINER (similar ZW class)
        "has‍jwnj",  # ZERO WIDTH JOINER
        "has﻿bom",  # BOM / ZWNBSP
    ],
    ids=[
        "dotdot",
        "dotdot_with_path",
        "absolute_slash",
        "embedded_slash",
        "leading_dot",
        "nul_byte",
        "control_u0001",
        "control_u007f",
        "bidi_rlo_u202e",
        "bidi_lri_u2066",
        "zwsp_u200b",
        "zwnj_u200c",
        "zwj_u200d",
        "bom_ufeff",
    ],
)
def test_write_payload_rejects_unsafe_case_id(output_root: Path, case_id: str) -> None:
    # T-4 / T-6 / T-7 / AC-2  (case_id slot)
    with pytest.raises(ValueError):
        write_payload(
            case_id=case_id,
            audit_id=_VALID_AUDIT_ID,
            tool=_VALID_TOOL,
            content=_VALID_CONTENT,
        )
    # No directory must have been created under the output root.
    assert (
        list(output_root.iterdir()) == []
    ), f"output_root must be empty after ValueError for case_id={case_id!r}"


@pytest.mark.parametrize(
    "audit_id",
    [
        "a/b",  # embedded slash
        "../x",  # dotdot
        "/absolute",  # leading slash
        ".hidden",  # leading dot
        "nul\x00byte",  # NUL
        "ctrl\x1fbyte",  # control char U+001F
        str(uuid.uuid4()) + "﻿",  # valid UUID4 + BOM suffix
        "has‮rbidi",  # RLO embedded
        "has​zwsp",  # ZWSP
    ],
    ids=[
        "slash",
        "dotdot",
        "absolute",
        "leading_dot",
        "nul",
        "control_u001f",
        "uuid_plus_bom",
        "bidi_rlo",
        "zwsp",
    ],
)
def test_write_payload_rejects_unsafe_audit_id(output_root: Path, audit_id: str) -> None:
    # T-5 / T-6 / T-7 / AC-2  (audit_id slot)
    with pytest.raises(ValueError):
        write_payload(
            case_id=_VALID_CASE_ID,
            audit_id=audit_id,
            tool=_VALID_TOOL,
            content=_VALID_CONTENT,
        )
    assert (
        list(output_root.iterdir()) == []
    ), f"output_root must be empty after ValueError for audit_id={audit_id!r}"


@pytest.mark.parametrize(
    "tool",
    [
        ".hidden",  # T-8: leading dot in tool slot
        "../escape",  # dotdot
        "/absolute",  # absolute
        "get/amcache",  # slash
        "tool\x00nul",  # NUL
        "tool\x01ctrl",  # control char
        "tool‮bidi",  # RLO
        "tool​zwsp",  # ZWSP
    ],
    ids=[
        "leading_dot",
        "dotdot",
        "absolute",
        "slash",
        "nul",
        "ctrl",
        "bidi_rlo",
        "zwsp",
    ],
)
def test_write_payload_rejects_unsafe_tool(output_root: Path, tool: str) -> None:
    # T-8 / AC-2  (tool slot)
    with pytest.raises(ValueError):
        write_payload(
            case_id=_VALID_CASE_ID,
            audit_id=_VALID_AUDIT_ID,
            tool=tool,
            content=_VALID_CONTENT,
        )
    assert (
        list(output_root.iterdir()) == []
    ), f"output_root must be empty after ValueError for tool={tool!r}"


def test_write_payload_nfkc_normalization_then_revalidate(output_root: Path) -> None:
    # T-9 / AC-2 — NFKC normalize-then-revalidate path
    # A case_id that is already NFC-safe and ASCII-only must be accepted.
    safe_id = str(uuid.uuid4())
    ref = write_payload(
        case_id=safe_id,
        audit_id=str(uuid.uuid4()),
        tool=_VALID_TOOL,
        content=_VALID_CONTENT,
    )
    assert Path(ref.path).exists(), "NFKC-safe input must produce a file"

    # An input whose NFKC form still contains a banned codepoint must be rejected.
    # U+202E (RLO) does not decompose away under NFKC — it must still be rejected.
    rlo_id = "case‮id"
    with pytest.raises(ValueError):
        write_payload(
            case_id=rlo_id,
            audit_id=str(uuid.uuid4()),
            tool=_VALID_TOOL,
            content=_VALID_CONTENT,
        )


def test_write_payload_rejects_fullwidth_solidus_post_nfkc(output_root: Path) -> None:
    # T-9b / AC-2 — proves the post-NFKC revalidation path actually fires.
    # U+FF0F FULLWIDTH SOLIDUS is allowed by the raw-form check (it is not "/"
    # and not in the banned-codepoint set). NFKC normalizes it to "/" — which
    # the post-NFKC pass must reject. A buggy impl that skips the second pass
    # would let this through.
    fullwidth_solidus_id = "case／attack"
    with pytest.raises(ValueError):
        write_payload(
            case_id=fullwidth_solidus_id,
            audit_id=str(uuid.uuid4()),
            tool=_VALID_TOOL,
            content=_VALID_CONTENT,
        )


# ---------------------------------------------------------------------------
# AC-7: Startup guard — SANCTUM_OUTPUT_ROOT resolving under SANCTUM_CASES_ROOT
# ---------------------------------------------------------------------------


def test_validate_offload_root_rejects_subpath_under_cases_root(tmp_path: Path) -> None:
    # T-17 / AC-7
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    output_root = cases_root / "output"
    output_root.mkdir()

    with pytest.raises(RuntimeError) as exc_info:
        validate_offload_root_distinct_from_cases_root(
            output_root=output_root,
            cases_root=cases_root,
        )

    msg = str(exc_info.value)
    # Message must name both env vars so the operator knows what to fix.
    assert "SANCTUM_OUTPUT_ROOT" in msg, "RuntimeError message must name SANCTUM_OUTPUT_ROOT"
    assert "SANCTUM_CASES_ROOT" in msg, "RuntimeError message must name SANCTUM_CASES_ROOT"


def test_validate_offload_root_accepts_distinct_root(tmp_path: Path) -> None:
    # T-15 companion / AC-7 happy path
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    output_root = tmp_path / "output"
    output_root.mkdir()

    # Must not raise when roots are genuinely distinct.
    validate_offload_root_distinct_from_cases_root(
        output_root=output_root,
        cases_root=cases_root,
    )


def test_validate_offload_root_rejects_exact_match_with_cases_root(tmp_path: Path) -> None:
    # T-17b / AC-7 — equality branch. SANCTUM_OUTPUT_ROOT=/cases when
    # SANCTUM_CASES_ROOT=/cases must be refused (not just sub-paths).
    shared = tmp_path / "shared"
    shared.mkdir()

    with pytest.raises(RuntimeError) as exc_info:
        validate_offload_root_distinct_from_cases_root(
            output_root=shared,
            cases_root=shared,
        )

    msg = str(exc_info.value)
    assert "SANCTUM_OUTPUT_ROOT" in msg
    assert "SANCTUM_CASES_ROOT" in msg


def test_validate_offload_root_rejects_nonexistent_cases_root(tmp_path: Path) -> None:
    # T-17c / AC-7 — defense for the resolve()-on-missing-path quirk.
    output_root = tmp_path / "output"
    output_root.mkdir()
    missing_cases = tmp_path / "no_such_cases"
    assert not missing_cases.exists()

    with pytest.raises(RuntimeError) as exc_info:
        validate_offload_root_distinct_from_cases_root(
            output_root=output_root,
            cases_root=missing_cases,
        )

    msg = str(exc_info.value)
    assert "SANCTUM_CASES_ROOT" in msg
    assert str(missing_cases) in msg


# ---------------------------------------------------------------------------
# AC-11: Startup guard — non-existent SANCTUM_OUTPUT_ROOT refused at startup
# ---------------------------------------------------------------------------


def test_nonexistent_output_root_refused_at_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # T-24 / AC-11
    missing_root = tmp_path / "does_not_exist"
    assert not missing_root.exists(), "pre-condition: directory must not exist"

    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(missing_root))

    with pytest.raises(RuntimeError) as exc_info:
        validate_offload_root_distinct_from_cases_root(
            output_root=missing_root,
            cases_root=tmp_path / "cases",
        )

    msg = str(exc_info.value)
    assert "SANCTUM_OUTPUT_ROOT" in msg, "error message must name the env var"
    assert str(missing_root) in msg, "error message must name the missing path"


# ---------------------------------------------------------------------------
# AC-15: Durability — fdatasync(payload_fd) then fsync(parent_dir_fd) before return
# ---------------------------------------------------------------------------


def test_write_payload_issues_fdatasync_then_fsync_in_order(
    output_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # T-31 / AC-15
    # Arrange: capture sync calls AND classify each fd by whether it points at
    # a regular file (the payload fd) or a directory (the parent dir fd). This
    # pins fd ROLES, not just ordering — so a buggy impl that calls
    # _fdatasync(dir_fd) + _fsync(payload_fd) would fail this oracle.
    sync_log: list[tuple[str, int, str]] = []

    def _classify(fd: int) -> str:
        try:
            mode = os.fstat(fd).st_mode
        except OSError:
            return "closed"
        if stat.S_ISDIR(mode):
            return "dir"
        if stat.S_ISREG(mode):
            return "file"
        return "other"

    def _track_fdatasync(fd: int) -> None:
        sync_log.append(("fdatasync", fd, _classify(fd)))

    def _track_fsync(fd: int) -> None:
        sync_log.append(("fsync", fd, _classify(fd)))

    monkeypatch.setattr("sanctum.payload._fdatasync", _track_fdatasync)
    monkeypatch.setattr("sanctum.payload._fsync", _track_fsync)

    # Act
    write_payload(
        case_id=_VALID_CASE_ID,
        audit_id=str(uuid.uuid4()),
        tool=_VALID_TOOL,
        content=_VALID_CONTENT,
    )

    assert (
        len(sync_log) == 2
    ), f"expected exactly 2 sync calls (fdatasync on file + fsync on dir), got {sync_log}"

    # First sync must be fdatasync on the PAYLOAD (regular file) fd.
    assert sync_log[0][0] == "fdatasync", f"expected fdatasync first; got {sync_log[0]}"
    assert (
        sync_log[0][2] == "file"
    ), f"fdatasync must target the payload (regular file) fd; got fd-type={sync_log[0][2]}"

    # Second sync must be fsync on the PARENT DIRECTORY fd.
    assert sync_log[1][0] == "fsync", f"expected fsync second; got {sync_log[1]}"
    assert (
        sync_log[1][2] == "dir"
    ), f"fsync must target the parent-directory fd; got fd-type={sync_log[1][2]}"

    # The two fds must be distinct (payload fd held while dir fd opens).
    assert (
        sync_log[0][1] != sync_log[1][1]
    ), "payload fd and parent-dir fd must be distinct (payload fd held during dir fsync)"


def test_write_payload_durability_calls_not_skipped_on_small_payload(
    output_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # T-32 / AC-15 — 1-byte payload must still trigger both sync calls.
    call_log: list[tuple[str, int]] = []

    monkeypatch.setattr("sanctum.payload._fdatasync", lambda fd: call_log.append(("fdatasync", fd)))
    monkeypatch.setattr("sanctum.payload._fsync", lambda fd: call_log.append(("fsync", fd)))

    write_payload(
        case_id=_VALID_CASE_ID,
        audit_id=str(uuid.uuid4()),
        tool=_VALID_TOOL,
        content="X",  # single byte
    )

    fdatasync_calls = [c for c in call_log if c[0] == "fdatasync"]
    fsync_calls = [c for c in call_log if c[0] == "fsync"]

    assert len(fdatasync_calls) >= 1, "fdatasync must be called even for a 1-byte payload"
    assert len(fsync_calls) >= 1, "fsync must be called even for a 1-byte payload"

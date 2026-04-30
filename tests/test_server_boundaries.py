"""Architectural-boundary tests.

These tests exist to prove — in CI, for every commit — that known bypass
classes from the hackathon judging rubric do not succeed against the MCP
server. The suite will grow as additional architectural invariants are added.
"""

from __future__ import annotations

import importlib
import json
import re
import secrets as _secrets
from datetime import datetime
from pathlib import Path

import pytest

from sanctum import server
from sanctum.parsers._fixture_io import FIXTURE_ENV, SIDECAR_SUFFIX

# ─── sidecar helpers ─────────────────────────────────────────────────────────

# Sidecar envelope fields expected by _fixture_io.load_sidecar().
# family must match sanctum.families.FAMILY_APPCOMPAT ("AppCompat").
# tool must match the MCP tool name ("get_amcache").
_SIDECAR_FAMILY = "AppCompat"
_SIDECAR_TOOL = "get_amcache"

# A single realistic execution event for fixture sidecars.
_SAMPLE_EVENT = {
    "program_path": r"C:\Windows\System32\notepad.exe",
    "timestamp": "2024-01-15T10:30:00+00:00",
    "evidence_size_bytes": 512,
    "extras": {"row_index": "0"},
}


def _write_sidecar(hive_path: Path, events: list[dict]) -> None:
    """Write a valid fixture sidecar next to ``hive_path``."""
    sidecar = hive_path.with_name(hive_path.name + SIDECAR_SUFFIX)
    sidecar.write_text(
        json.dumps({"family": _SIDECAR_FAMILY, "tool": _SIDECAR_TOOL, "events": events}),
        encoding="utf-8",
    )


def _make_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    case_name: str = "smoke",
    events: list[dict] | None = None,
) -> tuple[Path, Path]:
    """Create a minimal case directory with stub hive + optional sidecar.

    Returns (cases_root, hive_path).  The caller is responsible for setting
    FIXTURE_ENV via monkeypatch if a sidecar should be active.

    Also seeds ``SANCTUM_OUTPUT_ROOT`` to ``tmp_path/output`` (created)
    so the new offload-pattern get_amcache wrapper can write payload files.
    """
    if events is None:
        events = [_SAMPLE_EVENT]
    cases = tmp_path / "cases"
    case = cases / case_name
    (case / "registry").mkdir(parents=True, exist_ok=True)
    hive = case / "registry" / "Amcache.hve"
    hive.write_bytes(b"stub hive")
    _write_sidecar(hive, events)

    output_root = tmp_path / "output"
    output_root.mkdir(exist_ok=True)

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", _secrets.token_hex(32))
    return cases, hive


def _unwrap_body(out: str) -> dict:
    """Strip <evidence-untrusted> wrapper and JSON-parse the payload."""
    inner = out.removeprefix("<evidence-untrusted>").rstrip()
    inner = inner.removesuffix("</evidence-untrusted>").strip()
    return json.loads(inner)


def _read_offloaded_payload(body: dict) -> dict:
    """Read the on-disk offload payload referenced by ``body["payload_ref"]``.

    Under the offload pattern (Phase 3), the rows / full Finding live in a
    write-once file referenced by ``payload_ref.path``; the inline summary
    is metadata only. This helper centralizes the read so existing tests
    that previously asserted on ``body["rows"]`` continue to work after
    the contract migration.
    """
    payload_path = Path(body["payload_ref"]["path"])
    return json.loads(payload_path.read_text(encoding="utf-8"))


# ─── existing boundary tests (unchanged) ─────────────────────────────────────


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


# ─── T-7: AC-4 — evidence-wrapped assertion (fixture-mode rewrite) ────────────


@pytest.mark.asyncio
async def test_get_amcache_output_is_evidence_wrapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-7 / AC-4: ``get_amcache`` output MUST be wrapped in ``<evidence-untrusted>``.

    Migrated from b"stub hive" to fixture-mode (SANCTUM_USE_FIXTURE_SIDECAR=1)
    so the real ``parse_amcache`` does not raise ArtifactMalformedError on the
    unrecognisable stub bytes.
    """
    _make_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    out = await server.get_amcache("smoke")
    assert out.startswith("<evidence-untrusted>")
    assert out.rstrip().endswith("</evidence-untrusted>")


# ─── T-8: AC-4 — audit_id round-trip (fixture-mode rewrite) ──────────────────


@pytest.mark.asyncio
async def test_get_amcache_response_surfaces_audit_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-8 / AC-4: ``get_amcache`` MUST return its ``audit_id`` so the agent can cite it.

    Migrated from b"stub hive" to fixture-mode (SANCTUM_USE_FIXTURE_SIDECAR=1).

    The ``claim_finding`` gate's docstring says it takes "audit_ids
    previously returned by ``get_*`` tool calls" — this test pins the
    contract. Without the audit_id in the response, the agent has no
    cite-able value to pass to ``claim_finding`` and the gate becomes
    operationally unreachable over the MCP wire.

    Also verifies the round-trip: the audit_id surfaced in the response
    matches the audit_id of the corresponding ledger entry.
    """
    _make_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")
    ledger_path = tmp_path / "ledger.jsonl"

    out = await server.get_amcache("smoke")
    body = _unwrap_body(out)

    assert "audit_id" in body, "audit_id missing from response — claim_finding cannot cite"
    assert body["audit_id"], "audit_id surfaced but empty"
    assert body["case_id"] == "smoke"
    # Rows live on disk under the offload pattern; the inline summary is
    # metadata only. The post-migration assertion shifts to the on-disk file.
    payload = _read_offloaded_payload(body)
    assert "rows" in payload and isinstance(payload["rows"], list)

    # Round-trip: response audit_id matches the most-recently-appended ledger entry.
    last_line = ledger_path.read_text().strip().splitlines()[-1]
    assert json.loads(last_line)["audit_id"] == body["audit_id"]


# ─── T-1: AC-1 — real parser rows shape, no stub keys ────────────────────────


@pytest.mark.asyncio
async def test_get_amcache_rows_have_real_parser_shape_not_stub_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-1 / AC-1: rows must contain real-parser keys, NOT the stub shape.

    The stub returned dicts with keys: source, note, hve_size_bytes, hve_sha256.
    The real wire shape has: program_path, timestamp, family, tool,
    source_artifact, evidence_size_bytes, extras.

    Both shape sets are checked so this test fails if the stub is still live.
    """
    _make_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    out = await server.get_amcache("smoke")
    body = _unwrap_body(out)
    # Real-parser shape lives in the on-disk payload under the offload contract.
    rows = _read_offloaded_payload(body)["rows"]

    assert isinstance(rows, list)
    assert len(rows) >= 1, "fixture sidecar has one event — rows must be non-empty"

    row = rows[0]
    # Real wire-shape keys that must be present.
    for key in ("program_path", "timestamp", "family"):
        assert key in row, f"real-parser key {key!r} missing from row"

    # Stub-shape keys that must NOT be present.
    for stub_key in ("source", "note", "hve_size_bytes", "hve_sha256"):
        assert stub_key not in row, f"stub key {stub_key!r} must not appear in row after rewire"


# ─── T-3: AC-2 — _parse_amcache_stub absence (attribute check) ───────────────


def test_parse_amcache_stub_is_absent_from_server_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-3 / AC-2: ``_parse_amcache_stub`` MUST NOT exist on the server module.

    Uses importlib.reload so the assertion survives any cached-import state.
    A surviving dead stub re-opens the attack surface MED-1 closes.
    """
    importlib.reload(server)
    assert not hasattr(
        server, "_parse_amcache_stub"
    ), "_parse_amcache_stub still exists on server module — stub was not deleted"


# ─── T-5: AC-3 — empty sidecar → rows==[] and rowcount==0 ───────────────────


@pytest.mark.asyncio
async def test_get_amcache_empty_sidecar_returns_empty_rows_and_zero_rowcount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-5 / AC-3: empty ``events`` in sidecar → ``rows == []`` and ledger ``rowcount == 0``.

    Pins the semantic upgrade: the old stub always returned 1 fabricated row.
    The real parser must return 0 rows when there are genuinely no entries.
    Also asserts the stub-shape keys are absent (negative-sample guard).
    """
    _make_case(tmp_path, monkeypatch, events=[])
    monkeypatch.setenv(FIXTURE_ENV, "1")
    ledger_path = tmp_path / "ledger.jsonl"

    out = await server.get_amcache("smoke")
    body = _unwrap_body(out)
    payload = _read_offloaded_payload(body)

    assert payload["rows"] == [], f"expected empty rows list, got: {payload['rows']!r}"

    # Verify ledger rowcount agrees.
    last_entry = json.loads(ledger_path.read_text().strip().splitlines()[-1])
    assert (
        last_entry["rowcount"] == 0
    ), f"ledger rowcount must be 0 for empty events, got {last_entry['rowcount']!r}"

    # Negative-sample: stub-shape keys must not appear even in a fabricated 1-row result.
    for stub_key in ("source", "note", "hve_size_bytes", "hve_sha256"):
        for row in payload["rows"]:
            assert (
                stub_key not in row
            ), f"stub key {stub_key!r} found — stub may still be returning a fabricated row"


# ─── T-10: AC-5 — JSON round-trip and ISO-8601 timestamp ─────────────────────


@pytest.mark.asyncio
async def test_get_amcache_rows_are_json_serialisable_with_iso8601_timestamps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-10 / AC-5: rows must be fully JSON-serialisable; timestamps must be ISO-8601.

    ``ExecutionEvent.timestamp`` is a Python ``datetime``. If ``_event_to_row``
    does not call ``.isoformat()``, ``json.dumps`` raises ``TypeError``.
    Separately, ``str(datetime_obj)`` emits a space-separated form that strict
    ISO-8601 parsers (and ``datetime.fromisoformat`` in older Python) reject —
    the test pins the `T`-separator form.
    """
    _make_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    out = await server.get_amcache("smoke")
    body = _unwrap_body(out)
    # Reaching this test means the offload write already round-tripped through
    # ``json.dumps`` once; we re-check via the on-disk payload to keep the
    # boundary-leak signal explicit.
    rows = _read_offloaded_payload(body)["rows"]

    # Fail-closed: json.dumps must not raise (catches raw datetime / Path leak).
    try:
        json.dumps(rows)
    except TypeError as exc:
        raise AssertionError(
            f"json.dumps(rows) raised TypeError — datetime or Path object leaked "
            f"through server boundary: {exc}"
        ) from exc

    assert len(rows) >= 1, "need at least one row to check timestamp format"

    iso8601_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
    for i, row in enumerate(rows):
        ts = row.get("timestamp")
        assert isinstance(ts, str), (
            f"row[{i}]['timestamp'] is {type(ts).__name__}, expected str — "
            f"datetime was not serialised at the server boundary"
        )
        assert iso8601_re.match(ts), (
            f"row[{i}]['timestamp'] = {ts!r} does not match ISO-8601 pattern "
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} — "
            f"str(datetime) space-separated form would fail here"
        )
        # Property: semantically valid ISO-8601 (not just pattern-matching).
        datetime.fromisoformat(ts)  # raises ValueError if malformed


# ─── P1 tests ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_amcache_row_count_matches_sidecar_event_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-2 / AC-1 (P1): metamorphic — two sidecars with N and M events → len(rows)==N/M.

    Verifies the real parser honours the sidecar event list length, not a
    hard-coded constant.
    """
    # First call: 2 events.
    two_events = [
        {**_SAMPLE_EVENT, "extras": {"row_index": "0"}},
        {
            "program_path": r"C:\Windows\System32\calc.exe",
            "timestamp": "2024-01-15T11:00:00+00:00",
            "evidence_size_bytes": 256,
            "extras": {"row_index": "1"},
        },
    ]
    _make_case(tmp_path, monkeypatch, case_name="two-event", events=two_events)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    out = await server.get_amcache("two-event")
    body = _unwrap_body(out)
    rows = _read_offloaded_payload(body)["rows"]
    assert len(rows) == 2, f"expected 2 rows, got {len(rows)}"

    # Second case (different case_name, same tmp_path): 0 events.
    _make_case(tmp_path, monkeypatch, case_name="zero-event", events=[])
    out2 = await server.get_amcache("zero-event")
    body2 = _unwrap_body(out2)
    rows2 = _read_offloaded_payload(body2)["rows"]
    assert len(rows2) == 0, f"expected 0 rows, got {len(rows2)}"


def test_parse_amcache_stub_literal_absent_from_server_source() -> None:
    """T-4 / AC-2 (P1): literal string ``_parse_amcache_stub`` must not appear in server.py source.

    Catches the case where the function is deleted but a docstring reference,
    comment, or ``# legacy`` annotation survives.
    """
    import sanctum.server as _server_mod

    server_source = Path(_server_mod.__file__).read_text(encoding="utf-8")
    assert "_parse_amcache_stub" not in server_source, (
        "The literal string '_parse_amcache_stub' still appears in server.py — "
        "delete ALL references including comments and docstrings"
    )


@pytest.mark.asyncio
async def test_get_amcache_empty_sidecar_no_stub_shape_in_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-6 / AC-3 (P1): empty-sidecar case must NOT return the old stub shape.

    Negative-sample companion to T-5. The stub `_parse_amcache_stub`
    unconditionally produced exactly 1 row (a `{"source": "...", "note":
    "...", "hve_size_bytes": ..., "hve_sha256": ...}` shape) for any
    non-empty hive bytes. Asserting `rows == []` for an empty sidecar is
    the differential signal: a live stub would emit its 1-row shape and
    fail this assertion, regardless of sidecar content.
    """
    _make_case(tmp_path, monkeypatch, events=[])
    monkeypatch.setenv(FIXTURE_ENV, "1")

    out = await server.get_amcache("smoke")
    body = _unwrap_body(out)
    payload = _read_offloaded_payload(body)

    assert payload["rows"] == [], "empty sidecar must yield empty rows, not a stub-fabricated row"


@pytest.mark.asyncio
async def test_get_amcache_fixture_mode_off_raises_on_stub_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-9 / AC-4 (P1): without FIXTURE_ENV, stub-bytes hive raises ArtifactMalformedError.

    Confirms fixture-mode is not silently active by default — the env-var gate
    is the ONLY path that bypasses real parsing.
    """
    from sanctum.parsers._errors import ArtifactMalformedError

    cases = tmp_path / "cases"
    case = cases / "smoke"
    (case / "registry").mkdir(parents=True)
    (case / "registry" / "Amcache.hve").write_bytes(b"stub hive")

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", _secrets.token_hex(32))
    monkeypatch.delenv(FIXTURE_ENV, raising=False)

    with pytest.raises(ArtifactMalformedError):
        await server.get_amcache("smoke")


@pytest.mark.asyncio
async def test_get_amcache_timestamp_is_semantically_valid_iso8601(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-11 / AC-5 (P1): ``datetime.fromisoformat(row['timestamp'])`` must not raise.

    ``str(datetime_obj)`` produces a space-separated form accepted by Python's own
    ``fromisoformat`` but rejected by most strict ISO-8601 parsers outside Python.
    This test pins that the value is ``isoformat()``-form (``T`` separator) and is
    semantically valid (parseable without exception).
    """
    _make_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    out = await server.get_amcache("smoke")
    body = _unwrap_body(out)
    rows = _read_offloaded_payload(body)["rows"]

    assert len(rows) >= 1
    for i, row in enumerate(rows):
        ts = row["timestamp"]
        assert isinstance(ts, str), f"row[{i}]['timestamp'] must be str, got {type(ts).__name__}"
        try:
            datetime.fromisoformat(ts)
        except ValueError as exc:
            raise AssertionError(
                f"row[{i}]['timestamp'] = {ts!r} is not valid ISO-8601: {exc}"
            ) from exc
        # Must have a T separator, not the space-separated form str(datetime) emits.
        assert "T" in ts, (
            f"row[{i}]['timestamp'] = {ts!r} uses space separator — "
            f"must use isoformat() not str() at the server boundary"
        )


def test_adr_pl_003_status_block_references_real_parser_swap() -> None:
    """T-12 / AC-6 (P2): ADR-PL-003 status block must mention `parse_amcache`.

    Pins the AC-15c-retirement amendment as no longer aspirational. ADR-PL-003
    documents the original `_parse_amcache_stub` decision and was patched
    when this PR landed to record that the stub call was swapped for
    `parse_amcache(hive_path)` in `server.py`. If a future refactor re-stubs
    the parser path, the doc must be updated in the same change.
    """
    adr = Path(__file__).parent.parent / "docs" / "ADR_PARSER_LAYER.md"
    text = adr.read_text(encoding="utf-8")

    header_idx = text.find("## ADR-PL-003")
    assert header_idx != -1, "ADR-PL-003 section header missing from docs/ADR_PARSER_LAYER.md"
    next_section = text.find("\n## ", header_idx + 1)
    section = text[header_idx : next_section if next_section != -1 else len(text)]

    assert "parse_amcache" in section, (
        "ADR-PL-003 section does not reference `parse_amcache` — the retired-AC-15c "
        "amendment is missing or the ADR has been edited to remove it"
    )


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
    """No exported MCP tool name may use write/exec/delete verbs as a token.

    The architectural guarantee is that the agent physically cannot run
    destructive commands because the destructive surface does not exist.
    This test enforces that invariant at the module level.

    Token-boundary match (not substring): the intent is to catch function
    names like ``delete_record`` or ``write_evidence``, not to false-flag
    legitimate types like ``ExecutionEvent`` (contains "exec") or
    ``ArtifactMalformedError`` (contains "rm"). Tokens are separated by
    underscores or by camelCase boundaries.
    """
    import re as _re

    banned = {"write", "exec", "shell", "run", "delete", "rm", "mv", "cp_over", "unlink"}

    def _tokens(name: str) -> set[str]:
        # Token-boundary tokenizer (NOT substring): snake_case splits on `_`,
        # camelCase splits on lowercase→uppercase. The third regex alternative
        # `[A-Z]+(?=[A-Z]|$)` exists ONLY to catch all-caps acronyms inside
        # camelCase names (e.g. `parseHTTP` → {parse, http}, `XMLReader` →
        # {xml, reader}). Without it, `parseHTTP` would yield `{parse, h, t, t, p}`.
        # Removing this branch silently breaks acronym handling — keep it.
        snake = name.split("_")
        camel: list[str] = []
        for piece in snake:
            camel.extend(_re.findall(r"[A-Z][a-z]*|[a-z]+|[A-Z]+(?=[A-Z]|$)", piece))
        return {t.lower() for t in camel if t}

    for tool_name in dir(server):
        if tool_name.startswith("_"):
            continue
        hits = _tokens(tool_name) & banned
        assert not hits, f"server module exports a banned-verb symbol: {tool_name} (tokens: {hits})"


# ─── claim_finding MCP wrapper ───────────────────────────────────────────────


def _seed_two_family_ledger(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[str, str]:
    """Plant two ledger entries from different families and return their audit_ids.

    Used by claim_finding wrapper tests that need a non-empty, non-fabricated
    audit_id pair so the underlying gate produces a CORROBORATED Finding
    rather than refusing.

    Also seeds ``SANCTUM_OUTPUT_ROOT`` so the offload-pattern claim_finding
    wrapper has a write destination — claim_finding writes its summary file
    to ``$SANCTUM_OUTPUT_ROOT/<case_id>/<audit_id>/claim_finding.json``,
    not under cases root.
    """
    import secrets as _secrets

    from sanctum import audit

    monkeypatch.setenv(audit.LEDGER_ENV, str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv(audit.HMAC_KEY_ENV, _secrets.token_hex(32))

    output_root = tmp_path / "output"
    output_root.mkdir(exist_ok=True)
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(output_root))

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


@pytest.mark.asyncio
async def test_claim_finding_output_is_evidence_wrapped(
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

    out = await server.claim_finding(
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

    # AC-13: families, audit_ids, hypothesis, confirmation_basis, reason_codes
    # are deliberately ABSENT from the inline summary — they live in the
    # offload payload so the inline byte budget stays under AC-8's < 1024 B
    # cap. Asserting the family list and confirmation_basis is still valuable
    # context for the human reading the test, so move it to the on-disk read.
    payload = _read_offloaded_payload(body)
    assert sorted(payload["families"]) == ["AppCompat", "SysMain"]
    # confirmation_basis surfaces in the offloaded payload — a downstream
    # consumer can distinguish "the gate just barely fired" from
    # "two genuinely independent trust roots agree".
    assert payload["confirmation_basis"] == "independent_artifacts"


@pytest.mark.asyncio
async def test_claim_finding_refuses_empty_audit_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty audit_ids MUST refuse — a finding requires at least one source."""
    import secrets as _secrets

    from sanctum.finding import ClaimFindingError

    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", _secrets.token_hex(32))

    with pytest.raises(ClaimFindingError, match="empty"):
        await server.claim_finding(case_id="smoke", hypothesis="X ran", audit_ids=[])


@pytest.mark.asyncio
async def test_claim_finding_refuses_fabricated_audit_id(
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
        await server.claim_finding(
            case_id="smoke",
            hypothesis="X ran",
            audit_ids=["00000000-0000-0000-0000-000000000000"],
        )


@pytest.mark.asyncio
async def test_claim_finding_rejects_unsafe_case_id(
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
        await server.claim_finding(case_id="../etc", hypothesis="X ran", audit_ids=["x"])

    with pytest.raises(ValueError, match="unsafe"):
        # bidi-override codepoint inside an otherwise-safe-looking case_id
        await server.claim_finding(case_id="case‮id", hypothesis="X ran", audit_ids=["x"])


@pytest.mark.asyncio
async def test_claim_finding_writes_ledger_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful claim_finding call MUST extend the HMAC chain.

    Pins the property that findings live on the same chain as get_* calls —
    forging a finding requires the HMAC key, not just disk-write access.
    """
    from sanctum import audit

    aid1, aid2 = _seed_two_family_ledger(monkeypatch, tmp_path)
    await server.claim_finding(case_id="smoke", hypothesis="X ran", audit_ids=[aid1, aid2])

    ledger_path = tmp_path / "ledger.jsonl"
    # Position 2 of verify_chain's return is "first_bad_line_1based" (None on
    # clean), not a line count, after the AC-4/AC-10 contract change. The
    # 2-get + 1-claim count is now asserted via direct file read below.
    ok, first_bad, bad = audit.verify_chain(ledger_path)
    assert ok is True
    assert bad is None
    assert first_bad is None
    line_count = sum(
        1 for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()
    )
    assert line_count == 3, "2 get_* entries + 1 claim_finding entry"


# ─── Phase 3: payload-offload boundary tests (AC-1, AC-7..AC-14) ─────────────
#
# The offload pattern's design intent: every typed tool writes its full
# sanitized payload write-once to ``$SANCTUM_OUTPUT_ROOT/<case_id>/<audit_id>/
# <tool>.json`` (mode 0o444, O_CREAT|O_EXCL) and returns only a short summary
# (< 1 KiB) wrapped in ``<evidence-untrusted>``. The audit_id is pre-generated
# by the wrapper so the on-disk path and the HMAC-chained ledger entry share
# a key. The HMAC chain covers ``payload_ref`` so a swapped-payload attack
# breaks ``verify_chain``. See ``.sherlock-plan.md`` AC-1 / AC-7..AC-14.


@pytest.mark.asyncio
async def test_get_amcache_full_offload_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-1: end-to-end offload round-trip for ``get_amcache``.

    Covers the union of the offload contract: response carries a
    ``payload_ref`` (path, sha256, bytes, format), the file exists on disk
    with mode 0o444, the ``sha256`` digest in the response matches the file
    bytes verbatim, the on-disk path layout is
    ``<output_root>/<case_id>/<audit_id>/<tool>.json``, the ledger entry's
    audit_id matches the response audit_id, and ``verify_chain`` returns ok.
    """
    import hashlib as _hashlib
    import os as _os

    from sanctum import audit

    cases, _hive = _make_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")
    output_root = tmp_path / "output"

    out = await server.get_amcache("smoke")
    body = _unwrap_body(out)

    # Response shape: payload_ref carries the four offload-contract keys.
    assert "payload_ref" in body, "response must carry payload_ref under offload contract"
    pref = body["payload_ref"]
    for key in ("path", "sha256", "bytes", "format"):
        assert key in pref, f"payload_ref missing required key {key!r}"
    assert pref["format"] == "application/json"

    # On-disk path layout: <output_root>/<case_id>/<audit_id>/<tool>.json.
    expected_path = output_root / "smoke" / body["audit_id"] / "get_amcache.json"
    assert (
        Path(pref["path"]) == expected_path
    ), f"path layout violation: got {pref['path']!r}, expected {expected_path!s}"

    # File exists, is a regular file, and has mode 0o444 (read-only for
    # owner/group/other) — the OS-level immutability that resists same-process
    # tampering after the write succeeds.
    assert expected_path.is_file()
    mode = _os.stat(expected_path).st_mode & 0o777
    assert mode == 0o444, f"expected mode 0o444, got 0o{mode:o}"

    # Hash integrity: the sha256 in payload_ref MUST match the file bytes
    # verbatim. Otherwise a swapped-file attack against the offload directory
    # would not be detected by ``verify_chain``.
    file_bytes = expected_path.read_bytes()
    file_sha = _hashlib.sha256(file_bytes).hexdigest()
    assert pref["sha256"] == file_sha
    assert pref["bytes"] == len(file_bytes)

    # Ledger linkage: response audit_id == latest ledger entry audit_id.
    ledger_path = tmp_path / "ledger.jsonl"
    last_entry = json.loads(ledger_path.read_text().strip().splitlines()[-1])
    assert last_entry["audit_id"] == body["audit_id"]
    # Ledger entry carries the same payload_ref (the HMAC chain covers it).
    assert last_entry["payload_ref"] == pref

    # Whole-chain HMAC verification still passes after the offload write.
    ok, first_bad, _bad_aid = audit.verify_chain(ledger_path)
    assert ok is True and first_bad is None


@pytest.mark.asyncio
async def test_get_amcache_summary_response_under_1024_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-8: inline summary response MUST fit under 1024 bytes (UTF-8 hard cap).

    1024 B is the empirical Claude Code stdio cliff (anthropics/claude-code
    issue #36319) plus a safety margin. Tested against UTF-8-encoded byte
    length, NOT character count, because Unicode multi-byte chars expand —
    a hard ASCII budget would silently bypass the cap on Unicode payloads.

    Uses ``many_events`` (200 sidecar events) so a non-offloaded
    implementation that just inlined ``rows`` would blow well past 1024 B.
    The test is the differential signal: if rows leak into the summary,
    the response will exceed 1024 bytes and this test will fire RED.
    """
    many_events = [
        {
            "program_path": rf"C:\Windows\System32\program{i:03d}.exe",
            "timestamp": f"2024-01-15T10:30:{i % 60:02d}+00:00",
            "evidence_size_bytes": 512,
            "extras": {"row_index": str(i)},
        }
        for i in range(200)
    ]
    _make_case(tmp_path, monkeypatch, events=many_events)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    out = await server.get_amcache("smoke")
    out_bytes = out.encode("utf-8")
    assert len(out_bytes) < 1024, (
        f"summary exceeds 1024-byte cap (got {len(out_bytes)} bytes) — "
        f"rows likely leaked into the inline payload instead of being offloaded"
    )

    # Sanity: the offload file does carry all 200 rows — the cap was achieved
    # by offloading, not by truncating data.
    body = _unwrap_body(out)
    payload = _read_offloaded_payload(body)
    assert len(payload["rows"]) == 200


@pytest.mark.asyncio
async def test_claim_finding_summary_response_under_1024_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-8 (claim_finding variant): inline summary < 1024 B even with many audit_ids.

    Uses the universal helper path on a CORROBORATED finding to ensure
    a long ``audit_ids`` list does not push the inline summary over the cap.
    Under AC-13, ``audit_ids`` lives in the offloaded payload, not the
    summary — this test is the differential signal that the AC-13 split
    is enforced even at scale.
    """
    aid1, aid2 = _seed_two_family_ledger(monkeypatch, tmp_path)
    out = await server.claim_finding(
        case_id="smoke",
        hypothesis="X ran on a host with a long-name signature",
        audit_ids=[aid1, aid2],
    )
    out_bytes = out.encode("utf-8")
    assert len(out_bytes) < 1024, (
        f"claim_finding summary exceeds 1024-byte cap (got {len(out_bytes)} bytes) — "
        f"audit_ids/families/hypothesis likely leaked into the inline summary"
    )


@pytest.mark.asyncio
async def test_claim_finding_inline_summary_keys_match_ac13_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-13: claim_finding inline summary keys are EXACTLY the 11 listed.

    The AC-13 lock is structural: certain Finding fields (families, audit_ids,
    hypothesis, confirmation_basis, reason_codes) MUST live only in the
    on-disk payload because they (a) blow the byte budget at scale and
    (b) carry agent-controlled strings (hypothesis) that the offload
    boundary deliberately quarantines from the inline LLM-visible response.
    """
    aid1, aid2 = _seed_two_family_ledger(monkeypatch, tmp_path)
    out = await server.claim_finding(
        case_id="smoke",
        hypothesis="X ran",
        audit_ids=[aid1, aid2],
    )
    body = _unwrap_body(out)

    expected_keys = {
        "audit_id",
        "case_id",
        "tool",
        "rowcount",
        "input_ref",
        "payload_ref",
        "pre_sanitization_sha256",
        "post_sanitization_sha256",
        "tier",
        "n_distinct_families",
        "demoted_for_tamper",
    }
    forbidden_keys = {
        "families",
        "audit_ids",
        "hypothesis",
        "confirmation_basis",
        "reason_codes",
    }

    actual_keys = set(body.keys())
    missing = expected_keys - actual_keys
    extra = actual_keys - expected_keys
    leaked = actual_keys & forbidden_keys

    assert not missing, f"AC-13 inline summary missing keys: {sorted(missing)}"
    assert not leaked, (
        f"AC-13 lock violated: keys {sorted(leaked)} leaked into inline summary "
        f"instead of staying in the offloaded payload"
    )
    # ``extra`` may be non-empty if the AC-13 set is later widened with
    # consensus; for now we pin the set strictly.
    assert not extra, f"AC-13 inline summary has unexpected keys not in the lock: {sorted(extra)}"

    # Cross-check: the forbidden keys DO appear in the offloaded payload
    # (they're not gone, just relocated).
    payload = _read_offloaded_payload(body)
    for k in forbidden_keys:
        assert k in payload, (
            f"AC-13: relocated key {k!r} missing from offloaded payload — "
            f"it must move, not disappear"
        )


def test_validate_offload_root_distinct_from_cases_root_rejects_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-7: SANCTUM_OUTPUT_ROOT MUST NOT resolve under SANCTUM_CASES_ROOT.

    Cases root is a read-only evidence mount. If the offload directory
    resolves under it, the offload write attempts would either fail
    (read-only) or — worse — succeed under a misconfigured re-mount and
    cross-contaminate evidence with server-authored payloads. Refuse at
    startup so the failure mode is deterministic and operator-visible.
    """
    cases = tmp_path / "cases"
    cases.mkdir()
    overlapping_output = cases / "output"  # <-- under cases root
    overlapping_output.mkdir()

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(overlapping_output))

    with pytest.raises(RuntimeError, match=r"(under|inside|cases.root|overlap)"):
        server._validate_offload_root_distinct_from_cases_root()


def test_validate_offload_root_distinct_accepts_separate_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-7 (positive): separate paths MUST pass the startup guard.

    Pins that the guard rejects only true overlap, not prefix coincidence
    on the resolved path (e.g., ``/tmp/cases`` vs ``/tmp/cases-output`` —
    the second is NOT under the first despite sharing a string prefix).
    """
    cases = tmp_path / "cases"
    output = tmp_path / "output"
    cases.mkdir()
    output.mkdir()

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_OUTPUT_ROOT", str(output))

    # Must not raise.
    server._validate_offload_root_distinct_from_cases_root()


def test_validate_offload_root_missing_env_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-11: missing SANCTUM_OUTPUT_ROOT MUST refuse at startup.

    No silent default to ``/tmp`` or to the working directory — the
    offload location is operator-controlled and load-bearing for
    chain-of-custody, so an unset value is a configuration error,
    not a hint to invent a path.
    """
    monkeypatch.setenv(server.CASES_ROOT_ENV, str(tmp_path / "cases"))
    (tmp_path / "cases").mkdir()
    monkeypatch.delenv("SANCTUM_OUTPUT_ROOT", raising=False)

    with pytest.raises(RuntimeError, match=r"SANCTUM_OUTPUT_ROOT"):
        server._validate_offload_root_distinct_from_cases_root()


@pytest.mark.asyncio
async def test_get_amcache_orphan_payload_logs_error_on_append_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """AC-9: payload-then-ledger crash window MUST log ERROR with orphan path.

    The 0o444-and-O_EXCL write completes BEFORE the ledger append. If
    ``append_entry`` raises after the file lands (HMAC key gone, disk full,
    fsync error), the file is an orphan: it cannot be rewritten by the same
    process (mode 0o444), so the operator must learn about it from the log.

    The exception MUST propagate (no silent swallow). The orphan path MUST
    appear in the ERROR log so the operator can correlate.
    """
    import logging as _logging

    from sanctum import audit

    _make_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    # Force append_entry to raise AFTER the offload payload write succeeds.
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated HMAC key drop mid-call")

    monkeypatch.setattr(audit, "append_entry", _boom)

    with caplog.at_level(_logging.ERROR, logger="sanctum.server"):
        with pytest.raises(RuntimeError, match=r"simulated HMAC"):
            await server.get_amcache("smoke")

    orphan_records = [
        rec
        for rec in caplog.records
        if rec.levelno >= _logging.ERROR and "orphan" in rec.message.lower()
    ]
    assert orphan_records, "expected ERROR-level log mentioning 'orphan' after append_entry failure"
    # The orphan path must point under the configured output root so
    # the operator can correlate the log line to a real file.
    output_root = tmp_path / "output"
    assert any(
        str(output_root) in rec.message for rec in orphan_records
    ), "orphan ERROR log must include the on-disk path under SANCTUM_OUTPUT_ROOT"


def test_payload_ref_append_entry_called_through_universal_helper(
    tmp_path: Path,
) -> None:
    """AC-12: ``audit.append_entry(payload_ref=...)`` has exactly ONE call site.

    Decision 5=C universalizes the offload-with-payload-ref pattern across
    every tool that emits a payload (currently get_amcache + claim_finding).
    The contract is: only ``_emit_offloaded_response`` (or its named successor)
    may pass ``payload_ref`` to ``append_entry``. A second call site re-opens
    the inline-rows leak that AC-13 closes.

    Static check on server.py source — counting ``payload_ref=`` keyword
    occurrences in calls to ``append_entry``. Source-level rather than
    runtime because the helper is structural, not behavioral.
    """
    import sanctum.server as _server_mod

    src = Path(_server_mod.__file__).read_text(encoding="utf-8")

    # Match ``append_entry(`` ... ``payload_ref=`` patterns. We approximate
    # call-site granularity by counting the keyword occurrence — under the
    # universal-helper invariant, this should be exactly one (in the helper).
    payload_ref_kw_count = src.count("payload_ref=")
    assert payload_ref_kw_count == 1, (
        f"AC-12 universal-helper invariant violated: ``payload_ref=`` "
        f"appears {payload_ref_kw_count} times in server.py source — "
        f"expected exactly 1 (the universal helper). Multiple call sites "
        f"re-open the inline-rows leak that AC-13 closes."
    )


@pytest.mark.asyncio
async def test_lmax_cap_blocks_oversized_input_before_offload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-16 / AC-6: oversize parser output MUST raise BEFORE any offload write or ledger append.

    The implementation order in ``_emit_offloaded_response`` is:

        json.dumps(full_payload) → sanitize(...) → _write_payload(...) → append_entry(...)

    When ``sanitize`` rejects an input above ``MAX_INPUT_BYTES`` (16 MiB) with
    ``InputTooLargeError``, the two side effects (file under ``SANCTUM_OUTPUT_ROOT``
    and a new ledger entry) MUST NOT have happened. A future refactor that
    re-orders the steps (write-first, sanitize-after) would silently break the
    DoS guarantee from THREAT_MODEL_SANITIZATION.md §7 and admit forgery
    attempts where an attacker forces a partial write before the ledger gets
    a chance to refuse. This test is the regression canary.
    """
    from datetime import datetime as _datetime
    from datetime import timezone as _timezone

    from sanctum.events import ExecutionEvent
    from sanctum.sanitize import MAX_INPUT_BYTES, InputTooLargeError

    _make_case(tmp_path, monkeypatch)
    monkeypatch.setenv(FIXTURE_ENV, "1")

    output_root = tmp_path / "output"
    ledger_path = tmp_path / "ledger.jsonl"

    # Synthesise a parser return whose serialised JSON form exceeds
    # MAX_INPUT_BYTES. A single ASCII string of (cap + 1) bytes inside
    # ``program_path`` is enough — json.dumps emits each byte verbatim.
    huge_program_path = "A" * (MAX_INPUT_BYTES + 1)
    huge_event = ExecutionEvent(
        tool="get_amcache",
        family="AppCompat",
        program_path=huge_program_path,
        timestamp=_datetime(2024, 1, 15, 10, 30, tzinfo=_timezone.utc),
        source_artifact="/cases/smoke/registry/Amcache.hve",
        evidence_size_bytes=512,
        extras={"row_index": "0"},
    )
    monkeypatch.setattr(server, "parse_amcache", lambda _path: [huge_event])

    with pytest.raises(InputTooLargeError):
        await server.get_amcache("smoke")

    # Absence assert #1: no payload file landed under SANCTUM_OUTPUT_ROOT.
    # Walk the entire subtree — a partial-write would create
    # <output_root>/<case_id>/<audit_id>/get_amcache.json.
    leaked_files = [p for p in output_root.rglob("*") if p.is_file()]
    assert leaked_files == [], (
        f"AC-6 bypass: file(s) written under SANCTUM_OUTPUT_ROOT despite "
        f"InputTooLargeError: {leaked_files!r} — sanitize must run before "
        f"_write_payload"
    )

    # Absence assert #2: ledger has no entries from this call.
    if ledger_path.exists():
        non_blank_lines = [
            line for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        assert non_blank_lines == [], (
            f"AC-6 bypass: ledger gained {len(non_blank_lines)} entries "
            f"despite InputTooLargeError — append_entry must run after sanitize"
        )


def test_get_amcache_meta_max_result_size_chars_annotation_present() -> None:
    """AC-14: ``get_amcache`` MUST carry ``_meta``-level max-result-size hint.

    The PRIMARY cap on response size is AC-8's < 1024 B byte test. AC-14 is
    DEFENSE-IN-DEPTH: the ``anthropic/maxResultSizeChars: 4096`` _meta
    annotation tells client-side schedulers to short-circuit if the
    response would exceed the budget — the SDK was extended to surface
    this in mcp 1.27.0 (PR #1463). 4096 chars is loose enough to allow
    reasonable headroom over the 1024-byte cap while still acting as a
    canary against future regressions that re-inline rows.

    Source-level static check: introspecting FastMCP's internal tool
    registry is API-version-fragile, so we pin the contract on the
    decorator literal in the source file.
    """
    import sanctum.server as _server_mod

    src = Path(_server_mod.__file__).read_text(encoding="utf-8")

    # The decorator must apply the meta to BOTH offload tools.
    # We don't pin exact whitespace/quoting — just the key+value substring.
    expected = '"anthropic/maxResultSizeChars": 4096'
    assert expected in src, (
        f"AC-14: server.py source does not contain {expected!r} — "
        f"the @mcp.tool(meta=...) annotation is missing or has the wrong shape"
    )

    # Both tools must be decorated. Cheap proxy: count occurrences ≥ 2.
    count = src.count(expected)
    assert count >= 2, (
        f"AC-14: expected the meta annotation on BOTH get_amcache and "
        f"claim_finding (count >= 2), got {count}"
    )

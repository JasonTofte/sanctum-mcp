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
    """
    if events is None:
        events = [_SAMPLE_EVENT]
    cases = tmp_path / "cases"
    case = cases / case_name
    (case / "registry").mkdir(parents=True)
    hive = case / "registry" / "Amcache.hve"
    hive.write_bytes(b"stub hive")
    _write_sidecar(hive, events)

    monkeypatch.setenv(server.CASES_ROOT_ENV, str(cases))
    monkeypatch.setenv("SANCTUM_LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SANCTUM_LEDGER_HMAC_KEY", _secrets.token_hex(32))
    return cases, hive


def _unwrap_body(out: str) -> dict:
    """Strip <evidence-untrusted> wrapper and JSON-parse the payload."""
    inner = out.removeprefix("<evidence-untrusted>").rstrip()
    inner = inner.removesuffix("</evidence-untrusted>").strip()
    return json.loads(inner)


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


def test_get_amcache_output_is_evidence_wrapped(
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

    out = server.get_amcache("smoke")
    assert out.startswith("<evidence-untrusted>")
    assert out.rstrip().endswith("</evidence-untrusted>")


# ─── T-8: AC-4 — audit_id round-trip (fixture-mode rewrite) ──────────────────


def test_get_amcache_response_surfaces_audit_id(
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

    out = server.get_amcache("smoke")
    body = _unwrap_body(out)

    assert "audit_id" in body, "audit_id missing from response — claim_finding cannot cite"
    assert body["audit_id"], "audit_id surfaced but empty"
    assert body["case_id"] == "smoke"
    assert "rows" in body and isinstance(body["rows"], list)

    # Round-trip: response audit_id matches the most-recently-appended ledger entry.
    last_line = ledger_path.read_text().strip().splitlines()[-1]
    assert json.loads(last_line)["audit_id"] == body["audit_id"]


# ─── T-1: AC-1 — real parser rows shape, no stub keys ────────────────────────


def test_get_amcache_rows_have_real_parser_shape_not_stub_shape(
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

    out = server.get_amcache("smoke")
    body = _unwrap_body(out)
    rows = body["rows"]

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
    assert not hasattr(server, "_parse_amcache_stub"), (
        "_parse_amcache_stub still exists on server module — stub was not deleted"
    )


# ─── T-5: AC-3 — empty sidecar → rows==[] and rowcount==0 ───────────────────


def test_get_amcache_empty_sidecar_returns_empty_rows_and_zero_rowcount(
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

    out = server.get_amcache("smoke")
    body = _unwrap_body(out)

    assert body["rows"] == [], f"expected empty rows list, got: {body['rows']!r}"

    # Verify ledger rowcount agrees.
    last_entry = json.loads(ledger_path.read_text().strip().splitlines()[-1])
    assert last_entry["rowcount"] == 0, (
        f"ledger rowcount must be 0 for empty events, got {last_entry['rowcount']!r}"
    )

    # Negative-sample: stub-shape keys must not appear even in a fabricated 1-row result.
    for stub_key in ("source", "note", "hve_size_bytes", "hve_sha256"):
        for row in body["rows"]:
            assert stub_key not in row, (
                f"stub key {stub_key!r} found — stub may still be returning a fabricated row"
            )


# ─── T-10: AC-5 — JSON round-trip and ISO-8601 timestamp ─────────────────────


def test_get_amcache_rows_are_json_serialisable_with_iso8601_timestamps(
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

    out = server.get_amcache("smoke")
    body = _unwrap_body(out)
    rows = body["rows"]

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


def test_get_amcache_row_count_matches_sidecar_event_count(
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

    out = server.get_amcache("two-event")
    body = _unwrap_body(out)
    assert len(body["rows"]) == 2, f"expected 2 rows, got {len(body['rows'])}"

    # Second case (different case_name, same tmp_path): 0 events.
    _make_case(tmp_path, monkeypatch, case_name="zero-event", events=[])
    out2 = server.get_amcache("zero-event")
    body2 = _unwrap_body(out2)
    assert len(body2["rows"]) == 0, f"expected 0 rows, got {len(body2['rows'])}"


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


def test_get_amcache_empty_sidecar_no_stub_shape_in_rows(
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

    out = server.get_amcache("smoke")
    body = _unwrap_body(out)

    assert body["rows"] == [], "empty sidecar must yield empty rows, not a stub-fabricated row"


def test_get_amcache_fixture_mode_off_raises_on_stub_bytes(
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
        server.get_amcache("smoke")


def test_get_amcache_timestamp_is_semantically_valid_iso8601(
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

    out = server.get_amcache("smoke")
    body = _unwrap_body(out)
    rows = body["rows"]

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

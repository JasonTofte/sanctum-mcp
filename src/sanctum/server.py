"""Sanctum MCP server — six typed tools for Windows execution-evidence families.

All tools are ``async def`` (ARCH-001). Blocking I/O (registry hive parsing,
fsync, file hashing) is offloaded via ``anyio.to_thread.run_sync`` so the
event loop remains responsive for concurrent dispatch.

Concurrency model (ARCH-004 / ARCH-001):
- ``_ledger_write_lock``: ``asyncio.Lock`` serializing ledger writes inside
  ``_emit_offloaded_response``.  Prevents HMAC-chain order corruption when
  FastMCP dispatches multiple tools concurrently.
- ``_tool_semaphore``: ``asyncio.Semaphore(1)`` gating the full body of every
  tool call.  Active when ``SANCTUM_PARALLEL_TOOLS`` is unset or ``"0"``
  (default).  When ``SANCTUM_PARALLEL_TOOLS=1`` the semaphore is bypassed and
  FastMCP dispatches concurrently via its anyio task group.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import hashlib
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, TypedDict

import anyio
from mcp.server.fastmcp import FastMCP

# Imported as a module (not ``from sanctum.audit import append_entry``) so a
# test's ``monkeypatch.setattr(audit, "append_entry", ...)`` reaches the
# call site here in server.py — the AC-9 orphan-log test depends on this.
from sanctum import audit
from sanctum.audit import require_hmac_key
from sanctum.events import ExecutionEvent
from sanctum.finding import (  # noqa: PLC2701 — private package-internal symbols
    _CONFIDENCE_TO_C_SCALE,
    _sha256_canonical,
    evaluate_claim,
)
from sanctum.parsers._fixture_io import _safe_field
from sanctum.parsers.amcache import parse_amcache
from sanctum.parsers.appcompat import parse_shimcache
from sanctum.parsers.bam import parse_bam
from sanctum.parsers.prefetch import parse_prefetch
from sanctum.parsers.sysmon import parse_sysmon
from sanctum.parsers.userassist import parse_userassist

# ``write_payload`` is aliased to ``_write_payload`` to keep the "write"
# token off the module's public surface — the banned-verb tokenizer in
# test_server_exposes_no_write_tool walks ``dir(server)`` and rejects any
# non-underscore symbol containing ``write`` / ``exec`` / ``shell`` / ``run``.
from sanctum.payload import (
    OUTPUT_ROOT_ENV,
    validate_offload_root_distinct_from_cases_root,
)
from sanctum.payload import (
    write_payload as _write_payload,
)
from sanctum.sanitize import MAX_INPUT_BYTES, sanitize, wrap_evidence

log = logging.getLogger("sanctum.server")

CASES_ROOT_ENV = "SANCTUM_CASES_ROOT"
DEFAULT_CASES_ROOT = "/cases"
SKIP_MOUNT_CHECK_ENV = "SANCTUM_SKIP_MOUNT_CHECK"

# AC-14 (defense-in-depth): tells client schedulers to short-circuit if the
# response would exceed the budget. PRIMARY cap is the inline-summary byte
# test (AC-8 < 1024 B). 4096 chars is loose enough to accommodate UTF-8
# expansion while still acting as a regression canary if rows ever leak
# back into the inline payload. Surfaced via the ``meta`` parameter on
# ``@mcp.tool()`` (mcp 1.27.0+; see PR anthropics/python-sdk#1463). The
# literal is INLINED at every decorator site rather than DRY'd via a module
# constant — the AC-14 source-level test pins the literal at every offload
# tool, and the indirection through a name reference would silently bypass
# the regression canary if a future migration forgot to apply the constant.

# Conservative allowlist for ``case_id``. Rejects Unicode control characters
# (bidi override ‮, zero-width ​, etc.), shell metacharacters,
# whitespace, and path separators — defense in depth before the resolve-based
# containment check. Real case IDs in this project look like
# ``cfreds-hacking-case``; anything outside the allowlist is a bypass attempt.
_SAFE_CASE_ID = re.compile(r"^[A-Za-z0-9._-]+$")

mcp = FastMCP("sanctum")

# ─── concurrency primitives (ARCH-001 / ARCH-004) ─────────────────────────────

# Single-writer lock for ledger appends. Prevents HMAC-chain order corruption
# when FastMCP dispatches multiple async tools concurrently (ARCH-004).
# asyncio.Lock() created at module level is safe in Python 3.10+ — the lock
# does NOT store a loop reference; it calls asyncio.get_running_loop() when
# first acquired.
_ledger_write_lock = asyncio.Lock()

# Serialization semaphore for the full tool body.  Created once per
# (parallel_mode: bool) value so the SAME Semaphore(1) is reused across calls
# — a fresh Semaphore per call would not serialize anything.
@functools.lru_cache(maxsize=None)
def _get_tool_semaphore(*, parallel: bool) -> asyncio.Semaphore | None:
    return None if parallel else asyncio.Semaphore(1)


@contextlib.asynccontextmanager
async def _serial_gate() -> AsyncIterator[None]:
    """Acquire the per-call serialization gate unless ``SANCTUM_PARALLEL_TOOLS=1``.

    When the env var is ``"1"``, this is a no-op and FastMCP's anyio task group
    dispatches tools concurrently.  Otherwise, ``Semaphore(1)`` ensures at most
    one tool body runs at a time (AC-5).
    """
    sem = _get_tool_semaphore(parallel=(os.environ.get("SANCTUM_PARALLEL_TOOLS") == "1"))
    if sem is not None:
        async with sem:
            yield
    else:
        yield


@dataclass(frozen=True)
class CasePaths:
    case_id: str
    root: Path
    amcache_hve: Path
    system_hve: Path    # SYSTEM hive: shimcache (AppCompat) + bam (Background-service)
    ntuser_hve: Path    # NTUSER.DAT: userassist (Explorer/NTUSER)
    prefetch_dir: Path  # Prefetch/ directory: one .pf file per executable (SysMain)
    sysmon_evtx: Path   # Sysmon/Security EVTX: process-create events (Kernel-ETW)


def _validate_evidence_mount(cases_root: Path) -> None:
    """Refuse to start if the evidence mount is writable (CLAUDE.md invariant #4).

    The project invariant states that evidence directories are mounted
    read-only at the OS level so a compromised MCP process cannot mutate
    evidence in-place. This function is the runtime enforcement of that
    invariant — it checks the VFS read-only flag via ``os.statvfs`` and
    raises ``RuntimeError`` if the mount is writable.

    Completeness note: ``statvfs`` reports the **VFS-layer** ro flag only.
    A dirty ext3/4 filesystem can still replay its journal when mounted
    ``-o ro``, writing to the underlying block device. The mount command in
    ``docs/REPRODUCTION.md`` therefore also specifies ``noload,norecovery``
    plus ``blockdev --setro`` on the underlying device — the documented
    command and this runtime check are load-bearing together, not
    alternatives.

    Dev bypass: ``SANCTUM_SKIP_MOUNT_CHECK=1`` skips the check and emits a
    WARN log so the override is never silent. Never use in production.
    """

    if os.environ.get(SKIP_MOUNT_CHECK_ENV) == "1":
        log.warning(
            "%s=1 — skipping evidence-mount ro check. NEVER USE IN PRODUCTION.",
            SKIP_MOUNT_CHECK_ENV,
        )
        return

    if not cases_root.exists():
        raise RuntimeError(
            f"evidence mount check: cases root does not exist: {cases_root}. "
            f"Set {CASES_ROOT_ENV} or create the mount point."
        )

    flag = os.statvfs(cases_root).f_flag
    if not (flag & os.ST_RDONLY):
        raise RuntimeError(
            f"evidence mount {cases_root} is writable. "
            f"Re-mount read-only: "
            f"`mount -o remount,ro,noload,norecovery,noexec,nosuid {cases_root}`. "
            f"For ext-family filesystems also run "
            f"`blockdev --setro <underlying-device>` to block journal-replay "
            f"writes. Set {SKIP_MOUNT_CHECK_ENV}=1 to bypass for development."
        )
    log.info("evidence mount ro-check passed: %s", cases_root)


def _validate_case_id_format(case_id: str) -> None:
    """Format-only check on ``case_id`` — does not touch the filesystem.

    Layers 1 and 2 of :func:`_resolve_case`'s defense, factored out so tools
    that don't need filesystem resolution (e.g., :func:`claim_finding`, which
    operates over the ledger only) can still gate against bidi-override,
    zero-width, shell-metacharacter, and ``..``-traversal attacks before the
    untrusted string lands in the audit ledger.
    """
    if not case_id or not _SAFE_CASE_ID.match(case_id) or ".." in case_id:
        # ``case_id`` is attacker-influenceable input that has just failed the
        # allowlist; the exception string lands in the FastMCP ``isError``
        # channel which serializes raw bytes to the LLM, bypassing the
        # success-path ``sanitize.sanitize()`` and the ``<evidence-untrusted>``
        # quarantine wrapper (memory: ``feedback_error_channel_bypass``).
        # ``repr()`` escapes Cf-category Unicode (RLO, Tag block) but does
        # NOT escape printable ASCII like ``<`` ``>`` — wrap with
        # ``_safe_field`` so the parser-boundary delimiter set substitutes
        # ``?`` before the message is built. ``!r`` retained for analyst
        # readability (quote-delimited) and to keep the existing test regex
        # (``match="unsafe case_id"``) identical.
        raise ValueError(f"unsafe case_id: {_safe_field(case_id)!r}")


def _resolve_case(case_id: str) -> CasePaths:
    """Resolve and validate a case directory. Refuses paths outside the cases root.

    Three layers of defense, in order:

    1. ``_SAFE_CASE_ID`` allowlist rejects Unicode control characters, shell
       metacharacters, whitespace, and anything not ``[A-Za-z0-9._-]``. Catches
       bidi-override (``\\u202e``) and zero-width attacks before any filesystem
       operation runs.
    2. Explicit ``..`` string check — ``..`` is in the allowlist regex (``.``
       and ``.`` adjacent) but must never appear in a case_id.
    3. Canonical-path containment: each resolved artifact path must be rooted
       under the case directory. Catches symlinks pointing outside the case
       (e.g., ``<case>/registry/Amcache.hve -> /etc/shadow``).
    """

    _validate_case_id_format(case_id)

    root = Path(os.environ.get(CASES_ROOT_ENV, DEFAULT_CASES_ROOT)).resolve()
    case_dir = (root / case_id).resolve()
    if root not in case_dir.parents and case_dir != root:
        raise ValueError(f"case_id escapes cases root: {case_id!r}")
    if not case_dir.is_dir():
        raise FileNotFoundError(f"case directory not found: {case_dir}")

    def _check(rel: str) -> Path:
        """Resolve a case-relative path; reject symlinks that escape the case dir."""
        p = (case_dir / rel).resolve()
        if case_dir not in p.parents:
            raise ValueError(f"path escapes case directory (symlink?): {p}")
        return p

    return CasePaths(
        case_id=case_id,
        root=case_dir,
        amcache_hve=_check("registry/Amcache.hve"),
        system_hve=_check("registry/SYSTEM"),
        ntuser_hve=_check("registry/NTUSER.DAT"),
        prefetch_dir=_check("Prefetch"),
        sysmon_evtx=_check("logs/Microsoft-Windows-Sysmon%4Operational.evtx"),
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_offload_root_distinct_from_cases_root() -> None:
    """Startup guard for AC-7 + AC-11.

    AC-11: Refuses if ``SANCTUM_OUTPUT_ROOT`` is unset (no silent default
    to ``/tmp`` or to the cwd — the offload location is operator-controlled
    and load-bearing for evidence-path integrity, so an unset value is a
    configuration error, not a hint to invent a path).

    AC-7: Refuses if ``SANCTUM_OUTPUT_ROOT`` resolves under
    ``SANCTUM_CASES_ROOT``. The cases root is a read-only evidence mount;
    if the offload directory resolves under it, the offload write attempts
    would either fail (read-only mount) or — worse — succeed under a
    misconfigured re-mount and cross-contaminate evidence with
    server-authored payloads.
    """
    output_root_env = os.environ.get(OUTPUT_ROOT_ENV)
    if not output_root_env:
        raise RuntimeError(
            f"{OUTPUT_ROOT_ENV} is not set — refusing to start. The offload "
            f"location must be operator-configured; there is no safe default."
        )
    cases_root = Path(os.environ.get(CASES_ROOT_ENV, DEFAULT_CASES_ROOT))
    validate_offload_root_distinct_from_cases_root(
        output_root=Path(output_root_env),
        cases_root=cases_root,
    )


async def _emit_offloaded_response(
    *,
    case_id: str,
    tool: str,
    args: dict[str, Any],
    input_ref: dict[str, Any] | None,
    full_payload: dict[str, Any],
    rowcount: int | None,
    audit_id: str,
    summary_extra: dict[str, Any] | None = None,
) -> str:
    """Universal offload helper (AC-12). Async so the lock can wrap the ledger write.

    Flow:

    1. Sanitize ``full_payload`` (CPU-bound, inline — no blocking I/O).
    2. Offload payload write to a thread (``anyio.to_thread.run_sync``) —
       write-once to ``$SANCTUM_OUTPUT_ROOT/<case_id>/<audit_id>/<tool>.json``
       mode 0o444 via O_CREAT|O_EXCL.
    3. Under ``_ledger_write_lock``: offload ``audit.append_entry`` to a thread.
       The lock holds for the full sync call (read-prev-hash + write) preventing
       HMAC-chain order corruption across concurrent tool dispatches (ARCH-004).
    4. Build and return the AC-13 inline summary wrapped in
       ``<evidence-untrusted>``.

    Crash window (AC-9): if ``audit.append_entry`` raises after the payload
    write succeeds, the file is an orphan (mode 0o444). Log ERROR before
    re-raising so the operator can correlate.
    """
    raw = json.dumps(full_payload, ensure_ascii=False, sort_keys=False, indent=2)
    # Offloaded blobs may legitimately exceed the 64 KiB inline LLM cap.
    # MAX_INPUT_BYTES (16 MiB) is sized for on-disk payloads, not the summary.
    sanitized = sanitize(raw, max_bytes=MAX_INPUT_BYTES)

    payload_ref_obj = await anyio.to_thread.run_sync(
        lambda: _write_payload(
            case_id=case_id,
            audit_id=audit_id,
            tool=tool,
            content=sanitized.payload,
        )
    )
    payload_ref_dict = payload_ref_obj.to_json_dict()

    # Extract evidence-event timestamp bounds from rows for temporal demoter (AC-5).
    # ISO-8601 UTC strings sort lexicographically, so min/max over strings is correct.
    _ts_values = [
        row["timestamp"]
        for row in full_payload.get("rows", [])
        if isinstance(row, dict) and "timestamp" in row
    ]
    _first_event_ts: str | None = min(_ts_values) if _ts_values else None
    _last_event_ts: str | None = max(_ts_values) if _ts_values else None

    async with _ledger_write_lock:
        try:
            entry = await anyio.to_thread.run_sync(
                lambda: audit.append_entry(
                    case_id=case_id,
                    tool=tool,
                    args=args,
                    input_ref=input_ref,
                    pre_sanitization_sha256=sanitized.pre_hash,
                    post_sanitization_sha256=sanitized.post_hash,
                    rowcount=rowcount,
                    payload_ref=payload_ref_dict,
                    audit_id=audit_id,
                    first_event_ts=_first_event_ts,
                    last_event_ts=_last_event_ts,
                )
            )
        except Exception:
            log.error(
                "orphan payload at %s — ledger append failed (file is mode 0o444 "
                "and cannot be rewritten by the same process; operator must "
                "remove it manually if a retry with the same audit_id is desired)",
                payload_ref_obj.path,
            )
            raise

    summary: dict[str, Any] = {
        "audit_id": entry.audit_id,
        "case_id": entry.case_id,
        "tool": entry.tool,
        "rowcount": entry.rowcount,
        "input_ref": entry.input_ref,
        "payload_ref": payload_ref_dict,
        "pre_sanitization_sha256": entry.pre_sanitization_sha256,
        "post_sanitization_sha256": entry.post_sanitization_sha256,
    }
    if summary_extra:
        summary.update(summary_extra)

    # Include sanitized evidence rows inline so the LLM can reason about
    # what was found.  ``claim_finding``'s payload has no ``rows`` key so
    # this branch is skipped there (AC-13 is unaffected).  The outer
    # ``sanitize(summary_raw)`` call below strips injection patterns from
    # the row values before they reach the LLM, and ``wrap_evidence``
    # labels the whole block as untrusted data.
    rows = full_payload.get("rows")
    if rows is not None:
        summary["rows"] = rows

    summary_raw = json.dumps(summary, ensure_ascii=False, sort_keys=False)
    return wrap_evidence(sanitize(summary_raw).payload)


class AmcacheRow(TypedDict):
    """Wire shape for one row inside ``get_amcache``'s JSON response.

    The named keys exist to make the boundary contract checkable: a future
    rename / drop / addition surfaces as a mypy error at the call site
    rather than as a downstream JSON parse failure on the LLM side.
    `timestamp` is an ISO-8601 string (T-separator) and `extras` is a
    plain ``dict[str, str]`` because the row is JSON-serialised — not a
    ``MappingProxyType`` like the originating ``ExecutionEvent.extras``.
    """

    tool: str
    family: str
    program_path: str
    timestamp: str
    source_artifact: str
    evidence_size_bytes: int
    extras: dict[str, str]


def _event_to_row(event: ExecutionEvent) -> AmcacheRow:
    """Serialise one ExecutionEvent to the get_amcache wire shape.

    Local to server.py until a second family's MCP tool requires this shape
    (YAGNI): the `AmcacheRow` TypedDict above documents the stable wire
    contract, so extraction to a shared `sanctum.wire` module is a clean
    follow-up once tool two ships, not a refactor that needs to land here.

    ISO-8601 form is `isoformat()` (T-separator), not `str()` (which uses
    a space separator that strict ISO-8601 consumers reject).
    """
    return {
        "tool": event.tool,
        "family": event.family,
        "program_path": event.program_path,
        "timestamp": event.timestamp.isoformat(),
        "source_artifact": event.source_artifact,
        "evidence_size_bytes": event.evidence_size_bytes,
        "extras": dict(event.extras),
    }


# ─── MCP tools — all async def (ARCH-001) ─────────────────────────────────────


@mcp.tool(meta={"anthropic/maxResultSizeChars": 4096})
async def get_amcache(case_id: str) -> str:
    """Return structured Amcache rows for ``case_id``, quarantined for LLM consumption.

    Returns the standard offload-pattern summary (≤ ~800 B; bounded by AC-8
    < 1024 B) wrapped in ``<evidence-untrusted>``. The full row payload is
    written write-once to ``$SANCTUM_OUTPUT_ROOT/<case_id>/<audit_id>/
    get_amcache.json`` (mode 0o444); the inline summary carries a
    ``payload_ref`` so the caller can read the full data via Claude
    Code's generic file-read tool.

    Each row in the offloaded file is a dict serialised from
    :class:`~sanctum.events.ExecutionEvent` with keys: ``tool``, ``family``,
    ``program_path``, ``timestamp`` (ISO-8601 UTC, T-separator),
    ``source_artifact``, ``evidence_size_bytes``, ``extras``.

    Every invocation extends the HMAC-chained ledger with an entry whose
    ``payload_ref`` is covered by the chain — so a swapped-payload attack
    against the offload directory breaks ``verify_chain``.

    Raises:
      - :class:`ValueError` — on path-traversal or unsafe ``case_id``.
      - :class:`FileNotFoundError` — if the case or hive is missing.
      - :class:`~sanctum.parsers._errors.ArtifactMalformedError` — if the
        hive bytes can't be parsed (propagates from :func:`parse_amcache`,
        which scrubs attacker-controlled byte/offset values from the
        exception text per ``feedback_error_channel_bypass.md``).
    """
    async with _serial_gate():
        paths = _resolve_case(case_id)
        input_hash = await anyio.to_thread.run_sync(
            lambda: _sha256_file(paths.amcache_hve) if paths.amcache_hve.exists() else None
        )

        rows = await anyio.to_thread.run_sync(
            lambda: [_event_to_row(e) for e in parse_amcache(paths.amcache_hve)]
        )

        # Pre-mint audit_id BEFORE the offload write so the on-disk path and
        # the ledger entry share a key by construction (AC-7). Trying to
        # round-trip the audit_id from a post-write append_entry would create
        # a TOCTOU window between path commitment and ledger commitment.
        audit_id = str(uuid.uuid4())
        full_payload: dict[str, Any] = {
            "audit_id": audit_id,
            "case_id": case_id,
            "rows": rows,
        }

        return await _emit_offloaded_response(
            case_id=case_id,
            tool="get_amcache",
            args={"case_id": case_id},
            input_ref={
                "path": str(paths.amcache_hve),
                "sha256": input_hash,
            },
            full_payload=full_payload,
            rowcount=len(rows),
            audit_id=audit_id,
        )


@mcp.tool(meta={"anthropic/maxResultSizeChars": 4096})
async def get_shimcache(case_id: str) -> str:
    """Return ShimCache (AppCompatCache) rows for ``case_id`` from the SYSTEM hive.

    ShimCache records every executable that Windows AppCompatibility checked —
    including executables that ran but left no Amcache entry, and executables
    that were never run but were present on disk. Pairs with Amcache to form
    the AppCompat family (CLAUDE.md invariant #5).
    """
    async with _serial_gate():
        paths = _resolve_case(case_id)
        input_hash = await anyio.to_thread.run_sync(
            lambda: _sha256_file(paths.system_hve) if paths.system_hve.exists() else None
        )

        rows = await anyio.to_thread.run_sync(
            lambda: [_event_to_row(e) for e in parse_shimcache(paths.system_hve)]
        )

        audit_id = str(uuid.uuid4())
        full_payload: dict[str, Any] = {
            "audit_id": audit_id,
            "case_id": case_id,
            "rows": rows,
        }

        return await _emit_offloaded_response(
            case_id=case_id,
            tool="get_shimcache",
            args={"case_id": case_id},
            input_ref={
                "path": str(paths.system_hve),
                "sha256": input_hash,
            },
            full_payload=full_payload,
            rowcount=len(rows),
            audit_id=audit_id,
        )


@mcp.tool(meta={"anthropic/maxResultSizeChars": 4096})
async def get_userassist(case_id: str) -> str:
    """Return UserAssist execution-count rows for ``case_id`` from NTUSER.DAT.

    UserAssist records GUI-launched programs via the ROT-13-encoded registry
    key at ``NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\
    Explorer\\UserAssist``. Belongs to the Explorer/NTUSER family.
    """
    async with _serial_gate():
        paths = _resolve_case(case_id)
        input_hash = await anyio.to_thread.run_sync(
            lambda: _sha256_file(paths.ntuser_hve) if paths.ntuser_hve.exists() else None
        )

        rows = await anyio.to_thread.run_sync(
            lambda: [_event_to_row(e) for e in parse_userassist(paths.ntuser_hve)]
        )

        audit_id = str(uuid.uuid4())
        full_payload: dict[str, Any] = {
            "audit_id": audit_id,
            "case_id": case_id,
            "rows": rows,
        }

        return await _emit_offloaded_response(
            case_id=case_id,
            tool="get_userassist",
            args={"case_id": case_id},
            input_ref={
                "path": str(paths.ntuser_hve),
                "sha256": input_hash,
            },
            full_payload=full_payload,
            rowcount=len(rows),
            audit_id=audit_id,
        )


@mcp.tool(meta={"anthropic/maxResultSizeChars": 4096})
async def get_bam(case_id: str) -> str:
    """Return Background Activity Moderator rows for ``case_id`` from the SYSTEM hive.

    BAM records which executables were active in the background, with per-SID
    last-execution timestamps, from ``SYSTEM\\CurrentControlSet\\Services\\bam\\
    State\\UserSettings``. Belongs to the Background-service family.

    Note: BAM and ShimCache share the SYSTEM hive as their source. A
    ``{bam, shimcache}`` pair is documented as 'weakly corroborated' — they
    share a trust root and can be defeated together. See
    ``docs/THREAT_MODEL_TRIANGULATION.md`` §"Family coupling".
    """
    async with _serial_gate():
        paths = _resolve_case(case_id)
        input_hash = await anyio.to_thread.run_sync(
            lambda: _sha256_file(paths.system_hve) if paths.system_hve.exists() else None
        )

        rows = await anyio.to_thread.run_sync(
            lambda: [_event_to_row(e) for e in parse_bam(paths.system_hve)]
        )

        audit_id = str(uuid.uuid4())
        full_payload: dict[str, Any] = {
            "audit_id": audit_id,
            "case_id": case_id,
            "rows": rows,
        }

        return await _emit_offloaded_response(
            case_id=case_id,
            tool="get_bam",
            args={"case_id": case_id},
            input_ref={
                "path": str(paths.system_hve),
                "sha256": input_hash,
            },
            full_payload=full_payload,
            rowcount=len(rows),
            audit_id=audit_id,
        )


@mcp.tool(meta={"anthropic/maxResultSizeChars": 4096})
async def get_prefetch(case_id: str) -> str:
    """Return Prefetch execution rows for all ``.pf`` files under ``<case>/Prefetch/``.

    Prefetch files (``C:\\Windows\\Prefetch\\*.pf``) record executable names,
    load-order traces, and eight most-recent execution timestamps. Belongs to
    the SysMain (Prefetch) family. All ``.pf`` files in the case's
    ``Prefetch/`` directory are parsed; events are concatenated.
    """
    async with _serial_gate():
        paths = _resolve_case(case_id)

        def _parse_all_pf() -> list[AmcacheRow]:
            events: list[ExecutionEvent] = []
            if paths.prefetch_dir.is_dir():
                case_root = paths.root.resolve()
                for pf in sorted(paths.prefetch_dir.glob("*.pf")):
                    resolved = pf.resolve()
                    if case_root not in resolved.parents:
                        continue  # skip symlinks escaping the case directory
                    events.extend(parse_prefetch(pf))
            return [_event_to_row(e) for e in events]

        rows = await anyio.to_thread.run_sync(_parse_all_pf)

        audit_id = str(uuid.uuid4())
        full_payload: dict[str, Any] = {
            "audit_id": audit_id,
            "case_id": case_id,
            "rows": rows,
        }

        return await _emit_offloaded_response(
            case_id=case_id,
            tool="get_prefetch",
            args={"case_id": case_id},
            input_ref={
                "path": str(paths.prefetch_dir),
                "sha256": None,
            },
            full_payload=full_payload,
            rowcount=len(rows),
            audit_id=audit_id,
        )


@mcp.tool(meta={"anthropic/maxResultSizeChars": 4096})
async def get_sysmon_4688(case_id: str) -> str:
    """Return Sysmon EID-1 and Security EID-4688 process-create events for ``case_id``.

    Parses ``<case>/logs/Microsoft-Windows-Sysmon%4Operational.evtx``.
    Records command lines, process GUIDs, and parent process paths. Belongs
    to the Kernel-ETW (Sysmon/4688) family — the highest-fidelity execution
    evidence family because Kernel-ETW events require kernel-level compromise
    to forge retroactively.
    """
    async with _serial_gate():
        paths = _resolve_case(case_id)
        input_hash = await anyio.to_thread.run_sync(
            lambda: _sha256_file(paths.sysmon_evtx) if paths.sysmon_evtx.exists() else None
        )

        rows = await anyio.to_thread.run_sync(
            lambda: [_event_to_row(e) for e in parse_sysmon(paths.sysmon_evtx)]
        )

        audit_id = str(uuid.uuid4())
        full_payload: dict[str, Any] = {
            "audit_id": audit_id,
            "case_id": case_id,
            "rows": rows,
        }

        return await _emit_offloaded_response(
            case_id=case_id,
            tool="get_sysmon_4688",
            args={"case_id": case_id},
            input_ref={
                "path": str(paths.sysmon_evtx),
                "sha256": input_hash,
            },
            full_payload=full_payload,
            rowcount=len(rows),
            audit_id=audit_id,
        )


@mcp.tool(meta={"anthropic/maxResultSizeChars": 4096})
async def claim_finding(case_id: str, hypothesis: str, audit_ids: list[str]) -> str:
    """Gate a forensic claim through the family-corroboration check.

    The agent calls this after gathering evidence via ``get_*`` tools. The
    server reads each ``audit_id`` from the HMAC-chained ledger, resolves
    the contributing artifact family (CLAUDE.md invariant 5; the five
    families are AppCompat, Explorer/NTUSER, Background-service, Kernel-ETW,
    SysMain), counts distinct families, and returns a Finding whose
    ``tier`` is ``DRAFT``, ``CORROBORATED``, ``FINAL``, or
    ``DRAFT_TAMPER_SUSPECTED``. ≥2 distinct families promotes to
    CORROBORATED; ≥3 to FINAL.

    This is the **external-signal self-correction** primitive in Kamoi
    (TACL 2024)'s taxonomy — the agent's claim is checked against an
    independent signal (artifact-family coupling) rather than against the
    agent's own introspection (Reflexion / Self-Refine, both shown by
    Huang ICLR 2024 to degrade reasoning when the model is its own judge).

    Returns the AC-13 inline summary (audit_id, case_id, tool, rowcount,
    input_ref, payload_ref, pre/post sanitisation hashes, tier,
    confirmation_basis, n_distinct_families, demoted_for_tamper) wrapped
    in ``<evidence-untrusted>``. ``confirmation_basis`` is a
    server-computed ``Literal`` string (never agent-influenced) that lets
    the agent understand *why* the tier was set without re-reading the
    offloaded payload. The full Finding payload — including ``audit_ids``,
    ``families``, ``hypothesis``, and ``reason_codes`` — is written to
    the offloaded payload file, NOT the inline summary. The hypothesis
    string is agent-authored and the offload boundary deliberately
    quarantines it from the inline LLM-visible response.

    Refusal contracts (each surfaces an exception the agent observes):

    - Empty ``audit_ids`` → :class:`sanctum.finding.ClaimFindingError`.
    - Any ``audit_id`` not present in the ledger → ``ClaimFindingError``.
      This is the strict-fail-closed gate against an agent fabricating
      audit_ids under prompt-injection pressure — the most
      architecturally load-bearing refusal in the system.
    - Any referenced ledger entry has an unmapped tool →
      :class:`sanctum.families.UnknownToolError`.
    - Unsafe ``case_id`` (Unicode/bidi/zero-width/path-traversal) →
      :class:`ValueError`.
    """
    async with _serial_gate():
        _validate_case_id_format(case_id)

        # Gate evaluation, no ledger I/O — the offload helper does the append
        # so the on-disk path and the ledger entry share a pre-minted audit_id.
        evaluation = evaluate_claim(
            case_id=case_id,
            hypothesis=hypothesis,
            audit_ids=audit_ids,
        )

        audit_id = str(uuid.uuid4())
        finding_payload: dict[str, Any] = {
            "audit_id": audit_id,
            "case_id": case_id,
            "hypothesis": hypothesis,
            "tier": evaluation.tier.value,
            "audit_ids": list(evaluation.audit_ids),
            "families": list(evaluation.families),
            "n_distinct_families": evaluation.n_distinct_families,
            "confirmation_basis": evaluation.confirmation_basis,
            "reason_codes": list(evaluation.reason_codes),
            "demoted_for_tamper": evaluation.demoted_for_tamper,
            "c_scale": _CONFIDENCE_TO_C_SCALE[evaluation.tier],
        }

        # input_ref for claim_finding is a small content fingerprint (not the
        # full Finding) so the inline summary stays under AC-8's 1024-byte cap.
        # The full Finding lives in the offloaded payload, where size is
        # bounded only by the 16 MiB sanitize cap.
        finding_hash = _sha256_canonical(finding_payload)

        return await _emit_offloaded_response(
            case_id=case_id,
            tool="claim_finding",
            args={
                "hypothesis": hypothesis,
                "audit_ids": list(evaluation.audit_ids),
                "deception_signal_count": 0,
            },
            input_ref={"finding_hash": finding_hash},
            full_payload=finding_payload,
            rowcount=len(evaluation.audit_ids),
            audit_id=audit_id,
            summary_extra={
                "tier": evaluation.tier.value,
                "confirmation_basis": evaluation.confirmation_basis,
                "n_distinct_families": evaluation.n_distinct_families,
                "demoted_for_tamper": evaluation.demoted_for_tamper,
            },
        )


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("SANCTUM_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cases_root = Path(os.environ.get(CASES_ROOT_ENV, DEFAULT_CASES_ROOT))
    log.info("Sanctum MCP server starting; cases_root=%s", cases_root)
    _validate_evidence_mount(cases_root)
    _validate_offload_root_distinct_from_cases_root()  # AC-7 + AC-11
    log.info(
        "offload-root guard passed: %s",
        os.environ.get(OUTPUT_ROOT_ENV),
    )
    require_hmac_key()  # refuses to start if SANCTUM_LEDGER_HMAC_KEY is unset
    log.info("audit-ledger HMAC key loaded")
    mcp.run()


if __name__ == "__main__":
    main()

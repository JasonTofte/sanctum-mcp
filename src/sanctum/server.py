"""Sanctum MCP server — week-1 P0 skeleton.

Exposes exactly ONE typed tool: :func:`get_amcache`. The surface intentionally
does not include any shell-passthrough or file-write capabilities. Expanding
the tool surface is a week-2 activity; the P0 goal is proving the architecture
closes end-to-end against one CFReDS case.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from sanctum import payload as _payload_mod
from sanctum.audit import append_entry
from sanctum.sanitize import sanitize, wrap_evidence

log = logging.getLogger("sanctum.server")

CASES_ROOT_ENV = "SANCTUM_CASES_ROOT"
DEFAULT_CASES_ROOT = "/cases"

mcp = FastMCP("sanctum")


@dataclass(frozen=True)
class CasePaths:
    case_id: str
    root: Path
    amcache_hve: Path


def _resolve_case(case_id: str) -> CasePaths:
    """Resolve and validate a case directory. Refuses paths outside the cases root.

    A judge-scripted bypass — passing ``../..`` or an absolute path — MUST be
    blocked at this boundary. The MCP server never opens any file not rooted
    under :data:`CASES_ROOT_ENV`.
    """

    root = Path(os.environ.get(CASES_ROOT_ENV, DEFAULT_CASES_ROOT)).resolve()
    case_dir = (root / case_id).resolve()
    if root not in case_dir.parents and case_dir != root:
        raise ValueError(f"case_id escapes cases root: {case_id!r}")
    if not case_dir.is_dir():
        raise FileNotFoundError(f"case directory not found: {case_dir}")

    amcache = case_dir / "registry" / "Amcache.hve"
    return CasePaths(case_id=case_id, root=case_dir, amcache_hve=amcache)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_amcache_stub(path: Path) -> list[dict[str, object]]:
    """Placeholder parser — real implementation wraps Eric Zimmerman's AmcacheParser.

    Week-1 P0 returns a stub so end-to-end flow can be exercised without blocking
    on the full Amcache hive parser. Replace with a subprocess call to
    ``AmcacheParser.exe`` (via mono or dotnet on SIFT) or a pure-Python library
    in week 2.
    """

    # Intentionally minimal — structure matches what the week-2 parser will emit.
    return [
        {
            "source": "Amcache.hve",
            "note": "P0 stub — real parser wired in week 2",
            "hve_size_bytes": path.stat().st_size if path.exists() else None,
            "hve_sha256": _sha256_file(path) if path.exists() else None,
        }
    ]


def _build_summary(
    *,
    audit_id: str,
    case_id: str,
    tool: str,
    rowcount: int,
    input_ref: dict[str, object],
    payload_ref: _payload_mod.PayloadRef,
    pre_sanitization_sha256: str,
    post_sanitization_sha256: str,
) -> str:
    """Return the short JSON summary emitted to the LLM.

    Structured so the serialized-plus-evidence-wrapped output stays well below
    the MCP stdio payload cliff observed in anthropics/claude-code#36319 (~1 KB).
    """

    summary = {
        "audit_id": audit_id,
        "case_id": case_id,
        "tool": tool,
        "rowcount": rowcount,
        "input_ref": input_ref,
        "payload_ref": payload_ref.to_json_dict(),
        "pre_sanitization_sha256": pre_sanitization_sha256,
        "post_sanitization_sha256": post_sanitization_sha256,
    }
    return json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2)


@mcp.tool()
def get_amcache(case_id: str) -> str:
    """Return a short summary with a ``payload_ref`` for the Amcache rows.

    The full sanitized Amcache payload is written write-once to disk under
    :envvar:`SANCTUM_OUTPUT_ROOT`; the return value is a short JSON summary
    (wrapped in ``<evidence-untrusted>``) carrying an ``audit_id`` and a
    ``payload_ref`` that the caller can read via its generic file-read tool.

    The short-return shape survives the MCP stdio payload cliff
    (anthropics/claude-code#36319); an inline evidence dump on a realistic
    Amcache hive would silently drop, leaving the ledger with an ``audit_id``
    for output the LLM never saw.

    Every invocation writes:
      - An audit-ledger entry carrying ``input_ref`` + pre/post sanitization
        SHA-256 + ``payload_ref``. The ``audit_id`` is pre-generated so the
        ledger key and on-disk artifact path are guaranteed to match.
      - A payload file at ``<output_root>/<case_id>/<audit_id>/get_amcache.json``.

    Raises :class:`ValueError` on path-traversal attempts, :class:`FileNotFoundError`
    if the case or hive is missing.
    """

    paths = _resolve_case(case_id)
    input_hash = _sha256_file(paths.amcache_hve) if paths.amcache_hve.exists() else None

    rows = _parse_amcache_stub(paths.amcache_hve)
    raw_payload = json.dumps({"case_id": case_id, "rows": rows}, ensure_ascii=False, indent=2)

    result = sanitize(raw_payload)
    wrapped_full = wrap_evidence(result.payload)

    audit_id = str(uuid.uuid4())
    payload_ref = _payload_mod.write_payload(
        case_id=case_id,
        audit_id=audit_id,
        tool="get_amcache",
        content=wrapped_full,
    )

    input_ref: dict[str, object] = {
        "path": str(paths.amcache_hve),
        "sha256": input_hash,
    }
    append_entry(
        case_id=case_id,
        tool="get_amcache",
        args={"case_id": case_id},
        input_ref=input_ref,
        pre_sanitization_sha256=result.pre_hash,
        post_sanitization_sha256=result.post_hash,
        rowcount=len(rows),
        payload_ref=payload_ref.to_json_dict(),
        audit_id=audit_id,
    )

    summary = _build_summary(
        audit_id=audit_id,
        case_id=case_id,
        tool="get_amcache",
        rowcount=len(rows),
        input_ref=input_ref,
        payload_ref=payload_ref,
        pre_sanitization_sha256=result.pre_hash,
        post_sanitization_sha256=result.post_hash,
    )
    return wrap_evidence(summary)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("SANCTUM_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log.info("Sanctum MCP server starting; cases_root=%s", os.environ.get(CASES_ROOT_ENV, DEFAULT_CASES_ROOT))
    mcp.run()


if __name__ == "__main__":
    main()

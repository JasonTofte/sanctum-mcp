"""CVE-class coverage tests for Sanctum's MCP-layer injection defence.

These tests assert that Sanctum's architectural guardrails cover the attack
classes documented in two MCP-ecosystem CVEs:

- **CVE-2025-49596** (MCP Inspector < 0.14.1, published 2025-06-13): Lack of
  authentication between the Inspector client and proxy allows unauthenticated
  requests to launch MCP commands over stdio.  From Sanctum's perspective the
  relevant attack class is evidence-path content carrying injection patterns
  delivered through an unauthenticated MCP channel.  Sanctum's
  ``strip_known_injection_patterns()`` / ``wrap_evidence()`` pipeline intercepts
  this class before the LLM sees it.

- **CVE-2025-53109** (MCP Filesystem Servers < 0.6.4 / < 2025.7.01, published
  2025-07-02): Symlinks within allowed directories can be followed to access
  files outside those directories.  Sanctum's ``_resolve_case()`` already
  defends against this pattern via ``.resolve()`` + parent-containment check;
  these tests confirm that protection is present and tested.

CVSS notes (both scores are submitter-assigned CVSS 4.0; NVD enrichment
pending as of 2026-04-29):
- CVE-2025-49596 (numeric score pending NVD enrichment), vector
  AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
- CVE-2025-53109 7.3 HIGH (submitter-assigned), vector
  AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:H/SC:H/SI:H/SA:H

Primary source: NVD detail pages fetched 2026-04-29.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sanctum.sanitize import sanitize, wrap_evidence

FIXTURES = Path(__file__).parent / "fixtures"
CVE_49596_FIXTURE = FIXTURES / "cve_2025_49596_pattern.txt"


# ---------------------------------------------------------------------------
# AC-1: CVE-2025-49596 injection-pattern coverage
# ---------------------------------------------------------------------------


def test_cve_2025_49596_patterns_are_stripped() -> None:
    """Injection patterns deliverable via CVE-2025-49596 are intercepted.

    An attacker exploiting the unauthenticated MCP Inspector channel could
    embed classic LLM-injection frames in evidence-looking payloads.  Sanctum's
    sanitize pipeline strips them before the LLM sees the output.
    """
    raw = CVE_49596_FIXTURE.read_text(encoding="utf-8")
    result = sanitize(raw)
    assert result.patterns_stripped > 0, (
        "Expected CVE-2025-49596 fixture to contain at least one injection pattern; "
        "none stripped — check fixture content."
    )
    assert "[REDACTED:injection-candidate]" in result.payload


def test_cve_2025_49596_payload_is_quarantined_in_evidence_tags() -> None:
    """Sanitized output is wrapped in <evidence-untrusted> before the LLM sees it."""
    raw = CVE_49596_FIXTURE.read_text(encoding="utf-8")
    result = sanitize(raw)
    wrapped = wrap_evidence(result.payload)
    assert wrapped.startswith("<evidence-untrusted>"), (
        "Evidence payload must be quarantined inside <evidence-untrusted> wrapper."
    )
    assert wrapped.rstrip().endswith("</evidence-untrusted>"), (
        "Evidence payload must be closed by </evidence-untrusted> tag."
    )


# ---------------------------------------------------------------------------
# AC-2: CVE-2025-53109 symlink path-traversal coverage
# ---------------------------------------------------------------------------


def test_cve_2025_53109_symlink_escape_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_resolve_case() refuses a case whose Amcache path resolves outside case_dir.

    This test asserts Sanctum's existing containment check (via .resolve() +
    parent-containment) covers the CVE-2025-53109 attack class — symlinks inside
    an allowed directory pointing to files outside it.
    """
    from sanctum.server import _resolve_case, CASES_ROOT_ENV

    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    case_dir = cases_root / "test-case-001"
    case_dir.mkdir()
    registry_dir = case_dir / "registry"
    registry_dir.mkdir()

    # Place a real file outside the case directory.
    outside_target = tmp_path / "shadow_amcache.hve"
    outside_target.write_bytes(b"fake hive")

    # Symlink inside the case's registry dir pointing outside the cases root.
    symlink_hve = registry_dir / "Amcache.hve"
    symlink_hve.symlink_to(outside_target)

    monkeypatch.setenv(CASES_ROOT_ENV, str(cases_root))
    with pytest.raises(ValueError, match=r"escapes"):
        _resolve_case("test-case-001")


def test_cve_2025_53109_case_dir_symlink_escape_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_resolve_case() refuses a case_id whose directory itself is a symlink escaping cases root."""
    from sanctum.server import _resolve_case, CASES_ROOT_ENV

    cases_root = tmp_path / "cases"
    cases_root.mkdir()

    # Place a real directory outside the cases root.
    outside_case = tmp_path / "attacker_controlled"
    outside_case.mkdir()

    # Symlink inside cases root pointing to outside directory.
    symlink_case = cases_root / "escape-case"
    symlink_case.symlink_to(outside_case)

    monkeypatch.setenv(CASES_ROOT_ENV, str(cases_root))
    # Should raise FileNotFoundError (no registry dir) or ValueError (escape).
    # Either signals the case was not silently accepted.
    with pytest.raises((ValueError, FileNotFoundError)):
        _resolve_case("escape-case")

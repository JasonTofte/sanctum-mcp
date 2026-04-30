"""Sygnia 2025-08 attack-coverage assertion tests.

The Sygnia August 2025 incident report documents a class of LLM-assisted DFIR
failures where adversarially crafted process names caused an LLM analyst to
mis-narrate a Mimikatz execution as legitimate.  The documented attack surface
is tool output containing specially crafted strings that reframe the LLM's
interpretation of the evidence.

Sanctum's defence operates on **two paths**:

1. **Success path** — every tool call passes evidence through
   ``sanctum.sanitize.sanitize()`` + ``wrap_evidence()``.  Injection-candidate
   patterns are replaced with ``[REDACTED:injection-candidate]`` before the LLM
   sees the payload.

2. **Error path** — FastMCP's ``isError`` channel serialises raised exception
   strings directly to the LLM, bypassing the success-path sanitizer.  Sanctum
   mitigates this via ``_safe_field()`` (``sanctum.parsers._fixture_io``), which
   applies the same delimiter-substitute inventory before attacker-influenced
   input lands in an exception message.

These tests use a named fixture (``tests/fixtures/sygnia_2025_08_pattern.txt``)
so the coverage is traceable to the specific incident and both paths are
exercised explicitly.

Reference: Sygnia blog post "LLMs in the Battlefield" (August 2025); the
Mimikatz mis-narration example is discussed in ``README.md`` §"Design";
the injection pattern is registered in ``src/sanctum/sanitize.py:_INJECTION_PATTERNS``.
"""

from __future__ import annotations

from pathlib import Path

from sanctum.sanitize import sanitize, wrap_evidence

FIXTURES = Path(__file__).parent / "fixtures"
SYGNIA_FIXTURE = FIXTURES / "sygnia_2025_08_pattern.txt"


# ---------------------------------------------------------------------------
# AC-4 (success path)
# ---------------------------------------------------------------------------


def test_sygnia_2025_08_pattern_stripped_by_sanitize() -> None:
    """Sygnia 2025-08 pattern is stripped on the success path."""
    raw = SYGNIA_FIXTURE.read_text(encoding="utf-8")
    result = sanitize(raw)
    assert result.patterns_stripped > 0, (
        "Expected Sygnia 2025-08 fixture to trigger at least one injection-pattern "
        "redaction; none fired — check fixture content matches _INJECTION_PATTERNS."
    )
    assert "[REDACTED:injection-candidate]" in result.payload


def test_sygnia_2025_08_wrapped_output_is_quarantined() -> None:
    """Sanitised Sygnia-pattern output is enclosed in <evidence-untrusted> tags."""
    raw = SYGNIA_FIXTURE.read_text(encoding="utf-8")
    result = sanitize(raw)
    wrapped = wrap_evidence(result.payload)
    assert "<evidence-untrusted>" in wrapped
    assert "</evidence-untrusted>" in wrapped
    # The injection candidate must NOT appear outside the untrusted envelope.
    assert "RED TEAM REALITY CHECK" not in wrapped


# ---------------------------------------------------------------------------
# AC-4 (error path)
# ---------------------------------------------------------------------------


def test_sygnia_2025_08_pattern_scrubbed_by_safe_field() -> None:
    """_safe_field() scrubs the Sygnia pattern on the error (isError) path.

    FastMCP's isError channel serialises raw exception strings to the LLM.
    Sanctum's _safe_field() applies the shared delimiter inventory so that
    attacker-influenced content landing in an exception message is scrubbed
    before it reaches the LLM — same protection, different path.
    """
    from sanctum.parsers._fixture_io import _safe_field

    # Pull the <tool>...</tool> injection line from the fixture — this line
    # contains angle-bracket delimiters that _safe_field() must substitute.
    raw = SYGNIA_FIXTURE.read_text(encoding="utf-8")
    angle_bracket_lines = [l for l in raw.splitlines() if "<" in l or ">" in l]
    assert angle_bracket_lines, (
        "Sygnia fixture must contain at least one line with '<' or '>' "
        "to exercise the _safe_field delimiter-substitution path."
    )
    dangerous_line = angle_bracket_lines[0]
    assert "<" in dangerous_line or ">" in dangerous_line  # guard against empty match

    scrubbed = _safe_field(dangerous_line)

    # The shared inventory substitutes < > \x00-\x1f and invisible codepoints.
    assert "<" not in scrubbed, "_safe_field must substitute '<' delimiter"
    assert ">" not in scrubbed, "_safe_field must substitute '>' delimiter"

    # The scrubbed output must not contain raw control characters.
    for ch in scrubbed:
        assert ord(ch) >= 0x20 or ch in ("\t", "\n", "\r"), (
            f"_safe_field output contains control character U+{ord(ch):04X}"
        )

"""Phase 5 — AC-3, AC-5, AC-7: absence tests for ARCH-002 invariants.

T-7   No promote path in finding.py (AST-based absence assert)          [P0]
T-11  _check_temporal_coherence body has no file I/O                    [P0]
T-13  THREAT_MODEL_TRIANGULATION.md contains SoK + T1070.006 citations  [P0]

ARCH-002 bright line: zero code paths in the temporal-coupling demoter
raise a finding's confidence tier based on temporal consistency. The demoter
ONLY demotes; it never promotes.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

FINDING_PY = Path("src/sanctum/finding.py")
THREAT_MODEL = Path("docs/THREAT_MODEL_TRIANGULATION.md")


# ─── T-7: No promote path in finding.py ──────────────────────────────────────


def test_no_temporal_promote_path_in_finding_py() -> None:
    """T-7 (P0): AST walk of finding.py finds no code that raises confidence on 'coherent'.

    ARCH-002 invariant: _check_temporal_coherence must only feed a demotion
    branch; the string 'coherent' must never appear as the condition under which
    confidence is raised or a higher tier is returned.

    Strategy: parse finding.py and assert that no If/Compare node uses the
    string literal 'coherent' to assign a higher-confidence tier (CORROBORATED,
    FINAL). This is a best-effort AST check, not a complete static analysis;
    the manual diff review at merge is the authoritative gate.
    """
    source = FINDING_PY.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Collect all string literals that appear in If conditions alongside
    # references to high-confidence tiers. A false positive here means we
    # added a promote path; a false negative means the check was gamed by
    # indirection. The goal is to catch accidental promote paths, not
    # adversarial bypass.
    promote_tier_names = {"CORROBORATED", "FINAL"}

    class PromotePathVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.violations: list[tuple[int, str]] = []

        def visit_If(self, node: ast.If) -> None:
            # Check if 'coherent' appears in the condition
            condition_src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
            if "coherent" in condition_src:
                # Check if the body assigns or returns a promote-direction tier
                body_src = ast.unparse(ast.Module(body=node.body, type_ignores=[]))
                if any(tier in body_src for tier in promote_tier_names):
                    self.violations.append(
                        (node.lineno, f"'coherent' condition leads to high-confidence tier at line {node.lineno}")
                    )
            self.generic_visit(node)

    visitor = PromotePathVisitor()
    visitor.visit(tree)

    assert not visitor.violations, (
        "ARCH-002 VIOLATION: promote path detected in finding.py:\n"
        + "\n".join(f"  line {ln}: {msg}" for ln, msg in visitor.violations)
    )


def test_temporal_check_function_has_no_file_io() -> None:
    """T-11 (P0): _check_temporal_coherence body contains no file I/O (AC-5).

    The demoter is required to be pure-function on ledger data; it must not
    re-read evidence files. This test inspects the source of the function
    and asserts absence of file-open primitives.
    """
    from sanctum.finding import _check_temporal_coherence

    source = inspect.getsource(_check_temporal_coherence)

    forbidden = ["open(", "Path(", "os.stat", "os.path", ".read(", ".read_text"]
    violations = [tok for tok in forbidden if tok in source]
    assert not violations, (
        f"_check_temporal_coherence must not perform file I/O (AC-5). "
        f"Found forbidden patterns: {violations}"
    )


# ─── T-13: Threat-model doc citations ────────────────────────────────────────


def test_threat_model_triangulation_cites_sok_and_t1070006() -> None:
    """T-13 (P0): THREAT_MODEL_TRIANGULATION.md cites the SoK paper and T1070.006."""
    content = THREAT_MODEL.read_text(encoding="utf-8")

    assert "2504.18131" in content, (
        "docs/THREAT_MODEL_TRIANGULATION.md must cite the SoK timeline reconstruction paper "
        "(arXiv:2504.18131, Breitinger, Studiawan & Hargreaves 2025)"
    )
    assert "T1070.006" in content, (
        "docs/THREAT_MODEL_TRIANGULATION.md must cite MITRE ATT&CK T1070.006 (Timestomp)"
    )

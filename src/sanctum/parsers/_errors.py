"""Parser-layer exception hierarchy.

Kept in a leaf module so parser modules and the package `__init__.py` can
both import from it without circularity. Each subclass is rooted in a
standard-library exception so generic `except FileNotFoundError` /
`except ValueError` clauses still match.

`PartialImplementationError` exists because the alternative — letting a
`NotImplementedError` escape — would make stack traces less informative and
would not encode the recovery hint that the MCP 2025-11-25 spec requires for
tool-execution errors. FastMCP serializes any `NotImplementedError` (and
subclasses) into a JSON-RPC error with `isError: true`; the human-readable
message must contain enough information to debug without re-deriving
context from logs.
"""

from __future__ import annotations


class ArtifactNotFoundError(FileNotFoundError):
    """Raised when an artifact path does not point at a real file."""


class ArtifactMalformedError(ValueError):
    """Raised when artifact bytes (or a sidecar) cannot be parsed."""


class ArtifactEmptyError(ValueError):
    """Reserved — parsers default to returning `[]`, not raising, when an
    artifact is well-formed but contains no execution rows. Provided so a
    future caller can opt into stricter behavior without breaking the
    standard contract."""


class PartialImplementationError(NotImplementedError):
    """Raised when a parser is called outside fixture mode before its real
    implementation lands. Carries tool name and recovery hint; FastMCP turns
    this into an MCP-spec-compliant `isError: true` response.

    The fail-loud design survives the family-count silent-corruption analysis
    (see /deep-r plan c50c213cf6f6 + `feedback_sidecar_path_lookup.md`):
    `audit.classify_confidence` inspects only integer family count, so a
    structured stub event would make `claim_finding` count phantom evidence.
    """

    def __init__(self, tool: str, *, reason: str = "real parser arrives in week 3") -> None:
        message = (
            f"{tool} is not yet implemented — {reason}. "
            f"To exercise this code path in tests, set "
            f"SANCTUM_USE_FIXTURE_SIDECAR=1 and provide a "
            f"<artifact>.sanctum-fixture.json sidecar."
        )
        super().__init__(message)
        self.tool = tool

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

`PartialParseError` makes mid-stream truncation an *observable* event
rather than a silent return-shorter-list. AC-4 requires that already-
yielded events survive a partial failure — it does not require, but
this layer chooses, that callers can distinguish "clean EOF with N
events" from "stopped at row N because the next row was malformed".
The latter is forensic evidence in its own right (selective truncation
of one family's rows is a documented anti-forensic technique); a typed
exception carrying the partial events forces the caller to make an
explicit choice rather than letting tampering masquerade as a short
artifact.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sanctum.events import ExecutionEvent


class ArtifactNotFoundError(FileNotFoundError):
    """Raised when an artifact path does not point at a real file."""


class ArtifactMalformedError(ValueError):
    """Raised when artifact bytes (or a sidecar) cannot be parsed."""


class PartialParseError(ArtifactMalformedError):
    """Raised when row-level corruption truncates iteration mid-stream.

    Carries the events that were successfully parsed before the failure
    so callers can opt into recovery (``except PartialParseError as e:
    use(e.events)``) or treat it as a fatal error like any other
    :class:`ArtifactMalformedError` (existing ``except`` clauses still
    catch it via the subclass relationship — no migration cost).

    The ``cause`` attribute holds the underlying exception (typically a
    library-specific error like ``regipy.exceptions.RegistryParsingException``
    or ``Evtx`` decoder failure). It is also chained via
    ``raise PartialParseError(...) from cause`` so ``__cause__`` is set
    for tracebacks; the explicit attribute is kept so audit-ledger code
    can record ``type(e.cause).__name__`` without traceback parsing.

    NOTE on safety: the message string passed to ``__init__`` flows
    through FastMCP's error-channel serializer and is therefore visible
    to the LLM. Callers must scrub attacker-controlled fields with
    :func:`sanctum.parsers._fixture_io._safe_field` before constructing
    the message — same rule as the rest of this hierarchy. The
    ``events`` and ``cause`` attributes are NOT serialized into the
    message and stay on the Python object, so they can carry untrusted
    bytes without bypassing the quarantine.
    """

    def __init__(
        self,
        message: str,
        *,
        events: list[ExecutionEvent],
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.events = events
        self.cause = cause


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

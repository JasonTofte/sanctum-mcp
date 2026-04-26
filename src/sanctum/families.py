"""Tool → artifact-family resolution policy.

The five artifact families enumerated in ``CLAUDE.md`` invariant 5:

- ``AppCompat`` — ShimCache, Amcache (shared trust root: Application
  Experience Service / CSRSS).
- ``Explorer/NTUSER`` — UserAssist (per-user NTUSER.dat hive).
- ``Background-service`` — BAM (``bam.sys`` kernel driver + SYSTEM hive).
- ``Kernel-ETW`` — Sysmon, Windows EventID 4688 (kernel ETW providers).
- ``SysMain`` — Prefetch (``SysMain`` service).

The mapping is project policy — *which tool counts toward which family*.
Encoding it as a module-level dict (rather than a ``LedgerEntry`` schema
field) keeps the ledger format stable and the policy greppable; adding a
new tool is one dict line plus one regression test.

Adding a new family requires updating ``docs/THREAT_MODEL_TRIANGULATION.md``
quantitative analysis, since the gate's ``≥2`` threshold was derived
against exactly these five families and their per-family compromise
priors. Do not add a sixth family without that update — see
``feedback_security_posture.md`` (Jason's policy: pick the strongest
option that fits scope).
"""

from __future__ import annotations

from typing import Final

# The canonical five families. Strings are stable — they land in the
# audit ledger. Renaming is a backwards-incompatible ledger-format change.
FAMILY_APPCOMPAT: Final = "AppCompat"
FAMILY_EXPLORER_NTUSER: Final = "Explorer/NTUSER"
FAMILY_BACKGROUND_SERVICE: Final = "Background-service"
FAMILY_KERNEL_ETW: Final = "Kernel-ETW"
FAMILY_SYSMAIN: Final = "SysMain"

ALL_FAMILIES: Final = frozenset(
    {
        FAMILY_APPCOMPAT,
        FAMILY_EXPLORER_NTUSER,
        FAMILY_BACKGROUND_SERVICE,
        FAMILY_KERNEL_ETW,
        FAMILY_SYSMAIN,
    }
)


# Tool name → family. Tools whose role is *querying* but not contributing
# evidence (e.g., ``claim_finding`` itself) are intentionally absent and
# raise ``UnknownToolError`` if asked — surfaces the design gap rather
# than silently routing to a default family.
TOOL_TO_FAMILY: Final[dict[str, str]] = {
    # AppCompat family
    "get_amcache": FAMILY_APPCOMPAT,
    "get_shimcache": FAMILY_APPCOMPAT,
    "get_mft_timeline": FAMILY_APPCOMPAT,  # MFT lives near AppCompat trust root
    "get_usnjrnl": FAMILY_APPCOMPAT,
    # Explorer / NTUSER family
    "get_userassist": FAMILY_EXPLORER_NTUSER,
    # Background-service family
    "get_bam": FAMILY_BACKGROUND_SERVICE,
    # Kernel ETW family
    "get_sysmon_4688": FAMILY_KERNEL_ETW,
    # SysMain family
    "get_prefetch": FAMILY_SYSMAIN,
}


class UnknownToolError(KeyError):
    """Raised when a ledger-recorded tool has no family mapping.

    A ``KeyError`` subclass so callers using ``dict[]`` semantics can
    catch either, while ``isinstance(exc, UnknownToolError)`` reads
    cleanly in policy code.
    """


def resolve_family(tool: str) -> str:
    """Return the family for ``tool`` or raise :class:`UnknownToolError`.

    Refusing to silently route to a default is a deliberate failure-domain
    choice — a forgotten dict update is an audit gap, and silent
    defaulting would let a new tool's audit_ids vote into a wrong family
    (or a sentinel "unknown" family) and corrupt the gate.
    """
    try:
        return TOOL_TO_FAMILY[tool]
    except KeyError as exc:
        raise UnknownToolError(
            f"tool {tool!r} has no family mapping; add to " f"sanctum.families.TOOL_TO_FAMILY"
        ) from exc

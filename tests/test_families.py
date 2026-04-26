"""Tests for :mod:`sanctum.families` — tool→family policy table."""

from __future__ import annotations

import pytest

from sanctum import families


def test_all_get_tools_resolve_to_a_canonical_family() -> None:
    """Every key in TOOL_TO_FAMILY must resolve into ALL_FAMILIES.

    Catches typos in the dict literal — a stray family string would
    silently route audit_ids to a non-canonical bucket and break the
    gate.
    """
    for tool, family in families.TOOL_TO_FAMILY.items():
        assert (
            family in families.ALL_FAMILIES
        ), f"tool {tool!r} maps to non-canonical family {family!r}"


def test_resolve_family_known_tool() -> None:
    assert families.resolve_family("get_amcache") == families.FAMILY_APPCOMPAT
    assert families.resolve_family("get_userassist") == families.FAMILY_EXPLORER_NTUSER
    assert families.resolve_family("get_bam") == families.FAMILY_BACKGROUND_SERVICE
    assert families.resolve_family("get_sysmon_4688") == families.FAMILY_KERNEL_ETW
    assert families.resolve_family("get_prefetch") == families.FAMILY_SYSMAIN


def test_resolve_family_unknown_tool_raises() -> None:
    with pytest.raises(families.UnknownToolError):
        families.resolve_family("get_does_not_exist")


def test_unknown_tool_error_is_keyerror_subclass() -> None:
    """KeyError-compat lets dict-style callers catch with a single except."""
    assert issubclass(families.UnknownToolError, KeyError)


def test_appcompat_family_collapses_shimcache_and_amcache() -> None:
    """CLAUDE.md invariant 5 — ShimCache and Amcache share AppCompat trust root."""
    assert families.resolve_family("get_amcache") == families.resolve_family("get_shimcache")


def test_mft_tools_route_to_appcompat() -> None:
    """get_mft_timeline / get_usnjrnl tagged AppCompat per
    docs/THREAT_MODEL_DECEPTION.md — MFT lives near the AppCompat trust
    root for our scoring purposes. Pin so a future contributor renaming
    these has to consciously update the threat-model doc as well."""
    assert families.resolve_family("get_mft_timeline") == families.FAMILY_APPCOMPAT
    assert families.resolve_family("get_usnjrnl") == families.FAMILY_APPCOMPAT


def test_all_families_constant_has_exactly_five_members() -> None:
    """Adding a 6th family requires updating
    docs/THREAT_MODEL_TRIANGULATION.md quantitative analysis. Pin the
    cardinality so the change cannot land silently."""
    assert len(families.ALL_FAMILIES) == 5

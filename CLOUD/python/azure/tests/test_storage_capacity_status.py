"""Tests for storage capacity provenance in the HTML report.

A blank capacity total can mean three different things — Monitor access denied,
capacity opt-out, or a genuinely empty environment. The report must render them
distinctly so a permission gap is never mistaken for "no data". See
collectors/storage.py (capacity_requested / capacity_available) and
output/writer.py (_section_storage).
"""

from __future__ import annotations

import pytest

writer = pytest.importorskip(
    "output.writer", reason="output package (SE-side report code) is not in this repo"
)
_section_storage = writer._section_storage


def _data(status: str, *, cap_gb=None, accounts: int = 3) -> dict:
    return {
        "storage_total_accounts": accounts,
        "storage_total_gb": cap_gb,
        "storage_soft_delete_pct": 50.0,
        "storage_versioning_pct": 40.0,
        "storage_redundancy": {"LRS": accounts},
        "storage_kind": {"StorageV2": accounts},
        "storage_capacity_status": status,
    }


def test_available_shows_tb():
    html = _section_storage(_data("available", cap_gb=2048.0))
    assert "2.0 TB" in html
    assert "Unavailable" not in html


def test_unavailable_renders_monitor_callout():
    html = _section_storage(_data("unavailable"))
    # The capacity stat reads "Unavailable", not a blank or a misleading 0.
    assert "Unavailable" in html
    # And a callout explains it is a permission gap, not an empty environment.
    assert "Monitoring Reader" in html
    assert "not</em> an empty environment" in html or "not an empty environment" in html


def test_not_requested_renders_optout_note():
    html = _section_storage(_data("not_requested"))
    assert "Not collected" in html
    assert "--no-capacity" in html
    # opt-out is not an error — no Monitor-permission callout
    assert "Monitoring Reader" not in html


def test_no_accounts_short_circuits():
    html = _section_storage(_data("no_accounts", accounts=0))
    assert "No storage accounts collected" in html

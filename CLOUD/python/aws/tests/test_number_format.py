"""Numbers in the CSV files are written the way PowerShell writes them.

The expected values were taken from real PowerShell: ``ConvertTo-SizeUnits`` from
Get-AWSSizingInfo.ps1 and ``ConvertTo-Csv``, run in pwsh on the same inputs.
"""

from __future__ import annotations

import pytest

from csv_export import (
    _format,
    _format_float,
    _money,
    _ps_round,
    _units_from_bytes,
    _units_from_gib,
)


@pytest.mark.parametrize(
    "value,digits,expected",
    [
        (12.345, 2, 12.34),
        (2.675, 2, 2.68),
        (2.665, 2, 2.66),
        (0.125, 2, 0.12),
        (0.135, 2, 0.14),
        (-3.14159, 2, -3.14),
        (2.5, 0, 2.0),
        (3.5, 0, 4.0),
        (1e16, 2, 1e16),
        (0.0, 3, 0.0),
    ],
)
def test_ps_round_matches_dotnet(value, digits, expected):
    assert _ps_round(value, digits) == expected


def test_python_round_would_have_differed():
    assert round(12.345, 2) == 12.35 and _ps_round(12.345, 2) == 12.34


@pytest.mark.parametrize(
    "value,text",
    [
        (100.0, "100"),
        (0.1, "0.1"),
        (1234.5, "1234.5"),
        (999999999999999.0, "999999999999999"),
        (1e15, "1000000000000000"),
        (1000000000000007.0, "1000000000000007"),
        (1234567890123456.8, "1234567890123456.8"),
        (3846100266235522.5, "3846100266235522.5"),
        (1.5e16, "15000000000000000"),
        (9.999999999999998e16, "99999999999999980"),
        (1e17, "1E+17"),
        (1.2345678901234568e17, "1.2345678901234568E+17"),
        (1e20, "1E+20"),
        (0.000123, "0.000123"),
        (1e-05, "1E-05"),
        (1.5e-07, "1.5E-07"),
        (-2.5, "-2.5"),
    ],
)
def test_double_text_matches_dotnet(value, text):
    assert _format_float(value) == text
    assert _format(value) == text


@pytest.mark.parametrize(
    "value,bytes_cells,gib_cells",
    [
        (
            3846100266235522.0,
            ["3581960.0022", "3498.0078", "3846100.2662", "3846.1003"],
            [
                "3846100266235522.5",
                "3755957291245.6274",
                "4129718715154615.5",
                "4129718715154.6143",
            ],
        ),
        (
            7562288063945419.0,
            ["7042929.5897", "6877.8609", "7562288.0639", "7562.2881"],
            ["7562288063945418", "7385046937446.697", "8119944979394183", "8119944979394.183"],
        ),
    ],
)
def test_petabyte_sizes_are_positional_like_powershell(value, bytes_cells, gib_cells):
    assert [_format(v) for v in _units_from_bytes(value).values()] == bytes_cells
    assert [_format(v) for v in _units_from_gib(value).values()] == gib_cells


def test_size_conversion_rounds_a_tie_like_dotnet():
    # 0.5 GiB is 0.00048828125 TiB; the fifth decimal is a 5 and .NET and Python round it apart.
    assert _units_from_gib(0.5)["SizeTiB"] == _ps_round(0.5 / 1024, 4)
    assert _ps_round(0.5 / 1024, 4) == 0.0005


def test_money_rounding_follows_dotnet():
    assert _money(12.345) == "$12.34"
    assert _money(2.675) == "$2.68"
    assert _money(0.125) == "$0.12"

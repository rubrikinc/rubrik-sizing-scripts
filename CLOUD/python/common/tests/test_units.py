import pytest
from common.units import gcp_decimal_units, size_units


def test_bytes_input():
    r = size_units(107374182400, "Size")
    assert r == {"SizeGiB": 100.0, "SizeTiB": 0.0977, "SizeGB": 107.3742, "SizeTB": 0.1074}


def test_gib_input():
    r = size_units(100, "Size", input_unit="gib")
    assert r == {"SizeGiB": 100, "SizeTiB": 0.0977, "SizeGB": 107.3742, "SizeTB": 0.1074}


def test_precision_overrides():
    r = size_units(107374182400, gib_precision=0, gb_precision=3)
    assert r["GiB"] == 100 and r["GB"] == 107.374


def test_bad_unit():
    with pytest.raises(ValueError):
        size_units(1, input_unit="mb")


def test_gcp_decimal():
    assert gcp_decimal_units(500) == {"GB": 500, "TB": 0.5}

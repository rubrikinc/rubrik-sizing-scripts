import pytest
from common.csv_writer import csv_file_name, format_value, write_csv


def test_all_fields_quoted_fixed_order(tmp_path):
    p = tmp_path / "a.csv"
    n = write_csv(p, ["B", "A"], [{"A": 1, "B": "x"}, {"A": 2.5, "B": None}])
    assert n == 2
    assert p.read_text() == '"B","A"\n"x","1"\n"","2.5"\n'


def test_header_only_when_empty(tmp_path):
    p = tmp_path / "e.csv"
    assert write_csv(p, ["A", "B"], []) == 0
    assert p.read_text() == '"A","B"\n'


def test_unknown_column_rejected(tmp_path):
    with pytest.raises(ValueError):
        write_csv(tmp_path / "x.csv", ["A"], [{"A": 1, "Z": 2}])


def test_embedded_quote_and_comma(tmp_path):
    p = tmp_path / "q.csv"
    write_csv(p, ["A"], [{"A": 'a,"b"'}])
    assert p.read_text() == '"A"\n"a,""b"""\n'


def test_format_value():
    assert format_value(True) == "True"
    assert format_value(5.0) == "5"
    assert format_value(0.1) == "0.1"
    assert format_value(None) == ""
    assert format_value(1e-05) == "1E-05"
    assert format_value(1e22) == "1E+22"
    assert format_value(2e15) == "2E+15"
    assert format_value(1.5e-7) == "1.5E-07"
    assert format_value(123456789.0) == "123456789"


def test_file_name():
    assert (
        csv_file_name("ec2-instance info", "20250101-1200") == "ec2_instance_info-20250101-1200.csv"
    )

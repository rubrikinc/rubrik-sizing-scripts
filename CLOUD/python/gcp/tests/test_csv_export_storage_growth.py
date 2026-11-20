"""gce_storage_info: the growth columns, and when they are blank instead of a number."""

from __future__ import annotations

import csv_export
from tests.test_csv_export_storage import _bucket, _measured, _result, _rows

COLUMNS = (
    "GrowthStatus",
    "GrowthDays",
    "GrowthStartBytes",
    "GrowthEndBytes",
    "GrowthBytes",
    "GrowthPercent",
    "AnnualGrowthPercent",
)


def _grown(start, end, days, **kw):
    return _measured(
        "b1",
        end,
        growth_start_bytes=start,
        growth_end_bytes=end,
        growth_days=days,
        growth_status="measured",
        **kw,
    )


def test_the_growth_columns_come_right_after_the_size_status():
    columns = csv_export._STORAGE_COLUMNS
    at = columns.index("SizeStatus")
    assert tuple(columns[at + 1 : at + 1 + len(COLUMNS)]) == COLUMNS


def test_a_measured_bucket_has_its_change_and_both_percentages():
    (row,), _ = _rows(_result([_grown(1000, 1100, 30.0)]))
    assert row["GrowthStatus"] == "measured" and row["GrowthDays"] == "30"
    assert (row["GrowthStartBytes"], row["GrowthEndBytes"], row["GrowthBytes"]) == (
        "1000",
        "1100",
        "100",
    )
    assert row["GrowthPercent"] == "10"
    # 10% over 30 days, in a straight line over 365 days.
    assert row["AnnualGrowthPercent"] == "121.67"


def test_a_shrinking_bucket_has_negative_figures():
    (row,), _ = _rows(_result([_grown(1000, 400, 30.0)]))
    assert row["GrowthBytes"] == "-600" and row["GrowthPercent"] == "-60"


def test_the_annual_rate_is_blank_when_the_window_is_too_short_to_scale():
    (row,), _ = _rows(_result([_grown(1000, 1100, 5.0)]))
    assert row["GrowthPercent"] == "10" and row["GrowthBytes"] == "100"
    assert row["AnnualGrowthPercent"] == ""


def test_the_annual_rate_is_filled_from_the_shortest_allowed_window():
    (row,), _ = _rows(_result([_grown(1000, 1100, float(csv_export._MIN_DAYS_FOR_ANNUAL_RATE))]))
    assert row["AnnualGrowthPercent"] != ""


def test_a_bucket_that_started_empty_has_no_percentage_but_has_its_bytes():
    (row,), _ = _rows(_result([_grown(0, 500, 30.0)]))
    assert row["GrowthBytes"] == "500"
    assert row["GrowthPercent"] == "" and row["AnnualGrowthPercent"] == ""


def test_a_bucket_that_did_not_change_is_zero_growth_not_blank():
    (row,), _ = _rows(_result([_grown(1000, 1000, 30.0)]))
    assert row["GrowthBytes"] == "0" and row["GrowthPercent"] == "0"


def test_growth_that_was_not_requested_is_blank_in_every_cell():
    (row,), _ = _rows(_result([_measured("b1", 100)]))
    assert row["GrowthStatus"] == "not requested"
    for column in COLUMNS[1:]:
        assert row[column] == "", column


def test_too_few_readings_and_a_failed_read_are_blank_and_say_which():
    for status in ("too few readings", "not read"):
        (row,), _ = _rows(_result([_bucket("b1", growth_status=status)]))
        assert row["GrowthStatus"] == status
        assert all(row[c] == "" for c in COLUMNS[1:]), status


def test_a_stale_growth_figure_is_not_written_unless_the_status_says_measured():
    bucket = _grown(1000, 1100, 30.0)
    bucket["growth_status"] = "not read"
    (row,), _ = _rows(_result([bucket]))
    assert row["GrowthBytes"] == "" and row["GrowthPercent"] == ""

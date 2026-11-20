"""gce_storage_info: the lifecycle and requester-pays columns."""

from __future__ import annotations

import csv_export
from tests.test_csv_export_storage import _bucket, _result, _rows

LIFECYCLE = (
    "RequesterPays",
    "LifecycleRuleCount",
    "LifecycleDeleteDays",
    "LifecycleNoncurrentDeleteDays",
    "LifecycleTransitions",
)


def test_the_lifecycle_columns_follow_the_access_settings_and_come_before_the_sizes():
    columns = csv_export._STORAGE_COLUMNS
    at = columns.index("PublicAccessPrevention")
    assert tuple(columns[at + 1 : at + 1 + len(LIFECYCLE)]) == LIFECYCLE
    assert columns.index("LifecycleTransitions") < columns.index("SizeBytes")


def test_lifecycle_is_written_as_the_collector_found_it():
    bucket = _bucket(
        "b1",
        requester_pays=False,
        lifecycle_rule_count=2,
        lifecycle_delete_days=365,
        lifecycle_noncurrent_delete_days=30,
        lifecycle_transitions="NEARLINE@30d; ARCHIVE@180d",
    )
    (row,), _ = _rows(_result([bucket]))
    assert row["RequesterPays"] == "False" and row["LifecycleRuleCount"] == "2"
    assert (row["LifecycleDeleteDays"], row["LifecycleNoncurrentDeleteDays"]) == ("365", "30")
    assert row["LifecycleTransitions"] == "NEARLINE@30d; ARCHIVE@180d"


def test_a_bucket_with_no_rules_has_a_zero_count_and_blank_days():
    (row,), _ = _rows(_result([_bucket("b1", lifecycle_rule_count=0)]))
    assert row["LifecycleRuleCount"] == "0"
    assert row["LifecycleDeleteDays"] == "" and row["LifecycleTransitions"] == ""


def test_settings_the_listing_did_not_give_are_blank_not_zero_or_false():
    (row,), _ = _rows(_result([_bucket("b1")]))
    for column in LIFECYCLE:
        assert row[column] == "", column

"""Live and non-current bytes kept apart for each storage class.

``SizeBytes_<CLASS>`` is live plus non-current. These columns split it, so a reader can tell the
current data in a tier from the older versions Object Versioning keeps there.
"""

from __future__ import annotations

import csv_export
from models.discovery_dataclasses import STORAGE_CLASSES
from tests.test_collectors_storage import _make_bucket
from tests.test_collectors_storage_sizes import _collect, _monitoring, _series
from tests.test_csv_export_storage import _bucket, _result, _rows

LIVE, NONCURRENT = "live-object", "noncurrent-object"


def _one_bucket(*series):
    _, inventory = _collect([_make_bucket("b1")], _monitoring(bytes_series=list(series))[0])
    return inventory.buckets[0]


# ── collector ─────────────────────────────────────────────────────────────────


def test_each_class_keeps_its_live_and_noncurrent_bytes_apart():
    bucket = _one_bucket(
        _series("b1", 1000, "STANDARD", LIVE),
        _series("b1", 300, "STANDARD", NONCURRENT),
        _series("b1", 5000, "ARCHIVE", LIVE),
        _series("b1", 700, "ARCHIVE", NONCURRENT),
    )
    assert bucket.live_class_bytes["STANDARD"] == 1000
    assert bucket.noncurrent_class_bytes["STANDARD"] == 300
    assert bucket.live_class_bytes["ARCHIVE"] == 5000
    assert bucket.noncurrent_class_bytes["ARCHIVE"] == 700


def test_every_class_pair_adds_up_to_the_combined_class_size():
    bucket = _one_bucket(
        _series("b1", 10, "STANDARD", LIVE),
        _series("b1", 20, "NEARLINE", NONCURRENT),
        _series("b1", 30, "COLDLINE", LIVE),
        _series("b1", 40, "COLDLINE", NONCURRENT),
        _series("b1", 50, "SOME_LEGACY_CLASS", LIVE),
    )
    for name in STORAGE_CLASSES:
        both = bucket.live_class_bytes[name] + bucket.noncurrent_class_bytes[name]
        assert both == bucket.class_bytes[name], name
    assert sum(bucket.live_class_bytes.values()) == bucket.live_bytes
    assert sum(bucket.noncurrent_class_bytes.values()) == bucket.noncurrent_bytes


def test_a_bucket_without_versioning_has_zero_noncurrent_in_every_class():
    bucket = _one_bucket(_series("b1", 1000, "STANDARD", LIVE))
    assert set(bucket.noncurrent_class_bytes) == set(STORAGE_CLASSES)
    assert all(v == 0 for v in bucket.noncurrent_class_bytes.values())


def test_regional_data_is_counted_in_standard_for_both_halves():
    bucket = _one_bucket(
        _series("b1", 400, "REGIONAL", LIVE), _series("b1", 60, "REGIONAL", NONCURRENT)
    )
    assert bucket.live_class_bytes["STANDARD"] == 400
    assert bucket.noncurrent_class_bytes["STANDARD"] == 60
    assert bucket.live_class_bytes["OTHER"] == 0


def test_soft_deleted_and_multipart_bytes_are_in_neither_half():
    bucket = _one_bucket(
        _series("b1", 100, "STANDARD", LIVE),
        _series("b1", 999, "STANDARD", "soft-deleted-object"),
        _series("b1", 888, "STANDARD", "multipart-upload"),
    )
    assert bucket.live_class_bytes["STANDARD"] == 100
    assert bucket.noncurrent_class_bytes["STANDARD"] == 0


def test_a_bucket_with_no_reading_has_no_split():
    _, inventory = _collect([_make_bucket("b1")], _monitoring()[0])
    bucket = inventory.buckets[0]
    assert bucket.live_class_bytes == {} and bucket.noncurrent_class_bytes == {}


# ── csv ───────────────────────────────────────────────────────────────────────


def test_the_live_and_noncurrent_columns_follow_the_combined_class_columns():
    columns = csv_export._STORAGE_COLUMNS
    last_combined = columns.index(f"SizeBytes_{STORAGE_CLASSES[-1]}")
    wanted = [f"LiveBytes_{c}" for c in STORAGE_CLASSES] + [
        f"NoncurrentBytes_{c}" for c in STORAGE_CLASSES
    ]
    assert columns[last_combined + 1 : last_combined + 1 + len(wanted)] == wanted


def test_the_split_is_written_per_class_and_adds_up_in_the_file():
    zero = dict.fromkeys(STORAGE_CLASSES, 0)
    bucket = _bucket(
        "b1",
        size_status="measured",
        class_bytes={**zero, "STANDARD": 1300, "ARCHIVE": 5700},
        live_class_bytes={**zero, "STANDARD": 1000, "ARCHIVE": 5000},
        noncurrent_class_bytes={**zero, "STANDARD": 300, "ARCHIVE": 700},
    )
    (row,), _ = _rows(_result([bucket]))
    assert (row["LiveBytes_STANDARD"], row["NoncurrentBytes_STANDARD"]) == ("1000", "300")
    assert (row["LiveBytes_ARCHIVE"], row["NoncurrentBytes_ARCHIVE"]) == ("5000", "700")
    assert row["LiveBytes_NEARLINE"] == "0" and row["NoncurrentBytes_NEARLINE"] == "0"
    for name in STORAGE_CLASSES:
        both = int(row[f"LiveBytes_{name}"]) + int(row[f"NoncurrentBytes_{name}"])
        assert both == int(row[f"SizeBytes_{name}"]), name


def test_the_columns_are_blank_when_the_bucket_has_no_reading():
    (row,), _ = _rows(_result([_bucket("b1")]))
    for name in STORAGE_CLASSES:
        assert row[f"LiveBytes_{name}"] == "" and row[f"NoncurrentBytes_{name}"] == "", name

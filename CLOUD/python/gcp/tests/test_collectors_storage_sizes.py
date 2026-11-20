"""Bucket sizes from Cloud Monitoring: what is summed, what is blank, what is recorded as failed.

Monitoring is mocked at the client boundary. A series is built with the real protobuf types so the
labels and points are read the way a live response would be read.
"""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest
from google.cloud import monitoring_v3

from collectors.storage import BYTES_METRIC, OBJECT_COUNT_METRIC, StorageCollector
from models.discovery_dataclasses import SIZE_MEASURED, SIZE_NO_DATAPOINT, SIZE_NOT_READ
from tests.conftest import PROJECT_ID
from tests.test_collectors_storage import _make_bucket

_STORAGE_CLIENT = "google.cloud.storage.Client"
_MONITORING_CLIENT = "google.cloud.monitoring_v3.MetricServiceClient"
_T0 = datetime.datetime(2026, 11, 3, tzinfo=datetime.timezone.utc)


def _series(bucket, value, storage_class="STANDARD", kind=None, seconds=0, count=False):
    """One Monitoring time series for a bucket (a double for bytes, an integer for a count)."""
    labels = {"storage_class": storage_class}
    if kind:
        labels["type"] = kind
    point_value = {"int64_value": value} if count else {"double_value": float(value)}
    return monitoring_v3.TimeSeries(
        {
            "metric": {"type": BYTES_METRIC, "labels": labels},
            "resource": {"type": "gcs_bucket", "labels": {"bucket_name": bucket}},
            "points": [
                {
                    "interval": {"end_time": _T0 + datetime.timedelta(seconds=seconds)},
                    "value": point_value,
                }
            ],
        }
    )


def _monitoring(bytes_series=(), count_series=(), error=None):
    """A MetricServiceClient whose list_time_series answers by metric, recording each request."""
    client = MagicMock()
    requests = []

    def list_time_series(request):
        requests.append(request)
        if error is not None:
            raise error
        wanted = OBJECT_COUNT_METRIC if OBJECT_COUNT_METRIC in request.filter else BYTES_METRIC
        return iter(count_series if wanted == OBJECT_COUNT_METRIC else bytes_series)

    client.list_time_series.side_effect = list_time_series
    return client, requests


def _collect(buckets, monitoring_client):
    storage = MagicMock()
    storage.list_buckets.return_value = iter(buckets)
    with patch(_STORAGE_CLIENT, return_value=storage), patch(
        _MONITORING_CLIENT, return_value=monitoring_client
    ):
        collector = StorageCollector(PROJECT_ID, MagicMock())
        return collector, collector.collect()


def test_a_bucket_is_live_plus_noncurrent_and_the_rest_is_kept_apart():
    client, _ = _monitoring(
        bytes_series=[
            _series("b1", 1000, kind="live-object"),
            _series("b1", 200, kind="noncurrent-object"),
            _series("b1", 50, kind="soft-deleted-object"),
            _series("b1", 7, kind="multipart-upload"),
        ]
    )
    _, inventory = _collect([_make_bucket("b1")], client)
    (bucket,) = inventory.buckets
    assert (bucket.live_bytes, bucket.noncurrent_bytes) == (1000, 200)
    assert (bucket.soft_deleted_bytes, bucket.multipart_bytes) == (50, 7)
    # What a backup would copy: soft-deleted objects and unfinished uploads are not in it.
    assert bucket.size_bytes == 1200
    assert bucket.size_status == SIZE_MEASURED


def test_storage_classes_of_one_bucket_are_added_together():
    client, _ = _monitoring(
        bytes_series=[
            _series("b1", 100, "STANDARD", "live-object"),
            _series("b1", 300, "NEARLINE", "live-object"),
            _series("b1", 600, "ARCHIVE", "live-object"),
        ]
    )
    _, inventory = _collect([_make_bucket("b1")], client)
    assert inventory.buckets[0].live_bytes == 1000 and inventory.buckets[0].size_bytes == 1000


def test_a_type_with_no_series_is_zero_not_blank_when_the_bucket_has_a_reading():
    client, _ = _monitoring(bytes_series=[_series("b1", 500, kind="live-object")])
    _, inventory = _collect([_make_bucket("b1")], client)
    bucket = inventory.buckets[0]
    assert bucket.noncurrent_bytes == 0 and bucket.soft_deleted_bytes == 0


def test_a_bucket_with_no_datapoint_is_blank_and_marked_so_not_zero():
    # Monitoring leaves empty buckets out: an absent answer must not read as "0 bytes".
    client, _ = _monitoring(bytes_series=[_series("full", 900, kind="live-object")])
    _, inventory = _collect([_make_bucket("full"), _make_bucket("empty")], client)
    full, empty = inventory.buckets
    assert full.size_bytes == 900
    assert empty.size_bytes is None and empty.size_gb is None and empty.size_tb is None
    assert empty.live_bytes is None and empty.object_count is None
    assert empty.size_status == SIZE_NO_DATAPOINT


def test_a_bucket_that_is_in_the_scope_but_not_in_this_project_is_ignored():
    # A metrics scope can hold other projects' buckets; only the buckets listed here are filled.
    client, _ = _monitoring(
        bytes_series=[
            _series("mine", 100, kind="live-object"),
            _series("someone-elses", 10**15, kind="live-object"),
        ]
    )
    _, inventory = _collect([_make_bucket("mine")], client)
    assert [b.name for b in inventory.buckets] == ["mine"]
    assert inventory.total_size_bytes == 100


def test_the_newest_point_of_a_series_wins():
    older = _series("b1", 100, kind="live-object", seconds=0)
    newer = _series("b1", 999, kind="live-object", seconds=86400)
    for ordering in ([older, newer], [newer, older]):
        client, _ = _monitoring(bytes_series=ordering)
        _, inventory = _collect([_make_bucket("b1")], client)
        assert inventory.buckets[0].size_bytes == 999


def test_a_series_with_several_points_uses_the_newest_of_them():
    series = _series("b1", 100, kind="live-object", seconds=0)
    series.points.append(
        monitoring_v3.Point(
            {
                "interval": {"end_time": _T0 + datetime.timedelta(days=1)},
                "value": {"double_value": 700.0},
            }
        )
    )
    client, _ = _monitoring(bytes_series=[series])
    _, inventory = _collect([_make_bucket("b1")], client)
    assert inventory.buckets[0].size_bytes == 700


def test_the_object_count_is_read_and_summed_over_storage_classes():
    client, _ = _monitoring(
        bytes_series=[_series("b1", 10, kind="live-object")],
        count_series=[
            _series("b1", 40, "STANDARD", count=True),
            _series("b1", 2, "NEARLINE", count=True),
        ],
    )
    _, inventory = _collect([_make_bucket("b1")], client)
    assert inventory.buckets[0].object_count == 42


def test_the_project_costs_two_requests_however_many_buckets_it_has():
    buckets = [_make_bucket(f"bucket-{i}") for i in range(300)]
    client, requests = _monitoring(
        bytes_series=[_series(f"bucket-{i}", 1, kind="live-object") for i in range(300)]
    )
    _collect(buckets, client)
    assert len(requests) == 2
    assert {BYTES_METRIC in r.filter for r in requests} == {True, False}


def test_each_request_is_for_this_project_and_asks_for_one_aligned_point_per_series():
    client, requests = _monitoring(bytes_series=[_series("b1", 1, kind="live-object")])
    _collect([_make_bucket("b1")], client)
    for request in requests:
        assert request.name == f"projects/{PROJECT_ID}"
        assert 'resource.type="gcs_bucket"' in request.filter
        assert request.aggregation.alignment_period == datetime.timedelta(days=1)
        assert request.aggregation.per_series_aligner.name == "ALIGN_NEXT_OLDER"
        # The window must reach back past one day: a day's reading is not visible for a while.
        assert request.interval.end_time - request.interval.start_time >= datetime.timedelta(days=2)


def test_no_buckets_means_no_monitoring_request():
    client, requests = _monitoring()
    _, inventory = _collect([], client)
    assert requests == [] and inventory.total_buckets == 0


def test_a_failed_monitoring_read_keeps_the_buckets_marks_them_not_read_and_records_it():
    client, _ = _monitoring(
        error=PermissionError("403 Permission monitoring.timeSeries.list denied")
    )
    collector, inventory = _collect([_make_bucket("b1"), _make_bucket("b2")], client)
    assert inventory.total_buckets == 2
    assert {b.size_status for b in inventory.buckets} == {SIZE_NOT_READ}
    assert all(b.size_bytes is None for b in inventory.buckets)
    assert inventory.total_size_bytes is None
    (error,) = collector.errors
    assert error["collector"] == "storage:monitoring"
    assert error["category"] == "PERMISSION_DENIED"


def test_not_read_is_not_the_same_as_no_datapoint():
    failed, _ = _monitoring(error=RuntimeError("boom"))
    _, broke = _collect([_make_bucket("b1")], failed)
    empty, _ = _monitoring()
    _, none_yet = _collect([_make_bucket("b1")], empty)
    assert broke.buckets[0].size_status == SIZE_NOT_READ
    assert none_yet.buckets[0].size_status == SIZE_NO_DATAPOINT


def test_the_project_total_adds_only_the_measured_buckets():
    client, _ = _monitoring(
        bytes_series=[
            _series("a", 4_000_000_000, kind="live-object"),
            _series("b", 1_000_000_000, kind="noncurrent-object"),
        ]
    )
    _, inventory = _collect([_make_bucket("a"), _make_bucket("b"), _make_bucket("empty")], client)
    assert inventory.total_size_bytes == 5_000_000_000
    assert inventory.total_size_gb == 5.0 and inventory.total_size_tb == 0.005


def test_a_listing_failure_still_returns_an_empty_inventory_and_asks_monitoring_nothing():
    storage = MagicMock()
    storage.list_buckets.side_effect = Exception("403 forbidden")
    client, requests = _monitoring()
    with patch(_STORAGE_CLIENT, return_value=storage), patch(
        _MONITORING_CLIENT, return_value=client
    ):
        collector = StorageCollector(PROJECT_ID, MagicMock())
        inventory = collector.collect()
    assert inventory.total_buckets == 0 and requests == []
    assert [e["collector"] for e in collector.errors] == ["storage"]


@pytest.mark.parametrize(
    "double, integer, expected", [(1.5e12, 0, 1_500_000_000_000), (0.0, 42, 42), (0.0, 0, 0)]
)
def test_a_point_is_read_as_a_double_for_bytes_and_an_integer_for_counts(double, integer, expected):
    from collectors.storage import _point_value

    point = monitoring_v3.Point(
        {"value": {"double_value": double} if double else {"int64_value": integer}}
    )
    assert _point_value(point) == expected


def test_the_size_and_object_count_are_split_by_storage_class():
    client, _ = _monitoring(
        bytes_series=[
            _series("b1", 1000, "STANDARD", "live-object"),
            _series("b1", 200, "STANDARD", "noncurrent-object"),
            _series("b1", 300, "COLDLINE", "live-object"),
            _series("b1", 40, "DURABLE_REDUCED_AVAILABILITY", "live-object"),
            _series("b1", 999, "ARCHIVE", "soft-deleted-object"),
        ],
        count_series=[
            _series("b1", 10, "STANDARD", count=True),
            _series("b1", 3, "COLDLINE", count=True),
            _series("b1", 1, "DURABLE_REDUCED_AVAILABILITY", count=True),
        ],
    )
    _, inventory = _collect([_make_bucket("b1")], client)
    (bucket,) = inventory.buckets
    # Live plus noncurrent per class, like size_bytes. A class that is not one of the four goes to
    # OTHER, and a class with only soft-deleted bytes is a real zero because the bucket has a reading.
    assert bucket.class_bytes == {
        "STANDARD": 1200,
        "NEARLINE": 0,
        "COLDLINE": 300,
        "ARCHIVE": 0,
        "OTHER": 40,
    }
    assert sum(bucket.class_bytes.values()) == bucket.size_bytes
    assert bucket.class_object_counts["STANDARD"] == 10
    assert bucket.class_object_counts["OTHER"] == 1
    assert sum(bucket.class_object_counts.values()) == bucket.object_count


@pytest.mark.parametrize("label", ["REGIONAL", "MULTI_REGIONAL", "regional"])
def test_monitoring_labels_standard_data_regional_or_multi_regional(label):
    # What Cloud Monitoring returned for real buckets: Standard data in a region or multi-region
    # bucket carries these names, never STANDARD, so they must count as STANDARD and not OTHER.
    client, _ = _monitoring(
        bytes_series=[_series("b1", 500, label, "live-object")],
        count_series=[_series("b1", 7, label, count=True)],
    )
    _, inventory = _collect([_make_bucket("b1")], client)
    (bucket,) = inventory.buckets
    assert bucket.class_bytes["STANDARD"] == 500 and bucket.class_bytes["OTHER"] == 0
    assert bucket.class_object_counts["STANDARD"] == 7
    assert bucket.class_object_counts["OTHER"] == 0


def test_regional_and_standard_series_of_one_bucket_are_added_together():
    client, _ = _monitoring(
        bytes_series=[
            _series("b1", 500, "REGIONAL", "live-object"),
            _series("b1", 100, "STANDARD", "live-object"),
        ]
    )
    _, inventory = _collect([_make_bucket("b1")], client)
    assert inventory.buckets[0].class_bytes["STANDARD"] == 600


def test_a_bucket_with_no_datapoint_has_no_class_split():
    client, _ = _monitoring()
    _, inventory = _collect([_make_bucket("b1")], client)
    (bucket,) = inventory.buckets
    assert bucket.class_bytes == {} and bucket.class_object_counts == {}

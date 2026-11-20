"""Bucket growth: one extra Monitoring query, on or off, and what a short history looks like.

Monitoring is mocked at the client boundary with the real protobuf types, as in the size tests.
"""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

from google.cloud import monitoring_v3

from collectors.storage import (
    BYTES_METRIC,
    OBJECT_COUNT_METRIC,
    StorageCollector,
    _growth_endpoints,
)
from models.discovery_dataclasses import (
    GROWTH_MEASURED,
    GROWTH_NOT_READ,
    GROWTH_NOT_REQUESTED,
    GROWTH_TOO_FEW_READINGS,
    SIZE_MEASURED,
)
from tests.conftest import PROJECT_ID
from tests.test_collectors_storage import _make_bucket
from tests.test_collectors_storage_sizes import _series

_STORAGE_CLIENT = "google.cloud.storage.Client"
_MONITORING_CLIENT = "google.cloud.monitoring_v3.MetricServiceClient"
_T0 = datetime.datetime(2026, 11, 3, tzinfo=datetime.timezone.utc)
DAY = 86400


def _growth_series(bucket, points):
    """One summed series for a bucket: ``points`` is a list of (days after T0, bytes)."""
    return monitoring_v3.TimeSeries(
        {
            "metric": {"type": BYTES_METRIC},
            "resource": {"type": "gcs_bucket", "labels": {"bucket_name": bucket}},
            "points": [
                {
                    "interval": {"end_time": _T0 + datetime.timedelta(days=day)},
                    "value": {"double_value": float(value)},
                }
                for day, value in points
            ],
        }
    )


def _monitoring(growth_series=(), growth_error=None, size_error=None):
    """A client that answers the size queries and the growth query, and records each request."""
    client = MagicMock()
    requests = []

    def list_time_series(request):
        requests.append(request)
        is_growth = "one_of" in request.filter
        if is_growth:
            if growth_error is not None:
                raise growth_error
            return iter(growth_series)
        if size_error is not None:
            raise size_error
        if OBJECT_COUNT_METRIC in request.filter:
            return iter([])
        return iter([_series("b1", 1000, kind="live-object")])

    client.list_time_series.side_effect = list_time_series
    return client, requests


def _collect(client, growth_days, buckets=None):
    storage = MagicMock()
    storage.list_buckets.return_value = iter(buckets or [_make_bucket("b1")])
    with (
        patch(_STORAGE_CLIENT, return_value=storage),
        patch(_MONITORING_CLIENT, return_value=client),
    ):
        collector = StorageCollector(PROJECT_ID, MagicMock(), growth_days=growth_days)
        return collector, collector.collect()


# ── on and off ────────────────────────────────────────────────────────────────


def test_growth_is_off_by_default_and_costs_no_extra_query():
    client, requests = _monitoring()
    storage = MagicMock()
    storage.list_buckets.return_value = iter([_make_bucket("b1")])
    with (
        patch(_STORAGE_CLIENT, return_value=storage),
        patch(_MONITORING_CLIENT, return_value=client),
    ):
        inventory = StorageCollector(PROJECT_ID, MagicMock()).collect()
    assert len(requests) == 2  # bytes and object count, as before
    assert inventory.buckets[0].growth_status == GROWTH_NOT_REQUESTED


def test_growth_costs_exactly_one_more_query_for_the_whole_project():
    client, requests = _monitoring(growth_series=[_growth_series("b1", [(0, 100), (10, 150)])])
    _collect(client, 30, [_make_bucket("b1"), _make_bucket("b2"), _make_bucket("b3")])
    assert len(requests) == 3


def test_the_growth_query_covers_the_requested_days():
    client, requests = _monitoring(growth_series=[])
    _collect(client, 45)
    growth = next(r for r in requests if "one_of" in r.filter)
    span = growth.interval.end_time - growth.interval.start_time
    assert span == datetime.timedelta(days=45)


def test_the_size_query_keeps_its_short_window_so_an_emptied_class_does_not_linger():
    client, requests = _monitoring()
    _collect(client, 90)
    sizes = [r for r in requests if "one_of" not in r.filter]
    for request in sizes:
        assert request.interval.end_time - request.interval.start_time == datetime.timedelta(days=3)


def test_the_growth_query_adds_live_and_noncurrent_over_classes_on_the_server():
    client, requests = _monitoring()
    _collect(client, 30)
    growth = next(r for r in requests if "one_of" in r.filter)
    assert "live-object" in growth.filter and "noncurrent-object" in growth.filter
    assert "soft-deleted-object" not in growth.filter and "multipart-upload" not in growth.filter
    aggregation = growth.aggregation
    assert aggregation.cross_series_reducer == monitoring_v3.Aggregation.Reducer.REDUCE_SUM
    assert list(aggregation.group_by_fields) == ["resource.label.bucket_name"]


# ── the reading ───────────────────────────────────────────────────────────────


def test_growth_is_the_oldest_and_newest_reading_and_the_days_between_them():
    client, _ = _monitoring(
        growth_series=[_growth_series("b1", [(0, 1000), (15, 1200), (30, 1500)])]
    )
    _, inventory = _collect(client, 30)
    bucket = inventory.buckets[0]
    assert bucket.growth_status == GROWTH_MEASURED
    assert (bucket.growth_start_bytes, bucket.growth_end_bytes) == (1000, 1500)
    assert bucket.growth_days == 30.0


def test_a_bucket_younger_than_the_window_is_measured_over_its_own_age():
    client, _ = _monitoring(growth_series=[_growth_series("b1", [(25, 500), (30, 600)])])
    _, inventory = _collect(client, 30)
    assert inventory.buckets[0].growth_days == 5.0


def test_a_bucket_with_one_reading_has_too_few_readings_not_zero_growth():
    client, _ = _monitoring(growth_series=[_growth_series("b1", [(30, 500)])])
    _, inventory = _collect(client, 30)
    bucket = inventory.buckets[0]
    assert bucket.growth_status == GROWTH_TOO_FEW_READINGS
    assert bucket.growth_start_bytes is None and bucket.growth_days is None


def test_a_bucket_monitoring_has_no_series_for_has_too_few_readings():
    client, _ = _monitoring(growth_series=[])
    _, inventory = _collect(client, 30)
    assert inventory.buckets[0].growth_status == GROWTH_TOO_FEW_READINGS


def test_a_shrinking_bucket_has_a_negative_change():
    client, _ = _monitoring(growth_series=[_growth_series("b1", [(0, 1000), (30, 400)])])
    _, inventory = _collect(client, 30)
    bucket = inventory.buckets[0]
    assert bucket.growth_end_bytes - bucket.growth_start_bytes == -600


def test_a_bucket_that_comes_back_as_several_series_is_added_up_by_time():
    series = [
        _growth_series("b1", [(0, 100), (10, 150)]),
        _growth_series("b1", [(0, 50), (10, 70)]),
    ]
    assert _growth_endpoints(series)["b1"] == (
        _T0.timestamp(),
        150,
        (_T0 + datetime.timedelta(days=10)).timestamp(),
        220,
    )


def test_only_the_buckets_this_project_listed_get_growth():
    client, _ = _monitoring(
        growth_series=[_growth_series("other-project-bucket", [(0, 1), (9, 2)])]
    )
    _, inventory = _collect(client, 30)
    assert [b.name for b in inventory.buckets] == ["b1"]
    assert inventory.buckets[0].growth_status == GROWTH_TOO_FEW_READINGS


# ── failures ──────────────────────────────────────────────────────────────────


def test_a_failed_growth_query_is_recorded_and_leaves_the_sizes_alone():
    client, _ = _monitoring(growth_error=PermissionError("denied"))
    collector, inventory = _collect(client, 30)
    bucket = inventory.buckets[0]
    assert bucket.growth_status == GROWTH_NOT_READ
    assert bucket.size_status == SIZE_MEASURED and bucket.size_bytes == 1000
    assert [e["collector"] for e in collector.errors] == ["storage:growth"]


def test_when_the_sizes_could_not_be_read_growth_is_not_tried_again():
    client, requests = _monitoring(size_error=PermissionError("denied"))
    collector, inventory = _collect(client, 30)
    assert not any("one_of" in r.filter for r in requests)
    assert inventory.buckets[0].growth_status == GROWTH_NOT_READ
    assert [e["collector"] for e in collector.errors] == ["storage:monitoring"]

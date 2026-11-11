"""Tests for collectors/storage.py — all GCP SDK calls are mocked."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from collectors.storage import StorageCollector, _bytes_to_gb_tb

from tests.conftest import PROJECT_ID

_STORAGE_CLIENT = "google.cloud.storage.Client"


def _make_bucket(
    name: str,
    location: str = "US-CENTRAL1",
    storage_class: str = "STANDARD",
    versioning_enabled: bool = False,
    soft_delete_seconds: int = None,
    labels: dict = None,
    location_type: str = "region",
):
    b = MagicMock()
    b.name = name
    b.location = location
    b.storage_class = storage_class
    b.versioning_enabled = versioning_enabled
    b.labels = labels or {}
    b.location_type = location_type

    soft_delete = MagicMock()
    if soft_delete_seconds is not None:
        soft_delete.retention_duration_seconds = soft_delete_seconds
    else:
        soft_delete.retention_duration_seconds = None
    b.soft_delete_policy = soft_delete

    return b


def test_storage_collector_empty_project():
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = iter([])

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.total_buckets == 0
    assert result.buckets == []
    assert result.total_size_gb is None
    assert result.total_size_tb is None


def test_bytes_to_gb_tb_conversion():
    assert _bytes_to_gb_tb(None) == (None, None)
    gb, tb = _bytes_to_gb_tb(5_000_000_000)
    assert gb == 5.0
    assert tb == 0.005


def test_storage_collector_bucket_size_gb_tb_none_when_bytes_unavailable():
    # Cloud Monitoring size fetch isn't wired into list_buckets yet, so size_bytes
    # (and therefore size_gb/size_tb) stay None on every bucket at this stage.
    buckets = [_make_bucket("b1")]
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = iter(buckets)

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.buckets[0].size_bytes is None
    assert result.buckets[0].size_gb is None
    assert result.buckets[0].size_tb is None


def test_storage_collector_counts_buckets():
    buckets = [
        _make_bucket("bucket-1"),
        _make_bucket("bucket-2"),
        _make_bucket("bucket-3"),
    ]
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = iter(buckets)

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.total_buckets == 3
    assert result.project_id == PROJECT_ID


def test_storage_collector_class_breakdown():
    buckets = [
        _make_bucket("b1", storage_class="STANDARD"),
        _make_bucket("b2", storage_class="STANDARD"),
        _make_bucket("b3", storage_class="NEARLINE"),
        _make_bucket("b4", storage_class="COLDLINE"),
    ]
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = iter(buckets)

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.class_breakdown["STANDARD"] == 2
    assert result.class_breakdown["NEARLINE"] == 1
    assert result.class_breakdown["COLDLINE"] == 1


def test_storage_collector_soft_delete_percentage():
    buckets = [
        _make_bucket("b1", soft_delete_seconds=7 * 86400),
        _make_bucket("b2", soft_delete_seconds=None),
        _make_bucket("b3", soft_delete_seconds=30 * 86400),
        _make_bucket("b4", soft_delete_seconds=None),
    ]
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = iter(buckets)

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.soft_delete_enabled_count == 2
    assert result.soft_delete_pct == 50.0


def test_storage_collector_versioning_percentage():
    buckets = [
        _make_bucket("b1", versioning_enabled=True),
        _make_bucket("b2", versioning_enabled=False),
        _make_bucket("b3", versioning_enabled=True),
    ]
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = iter(buckets)

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.versioning_enabled_count == 2
    assert round(result.versioning_pct, 1) == 66.7


def test_storage_collector_soft_delete_days_calculation():
    buckets = [_make_bucket("b1", soft_delete_seconds=7 * 86400)]
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = iter(buckets)

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.buckets[0].soft_delete_retention_days == 7


def test_storage_collector_graceful_on_permission_error():
    mock_client = MagicMock()
    mock_client.list_buckets.side_effect = Exception("403 forbidden")

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.total_buckets == 0
    assert result.buckets == []


def test_storage_collector_label_summary_populated():
    buckets = [
        _make_bucket("b1", labels={"env": "prod"}),
        _make_bucket("b2", labels={}),
    ]
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = iter(buckets)

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.label_summary is not None
    assert result.label_summary.unlabelled_count == 1


def test_storage_collector_location_type_breakdown():
    buckets = [
        _make_bucket("b1", location="US", location_type="multi-region"),
        _make_bucket("b2", location="US-CENTRAL1", location_type="region"),
        _make_bucket("b3", location="US-CENTRAL1", location_type="region"),
    ]
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = iter(buckets)

    with patch(_STORAGE_CLIENT, return_value=mock_client):
        result = StorageCollector(PROJECT_ID, MagicMock()).collect()

    assert result.location_type_breakdown["region"] == 2
    assert result.location_type_breakdown["multi-region"] == 1

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
    # No Cloud Monitoring data here (the conftest refuses it), so the sizes stay None. The
    # reading-by-reading behaviour is in test_collectors_storage_sizes.py.
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


# ── bucket settings ───────────────────────────────────────────────────────────


def _configure(bucket, **props):
    """Set real values for the settings a bucket object reports (a MagicMock gives none)."""
    defaults = {
        "time_created": None,
        "data_locations": None,
        "rpo": None,
        "autoclass_enabled": None,
        "autoclass_terminal_storage_class": None,
        "hierarchical_namespace_enabled": None,
        "retention_period": None,
        "retention_policy_locked": None,
        "default_kms_key_name": None,
        "iam_configuration": None,
    }
    defaults.update(props)
    for name, value in defaults.items():
        setattr(bucket, name, value)
    return bucket


def _collect_one(bucket):
    client = MagicMock()
    client.list_buckets.return_value = iter([bucket])
    with patch(_STORAGE_CLIENT, return_value=client), patch(
        "collectors.storage.StorageCollector._fill_sizes"
    ):
        (result,) = StorageCollector(PROJECT_ID, MagicMock()).collect().buckets
    return result


def test_a_plain_regional_bucket_reports_its_defaults():
    bucket = _configure(_make_bucket("plain"))
    result = _collect_one(bucket)
    assert result.dual_region_locations == []
    # Turbo replication only exists on a dual-region bucket, so a regional one leaves it blank.
    assert result.turbo_replication_enabled is None
    assert result.retention_policy_enabled is False and result.retention_period_days is None
    assert result.bucket_lock_locked is False
    # The API leaves HNS out of a flat bucket, so a bucket that does not report it is not HNS.
    assert result.hns_enabled is False
    assert result.soft_delete_enabled is False
    assert result.default_kms_key_name is None
    assert result.creation_time is None


def test_a_dual_region_bucket_with_turbo_and_custom_placement():
    bucket = _configure(
        _make_bucket("dual", location="NAM4", location_type="dual-region"),
        rpo="ASYNC_TURBO",
        data_locations=["US-CENTRAL1", "US-EAST1"],
    )
    result = _collect_one(bucket)
    assert result.location_type == "dual-region"
    assert result.turbo_replication_enabled is True
    assert result.dual_region_locations == ["US-CENTRAL1", "US-EAST1"]


def test_a_dual_region_bucket_without_turbo_is_false_not_blank():
    bucket = _configure(
        _make_bucket("dual", location_type="dual-region"), rpo="DEFAULT", data_locations=None
    )
    result = _collect_one(bucket)
    assert result.turbo_replication_enabled is False and result.dual_region_locations == []


def test_autoclass_and_hierarchical_namespace():
    bucket = _configure(
        _make_bucket("auto"),
        autoclass_enabled=True,
        autoclass_terminal_storage_class="ARCHIVE",
        hierarchical_namespace_enabled=True,
    )
    result = _collect_one(bucket)
    assert result.autoclass_enabled is True
    assert result.autoclass_terminal_storage_class == "ARCHIVE"
    assert result.hns_enabled is True


def test_the_terminal_class_is_blank_when_autoclass_is_off():
    bucket = _configure(
        _make_bucket("noauto"), autoclass_enabled=False, autoclass_terminal_storage_class="NEARLINE"
    )
    result = _collect_one(bucket)
    assert result.autoclass_enabled is False
    assert result.autoclass_terminal_storage_class is None


def test_a_locked_retention_policy_is_reported_in_days():
    bucket = _configure(
        _make_bucket("locked"), retention_period=30 * 86400, retention_policy_locked=True
    )
    result = _collect_one(bucket)
    assert result.retention_policy_enabled is True and result.retention_period_days == 30
    assert result.bucket_lock_locked is True


def test_an_unlocked_retention_policy():
    bucket = _configure(
        _make_bucket("unlocked"), retention_period=86400, retention_policy_locked=False
    )
    result = _collect_one(bucket)
    assert result.retention_policy_enabled is True and result.bucket_lock_locked is False


def test_soft_delete_is_enabled_when_a_retention_period_is_set():
    result = _collect_one(_configure(_make_bucket("sd", soft_delete_seconds=7 * 86400)))
    assert result.soft_delete_enabled is True and result.soft_delete_retention_days == 7


def test_encryption_key_and_access_settings():
    iam = MagicMock()
    iam.uniform_bucket_level_access_enabled = True
    iam.public_access_prevention = "enforced"
    key = "projects/p/locations/us/keyRings/r/cryptoKeys/k"
    result = _collect_one(
        _configure(_make_bucket("secure"), default_kms_key_name=key, iam_configuration=iam)
    )
    assert result.default_kms_key_name == key
    assert result.ubla_enabled is True and result.public_access_prevention == "enforced"


def test_a_setting_the_library_cannot_read_is_blank_not_a_guess():
    iam = MagicMock()
    iam.uniform_bucket_level_access_enabled = "not a bool"
    iam.public_access_prevention = ""
    bucket = _configure(_make_bucket("odd"), iam_configuration=iam, autoclass_enabled="yes")
    result = _collect_one(bucket)
    assert result.ubla_enabled is None and result.public_access_prevention is None
    assert result.autoclass_enabled is None


def test_a_property_that_raises_is_blank_and_does_not_fail_the_listing():
    class Broken:
        @property
        def rpo(self):
            raise RuntimeError("not loaded")

    from collectors.storage import _property

    assert _property(Broken(), "rpo") is None


def test_the_creation_time_is_an_iso_timestamp():
    import datetime

    created = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    result = _collect_one(_configure(_make_bucket("old"), time_created=created))
    assert result.creation_time == "2026-01-02T03:04:05+00:00"

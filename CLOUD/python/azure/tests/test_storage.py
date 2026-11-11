"""Tests for collectors/storage.py."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from collectors.storage import _SKU_REDUNDANCY, StorageCollector

from tests.fixtures import (
    MOCK_BLOB_INVENTORY_POLICIES,
    MOCK_BLOB_PROPS,
    MOCK_STORAGE_ACCOUNTS,
    MOCK_STORAGE_METRICS,
    RG_ANALYTICS,
    RG_DATA,
    RG_DEV,
    RG_PROD,
    SUB_ID,
    _storage_id,
    mock_blob_inventory_effect,
    mock_blob_props_effect,
    mock_monitor_metrics_effect,
)


def _make_collector(
    accounts=None,
    blob_props_effect=None,
    inventory_effect=None,
    metrics_effect=None,
    collect_capacity=True,
) -> StorageCollector:
    """Return a StorageCollector with fully mocked Azure clients."""
    account_list = MOCK_STORAGE_ACCOUNTS if accounts is None else accounts

    mock_storage = MagicMock()
    mock_storage.storage_accounts.list.return_value = iter(account_list)
    mock_storage.blob_services.get_service_properties.side_effect = (
        blob_props_effect or mock_blob_props_effect
    )
    mock_storage.blob_inventory_policies.get.side_effect = (
        inventory_effect or mock_blob_inventory_effect
    )

    mock_monitor = MagicMock()
    mock_monitor.metrics.list.side_effect = metrics_effect or mock_monitor_metrics_effect

    with (
        patch("collectors.storage.StorageManagementClient", return_value=mock_storage),
        patch("collectors.storage.MonitorManagementClient", return_value=mock_monitor),
    ):
        collector = StorageCollector(SUB_ID, MagicMock(), collect_capacity=collect_capacity)

    # expose the monitor mock so tests can assert metrics were/weren't queried
    collector._test_monitor = mock_monitor  # type: ignore[attr-defined]
    return collector


class TestSkuRedundancyMapping:
    def test_standard_skus_present(self):
        for sku in [
            "Standard_LRS",
            "Standard_GRS",
            "Standard_RAGRS",
            "Standard_ZRS",
            "Standard_GZRS",
            "Standard_RAGZRS",
        ]:
            assert sku in _SKU_REDUNDANCY, f"{sku} missing from _SKU_REDUNDANCY"

    def test_premium_skus_present(self):
        assert _SKU_REDUNDANCY["Premium_LRS"] == "Premium LRS"
        assert _SKU_REDUNDANCY["Premium_ZRS"] == "Premium ZRS"

    def test_standard_lrs_label(self):
        assert _SKU_REDUNDANCY["Standard_LRS"] == "LRS"

    def test_standard_ragrs_label(self):
        assert _SKU_REDUNDANCY["Standard_RAGRS"] == "RA-GRS"

    def test_unknown_sku_falls_through(self):
        assert _SKU_REDUNDANCY.get("CustomSKU", "CustomSKU") == "CustomSKU"


class TestListAccounts:
    def test_all_accounts_collected(self):
        inventory = _make_collector().collect()
        assert inventory.total_accounts == 5
        names = {a.name for a in inventory.accounts}
        assert names == {
            "stgproddata",
            "stgprodlogs",
            "stganalytics",
            "stgdevassets",
            "stgpremblobs",
        }

    def test_account_core_fields(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgproddata")
        assert acct.resource_group == RG_DATA
        assert acct.subscription_id == SUB_ID
        assert acct.location == "eastus"
        assert acct.kind == "StorageV2"
        assert acct.sku == "Standard_GRS"
        assert acct.redundancy == "GRS"
        assert acct.access_tier == "Hot"

    def test_tags_collected(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgproddata")
        assert acct.tags["environment"] == "prod"
        assert acct.tags["owner"] == "dba-team"

    def test_no_access_tier_for_premium(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgpremblobs")
        assert acct.access_tier is None

    def test_premium_redundancy_label(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgpremblobs")
        assert acct.redundancy == "Premium LRS"


class TestRegionFilter:
    def test_filter_to_eastus(self):
        collector = _make_collector()
        collector._regions = frozenset(["eastus"])
        accounts = collector._list_accounts()
        assert len(accounts) == 4
        assert all(a.location == "eastus" for a in accounts)
        assert all(a.name != "stgdevassets" for a in accounts)

    def test_filter_to_westus2(self):
        collector = _make_collector()
        collector._regions = frozenset(["westus2"])
        accounts = collector._list_accounts()
        assert len(accounts) == 1
        assert accounts[0].name == "stgdevassets"

    def test_no_filter_returns_all(self):
        collector = _make_collector()
        assert collector._regions is None
        accounts = collector._list_accounts()
        assert len(accounts) == 5


class TestBlobProperties:
    def test_soft_delete_enabled_with_days(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgproddata")
        assert acct.blob_soft_delete_enabled is True
        assert acct.blob_soft_delete_days == 14

    def test_container_soft_delete_enabled_with_days(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgproddata")
        assert acct.container_soft_delete_enabled is True
        assert acct.container_soft_delete_days == 7

    def test_versioning_enabled(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgproddata")
        assert acct.versioning_enabled is True

    def test_soft_delete_disabled_no_days(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stganalytics")
        assert acct.blob_soft_delete_enabled is False
        assert acct.blob_soft_delete_days is None

    def test_versioning_disabled(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgprodlogs")
        assert acct.versioning_enabled is False

    def test_container_soft_delete_disabled_no_days(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgprodlogs")
        assert acct.container_soft_delete_enabled is False
        assert acct.container_soft_delete_days is None

    def test_premium_account_defaults_to_false(self):
        """Premium/BlockBlobStorage raises ResourceNotFoundError — defaults applied."""
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgpremblobs")
        assert acct.blob_soft_delete_enabled is False
        assert acct.versioning_enabled is False
        assert acct.blob_soft_delete_days is None

    def test_http_error_returns_defaults(self):
        def always_http_error(rg, name):
            raise HttpResponseError(message="Forbidden")

        inventory = _make_collector(blob_props_effect=always_http_error).collect()
        for acct in inventory.accounts:
            assert acct.blob_soft_delete_enabled is False
            assert acct.versioning_enabled is False


class TestBlobInventory:
    def test_inventory_enabled_for_stgproddata(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgproddata")
        assert acct.blob_inventory_enabled is True

    def test_inventory_disabled_for_remaining_accounts(self):
        inventory = _make_collector().collect()
        for acct in inventory.accounts:
            if acct.name != "stgproddata":
                assert acct.blob_inventory_enabled is False, (
                    f"Expected blob_inventory_enabled=False for {acct.name}"
                )

    def test_unexpected_exception_returns_false(self):
        def boom(rg, name):
            raise RuntimeError("unexpected SDK error")

        inventory = _make_collector(inventory_effect=boom).collect()
        for acct in inventory.accounts:
            assert acct.blob_inventory_enabled is False


class TestCapacityMetrics:
    def test_capacity_populated_for_known_accounts(self):
        inventory = _make_collector().collect()
        acct = next(a for a in inventory.accounts if a.name == "stgproddata")
        assert acct.capacity_bytes == 500 * 1024**3
        assert acct.capacity_gb == 500.0
        # capacity_tb is a straight /1024 conversion of capacity_gb (matches
        # ComputeInventory.total_disk_tb's divisor).
        assert acct.capacity_tb == round(500.0 / 1024, 3)

    def test_capacity_none_for_unavailable_accounts(self):
        inventory = _make_collector().collect()
        for name in ("stgdevassets", "stgpremblobs"):
            acct = next(a for a in inventory.accounts if a.name == name)
            assert acct.capacity_bytes is None, f"{name} should have no bytes"
            assert acct.capacity_gb is None, f"{name} should have no gb"
            assert acct.capacity_tb is None, f"{name} should have no tb"

    def test_bytes_to_gb_conversion(self):
        bytes_in = 1.5 * 1024**3
        result = NS(value=[NS(timeseries=[NS(data=[NS(maximum=bytes_in)])])])
        inventory = _make_collector(metrics_effect=lambda resource_uri, **kw: result).collect()
        assert all(a.capacity_gb == 1.5 for a in inventory.accounts)
        assert all(a.capacity_gb_decimal == 1.611 for a in inventory.accounts)
        assert all(a.capacity_tb_decimal == 0.0016 for a in inventory.accounts)
        assert inventory.total_capacity_gb_decimal == round(
            len(inventory.accounts) * 1.5 * 1024**3 / 1e9, 3
        )

    def test_capacity_is_the_latest_hourly_maximum_of_the_last_day(self):
        from datetime import datetime

        calls = []
        result = NS(value=[NS(timeseries=[NS(data=[NS(maximum=1024**3)])])])

        def metrics(resource_uri, **kw):
            calls.append(kw)
            return result

        _make_collector(metrics_effect=metrics).collect()

        capacity_calls = [c for c in calls if c.get("metricnames") == "UsedCapacity"]
        assert capacity_calls and {c["interval"] for c in capacity_calls} == {"PT1H"}
        for kw in capacity_calls:
            assert kw["aggregation"] == "Maximum"
            start, end = (datetime.fromisoformat(x.replace("Z", "+00:00")) for x in kw["timespan"].split("/"))
            assert end - start == timedelta(days=1)

    @staticmethod
    def _by_interval(hourly, daily):
        def metrics(resource_uri, **kw):
            points = hourly if kw["interval"] == "PT1H" else daily
            return NS(value=[NS(timeseries=[NS(data=[NS(maximum=p) for p in points])])])

        return metrics

    def test_an_account_that_shrank_reports_its_latest_size_not_the_days_largest(self):
        metrics = self._by_interval(hourly=[9.0e12, 7.5e12, 6.1e12], daily=[9.8e12])
        inventory = _make_collector(metrics_effect=metrics).collect()
        assert all(a.capacity_bytes == 6.1e12 for a in inventory.accounts)

    def test_without_an_hourly_point_the_daily_one_is_used(self):
        metrics = self._by_interval(hourly=[], daily=[2.0e12])
        inventory = _make_collector(metrics_effect=metrics).collect()
        assert all(a.capacity_bytes == 2.0e12 for a in inventory.accounts)

    def test_average_only_point_is_ignored(self):
        result = NS(value=[NS(timeseries=[NS(data=[NS(average=1024**3, maximum=None)])])])
        inventory = _make_collector(metrics_effect=lambda resource_uri, **kw: result).collect()
        assert all(a.capacity_bytes is None for a in inventory.accounts)

    def test_null_then_non_null_point_picks_latest(self):
        """Collector walks timeseries reversed — picks latest non-null point."""
        bytes_latest = 300 * 1024**3
        result = NS(
            value=[
                NS(
                    timeseries=[
                        NS(
                            data=[
                                NS(maximum=100 * 1024**3),  # older
                                NS(maximum=None),  # null in between
                                NS(maximum=bytes_latest),  # newest
                            ]
                        )
                    ]
                )
            ]
        )
        collector = _make_collector(metrics_effect=lambda resource_uri, **kw: result)
        accounts = collector._list_accounts()
        assert all(a.capacity_gb == 300.0 for a in accounts)

    def test_http_error_returns_none(self):
        def no_metrics(resource_uri, **kw):
            raise HttpResponseError(message="Metrics unavailable")

        inventory = _make_collector(metrics_effect=no_metrics).collect()
        for acct in inventory.accounts:
            assert acct.capacity_bytes is None
            assert acct.capacity_gb is None

    def test_empty_resource_id_returns_none(self):
        collector = _make_collector()
        result = collector._get_capacity("")
        assert result == (None, None)

    def test_fallback_to_blob_service_metric(self):
        """When UsedCapacity returns no data, BlobCapacity on the sub-resource is used."""
        blob_bytes = 750 * 1024**3
        empty = NS(value=[NS(timeseries=[NS(data=[])])])
        blob_result = NS(value=[NS(timeseries=[NS(data=[NS(maximum=blob_bytes)])])])

        def metrics_effect(resource_uri, **kw):
            if "blobServices" in resource_uri and kw.get("metricnames") == "BlobCapacity":
                return blob_result
            return empty

        collector = _make_collector(metrics_effect=metrics_effect)
        bytes_out, gb_out = collector._get_capacity(
            "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/test"
        )
        assert bytes_out == blob_bytes
        assert gb_out == pytest.approx(750.0, rel=1e-3)

    def test_fallback_sums_multiple_services(self):
        """Blob + File capacity are summed when UsedCapacity is unavailable."""
        blob_bytes = 400 * 1024**3
        file_bytes = 100 * 1024**3
        empty = NS(value=[NS(timeseries=[NS(data=[])])])

        def metrics_effect(resource_uri, **kw):
            if "blobServices" in resource_uri:
                return NS(value=[NS(timeseries=[NS(data=[NS(maximum=blob_bytes)])])])
            if "fileServices" in resource_uri:
                return NS(value=[NS(timeseries=[NS(data=[NS(maximum=file_bytes)])])])
            return empty

        collector = _make_collector(metrics_effect=metrics_effect)
        bytes_out, gb_out = collector._get_capacity(
            "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/test"
        )
        assert bytes_out == blob_bytes + file_bytes
        assert gb_out == pytest.approx(500.0, rel=1e-3)


class TestRollups:
    def test_total_accounts(self):
        assert _make_collector().collect().total_accounts == 5

    def test_redundancy_breakdown(self):
        rb = _make_collector().collect().redundancy_breakdown
        assert rb["GRS"] == 1  # stgproddata
        assert rb["LRS"] == 2  # stgprodlogs + stgdevassets
        assert rb["RA-GRS"] == 1  # stganalytics
        assert rb["Premium LRS"] == 1  # stgpremblobs

    def test_kind_breakdown(self):
        kb = _make_collector().collect().kind_breakdown
        assert kb["StorageV2"] == 4
        assert kb["BlockBlobStorage"] == 1

    def test_soft_delete_count(self):
        inv = _make_collector().collect()
        # stgproddata + stgprodlogs have blob soft delete enabled
        assert inv.soft_delete_enabled_count == 2

    def test_soft_delete_coverage_pct(self):
        assert _make_collector().collect().soft_delete_coverage_pct == 40.0

    def test_versioning_count(self):
        inv = _make_collector().collect()
        # stgproddata + stganalytics have versioning enabled
        assert inv.versioning_enabled_count == 2

    def test_versioning_coverage_pct(self):
        assert _make_collector().collect().versioning_coverage_pct == 40.0

    def test_total_capacity_gb(self):
        inv = _make_collector().collect()
        # 500 + 200 + 1500 = 2200 GB
        assert inv.total_capacity_gb == 2200.0
        assert inv.capacity_available is True
        # total_capacity_bytes sums the per-account native bytes; total_capacity_tb is a
        # straight /1024 conversion of the GB rollup.
        assert inv.total_capacity_bytes == (500 + 200 + 1500) * 1024**3
        assert inv.total_capacity_tb == round(2200.0 / 1024, 3)

    def test_total_capacity_none_when_all_metrics_fail(self):
        def no_metrics(resource_uri, **kw):
            raise HttpResponseError(message="No metrics")

        inv = _make_collector(metrics_effect=no_metrics).collect()
        assert inv.total_capacity_gb is None
        assert inv.capacity_available is False
        assert inv.total_capacity_bytes is None
        assert inv.total_capacity_tb is None

    def test_tag_summary_built(self):
        inv = _make_collector().collect()
        assert inv.tag_summary is not None
        assert "environment" in inv.tag_summary.key_coverage

    def test_tag_summary_environment_coverage(self):
        inv = _make_collector().collect()
        # All 5 accounts have "environment" tag → 100%
        assert inv.tag_summary.key_coverage["environment"] == 100.0

    def test_tag_summary_owner_coverage(self):
        inv = _make_collector().collect()
        # stganalytics has no "owner" tag → 4/5 = 80%
        assert inv.tag_summary.key_coverage["owner"] == 80.0


class TestGracefulDegradation:
    def test_bad_account_skipped(self):
        """Account that raises AttributeError during processing is skipped."""
        # NS() is truthy but has no 'name' attribute → sku.name raises AttributeError
        bad = NS(
            id=_storage_id(RG_PROD, "bad-account"),
            name="bad-account",
            location="eastus",
            kind="StorageV2",
            sku=NS(),  # truthy NS with no 'name' attr
            access_tier="Hot",
            tags={},
        )
        collector = _make_collector(accounts=list(MOCK_STORAGE_ACCOUNTS) + [bad])
        inventory = collector.collect()
        assert inventory.total_accounts == 5
        assert all(a.name != "bad-account" for a in inventory.accounts)


class TestObjectCounts:
    """Blob/file object counts via Monitor metrics — Blob (cloud-native) and Files (NCD)
    captured separately, summed into the inventory rollups."""

    @staticmethod
    def _counts_effect(resource_uri: str, **kwargs):
        """Return a fixed count per metric name on the blob/file service URIs; HTTP error
        elsewhere (so capacity falls through to None like an account with no data)."""
        metric = kwargs.get("metricnames")
        values = {"BlobCount": 1000, "FileCount": 500, "FileShareCount": 3}
        if metric in values and ("blobServices" in resource_uri or "fileServices" in resource_uri):
            return NS(value=[NS(timeseries=[NS(data=[NS(maximum=float(values[metric]))])])])
        raise HttpResponseError(message=f"no metric {metric} for {resource_uri}")

    def test_counts_populated_per_account(self):
        inventory = _make_collector(metrics_effect=self._counts_effect).collect()
        assert inventory.accounts  # sanity
        for acct in inventory.accounts:
            assert acct.blob_count == 1000  # cloud-native Blob object count
            assert acct.file_count == 500  # Azure Files file count
            assert acct.file_share_count == 3  # Azure Files share count

    def test_count_rollups_sum_across_accounts(self):
        inventory = _make_collector(metrics_effect=self._counts_effect).collect()
        n = inventory.total_accounts
        assert inventory.total_blob_count == 1000 * n
        assert inventory.total_file_count == 500 * n
        assert inventory.total_file_share_count == 3 * n

    def test_counts_none_when_metric_unavailable(self):
        # Default mock returns capacity for some accounts but no count metrics → None, and
        # rollups stay None (so the report shows "—", not a misleading 0).
        inventory = _make_collector().collect()
        assert all(a.blob_count is None for a in inventory.accounts)
        assert inventory.total_blob_count is None
        assert inventory.total_file_share_count is None


class TestListAccountsErrors:
    def test_list_accounts_http_error_returns_empty(self):
        mock_storage = MagicMock()
        mock_storage.storage_accounts.list.side_effect = HttpResponseError(
            message="Subscription not accessible"
        )
        mock_monitor = MagicMock()

        with (
            patch("collectors.storage.StorageManagementClient", return_value=mock_storage),
            patch("collectors.storage.MonitorManagementClient", return_value=mock_monitor),
        ):
            collector = StorageCollector(SUB_ID, MagicMock())

        assert collector._list_accounts() == []


class TestCapacityWarning:
    """Warn loudly when used-capacity is unavailable for ALL storage accounts."""

    def test_warns_when_no_account_has_capacity(self, caplog):
        def _deny(*_args, **_kwargs):
            raise HttpResponseError("metrics read denied")

        with caplog.at_level("WARNING", logger="collectors.storage"):
            inventory = _make_collector(metrics_effect=_deny).collect()

        assert inventory.accounts  # accounts were still collected
        assert inventory.capacity_available is False
        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert any("capacity" in r.getMessage().lower() for r in warnings), (
            "expected a WARNING about unavailable storage capacity"
        )

    def test_no_warning_when_capacity_available(self, caplog):
        with caplog.at_level("WARNING", logger="collectors.storage"):
            inventory = _make_collector().collect()  # default metrics return capacity

        assert inventory.capacity_available is True
        assert not [
            r
            for r in caplog.records
            if r.levelname == "WARNING" and "capacity" in r.getMessage().lower()
        ]


class TestCollectCapacityToggle:
    """collect_capacity=False skips the whole Monitor metrics pass (capacity + counts)."""

    def test_skips_metrics_no_warning(self, caplog):
        collector = _make_collector(collect_capacity=False)
        with caplog.at_level("WARNING", logger="collectors.storage"):
            inventory = collector.collect()

        # accounts still inventoried, but NO Monitor metrics are queried at all —
        # neither used-capacity nor blob/file object counts.
        assert inventory.accounts
        assert inventory.capacity_available is False
        assert all(a.capacity_gb is None for a in inventory.accounts)
        assert all(a.blob_count is None and a.file_count is None for a in inventory.accounts)
        collector._test_monitor.metrics.list.assert_not_called()
        # the all-unavailable warning must NOT fire when capacity was intentionally skipped
        assert not [
            r
            for r in caplog.records
            if r.levelname == "WARNING" and "capacity" in r.getMessage().lower()
        ]


class TestCapacityRequestedFlag:
    """capacity_requested records whether the Monitor pass was asked for, so the SE can
    tell 'access denied / unavailable' apart from 'opted out' (both leave totals None)."""

    def test_requested_true_by_default(self):
        assert _make_collector().collect().capacity_requested is True

    def test_requested_false_when_opted_out(self):
        inv = _make_collector(collect_capacity=False).collect()
        assert inv.capacity_requested is False
        # opted-out and access-denied both yield capacity_available False — the
        # capacity_requested flag is what distinguishes them downstream.
        assert inv.capacity_available is False


class TestMonitorPreflight:
    """probe_monitor_access() — cheap up-front check of Monitor metrics read."""

    @staticmethod
    def _http_error(status: int) -> HttpResponseError:
        err = HttpResponseError(message=f"status {status}")
        err.status_code = status
        return err

    def test_ok_when_metrics_return(self):
        collector = _make_collector(metrics_effect=lambda *a, **k: NS(value=[]))
        assert collector.probe_monitor_access() == "ok"

    def test_denied_on_403(self):
        def _deny(*_a, **_k):
            raise self._http_error(403)

        assert _make_collector(metrics_effect=_deny).probe_monitor_access() == "denied"

    def test_denied_on_401(self):
        def _deny(*_a, **_k):
            raise self._http_error(401)

        assert _make_collector(metrics_effect=_deny).probe_monitor_access() == "denied"

    def test_error_on_other_http_status(self):
        def _boom(*_a, **_k):
            raise self._http_error(500)

        assert _make_collector(metrics_effect=_boom).probe_monitor_access() == "error"

    def test_no_accounts_when_empty(self):
        assert _make_collector(accounts=[]).probe_monitor_access() == "no_accounts"

    def test_skipped_when_capacity_opted_out(self):
        collector = _make_collector(collect_capacity=False)
        assert collector.probe_monitor_access() == "skipped"
        # never touches Monitor when capacity is opted out
        collector._test_monitor.metrics.list.assert_not_called()

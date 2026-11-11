"""Tests for collectors/s3.py."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from collectors.s3 import fetch_s3

ACCT = "123456789012"
ALIAS = "test-account"
REGION = "us-east-1"


def _make_session(buckets, location_side_effect=None, cw_datapoints=None):
    """Return a session mock wiring s3 and cloudwatch clients."""
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": buckets}

    if location_side_effect is not None:
        mock_s3.get_bucket_location.side_effect = location_side_effect
    else:
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": REGION}

    mock_cw = MagicMock()
    if cw_datapoints is not None:
        mock_cw.get_metric_statistics.return_value = {"Datapoints": cw_datapoints}
    else:
        mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

    def client_factory(service, **kwargs):
        if service == "s3":
            return mock_s3
        return mock_cw

    s = MagicMock()
    s.client.side_effect = client_factory
    return s


def _datapoint(value, ts=None):
    return {"Maximum": value, "Average": value, "Timestamp": ts or datetime.now(timezone.utc)}


class TestFetchS3:
    def test_bucket_in_region_included(self):
        session = _make_session(
            buckets=[{"Name": "my-bucket"}],
            cw_datapoints=[_datapoint(1024 * 1024 * 1024)],
        )
        result = fetch_s3(session, REGION, ACCT, ALIAS, set())
        assert len(result) == 1
        assert result[0].bucket_name == "my-bucket"
        assert result[0].region == REGION

    def test_bucket_in_different_region_excluded(self):
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "other-region-bucket"}]}
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}
        mock_cw = MagicMock()
        mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

        def client_factory(service, **kwargs):
            return mock_s3 if service == "s3" else mock_cw

        s = MagicMock()
        s.client.side_effect = client_factory
        result = fetch_s3(s, REGION, ACCT, ALIAS, set())
        assert result == []

    def test_null_location_constraint_treated_as_us_east_1(self):
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "classic-bucket"}]}
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": None}
        mock_cw = MagicMock()
        mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

        def client_factory(service, **kwargs):
            return mock_s3 if service == "s3" else mock_cw

        s = MagicMock()
        s.client.side_effect = client_factory
        result = fetch_s3(s, "us-east-1", ACCT, ALIAS, set())
        assert len(result) == 1

    def test_cloudwatch_size_bytes_to_gb(self):
        gib = 1024**3
        session = _make_session(
            buckets=[{"Name": "big-bucket"}],
            cw_datapoints=[_datapoint(gib)],
        )
        result = fetch_s3(session, REGION, ACCT, ALIAS, set())
        assert result[0].size_bytes == gib
        assert result[0].size_gb == pytest.approx(1.0, abs=0.001)
        assert result[0].size_tb == pytest.approx(1.0 / 1024, abs=1e-4)

    def test_cloudwatch_no_datapoints_returns_zero(self):
        session = _make_session(
            buckets=[{"Name": "empty-bucket"}],
            cw_datapoints=[],
        )
        result = fetch_s3(session, REGION, ACCT, ALIAS, set())
        assert result[0].size_bytes == 0
        assert result[0].size_gb == 0.0

    def test_cloudwatch_latest_datapoint_used(self):
        from datetime import timedelta

        old_ts = datetime.now(timezone.utc) - timedelta(hours=30)
        new_ts = datetime.now(timezone.utc) - timedelta(hours=5)
        session = _make_session(
            buckets=[{"Name": "bucket"}],
            cw_datapoints=[
                _datapoint(100, old_ts),
                _datapoint(999, new_ts),
            ],
        )
        result = fetch_s3(session, REGION, ACCT, ALIAS, set())
        assert result[0].size_bytes == 999

    def test_backup_protection_marked(self):
        bucket_arn = "arn:aws:s3:::my-bucket"
        session = _make_session(buckets=[{"Name": "my-bucket"}])
        result = fetch_s3(session, REGION, ACCT, ALIAS, {bucket_arn})
        assert result[0].in_backup_plan is True
        assert result[0].backup_plans == ["AWS Backup"]

    def test_list_buckets_error_returns_empty(self):
        mock_s3 = MagicMock()
        mock_s3.list_buckets.side_effect = Exception("AccessDenied")
        mock_cw = MagicMock()

        def client_factory(service, **kwargs):
            return mock_s3 if service == "s3" else mock_cw

        s = MagicMock()
        s.client.side_effect = client_factory
        result = fetch_s3(s, REGION, ACCT, ALIAS, set())
        assert result == []

    def test_get_bucket_location_error_skips_bucket(self):
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "b1"}, {"Name": "b2"}]}
        mock_s3.get_bucket_location.side_effect = [
            Exception("AccessDenied"),
            {"LocationConstraint": REGION},
        ]
        mock_cw = MagicMock()
        mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

        def client_factory(service, **kwargs):
            return mock_s3 if service == "s3" else mock_cw

        s = MagicMock()
        s.client.side_effect = client_factory
        result = fetch_s3(s, REGION, ACCT, ALIAS, set())
        assert len(result) == 1
        assert result[0].bucket_name == "b2"

    def test_boto_config_applied_to_clients(self):
        """fetch_s3 must pass config= to boto3 so timeouts fire on slow endpoints."""
        from collectors import BOTO_ADAPTIVE_CFG

        recorded: list[dict] = []

        def client_factory(service, **kwargs):
            recorded.append({"service": service, "kwargs": kwargs})
            m = MagicMock()
            m.list_buckets.return_value = {"Buckets": [{"Name": "b1"}]}
            m.get_bucket_location.return_value = {"LocationConstraint": REGION}
            m.get_metric_statistics.return_value = {"Datapoints": []}
            return m

        s = MagicMock()
        s.client.side_effect = client_factory
        fetch_s3(s, REGION, ACCT, ALIAS, set())

        configs = {r["service"]: r["kwargs"].get("config") for r in recorded}
        assert configs.get("s3") is BOTO_ADAPTIVE_CFG, "S3 client missing adaptive config"
        assert configs.get("cloudwatch") is BOTO_ADAPTIVE_CFG, "CloudWatch client missing config"

    def test_adaptive_retry_mode_enabled(self):
        from collectors import BOTO_ADAPTIVE_CFG

        assert BOTO_ADAPTIVE_CFG.retries["mode"] == "adaptive"
        assert BOTO_ADAPTIVE_CFG.retries["max_attempts"] > 1


class TestMetricErrors:
    def _session(self, cw_error=None):
        s = _make_session(buckets=[{"Name": "b1"}], cw_datapoints=[])
        if cw_error:
            cw = s.client("cloudwatch")
            cw.get_metric_statistics.side_effect = cw_error
        return s

    def test_failed_metric_flagged_and_recorded(self):
        from collectors import DenialTracker

        tracker = DenialTracker()
        result = fetch_s3(
            self._session(Exception("ThrottlingException")), REGION, ACCT, ALIAS, set(), tracker
        )
        assert result[0].size_bytes == 0
        assert result[0].size_metric_failed is True
        errs = tracker.permission_errors()
        assert len(errs) == 1 and errs[0]["service"] == "cloudwatch"
        assert "ThrottlingException" in errs[0]["error"]

    def test_failed_object_count_is_flagged_separately(self):
        session = self._session()
        cw = session.client("cloudwatch")

        def metric(**kw):
            if kw["MetricName"] == "NumberOfObjects":
                raise Exception("AccessDenied: cloudwatch:GetMetricStatistics")
            return {"Datapoints": []}

        cw.get_metric_statistics.side_effect = metric
        result = fetch_s3(session, REGION, ACCT, ALIAS, set())
        assert result[0].object_count_metric_failed is True
        assert result[0].size_metric_failed is False

    def test_no_datapoints_is_not_a_failure(self):
        from collectors import DenialTracker

        tracker = DenialTracker()
        result = fetch_s3(self._session(), REGION, ACCT, ALIAS, set(), tracker)
        assert result[0].size_metric_failed is False
        assert tracker.permission_errors() == []


class TestBucketRegionAndFailures:
    def _session(self, buckets, location_by_bucket, tagging=None, calls=None):
        """Session whose s3 client reports ``location_by_bucket`` and records region_name."""
        mock_cw = MagicMock()
        mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

        def make_s3():
            s3 = MagicMock()
            s3.list_buckets.return_value = {"Buckets": [{"Name": b} for b in buckets]}

            def location(Bucket):
                result = location_by_bucket[Bucket]
                if isinstance(result, Exception):
                    raise result
                return result

            s3.get_bucket_location.side_effect = location
            if tagging is not None:
                s3.get_bucket_tagging.side_effect = tagging
            return s3

        s3_clients = []

        def factory(service, **kwargs):
            if calls is not None:
                calls.append((service, kwargs.get("region_name")))
            if service == "s3":
                s3_clients.append(make_s3())
                return s3_clients[-1]
            return mock_cw

        s = MagicMock()
        s.client.side_effect = factory
        s.s3_clients = s3_clients
        return s

    def test_tagging_client_uses_the_buckets_region(self):
        calls = []
        session = self._session(["b1"], {"b1": {"LocationConstraint": "ap-south-1"}}, calls=calls)
        result = fetch_s3(session, "ap-south-1", ACCT, ALIAS, set())
        assert [b.bucket_name for b in result] == ["b1"]
        assert ("s3", "ap-south-1") in calls

    def test_buckets_are_listed_once_across_regions_with_a_shared_locator(self):
        from collectors.s3 import BucketLocator

        session = self._session(
            ["a", "b"],
            {"a": {"LocationConstraint": "us-west-2"}, "b": {"LocationConstraint": "eu-west-1"}},
        )
        locator = BucketLocator()
        regions = ["us-west-2", "eu-west-1", "us-east-1", "ap-south-1"]
        names = {
            r: [b.bucket_name for b in fetch_s3(session, r, ACCT, ALIAS, set(), locator=locator)]
            for r in regions
        }
        assert names == {"us-west-2": ["a"], "eu-west-1": ["b"], "us-east-1": [], "ap-south-1": []}
        listings = sum(c.list_buckets.call_count for c in session.s3_clients)
        assert listings == 1

    def test_legacy_eu_location_constraint_maps_to_eu_west_1(self):
        session = self._session(["b1"], {"b1": {"LocationConstraint": "EU"}})
        assert [b.bucket_name for b in fetch_s3(session, "eu-west-1", ACCT, ALIAS, set())] == ["b1"]

    def test_empty_location_constraint_means_us_east_1(self):
        session = self._session(["b1"], {"b1": {"LocationConstraint": None}})
        assert [b.bucket_name for b in fetch_s3(session, "us-east-1", ACCT, ALIAS, set())] == ["b1"]

    def test_location_failure_is_recorded_and_other_buckets_still_scanned(self):
        from collectors import DenialTracker

        tracker = DenialTracker()
        session = self._session(
            ["ok", "bad"],
            {
                "ok": {"LocationConstraint": REGION},
                "bad": Exception("AccessDenied: GetBucketLocation"),
            },
        )
        result = fetch_s3(session, REGION, ACCT, ALIAS, set(), tracker)
        assert [b.bucket_name for b in result] == ["ok"]
        [err] = tracker.permission_errors()
        assert (
            err["service"] == "s3"
            and "skipped" in err["error"]
            and "1 access denied" in err["error"]
        )

    def test_bucket_listing_failure_is_recorded_once(self):
        from collectors import DenialTracker
        from collectors.s3 import BucketLocator

        tracker = DenialTracker()
        session = self._session([], {})
        session.client.side_effect = None
        s3 = MagicMock()
        s3.list_buckets.side_effect = Exception("AccessDenied: ListAllMyBuckets")
        session.client.return_value = s3
        locator = BucketLocator()
        for r in ["us-east-1", "us-west-2"]:
            assert fetch_s3(session, r, ACCT, ALIAS, set(), tracker, locator) == []
        assert [e["service"] for e in tracker.permission_errors()] == ["s3"]

    def test_tag_failure_is_flagged_and_recorded_but_no_such_tag_set_is_not(self):
        from collectors import DenialTracker

        class Boto(Exception):
            def __init__(self, code):
                super().__init__(code)
                self.response = {"Error": {"Code": code}}

        def tagging(Bucket):
            raise Boto("NoSuchTagSet" if Bucket == "plain" else "PermanentRedirect")

        tracker = DenialTracker()
        session = self._session(
            ["plain", "redirected"],
            {"plain": {"LocationConstraint": REGION}, "redirected": {"LocationConstraint": REGION}},
            tagging=tagging,
        )
        result = {b.bucket_name: b for b in fetch_s3(session, REGION, ACCT, ALIAS, set(), tracker)}
        assert result["plain"].tags_lookup_failed is False
        assert result["redirected"].tags_lookup_failed is True
        [err] = tracker.permission_errors()
        assert err["service"] == "s3" and "1 time(s)" in err["error"]


# ── storage classes, 7-day maximum and Storage Lens ──────────────────────────


def _dim(name, value):
    return {"Name": name, "Value": value}


def _class_session(
    size_types=("StandardStorage",),
    object_types=("AllStorageTypes",),
    values=None,
    lens_configs=None,
    lens_values=None,
    lens_classes=("STANDARD",),
    bucket="b1",
):
    """Session with CloudWatch metrics per storage class and optional Storage Lens dashboards."""
    values = values or {}
    lens_values = lens_values or {}
    calls = []

    cw = MagicMock()

    def paginator(operation):
        assert operation == "list_metrics"
        p = MagicMock()

        def paginate(**kw):
            if kw["Namespace"] == "AWS/S3":
                types = size_types if kw["MetricName"] == "BucketSizeBytes" else object_types
                return [
                    {
                        "Metrics": [
                            {
                                "Dimensions": [
                                    _dim("BucketName", bucket),
                                    _dim("StorageType", t),
                                ]
                            }
                            for t in types
                        ]
                    }
                ]
            return [
                {
                    "Metrics": [
                        {"Dimensions": [_dim("configuration_id", "c1"), _dim("storage_class", c)]}
                        for c in lens_classes
                    ]
                }
            ]

        p.paginate.side_effect = paginate
        return p

    cw.get_paginator.side_effect = paginator

    def stats(**kw):
        calls.append(kw)
        dims = {d["Name"]: d["Value"] for d in kw["Dimensions"]}
        if kw["Namespace"] == "AWS/S3":
            key = (kw["MetricName"], dims["StorageType"])
            points = values.get(key, [])
        else:
            key = (kw["MetricName"], dims["storage_class"])
            points = lens_values.get(key, [])
        return {"Datapoints": [{"Maximum": v, "Timestamp": t} for v, t in points]}

    cw.get_metric_statistics.side_effect = stats

    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": bucket}]}
    s3.get_bucket_location.return_value = {"LocationConstraint": REGION}
    s3.get_bucket_tagging.return_value = {"TagSet": []}

    s3control = MagicMock()
    configs = lens_configs or {}
    s3control.list_storage_lens_configurations.return_value = {
        "StorageLensConfigurationList": [{"Id": i} for i in configs]
    }
    s3control.get_storage_lens_configuration.side_effect = lambda ConfigId, AccountId: {
        "StorageLensConfiguration": configs[ConfigId]
    }

    def factory(service, **kwargs):
        calls.append(("client", service, kwargs.get("region_name")))
        return {"s3": s3, "cloudwatch": cw, "s3control": s3control}[service]

    session = MagicMock()
    session.client.side_effect = factory
    return session, calls, cw


def _day(n):
    return datetime(2026, 10, n, tzinfo=timezone.utc)


def _enabled(**extra):
    return {"IsEnabled": True, "DataExport": {"CloudWatchMetrics": {"IsEnabled": True}}, **extra}


class TestStorageClasses:
    def test_size_is_the_largest_daily_maximum_not_the_latest_average(self):
        session, calls, _ = _class_session(
            values={
                ("BucketSizeBytes", "StandardStorage"): [
                    (100, _day(1)),
                    (900, _day(2)),
                    (300, _day(3)),
                ]
            }
        )
        [bucket] = fetch_s3(session, REGION, ACCT, ALIAS, set())
        assert bucket.size_bytes == 900 and bucket.storage_class_bytes == {"StandardStorage": 900.0}
        sent = next(
            c for c in calls if isinstance(c, dict) and c["MetricName"] == "BucketSizeBytes"
        )
        assert sent["Statistics"] == ["Maximum"] and sent["Period"] == 86400
        assert sent["EndTime"] - sent["StartTime"] == timedelta(days=7)

    def test_every_storage_class_with_data_is_collected_standard_first(self):
        session, _, _ = _class_session(
            size_types=("StandardIAStorage", "StandardStorage", "GlacierStorage"),
            values={
                ("BucketSizeBytes", "StandardStorage"): [(10, _day(1))],
                ("BucketSizeBytes", "StandardIAStorage"): [(20, _day(1))],
                ("BucketSizeBytes", "GlacierStorage"): [(30, _day(1))],
            },
        )
        [bucket] = fetch_s3(session, REGION, ACCT, ALIAS, set())
        assert list(bucket.storage_class_bytes) == [
            "StandardStorage",
            "GlacierStorage",
            "StandardIAStorage",
        ]
        assert bucket.storage_class_bytes["GlacierStorage"] == 30.0 and bucket.size_bytes == 10

    def test_standard_and_all_types_are_present_even_without_data(self):
        session, _, _ = _class_session(size_types=(), object_types=())
        [bucket] = fetch_s3(session, REGION, ACCT, ALIAS, set())
        assert bucket.storage_class_bytes == {"StandardStorage": None}
        assert bucket.storage_class_objects == {"AllStorageTypes": None}
        assert bucket.size_metric_failed is False

    def test_object_count_uses_all_storage_types(self):
        session, _, _ = _class_session(
            values={("NumberOfObjects", "AllStorageTypes"): [(5, _day(1)), (7, _day(2))]}
        )
        [bucket] = fetch_s3(session, REGION, ACCT, ALIAS, set())
        assert bucket.object_count == 7

    def test_listing_failure_is_recorded_and_standard_is_still_queried(self):
        from collectors import DenialTracker

        session, _, cw = _class_session(
            values={("BucketSizeBytes", "StandardStorage"): [(42, _day(1))]}
        )
        cw.get_paginator.side_effect = Exception("AccessDenied: cloudwatch:ListMetrics")
        tracker = DenialTracker()
        [bucket] = fetch_s3(session, REGION, ACCT, ALIAS, set(), tracker)
        assert bucket.size_bytes == 42
        assert [e["service"] for e in tracker.permission_errors()] == ["cloudwatch"]


class TestStorageLens:
    def _fetch(self, session, **kw):
        from collectors.s3 import StorageLensLookup

        return fetch_s3(
            session,
            REGION,
            ACCT,
            ALIAS,
            set(),
            storage_lens=StorageLensLookup([REGION, "eu-west-1"]),
            **kw
        )

    def test_current_version_values_use_the_latest_day_from_the_dashboard_region(self):
        session, calls, _ = _class_session(
            lens_configs={"c1": _enabled(Include={}, Exclude={})},
            lens_values={
                ("CurrentVersionStorageBytes", "STANDARD"): [
                    (500, _day(1)),
                    (100, _day(3)),
                    (900, _day(2)),
                ],
                ("CurrentVersionObjectCount", "STANDARD"): [(8, _day(1)), (3, _day(3))],
            },
        )
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {"STANDARD": 100.0}
        assert bucket.current_version_objects == {"STANDARD": 3.0}
        lens_call = next(
            c for c in calls if isinstance(c, dict) and c["Namespace"] == "AWS/S3/Storage-Lens"
        )
        assert {d["Name"] for d in lens_call["Dimensions"]} == {
            "configuration_id",
            "aws_account_number",
            "aws_region",
            "bucket_name",
            "metrics_version",
            "record_type",
            "storage_class",
        }
        assert ("client", "cloudwatch", REGION) in calls

    def test_dashboards_that_do_not_publish_to_cloudwatch_are_ignored(self):
        disabled = {"IsEnabled": True, "DataExport": {"CloudWatchMetrics": {"IsEnabled": False}}}
        session, _, _ = _class_session(lens_configs={"c1": disabled})
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {} and bucket.current_version_objects == {}

    def test_no_dashboards_means_no_current_version_columns(self):
        session, _, _ = _class_session()
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {}

    @pytest.mark.parametrize(
        "config, covered",
        [
            ({}, True),
            ({"Include": {"Buckets": ["arn:aws:s3:::b1"]}}, True),
            ({"Include": {"Buckets": ["arn:aws:s3:::other"]}}, False),
            ({"Include": {"Regions": [REGION]}}, True),
            ({"Include": {"Regions": ["eu-west-1"]}}, False),
            ({"Exclude": {"Buckets": ["arn:aws:s3:::b1"]}}, False),
            ({"Exclude": {"Regions": [REGION]}}, False),
        ],
    )
    def test_dashboard_coverage_follows_include_and_exclude(self, config, covered):
        session, _, _ = _class_session(
            lens_configs={"c1": _enabled(**config)},
            lens_values={("CurrentVersionStorageBytes", "STANDARD"): [(1, _day(1))]},
        )
        [bucket] = self._fetch(session)
        assert bool(bucket.current_version_bytes) is covered

    def test_first_covering_dashboard_wins(self):
        session, _, _ = _class_session(
            lens_configs={
                "c0": _enabled(Include={"Buckets": ["arn:aws:s3:::other"]}),
                "c1": _enabled(),
            },
            lens_values={("CurrentVersionStorageBytes", "STANDARD"): [(1, _day(1))]},
        )
        [bucket] = self._fetch(session)
        assert list(bucket.current_version_bytes) == ["STANDARD"]

    def test_dashboard_lookup_failure_is_recorded_once_and_the_bucket_is_still_collected(self):
        from collectors import DenialTracker

        session, _, _ = _class_session()
        s3control = session.client("s3control")
        s3control.list_storage_lens_configurations.side_effect = Exception("AccessDenied: s3")
        tracker = DenialTracker()
        buckets = self._fetch(session, tracker=tracker)
        assert len(buckets) == 1
        errors = [e for e in tracker.permission_errors() if e["service"] == "s3"]
        assert len(errors) == 1 and "2 time(s)" in errors[0]["error"]

    def test_lookup_runs_once_for_all_regions_and_only_when_a_bucket_exists(self):
        from collectors.s3 import StorageLensLookup

        session, calls, _ = _class_session(bucket="b1")
        lens = StorageLensLookup([REGION])
        fetch_s3(session, REGION, ACCT, ALIAS, set(), storage_lens=lens)
        fetch_s3(session, REGION, ACCT, ALIAS, set(), storage_lens=lens)
        assert sum(1 for c in calls if c == ("client", "s3control", REGION)) == 1
        empty, empty_calls, _ = _class_session(bucket="b1")
        fetch_s3(
            empty, "eu-west-1", ACCT, ALIAS, set(), storage_lens=StorageLensLookup(["eu-west-1"])
        )
        assert not any(
            c[:2] == ("client", "s3control") for c in empty_calls if isinstance(c, tuple)
        )

    def test_a_region_that_cannot_host_storage_lens_is_not_an_error(self):
        from collectors import DenialTracker

        session, _, _ = _class_session()
        s3control = session.client("s3control")
        s3control.list_storage_lens_configurations.side_effect = Exception(
            "An error occurred (AccessDenied) when calling the ListStorageLensConfigurations "
            "operation: Region is not supported as home region for S3 Storage Lens"
        )
        tracker = DenialTracker()
        [bucket] = self._fetch(session, tracker=tracker)
        assert bucket.current_version_bytes == {}
        assert tracker.permission_errors() == []

    def test_other_access_denials_are_still_recorded(self):
        from collectors import DenialTracker

        session, _, _ = _class_session()
        session.client("s3control").list_storage_lens_configurations.side_effect = Exception(
            "An error occurred (AccessDenied) when calling the ListStorageLensConfigurations operation"
        )
        tracker = DenialTracker()
        self._fetch(session, tracker=tracker)
        assert [e["service"] for e in tracker.permission_errors()] == ["s3"]


# ── Storage Lens CSV export, for dashboards that do not publish to CloudWatch ──

_SCHEMA = (
    "version_number,configuration_id,report_date,aws_account_number,aws_region,"
    "storage_class,record_type,record_value,bucket_name,metric_name,metric_value"
)


def _export_config(fmt="CSV", **extra):
    return {
        "IsEnabled": True,
        "DataExport": {
            "CloudWatchMetrics": {"IsEnabled": False},
            "S3BucketDestination": {"Format": fmt, "Arn": "arn:aws:s3:::exp", "Prefix": "pre"},
        },
        **extra,
    }


def _row(region, storage_class, record_type, bucket, metric, value):
    return f"V_1,c1,2026-10-28,{ACCT},{region},{storage_class},{record_type},{bucket},{bucket},{metric},{value}"


def _body(data: bytes):
    body = MagicMock()
    body.read.return_value = data
    body.iter_lines.return_value = data.split(b"\n")
    return body


def _export_session(rows, manifest_fmt="CSV", manifest_days=(0,), config=None, report_bytes=None):
    import json

    from botocore.exceptions import ClientError

    session, calls, _ = _class_session(lens_configs={"c1": config or _export_config()})
    s3 = session.client("s3")
    today = datetime.now(timezone.utc).date()
    manifest_keys = {
        f"pre/StorageLens/{ACCT}/c1/V_1/manifests/dt={(today - timedelta(days=d)).isoformat()}/manifest.json"
        for d in manifest_days
    }
    report_key = f"pre/StorageLens/{ACCT}/c1/V_1/reports/dt=x/r.csv"
    manifest = {
        "reportFormat": manifest_fmt,
        "reportDate": "2026-10-28",
        "reportSchema": _SCHEMA,
        "reportFiles": [{"key": report_key, "size": 100}],
    }

    def get_object(Bucket, Key, **_):
        assert Bucket == "exp"
        if Key in manifest_keys:
            return {"Body": _body(json.dumps(manifest).encode())}
        if Key == report_key:
            data = report_bytes if report_bytes is not None else "\n".join(rows).encode()
            return {"Body": _body(data)}
        raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "x"}}, "GetObject")

    s3.get_object.side_effect = get_object
    return session, s3


class TestStorageLensExport:
    def _fetch(self, session, **kw):
        from collectors.s3 import StorageLensLookup

        return fetch_s3(
            session, REGION, ACCT, ALIAS, set(), storage_lens=StorageLensLookup([REGION]), **kw
        )

    def test_a_dashboard_without_cloudwatch_is_read_from_its_csv_export(self):
        rows = [
            _row(REGION, "STANDARD", "BUCKET", "b1", "CurrentVersionStorageBytes", 100),
            _row(REGION, "STANDARD", "BUCKET", "b1", "CurrentVersionObjectCount", 3),
            _row(REGION, "GLACIER", "BUCKET", "b1", "CurrentVersionStorageBytes", 40),
            _row(REGION, "STANDARD", "BUCKET", "other", "CurrentVersionStorageBytes", 999),
            _row(REGION, "STANDARD", "ACCOUNT", "b1", "CurrentVersionStorageBytes", 777),
            _row(REGION, "STANDARD", "BUCKET", "b1", "StorageBytes", 555),
        ]
        session, _ = _export_session(rows)
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {"STANDARD": 100.0, "GLACIER": 40.0}
        assert bucket.current_version_objects == {"STANDARD": 3.0}

    def test_the_newest_manifest_within_the_lookback_is_used(self):
        rows = [_row(REGION, "STANDARD", "BUCKET", "b1", "CurrentVersionStorageBytes", 5)]
        session, _ = _export_session(rows, manifest_days=(2,))
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {"STANDARD": 5.0}

    def test_no_recent_manifest_leaves_the_columns_blank_without_an_error(self):
        from collectors import DenialTracker

        session, _ = _export_session([], manifest_days=())
        tracker = DenialTracker()
        [bucket] = self._fetch(session, tracker=tracker)
        assert bucket.current_version_bytes == {} and bucket.current_version_objects == {}
        assert [e for e in tracker.permission_errors() if e["service"] == "s3"] == []

    def test_an_export_in_another_format_is_not_used(self):
        session, s3 = _export_session([], config=_export_config(fmt="ORC"))
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {}
        s3.get_object.assert_not_called()

    def test_a_manifest_in_another_format_is_not_read(self):
        session, _ = _export_session([], manifest_fmt="ORC")
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {}

    def test_a_parquet_export_is_read(self):
        pa = pytest.importorskip("pyarrow")
        import io

        import pyarrow.parquet as pq

        names = [c for c in _SCHEMA.split(",")]
        records = [
            ("V_1", "c1", "2026-10-28", ACCT, REGION, "STANDARD", "BUCKET", "b1", "b1",
             "CurrentVersionStorageBytes", 100),
            ("V_1", "c1", "2026-10-28", ACCT, REGION, "STANDARD", "BUCKET", "b1", "b1",
             "CurrentVersionObjectCount", 3),
            ("V_1", "c1", "2026-10-28", ACCT, REGION, "STANDARD", "ACCOUNT", "", "b1",
             "CurrentVersionStorageBytes", 777),
            ("V_1", "c1", "2026-10-28", ACCT, REGION, "STANDARD", "BUCKET", "other", "other",
             "CurrentVersionStorageBytes", 999),
        ]
        table = pa.table({n: [r[i] for r in records] for i, n in enumerate(names)})
        out = io.BytesIO()
        pq.write_table(table, out)
        session, _ = _export_session(
            [], manifest_fmt="Parquet", config=_export_config(fmt="Parquet"),
            report_bytes=out.getvalue(),
        )
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {"STANDARD": 100.0}
        assert bucket.current_version_objects == {"STANDARD": 3.0}

    def test_a_parquet_report_without_the_needed_columns_is_recorded_as_an_error(self):
        pa = pytest.importorskip("pyarrow")
        import io

        import pyarrow.parquet as pq
        from collectors import DenialTracker

        out = io.BytesIO()
        pq.write_table(pa.table({"bucket_name": ["b1"]}), out)
        session, _ = _export_session(
            [], manifest_fmt="Parquet", config=_export_config(fmt="Parquet"),
            report_bytes=out.getvalue(),
        )
        tracker = DenialTracker()
        [bucket] = self._fetch(session, tracker=tracker)
        assert bucket.current_version_bytes == {}
        assert len([e for e in tracker.permission_errors() if e["service"] == "s3"]) == 1

    def test_a_parquet_export_without_pyarrow_leaves_the_columns_blank(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def no_pyarrow(name, *args, **kwargs):
            if name == "pyarrow" or name.startswith("pyarrow."):
                raise ImportError("no pyarrow")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_pyarrow)
        session, s3 = _export_session(
            [], manifest_fmt="Parquet", config=_export_config(fmt="Parquet")
        )
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {}
        # the manifest was read, the report file was not
        assert all("reports" not in c.kwargs["Key"] for c in s3.get_object.call_args_list)

    def test_an_access_denied_on_the_export_is_recorded_once(self):
        from botocore.exceptions import ClientError
        from collectors import DenialTracker

        session, s3 = _export_session([])
        s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetObject"
        )
        tracker = DenialTracker()
        [bucket] = self._fetch(session, tracker=tracker)
        assert bucket.current_version_bytes == {}
        errors = [e for e in tracker.permission_errors() if e["service"] == "s3"]
        assert len(errors) == 1 and "Storage Lens export" in errors[0]["error"]

    def test_cloudwatch_wins_when_both_kinds_of_dashboard_cover_the_bucket(self):
        session, _, _ = _class_session(
            lens_configs={"c0": _export_config(), "c1": _enabled()},
            lens_values={("CurrentVersionStorageBytes", "STANDARD"): [(7, _day(1))]},
        )
        [bucket] = self._fetch(session)
        assert bucket.current_version_bytes == {"STANDARD": 7.0}

"""Tests for main.py — _build_summary, _to_dict, and _scan_region helpers."""

import dataclasses
import json
import logging

import pytest
from main import _build_summary, _scan_region, _to_dict
from models.discovery import (
    BackupCostEntry,
    BackupPlan,
    BackupRule,
    DiscoverySummary,
    DynamoDBTable,
    EC2Instance,
    EC2Volume,
    EFSFileSystem,
    KMSRegionCount,
    RDSInstance,
    S3Bucket,
    SecretsRegionCount,
    SQSRegionCount,
)

ACCT = "123456789012"
ALIAS = "test-account"
REGION = "us-east-1"


def _ec2(instance_id, in_backup=False):
    return EC2Instance(
        account_id=ACCT,
        account_alias=ALIAS,
        instance_id=instance_id,
        name=instance_id,
        instance_type="t3.micro",
        platform="linux",
        state="running",
        vcpus=2,
        memory_gib=1.0,
        region=REGION,
        volume_count=1,
        size_gib=50,
        size_tb=0.05,
        size_bytes_derived=50 * 1024**3,
        in_backup_plan=in_backup,
        backup_plans=["AWS Backup"] if in_backup else [],
        tags={},
    )


def _vol(vol_id, size_tb=0.05, in_backup=False):
    size_gib = int(size_tb * 1024)
    return EC2Volume(
        account_id=ACCT,
        account_alias=ALIAS,
        volume_id=vol_id,
        instance_id="i-1",
        instance_name="host",
        name="root",
        device_name="/dev/xvda",
        size_gib=size_gib,
        size_tb=size_tb,
        size_bytes_derived=size_gib * 1024**3,
        region=REGION,
        availability_zone="us-east-1a",
        volume_type="gp3",
        state="in-use",
        iops=3000,
        throughput=125,
        encrypted=True,
        in_backup_plan=in_backup,
        backup_plans=[],
        tags={},
    )


def _rds(db_id, in_backup=False):
    return RDSInstance(
        account_id=ACCT,
        account_alias=ALIAS,
        db_instance_identifier=db_id,
        db_name="mydb",
        size_gib=100,
        size_tb=round(100 / 1024, 6),
        size_bytes_derived=100 * 1024**3,
        region=REGION,
        engine="mysql",
        storage_type="gp2",
        instance_class="db.t3.medium",
        multi_az=False,
        native_backup_enabled=True,
        native_backup_retention_days=7,
        in_backup_plan=in_backup,
        backup_plans=[],
        tags={},
    )


def _dynamodb(name, in_backup=False):
    return DynamoDBTable(
        account_id=ACCT,
        account_alias=ALIAS,
        region=REGION,
        table_name=name,
        table_id="id",
        table_arn=f"arn:aws:dynamodb:::table/{name}",
        size_bytes=0,
        size_gib=0.0,
        size_tb=0.0,
        item_count=0,
        status="ACTIVE",
        deletion_protection=False,
        read_capacity_units=5,
        write_capacity_units=5,
        pitr_enabled=False,
        in_backup_plan=in_backup,
        backup_plans=[],
    )


def _efs(fs_id, in_backup=False):
    return EFSFileSystem(
        account_id=ACCT,
        account_alias=ALIAS,
        file_system_id=fs_id,
        name="",
        size_bytes=0,
        size_gib=0.0,
        size_tb=0.0,
        mount_targets=0,
        owner_id=ACCT,
        performance_mode="generalPurpose",
        throughput_mode="bursting",
        provisioned_throughput_mibps=0.0,
        region=REGION,
        in_backup_plan=in_backup,
        backup_plans=[],
        tags={},
    )


def _s3(name, size_gb=10.0):
    return S3Bucket(
        account_id=ACCT,
        account_alias=ALIAS,
        bucket_name=name,
        region=REGION,
        size_bytes=int(size_gb * 1024**3),
        size_gb=size_gb,
        size_tb=round(size_gb / 1024, 4),
        object_count=100,
        in_backup_plan=False,
        backup_plans=[],
    )


def _cost_entry(amt):
    return BackupCostEntry(
        account_id=ACCT,
        account_alias=ALIAS,
        period_start="2023-01-01",
        period_end="2023-02-01",
        amortized_cost=amt,
        blended_cost=amt,
        unblended_cost=amt,
    )


class TestBuildSummary:
    def _agg(self, **kwargs):
        defaults = {
            "instances": [],
            "attached": [],
            "unattached": [],
            "rds": [],
            "dynamodb": [],
            "efs": [],
            "fsx": [],
            "s3": [],
            "kms": [KMSRegionCount(ACCT, ALIAS, REGION, 0)],
            "secrets": [SecretsRegionCount(ACCT, ALIAS, REGION, 0)],
            "sqs": [SQSRegionCount(ACCT, ALIAS, REGION, 0)],
            "plans": [],
        }
        defaults.update(kwargs)
        return defaults

    def test_ec2_counts(self):
        instances = [_ec2("i-1", in_backup=True), _ec2("i-2"), _ec2("i-3")]
        s = _build_summary(self._agg(instances=instances), backup_costs=[])
        assert s.total_ec2_instances == 3
        assert s.total_ec2_protected == 1
        assert s.total_ec2_unprotected == 2

    def test_ec2_protection_pct(self):
        instances = [
            _ec2("i-1", in_backup=True),
            _ec2("i-2"),
            _ec2("i-3"),
            _ec2("i-4", in_backup=True),
        ]
        s = _build_summary(self._agg(instances=instances), backup_costs=[])
        assert s.ec2_protection_pct == pytest.approx(50.0)

    def test_ec2_protection_pct_zero_instances(self):
        s = _build_summary(self._agg(instances=[]), backup_costs=[])
        assert s.ec2_protection_pct == 0.0

    def test_disk_totals(self):
        attached = [_vol("v1", size_tb=1.0), _vol("v2", size_tb=2.0)]
        unattached = [_vol("v3", size_tb=0.5)]
        s = _build_summary(self._agg(attached=attached, unattached=unattached), backup_costs=[])
        assert s.total_attached_disk_tb == pytest.approx(3.0, abs=0.001)
        assert s.total_unattached_disk_tb == pytest.approx(0.5, abs=0.001)
        assert s.total_disk_tb == pytest.approx(3.5, abs=0.001)

    def test_rds_counts(self):
        rds = [_rds("db-1", in_backup=True), _rds("db-2")]
        s = _build_summary(self._agg(rds=rds), backup_costs=[])
        assert s.total_rds_instances == 2
        assert s.total_rds_protected == 1

    def test_dynamodb_counts(self):
        tables = [_dynamodb("t1", in_backup=True), _dynamodb("t2"), _dynamodb("t3", in_backup=True)]
        s = _build_summary(self._agg(dynamodb=tables), backup_costs=[])
        assert s.total_dynamodb_tables == 3
        assert s.total_dynamodb_protected == 2

    def test_efs_counts(self):
        efs = [_efs("fs-1"), _efs("fs-2", in_backup=True)]
        s = _build_summary(self._agg(efs=efs), backup_costs=[])
        assert s.total_efs_filesystems == 2
        assert s.total_efs_protected == 1

    def test_s3_totals(self):
        buckets = [_s3("b1", 10.0), _s3("b2", 20.5)]
        s = _build_summary(self._agg(s3=buckets), backup_costs=[])
        assert s.total_s3_buckets == 2
        assert s.total_s3_gb == pytest.approx(30.5, abs=0.001)

    def test_kms_aggregate(self):
        kms = [
            KMSRegionCount(ACCT, ALIAS, "us-east-1", 5),
            KMSRegionCount(ACCT, ALIAS, "us-west-2", 3),
        ]
        s = _build_summary(self._agg(kms=kms), backup_costs=[])
        assert s.total_kms_keys == 8

    def test_secrets_aggregate(self):
        secrets = [
            SecretsRegionCount(ACCT, ALIAS, "us-east-1", 10),
            SecretsRegionCount(ACCT, ALIAS, "eu-west-1", 4),
        ]
        s = _build_summary(self._agg(secrets=secrets), backup_costs=[])
        assert s.total_secrets == 14

    def test_sqs_aggregate(self):
        sqs = [SQSRegionCount(ACCT, ALIAS, REGION, 7)]
        s = _build_summary(self._agg(sqs=sqs), backup_costs=[])
        assert s.total_sqs_queues == 7

    def test_backup_plans_count(self):
        rule = BackupRule("daily", "Default", "cron(0 5 ? * * *)", 60, 180, 35, 0)
        plan = BackupPlan(ACCT, ALIAS, REGION, "p1", "", "Plan1", "v1", "", "", [rule], [])
        s = _build_summary(self._agg(plans=[plan]), backup_costs=[])
        assert s.total_backup_plans == 1

    def test_backup_spend_sum(self):
        costs = [_cost_entry(100.0), _cost_entry(200.5), _cost_entry(50.25)]
        s = _build_summary(self._agg(), backup_costs=costs)
        assert s.total_12mo_backup_spend_usd == pytest.approx(350.75)

    def test_zero_backup_spend(self):
        s = _build_summary(self._agg(), backup_costs=[])
        assert s.total_12mo_backup_spend_usd == 0.0


class TestToDict:
    def test_primitive_passthrough(self):
        assert _to_dict(42) == 42
        assert _to_dict("hello") == "hello"
        assert _to_dict(3.14) == 3.14

    def test_list_passthrough(self):
        assert _to_dict([1, 2, 3]) == [1, 2, 3]

    def test_tuple_becomes_list(self):
        result = _to_dict((1, 2, 3))
        assert result == [1, 2, 3]

    def test_dataclass_becomes_dict(self):
        inst = _ec2("i-test", in_backup=True)
        d = _to_dict(inst)
        assert isinstance(d, dict)
        assert d["instance_id"] == "i-test"
        assert d["in_backup_plan"] is True

    def test_nested_dataclass(self):
        s = DiscoverySummary(total_ec2_instances=5)
        result = _to_dict(s)
        assert isinstance(result, dict)
        assert result["total_ec2_instances"] == 5

    def test_list_of_dataclasses(self):
        instances = [_ec2("i-1"), _ec2("i-2")]
        result = _to_dict(instances)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["instance_id"] == "i-1"
        assert result[1]["instance_id"] == "i-2"


class TestScanRegionOptIn:
    """_scan_region must fail fast and silently on unreachable opt-in regions."""

    _EMPTY_KEYS = {
        "instances",
        "attached",
        "unattached",
        "rds",
        "dynamodb",
        "efs",
        "fsx",
        "s3",
        "kms",
        "secrets",
        "sqs",
        "plans",
        "vaults",
        "cfn",
        "native_backups",
        "rds_snapshots",
        "ebs_ami",
        "vpcs",
        "load_balancers",
        "eks_clusters",
        "eks_nodegroups",
        "kms_keys",
        "redshift",
        "fsx_volumes",
        "s3_tables",
        "glue_iceberg",
        "recovery_points",
        "recovery_aggregates",
        "truncated_backup_regions",
    }

    def _session(self, probe_exc):
        """Session whose EC2 client raises probe_exc on describe_availability_zones."""
        from unittest.mock import MagicMock

        ec2 = MagicMock()
        ec2.describe_availability_zones.side_effect = probe_exc
        session = MagicMock()
        session.client.return_value = ec2
        return session

    def test_unreachable_endpoint_returns_empty(self):
        """Connection error on the region probe → all-empty result, no exception."""
        session = self._session(Exception("ConnectTimeoutError: me-south-1"))
        result = _scan_region(session, "me-south-1", "123456789012", "acct", frozenset())
        assert set(result.keys()) == self._EMPTY_KEYS
        assert all(v == [] for v in result.values())

    def test_unreachable_endpoint_logs_debug_not_warning(self, caplog):
        """Non-SCP probe failure must not surface as a WARNING (customer sees no noise)."""
        session = self._session(Exception("EndpointResolutionError: region not enabled"))
        with caplog.at_level(logging.DEBUG, logger="root"):
            _scan_region(session, "me-south-1", "123456789012", "acct", frozenset())
        warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert not warning_msgs, f"unexpected WARNING log(s): {warning_msgs}"

    def test_scp_denial_logs_info_not_warning(self, caplog):
        """SCP explicit-deny on the probe → INFO (not WARNING, not silent)."""
        exc = Exception("service_control_policy explicit deny in effect")
        session = self._session(exc)
        with caplog.at_level(logging.DEBUG, logger="root"):
            result = _scan_region(session, "us-east-1", "123456789012", "acct", frozenset())
        assert all(v == [] for v in result.values())
        info_msgs = [r.message for r in caplog.records if r.levelno == logging.INFO]
        assert any("SCP" in m for m in info_msgs)


class TestScpRestrictionsSuspected:
    """DiscoveryResult.scp_restrictions_suspected is set via DenialTracker when an
    SCP-denied API call is recorded during a scan."""

    def _make_result(self, **summary_kwargs):
        from models.discovery import DiscoveryResult, DiscoverySummary

        summary = DiscoverySummary(**summary_kwargs)
        return DiscoveryResult(
            schema_version="1.0",
            account_id=ACCT,
            account_alias=ALIAS,
            generated_at="2026-01-01T00:00:00+00:00",
            regions_scanned=["us-east-1"],
            ec2_instances=[],
            ec2_attached_volumes=[],
            ec2_unattached_volumes=[],
            rds_instances=[],
            dynamodb_tables=[],
            efs_filesystems=[],
            fsx_filesystems=[],
            s3_buckets=[],
            kms_counts=[],
            secrets_counts=[],
            sqs_counts=[],
            backup_plans=[],
            backup_costs=[],
            summary=summary,
        )

    def test_defaults_to_false(self):
        result = self._make_result()
        assert result.scp_restrictions_suspected is False

    def test_can_be_set_true(self):
        result = self._make_result()
        result.scp_restrictions_suspected = True
        assert result.scp_restrictions_suspected is True

    def test_serialises_into_dict(self):
        result = self._make_result()
        result.scp_restrictions_suspected = True
        d = _to_dict(result)
        assert d["scp_restrictions_suspected"] is True


class TestDenialTracker:
    """DenialTracker accumulates SCP-denied service names in a thread-safe way."""

    def test_empty_tracker_is_falsy(self):
        from collectors import DenialTracker

        tracker = DenialTracker()
        assert not tracker

    def test_record_makes_truthy(self):
        from collectors import DenialTracker

        tracker = DenialTracker()
        tracker.record("ec2")
        assert tracker

    def test_denied_services_returns_frozenset(self):
        from collectors import DenialTracker

        tracker = DenialTracker()
        tracker.record("ec2")
        tracker.record("rds")
        assert tracker.denied_services() == frozenset({"ec2", "rds"})

    def test_duplicate_records_deduplicated(self):
        from collectors import DenialTracker

        tracker = DenialTracker()
        tracker.record("s3")
        tracker.record("s3")
        assert tracker.denied_services() == frozenset({"s3"})

    def test_is_scp_denial_explicit_deny(self):
        from collectors import is_scp_denial

        class FakeExc(Exception):
            pass

        assert is_scp_denial(FakeExc("explicit deny in a service_control_policy"))
        assert is_scp_denial(FakeExc("AccessDeniedException: explicit deny"))
        assert not is_scp_denial(FakeExc("AccessDenied: some other reason"))


class TestScanErrorsReachOutput:
    def _run(self, tmp_path, monkeypatch, tracker):
        from unittest.mock import MagicMock

        import main

        empty_agg = {
            k: []
            for k in (
                "instances",
                "attached",
                "unattached",
                "rds",
                "dynamodb",
                "efs",
                "fsx",
                "s3",
                "kms",
                "secrets",
                "sqs",
                "plans",
                "vaults",
                "cfn",
            )
        }
        monkeypatch.setattr(main, "_scan_all_regions", lambda *a, **k: empty_agg)
        session = MagicMock()
        session.client.return_value.get_caller_identity.return_value = {"Account": ACCT}
        session.client.return_value.list_account_aliases.return_value = {"AccountAliases": []}
        path = main.run(
            output_dir=str(tmp_path),
            session=session,
            regions=[REGION],
            collect_cost=False,
            denial_tracker=tracker,
        )
        return json.loads(open(path).read())

    def test_permission_errors_are_written_without_an_scp_denial(self, tmp_path, monkeypatch):
        from collectors import DenialTracker

        tracker = DenialTracker()
        tracker.record_permission_error("cloudwatch", REGION, Exception("2 throttled"))
        data = self._run(tmp_path, monkeypatch, tracker)
        assert [e["service"] for e in data["scan_errors"]] == ["cloudwatch"]
        assert data["scp_restrictions_suspected"] is False

    def test_scp_denial_sets_the_flag_and_keeps_errors(self, tmp_path, monkeypatch):
        from collectors import DenialTracker

        tracker = DenialTracker()
        tracker.record("ec2")
        tracker.record_permission_error("rds", REGION, Exception("AccessDenied"))
        data = self._run(tmp_path, monkeypatch, tracker)
        assert data["scp_restrictions_suspected"] is True
        assert [e["service"] for e in data["scan_errors"]] == ["rds"]


class TestRunWithoutDenialTracker:
    """run() is called with no denial_tracker at all in the CLI's single-account
    path (main()'s plain `run(output_dir=..., ...)` call, used by `aws-sizing
    --output ./output` for testing accounts without the StackSet role). It must
    not assume a tracker is present."""

    def test_run_succeeds_with_denial_tracker_none(self, tmp_path, monkeypatch):
        from unittest.mock import MagicMock

        import main

        empty_agg = {
            "instances": [],
            "attached": [],
            "unattached": [],
            "rds": [],
            "dynamodb": [],
            "efs": [],
            "fsx": [],
            "s3": [],
            "kms": [],
            "secrets": [],
            "sqs": [],
            "plans": [],
            "vaults": [],
            "cfn": [],
        }
        monkeypatch.setattr(main, "_scan_all_regions", lambda *a, **k: empty_agg)

        session = MagicMock()
        session.client.return_value.get_caller_identity.return_value = {"Account": ACCT}
        session.client.return_value.list_account_aliases.return_value = {"AccountAliases": []}

        json_path = main.run(
            output_dir=str(tmp_path),
            session=session,
            regions=[REGION],
            collect_cost=False,
            denial_tracker=None,
        )

        data = json.loads(open(json_path).read())
        assert data["scan_errors"] == []
        assert data["scp_restrictions_suspected"] is False

    def test_errors_are_still_written_to_scan_errors_when_no_tracker_is_passed(
        self, tmp_path, monkeypatch
    ):
        from unittest.mock import MagicMock

        import main

        def scan(session, regions, account_id, alias, services, tracker):
            tracker.record_permission_error("cost", "global", Exception("access denied"))
            return {
                k: []
                for k in (
                    "instances",
                    "attached",
                    "unattached",
                    "rds",
                    "dynamodb",
                    "efs",
                    "fsx",
                    "s3",
                    "kms",
                    "secrets",
                    "sqs",
                    "plans",
                    "vaults",
                    "cfn",
                )
            }

        monkeypatch.setattr(main, "_scan_all_regions", scan)
        session = MagicMock()
        session.client.return_value.get_caller_identity.return_value = {"Account": ACCT}
        session.client.return_value.list_account_aliases.return_value = {"AccountAliases": []}
        json_path = main.run(
            output_dir=str(tmp_path), session=session, regions=[REGION], collect_cost=False
        )
        data = json.loads(open(json_path).read())
        assert [(e["service"], e["region"]) for e in data["scan_errors"]] == [("cost", "global")]

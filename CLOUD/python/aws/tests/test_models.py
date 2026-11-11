"""Tests for models/discovery.py — dataclass instantiation and serialisation."""

import dataclasses

import pytest
from models.discovery import (
    BackupCostEntry,
    BackupPlan,
    BackupRule,
    DiscoveryResult,
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


class TestEC2Instance:
    def test_roundtrip(self):
        inst = EC2Instance(
            account_id=ACCT,
            account_alias=ALIAS,
            instance_id="i-abc",
            name="web",
            instance_type="t3.micro",
            platform="linux",
            state="running",
            vcpus=2,
            memory_gib=1.0,
            region=REGION,
            volume_count=1,
            size_gib=20,
            size_tb=0.02,
            size_bytes_derived=20 * 1024**3,
            in_backup_plan=True,
            backup_plans=["AWS Backup"],
            tags={"Env": "prod"},
        )
        d = dataclasses.asdict(inst)
        assert d["instance_id"] == "i-abc"
        assert d["in_backup_plan"] is True
        assert d["backup_plans"] == ["AWS Backup"]
        assert d["tags"] == {"Env": "prod"}
        assert d["size_bytes_derived"] == 20 * 1024**3

    def test_unprotected_defaults(self):
        inst = EC2Instance(
            account_id=ACCT,
            account_alias=ALIAS,
            instance_id="i-def",
            name="",
            instance_type="m5.large",
            platform="windows",
            state="stopped",
            vcpus=4,
            memory_gib=16.0,
            region=REGION,
            volume_count=0,
            size_gib=0,
            size_tb=0.0,
            size_bytes_derived=0,
            in_backup_plan=False,
            backup_plans=[],
            tags={},
        )
        assert inst.in_backup_plan is False
        assert inst.backup_plans == []


class TestEC2Volume:
    def test_roundtrip(self):
        vol = EC2Volume(
            account_id=ACCT,
            account_alias=ALIAS,
            volume_id="vol-1",
            instance_id="i-1",
            instance_name="web",
            name="root",
            device_name="/dev/xvda",
            size_gib=100,
            size_tb=0.097656,
            size_bytes_derived=100 * 1024**3,
            region=REGION,
            availability_zone="us-east-1a",
            volume_type="gp3",
            state="in-use",
            iops=3000,
            throughput=125,
            encrypted=True,
            in_backup_plan=False,
            backup_plans=[],
            tags={},
        )
        d = dataclasses.asdict(vol)
        assert d["volume_id"] == "vol-1"
        assert d["encrypted"] is True
        assert d["iops"] == 3000
        assert d["size_bytes_derived"] == 100 * 1024**3


class TestDiscoverySummary:
    def test_defaults_are_zero(self):
        s = DiscoverySummary()
        assert s.total_ec2_instances == 0
        assert s.total_ec2_protected == 0
        assert s.ec2_protection_pct == 0.0
        assert s.total_disk_tb == 0.0
        assert s.total_12mo_backup_spend_usd == 0.0

    def test_asdict_serialisable(self):
        s = DiscoverySummary(total_ec2_instances=5, total_ec2_protected=3)
        d = dataclasses.asdict(s)
        assert d["total_ec2_instances"] == 5
        assert d["total_ec2_protected"] == 3


class TestDiscoveryResult:
    def _make_result(self):
        return DiscoveryResult(
            schema_version="1.0",
            account_id=ACCT,
            account_alias=ALIAS,
            generated_at="2024-01-01T00:00:00+00:00",
            regions_scanned=["us-east-1", "us-west-2"],
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
        )

    def test_default_summary(self):
        r = self._make_result()
        assert isinstance(r.summary, DiscoverySummary)

    def test_regions_scanned(self):
        r = self._make_result()
        assert "us-east-1" in r.regions_scanned
        assert len(r.regions_scanned) == 2

    def test_asdict_serialisable(self):
        r = self._make_result()
        d = dataclasses.asdict(r)
        assert d["schema_version"] == "1.0"
        assert d["ec2_instances"] == []
        assert isinstance(d["summary"], dict)


class TestBackupRule:
    def test_roundtrip(self):
        rule = BackupRule(
            rule_name="daily",
            vault_name="Default",
            schedule="cron(0 5 ? * * *)",
            start_window_minutes=60,
            completion_window_minutes=180,
            delete_after_days=35,
            cold_storage_after_days=0,
        )
        d = dataclasses.asdict(rule)
        assert d["rule_name"] == "daily"
        assert d["delete_after_days"] == 35


class TestDynamoDBTable:
    def test_size_fields(self):
        t = DynamoDBTable(
            account_id=ACCT,
            account_alias=ALIAS,
            region=REGION,
            table_name="users",
            table_id="tid",
            table_arn="arn:aws:dynamodb:::table/users",
            size_bytes=1_073_741_824,
            size_gib=1.0,
            size_tb=0.000977,
            item_count=10000,
            status="ACTIVE",
            deletion_protection=False,
            read_capacity_units=5,
            write_capacity_units=5,
            pitr_enabled=False,
            in_backup_plan=False,
            backup_plans=[],
        )
        assert t.size_bytes == 1_073_741_824
        assert t.size_gib == 1.0


class TestBackupCostEntry:
    def test_float_amounts(self):
        e = BackupCostEntry(
            account_id=ACCT,
            account_alias=ALIAS,
            period_start="2024-01-01",
            period_end="2024-02-01",
            amortized_cost=123.45,
            blended_cost=124.00,
            unblended_cost=123.00,
        )
        assert isinstance(e.amortized_cost, float)
        assert e.amortized_cost == pytest.approx(123.45)

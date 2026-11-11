"""Tests for the FSx file system and volume collectors and CSV rows."""

import csv
import io
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import csv_export as ce
import pytest
from collectors import DenialTracker
from collectors.fsx import fetch_fsx, fetch_fsx_volumes

ACCT = "123456789012"
REGION = "us-west-2"
GIB = 1073741824


def _points(statistic, values):
    now = datetime.now(timezone.utc)
    return [{statistic: v, "Timestamp": now - timedelta(hours=i)} for i, v in enumerate(values)]


def _session(file_systems=(), volumes=(), metrics=None, metric_error=None):
    """metrics: (metric name, statistic) -> list of datapoint values."""
    metrics = metrics or {}
    calls = []

    fsx = MagicMock()

    def paginator(operation):
        p = MagicMock()
        if operation == "describe_file_systems":
            p.paginate.return_value = [{"FileSystems": list(file_systems)}]
        else:
            p.paginate.return_value = [{"Volumes": list(volumes)}]
        return p

    fsx.get_paginator.side_effect = paginator

    cw = MagicMock()

    def stats(**kw):
        calls.append(kw)
        if metric_error is not None:
            raise metric_error
        stat = kw["Statistics"][0]
        return {"Datapoints": _points(stat, metrics.get((kw["MetricName"], stat), []))}

    cw.get_metric_statistics.side_effect = stats
    session = MagicMock()
    session.client.side_effect = lambda service, **kw: {"fsx": fsx, "cloudwatch": cw}[service]
    return session, calls


def _fs(fs_id, kind, capacity=1024, **extra):
    config = {
        "ontap": "OntapConfiguration",
        "windows": "WindowsConfiguration",
        "lustre": "LustreConfiguration",
        "openzfs": "OpenZFSConfiguration",
    }[kind]
    return {
        "FileSystemId": fs_id,
        "FileSystemType": kind.upper(),
        "FileSystemTypeVersion": "2.15",
        "OwnerId": ACCT,
        "StorageType": "SSD",
        "StorageCapacity": capacity,
        "DNSName": f"{fs_id}.fsx.example",
        "ResourceARN": f"arn:aws:fsx:{REGION}:{ACCT}:file-system/{fs_id}",
        "Lifecycle": "AVAILABLE",
        "Tags": [{"Key": "Name", "Value": f"name-{fs_id}"}, {"Key": "team", "Value": "x"}],
        config: {},
        **extra,
    }


# ── file systems ──────────────────────────────────────────────────────────────


def test_each_type_reads_its_own_metric_over_seven_days_at_hourly_period():
    session, calls = _session(
        [_fs("fs-o", "ontap")], metrics={("StorageUsed", "Maximum"): [10, 50, 30]}
    )
    [fs] = fetch_fsx(session, REGION, ACCT, "", set())
    assert fs.config_type == "ontap" and fs.usage_metrics == {"StorageUsed": 50.0}
    [call] = calls
    assert call["Namespace"] == "AWS/FSx" and call["Period"] == 3600
    assert call["EndTime"] - call["StartTime"] == timedelta(days=7)
    assert call["Dimensions"] == [{"Name": "FileSystemId", "Value": "fs-o"}]


def test_windows_and_openzfs_metrics():
    session, _ = _session(
        [_fs("fs-w", "windows"), _fs("fs-z", "openzfs")],
        metrics={
            ("StorageCapacityUtilization", "Maximum"): [20.5, 71.25],
            ("UsedStorageCapacity", "Maximum"): [5, 9],
        },
    )
    windows, zfs = fetch_fsx(session, REGION, ACCT, "", set())
    assert windows.usage_metrics == {"StorageCapacityUtilizationPercentage": 71.25}
    assert zfs.usage_metrics == {"UsedStorageCapacity": 9.0}


def test_lustre_uses_peak_hourly_sum_for_usage_and_lowest_for_free_capacity():
    session, calls = _session(
        [_fs("fs-l", "lustre")],
        metrics={
            ("PhysicalDiskUsage", "Sum"): [100, 400, 300],
            ("LogicalDiskUsage", "Sum"): [50, 70],
            ("FreeDataStorageCapacity", "Sum"): [900, 200, 500],
        },
    )
    [fs] = fetch_fsx(session, REGION, ACCT, "", set())
    assert fs.usage_metrics == {
        "PhysicalDiskUsage": 400.0,
        "LogicalDiskUsage": 70.0,
        "FreeDataStorageCapacity": 200.0,
    }
    assert {c["Statistics"][0] for c in calls} == {"Sum"}


def test_no_datapoints_gives_none_and_a_failed_call_is_recorded():
    session, _ = _session([_fs("fs-o", "ontap")])
    [fs] = fetch_fsx(session, REGION, ACCT, "", set())
    assert fs.usage_metrics == {"StorageUsed": None}
    tracker = DenialTracker()
    session, _ = _session([_fs("fs-o", "ontap")], metric_error=Exception("Throttling"))
    [fs] = fetch_fsx(session, REGION, ACCT, "", set(), tracker)
    assert fs.usage_metrics == {"StorageUsed": None}
    assert [e["service"] for e in tracker.permission_errors()] == ["cloudwatch"]


def test_file_system_fields_and_backup_plan_membership():
    arn = f"arn:aws:fsx:{REGION}:{ACCT}:file-system/fs-o"
    session, _ = _session([_fs("fs-o", "ontap", capacity=2048)])
    [fs] = fetch_fsx(session, REGION, ACCT, "alias", {arn})
    assert (fs.file_system_type, fs.file_system_type_version, fs.owner_id) == (
        "ONTAP",
        "2.15",
        ACCT,
    )
    assert fs.storage_capacity_gib == 2048 and fs.in_backup_plan and fs.name == "name-fs-o"
    assert fs.dns_name == "fs-o.fsx.example" and fs.tags["team"] == "x"


def test_listing_failure_is_recorded():
    session, _ = _session()
    session.client("fsx").get_paginator.side_effect = Exception("AccessDenied: fsx")
    tracker = DenialTracker()
    assert fetch_fsx(session, REGION, ACCT, "", set(), tracker) == []
    assert [e["service"] for e in tracker.permission_errors()] == ["fsx"]


# ── volumes ───────────────────────────────────────────────────────────────────


def _volume(volume_id="fsvol-1", fs_id="fs-o"):
    return {
        "VolumeId": volume_id,
        "FileSystemId": fs_id,
        "Name": "vol-name",
        "VolumeType": "ONTAP",
        "Lifecycle": "CREATED",
        "ResourceARN": f"arn:aws:fsx:{REGION}:{ACCT}:volume/{fs_id}/{volume_id}",
        "Tags": [{"Key": "env", "Value": "prod"}],
    }


def test_volumes_read_used_and_capacity_with_both_dimensions_and_copy_parent_details():
    parent_session, _ = _session([_fs("fs-o", "ontap")])
    [parent] = fetch_fsx(parent_session, REGION, ACCT, "", set())
    session, calls = _session(
        volumes=[_volume()],
        metrics={
            ("StorageUsed", "Maximum"): [100, 300],
            ("StorageCapacity", "Maximum"): [1000, 2000],
        },
    )
    [vol] = fetch_fsx_volumes(session, REGION, ACCT, "", set(), [parent])
    assert (vol.storage_used_bytes, vol.storage_capacity_bytes) == (300.0, 2000.0)
    assert {d["Name"] for d in calls[0]["Dimensions"]} == {"FileSystemId", "VolumeId"}
    assert vol.file_system_dns_name == "fs-o.fsx.example" and vol.file_system_type == "ONTAP"
    assert vol.file_system_owner_id == ACCT and vol.tags == {"env": "prod"}
    assert vol.volume_type == "ONTAP" and vol.lifecycle == "CREATED"


def test_volume_whose_file_system_is_unknown_keeps_blank_parent_fields_and_backup_flag():
    session, _ = _session(volumes=[_volume(fs_id="fs-gone")])
    arn = f"arn:aws:fsx:{REGION}:{ACCT}:volume/fs-gone/fsvol-1"
    [vol] = fetch_fsx_volumes(session, REGION, ACCT, "", {arn}, [])
    assert vol.file_system_dns_name == "" and vol.in_backup_plan is True
    assert vol.storage_used_bytes is None


def test_volume_listing_failure_is_recorded():
    session, _ = _session()
    session.client("fsx").get_paginator.side_effect = Exception("AccessDenied: fsx")
    tracker = DenialTracker()
    assert fetch_fsx_volumes(session, REGION, ACCT, "", set(), [], tracker) == []
    assert [e["service"] for e in tracker.permission_errors()] == ["fsx"]


# ── CSV rows ──────────────────────────────────────────────────────────────────

STAMP = "T"


def _table(result, prefix):
    files = ce.build_csv_files([result], STAMP)
    rows = list(csv.reader(io.StringIO(files[f"{prefix}-{STAMP}.csv"])))
    return rows[0], [dict(zip(rows[0], r)) for r in rows[1:]], files[f"{prefix}-{STAMP}.csv"]


def _fs_record(fs_id, kind, usage, tags=None, **extra):
    return dict(
        account_id=ACCT,
        account_alias="",
        region=REGION,
        file_system_id=fs_id,
        file_system_type=kind.upper(),
        file_system_type_version="2.15",
        owner_id=ACCT,
        storage_type="SSD",
        storage_capacity_gib=1024,
        dns_name=f"{fs_id}.example",
        config_type=kind,
        usage_metrics=usage,
        tags=tags if tags is not None else {"Name": "n", "team": "x"},
        in_backup_plan=False,
        **extra,
    )


def test_file_system_row_matches_the_powershell_columns():
    header, [row], _ = _table(
        {"fsx_filesystems": [_fs_record("fs-o", "ontap", {"StorageUsed": 2.0 * GIB})]},
        "aws_fsx_filesystem_info",
    )
    assert header[:6] == [
        "AwsAccountId",
        "AwsAccountAlias",
        "Region",
        "FileSystemId",
        "ResourceArn",
        "FileSystemDNSName",
    ]
    assert row["ResourceArn"] == f"arn:aws:fsx:{REGION}:{ACCT}:file-system/fs-o"
    assert (row["OnTapType"], row["WindowsType"], row["LustreType"], row["OpenZFSType"]) == (
        "True",
        "False",
        "False",
        "False",
    )
    assert row["StorageCapacityBytes"] == str(1024 * GIB)
    assert (row["StorageCapacityGiB"], row["StorageCapacityTiB"]) == ("1024", "1")
    assert row["StorageCapacityGB"] == "1099.5116" and row["StorageCapacityTB"] == "1.0995"
    assert row["StorageUsedBytes"] == str(2 * GIB) and row["StorageUsedGiB"] == "2"
    assert row["StorageUsedGB"] == "2.1475" and row["Name"] == "n" and row["Tag: team"] == "x"
    assert "Tag: Name" not in header


def test_columns_are_the_first_seen_union_and_missing_cells_are_blank():
    result = {
        "fsx_filesystems": [
            _fs_record("fs-o", "ontap", {"StorageUsed": 1.0 * GIB}, {"a": "1"}),
            _fs_record(
                "fs-w", "windows", {"StorageCapacityUtilizationPercentage": 42.5}, {"b": "2"}
            ),
        ]
    }
    header, rows, _ = _table(result, "aws_fsx_filesystem_info")
    assert header.index("Tag: a") < header.index("StorageCapacityUtilizationPercentage")
    first, second = rows
    assert first["StorageCapacityUtilizationPercentage"] == "" and second["StorageUsedBytes"] == ""
    assert second["StorageCapacityUtilizationPercentage"] == "42.5" and second["Tag: a"] == ""


def test_no_datapoint_leaves_bytes_blank_and_units_zero_and_a_missing_name_is_blank():
    _, [row], text = _table(
        {"fsx_filesystems": [_fs_record("fs-o", "ontap", {"StorageUsed": None}, tags={})]},
        "aws_fsx_filesystem_info",
    )
    assert row["StorageUsedBytes"] == "" and row["StorageUsedGiB"] == "0" and row["Name"] == ""
    assert '"fs-o.example","ONTAP","2.15"' in text and ",," in text


def test_lustre_columns_come_with_five_units_each():
    usage = {
        "PhysicalDiskUsage": 1.0 * GIB,
        "LogicalDiskUsage": 2.0 * GIB,
        "FreeDataStorageCapacity": 3.0 * GIB,
    }
    header, [row], _ = _table(
        {"fsx_filesystems": [_fs_record("fs-l", "lustre", usage)]}, "aws_fsx_filesystem_info"
    )
    for prefix, gib in (
        ("PhysicalDiskUsage", "1"),
        ("LogicalDiskUsage", "2"),
        ("FreeDataStorageCapacity", "3"),
    ):
        assert [c for c in header if c.startswith(prefix)] == [
            f"{prefix}Bytes",
            f"{prefix}GiB",
            f"{prefix}TiB",
            f"{prefix}GB",
            f"{prefix}TB",
        ]
        assert row[f"{prefix}GiB"] == gib


def test_volume_row():
    record = dict(
        account_id=ACCT,
        account_alias="",
        region=REGION,
        file_system_id="fs-o",
        volume_id="fsvol-1",
        name="vol-name",
        volume_type="ONTAP",
        lifecycle="CREATED",
        resource_arn="arn:vol",
        storage_used_bytes=1.5 * GIB,
        storage_capacity_bytes=None,
        in_backup_plan=False,
        file_system_dns_name="d",
        file_system_type="ONTAP",
        tags={"env": "prod", "Name": "ignored"},
    )
    header, [row], _ = _table({"fsx_volumes": [record]}, "aws_fsx_volume_info")
    assert row["StorageUsedBytes"] == str(int(1.5 * GIB)) and row["StorageUsedGiB"] == "1.5"
    assert row["StorageCapacityBytes"] == "" and row["StorageCapacityGiB"] == "0"
    assert row["LifeCycle"] == "CREATED" and row["Tag: env"] == "prod" and "Tag: Name" not in header
    assert header.index("StorageUsedBytes") < header.index("StorageCapacityBytes")


def test_no_fsx_gives_empty_files_like_powershell():
    # a bare Export-Csv of an empty list leaves a zero-byte file
    files = ce.build_csv_files([{}], STAMP)
    for prefix in ("aws_fsx_filesystem_info", "aws_fsx_volume_info"):
        assert files[f"{prefix}-{STAMP}.csv"] == ""

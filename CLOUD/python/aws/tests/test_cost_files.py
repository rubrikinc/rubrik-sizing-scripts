"""Tests for the AWS Backup and snapshot storage cost collectors and their CSVs."""

import csv
import io
from datetime import datetime
from unittest.mock import MagicMock

import csv_export as ce
import pytest
from botocore.exceptions import ClientError
from collectors import DenialTracker
from collectors.cost import (
    CE_METRICS,
    ce_time_period,
    fetch_backup_cost_months,
    fetch_snapshot_storage_costs,
    is_snapshot_usage_type,
)

ACCT = "123456789012"
NOW = datetime(2026, 10, 5, 14, 6)


def _amounts(**values):
    return {m: {"Amount": str(values.get(m, 0)), "Unit": "USD"} for m in CE_METRICS}


def _client_error(code, message="boom"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "GetCostAndUsage")


def _session(ce_client):
    session = MagicMock()
    session.client.side_effect = lambda service, **kw: ce_client
    return session


# ── window and classifier ─────────────────────────────────────────────────────


def test_window_is_the_first_of_the_month_a_year_ago_until_today():
    assert ce_time_period(NOW) == {"Start": "2025-10-01", "End": "2026-10-05"}
    assert ce_time_period(datetime(2026, 1, 31)) == {"Start": "2025-01-01", "End": "2026-01-31"}


@pytest.mark.parametrize(
    "usage_type, expected",
    [
        ("EBS:SnapshotUsage", True),
        ("Aurora:BackupUsage", True),
        ("RDS:ChargedBackupUsage", True),
        ("ContinuousBackupUsage", True),
        ("EFS-Backup-ByteHrs", False),  # counted under EFS
        ("S3-Backup-Storage", False),
        ("AWSBackup-Storage", False),  # counted by the AWS Backup service query
        ("DynamoDB-Backup-Advanced-Storage", False),
        ("Requests-Tier1", False),
        ("ebs:snapshotusage", True),  # case-insensitive, like PowerShell
    ],
)
def test_snapshot_usage_type_classifier(usage_type, expected):
    assert is_snapshot_usage_type(usage_type) is expected


# ── AWS Backup cost by month ──────────────────────────────────────────────────


def test_backup_cost_months_keep_every_metric_and_follow_pagination():
    client = MagicMock()
    page1 = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": "2025-10-01", "End": "2025-11-01"},
                "Total": _amounts(AmortizedCost=1.5, UsageQuantity=2),
            }
        ],
        "NextPageToken": "t2",
    }
    page2 = {
        "ResultsByTime": [
            {"TimePeriod": {"Start": "2025-11-01", "End": "2025-12-01"}, "Total": _amounts()}
        ]
    }
    client.get_cost_and_usage.side_effect = [page1, page2]
    months = fetch_backup_cost_months(_session(client), ACCT, "", now=NOW)
    assert [m.period_start for m in months] == ["2025-10-01", "2025-11-01"]
    assert months[0].amounts["AmortizedCost"] == 1.5 and set(months[0].amounts) == set(CE_METRICS)
    first, second = client.get_cost_and_usage.call_args_list
    assert first.kwargs["Filter"] == {"Dimensions": {"Key": "SERVICE", "Values": ["AWS Backup"]}}
    assert first.kwargs["TimePeriod"] == {"Start": "2025-10-01", "End": "2026-10-05"}
    assert "NextPageToken" not in first.kwargs and second.kwargs["NextPageToken"] == "t2"


@pytest.mark.parametrize(
    "code, expected",
    [("AccessDeniedException", "access denied"), ("DataUnavailableException", "no data")],
)
def test_backup_cost_failures_are_recorded_not_raised(code, expected):
    client = MagicMock()
    client.get_cost_and_usage.side_effect = _client_error(code)
    tracker = DenialTracker()
    assert fetch_backup_cost_months(_session(client), ACCT, "", tracker, NOW) == []
    [error] = tracker.permission_errors()
    assert error["service"] == "cost" and expected in error["error"]


def test_other_cost_failures_are_recorded_too():
    client = MagicMock()
    client.get_cost_and_usage.side_effect = _client_error("InternalFailure")
    tracker = DenialTracker()
    assert fetch_backup_cost_months(_session(client), ACCT, "", tracker, NOW) == []
    assert [e["service"] for e in tracker.permission_errors()] == ["cost"]


# ── snapshot storage costs ────────────────────────────────────────────────────


def _dimension_client(usage_types, cost_pages):
    client = MagicMock()
    client.get_dimension_values.return_value = {
        "DimensionValues": [{"Value": u} for u in usage_types]
    }
    client.get_cost_and_usage.side_effect = cost_pages
    return client


def _group(service, usage_type, unit="GB-Month", **values):
    metrics = _amounts(**values)
    metrics["UsageQuantity"]["Unit"] = unit
    return {"Keys": [service, usage_type], "Metrics": metrics}


def test_only_snapshot_usage_types_are_queried_and_rows_keep_api_order():
    usage_types = [
        "USW2-EBS:SnapshotUsage",
        "USW2-Requests-Tier1",
        "USE2-AWSBackup-Storage",
        "USE2-EFS-Backup-ByteHrs",
        "USE2-Aurora:BackupUsage",
    ]
    period = {
        "TimePeriod": {"Start": "2026-09-01", "End": "2026-10-01"},
        "Groups": [
            _group("EC2 - Other", "USW2-EBS:SnapshotUsage", UsageQuantity=25.2, UnblendedCost=1.06),
            _group("Tax", "USW2-EBS:SnapshotUsage", unit=""),
            _group("Amazon Relational Database Service", "USE2-Aurora:BackupUsage"),
        ],
    }
    client = _dimension_client(usage_types, [{"ResultsByTime": [period]}])
    rows = fetch_snapshot_storage_costs(_session(client), ACCT, "", now=NOW)
    sent = client.get_cost_and_usage.call_args.kwargs
    assert sent["Filter"]["Dimensions"]["Values"] == [
        "USW2-EBS:SnapshotUsage",
        "USE2-Aurora:BackupUsage",
    ]
    assert [g["Key"] for g in sent["GroupBy"]] == ["SERVICE", "USAGE_TYPE"]
    assert [(r.service, r.usage_type, r.usage_unit) for r in rows] == [
        ("EC2 - Other", "USW2-EBS:SnapshotUsage", "GB-Month"),
        ("Tax", "USW2-EBS:SnapshotUsage", ""),
        ("Amazon Relational Database Service", "USE2-Aurora:BackupUsage", "GB-Month"),
    ]
    assert rows[0].amounts["UsageQuantity"] == 25.2 and rows[0].amounts["UnblendedCost"] == 1.06


def test_usage_types_are_queried_in_chunks_of_200():
    usage_types = [f"USE1-Snap-{i}Snapshot" for i in range(450)]
    client = _dimension_client(usage_types, [{"ResultsByTime": []}] * 3)
    fetch_snapshot_storage_costs(_session(client), ACCT, "", now=NOW)
    sizes = [
        len(c.kwargs["Filter"]["Dimensions"]["Values"])
        for c in client.get_cost_and_usage.call_args_list
    ]
    assert sizes == [200, 200, 50]


def test_validation_error_retries_the_same_slice_with_100_per_call():
    usage_types = [f"USE1-{i}Snapshot" for i in range(250)]
    pages = [_client_error("ValidationException")] + [{"ResultsByTime": []}] * 3
    client = _dimension_client(usage_types, pages)
    fetch_snapshot_storage_costs(_session(client), ACCT, "", now=NOW)
    sizes = [
        len(c.kwargs["Filter"]["Dimensions"]["Values"])
        for c in client.get_cost_and_usage.call_args_list
    ]
    assert sizes == [200, 100, 100, 50]


def test_dimension_values_follow_pagination():
    client = MagicMock()
    client.get_dimension_values.side_effect = [
        {"DimensionValues": [{"Value": "USE1-A-Snapshot"}], "NextPageToken": "n"},
        {"DimensionValues": [{"Value": "USE1-B-Snapshot"}]},
    ]
    client.get_cost_and_usage.return_value = {"ResultsByTime": []}
    fetch_snapshot_storage_costs(_session(client), ACCT, "", now=NOW)
    assert client.get_cost_and_usage.call_args.kwargs["Filter"]["Dimensions"]["Values"] == [
        "USE1-A-Snapshot",
        "USE1-B-Snapshot",
    ]


def test_no_matching_usage_types_means_no_cost_query():
    client = _dimension_client(["USW2-Requests-Tier1"], [])
    assert fetch_snapshot_storage_costs(_session(client), ACCT, "", now=NOW) == []
    client.get_cost_and_usage.assert_not_called()


def test_snapshot_cost_failure_is_recorded_and_returns_nothing():
    client = MagicMock()
    client.get_dimension_values.side_effect = _client_error("AccessDeniedException")
    tracker = DenialTracker()
    assert fetch_snapshot_storage_costs(_session(client), ACCT, "", tracker, NOW) == []
    assert [e["service"] for e in tracker.permission_errors()] == ["cost"]


# ── CSV rows ──────────────────────────────────────────────────────────────────


def _cost_result():
    return {
        "backup_cost_months": [
            dict(
                account_id=ACCT,
                account_alias="",
                period_start="2025-10-01",
                period_end="2025-11-01",
                amounts={"AmortizedCost": 1.234, "UnblendedCost": 12.5, "UsageQuantity": 0.12345},
            )
        ],
        "snapshot_storage_costs": [
            dict(
                account_id=ACCT,
                account_alias="",
                period_start="2025-10-01",
                period_end="2025-11-01",
                service="Tax",
                usage_type="USW2-EBS:SnapshotUsage",
                usage_unit="",
                amounts={
                    "UsageQuantity": 3.77354,
                    "BlendedCost": 0.1555,
                    "NormalizedUsageAmount": 2,
                },
            )
        ],
    }


def _table(files, prefix):
    rows = list(csv.reader(io.StringIO(files[f"{prefix}-T.csv"])))
    return rows[0], [dict(zip(rows[0], r)) for r in rows[1:]]


def test_backup_cost_csv_formats_money_and_numbers_like_powershell():
    header, [row] = _table(ce.build_csv_files([_cost_result()], "T"), "aws_backup_costs")
    assert header[:4] == ["AwsAccountId", "AwsAccountAlias", "Time-Period-Start", "Time-Period-End"]
    assert row["AWSBackupAmortizedCost"] == "$1.23" and row["AWSBackupUnblendedCost"] == "$12.5"
    assert row["AWSBackupBlendedCost"] == "$0" and row["AWSBackupUsageQuantity"] == "0.123"
    assert row["AWSBackupNormalizedUsageAmount"] == "0"


def test_snapshot_cost_csv_rounds_and_quotes_an_empty_unit():
    files = ce.build_csv_files([_cost_result()], "T")
    header, [row] = _table(files, "aws_snapshot_storage_costs")
    assert row["UsageQuantity"] == "3.7735" and row["BlendedCost"] == "$0.16"
    assert row["NormalizedUsageAmount"] == "2" and row["UsageUnit"] == ""
    assert ',"",' in files["aws_snapshot_storage_costs-T.csv"].splitlines()[1]
    assert len(header) == 14


def test_cost_files_without_cost_data_are_powershells_header_only_fallbacks():
    files = ce.build_csv_files([{"account_id": ACCT, "account_alias": ""}], "T")
    costs = files["aws_backup_costs-T.csv"].splitlines()
    # the script writes a #TYPE line and a quoted header for the backup costs
    assert costs[0] == "#TYPE System.Management.Automation.PSCustomObject" and len(costs) == 2
    assert costs[1].startswith('"AwsAccountId","AwsAccountAlias","Time-Period-Start"')
    # and one unquoted header line for the snapshot storage costs
    snapshot = files["aws_snapshot_storage_costs-T.csv"].splitlines()
    assert len(snapshot) == 1 and snapshot[0].startswith("AwsAccountId,AwsAccountAlias,")

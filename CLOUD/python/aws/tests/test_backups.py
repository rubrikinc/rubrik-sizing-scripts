"""Tests for AWS Backup recovery points, the native FSx/DynamoDB/Redshift backups and the merge."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from collectors import DenialTracker
from collectors.recovery_points import (
    fetch_recovery_points,
    is_access_denied,
    list_plan_names,
    resource_id_from_arn,
)
from collectors.snapshots import (
    NativeBackup,
    apply_backup_summaries,
    backup_key,
    fetch_dynamodb_backups,
    fetch_fsx_backups,
    fetch_redshift_snapshots,
    merge_backups,
    recovery_point_keys,
)
from models.discovery import BackupSummary, DynamoDBTable, RecoveryPointAggregate

ACCT = "123456789012"
REGION = "us-west-2"


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Op")


def _day(d, h=0):
    return datetime(2026, 9, d, h, tzinfo=timezone.utc)


# ── helpers ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "arn, expected",
    [
        (f"arn:aws:ec2:{REGION}:{ACCT}:instance/i-0123", "i-0123"),
        (f"arn:aws:ec2:{REGION}:{ACCT}:volume/vol-9", "vol-9"),
        (f"arn:aws:rds:{REGION}:{ACCT}:db:mydb", "mydb"),
        ("arn:aws:s3:::my-bucket", "my-bucket"),
        (f"arn:aws:fsx:{REGION}:{ACCT}:file-system/fs-1", "fs-1"),
        ("", ""),
    ],
)
def test_resource_id_from_arn(arn, expected):
    assert resource_id_from_arn(arn) == expected


def test_access_denied_family():
    assert is_access_denied(_client_error("AccessDeniedException"))
    assert is_access_denied(_client_error("UnauthorizedOperation"))
    assert is_access_denied(_client_error("AuthFailure"))
    assert not is_access_denied(_client_error("ThrottlingException"))
    assert not is_access_denied(ValueError("nope"))


# ── recovery points ───────────────────────────────────────────────────────────


def _rp(arn, vault="v1", status="COMPLETED", size=1073741824, day=1, plan_id="plan-1", **extra):
    rp = {
        "BackupVaultName": vault,
        "BackupVaultArn": f"arn:aws:backup:{REGION}:{ACCT}:backup-vault:{vault}",
        "RecoveryPointArn": f"arn:aws:backup:{REGION}:{ACCT}:recovery-point:{vault}-{day}",
        "ResourceArn": arn,
        "ResourceName": "res",
        "ResourceType": "EC2",
        "BackupSizeInBytes": size,
        "CreationDate": _day(day),
        "CreatedBy": {"BackupPlanId": plan_id} if plan_id else None,
        "Status": status,
        "IsParent": False,
    }
    rp.update(extra)
    return rp


def _backup_session(vaults, points_by_vault, vault_error=None, vault_errors=None):
    client = MagicMock()

    def paginator(operation):
        p = MagicMock()
        if operation == "list_backup_vaults":
            if vault_error:
                p.paginate.side_effect = vault_error
            else:
                p.paginate.return_value = [
                    {"BackupVaultList": [{"BackupVaultName": v} for v in vaults]}
                ]
        else:

            def paginate(BackupVaultName):
                if vault_errors and BackupVaultName in vault_errors:
                    raise vault_errors[BackupVaultName]
                return [{"RecoveryPoints": page} for page in points_by_vault[BackupVaultName]]

            p.paginate.side_effect = paginate
        return p

    client.get_paginator.side_effect = paginator
    session = MagicMock()
    session.client.return_value = client
    return session


INSTANCE = f"arn:aws:ec2:{REGION}:{ACCT}:instance/i-1"
VOLUME = f"arn:aws:ec2:{REGION}:{ACCT}:volume/vol-1"


def test_only_completed_recovery_points_become_rows_with_the_plan_name_looked_up():
    session = _backup_session(
        ["v1"],
        {
            "v1": [
                [
                    _rp(INSTANCE, day=1),
                    _rp(INSTANCE, day=2, status="PARTIAL"),
                    _rp(VOLUME, day=3, size=None, plan_id=None),
                ],
                [_rp(INSTANCE, day=4, vault="v1")],
            ]
        },
    )
    result = fetch_recovery_points(session, REGION, ACCT, "alias", {"plan-1": "Daily"})
    assert [r.recovery_point_arn[-1] for r in result.rows] == ["1", "3", "4"]
    first, second = result.rows[0], result.rows[1]
    assert (first.backup_plan_id, first.backup_plan_name, first.resource_id) == (
        "plan-1",
        "Daily",
        "i-1",
    )
    assert (
        second.backup_size_bytes == 0
        and second.backup_plan_id == ""
        and second.backup_plan_name == ""
    )
    assert first.source == "AWSBackup" and first.status == "COMPLETED"
    assert first.creation_date == _day(1).isoformat() and first.account_alias == "alias"


def test_aggregate_keeps_count_latest_date_and_size_never_a_sum():
    session = _backup_session(
        ["v1", "v2"],
        {
            "v1": [[_rp(INSTANCE, day=1, size=100), _rp(INSTANCE, day=5, size=500)]],
            "v2": [[_rp(INSTANCE, vault="v2", day=3, size=300, plan_id="plan-2")]],
        },
    )
    [agg] = fetch_recovery_points(
        session, REGION, ACCT, "", {"plan-1": "Daily", "plan-2": "Weekly"}
    ).aggregates
    assert agg.recovery_point_count == 3
    assert (agg.latest_recovery_point_date, agg.latest_recovery_point_size_bytes) == (
        _day(5).isoformat(),
        500,
    )
    assert agg.backup_plan_names == ["Daily", "Weekly"] and agg.backup_vault_names == ["v1", "v2"]
    assert agg.latest_recovery_point_arn.endswith("v1-5")


def test_null_sizes_are_counted_and_parents_are_left_out_of_the_aggregate_only():
    session = _backup_session(
        ["v1"],
        {
            "v1": [
                [
                    _rp(VOLUME, day=1, size=None),
                    _rp(VOLUME, day=2, IsParent=True),
                    _rp("", day=3),
                ]
            ]
        },
    )
    result = fetch_recovery_points(session, REGION, ACCT, "")
    assert len(result.rows) == 3  # the CSV lists every completed recovery point
    [agg] = result.aggregates
    assert (agg.recovery_point_count, agg.null_size_recovery_point_count) == (1, 1)


def test_denied_vaults_are_counted_skipped_and_recorded_once():
    tracker = DenialTracker()
    session = _backup_session(
        ["ok", "denied1", "denied2"],
        {"ok": [[_rp(INSTANCE)]], "denied1": [], "denied2": []},
        vault_errors={
            "denied1": _client_error("AccessDeniedException"),
            "denied2": _client_error("AccessDenied"),
        },
    )
    result = fetch_recovery_points(session, REGION, ACCT, "", tracker=tracker)
    assert len(result.rows) == 1 and result.vaults_access_denied == 2
    [error] = tracker.permission_errors()
    assert error["service"] == "backup" and "2 vault(s)" in error["error"]


def test_a_denied_vault_listing_skips_the_region_and_is_recorded():
    tracker = DenialTracker()
    session = _backup_session([], {}, vault_error=_client_error("AccessDeniedException"))
    result = fetch_recovery_points(session, REGION, ACCT, "", tracker=tracker)
    assert result.rows == [] and result.aggregates == [] and not result.truncated
    assert [e["service"] for e in tracker.permission_errors()] == ["backup"]


def test_another_failure_while_listing_one_vault_is_recorded_and_the_rest_continue():
    tracker = DenialTracker()
    session = _backup_session(
        ["bad", "good"],
        {"bad": [], "good": [[_rp(INSTANCE)]]},
        vault_errors={"bad": _client_error("InternalFailure")},
    )
    result = fetch_recovery_points(session, REGION, ACCT, "", tracker=tracker)
    assert len(result.rows) == 1 and result.vaults_access_denied == 0
    assert [e["service"] for e in tracker.permission_errors()] == ["backup"]


def test_the_time_budget_truncates_and_flags_the_region():
    session = _backup_session(["v1"], {"v1": [[_rp(INSTANCE)]]})
    result = fetch_recovery_points(session, REGION, ACCT, "", timeout_minutes=-1)
    assert result.truncated is True and result.rows == []


def test_plan_names_for_regions_where_the_backup_service_is_not_collected():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {"BackupPlansList": [{"BackupPlanId": "p1", "BackupPlanName": "Daily"}]}
    ]
    session = MagicMock()
    session.client.return_value = client
    assert list_plan_names(session, REGION) == {"p1": "Daily"}
    client.get_paginator.return_value.paginate.side_effect = _client_error("AccessDenied")
    assert list_plan_names(session, REGION) == {}


# ── native FSx / DynamoDB / Redshift backups ─────────────────────────────────


def _paged_session(service_pages):
    """Session whose client(service).get_paginator(op).paginate() returns the given pages."""
    session = MagicMock()

    def client(service, **kw):
        c = MagicMock()
        pages = service_pages[service]

        def paginator(operation):
            p = MagicMock()
            if isinstance(pages, Exception):
                p.paginate.side_effect = pages
            else:
                p.paginate.return_value = pages
            return p

        c.get_paginator.side_effect = paginator
        return c

    session.client.side_effect = client
    return session


def test_fsx_backups_attribute_to_the_source_and_skip_aws_backup_and_unfinished_ones():
    pages = [
        {
            "Backups": [
                {
                    "Type": "AUTOMATIC",
                    "Lifecycle": "AVAILABLE",
                    "SizeInBytes": 10,
                    "CreationTime": _day(1),
                    "FileSystem": {"FileSystemId": "fs-1"},
                },
                {
                    "Type": "USER_INITIATED",
                    "Lifecycle": "AVAILABLE",
                    "SizeInBytes": 20,
                    "CreationTime": _day(2),
                    "Volume": {"VolumeId": "fsvol-1"},
                },
                {
                    "Type": "AWS_BACKUP",
                    "Lifecycle": "AVAILABLE",
                    "SizeInBytes": 30,
                    "FileSystem": {"FileSystemId": "fs-1"},
                },
                {
                    "Type": "USER_INITIATED",
                    "Lifecycle": "CREATING",
                    "FileSystem": {"FileSystemId": "fs-1"},
                },
                {
                    "Type": "USER_INITIATED",
                    "Lifecycle": "AVAILABLE",
                    "ResourceARN": "arn:backup-itself",
                },
            ]
        }
    ]
    found = fetch_fsx_backups(_paged_session({"fsx": pages}), REGION, ACCT)
    assert [(b.resource_arn, b.source, b.size_bytes) for b in found] == [
        (f"arn:aws:fsx:{REGION}:{ACCT}:file-system/fs-1", "FSxAutomatic", 10),
        (f"arn:aws:fsx:{REGION}:{ACCT}:volume/fsvol-1", "FSxUserInitiated", 20),
        ("arn:backup-itself", "FSxUserInitiated", 0),
    ]
    assert found[0].creation_date == _day(1).isoformat()


def _table(name, region=REGION, account=ACCT, pitr=False, size=1000):
    return SimpleNamespace(
        table_arn=f"arn:aws:dynamodb:{region}:{account}:table/{name}",
        region=region,
        account_id=account,
        pitr_enabled=pitr,
        size_bytes=size,
    )


def test_dynamodb_on_demand_backups_and_pitr_upper_bounds():
    pages = [
        {
            "BackupSummaries": [
                {
                    "BackupStatus": "AVAILABLE",
                    "BackupSizeBytes": 400,
                    "TableArn": "arn:t1",
                    "BackupCreationDateTime": _day(3),
                },
                {"BackupStatus": "CREATING", "BackupSizeBytes": 0, "TableArn": "arn:t1"},
            ]
        }
    ]
    tables = [
        _table("on", pitr=True, size=5000),
        _table("off", pitr=False),
        _table("elsewhere", region="eu-west-1", pitr=True),
        _table("other-account", account="999999999999", pitr=True),
    ]
    found = fetch_dynamodb_backups(_paged_session({"dynamodb": pages}), REGION, ACCT, tables)
    assert [(b.source, b.resource_arn, b.size_bytes, b.creation_date) for b in found] == [
        ("DDBOnDemand", "arn:t1", 400, _day(3).isoformat()),
        ("DDBPITR", f"arn:aws:dynamodb:{REGION}:{ACCT}:table/on", 5000, None),
    ]


def test_redshift_snapshots_use_decimal_megabytes_and_only_this_accounts_available_ones():
    pages = [
        {
            "Snapshots": [
                {
                    "Status": "available",
                    "ClusterIdentifier": "rs",
                    "SnapshotType": "automated",
                    "TotalBackupSizeInMegaBytes": 1.5,
                    "SnapshotCreateTime": _day(2),
                },
                {
                    "Status": "available",
                    "ClusterIdentifier": "rs",
                    "SnapshotType": "manual",
                    "OwnerAccount": ACCT,
                    "TotalBackupSizeInMegaBytes": 2,
                },
                {
                    "Status": "available",
                    "ClusterIdentifier": "rs",
                    "SnapshotType": "manual",
                    "OwnerAccount": "999999999999",
                    "TotalBackupSizeInMegaBytes": 9,
                },
                {"Status": "creating", "ClusterIdentifier": "rs", "SnapshotType": "manual"},
                {"Status": "available", "ClusterIdentifier": "rs", "SnapshotType": "manual"},
            ]
        }
    ]
    found = fetch_redshift_snapshots(_paged_session({"redshift": pages}), REGION, ACCT)
    assert [(b.source, b.size_bytes) for b in found] == [
        ("RedshiftAutomated", 1_500_000),
        ("RedshiftManual", 2_000_000),
        ("RedshiftManual", 0),
    ]
    assert found[0].resource_arn == f"arn:aws:redshift:{REGION}:{ACCT}:cluster:rs"


@pytest.mark.parametrize(
    "fetch, service",
    [
        (lambda s, t: fetch_fsx_backups(s, REGION, ACCT, t), "fsx"),
        (lambda s, t: fetch_dynamodb_backups(s, REGION, ACCT, [], t), "dynamodb"),
        (lambda s, t: fetch_redshift_snapshots(s, REGION, ACCT, t), "redshift"),
    ],
)
def test_listing_failures_are_recorded_and_give_no_backups(fetch, service):
    tracker = DenialTracker()
    session = _paged_session({service: _client_error("ThrottlingException")})
    assert fetch(session, tracker) == []
    assert [e["service"] for e in tracker.permission_errors()] == ["snapshots"]


# ── merging ───────────────────────────────────────────────────────────────────


def _agg(arn, count=1, date=_day(1), size=100):
    return RecoveryPointAggregate(
        account_id=ACCT,
        region=REGION,
        resource_arn=arn,
        resource_type="EC2",
        resource_name="r",
        recovery_point_count=count,
        latest_recovery_point_date=date.isoformat() if date else None,
        latest_recovery_point_size_bytes=size,
    )


def _native(arn, source, size, date=None):
    return NativeBackup(ACCT, REGION, arn, source, size, date.isoformat() if date else None)


def _summary(merged, arn):
    return merged[backup_key(ACCT, REGION, arn)]


def test_recovery_points_and_native_backups_merge_per_resource():
    merged = merge_backups(
        [
            _native("arn:x", "DDBOnDemand", 900, _day(9)),
            _native("arn:x", "DDBOnDemand", 50, _day(2)),
        ],
        [_agg("arn:x", count=4, date=_day(5), size=500)],
    )
    summary = _summary(merged, "arn:x")
    assert summary.has_backups and summary.backup_count == 6
    assert summary.backup_sources == "AWSBackup, DDBOnDemand"
    assert (
        summary.latest_backup_date == _day(9).isoformat()
        and summary.latest_backup_size_bytes == 900
    )


def test_the_newest_backup_wins_even_when_the_recovery_point_is_newer_than_natives():
    merged = merge_backups(
        [_native("arn:x", "FSxAutomatic", 7, _day(2))], [_agg("arn:x", date=_day(8), size=80)]
    )
    summary = _summary(merged, "arn:x")
    assert (summary.latest_backup_date, summary.latest_backup_size_bytes) == (
        _day(8).isoformat(),
        80,
    )


def test_an_undated_backup_arriving_after_dated_ones_only_raises_the_size():
    # The collectors list on-demand backups before the PITR bound, so this is the real order.
    merged = merge_backups(
        [_native("arn:x", "DDBOnDemand", 40, _day(1)), _native("arn:x", "DDBPITR", 5000)]
    )
    summary = _summary(merged, "arn:x")
    assert (
        summary.latest_backup_size_bytes == 5000
        and summary.latest_backup_date == _day(1).isoformat()
    )
    merged = merge_backups(
        [_native("arn:y", "DDBOnDemand", 40, _day(1)), _native("arn:y", "DDBPITR", 10)]
    )
    assert _summary(merged, "arn:y").latest_backup_size_bytes == 40  # a smaller bound is ignored


def test_a_dated_backup_replaces_an_earlier_undated_one():
    merged = merge_backups(
        [_native("arn:x", "DDBPITR", 5000), _native("arn:x", "DDBOnDemand", 40, _day(1))]
    )
    summary = _summary(merged, "arn:x")
    assert (
        summary.latest_backup_size_bytes == 40 and summary.latest_backup_date == _day(1).isoformat()
    )


def test_a_dateless_only_resource_keeps_its_date_empty():
    summary = _summary(merge_backups([_native("arn:z", "DDBPITR", 123)]), "arn:z")
    assert summary.latest_backup_date == "" and summary.latest_backup_size_bytes == 123


def test_entries_without_an_arn_are_ignored_and_sources_are_sorted():
    merged = merge_backups(
        [
            _native("", "RDSSnapshot", 1),
            _native("arn:q", "RedshiftManual", 1),
            _native("arn:q", "EBSSnapshot", 1),
        ],
        [_agg("", count=3)],
    )
    assert list(merged) == [backup_key(ACCT, REGION, "arn:q")]
    assert _summary(merged, "arn:q").backup_sources == "EBSSnapshot, RedshiftManual"


# ── applying to rows ──────────────────────────────────────────────────────────


def _row(arn, region=REGION):
    return SimpleNamespace(account_id=ACCT, region=region, arn=arn, backup=BackupSummary())


def test_rows_get_summaries_recovery_point_flags_and_truncation():
    with_rp, without, elsewhere = _row("arn:a"), _row("arn:b"), _row("arn:c", "eu-west-1")
    aggregates = [_agg("arn:a", count=2)]
    merged = merge_backups([_native("arn:b", "FSxAutomatic", 5, _day(1))], aggregates)
    apply_backup_summaries(
        [with_rp, without, elsewhere],
        merged,
        lambda r: r.arn,
        recovery_keys=recovery_point_keys(aggregates),
        truncated_regions=frozenset({REGION}),
    )
    assert with_rp.backup.has_backups and with_rp.backup.has_recovery_points
    assert without.backup.has_backups and not without.backup.has_recovery_points
    assert (
        with_rp.backup.backup_enumeration_truncated and without.backup.backup_enumeration_truncated
    )
    assert not elsewhere.backup.backup_enumeration_truncated and not elsewhere.backup.has_backups


def test_truncation_applies_to_rows_that_have_no_backups_at_all():
    row = _row("arn:none")
    apply_backup_summaries([row], {}, lambda r: r.arn, truncated_regions=frozenset({REGION}))
    assert row.backup.backup_enumeration_truncated and not row.backup.has_backups


def test_the_default_call_keeps_the_previous_behaviour():
    row = _row("arn:a")
    merged = merge_backups([_native("arn:a", "EBSSnapshot", 3, _day(1))])
    apply_backup_summaries([row], merged, lambda r: r.arn)
    assert row.backup.backup_count == 1 and not row.backup.has_recovery_points

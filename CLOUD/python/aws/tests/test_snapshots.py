"""Tests for collectors/snapshots.py: native RDS/EBS/AMI backups and their merge."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from collectors import DenialTracker
from collectors.snapshots import (
    NativeBackup,
    apply_backup_summaries,
    fetch_ebs_and_ami,
    fetch_rds_snapshots,
    merge_native_backups,
)
from models.discovery import BackupSummary

ACCT = "123456789012"
ALIAS = "acct"
REGION = "us-west-2"
GIB = 1024**3


def _dt(day, hour=0):
    return datetime(2026, 10, day, hour, 30, 0, tzinfo=timezone.utc)


def _client(pages_by_operation=None, errors=None):
    """A boto3-like client whose paginators return the given pages, or raise."""
    pages_by_operation = pages_by_operation or {}
    errors = errors or {}

    def get_paginator(operation):
        paginator = MagicMock()
        if operation in errors:
            paginator.paginate.side_effect = errors[operation]
        else:
            paginator.paginate.return_value = pages_by_operation.get(operation, [])
        return paginator

    client = MagicMock()
    client.get_paginator.side_effect = get_paginator
    return client


def _session(client):
    session = MagicMock()
    session.client.return_value = client
    return session


# ── RDS ───────────────────────────────────────────────────────────────────────


def _db_snap(
    identifier="rds:db-1-2026-10-05", db="db-1", status="available", kind="automated", **kw
):
    snap = {
        "DBSnapshotIdentifier": identifier,
        "DBSnapshotArn": f"arn:aws:rds:{REGION}:{ACCT}:snapshot:{identifier}",
        "DBInstanceIdentifier": db,
        "Engine": "postgres",
        "AllocatedStorage": 100,
        "Status": status,
        "SnapshotType": kind,
        "SnapshotCreateTime": _dt(5, 6),
    }
    snap.update(kw)
    return snap


def _rds(db=None, clusters=None, errors=None):
    pages = {
        "describe_db_snapshots": [{"DBSnapshots": db or []}],
        "describe_db_cluster_snapshots": [{"DBClusterSnapshots": clusters or []}],
    }
    return _session(_client(pages, errors))


def test_rds_automated_and_manual_snapshots_become_backups():
    session = _rds([_db_snap(), _db_snap("manual-1", kind="manual")])
    backups, rows = fetch_rds_snapshots(session, REGION, ACCT, ALIAS)
    assert [b.source for b in backups] == ["RDSAutomated", "RDSManual"]
    assert backups[0].size_bytes == 100 * GIB
    assert backups[0].resource_arn == f"arn:aws:rds:{REGION}:{ACCT}:db:db-1"
    assert backups[0].creation_date == _dt(5, 6).isoformat()
    row = rows[0]
    assert (row.engine, row.snapshot_type, row.status, row.cluster_identifier) == (
        "postgres",
        "automated",
        "available",
        "",
    )
    assert row.snapshot_arn.endswith("snapshot:rds:db-1-2026-10-05")


def test_rds_filters_unavailable_aws_backup_and_unsupported_engines():
    session = _rds(
        [
            _db_snap("keep"),
            _db_snap("creating", status="creating"),
            _db_snap("awsbackup:job-123"),
            _db_snap("doc", Engine="docdb"),
            _db_snap("nep", Engine="neptune"),
        ]
    )
    backups, rows = fetch_rds_snapshots(session, REGION, ACCT, ALIAS)
    assert [r.snapshot_identifier for r in rows] == ["keep"]
    assert len(backups) == 1


def test_rds_cluster_snapshots_have_no_size_and_use_the_cluster_arn():
    cluster = {
        "DBClusterSnapshotIdentifier": "cl-snap",
        "DBClusterSnapshotArn": f"arn:aws:rds:{REGION}:{ACCT}:cluster-snapshot:cl-snap",
        "DBClusterIdentifier": "cl-1",
        "Engine": "aurora-postgresql",
        "AllocatedStorage": 1,
        "Status": "available",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _dt(4),
    }
    backups, rows = fetch_rds_snapshots(_rds(clusters=[cluster]), REGION, ACCT, ALIAS)
    assert backups[0].size_bytes == 0
    assert backups[0].resource_arn == f"arn:aws:rds:{REGION}:{ACCT}:cluster:cl-1"
    assert rows[0].cluster_identifier == "cl-1" and rows[0].source == "RDSManual"


def test_rds_listing_failure_is_recorded_and_the_other_listing_still_runs():
    tracker = DenialTracker()
    cluster = {
        "DBClusterSnapshotIdentifier": "c",
        "DBClusterIdentifier": "cl",
        "Engine": "aurora",
        "Status": "available",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _dt(4),
    }
    session = _rds(
        clusters=[cluster],
        errors={"describe_db_snapshots": Exception("AccessDenied: DescribeDBSnapshots")},
    )
    backups, _ = fetch_rds_snapshots(session, REGION, ACCT, ALIAS, tracker)
    assert len(backups) == 1
    [err] = tracker.permission_errors()
    assert err["service"] == "snapshots" and "1 access denied" in err["error"]


def test_rds_scp_denial_is_recorded_as_a_denied_service():
    tracker = DenialTracker()
    boom = Exception("AccessDeniedException: explicit deny in a service_control_policy")
    session = _rds(errors={"describe_db_snapshots": boom, "describe_db_cluster_snapshots": boom})
    assert fetch_rds_snapshots(session, REGION, ACCT, ALIAS, tracker) == ([], [])
    assert "snapshots" in tracker.denied_services()


# ── EBS and AMI ───────────────────────────────────────────────────────────────


def _snap(snapshot_id="snap-1", volume="vol-1", state="completed", size=5 * GIB, **kw):
    snap = {
        "SnapshotId": snapshot_id,
        "VolumeId": volume,
        "State": state,
        "StartTime": _dt(3),
        "FullSnapshotSizeInBytes": size,
        "Description": "manual",
        "Tags": [],
    }
    snap.update(kw)
    return snap


def _ec2(snapshots=None, images=None, errors=None):
    client = _client({"describe_snapshots": [{"Snapshots": snapshots or []}]}, errors)
    client.describe_images.return_value = {"Images": images or []}
    return _session(client), client


def _image(image_id="ami-1", snapshots=("snap-a",), state="available", **kw):
    image = {
        "ImageId": image_id,
        "State": state,
        "Name": "my image",
        "Description": "d",
        "CreationDate": "2026-10-02T08:00:00.000Z",
        "BlockDeviceMappings": [{"Ebs": {"SnapshotId": s}} for s in snapshots],
        "Tags": [],
    }
    image.update(kw)
    return image


def test_ebs_snapshot_is_attributed_to_its_volume_with_the_real_size():
    session, _ = _ec2([_snap(size=7 * GIB)])
    backups, rows = fetch_ebs_and_ami(session, REGION, ACCT, ALIAS)
    assert backups == [
        NativeBackup(
            ACCT,
            REGION,
            f"arn:aws:ec2:{REGION}:{ACCT}:volume/vol-1",
            "EBSNative",
            7 * GIB,
            _dt(3).isoformat(),
        )
    ]
    assert (rows[0].source, rows[0].snapshot_id, rows[0].image_id, rows[0].name) == (
        "EBSNative",
        "snap-1",
        "",
        "",
    )


def test_ebs_size_falls_back_to_the_volume_size():
    snap = _snap()
    del snap["FullSnapshotSizeInBytes"]
    snap["VolumeSize"] = 8
    session, _ = _ec2([snap])
    assert fetch_ebs_and_ami(session, REGION, ACCT, ALIAS)[0][0].size_bytes == 8 * GIB


def test_ebs_skips_incomplete_aws_backup_and_ami_backing_snapshots():
    session, _ = _ec2(
        [
            _snap("keep"),
            _snap("pending", state="pending"),
            _snap("by-backup", Tags=[{"Key": "aws:backup:source-resource", "Value": "x"}]),
            _snap("snap-a"),  # backs the AMI below
        ],
        [_image(snapshots=("snap-a",))],
    )
    _, rows = fetch_ebs_and_ami(session, REGION, ACCT, ALIAS)
    assert sorted((r.source, r.snapshot_id or r.image_id) for r in rows) == [
        ("AMI", "ami-1"),
        ("EBSNative", "keep"),
    ]


def test_snapshot_without_a_volume_uses_the_snapshot_arn():
    session, _ = _ec2([_snap(volume="")])
    assert fetch_ebs_and_ami(session, REGION, ACCT, ALIAS)[0][0].resource_arn == (
        f"arn:aws:ec2:{REGION}::snapshot/snap-1"
    )


def test_ami_is_attributed_to_the_instance_in_the_snapshot_description():
    snaps = [
        _snap("snap-a", size=4 * GIB, Description="Created by CreateImage(i-0abc123) for ami-1"),
        _snap("snap-b", size=6 * GIB),
    ]
    session, _ = _ec2(snaps, [_image(snapshots=("snap-a", "snap-b"))])
    backups, rows = fetch_ebs_and_ami(session, REGION, ACCT, ALIAS)
    ami = [b for b in backups if b.source == "AMI"]
    assert [b.resource_arn for b in ami] == [f"arn:aws:ec2:{REGION}:{ACCT}:instance/i-0abc123"]
    assert ami[0].size_bytes == 10 * GIB  # sum of the backing snapshots
    assert ami[0].creation_date == "2026-10-02T08:00:00+00:00"
    assert [r.image_id for r in rows if r.source == "AMI"] == ["ami-1"]
    assert not [r for r in rows if r.source == "EBSNative"]  # both snapshots back the AMI


def test_ami_falls_back_to_the_source_instance_tag_then_the_image():
    tagged = _image(
        "ami-t", snapshots=(), Tags=[{"Key": "ec2:source-instance-id", "Value": "i-0def456"}]
    )
    plain = _image("ami-p", snapshots=())
    bad_tag = _image(
        "ami-b", snapshots=(), Tags=[{"Key": "ec2:source-instance-id", "Value": "not-an-id"}]
    )
    session, _ = _ec2(images=[tagged, plain, bad_tag])
    arns = {b.resource_arn for b in fetch_ebs_and_ami(session, REGION, ACCT, ALIAS)[0]}
    assert arns == {
        f"arn:aws:ec2:{REGION}:{ACCT}:instance/i-0def456",
        f"arn:aws:ec2:{REGION}:{ACCT}:image/ami-p",
        f"arn:aws:ec2:{REGION}:{ACCT}:image/ami-b",
    }


def test_unavailable_amis_are_skipped():
    session, _ = _ec2(images=[_image(state="pending")])
    assert fetch_ebs_and_ami(session, REGION, ACCT, ALIAS) == ([], [])


def test_ebs_failures_are_recorded_and_the_other_call_still_runs():
    tracker = DenialTracker()
    session, client = _ec2(
        [_snap()], errors={"describe_snapshots": Exception("AccessDenied: DescribeSnapshots")}
    )
    client.describe_images.return_value = {"Images": [_image(snapshots=())]}
    backups, _ = fetch_ebs_and_ami(session, REGION, ACCT, ALIAS, tracker)
    assert [b.source for b in backups] == ["AMI"]
    assert [e["service"] for e in tracker.permission_errors()] == ["snapshots"]


# ── merge ─────────────────────────────────────────────────────────────────────

ARN = f"arn:aws:rds:{REGION}:{ACCT}:db:db-1"


def _nb(arn=ARN, source="RDSAutomated", size=100 * GIB, created=None, region=REGION):
    return NativeBackup(ACCT, region, arn, source, size, created.isoformat() if created else None)


def test_merge_counts_every_backup_and_keeps_the_latest_size_not_a_sum():
    merged = merge_native_backups(
        [
            _nb(size=10 * GIB, created=_dt(1)),
            _nb(size=30 * GIB, created=_dt(3)),
            _nb(size=20 * GIB, created=_dt(2)),
        ]
    )
    summary = merged[f"{ACCT}|{REGION}|{ARN}"]
    assert summary.has_backups is True and summary.backup_count == 3
    assert summary.latest_backup_date == _dt(3).isoformat()
    assert summary.latest_backup_size_bytes == 30 * GIB


def test_merge_lists_each_source_once_sorted_ignoring_case():
    merged = merge_native_backups(
        [
            _nb(source="EBSNative", created=_dt(1)),
            _nb(source="AMI", created=_dt(2)),
            _nb(source="EBSNative", created=_dt(3)),
        ]
    )
    assert merged[f"{ACCT}|{REGION}|{ARN}"].backup_sources == "AMI, EBSNative"


def test_merge_undated_backups_only_raise_the_size():
    merged = merge_native_backups(
        [_nb(size=10 * GIB, created=_dt(2)), _nb(size=50 * GIB), _nb(size=5 * GIB)]
    )
    summary = merged[f"{ACCT}|{REGION}|{ARN}"]
    assert summary.latest_backup_date == _dt(2).isoformat()
    assert summary.latest_backup_size_bytes == 50 * GIB and summary.backup_count == 3


def test_merge_keeps_resources_and_regions_apart_and_skips_empty_arns():
    merged = merge_native_backups(
        [
            _nb(created=_dt(1)),
            _nb(arn="other", created=_dt(1)),
            _nb(region="eu-west-1", created=_dt(1)),
            _nb(arn=""),
        ]
    )
    assert len(merged) == 3


def test_apply_sets_only_rows_with_a_summary():
    class Row:
        def __init__(self, db):
            self.account_id, self.region, self.db = ACCT, REGION, db
            self.backup = BackupSummary()

    merged = merge_native_backups([_nb(created=_dt(1))])
    covered, uncovered = Row("db-1"), Row("db-2")
    apply_backup_summaries(
        [covered, uncovered], merged, lambda r: f"arn:aws:rds:{REGION}:{ACCT}:db:{r.db}"
    )
    assert covered.backup.has_backups and covered.backup.backup_count == 1
    assert uncovered.backup == BackupSummary()


# ── wiring ────────────────────────────────────────────────────────────────────


def test_region_scan_collects_native_backups_only_for_the_snapshots_service(monkeypatch):
    import main

    calls = []
    monkeypatch.setattr(
        main,
        "fetch_rds_snapshots",
        lambda *a, **k: (
            calls.append("rds") or [NativeBackup(ACCT, REGION, "a", "RDSManual", 1, None)],
            ["r"],
        ),
    )
    monkeypatch.setattr(
        main,
        "fetch_ebs_and_ami",
        lambda *a, **k: (
            calls.append("ebs") or [NativeBackup(ACCT, REGION, "b", "AMI", 2, None)],
            ["e"],
        ),
    )
    session = MagicMock()
    with_snapshots = main._scan_region(
        session, REGION, ACCT, ALIAS, frozenset({"snapshots", "rds", "ec2"})
    )
    assert calls == ["rds", "ebs"]
    assert [b.resource_arn for b in with_snapshots["native_backups"]] == ["a", "b"]
    assert with_snapshots["rds_snapshots"] == ["r"] and with_snapshots["ebs_ami"] == ["e"]
    calls.clear()
    without = main._scan_region(session, REGION, ACCT, ALIAS, frozenset({"ec2"}))
    assert calls == [] and without["native_backups"] == []


def test_no_backup_capacity_flag_removes_the_snapshots_service(tmp_path, monkeypatch):
    import json
    import sys

    import main

    seen = {}
    out = tmp_path / "out"
    out.mkdir()
    json_path = out / "aws_sizing_discovery.json"
    json_path.write_text(json.dumps({}))

    def fake_run(**kwargs):
        seen["services"] = kwargs["services"]
        json_path.write_text(json.dumps({}))  # a real run writes a new file each time
        return str(json_path)

    monkeypatch.setattr(main, "run", fake_run)
    for extra in ([], ["--no-backup-capacity"]):
        monkeypatch.setattr(
            sys, "argv", ["main.py", "--output", str(out), "--no-cost", "--no-csv", *extra]
        )
        main.main()
        if extra:
            assert "snapshots" not in seen["services"] and "ec2" in seen["services"]
        else:
            assert seen["services"] is None  # default: every service, including snapshots
    assert "snapshots" in main.ALL_SERVICES


@pytest.mark.parametrize(
    "services, expected",
    [
        ({"snapshots", "rds", "ec2"}, ["rds", "ebs"]),
        ({"snapshots", "rds"}, ["rds"]),  # RDS snapshots follow the rds service
        ({"snapshots", "ec2"}, ["ebs"]),  # EBS snapshots and AMIs follow the ec2 service
        ({"snapshots", "s3"}, []),
        ({"rds", "ec2"}, []),  # backup capacity switched off
    ],
)
def test_native_backups_follow_the_resource_services(monkeypatch, services, expected):
    import main

    calls = []
    monkeypatch.setattr(
        main, "fetch_rds_snapshots", lambda *a, **k: (calls.append("rds") or [], [])
    )
    monkeypatch.setattr(main, "fetch_ebs_and_ami", lambda *a, **k: (calls.append("ebs") or [], []))
    main._scan_region(MagicMock(), REGION, ACCT, ALIAS, frozenset(services))
    assert calls == expected


@pytest.mark.parametrize(
    "argv, expect_snapshots",
    [
        (["--services", "backup,dynamodb,ec2,efs,fsx,kms,rds,s3,secrets,sqs"], True),
        (["--services", "ec2"], True),
        (["--services", "ec2", "--no-backup-capacity"], False),
        (["--no-backup-capacity"], False),
    ],
)
def test_backup_capacity_is_on_for_an_explicit_service_list(
    tmp_path, monkeypatch, argv, expect_snapshots
):
    import json
    import sys

    import main

    seen = {}
    json_path = tmp_path / "aws_sizing_discovery.json"
    json_path.write_text(json.dumps({}))
    monkeypatch.setattr(
        main, "run", lambda **kw: seen.update(services=kw["services"]) or str(json_path)
    )
    monkeypatch.setattr(
        sys, "argv", ["main.py", "--output", str(tmp_path), "--no-cost", "--no-csv", *argv]
    )
    main.main()
    assert ("snapshots" in seen["services"]) is expect_snapshots

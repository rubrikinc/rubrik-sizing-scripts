"""Tests for csv_export.py: PowerShell-compatible CSV files from the discovery results."""

import csv
import io
import json
import os
import sys
import zipfile
from dataclasses import asdict

import csv_export as ce
import pytest
from collectors import arns
from models.discovery import (
    DynamoDBTable,
    EC2Instance,
    EC2Volume,
    EFSFileSystem,
    RDSInstance,
    S3Bucket,
    SecretsRegionCount,
    SQSRegionCount,
)

ACCT = "057149785675"
STAMP = "2026-10-05_140650"


def _result(account=ACCT, **overrides):
    """A discovery dict (as written to JSON) with one record of each collected kind."""
    base = dict(account_id=account, account_alias="")
    data = {
        "ec2_instances": [
            asdict(
                EC2Instance(
                    **base,
                    instance_id="i-1",
                    name="web",
                    instance_type="c5a.xlarge",
                    platform="linux",
                    state="running",
                    vcpus=4,
                    memory_gib=8,
                    region="us-west-2",
                    volume_count=2,
                    size_gib=150,
                    size_tb=0.1465,
                    size_bytes_derived=150 * 1024**3,
                    in_backup_plan=False,
                    backup_plans=[],
                    tags={"Name": "web", "Env": "prod", "aws:cloudformation:stack-name": "s"},
                )
            )
        ],
        "ec2_attached_volumes": [
            asdict(
                EC2Volume(
                    **base,
                    volume_id="vol-1",
                    instance_id="i-1",
                    instance_name="web",
                    name="",
                    device_name="/dev/sda1",
                    size_gib=100,
                    size_tb=0.0977,
                    size_bytes_derived=100 * 1024**3,
                    region="us-west-2",
                    availability_zone="us-west-2a",
                    volume_type="gp2",
                    state="in-use",
                    iops=300,
                    throughput=0,
                    encrypted=True,
                    in_backup_plan=True,
                    backup_plans=["AWS Backup"],
                    tags={},
                )
            )
        ],
        "ec2_unattached_volumes": [
            asdict(
                EC2Volume(
                    **base,
                    volume_id="vol-2",
                    instance_id="",
                    instance_name="",
                    name="",
                    device_name="",
                    size_gib=30,
                    size_tb=0.0293,
                    size_bytes_derived=30 * 1024**3,
                    region="us-west-2",
                    availability_zone="us-west-2b",
                    volume_type="gp3",
                    state="available",
                    iops=3000,
                    throughput=125,
                    encrypted=False,
                    in_backup_plan=False,
                    backup_plans=[],
                    tags={},
                )
            )
        ],
        "rds_instances": [
            asdict(
                RDSInstance(
                    **base,
                    db_instance_identifier="db-1",
                    db_name="",
                    size_gib=100,
                    size_tb=0.0977,
                    size_bytes_derived=100 * 1024**3,
                    region="us-west-2",
                    engine="postgres",
                    instance_class="db.t3.medium",
                    multi_az=False,
                    storage_type="gp2",
                    native_backup_enabled=True,
                    native_backup_retention_days=7,
                    in_backup_plan=True,  # native backups only, no AWS Backup plan
                    backup_plans=[],
                    tags={"Name": "db", "Team": "x"},
                    engine_version="14.22",
                    db_instance_status="available",
                    preferred_backup_window="10:46-11:16",
                )
            )
        ],
        "efs_filesystems": [
            asdict(
                EFSFileSystem(
                    **base,
                    file_system_id="fs-1",
                    name="shared",
                    size_bytes=6144,
                    size_gib=0.0,
                    size_tb=0.0,
                    mount_targets=2,
                    owner_id=account,
                    performance_mode="generalPurpose",
                    throughput_mode="bursting",
                    provisioned_throughput_mibps=0.0,
                    region="us-west-2",
                    in_backup_plan=False,
                    backup_plans=[],
                    tags={},
                    file_system_protection="ENABLED",
                )
            )
        ],
        "dynamodb_tables": [
            asdict(
                DynamoDBTable(
                    **base,
                    region="us-west-2",
                    table_name="t1",
                    table_id="id-1",
                    table_arn=f"arn:aws:dynamodb:us-west-2:{account}:table/t1",
                    size_bytes=2048,
                    size_gib=0.0,
                    size_tb=0.0,
                    item_count=10,
                    status="ACTIVE",
                    deletion_protection=False,
                    read_capacity_units=5,
                    write_capacity_units=5,
                    pitr_enabled=True,
                    in_backup_plan=True,  # PITR only
                    backup_plans=[],
                )
            )
        ],
        "s3_buckets": [
            asdict(
                S3Bucket(
                    **base,
                    bucket_name="b-1",
                    region="us-west-2",
                    size_bytes=21474836480,  # 20 GiB
                    size_gb=20.0,
                    size_tb=0.0182,
                    object_count=42,
                    in_backup_plan=False,
                    backup_plans=[],
                    tags={"Name": "bucket one", "Project": "p"},
                )
            )
        ],
        "secrets_counts": [asdict(SecretsRegionCount(**base, region="us-west-2", secret_count=3))],
        "sqs_counts": [asdict(SQSRegionCount(**base, region="us-west-2", queue_count=2))],
    }
    data.update(overrides)
    return data


def _files(*results):
    return ce.build_csv_files(list(results), STAMP)


def _table(text):
    rows = list(csv.reader(io.StringIO(text)))
    return rows[0], [dict(zip(rows[0], r)) for r in rows[1:]]


def _row(prefix, *results):
    header, rows = _table(_files(*results)[f"{prefix}-{STAMP}.csv"])
    return header, rows[0]


# ── format ────────────────────────────────────────────────────────────────────


def test_every_value_is_quoted_except_null_which_is_a_bare_empty_field():
    columns = ["AwsAccountAlias", "Name", "Size", "Flag"]
    row = {"AwsAccountAlias": "", "Name": "", "Size": 1.5, "Flag": True}
    # The alias is a quoted empty string; other empties and missing values are bare nulls.
    assert ce.render(columns, [row]) == '"AwsAccountAlias","Name","Size","Flag"\n"",,"1.5","True"\n'
    assert ce.render(["A", "B"], [{"A": None, "B": 'say "hi"'}]) == '"A","B"\n,"say ""hi"""\n'


def test_quoted_empty_columns_are_configurable():
    assert ce.render(["Name"], [{"Name": ""}], frozenset({"Name"})) == '"Name"\n""\n'
    assert ce.render(["Name"], [{"Name": ""}]) == '"Name"\n\n'


def test_numbers_and_booleans_use_powershell_text():
    assert ce._format(1231.0) == "1231"
    assert ce._format(0.0977) == "0.0977"
    assert ce._format(1e-05) == "1E-05"
    assert ce._format(False) == "False" and ce._format(7) == "7"


def test_files_are_utf8_lf_without_bom(tmp_path):
    paths = ce.write_csv_files([_result()], str(tmp_path), STAMP)
    assert len(paths) == len(ce.FILES)
    raw = open(paths[0], "rb").read()
    assert not raw.startswith(b"\xef\xbb\xbf") and b"\r" not in raw and raw.endswith(b"\n")


# ── units (expected values taken from the real PowerShell output) ─────────────


def test_gib_input_units_match_convert_to_size_units():
    assert ce._units_from_gib(100) == {
        "SizeGiB": 100,
        "SizeTiB": 0.0977,
        "SizeGB": 107.374,
        "SizeTB": 0.1074,
    }


def test_bytes_input_units_use_four_decimals_everywhere():
    assert ce._units_from_bytes(107374182400) == {
        "SizeGiB": 100.0,
        "SizeTiB": 0.0977,
        "SizeGB": 107.3742,
        "SizeTB": 0.1074,
    }
    assert ce._units_from_bytes(2048, prefix="TableSize")["TableSizeGiB"] == 0.0


def test_s3_sizes_keep_powershell_swapped_labels():
    _, row = _row("aws_s3_info", _result())
    assert row["StandardStorage_SizeBytes"] == "21474836480"
    assert row["StandardStorage_SizeGB"] == "20"  # really GiB
    assert row["StandardStorage_SizeGiB"] == "18.626"  # really decimal GB
    assert row["StandardStorage_SizeTB"] == "0.02"
    assert row["StandardStorage_SizeTiB"] == "0.0182"


def test_s3_without_metrics_is_zero():
    r = _result()
    r["s3_buckets"][0].update(size_bytes=0, object_count=0)
    _, row = _row("aws_s3_info", r)
    assert row["StandardStorage_SizeGB"] == "0" and row["NumberOfObjects-AllStorageTypes"] == "0"


# ── per-file content ──────────────────────────────────────────────────────────


def test_ec2_instance_row():
    header, row = _row("aws_ec2_instance_info", _result())
    assert header[:4] == ["AwsAccountId", "AwsAccountAlias", "InstanceId", "ResourceArn"]
    assert row["AwsAccountId"] == ACCT
    assert row["ResourceArn"] == f"arn:aws:ec2:us-west-2:{ACCT}:instance/i-1"
    assert (row["Volumes"], row["SizeGiB"], row["Platform"], row["ProductCode"]) == (
        "2",
        "150",
        "",
        "",
    )
    assert row["InBackupPlan"] == "False" and row["HasBackups"] == "False"


def test_windows_platform_is_written_as_windows():
    r = _result()
    r["ec2_instances"][0]["platform"] = "windows"
    assert _row("aws_ec2_instance_info", r)[1]["Platform"] == "Windows"


def test_attached_volume_blank_throughput_and_aws_backup_membership():
    _, row = _row("aws_ec2_attached_volume_info", _result())
    assert row["Throughput"] == "" and row["Iops"] == "300" and row["Encrypted"] == "True"
    assert row["InBackupPlan"] == "True" and row["BackupPlans"] == ""
    _, unattached = _row("aws_ec2_unattached_volume_info", _result())
    assert unattached["ResourceArn"].endswith(":volume/vol-2")


def test_rds_in_backup_plan_means_aws_backup_not_native_backups():
    _, row = _row("aws_rds_info", _result())
    assert row["InBackupPlan"] == "False" and row["BackupRetentionPeriod"] == "7"
    assert (row["EngineVersion"], row["DBInstanceStatus"]) == ("14.22", "available")
    assert row["PreferredBackupWindow"] == "10:46-11:16" and row["InstanceCount"] == "1"
    r = _result()
    r["rds_instances"][0]["backup_plans"] = ["AWS Backup"]
    assert _row("aws_rds_info", r)[1]["InBackupPlan"] == "True"


def test_efs_and_dynamodb_rows():
    _, efs = _row("aws_efs_info", _result())
    assert efs["FileSystemProtection"] == "ENABLED" and efs["ProvisionedThroughputInMibps"] == ""
    assert efs["ResourceArn"] == f"arn:aws:elasticfilesystem:us-west-2:{ACCT}:file-system/fs-1"
    _, ddb = _row("aws_DynamoDB_info", _result())
    assert ddb["ResourceArn"] == ddb["TableArn"] and ddb["PITREnabled"] == "True"
    assert ddb["InBackupPlan"] == "False"
    assert ddb["ProvisionedThroughput.NumberOfDecreasesToday"] == "0"


def test_secrets_and_sqs_rows():
    assert _row("aws_secrets_numbers", _result())[1]["Secrets"] == "3"
    assert _row("aws_sqs_numbers", _result())[1]["Queues"] == "2"


def test_partition_follows_the_region():
    assert [arns.partition(r) for r in ("us-east-1", "us-gov-west-1", "cn-north-1")] == [
        "aws",
        "aws-us-gov",
        "aws-cn",
    ]
    r = _result()
    r["ec2_instances"][0]["region"] = "us-gov-west-1"
    assert _row("aws_ec2_instance_info", r)[1]["ResourceArn"].startswith("arn:aws-us-gov:ec2:")


# ── tags ──────────────────────────────────────────────────────────────────────


def test_tag_columns_are_sanitized_and_exclude_name_except_for_s3():
    header, row = _row("aws_ec2_instance_info", _result())
    assert "Tag: Env" in header and "Tag: aws_cloudformation_stack_name" in header
    assert "Tag: Name" not in header and row["Tag: Env"] == "prod"
    s3_header, s3_row = _row("aws_s3_info", _result())
    assert s3_header[-2:] == ["Tag: Name", "Tag: Project"] and s3_row["Tag: Name"] == "bucket one"


def test_rows_without_a_tag_get_a_blank_cell_and_s3_tags_are_sorted():
    r = _result()
    r["s3_buckets"].append(
        {**r["s3_buckets"][0], "bucket_name": "b-2", "tags": {"Zeta": "1", "Alpha": "2"}}
    )
    header, rows = _table(_files(r)[f"aws_s3_info-{STAMP}.csv"])
    tags = [c for c in header if c.startswith("Tag: ")]
    assert tags == sorted(tags, key=str.lower)
    assert rows[0]["Tag: Zeta"] == "" and rows[1]["Tag: Project"] == ""


def test_dynamodb_has_no_tag_columns():
    header, _ = _row("aws_DynamoDB_info", _result())
    assert not any(c.startswith("Tag: ") for c in header)


# ── assembly ──────────────────────────────────────────────────────────────────


# Written by PowerShell with a hand-made fallback when there are no rows; every other file is
# the zero-byte file Export-Csv leaves for an empty list (see ce._EMPTY_FILE_TEXT).
_HAND_MADE_WHEN_EMPTY = {
    "aws_backup_recovery_points",
    "aws_backup_costs",
    "aws_snapshot_storage_costs",
    "aws_ebs_and_ami_info",
    "aws_rds_snapshot_info",
    "aws_redshift_info",
}


def test_empty_collections_give_the_files_powershell_writes():
    files = ce.build_csv_files([{}], STAMP)
    assert len(files) == len(ce.FILES)
    for spec in ce.FILES:
        text = files[f"{spec.prefix}-{STAMP}.csv"]
        if spec.prefix in _HAND_MADE_WHEN_EMPTY:
            assert text.endswith("\n") and text.count("\n") >= 1, spec.prefix
        else:
            assert text == "", spec.prefix  # zero bytes, as Export-Csv leaves it


def test_the_hand_made_empty_files_are_powershells_literals():
    files = {k.rsplit("-" + STAMP, 1)[0]: v for k, v in ce.build_csv_files([{}], STAMP).items()}
    # quoted header, as the data rows are written
    recovery = next(s for s in ce.FILES if s.prefix == "aws_backup_recovery_points")
    assert files["aws_backup_recovery_points"] == ce.render(list(recovery.columns), [])
    assert files["aws_backup_recovery_points"].startswith('"AwsAccountId","AwsAccountAlias"')
    # the backup costs file starts with a #TYPE line, then a quoted header
    first, second = files["aws_backup_costs"].split("\n")[:2]
    assert first == "#TYPE System.Management.Automation.PSCustomObject"
    assert second.startswith('"AwsAccountId","AwsAccountAlias","Time-Period-Start"')
    # the other four are unquoted single-line headers
    for prefix in (
        "aws_snapshot_storage_costs",
        "aws_ebs_and_ami_info",
        "aws_rds_snapshot_info",
        "aws_redshift_info",
    ):
        text = files[prefix]
        assert (
            text.count("\n") == 1 and '"' not in text and text.startswith("AwsAccountId,")
        ), prefix
    # PowerShell's Redshift literal puts ResourceArn after ManualSnapshotRetentionPeriod
    columns = files["aws_redshift_info"].strip().split(",")
    assert columns.index("ResourceArn") == columns.index("ManualSnapshotRetentionPeriod") + 1


def test_the_unquoted_literals_name_the_same_columns_as_the_rows():
    """The literals are copied from PowerShell, so a drift between them and the row builders
    would show here (Redshift's order is the one known difference)."""
    files = {k.rsplit("-" + STAMP, 1)[0]: v for k, v in ce.build_csv_files([{}], STAMP).items()}
    specs = {s.prefix: s for s in ce.FILES}
    for prefix in (
        "aws_snapshot_storage_costs",
        "aws_ebs_and_ami_info",
        "aws_rds_snapshot_info",
        "aws_redshift_info",
    ):
        assert set(files[prefix].strip().split(",")) == set(specs[prefix].columns), prefix
    cost_columns = [c.strip('"') for c in files["aws_backup_costs"].split("\n")[1].split(",")]
    assert cost_columns == list(specs["aws_backup_costs"].columns)
    ebs = files["aws_ebs_and_ami_info"].strip().split(",")
    assert ebs == list(specs["aws_ebs_and_ami_info"].columns)


def test_accounts_are_combined_and_sorted():
    other = _result(account="111111111111")
    header, rows = _table(_files(_result(), other)["aws_ec2_instance_info-" + STAMP + ".csv"])
    assert [r["AwsAccountId"] for r in rows] == ["057149785675", "111111111111"]
    assert len(_table(_files(_result(), other)[f"aws_sqs_numbers-{STAMP}.csv"])[1]) == 2


def test_file_names_follow_the_powershell_pattern():
    assert set(_files(_result())) == {f"{spec.prefix}-{STAMP}.csv" for spec in ce.FILES}


# ── contract ──────────────────────────────────────────────────────────────────


def test_generated_headers_conform_to_the_extracted_contract():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    contract = pytest.importorskip("contract.contract")
    c = contract.Contract.load()
    for name, text in _files(_result()).items():
        prefix = name.rsplit("-" + STAMP, 1)[0]
        data_lines = [line for line in text.splitlines() if not line.startswith("#TYPE")][1:]
        if text == "" or (prefix in _HAND_MADE_WHEN_EMPTY and not data_lines):
            continue  # an empty file as PowerShell writes it: zero bytes, or a literal header
        header = _table(text)[0]
        assert c.check_csv(name, header) == [], name


# ── packaging ─────────────────────────────────────────────────────────────────


def _progress_dir(tmp_path, *accounts):
    for acct in accounts:
        d = tmp_path / acct
        d.mkdir()
        (d / "aws_sizing_discovery.json").write_text(json.dumps(_result(account=acct)))
    return str(tmp_path)


def _package(tmp_path, accounts, **kwargs):
    import main

    progress = tmp_path / "progress"
    progress.mkdir()
    _progress_dir(progress, *accounts)
    zip_path = str(tmp_path / "out.zip")
    main._package_results(str(progress), zip_path, len(accounts), 0, **kwargs)
    return zipfile.ZipFile(zip_path)


def test_package_results_adds_combined_csvs_to_the_zip(tmp_path):
    archive = _package(tmp_path, ["111111111111", "222222222222"])
    names = archive.namelist()
    csvs = [n for n in names if n.endswith(".csv")]
    assert len(csvs) == len(ce.FILES) and all("/" not in n for n in csvs)
    assert sum(n.endswith("aws_sizing_discovery.json") for n in names) == 2
    _, rows = _table(archive.read(next(n for n in csvs if "ec2_instance" in n)).decode())
    assert [r["AwsAccountId"] for r in rows] == ["111111111111", "222222222222"]


def test_package_results_without_csv(tmp_path):
    archive = _package(tmp_path, ["111111111111"], write_csv=False)
    assert not [n for n in archive.namelist() if n.endswith(".csv")]


@pytest.mark.parametrize("extra, expect_csv", [([], True), (["--no-csv"], False)])
def test_cli_single_account_zip_contents(tmp_path, monkeypatch, extra, expect_csv):
    """The zip holds the JSON, the CSV files (unless --no-csv) and the log; nothing else is left."""
    import main

    out = tmp_path / "out"
    out.mkdir()
    json_path = out / "aws_sizing_discovery.json"
    json_path.write_text(json.dumps(_result()))
    monkeypatch.setattr(main, "run", lambda **kwargs: str(json_path))
    monkeypatch.setattr(sys, "argv", ["main.py", "--output", str(out), "--no-cost", *extra])
    main.main()
    zip_path = next(out.glob("aws_sizing_results_*.zip"))
    names = zipfile.ZipFile(zip_path).namelist()
    stamp = zip_path.stem[len("aws_sizing_results_") :]
    assert "aws_sizing_discovery.json" in names and f"output_aws_{stamp}.log" in names
    assert bool([n for n in names if n.endswith(".csv")]) is expect_csv
    assert sorted(p.name for p in out.iterdir()) == [zip_path.name]


# ── backup columns and the snapshot detail files ──────────────────────────────


def _with_backup(**fields):
    r = _result()
    r["rds_instances"][0]["backup"] = {
        "has_backups": True,
        "has_recovery_points": False,
        "backup_count": 9,
        "backup_sources": "RDSAutomated",
        "latest_backup_date": "2026-10-05T06:29:13+00:00",
        "latest_backup_size_bytes": 100 * 1024**3,
        "backup_enumeration_truncated": False,
        **fields,
    }
    return r


def test_backup_columns_come_from_the_merged_summary():
    _, row = _row("aws_rds_info", _with_backup())
    assert (row["HasBackups"], row["BackupCount"], row["BackupSources"]) == (
        "True",
        "9",
        "RDSAutomated",
    )
    assert row["LatestBackupDate"] == "10/5/2026 6:29:13 AM"
    assert [row[f"LatestBackupSize{u}"] for u in ("GiB", "TiB", "GB", "TB")] == [
        "100",
        "0.0977",
        "107.3742",
        "0.1074",
    ]
    assert row["InBackupPlan"] == "False"  # native backups are not an AWS Backup plan


def test_backup_columns_default_when_there_are_no_backups():
    _, row = _row("aws_rds_info", _result())
    assert (row["HasBackups"], row["BackupCount"], row["LatestBackupDate"]) == ("False", "0", "")
    assert row["LatestBackupSizeGiB"] == "0" and row["BackupEnumerationTruncated"] == "False"


@pytest.mark.parametrize(
    "iso, text",
    [
        ("2026-10-05T00:05:09+00:00", "10/5/2026 12:05:09 AM"),
        ("2026-10-05T12:00:00+00:00", "10/5/2026 12:00:00 PM"),
        ("2026-10-05T13:05:09+00:00", "10/5/2026 1:05:09 PM"),
        ("2026-12-25T23:59:59+00:00", "12/25/2026 11:59:59 PM"),
        ("2026-10-05T14:30:00+05:30", "10/5/2026 9:00:00 AM"),  # converted to UTC
    ],
)
def test_dates_use_powershell_text_in_utc(iso, text):
    assert ce._ps_datetime(iso) == text
    assert ce._ps_datetime(None) is None and ce._ps_datetime("") is None


def test_snapshot_detail_files():
    r = _result()
    r["rds_snapshots"] = [
        dict(
            account_id=ACCT,
            account_alias="",
            region="us-west-2",
            source="RDSAutomated",
            engine="postgres",
            snapshot_identifier="rds:db-1-2026-10-05",
            resource_arn=f"arn:aws:rds:us-west-2:{ACCT}:db:db-1",
            snapshot_arn="arn:snap",
            size_bytes=107374182400,
            creation_date="2026-10-05T06:29:13+00:00",
            snapshot_type="automated",
            status="available",
            cluster_identifier="",
        )
    ]
    r["ebs_and_ami"] = [
        dict(
            account_id=ACCT,
            account_alias="",
            region="us-west-2",
            source="EBSNative",
            image_id="",
            snapshot_id="snap-1",
            resource_arn=f"arn:aws:ec2:us-west-2:{ACCT}:volume/vol-9",
            size_bytes=5368709120,
            creation_date="2026-10-03T00:30:00+00:00",
            name="",
            description="nightly",
            state="completed",
        )
    ]
    files = _files(r)
    rds = files[f"aws_rds_snapshot_info-{STAMP}.csv"].split("\n")
    assert rds[1] == (
        f'"{ACCT}","","us-west-2","RDSAutomated","postgres","rds:db-1-2026-10-05",'
        f'"arn:aws:rds:us-west-2:{ACCT}:db:db-1","arn:snap","107374182400","100",'
        '"10/5/2026 6:29:13 AM","automated","available",""'
    )
    ebs = files[f"aws_ebs_and_ami_info-{STAMP}.csv"].split("\n")
    assert ebs[1] == (
        f'"{ACCT}","","us-west-2","EBSNative","","snap-1","arn:aws:ec2:us-west-2:{ACCT}:volume/vol-9",'
        '"5368709120","5","10/3/2026 12:30:00 AM","","nightly","completed"'
    )


def test_detail_rows_keep_their_order_within_a_region():
    r = _result()
    base = dict(
        account_id=ACCT,
        account_alias="",
        region="us-west-2",
        source="EBSNative",
        image_id="",
        resource_arn="a",
        size_bytes=1,
        creation_date=None,
        name="",
        description="",
        state="completed",
    )
    r["ebs_and_ami"] = [{**base, "snapshot_id": s} for s in ("snap-z", "snap-a", "snap-m")]
    _, rows = _table(_files(r)[f"aws_ebs_and_ami_info-{STAMP}.csv"])
    assert [x["SnapshotId"] for x in rows] == ["snap-z", "snap-a", "snap-m"]


# ── resource files: VPC, load balancers, EKS, KMS, Route53, IAM, Redshift ────


def _plain(**fields):
    return dict(account_id=ACCT, account_alias="", **fields)


def _resources(**overrides):
    data = {
        "vpcs": [
            _plain(
                region="us-west-2",
                vpc_id="vpc-1",
                owner_id=ACCT,
                cidr_block="10.0.0.0/16",
                state="available",
                is_default=True,
                tags={"Name": "main", "map-migrated": "x"},
            )
        ],
        "load_balancers": [
            _plain(
                region="us-west-2",
                name="lb-1",
                type="application",
                scheme="internal",
                vpc_id="vpc-1",
                dns_name="lb.example",
                arn="arn:lb",
                tags={"Name": "ignored", "k8s.io/cluster": "c", "env": "prod"},
            )
        ],
        "eks_clusters": [
            _plain(
                name="c1",
                version="1.30",
                platform_version="eks.5",
                status="ACTIVE",
                arn="arn:c",
                role_arn="arn:r",
                region="us-west-2",
                tags={"Name": "c1", "team-a": "x"},
            )
        ],
        "eks_nodegroups": [
            _plain(
                nodegroup_name="ng",
                cluster_name="c1",
                disk_size=20,
                capacity_type="ON_DEMAND",
                ami_type="AL2",
                nodegroup_arn="arn:ng",
                node_role="arn:nr",
                status="ACTIVE",
                release_version="1.30.0",
                version="1.30",
                region="us-west-2",
                tags={},
            )
        ],
        "kms_keys": [
            _plain(
                region="us-east-1",
                alias="alias/a; alias/b",
                key_id="k1",
                arn="arn:k",
                key_manager="CUSTOMER",
                key_state="Enabled",
                creation_date="2026-01-05T10:20:30.1230000Z",
            )
        ],
        "route53_zones": [
            _plain(
                hosted_zone_id="/hostedzone/Z1",
                name="a.example.",
                private_zone=False,
                resource_record_set_count=4,
            )
        ],
        "iam_summaries": [_plain(users=3, roles=5, customer_managed_policies=2)],
        "redshift_clusters": [
            _plain(
                region="us-west-2",
                cluster_identifier="rs-1",
                node_type="ra3.xlplus",
                number_of_nodes=2,
                cluster_status="available",
                master_username="admin",
                db_name="dev",
                cluster_create_time="2026-03-04T05:06:07+00:00",
                automated_snapshot_retention_period=1,
                manual_snapshot_retention_period=-1,
                backup={},
            )
        ],
    }
    data.update(overrides)
    return _result(**data)


def test_vpc_tags_keep_hyphens_and_the_name_tag():
    header, row = _row("aws_vpc_info", _resources())
    assert header[-2:] == ["Tag: Name", "Tag: map-migrated"] and row["IsDefault"] == "True"
    assert row["Tag: map-migrated"] == "x" and row["CidrBlock"] == "10.0.0.0/16"


def test_load_balancer_tags_keep_hyphens_sanitize_other_characters_and_skip_name():
    header, row = _row("aws_lb_info", _resources())
    assert header[-2:] == ["Tag: k8s_io_cluster", "Tag: env"]
    assert row["LoadBalancerName"] == "lb-1" and row["Arn"] == "arn:lb"


def test_eks_tags_replace_hyphens_and_keep_name():
    header, row = _row("aws_eks_clusters_info", _resources())
    assert header[-2:] == ["Tag: Name", "Tag: team_a"] and row["Version"] == "1.30"
    header, row = _row("aws_eks_nodegroups_info", _resources())
    assert header[-1] == "Region" and row["DiskSize"] == "20" and row["ClusterName"] == "c1"


def test_kms_route53_and_iam_rows():
    _, kms = _row("aws_kms_numbers", _resources())
    assert (
        kms["Alias"] == "alias/a; alias/b" and kms["CreationDate"] == "2026-01-05T10:20:30.1230000Z"
    )
    _, zone = _row("aws_route53_info", _resources())
    assert (zone["HostedZoneId"], zone["PrivateZone"], zone["ResourceRecordSetCount"]) == (
        "/hostedzone/Z1",
        "False",
        "4",
    )
    _, iam = _row("aws_iam_info", _resources())
    assert (iam["Users"], iam["Roles"], iam["CustomerManagedPolicies"]) == ("3", "5", "2")


def test_redshift_row_has_arn_date_and_backup_columns():
    header, row = _row("aws_redshift_info", _resources())
    assert row["ResourceArn"] == "arn:aws:redshift:us-west-2:057149785675:cluster:rs-1"
    assert row["ClusterCreateTime"] == "3/4/2026 5:06:07 AM"
    assert row["ManualSnapshotRetentionPeriod"] == "-1" and row["HasBackups"] == "False"
    assert len(header) == 23


def test_rows_follow_the_scan_order_of_regions_then_collection_order():
    rows = [
        _plain(region=r, vpc_id=f"vpc-{i}", owner_id="", cidr_block="", state="", is_default=False)
        for i, r in enumerate(["us-west-2", "ap-south-1", "us-west-2", "eu-west-1"])
    ]
    result = _result(
        vpcs=rows, regions_scanned=["ap-south-1", "eu-west-1", "us-east-1", "us-west-2"]
    )
    _, out = _table(_files(result)[f"aws_vpc_info-{STAMP}.csv"])
    assert [r["VpcId"] for r in out] == ["vpc-1", "vpc-3", "vpc-0", "vpc-2"]


def test_regions_missing_from_the_scan_list_sort_last_by_name():
    rows = [
        _plain(region=r, vpc_id=r, owner_id="", cidr_block="", state="", is_default=False)
        for r in ["zz-east-1", "aa-west-1", "us-west-2"]
    ]
    _, out = _table(
        _files(_result(vpcs=rows, regions_scanned=["us-west-2"]))[f"aws_vpc_info-{STAMP}.csv"]
    )
    assert [r["VpcId"] for r in out] == ["us-west-2", "aa-west-1", "zz-east-1"]


# ── S3 storage classes and Storage Lens ───────────────────────────────────────


def _bucket(name, **fields):
    base = dict(
        account_id=ACCT,
        account_alias="",
        bucket_name=name,
        region="us-west-2",
        size_bytes=0,
        object_count=0,
        in_backup_plan=False,
        tags={},
    )
    base.update(fields)
    return base


def _s3_table(*buckets):
    files = _files(_result(s3_buckets=list(buckets)))
    return _table(files[f"aws_s3_info-{STAMP}.csv"])


def test_s3_columns_follow_each_bucket_classes_in_powershell_order():
    header, [row] = _s3_table(
        _bucket(
            "a",
            storage_class_bytes={"StandardStorage": 1073741824.0, "GlacierStorage": 2147483648.0},
            storage_class_objects={"AllStorageTypes": 9.0},
            current_version_bytes={"STANDARD": 1073741824.0},
            current_version_objects={"STANDARD": 4.0},
        )
    )
    start = header.index("StandardStorage_SizeGB")
    assert header[start:] == [
        "StandardStorage_SizeGB",
        "StandardStorage_SizeTB",
        "StandardStorage_SizeGiB",
        "StandardStorage_SizeTiB",
        "StandardStorage_SizeBytes",
        "GlacierStorage_SizeGB",
        "GlacierStorage_SizeTB",
        "GlacierStorage_SizeGiB",
        "GlacierStorage_SizeTiB",
        "GlacierStorage_SizeBytes",
        "NumberOfObjects-AllStorageTypes",
        "CurrentVersion_STANDARD_SizeBytes",
        "CurrentVersion_STANDARD_SizeGB",
        "CurrentVersion_STANDARD_SizeTB",
        "CurrentVersion_STANDARD_SizeGiB",
        "CurrentVersion_STANDARD_SizeTiB",
        "CurrentVersionObjectCount_STANDARD",
        "HasIcebergTable",
    ]
    assert row["GlacierStorage_SizeGB"] == "2" and row["GlacierStorage_SizeBytes"] == "2147483648"
    assert (
        row["CurrentVersion_STANDARD_SizeGiB"] == "0.931"
        and row["CurrentVersionObjectCount_STANDARD"] == "4"
    )


def test_s3_columns_are_the_union_across_buckets_and_missing_cells_are_zero():
    header, rows = _s3_table(
        _bucket(
            "a",
            storage_class_bytes={"StandardStorage": 1073741824.0},
            storage_class_objects={"AllStorageTypes": 1.0},
        ),
        _bucket(
            "b",
            storage_class_bytes={"StandardStorage": None, "GlacierStorage": 1073741824.0},
            storage_class_objects={"AllStorageTypes": 2.0},
            current_version_bytes={"STANDARD": 1073741824.0},
            current_version_objects={"STANDARD": 3.0},
        ),
    )
    assert header.index("GlacierStorage_SizeBytes") > header.index("HasIcebergTable")  # first-seen
    first, second = rows
    assert first["GlacierStorage_SizeGB"] == "0" and first["GlacierStorage_SizeBytes"] == "0"
    assert first["CurrentVersion_STANDARD_SizeBytes"] == "0"
    assert first["CurrentVersionObjectCount_STANDARD"] == "0"
    assert second["StandardStorage_SizeBytes"] == "0" and second["GlacierStorage_SizeGB"] == "1"


def test_s3_without_per_class_data_falls_back_to_the_standard_totals():
    header, [row] = _s3_table(_bucket("a", size_bytes=21474836480, object_count=3))
    assert row["StandardStorage_SizeGB"] == "20" and row["NumberOfObjects-AllStorageTypes"] == "3"
    assert "CurrentVersion_STANDARD_SizeBytes" not in header


def test_s3_with_no_buckets_is_an_empty_file_like_powershell():
    # PowerShell exports the bucket list with a bare Export-Csv, which leaves a zero-byte file
    assert ce.build_csv_files([_result(s3_buckets=[])], STAMP)[f"aws_s3_info-{STAMP}.csv"] == ""


def test_s3_tags_stay_after_the_dynamic_columns_sorted():
    header, _ = _s3_table(
        _bucket(
            "a", tags={"zeta": "1", "Alpha": "2"}, storage_class_bytes={"StandardStorage": 1.0}
        ),
    )
    assert header[-3:] == ["HasIcebergTable", "Tag: Alpha", "Tag: zeta"]


# ── S3 Tables, Glue Iceberg, recovery points ──────────────────────────────────

_GIB = 1073741824


def _iceberg(**fields):
    base = dict(
        format_version=2,
        total_file_size_bytes=_GIB,
        data_file_count=12,
        total_delete_file_count=3,
        manifest_count=7,
        target_manifest_size_bytes=8388608,
        manifest_bytes_estimate=7 * 8388608,
        compaction_enabled=True,
        metadata_file_storage_class="",
    )
    base.update(fields)
    return base


def _s3_table_record(**fields):
    base = dict(
        account_id=ACCT,
        account_alias="",
        region="us-east-1",
        namespace="analytics/sales",
        table_name="customers",
        table_bucket_name="tb",
        table_bucket_arn="arn:bucket",
        table_arn="arn:table",
        warehouse_location="s3://wh",
        metadata_location=None,
        table_type="customer",
        created_at="2026-07-18T11:50:02+00:00",
        modified_at="2026-07-18T12:00:00+00:00",
        storage_class="STANDARD",
        iceberg=None,
        cloudwatch_size_bytes=None,
        total_file_count=None,
        compaction_enabled=None,
        snapshot_management_enabled=None,
        tags={},
    )
    base.update(fields)
    return base


def _one(prefix, collection, record):
    files = _files(_result(**{collection: [record]}))
    text = files[f"{prefix}-{STAMP}.csv"]
    header, rows = _table(text)
    return header, rows[0], text


def test_s3_table_without_metadata_has_blank_stats_and_quoted_empty_storage_class():
    header, row, text = _one("aws_s3_tables_info", "s3_tables", _s3_table_record())
    assert len(header) == 33 and row["CatalogType"] == "S3Tables"
    assert row["DatabaseName"] == row["Namespace"] == "analytics/sales"
    assert (
        row["CreatedAt"] == "7/18/2026 11:50:02 AM" and row["ModifiedAt"] == "7/18/2026 12:00:00 PM"
    )
    assert (
        row["MetadataLocation"] == ""
        and row["TotalFileSizeGiB"] == ""
        and row["CompactionEnabled"] == ""
    )
    assert row["InBackupPlan"] == "False" and row["TableType"] == "customer"
    body = text.splitlines()[1]
    assert '"s3://wh",,"customer"' in body  # a null metadata location is a bare empty field
    assert ',"STANDARD",""' in body  # MetadataFileStorageClass is an empty string


def test_s3_table_prefers_the_metadata_size_and_falls_back_to_cloudwatch():
    _, row, _ = _one(
        "aws_s3_tables_info",
        "s3_tables",
        _s3_table_record(
            metadata_location="s3://m",
            iceberg=_iceberg(),
            cloudwatch_size_bytes=5 * _GIB,
            total_file_count=40,
        ),
    )
    assert row["TotalFileSizeGiB"] == "1" and row["TotalFileSizeGB"] == "1.0737"
    assert row["TotalFileCount"] == "40" and row["DataFileCount"] == "12"
    assert row["ManifestCount"] == "7" and row["ManifestBytesEstimate"] == str(7 * 8388608)
    assert row["FormatVersion"] == "2" and row["TargetManifestSizeBytes"] == "8388608"
    _, row, _ = _one(
        "aws_s3_tables_info",
        "s3_tables",
        _s3_table_record(
            iceberg=_iceberg(total_file_size_bytes=None), cloudwatch_size_bytes=2 * _GIB
        ),
    )
    assert row["TotalFileSizeGiB"] == "2"
    _, row, _ = _one(
        "aws_s3_tables_info", "s3_tables", _s3_table_record(cloudwatch_size_bytes=3 * _GIB)
    )
    assert row["TotalFileSizeGiB"] == "3" and row["DataFileCount"] == ""


def test_s3_table_compaction_prefers_the_maintenance_config_over_the_metadata():
    for config, metadata, expected in [
        (False, True, "False"),
        (True, False, "True"),
        (None, True, "True"),
        (None, None, ""),
    ]:
        iceberg = _iceberg(compaction_enabled=metadata) if metadata is not None else None
        _, row, _ = _one(
            "aws_s3_tables_info",
            "s3_tables",
            _s3_table_record(compaction_enabled=config, iceberg=iceberg),
        )
        assert row["CompactionEnabled"] == expected


def test_s3_table_failed_calls_write_quoted_empty_strings_and_tags_follow_in_row():
    header, row, text = _one(
        "aws_s3_tables_info",
        "s3_tables",
        _s3_table_record(warehouse_location="", metadata_location="", tags={"Env": "prod"}),
    )
    assert ',"","",' in text.splitlines()[1]
    assert header[-1] == "Tag: Env" and row["Tag: Env"] == "prod"


def _glue_record(**fields):
    base = dict(
        account_id=ACCT,
        account_alias="",
        region="us-west-2",
        database_name="db",
        table_name="tbl",
        s3_bucket_name="warehouse",
        s3_location="s3://warehouse/db/tbl",
        metadata_location="s3://warehouse/db/tbl/metadata/v1.json",
        create_time="2026-07-18T11:50:02+00:00",
        update_time="2026-07-19T01:02:03+00:00",
        iceberg=_iceberg(),
        tags={"team": "x"},
    )
    base.update(fields)
    return base


def test_glue_iceberg_row():
    header, row, _ = _one("aws_glue_iceberg_info", "glue_iceberg_tables", _glue_record())
    assert len(header) == 26 and header[-1] == "Tag: team"
    assert (row["CatalogType"], row["TableType"], row["S3BucketName"]) == (
        "GlueDataCatalog",
        "ICEBERG",
        "warehouse",
    )
    assert (
        row["CreateTime"] == "7/18/2026 11:50:02 AM" and row["UpdateTime"] == "7/19/2026 1:02:03 AM"
    )
    assert row["TotalFileSizeBytes"] == str(_GIB) and row["TotalFileSizeGiB"] == "1"
    assert row["CompactionEnabled"] == "True" and row["Tag: team"] == "x"


def test_glue_iceberg_with_unknown_stats_keeps_the_defaults_blank():
    _, row, text = _one(
        "aws_glue_iceberg_info",
        "glue_iceberg_tables",
        _glue_record(
            metadata_location=None,
            s3_location="",
            s3_bucket_name="",
            iceberg=dict(
                format_version=None,
                total_file_size_bytes=None,
                data_file_count=None,
                total_delete_file_count=None,
                manifest_count=None,
                target_manifest_size_bytes=8388608,
                manifest_bytes_estimate=None,
                compaction_enabled=False,
                metadata_file_storage_class="",
            ),
            tags={},
        ),
    )
    assert (
        row["TotalFileSizeBytes"] == ""
        and row["TotalFileSizeGiB"] == ""
        and row["ManifestCount"] == ""
    )
    assert row["TargetManifestSizeBytes"] == "8388608" and row["CompactionEnabled"] == "False"
    assert (
        '"ICEBERG","",,' in text.splitlines()[1]
    )  # S3Location "" is quoted, MetadataLocation null is bare


def test_a_class_reduced_by_iceberg_data_is_recomputed_as_powershell_recomputes_it():
    """Get-AWSSizingInfo.ps1 writes GiB = bytes / 2^30 / 1.073741824 for every bucket (line
    1095), but recomputes a class it deducted Glue Iceberg bytes from with GiB = bytes / 2^30
    (lines 5864-5868). GB and TB use the same formula both times."""
    _, [row] = _s3_table(
        _bucket(
            "lake",
            storage_class_bytes={"StandardStorage": 5.0 * _GIB, "GlacierStorage": 5.0 * _GIB},
            iceberg_adjusted_classes=["StandardStorage"],
        )
    )
    adjusted = {k: row[f"StandardStorage_Size{k}"] for k in ("GB", "TB", "GiB", "TiB")}
    untouched = {k: row[f"GlacierStorage_Size{k}"] for k in ("GB", "TB", "GiB", "TiB")}
    assert adjusted == {"GB": "5", "TB": "0.005", "GiB": "5", "TiB": "0.0049"}
    assert untouched == {"GB": "5", "TB": "0.005", "GiB": "4.657", "TiB": "0.0045"}


def test_has_iceberg_table_is_yes_only_for_buckets_that_hold_glue_iceberg_data():
    for flag, expected in [(True, "Yes"), (False, "No")]:
        _, rows = _s3_table(_bucket("a", has_iceberg_table=flag))
        assert rows[0]["HasIcebergTable"] == expected


def _recovery_point(region, vault="v", **fields):
    base = dict(
        account_id=ACCT,
        account_alias="",
        region=region,
        backup_vault_name=vault,
        backup_vault_arn="arn:vault",
        recovery_point_arn=f"arn:rp:{region}:{vault}",
        resource_arn="arn:aws:ec2:us-west-2:1:instance/i-1",
        resource_id="i-1",
        resource_name="web",
        resource_type="EC2",
        backup_size_bytes=2 * _GIB,
        creation_date="2026-09-02T03:04:05+00:00",
        backup_plan_id="plan-1",
        backup_plan_name="Daily",
        status="COMPLETED",
        is_parent=False,
        parent_recovery_point_arn=None,
        source="AWSBackup",
    )
    base.update(fields)
    return base


def test_recovery_point_row():
    header, row, text = _one(
        "aws_backup_recovery_points", "backup_recovery_points", _recovery_point("us-west-2")
    )
    assert len(header) == 20 and header[-1] == "Source"
    assert (row["BackupSizeBytes"], row["BackupSizeGiB"], row["BackupSizeTiB"]) == (
        str(2 * _GIB),
        "2",
        "0.002",
    )
    assert row["CreationDate"] == "9/2/2026 3:04:05 AM" and row["IsParent"] == "False"
    assert (
        row["ResourceId"] == "i-1" and row["Status"] == "COMPLETED" and row["Source"] == "AWSBackup"
    )
    assert text.splitlines()[1].endswith('"False",,"AWSBackup"')  # null parent ARN is bare


def test_recovery_point_blank_plan_fields_are_quoted_empty():
    _, row, text = _one(
        "aws_backup_recovery_points",
        "backup_recovery_points",
        _recovery_point("us-west-2", backup_plan_id="", backup_plan_name=""),
    )
    assert ',"","","COMPLETED"' in text.splitlines()[1]


def test_recovery_points_are_ordered_by_region_name_not_scan_order():
    records = [_recovery_point(r) for r in ("us-west-2", "eu-west-1", "ap-south-1", "eu-west-1")]
    result = _result(
        backup_recovery_points=records, regions_scanned=["us-west-2", "eu-west-1", "ap-south-1"]
    )
    _, rows = _table(_files(result)[f"aws_backup_recovery_points-{STAMP}.csv"])
    assert [r["Region"] for r in rows] == ["ap-south-1", "eu-west-1", "eu-west-1", "us-west-2"]


def test_fsx_volume_resource_arn_uses_the_volume_id_like_powershell():
    record = dict(
        account_id=ACCT,
        account_alias="",
        region="us-west-2",
        file_system_id="fs-1",
        volume_id="fsvol-9",
        name="v",
        volume_type="ONTAP",
        lifecycle="CREATED",
        resource_arn="arn:aws:fsx:us-west-2:1:volume/fs-1/fsvol-9",  # the API's own ARN is not used
        storage_used_bytes=None,
        storage_capacity_bytes=None,
        in_backup_plan=False,
        tags={},
    )
    _, row, _ = _one("aws_fsx_volume_info", "fsx_volumes", record)
    assert row["ResourceArn"] == f"arn:aws:fsx:us-west-2:{ACCT}:volume/fsvol-9"


def test_recovery_points_set_the_backup_columns_of_a_row():
    record = _result()["ec2_instances"][0]
    record["backup"] = dict(
        has_backups=True,
        has_recovery_points=True,
        backup_count=3,
        backup_sources="AWSBackup",
        latest_backup_date="2026-09-02T03:04:05+00:00",
        latest_backup_size_bytes=_GIB,
        backup_enumeration_truncated=True,
    )
    _, row = _row("aws_ec2_instance_info", _result(ec2_instances=[record]))
    assert (row["HasBackups"], row["HasRecoveryPoints"], row["BackupCount"]) == (
        "True",
        "True",
        "3",
    )
    assert row["BackupSources"] == "AWSBackup" and row["BackupEnumerationTruncated"] == "True"

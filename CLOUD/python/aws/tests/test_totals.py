"""The totals block: wording and numbers are PowerShell's, and every number comes from the CSV rows."""

import csv_export
import pytest
import totals


def _line(lines, start):
    [found] = [line for line in lines if line.startswith(start)]
    return found


def _record(**extra):
    return {"account_id": "111122223333", "account_alias": "", "region": "us-east-1", **extra}


def _backup(has=True, size=0, sources="", plan=None):
    return {
        "backup": {
            "has_backups": has,
            "has_recovery_points": has,
            "backup_count": 1 if has else 0,
            "backup_sources": sources,
            "latest_backup_size_bytes": size,
        },
        "backup_plans": plan or [],
    }


def _discovery(**collections):
    return {"account_id": "111122223333", "regions_scanned": ["us-east-1"], **collections}


def _lines(*results, cost=True):
    return totals.summary_lines(csv_export.rows_by_file(list(results)), cost)


def test_ec2_totals_use_powershells_wording_and_unit_order():
    result = _discovery(
        ec2_instances=[
            _record(instance_id="i-1", volume_count=2, size_gib=100),
            _record(instance_id="i-2", volume_count=1, size_gib=50),
        ]
    )
    lines = _lines(result)
    assert "Total # of EC2 instances: 2" in lines
    assert "Total # of volumes: 3" in lines
    assert _line(lines, "Total capacity of all volumes") == (
        "Total capacity of all volumes: 150 GiB or 161.061 GB or 0.1465 TiB or 0.1611 TB"
    )


def test_a_sum_is_printed_with_fifteen_significant_digits_like_powershell():
    assert totals._number(1321.7769999999996) == "1321.777"
    assert totals._number(1.3219999999999998) == "1.322"
    assert totals._number(1231.0) == "1231"
    assert totals._number(0) == "0"


def test_latest_backup_line_counts_rows_with_backups_and_lists_sources_once():
    gib = 1073741824
    result = _discovery(
        rds_instances=[
            _record(
                db_instance_identifier="a", size_gib=10, **_backup(size=gib, sources="RDSAutomated")
            ),
            _record(
                db_instance_identifier="b",
                size_gib=20,
                **_backup(size=2 * gib, sources="RDSAutomated, AWSBackup"),
            ),
            _record(db_instance_identifier="c", size_gib=30, **_backup(has=False)),
        ]
    )
    lines = _lines(result)
    assert _line(lines, "Latest-backup logical size of RDS instances").startswith(
        "Latest-backup logical size of RDS instances with backups (any source): 2 resources, sum = 3 GiB /"
    )
    assert "  Sources observed: AWSBackup, RDSAutomated" in lines


def test_a_workload_without_backups_prints_zero_sums_not_blanks():
    lines = _lines(_discovery(rds_instances=[_record(db_instance_identifier="a", size_gib=10)]))
    assert (
        "Latest-backup logical size of RDS instances with backups (any source): 0 resources, "
        "sum = 0 GiB / 0 TiB / 0 GB / 0 TB"
    ) in lines
    assert (
        "Provisioned source size of RDS instances in AWS Backup plans: 0 GiB or 0 GB or 0 TiB or 0 TB"
        in lines
    )


def test_an_empty_run_prints_every_section_with_zeros():
    lines = _lines(_discovery())
    for expected in (
        "Total # of EC2 instances: 0",
        "Total # of S3 buckets: 0",
        "No S3 Buckets",
        "# of Backed Up S3 buckets: 0",
        "No S3 Buckets backed up",
        "Total # of customer-managed KMS Keys: 0",
        "Total # of Secrets: 0",
        "Total # of SQS Queues: 0",
    ):
        assert expected in lines


def test_s3_sizes_are_listed_by_storage_type_with_seven_decimals():
    result = _discovery(
        s3_buckets=[
            _record(bucket_name="b1", size_bytes=2 * 1073741824 * 1000, storage_class_bytes={}),
        ]
    )
    rows = csv_export.rows_by_file([result])["aws_s3_info"]
    size_columns = sorted({key for row in rows for key in row if "_SizeTB" in key})
    lines = totals.summary_lines(csv_export.rows_by_file([result]))
    for column in size_columns:
        assert any(line.startswith(f"StorageType: {column}, Size_TB: ") for line in lines)
    assert all(
        len(line.split("Size_TB: ")[1].split(".")[1]) == 7 for line in lines if "Size_TB:" in line
    )


def test_kms_keys_are_counted_by_who_manages_them():
    result = _discovery(
        kms_keys=[
            _record(key_manager="CUSTOMER"),
            _record(key_manager="AWS"),
            _record(key_manager="AWS"),
        ]
    )
    lines = _lines(result)
    assert "Total # of customer-managed KMS Keys: 1" in lines
    assert "Total # of AWS-managed KMS Keys: 2" in lines


def test_the_totals_sum_every_account():
    one = _discovery(ec2_instances=[_record(instance_id="i-1", volume_count=1, size_gib=10)])
    two = {**one, "account_id": "999988887777"}
    two["ec2_instances"] = [
        dict(_record(instance_id="i-2", volume_count=2, size_gib=5), account_id="999988887777")
    ]
    lines = _lines(one, two)
    assert "Total # of EC2 instances: 2" in lines and "Total # of volumes: 3" in lines
    assert _line(lines, "Total capacity of all volumes").startswith(
        "Total capacity of all volumes: 15 GiB"
    )


def test_the_totals_hold_no_account_ids_or_resource_names():
    result = _discovery(
        ec2_instances=[
            _record(instance_id="i-secretname", name="payroll-db", volume_count=1, size_gib=1)
        ]
    )
    text = "\n".join(_lines(result))
    assert "111122223333" not in text and "payroll-db" not in text and "i-secretname" not in text


# ── S3 Tables flags ───────────────────────────────────────────────────────────


def _table(name, compaction, snapshot):
    return _record(
        namespace="ns",
        table_name=name,
        table_bucket_name="tb",
        table_arn=f"arn:aws:s3tables:us-east-1:111122223333:bucket/tb/table/{name}",
        compaction_enabled=compaction,
        snapshot_management_enabled=snapshot,
    )


def test_s3_table_flags_are_counted_on_off_and_unknown():
    result = _discovery(
        s3_tables=[_table("a", True, True), _table("b", False, True), _table("c", None, None)]
    )
    lines = _lines(result)
    assert "S3 Tables compaction enabled: 1 on, 1 off, 1 unknown" in lines
    assert "S3 Tables snapshot management enabled: 2 on, 0 off, 1 unknown" in lines


def test_the_flag_counts_agree_with_the_csv_cells():
    result = _discovery(s3_tables=[_table("a", True, True), _table("b", None, None)])
    rows = csv_export.rows_by_file([result])["aws_s3_tables_info"]
    assert [r["CompactionEnabled"] for r in rows] == [True, None]
    assert "S3 Tables compaction enabled: 1 on, 0 off, 1 unknown" in _lines(result)


# ── cost ──────────────────────────────────────────────────────────────────────


def _cost(backup, snapshot):
    return _discovery(
        backup_cost_months=[
            {
                "account_id": "111122223333",
                "period_start": "2026-01-01",
                "period_end": "2026-02-01",
                "net_unblended_cost": amount,
            }
            for amount in backup
        ],
        snapshot_storage_costs=[
            {
                "account_id": "111122223333",
                "period_start": "2026-01-01",
                "period_end": "2026-02-01",
                "net_unblended_cost": amount,
            }
            for amount in snapshot
        ],
    )


def test_cost_lines_sum_both_sources_and_add_a_combined_upper_bound():
    rows = {
        "aws_backup_costs": [
            {"AWSBackupNetUnblendedCost": "$1.25"},
            {"AWSBackupNetUnblendedCost": "$0.50"},
        ],
        "aws_snapshot_storage_costs": [
            {"NetUnblendedCost": "$2.001"},
            {"NetUnblendedCost": "$2.17"},
        ],
    }
    lines = totals.summary_lines(rows, True)
    assert "Net unblended cost of AWS Backup for past 12 months + this month so far: $1.75" in lines
    assert "  AWS Backup service (fully-managed resources)        : $1.75" in lines
    assert "  Snapshot/backup USAGE_TYPE (source-service-billed)  : $4.17" in lines
    assert "  Combined upper bound                                : $5.92" in lines
    assert lines[-1].startswith("Note: the USAGE_TYPE component")


def test_no_cost_rows_print_dollar_zero_as_powershell_does():
    lines = totals.summary_lines({}, True)
    assert "Net unblended cost of AWS Backup for past 12 months + this month so far: $0" in lines
    assert "  Combined upper bound                                : $0" in lines


def test_a_run_without_cost_says_so_instead_of_printing_zero_dollars():
    lines = totals.summary_lines({}, False)
    assert (
        lines[-1] == "Cost data was not collected (cost scan skipped), so there is no cost summary."
    )
    assert not any("Combined upper bound" in line for line in lines)


def test_print_totals_sends_every_line_to_the_sink():
    seen = []
    count = totals.print_totals({}, seen.append, True)
    assert count == len(seen) == len(totals.summary_lines({}, True))

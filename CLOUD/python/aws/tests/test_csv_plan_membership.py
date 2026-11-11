"""BackupPlans and InBackupPlan in the CSV files come from the plans' selections, like PowerShell."""

import copy
import csv
import io
import logging
from dataclasses import asdict

import csv_export as ce
import pytest
from anonymize import Anonymizer
from models.discovery import BackupPlan, BackupSelection
from tests.test_csv_export import ACCT, STAMP, _result, _s3_table_record

REGION = "us-west-2"  # the region of the shared fixture records


def tag(key, value):
    return {"ConditionType": "STRINGEQUALS", "ConditionKey": key, "ConditionValue": value}


def cond(key, value):
    return {"ConditionKey": key, "ConditionValue": value}


def sel(resources=(), not_resources=(), tags=(), eq=(), not_eq=()):
    return BackupSelection(
        "s", list(resources), list(not_resources), list(tags), list(eq), [], list(not_eq), []
    )


def plan(name, *selections, account=ACCT, region=REGION, complete=True, with_selections=True):
    """A plan dict as the serialized discovery JSON has it."""
    data = asdict(
        BackupPlan(
            account,
            "",
            region,
            f"id-{name}",
            "",
            name,
            "v1",
            "",
            "",
            [],
            [],
            selections=list(selections),
            selections_complete=complete,
        )
    )
    if not with_selections:  # a plan from a discovery file that predates selections
        del data["selections"]
        del data["selections_complete"]
    return data


def table(prefix, result, anonymizer=None):
    files = ce.build_csv_files([result], STAMP, anonymizer)
    rows = list(csv.reader(io.StringIO(files[f"{prefix}-{STAMP}.csv"])))
    return [dict(zip(rows[0], r)) for r in rows[1:]]


def plans_of(rows, id_column):
    return {r[id_column]: (r["BackupPlans"], r["InBackupPlan"]) for r in rows}


def ec2(instance_id, **tags):
    record = copy.deepcopy(_result()["ec2_instances"][0])
    record.update(instance_id=instance_id, tags=tags)
    return record


def rds(identifier, **tags):
    record = copy.deepcopy(_result()["rds_instances"][0])
    record.update(db_instance_identifier=identifier, tags=tags)
    return record


def fsx_volume(volume_id, **tags):
    return dict(
        account_id=ACCT,
        account_alias="",
        region=REGION,
        file_system_id="fs-1",
        volume_id=volume_id,
        name="v",
        tags=tags,
    )


def fsx_file_system(file_system_id, **tags):
    return dict(
        account_id=ACCT,
        account_alias="",
        region=REGION,
        file_system_id=file_system_id,
        config_type="ontap",
        tags=tags,
    )


# ── plans select rows ─────────────────────────────────────────────────────────────────────────


def test_rows_get_the_names_of_every_plan_that_selects_them():
    result = _result(
        rds_instances=[rds("prod-1", backup="true"), rds("prod-2")],
        backup_plans=[
            plan("Daily", sel(resources=[f"arn:aws:rds:{REGION}:{ACCT}:db:prod-1"])),
            plan("Weekly", sel(tags=[tag("backup", "true")])),
        ],
    )
    got = plans_of(table("aws_rds_info", result), "DBInstanceIdentifier")
    assert got == {"prod-1": ("Daily, Weekly", "True"), "prod-2": ("", "False")}


def test_in_backup_plan_follows_the_selections_not_native_backups():
    # the shared RDS record has native backups (in_backup_plan=True) but no plan selects it
    result = _result(backup_plans=[plan("Other", sel(resources=["arn:aws:ec2:*:*:instance/*"]))])
    assert plans_of(table("aws_rds_info", result), "DBInstanceIdentifier") == {
        "db-1": ("", "False")
    }


def test_not_resources_strips_the_plan_from_the_listed_instance():
    skipped = f"arn:aws:ec2:{REGION}:{ACCT}:instance/i-skip"
    result = _result(
        ec2_instances=[ec2("i-skip"), ec2("i-other")],
        backup_plans=[
            plan("All", sel(resources=["arn:aws:ec2:*:*:instance/*"], not_resources=[skipped]))
        ],
    )
    got = plans_of(table("aws_ec2_instance_info", result), "InstanceId")
    assert got == {"i-skip": ("", "False"), "i-other": ("All", "True")}


def test_selections_of_one_plan_are_evaluated_apart_and_negations_reach_untagged_rows():
    result = _result(
        ec2_instances=[
            ec2("A", env="dev", tier="silver"),
            ec2("B", env="prod", tier="gold"),
            ec2("C"),
            ec2("D", env="dev", tier="gold"),
        ],
        backup_plans=[
            plan(
                "P",
                sel(tags=[tag("env", "prod")]),
                sel(not_eq=[cond("aws:ResourceTag/tier", "gold")]),
            )
        ],
    )
    got = plans_of(table("aws_ec2_instance_info", result), "InstanceId")
    assert got == {
        "A": ("P", "True"),  # second selection only
        "B": ("P", "True"),  # first selection only; merged criteria would have dropped it
        "C": ("P", "True"),  # second selection: no tier tag at all
        "D": ("", "False"),
    }
    # DynamoDB rows have no tag columns, so a negation-only selection matches them too
    assert plans_of(table("aws_DynamoDB_info", result), "TableName") == {"t1": ("P", "True")}


def test_unattached_volumes_never_match_even_when_aws_backup_protects_them():
    unattached = copy.deepcopy(_result()["ec2_unattached_volumes"][0])
    unattached.update(backup_plans=["AWS Backup"], in_backup_plan=True)  # protected by AWS Backup
    result = _result(
        ec2_unattached_volumes=[unattached],
        backup_plans=[plan("Vols", sel(resources=["arn:aws:ec2:*:*:volume/*"]))],
    )
    assert plans_of(table("aws_ec2_attached_volume_info", result), "VolumeId") == {
        "vol-1": ("Vols", "True")
    }
    assert plans_of(table("aws_ec2_unattached_volume_info", result), "VolumeId") == {
        "vol-2": ("", "False")
    }


def test_s3_tables_fsx_and_s3_follow_their_own_arn_rules():
    result = _result(
        s3_tables=[_s3_table_record(region=REGION, table_bucket_name="tb1")],
        fsx_volumes=[fsx_volume("fsvol-1", backup="true"), fsx_volume("fsvol-2")],
        fsx_filesystems=[fsx_file_system("fs-1", backup="true"), fsx_file_system("fs-2")],
        backup_plans=[
            plan("Tables", sel(resources=[f"arn:aws:s3tables:{REGION}:{ACCT}:bucket/tb1"])),
            plan("Tagged", sel(tags=[tag("backup", "true")])),
            plan("OneVolume", sel(resources=[f"arn:aws:fsx:{REGION}:{ACCT}:volume/fs-1/fsvol-2"])),
            plan("Plain", sel(resources=["arn:aws:s3:::b-1"])),  # no "/": names no bucket
        ],
    )
    (tables_row,) = table("aws_s3_tables_info", result)
    assert (tables_row["BackupPlans"], tables_row["InBackupPlan"]) == ("Tables", "True")
    volumes = plans_of(table("aws_fsx_volume_info", result), "VolumeId")
    assert volumes == {"fsvol-1": ("Tagged", "True"), "fsvol-2": ("OneVolume", "True")}
    systems = plans_of(table("aws_fsx_filesystem_info", result), "FileSystemId")
    assert systems == {"fs-1": ("Tagged", "True"), "fs-2": ("", "False")}
    assert plans_of(table("aws_s3_info", result), "BucketName") == {"b-1": ("", "False")}

    wildcard = _result(backup_plans=[plan("All", sel(resources=["arn:aws:s3:::*"]))])
    assert plans_of(table("aws_s3_info", wildcard), "BucketName") == {"b-1": ("All", "True")}


def test_the_matcher_row_arn_is_the_arn_the_csv_shows():
    """NotResources ARNs are compared with what the CSV writes in ResourceArn."""
    result = _result(
        s3_tables=[_s3_table_record(region=REGION)],
        fsx_volumes=[fsx_volume("fsvol-1")],
        fsx_filesystems=[fsx_file_system("fs-1")],
    )
    specs = {spec.collection: spec for spec in ce.FILES}
    for collection, kind in ce._PLAN_KINDS.items():
        record = result[collection][0]
        shown = specs[collection].build(record)["ResourceArn"]
        assert ce._plan_row(kind, record).resource_arn == shown, collection


# ── older or partial plan data falls back to the previous signal ─────────────────────────────


def legacy_signal(result):
    return plans_of(table("aws_ec2_attached_volume_info", result), "VolumeId")


def warnings_of(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize(
    "bad_plan",
    [
        plan("Old", with_selections=False),  # discovery file from before selections existed
        plan("Cut", sel(resources=["arn:aws:ec2:*:*:volume/*"]), complete=False),
    ],
    ids=["no-selections-key", "incomplete"],
)
def test_unusable_plan_data_keeps_the_previous_signal_and_warns_once_per_account(bad_plan, caplog):
    result = _result(backup_plans=[bad_plan])
    with caplog.at_level(logging.WARNING):
        got = legacy_signal(result)
    # vol-1 is protected by AWS Backup in the fixture: InBackupPlan stays True, no names
    assert got == {"vol-1": ("", "True")}
    messages = warnings_of(caplog)
    assert len(messages) == 1 and ACCT in messages[0] and REGION in messages[0]


def test_one_failed_plan_read_does_not_let_the_other_plans_stand_alone(caplog):
    placeholder = plan("Lost", complete=False)  # get_backup_plan failed for this plan
    good = plan("Good", sel(resources=["arn:aws:rds:*:*:db:*"]))
    protected = rds("db-1")
    protected["backup_plans"] = ["AWS Backup"]  # AWS Backup protects it, possibly via "Lost"
    result = _result(rds_instances=[protected], backup_plans=[good, placeholder])
    with caplog.at_level(logging.WARNING):
        got = plans_of(table("aws_rds_info", result), "DBInstanceIdentifier")
    # the group falls back to the old signal: "Good" alone would have said ("Good", "True")
    assert got == {"db-1": ("", "True")}
    assert len(warnings_of(caplog)) == 1


def test_groups_are_judged_one_by_one():
    elsewhere = copy.deepcopy(_result()["ec2_instances"][0])
    elsewhere.update(instance_id="i-eu", region="eu-west-1")
    result = _result(
        ec2_instances=[ec2("i-us"), elsewhere],
        regions_scanned=[REGION, "eu-west-1"],
        backup_plans=[
            plan("Daily", sel(resources=["arn:aws:ec2:*:*:instance/*"])),
            plan("Old", with_selections=False, region="eu-west-1"),
        ],
    )
    got = plans_of(table("aws_ec2_instance_info", result), "InstanceId")
    assert got == {"i-us": ("Daily", "True"), "i-eu": ("", "False")}


def test_a_group_without_plans_is_silent_unless_the_old_signal_says_protected(caplog):
    quiet = _result(ec2_attached_volumes=[])  # nothing carries the AWS Backup marker
    with caplog.at_level(logging.WARNING):
        table("aws_ec2_attached_volume_info", quiet)
        table("aws_rds_info", quiet)
    assert warnings_of(caplog) == []

    with caplog.at_level(logging.WARNING):
        assert legacy_signal(_result()) == {"vol-1": ("", "True")}  # the fixture's vol-1 is marked
    assert len(warnings_of(caplog)) == 1


def test_the_callers_results_are_not_modified():
    result = _result(
        ec2_instances=[ec2("i-1", backup="true")],
        backup_plans=[plan("P", sel(tags=[tag("backup", "true")]))],
    )
    before = copy.deepcopy(result)
    table("aws_ec2_instance_info", result)
    assert result == before and "plan_names" not in result["ec2_instances"][0]


def test_plans_of_several_accounts_do_not_leak_into_each_other():
    first = _result(
        ec2_instances=[ec2("i-1")],
        backup_plans=[plan("First", sel(resources=["arn:aws:ec2:*:*:instance/*"]))],
    )
    second = _result(account="222222222222", ec2_instances=[ec2("i-1")])
    second["ec2_instances"][0]["account_id"] = "222222222222"
    second["backup_plans"] = [plan("Second", sel(tags=[tag("none", "x")]), account="222222222222")]
    files = ce.build_csv_files([first, second], STAMP)
    rows = list(csv.reader(io.StringIO(files[f"aws_ec2_instance_info-{STAMP}.csv"])))
    got = {
        r[0]: (r[rows[0].index("BackupPlans")], r[rows[0].index("InBackupPlan")]) for r in rows[1:]
    }
    assert got == {ACCT: ("First", "True"), "222222222222": ("", "False")}


# ── anonymization ─────────────────────────────────────────────────────────────────────────────


def test_anonymized_plan_names_are_numbered_in_plan_order_not_row_order():
    # EC2 rows are anonymized before RDS rows, and Beta (the second plan) selects only EC2.
    result = _result(
        ec2_instances=[ec2("i-1")],
        rds_instances=[rds("db-1")],
        backup_plans=[
            plan("Alpha", sel(resources=[f"arn:aws:rds:{REGION}:{ACCT}:db:db-1"])),
            plan("Beta", sel(resources=["arn:aws:ec2:*:*:instance/*"])),
        ],
    )
    anonymizer = Anonymizer()
    (ec2_row,) = table("aws_ec2_instance_info", result, anonymizer)
    (rds_row,) = table("aws_rds_info", result, anonymizer)
    assert rds_row["BackupPlans"] == "BackupPlanName-00000"  # Alpha, first in the plan list
    assert ec2_row["BackupPlans"] == "BackupPlanName-00001"  # Beta


def test_plan_names_that_no_row_uses_are_still_numbered_in_plan_order():
    result = _result(
        backup_plans=[
            plan("Unused", sel(resources=["arn:aws:ec2:*:*:instance/nothing"])),
            plan("Used", sel(resources=["arn:aws:ec2:*:*:instance/*"])),
        ]
    )
    anonymizer = Anonymizer()
    (row,) = table("aws_ec2_instance_info", result, anonymizer)
    assert row["BackupPlans"] == "BackupPlanName-00001"
    assert ("BackupPlanName-00000", "Unused") in anonymizer.key_rows()


def test_pre_label_does_nothing_for_a_field_that_is_not_anonymized():
    anonymizer = Anonymizer(not_fields=["BackupPlanName"])
    anonymizer.pre_label("BackupPlanName", ["Alpha"])
    assert anonymizer.key_rows() == []
    anonymizer = Anonymizer()
    anonymizer.pre_label("BackupPlanName", ["Alpha", "", None, "alpha", "Beta"])
    assert anonymizer.key_rows() == [
        ("BackupPlanName-00000", "Alpha"),
        ("BackupPlanName-00001", "Beta"),
    ]

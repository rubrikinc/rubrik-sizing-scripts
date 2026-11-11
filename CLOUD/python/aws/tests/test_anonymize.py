"""Tests for aws/anonymize.py (port of -Anonymize in Get-AWSSizingInfo.ps1)."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from anonymize import (
    DEFAULT_FIELDS,
    FILE_ORDER,
    Anonymizer,
    anonymized_log_note,
    file_rank,
)

SCRIPT = Path(__file__).resolve().parents[3] / "Get-AWSSizingInfo.ps1"


def _row(**fields):
    return dict(fields)


# ── labels ────────────────────────────────────────────────────────────────────


def test_values_become_field_dash_number_and_repeat_values_share_a_label():
    a = Anonymizer()
    first = a.anonymize_row(_row(InstanceId="i-1", Region="us-west-2"))
    second = a.anonymize_row(_row(InstanceId="i-2"))
    again = a.anonymize_row(_row(InstanceId="i-1"))
    assert first == {"InstanceId": "InstanceId-00000", "Region": "us-west-2"}
    assert second["InstanceId"] == "InstanceId-00001" and again["InstanceId"] == "InstanceId-00000"


def test_matching_ignores_case_and_the_key_file_keeps_the_first_spelling():
    a = Anonymizer()
    a.anonymize_row(_row(Name="web"))
    assert a.anonymize_row(_row(Name="WEB"))["Name"] == "Name-00000"
    assert a.key_rows() == [("Name-00000", "web")]


def test_the_mapping_is_shared_across_fields_so_files_still_join():
    a = Anonymizer()
    a.anonymize_row(_row(InstanceId="shared-id"))
    assert a.anonymize_row(_row(BucketName="shared-id"))["BucketName"] == "InstanceId-00000"


def test_counters_run_per_field():
    a = Anonymizer()
    a.anonymize_row(_row(InstanceId="a", VolumeId="b"))
    out = a.anonymize_row(_row(InstanceId="c", VolumeId="d"))
    assert out == {"InstanceId": "InstanceId-00001", "VolumeId": "VolumeId-00001"}


def test_an_empty_string_is_anonymized_but_a_missing_value_is_not():
    a = Anonymizer()
    out = a.anonymize_row(_row(AwsAccountAlias="", Name=None, Description=None))
    assert out == {"AwsAccountAlias": "AwsAccountAlias-00000", "Name": None, "Description": None}


def test_non_text_values_in_listed_fields_are_matched_by_their_text():
    a = Anonymizer()
    out = a.anonymize_row(_row(OwnerId=123456789012, VpcId=True))
    assert out == {"OwnerId": "OwnerId-00000", "VpcId": "VpcId-00000"}
    assert a.key_rows() == [("OwnerId-00000", "123456789012"), ("VpcId-00000", "True")]


def test_fields_that_are_not_listed_are_left_alone():
    a = Anonymizer()
    row = _row(Region="us-west-2", SizeGiB=12.5, Volumes=2, InBackupPlan=False, State="running")
    assert a.anonymize_row(row) == row


def test_numbering_stays_unique_beyond_ten_values_unlike_powershell():
    a = Anonymizer()
    labels = [a.anonymize_row(_row(InstanceId=f"i-{n}"))["InstanceId"] for n in range(25)]
    assert len(set(labels)) == 25
    assert labels[:10] == [f"InstanceId-{n:05d}" for n in range(10)]
    assert labels[10] == "InstanceId-00010" and labels[24] == "InstanceId-00024"


# ── lists, tags, backup plans ─────────────────────────────────────────────────


def test_list_values_are_anonymized_item_by_item():
    a = Anonymizer()
    out = a.anonymize_row(_row(Resources=["arn:one", "arn:two", "arn:one"]))
    assert out["Resources"] == ["Resources-00000", "Resources-00001", "Resources-00000"]
    assert a.anonymize_row(_row(Resources=[]))["Resources"] == []


def test_tag_columns_are_renamed_with_their_values_and_moved_to_the_end():
    a = Anonymizer()
    row = {"Tag: Env": "prod", "InstanceId": "i-1", "Tag: Team": None, "Volumes": 2}
    out = a.anonymize_row(row)
    assert list(out) == ["InstanceId", "Volumes", "Tag: TagName-00000", "Tag: TagName-00001"]
    assert out["Tag: TagName-00000"] == "TagValue-00000" and out["Tag: TagName-00001"] is None


def test_tag_names_and_values_are_matched_without_regard_to_case():
    a = Anonymizer()
    a.anonymize_row({"Tag: Environment": "prod"})
    out = a.anonymize_row({"Tag: environment": "PROD"})
    assert out == {"Tag: TagName-00000": "TagValue-00000"}


def test_the_key_file_lists_the_tag_name_with_the_space_after_the_prefix():
    a = Anonymizer()
    a.anonymize_row({"Tag: Env": "prod"})
    assert ("TagName-00000", " Env") in a.key_rows()


def test_backup_plans_are_anonymized_plan_by_plan_and_joined_with_space_comma():
    a = Anonymizer()
    out = a.anonymize_row(_row(BackupPlans="Daily, Weekly"))
    assert out["BackupPlans"] == "BackupPlanName-00000 ,BackupPlanName-00001"
    assert a.anonymize_row(_row(BackupPlans="Daily"))["BackupPlans"] == "BackupPlanName-00000"
    assert a.anonymize_row(_row(BackupPlans=""))["BackupPlans"] == ""
    assert a.anonymize_row(_row(BackupPlans=None))["BackupPlans"] is None


# ── options ───────────────────────────────────────────────────────────────────


def test_extra_fields_are_added_and_not_fields_are_removed():
    a = Anonymizer.from_options(anonymize_fields="Region,InstanceType", not_anonymize_fields="Name")
    out = a.anonymize_row(_row(Region="us-west-2", InstanceType="m5", Name="web", InstanceId="i-1"))
    assert out["Region"] == "Region-00000" and out["InstanceType"] == "InstanceType-00000"
    assert out["Name"] == "web" and out["InstanceId"] == "InstanceId-00000"


def test_the_tags_keyword_leaves_every_tag_column_alone():
    a = Anonymizer.from_options(not_anonymize_fields="Tags")
    row = {"InstanceId": "i-1", "Tag: Env": "prod"}
    assert a.anonymize_row(row) == {"InstanceId": "InstanceId-00000", "Tag: Env": "prod"}


def test_the_default_fields_are_unique_and_include_the_usual_identifiers():
    for name in (
        "AwsAccountId",
        "BucketName",
        "ResourceArn",
        "WarehouseLocation",
        "Resources",
        "KeyId",
    ):
        assert name in DEFAULT_FIELDS
    assert len(DEFAULT_FIELDS) == len(set(DEFAULT_FIELDS))


@pytest.mark.skipif(not SCRIPT.exists(), reason="needs the PowerShell script")
def test_the_default_fields_are_the_list_in_the_powershell_script():
    text = SCRIPT.read_text(encoding="utf-8")
    block = text[text.index("$global:anonymizeProperties = @(") :]
    block = block[: block.index(")\n")]
    assert list(DEFAULT_FIELDS) == re.findall(r'"([^"]+)"', block)


# ── key file, order, note ─────────────────────────────────────────────────────


def test_key_file_is_sorted_by_label_and_quotes_every_value():
    a = Anonymizer()
    a.anonymize_row(_row(VolumeId='vol "1"', InstanceId="i-1", AwsAccountAlias=""))
    assert a.key_file_text() == (
        '"AnonymizedValue","ActualValue"\n'
        '"AwsAccountAlias-00000",""\n'
        '"InstanceId-00000","i-1"\n'
        '"VolumeId-00000","vol ""1"""\n'
    )


def test_files_are_anonymized_in_the_order_powershell_uses():
    assert file_rank("aws_backup_costs") < file_rank("aws_ec2_instance_info")
    assert file_rank("aws_ec2_instance_info") < file_rank("aws_rds_info") < file_rank("aws_s3_info")
    assert file_rank("aws_s3_info") < file_rank("aws_iam_info")
    assert file_rank("not_a_file") == len(FILE_ORDER)


def test_the_zip_log_note_says_the_customer_has_the_original():
    assert anonymized_log_note().startswith("Anonymized file; customer has original.")


# ── against PowerShell itself ─────────────────────────────────────────────────

SAMPLE = {
    "first": [
        {
            "AwsAccountId": "111122223333",
            "AwsAccountAlias": "",
            "InstanceId": "i-aaa",
            "Name": "web",
            "Region": "us-west-2",
            "InstanceType": "m5.large",
            "InBackupPlan": False,
            "BackupPlans": "Daily, Weekly",
            "SizeGiB": 12.5,
            "Tag: Environment": "prod",
            "Tag: Team": "x",
            "Tag: Empty": None,
            "Volumes": 2,
        },
        {
            "AwsAccountId": "111122223333",
            "AwsAccountAlias": "alias",
            "InstanceId": "i-bbb",
            "Name": "WEB",
            "Region": "us-east-1",
            "InstanceType": "m5.large",
            "InBackupPlan": True,
            "BackupPlans": "Daily",
            "SizeGiB": 1,
            "Tag: Environment": "prod",
            "Tag: Team": "y",
            "Tag: Empty": None,
            "Volumes": None,
        },
    ],
    "second": [
        {
            "AwsAccountId": "111122223333",
            "BucketName": "i-aaa",
            "ResourceArn": "arn:aws:s3:::i-aaa",
            "Description": "i-bbb",
            "KeyId": "k1",
            "Tag: environment": "PROD",
            "Resources": ["arn:one", "arn:two", "arn:one"],
        },
        {
            "AwsAccountId": "999900001111",
            "BucketName": "other",
            "ResourceArn": "arn:aws:s3:::other",
            "Description": None,
            "KeyId": "k2",
            "Tag: Other": "v",
            "Resources": [],
        },
    ],
}


def _harness(tmp_path: Path) -> Path:
    lines = SCRIPT.read_text(encoding="utf-8").split("\n")
    start = next(
        i for i, l in enumerate(lines) if l.startswith("  $global:anonymizeProperties = @(")
    )
    end = next(i for i, l in enumerate(lines) if l.startswith("  # Anonymize each list"))
    head = (
        'param([string]$InFile,[string]$OutFile,[string]$AnonymizeFields="",'
        '[string]$NotAnonymizeFields="")\n'
        '$script:tagPrefix = "Tag:"\n$script:tagPrefixLength = 4\n'
        '$script:tagKeyAnonField = "TagName"\n$script:tagValueAnonField = "TagValue"\n'
    )
    tail = (
        "\n$sets = Get-Content -Raw $InFile | ConvertFrom-Json\n"
        "$result = [ordered]@{}\n"
        "foreach ($set in $sets.PSObject.Properties) {\n"
        "  $result[$set.Name] = Invoke-CollectionAnonymization -Collection @($set.Value)\n}\n"
        "$dict = @($global:anonymizeDict.GetEnumerator() | ForEach-Object {"
        " [PSCustomObject]@{ AnonymizedValue = $_.Value; ActualValue = $_.Key } }"
        " | Sort-Object -Property AnonymizedValue)\n"
        '$result["__dict"] = $dict\n'
        "$result | ConvertTo-Json -Depth 10 | Set-Content -Path $OutFile -Encoding utf8\n"
    )
    path = tmp_path / "harness.ps1"
    path.write_text(head + "\n".join(lines[start:end]) + tail, encoding="utf-8")
    return path


@pytest.mark.skipif(not shutil.which("pwsh") or not SCRIPT.exists(), reason="needs pwsh")
@pytest.mark.parametrize(
    "anonymize_fields, not_anonymize_fields",
    [
        ("", ""),
        ("Region,InstanceType", ""),
        ("", "Name,Description"),
        ("", "Tags"),
        ("Region", "Tags,KeyId"),
    ],
)
def test_output_matches_the_powershell_functions(tmp_path, anonymize_fields, not_anonymize_fields):
    infile, outfile = tmp_path / "in.json", tmp_path / "out.json"
    infile.write_text(json.dumps(SAMPLE), encoding="utf-8")
    subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(_harness(tmp_path)),
            "-InFile",
            str(infile),
            "-OutFile",
            str(outfile),
            "-AnonymizeFields",
            anonymize_fields,
            "-NotAnonymizeFields",
            not_anonymize_fields,
        ],
        check=True,
        capture_output=True,
    )
    expected = json.loads(outfile.read_text(encoding="utf-8-sig"))
    a = Anonymizer.from_options(anonymize_fields, not_anonymize_fields)
    for name, rows in SAMPLE.items():
        for row, want in zip(rows, expected[name]):
            got = a.anonymize_row(row)
            assert got == want and list(got) == list(want)
    assert a.key_rows() == [(r["AnonymizedValue"], r["ActualValue"]) for r in expected["__dict"]]

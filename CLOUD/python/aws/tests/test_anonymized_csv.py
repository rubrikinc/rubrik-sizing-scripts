"""Anonymization inside the CSV pipeline: file order, tag columns, S3's two passes."""

import csv
import io
import json
import shutil
import subprocess

import csv_export as ce
import pytest
from anonymize import Anonymizer
from tests.test_anonymize import SCRIPT, _harness
from tests.test_csv_export import ACCT, STAMP, _bucket, _result

OTHER = "999900001111"


def _only(**collections):
    """A discovery result holding only the given collections, so label numbers start at 0."""
    return {"account_id": ACCT, "account_alias": "", **collections}


def _build(*results, anonymizer=None):
    return ce.build_csv_files(list(results), STAMP, anonymizer)


def _table(files, prefix):
    rows = list(csv.reader(io.StringIO(files[f"{prefix}-{STAMP}.csv"])))
    return rows[0], [dict(zip(rows[0], r)) for r in rows[1:]]


def test_without_an_anonymizer_nothing_changes():
    assert _build(_result()) == _build(_result(), anonymizer=None)


def test_values_are_replaced_and_files_still_come_back_in_the_normal_order():
    files = _build(_result(), anonymizer=Anonymizer())
    assert list(files) == [f"{spec.prefix}-{STAMP}.csv" for spec in ce.FILES]
    header, [row] = _table(files, "aws_ec2_instance_info")
    assert row["AwsAccountId"] == "AwsAccountId-00000"
    assert row["InstanceId"] == "InstanceId-00000" and ACCT not in "".join(row.values())


def test_a_blank_account_alias_is_anonymized_like_any_other_value():
    _, rows = _table(_build(_result(), anonymizer=Anonymizer()), "aws_ec2_instance_info")
    assert {r["AwsAccountAlias"] for r in rows} == {"AwsAccountAlias-00000"}


def test_tag_columns_are_renamed_and_come_last():
    header, [row] = _table(_build(_result(), anonymizer=Anonymizer()), "aws_ec2_instance_info")
    tags = [c for c in header if c.startswith("Tag:")]
    assert tags and header[-len(tags) :] == tags
    assert all(c.startswith("Tag: TagName-") for c in tags)
    assert all(row[c].startswith("TagValue-") for c in tags if row[c])


def test_the_not_anonymize_option_for_tags_keeps_them_readable():
    header, _ = _table(
        _build(_result(), anonymizer=Anonymizer(not_fields=["Tags"])), "aws_ec2_instance_info"
    )
    assert not [c for c in header if c.startswith("Tag: TagName-")]
    assert [c for c in header if c.startswith("Tag:")]


def test_labels_are_numbered_in_the_order_powershell_anonymizes_its_lists():
    # EC2 is anonymized before RDS, so the EC2 account is number 0 whatever file is built first.
    ec2_account, rds_account = ACCT, OTHER
    ec2 = _result(account=ec2_account)
    rds = _result(account=rds_account)
    both = {
        "account_id": ec2_account,
        "account_alias": "",
        "ec2_instances": ec2["ec2_instances"],
        "rds_instances": [
            {**rds["rds_instances"][0], "account_id": rds_account, "account_alias": ""}
        ],
    }
    files = _build(both, anonymizer=Anonymizer())
    _, ec2_rows = _table(files, "aws_ec2_instance_info")
    _, rds_rows = _table(files, "aws_rds_info")
    assert ec2_rows[0]["AwsAccountId"] == "AwsAccountId-00000"
    assert rds_rows[0]["AwsAccountId"] == "AwsAccountId-00001"


def test_the_same_value_gets_the_same_label_in_every_file():
    result = _result()
    files = _build(result, anonymizer=Anonymizer())
    _, ec2 = _table(files, "aws_ec2_instance_info")
    _, rds = _table(files, "aws_rds_info")
    assert ec2[0]["AwsAccountId"] == rds[0]["AwsAccountId"] == "AwsAccountId-00000"


def test_glue_iceberg_tables_are_anonymized_too():
    glue = {
        "account_id": ACCT,
        "account_alias": "",
        "region": "us-west-2",
        "database_name": "db",
        "table_name": "orders",
        "s3_bucket_name": "warehouse",
        "s3_location": "s3://warehouse/db/orders",
        "metadata_location": None,
        "iceberg": {"target_manifest_size_bytes": 8388608, "compaction_enabled": False},
        "tags": {"team": "x"},
    }
    _, [row] = _table(
        _build(_only(glue_iceberg_tables=[glue]), anonymizer=Anonymizer()),
        "aws_glue_iceberg_info",
    )
    assert row["TableName"] == "TableName-00000" and row["AwsAccountId"].startswith("AwsAccountId-")
    assert row["Tag: TagName-00000"] == "TagValue-00000"
    assert row["DatabaseName"] == "db"  # not in PowerShell's default list; see --anonymize-fields


def test_extra_fields_reach_the_csv():
    anonymizer = Anonymizer.from_options(anonymize_fields="Region")
    _, [row] = _table(_build(_result(), anonymizer=anonymizer), "aws_ec2_instance_info")
    assert row["Region"] == "Region-00000"


def test_the_key_file_maps_every_label_back():
    anonymizer = Anonymizer()
    _build(_result(), anonymizer=anonymizer)
    rows = {a: b for a, b in anonymizer.key_rows()}
    assert rows["AwsAccountId-00000"] == ACCT
    assert any(v == "i-0123456789abcdef0" or v.startswith("i-") for v in rows.values())


# ── S3: PowerShell anonymizes the bucket rows twice ───────────────────────────


def _buckets():
    return [
        _bucket("zeta-bucket", tags={"zeta": "z1", "Alpha": "a1"}),
        _bucket("beta-bucket", tags={"mid": "m1", "zeta": "z2"}),
    ]


def test_s3_tag_numbers_follow_the_bucket_rows_not_the_sorted_columns():
    files = _build(_only(s3_buckets=_buckets()), anonymizer=Anonymizer())
    header, rows = _table(files, "aws_s3_info")
    tags = [c for c in header if c.startswith("Tag:")]
    # Sorted by real name (Alpha, mid, zeta), numbered in the order met (zeta, Alpha, mid).
    assert tags == ["Tag: TagName-00001", "Tag: TagName-00002", "Tag: TagName-00000"]
    first, second = rows
    assert (
        first["Tag: TagName-00001"].startswith("TagValue-") and second["Tag: TagName-00001"] == ""
    )


@pytest.mark.skipif(not shutil.which("pwsh") or not SCRIPT.exists(), reason="needs pwsh")
def test_s3_labels_match_powershells_two_passes(tmp_path):
    raw = [
        {"AwsAccountId": ACCT, "BucketName": "zeta-bucket", "Tag: zeta": "z1", "Tag: Alpha": "a1"},
        {"AwsAccountId": ACCT, "BucketName": "beta-bucket", "Tag: mid": "m1", "Tag: zeta": "z2"},
    ]
    normalized = [
        {
            "AwsAccountId": ACCT,
            "BucketName": "zeta-bucket",
            "Tag: Alpha": "a1",
            "Tag: mid": None,
            "Tag: zeta": "z1",
        },
        {
            "AwsAccountId": ACCT,
            "BucketName": "beta-bucket",
            "Tag: Alpha": None,
            "Tag: mid": "m1",
            "Tag: zeta": "z2",
        },
    ]
    infile, outfile = tmp_path / "in.json", tmp_path / "out.json"
    infile.write_text(json.dumps({"s3List": raw, "s3ListAg": normalized}))
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
        ],
        check=True,
        capture_output=True,
    )
    want = json.loads(outfile.read_text(encoding="utf-8-sig"))["s3ListAg"]
    header, rows = _table(
        _build(_only(s3_buckets=_buckets()), anonymizer=Anonymizer()), "aws_s3_info"
    )
    ours = [c for c in header if c.startswith("Tag:") or c == "BucketName"]
    assert ours == [c for c in want[0] if c.startswith("Tag:") or c == "BucketName"]
    for mine, theirs in zip(rows, want):
        for column in ours:
            assert (mine[column] or None) == theirs[column]

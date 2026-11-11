"""CSV formula injection (SPARK-957429): a value an attacker controls, such as a tag value, must not be
read by a spreadsheet as a formula.

``Get-AWSSizingInfo.ps1`` on master adds ``Protect-CsvValue`` and applies it to every tag value, to the
Name tag of EC2 instances, volumes and FSx file systems, and to the Description of AMIs and snapshots. A
value that starts with ``= + - @``, a tab, a CR or an LF gets a single quote in front of it. Tag keys were
already sanitized. These tests check the Python exporter does the same, in the same places and no others.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
from pathlib import Path

import pytest

from csv_injection import protect_csv_value
from tests.test_csv_export import ACCT, _one, _result, _row
from tests.test_fsx import _fs_record

# The function as it is on master, so a drift between the two implementations is a test failure.
PS_FUNCTION = r"""
function Protect-CsvValue {
  param($Value)
  if ($null -eq $Value) { return $Value }
  if ($Value -match '^[=+\-@\t\r\n]') { return "'" + $Value }
  return $Value
}
"""

HOSTILE = [
    '=WEBSERVICE("http://example.com")',
    "+cmd|' /C calc'!A0",
    "-2+3",
    "@SUM(1+1)",
    "\t=1+1",
    "\r=1+1",
    "\n=1+1",
]
SAFE = ["prod", "a=b", "x+y", "1-2", "email@example.com", " =1", "", "'=already quoted"]


@pytest.mark.parametrize("value", HOSTILE)
def test_a_formula_leading_value_gets_a_quote(value):
    assert protect_csv_value(value) == "'" + value


@pytest.mark.parametrize("value", SAFE)
def test_an_ordinary_value_is_left_alone(value):
    assert protect_csv_value(value) == value


def test_a_lone_formula_character_is_still_protected():
    assert protect_csv_value("=") == "'="


def test_none_stays_none():
    assert protect_csv_value(None) is None


def test_a_value_that_is_not_text_is_left_alone():
    """A number is not a formula however it looks: -3.5 stays a number."""
    assert protect_csv_value(5) == 5
    assert protect_csv_value(True) is True
    assert protect_csv_value(-3.5) == -3.5


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not installed")
def test_it_agrees_with_the_powershell_function_on_every_case(tmp_path: Path):
    cases = HOSTILE + SAFE + ["="]
    # each case is built from char codes, so control characters survive the script file
    items = ",".join(
        "([string]::Join('',(" + ",".join(f"[char]{ord(ch)}" for ch in c) + ")))" if c else "''"
        for c in cases
    )
    script = tmp_path / "cases.ps1"
    script.write_text(
        PS_FUNCTION
        + f"\n$cases = @({items})\n"
        + "foreach ($c in $cases) { [Convert]::ToBase64String("
        + "[Text.Encoding]::UTF8.GetBytes((Protect-CsvValue $c))) }\n"
    )
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(script)], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    from_ps = [base64.b64decode(line).decode() for line in out]
    assert len(from_ps) == len(cases)
    assert from_ps == [protect_csv_value(c) for c in cases]


# ── the exporter applies it where PowerShell does ────────────────────────────────────────────


def _with(collection: str, index: int = 0, **fields):
    r = _result()
    r[collection][index].update(fields)
    return r


def test_every_tag_value_is_protected_and_the_key_is_only_sanitized():
    _, row = _row(
        "aws_ec2_instance_info",
        _with("ec2_instances", tags={"Env": "=1+1", "Owner": "bob", "=bad key": "x"}),
    )
    assert row["Tag: Env"] == "'=1+1" and row["Tag: Owner"] == "bob"
    assert row["Tag: _bad_key"] == "x", "the key is sanitized to word characters, not quoted"


def test_the_s3_tag_cells_are_protected_including_a_name_tag():
    _, row = _row("aws_s3_info", _with("s3_buckets", tags={"Project": "@evil", "Name": "-x"}))
    assert row["Tag: Project"] == "'@evil" and row["Tag: Name"] == "'-x"


def test_tag_values_are_protected_in_every_file_that_has_tag_columns():
    cases = {
        "aws_rds_info": "rds_instances",
        "aws_efs_info": "efs_filesystems",
        "aws_ec2_attached_volume_info": "ec2_attached_volumes",
        "aws_ec2_unattached_volume_info": "ec2_unattached_volumes",
    }
    for prefix, collection in cases.items():
        _, row = _row(prefix, _with(collection, tags={"Env": "=1+1"}))
        assert row["Tag: Env"] == "'=1+1", prefix


def test_the_ec2_instance_name_is_protected():
    _, row = _row("aws_ec2_instance_info", _with("ec2_instances", name="=HYPERLINK(1)"))
    assert row["Name"] == "'=HYPERLINK(1)"


def test_the_attached_and_unattached_volume_names_are_protected():
    r = _with("ec2_attached_volumes", name="+1")
    r["ec2_unattached_volumes"][0]["name"] = "@2"
    assert _row("aws_ec2_attached_volume_info", r)[1]["Name"] == "'+1"
    assert _row("aws_ec2_unattached_volume_info", r)[1]["Name"] == "'@2"


def test_the_fsx_file_system_name_tag_is_protected():
    record = _fs_record("fs-1", "ontap", {"StorageUsed": 1.0}, tags={"Name": "=fs", "team": "+x"})
    _, row, _ = _one("aws_fsx_filesystem_info", "fsx_filesystems", record)
    assert row["Name"] == "'=fs" and row["Tag: team"] == "'+x"


def test_the_ami_and_snapshot_description_is_protected():
    record = dict(
        account_id=ACCT,
        account_alias="",
        region="us-west-2",
        source="EBSNative",
        image_id="",
        snapshot_id="snap-1",
        resource_arn="arn:aws:ec2:us-west-2:1:volume/vol-9",
        size_bytes=1,
        creation_date="2026-10-03T00:30:00+00:00",
        name="",
        description="=cmd",
        state="completed",
    )
    _, row, _ = _one("aws_ebs_and_ami_info", "ebs_and_ami", record)
    assert row["Description"] == "'=cmd"


def test_a_name_that_powershell_does_not_protect_is_left_as_is():
    """The EKS cluster name is a resource name the account owner chose, not a tag value. PowerShell
    applies the protection to its tags only, so the Python files do not change it."""
    from tests.test_csv_export import _plain

    record = _plain(
        name="=cluster",
        version="1.30",
        platform_version="eks.5",
        status="ACTIVE",
        arn="arn:c",
        role_arn="arn:r",
        region="us-west-2",
        tags={"team-a": "=x"},
    )
    header, row, _ = _one("aws_eks_clusters_info", "eks_clusters", record)
    assert row["Name"] == "=cluster", "a resource name is not protected"
    assert row["Tag: team_a"] == "'=x" or row.get("Tag: team-a") == "'=x", "its tag value is"

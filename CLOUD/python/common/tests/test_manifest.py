"""The manifest written into every results zip: what the tool produced, in a form CI and an importer can check.

It lists the CSV and JSON data files (not the run log) with a row count, a SHA-256 and, for CSV files, the
columns. It records no names, tags or values, so it is safe in an anonymized run. The module is shared
as a byte-identical copy in each tool (see test_manifest_copies.py), so it uses only the standard library.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from common import manifest

STAMP = "2026-10-15_1741"
CSV = '"A","B"\n"1","x"\n"2","y"\n'


def _build(files=None, **kwargs):
    base = dict(
        tool="azure",
        tool_version="1.1.0",
        code_version="06cbcc9a13 2026-10-14",
        generated_at="2026-10-15T17:41:00Z",
    )
    base.update(kwargs)
    return json.loads(manifest.build(files or {f"azure_vmdisk_info-{STAMP}.csv": CSV}, **base))


def test_it_records_the_tool_and_when_it_ran():
    m = _build()
    assert m["manifest_version"] == 1
    assert (m["tool"], m["tool_version"]) == ("azure", "1.1.0")
    assert m["code_version"] == "06cbcc9a13 2026-10-14"
    assert m["generated_at"] == "2026-10-15T17:41:00Z"


def test_a_csv_file_has_its_kind_rows_hash_and_columns():
    (entry,) = _build()["files"]
    assert entry["name"] == f"azure_vmdisk_info-{STAMP}.csv"
    assert entry["kind"] == "azure_vmdisk_info"
    assert entry["rows"] == 2
    assert entry["columns"] == ["A", "B"]
    assert entry["sha256"] == hashlib.sha256(CSV.encode("utf-8")).hexdigest()


def test_the_timestamp_is_not_part_of_the_kind():
    for name, kind in [
        (f"aws_ec2_instance_info-2026-10-05_140650.csv", "aws_ec2_instance_info"),
        (f"aws-backup-plans-info-{STAMP}.json", "aws-backup-plans-info"),
        ("aws_sizing_discovery.json", "aws_sizing_discovery"),
        ("123456789012/aws_sizing_discovery.json", "aws_sizing_discovery"),
    ]:
        assert manifest.kind_of(name) == kind, name


def test_a_json_file_has_a_hash_and_no_columns():
    plans = '[{"BackupPlanName": "Daily"}]\n'
    m = _build({f"aws-backup-plans-info-{STAMP}.json": plans})
    (entry,) = m["files"]
    assert entry["sha256"] == hashlib.sha256(plans.encode()).hexdigest()
    assert "columns" not in entry and entry["rows"] is None


def test_an_empty_csv_file_has_no_columns_and_no_rows():
    """PowerShell writes a zero-byte file when there is nothing to report."""
    (entry,) = _build({f"azure_aks_info-{STAMP}.csv": ""})["files"]
    assert entry["rows"] == 0 and entry["columns"] == []
    assert entry["sha256"] == hashlib.sha256(b"").hexdigest()


def test_a_header_only_csv_has_columns_and_no_rows():
    (entry,) = _build({f"azure_x-{STAMP}.csv": '"A","B"\n'})["files"]
    assert entry["rows"] == 0 and entry["columns"] == ["A", "B"]


def test_the_type_line_powershell_writes_is_skipped_for_the_columns():
    """Export-Csv without -NoTypeInformation starts the file with a #TYPE line; the header is the next one."""
    text = '#TYPE System.Management.Automation.PSCustomObject\n"A","B"\n"1","2"\n'
    (entry,) = _build({f"aws_backup_costs-{STAMP}.csv": text})["files"]
    assert entry["columns"] == ["A", "B"] and entry["rows"] == 1


def test_a_quoted_comma_and_a_quoted_newline_do_not_split_a_row():
    text = '"A","B"\n"x, y","line1\nline2"\n"z","w"\n'
    (entry,) = _build({f"azure_x-{STAMP}.csv": text})["files"]
    assert entry["rows"] == 2 and entry["columns"] == ["A", "B"]


def test_a_leading_byte_order_mark_is_not_part_of_the_first_column():
    (entry,) = _build({f"azure_x-{STAMP}.csv": "﻿" + CSV})["files"]
    assert entry["columns"] == ["A", "B"]


def test_files_are_listed_in_name_order_so_two_runs_can_be_compared():
    names = [f"azure_{n}-{STAMP}.csv" for n in ("zeta", "alpha", "mid")]
    listed = [e["name"] for e in _build({n: CSV for n in names})["files"]]
    assert listed == sorted(names)


def test_the_same_input_gives_the_same_bytes():
    files = {f"azure_a-{STAMP}.csv": CSV, f"azure_b-{STAMP}.csv": CSV}
    assert manifest.build(files, tool="azure", generated_at="t") == manifest.build(
        dict(reversed(list(files.items()))), tool="azure", generated_at="t"
    )


def test_a_binary_value_is_hashed_as_given():
    raw = b'"A"\n"\xc3\xa9"\n'
    (entry,) = _build({f"azure_x-{STAMP}.csv": raw})["files"]
    assert entry["sha256"] == hashlib.sha256(raw).hexdigest() and entry["rows"] == 1


def test_it_holds_no_values_from_the_files():
    secret = "super-secret-resource-name"
    text = f'"Name"\n"{secret}"\n'
    assert secret not in manifest.build({f"azure_x-{STAMP}.csv": text}, tool="azure")


def test_the_log_is_not_a_data_file():
    assert not manifest.is_data_file("output_azure_2026-10-15_174100.log")
    assert not manifest.is_data_file("manifest.json")
    assert manifest.is_data_file("azure_vmdisk_info-2026-10-15_1741.csv")
    assert manifest.is_data_file("aws-backup-plans-info-2026-10-15_1741.json")
    assert manifest.is_data_file("aws_sizing_discovery.json")


def test_the_file_name_has_no_cloud_prefix():
    """The importer routes a file by an aws_ / azure_ / gce_ prefix, so a manifest must not have one."""
    assert manifest.FILE_NAME == "manifest.json"
    assert not manifest.FILE_NAME.startswith(("aws", "azure", "gce", "gcp"))


def test_a_file_that_is_not_text_or_bytes_is_rejected():
    with pytest.raises(TypeError):
        manifest.build({"azure_x.csv": 5}, tool="azure")


def test_an_installed_distribution_has_a_version_and_a_missing_one_has_none():
    assert manifest.installed_version("pytest")
    assert manifest.installed_version("no-such-distribution-zzz") is None

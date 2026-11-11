"""Anonymization of the GCP output (-Anonymize).

Expected labels and files were checked against the real anonymizer of Get-GCPSizingInfo.ps1 run in
pwsh on the same rows (default fields, -AnonymizeFields, -NotAnonymizeFields and "Tags").
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

import anonymize
import csv_export
from anonymize import (
    DEFAULT_FIELDS,
    FILE_ORDER,
    KEY_FILE_PREFIX,
    Anonymizer,
    anonymized_log_note,
    file_rank,
)
from csv_export import build_csv_files

_SCRIPT = Path(__file__).resolve().parents[2] / ".." / "Get-GCPSizingInfo.ps1"


# ── the field list and the file order ─────────────────────────────────────────


@pytest.mark.skipif(not _SCRIPT.exists(), reason="the PowerShell script is not in this checkout")
def test_default_fields_are_the_scripts_list():
    text = _SCRIPT.read_text(encoding="utf-8")
    block = text[text.index("$global:anonymizeProperties = @(") :]
    block = block[: block.index(")")]
    in_script = re.findall(r'"([^"]+)"', block)
    # Master's script adds three fields for BigQuery; a checkout that still has the older script
    # lists the first eight only.
    bigquery = ["DatasetId", "TableId", "ExternalSourceUri"]
    assert list(DEFAULT_FIELDS) in (in_script, in_script + bigquery)
    assert list(DEFAULT_FIELDS[-3:]) == bigquery


def test_file_order_is_the_order_the_script_anonymizes_in():
    assert [file_rank(p) for p in FILE_ORDER] == list(range(len(FILE_ORDER)))
    assert list(FILE_ORDER) == [spec.prefix for spec in csv_export.FILES]
    assert file_rank("something_else") == len(FILE_ORDER)


# ── labels ────────────────────────────────────────────────────────────────────


def test_a_value_becomes_field_dash_number_and_repeats_get_the_same_label():
    a = Anonymizer()
    rows = [a.anonymize_row({"Name": n}) for n in ("vm-a", "vm-b", "vm-a")]
    assert [r["Name"] for r in rows] == ["Name-00000", "Name-00001", "Name-00000"]


def test_labels_ignore_case_and_are_shared_across_fields():
    a = Anonymizer()
    first = a.anonymize_row({"Name": "Shared"})
    second = a.anonymize_row({"DiskName": "SHARED"})
    assert first["Name"] == second["DiskName"] == "Name-00000"


def test_counters_are_per_field():
    a = Anonymizer()
    assert a.anonymize_row({"Name": "x", "Project": "y", "Id": "z"}) == {
        "Name": "Name-00000",
        "Project": "Project-00000",
        "Id": "Id-00000",
    }


def test_null_is_left_alone_but_an_empty_string_is_a_value():
    a = Anonymizer()
    row = a.anonymize_row({"DiskEncryptionKey": None, "Name": "", "InstanceName": ""})
    assert row["DiskEncryptionKey"] is None
    assert row["Name"] == row["InstanceName"] == "Name-00000"


def test_other_columns_are_untouched_and_field_names_are_matched_without_case():
    a = Anonymizer()
    row = a.anonymize_row(
        {"vmname": "v", "Zone": "us-central1-a", "SizeGb": 100.0, "Status": "RUNNING"}
    )
    assert row == {
        "vmname": "vmname-00000",
        "Zone": "us-central1-a",
        "SizeGb": 100.0,
        "Status": "RUNNING",
    }


def test_list_values_are_anonymized_item_by_item():
    assert Anonymizer().anonymize_row({"Name": ["a", "b", "a"]})["Name"] == [
        "Name-00000",
        "Name-00001",
        "Name-00000",
    ]


def test_numbering_continues_past_ten_where_powershell_repeats():
    a = Anonymizer()
    labels = [a.anonymize_row({"Name": f"v{i}"})["Name"] for i in range(12)]
    assert len(set(labels)) == 12 and labels[11] == "Name-00011"


# ── values that are not text ──────────────────────────────────────────────────


def test_a_boolean_has_one_label_per_value_where_powershell_gives_every_row_a_new_one():
    a = Anonymizer()
    labels = [
        a.anonymize_row({"DiskEncryptionKey": v})["DiskEncryptionKey"]
        for v in (False, True, False, True)
    ]
    assert labels == ["DiskEncryptionKey-00000", "DiskEncryptionKey-00001"] * 2
    assert dict(a.key_rows()) == {
        "DiskEncryptionKey-00000": "False",
        "DiskEncryptionKey-00001": "True",
    }


def test_a_number_added_with_anonymize_fields_has_one_label_per_value():
    a = Anonymizer.from_options(anonymize_fields="SizeGb")
    labels = [a.anonymize_row({"SizeGb": v})["SizeGb"] for v in (100.0, 200.0, 100.0)]
    assert labels == ["SizeGb-00000", "SizeGb-00001", "SizeGb-00000"]
    assert dict(a.key_rows()) == {"SizeGb-00000": "100", "SizeGb-00001": "200"}


# ── labels (the label columns) ────────────────────────────────────────────────


def test_label_columns_are_renamed_without_a_space_and_moved_to_the_end():
    a = Anonymizer()
    row = a.anonymize_row(
        {"Label/Tag: env": "prod", "Name": "x", "Label/Tag: team": None, "Zone": "z"}
    )
    assert list(row) == [
        "Name",
        "Zone",
        "Label/Tag:Label/TagName-00000",
        "Label/Tag:Label/TagName-00001",
    ]
    assert row["Label/Tag:Label/TagName-00000"] == "Label/TagValue-00000"
    assert row["Label/Tag:Label/TagName-00001"] is None


def test_the_label_name_keeps_its_leading_space_as_the_key():
    a = Anonymizer()
    a.anonymize_row({"Label/Tag: env": "prod"})
    assert (" env", "Label/TagName-00000") in [(actual, label) for label, actual in a.key_rows()]


def test_tags_in_not_anonymize_fields_leaves_every_label_column_alone():
    a = Anonymizer.from_options(not_anonymize_fields="Tags")
    assert a.anonymize_row({"Name": "x", "Label/Tag: env": "prod"}) == {
        "Name": "Name-00000",
        "Label/Tag: env": "prod",
    }


def test_an_empty_label_value_gets_a_label():
    a = Anonymizer()
    assert (
        a.anonymize_row({"Label/Tag: team": ""})["Label/Tag:Label/TagName-00000"]
        == "Label/TagValue-00000"
    )


# ── options ───────────────────────────────────────────────────────────────────


def test_extra_fields_are_anonymized_and_matched_without_case():
    a = Anonymizer.from_options(anonymize_fields="Zone, status")
    assert a.anonymize_row({"Zone": "z", "Status": "RUNNING", "Id": "1"}) == {
        "Zone": "Zone-00000",
        "Status": "Status-00000",
        "Id": "Id-00000",
    }


def test_not_anonymize_fields_removes_default_fields():
    a = Anonymizer.from_options(not_anonymize_fields="name,Project")
    assert a.anonymize_row({"Name": "x", "Project": "p", "Id": "1"}) == {
        "Name": "x",
        "Project": "p",
        "Id": "Id-00000",
    }


def test_a_field_in_both_lists_is_not_anonymized():
    a = Anonymizer.from_options(anonymize_fields="Zone", not_anonymize_fields="Zone")
    assert a.anonymize_row({"Zone": "z"}) == {"Zone": "z"}


# ── the key file ──────────────────────────────────────────────────────────────


def test_key_file_maps_labels_back_sorted_by_label_with_every_value_quoted():
    a = Anonymizer()
    a.anonymize_row({"Project": "my proj", "Name": 'say "hi"', "Id": "7"})
    assert a.key_file_text() == (
        '"AnonymizedValue","ActualValue"\n'
        '"Id-00000","7"\n'
        '"Name-00000","say ""hi"""\n'
        '"Project-00000","my proj"\n'
    )


def test_the_key_file_name_and_log_note_match_the_script():
    assert KEY_FILE_PREFIX == "gcp_anonymized_keys_to_actual_values"
    assert anonymized_log_note().startswith("Anonymized file; customer has original.")


# ── the files ─────────────────────────────────────────────────────────────────


def _disk(name, size, did, zone="zones/us-central1-a", labels=None, key=None):
    return {
        "name": name,
        "zone": zone,
        "size_gb": size,
        "disk_id": did,
        "labels": labels or {},
        "encrypted": bool(key),
        "encryption_key": key,
        "source_image": None,
    }


def _result() -> dict:
    return {
        "projects_scanned": ["proj-a"],
        "compute": [
            {
                "project_id": "proj-a",
                "instances": [
                    {
                        "name": "web-01",
                        "zone": "us-central1-a",
                        "status": "RUNNING",
                        "labels": {"env": "prod"},
                        "disks": [
                            _disk(
                                "web-01",
                                100,
                                "11",
                                labels={"env": "prod"},
                                key={"kmsKeyName": "projects/k/x"},
                            )
                        ],
                    }
                ],
                "unattached_disks": [_disk("orphan", 10, "22", key={"kmsKeyName": "projects/k/x"})],
            },
        ],
        "databases": [
            {
                "project_id": "proj-a",
                "cloud_sql_instances": [
                    {
                        "name": "WEB-01",
                        "database_version": "MYSQL_8_0",
                        "region": "us-central1",
                        "number_of_databases": 1,
                        "labels": {"env": "dev"},
                    }
                ],
                "spanner_instances": [
                    {
                        "name": "sp1",
                        "display_name": "My Spanner",
                        "config": "nam6",
                        "state": "READY",
                        "labels": {},
                    }
                ],
            },
        ],
    }


def _rows(files, prefix):
    return list(csv.reader(io.StringIO(files[f"{prefix}-S.csv"])))


def test_files_are_anonymized_and_label_columns_renamed():
    files = build_csv_files(_result(), "S", Anonymizer())
    vm = _rows(files, "gce_vm_info")
    cells = dict(zip(vm[0], vm[1]))
    assert cells["Project"] == "Project-00000" and cells["Name"] == "Name-00000"
    assert cells["Zone"] == "us-central1-a" and cells["Status"] == "RUNNING"
    assert (
        vm[0][-1] == "Label/Tag:Label/TagName-00000"
        and cells["Label/Tag:Label/TagName-00000"] == "Label/TagValue-00000"
    )
    text = "".join(files.values())
    for real in ("proj-a", "web-01", "orphan", "My Spanner", "projects/k/x"):
        assert real.casefold() not in text.casefold(), real


def test_a_value_in_two_files_gets_one_label_and_the_first_file_decides_the_field():
    files = build_csv_files(_result(), "S", Anonymizer())
    sql = _rows(files, "gce_cloudsql_info")
    assert dict(zip(sql[0], sql[1]))["InstanceName"] == "Name-00000"  # first met as a VM Name


def test_the_attached_disk_key_column_is_a_label_per_value_and_unattached_text_is_a_label():
    files = build_csv_files(_result(), "S", Anonymizer())
    assert (
        dict(zip(*_rows(files, "gce_attached_disk_info")[:2]))["DiskEncryptionKey"]
        == "DiskEncryptionKey-00000"
    )
    assert (
        dict(zip(*_rows(files, "gce_unattached_disk_info")[:2]))["DiskEncryptionKey"]
        == "DiskEncryptionKey-00001"
    )


def test_unanonymized_output_is_unchanged_by_the_new_argument():
    assert build_csv_files(_result(), "S") == build_csv_files(_result(), "S", None)


def test_files_without_rows_stay_empty():
    assert (
        build_csv_files(
            {"projects_scanned": [], "compute": [], "databases": []}, "S", Anonymizer()
        )["gce_vm_info-S.csv"]
        == ""
    )


# ── the ZIP and the run ───────────────────────────────────────────────────────

_STARTED = datetime(2026, 10, 6, 17, 59, 3, tzinfo=timezone.utc)


def _finalise(tmp_path, anonymizer):
    import main

    out = tmp_path / "gcp-sizing-discovery-20261006-175903.json"
    out.write_text(json.dumps(_result()))
    log = tmp_path / "run.log"
    log.write_text("scanned proj-a web-01")
    return (
        main._finalise_zip(
            out, logging.NullHandler(), str(log), started=_STARTED, anonymizer=anonymizer
        ),
        out,
    )


def test_an_anonymized_zip_has_no_json_and_no_real_names(tmp_path):
    zip_path, out = _finalise(tmp_path, Anonymizer())
    zf = zipfile.ZipFile(zip_path)
    names = zf.namelist()
    # no raw discovery JSON (it holds every real name); the manifest names no resource, so it may stay
    assert [n for n in names if n.endswith(".json")] == ["manifest.json"]
    assert sorted(names) == sorted(
        [f"{p}-2026-10-06_175903.csv" for p in FILE_ORDER]
        + ["manifest.json", "output_gcp_2026-10-06_175903.log"]
    )
    assert zf.read("output_gcp_2026-10-06_175903.log").decode() == anonymized_log_note()
    assert "proj-a" not in "".join(zf.read(n).decode() for n in names)
    assert not out.exists()


def test_the_key_file_and_the_real_log_sit_beside_the_zip(tmp_path):
    anonymizer = Anonymizer()
    zip_path, _ = _finalise(tmp_path, anonymizer)
    beside = sorted(p.name for p in tmp_path.iterdir())
    key = "gcp_anonymized_keys_to_actual_values-2026-10-06_175903.csv"
    real_log = "output_gcp_not_anonymized_2026-10-06_175903.log"
    assert beside == sorted([zip_path.name, key, real_log])
    keys = list(csv.reader((tmp_path / key).open(encoding="utf-8")))
    assert keys[0] == ["AnonymizedValue", "ActualValue"] and ["Project-00000", "proj-a"] in keys
    assert (tmp_path / real_log).read_text() == "scanned proj-a web-01"


def test_every_label_in_the_zip_is_in_the_key_file(tmp_path):
    zip_path, _ = _finalise(tmp_path, Anonymizer())
    key = next(tmp_path.glob(f"{KEY_FILE_PREFIX}-*.csv"))
    labels = {row[0] for row in list(csv.reader(key.open(encoding="utf-8")))[1:]}
    seen = set()
    zf = zipfile.ZipFile(zip_path)
    for name in zf.namelist():
        if name.endswith(".csv"):
            for row in list(csv.reader(io.StringIO(zf.read(name).decode())))[1:]:
                seen.update(c for c in row if re.fullmatch(r"[A-Za-z/]+-\d{5}", c))
    assert seen and seen <= labels


def test_a_run_without_anonymize_is_unchanged(tmp_path):
    zip_path, _ = _finalise(tmp_path, None)
    assert any(n.endswith(".json") for n in zipfile.ZipFile(zip_path).namelist())
    assert not list(tmp_path.glob(f"{KEY_FILE_PREFIX}-*"))
    assert not list(tmp_path.glob("output_gcp_not_anonymized_*"))


def test_anonymize_fields_need_anonymize(monkeypatch, capsys):
    import main

    for flag in ("--anonymize-fields", "--not-anonymize-fields"):
        monkeypatch.setattr(sys, "argv", ["main.py", "--mock", flag, "Name"])
        with pytest.raises(SystemExit):
            main.main()
        assert "need --anonymize" in capsys.readouterr().err


def test_anonymize_cannot_be_combined_with_no_csv(monkeypatch, capsys):
    import main

    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--anonymize", "--no-csv"])
    with pytest.raises(SystemExit):
        main.main()
    assert "cannot be used with --no-csv" in capsys.readouterr().err


def test_a_mock_run_with_anonymize_writes_the_zip_the_key_file_and_the_real_log(
    monkeypatch, tmp_path
):
    import main

    monkeypatch.setattr(
        sys, "argv", ["main.py", "--mock", "--anonymize", "--output", str(tmp_path)]
    )
    main.main()
    beside = sorted(p.name for p in tmp_path.iterdir())
    assert [n for n in beside if n.startswith("gcp_sizing_results_")]
    assert [n for n in beside if n.startswith(KEY_FILE_PREFIX)]
    assert [n for n in beside if n.startswith("output_gcp_not_anonymized_")]
    assert not [n for n in beside if n.endswith(".json")]

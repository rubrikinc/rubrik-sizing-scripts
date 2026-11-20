"""Anonymization of the Azure output (-Anonymize).

Expected labels and files were checked against the real anonymizer of Get-AzureSizingInfo.ps1 run in
pwsh on the same rows (default fields, -AnonymizeFields, -NotAnonymizeFields and "Tags").
"""

from __future__ import annotations

import csv
import io
import json
import re
import sys
import zipfile
from pathlib import Path

import pytest

import anonymize
import csv_export
import main
from anonymize import (
    DEFAULT_FIELDS,
    FILE_ORDER,
    KEY_FILE_PREFIX,
    Anonymizer,
    anonymized_log_note,
    file_rank,
)
from csv_export import build_csv_files

_SCRIPT = Path(__file__).resolve().parents[3] / "Get-AzureSizingInfo.ps1"


# ── the field list and the file order ─────────────────────────────────────────


# Fields the Python tool anonymizes that the script's list lacks, because a column it writes holds
# a real id the script never wrote: Az.RecoveryServices 7.x puts the VM's subscription id in
# ContainerSubscriptionId of the VM items file.
ADDED_TO_THE_SCRIPTS_LIST = ("ContainerSubscriptionId",)


@pytest.mark.skipif(not _SCRIPT.exists(), reason="the PowerShell script is not in this checkout")
def test_default_fields_are_the_scripts_list_plus_the_documented_additions():
    text = _SCRIPT.read_text(encoding="utf-8")
    block = text[text.index("$global:anonymizeProperties = @(") :]
    block = block[: block.index(")")]
    script_fields = re.findall(r'"([^"]+)"', block)
    assert [f for f in DEFAULT_FIELDS if f not in ADDED_TO_THE_SCRIPTS_LIST] == script_fields
    assert set(ADDED_TO_THE_SCRIPTS_LIST) <= set(DEFAULT_FIELDS)


def test_file_order_is_the_order_the_script_anonymizes_in():
    assert [file_rank(p) for p in FILE_ORDER] == list(range(len(FILE_ORDER)))
    assert file_rank("azure_sizing_summary") == len(FILE_ORDER)
    assert (
        file_rank("azure_vmdisk_info") < file_rank("azure_sql_info") < file_rank("azure_aks_info")
    )


# ── labels ────────────────────────────────────────────────────────────────────


def test_a_value_becomes_field_dash_number_and_repeats_get_the_same_label():
    a = Anonymizer()
    rows = [a.anonymize_row({"Name": n}) for n in ("vm-a", "vm-b", "vm-a")]
    assert [r["Name"] for r in rows] == ["Name-00000", "Name-00001", "Name-00000"]


def test_labels_ignore_case_and_are_shared_across_fields():
    a = Anonymizer()
    first = a.anonymize_row({"Name": "Shared"})
    second = a.anonymize_row({"StorageAccount": "SHARED"})
    assert first["Name"] == second["StorageAccount"] == "Name-00000"


def test_counters_are_per_field():
    a = Anonymizer()
    row = a.anonymize_row({"Name": "x", "Subscription": "y", "ResourceGroup": "z"})
    assert row == {
        "Name": "Name-00000",
        "Subscription": "Subscription-00000",
        "ResourceGroup": "ResourceGroup-00000",
    }


def test_null_is_left_alone_but_an_empty_string_is_a_value():
    a = Anonymizer()
    row = a.anonymize_row({"Tenant": None, "Database": "", "Server": ""})
    assert row["Tenant"] is None
    assert row["Database"] == row["Server"] == "Database-00000"


def test_other_columns_are_untouched_and_field_names_are_matched_without_case():
    a = Anonymizer()
    row = a.anonymize_row(
        {"vmid": "g", "Region": "westus2", "SizeGiB": 128.0, "InBackupPolicy": True}
    )
    assert row == {
        "vmid": "vmID-00000"[:0] + "vmid-00000",
        "Region": "westus2",
        "SizeGiB": 128.0,
        "InBackupPolicy": True,
    }


def test_list_values_are_anonymized_item_by_item():
    a = Anonymizer()
    assert a.anonymize_row({"Name": ["a", "b", "a"]})["Name"] == [
        "Name-00000",
        "Name-00001",
        "Name-00000",
    ]


def test_numbering_continues_past_ten_where_powershell_repeats():
    a = Anonymizer()
    labels = [a.anonymize_row({"Name": f"v{i}"})["Name"] for i in range(12)]
    assert len(set(labels)) == 12 and labels[11] == "Name-00011"


# ── tags ──────────────────────────────────────────────────────────────────────


def test_tag_columns_are_renamed_without_a_space_and_moved_to_the_end():
    a = Anonymizer()
    row = a.anonymize_row({"Tag: Env": "prod", "Name": "x", "Tag: owner": None, "Region": "r"})
    assert list(row) == ["Name", "Region", "Tag:TagName-00000", "Tag:TagName-00001"]
    assert row["Tag:TagName-00000"] == "TagValue-00000" and row["Tag:TagName-00001"] is None


def test_the_tag_name_keeps_its_leading_space_as_the_label_key():
    a = Anonymizer()
    a.anonymize_row({"Tag: Env": "prod"})
    assert (" Env", "TagName-00000") in [(actual, label) for label, actual in a.key_rows()]


def test_tags_in_not_anonymize_fields_leaves_every_tag_column_alone():
    a = Anonymizer.from_options(not_anonymize_fields="Tags")
    row = a.anonymize_row({"Name": "x", "Tag: Env": "prod"})
    assert row == {"Name": "Name-00000", "Tag: Env": "prod"}


# ── options ───────────────────────────────────────────────────────────────────


def test_extra_fields_are_anonymized_and_matched_without_case():
    a = Anonymizer.from_options(anonymize_fields="Region, instancetype")
    row = a.anonymize_row({"Region": "westus2", "InstanceType": "D4", "Status": "0"})
    assert row == {"Region": "Region-00000", "InstanceType": "InstanceType-00000", "Status": "0"}


def test_not_anonymize_fields_removes_default_fields():
    a = Anonymizer.from_options(not_anonymize_fields="name,Tenant")
    row = a.anonymize_row({"Name": "x", "Tenant": "t", "Subscription": "s"})
    assert row == {"Name": "x", "Tenant": "t", "Subscription": "Subscription-00000"}


def test_a_field_in_both_lists_is_not_anonymized():
    a = Anonymizer.from_options(anonymize_fields="Region", not_anonymize_fields="Region")
    assert a.anonymize_row({"Region": "r"}) == {"Region": "r"}


# ── the key file ──────────────────────────────────────────────────────────────


def test_key_file_maps_labels_back_sorted_by_label_with_every_value_quoted():
    a = Anonymizer()
    a.anonymize_row({"Subscription": "S one", "Name": 'say "hi"', "Tenant": "T"})
    assert a.key_file_text() == (
        '"AnonymizedValue","ActualValue"\n'
        '"Name-00000","say ""hi"""\n'
        '"Subscription-00000","S one"\n'
        '"Tenant-00000","T"\n'
    )


def test_key_file_keeps_the_first_spelling_of_a_value():
    a = Anonymizer()
    a.anonymize_row({"Name": "Web"})
    a.anonymize_row({"Name": "WEB"})
    assert a.key_rows() == [("Name-00000", "Web")]


def test_the_log_note_and_key_file_name_match_the_script():
    assert anonymized_log_note().startswith("Anonymized file; customer has original.")
    assert KEY_FILE_PREFIX == "azure_anonymized_keys_to_actual_values"


# ── the files ─────────────────────────────────────────────────────────────────


def _result() -> dict:
    return {
        "tenant_name": "Contoso",
        "tenant_id": "t",
        "subscription_names": {"sub-1": "Sub One"},
        "tag_names": {"sub-1": ["Env"]},
        "compute": [
            {
                "subscription_id": "sub-1",
                "vms": [
                    {
                        "name": "web-01",
                        "location": "westus2",
                        "resource_group": "rg-web",
                        "vm_id": "g1",
                        "vm_size": "D4",
                        "disks": [{}],
                        "total_disk_gb": 128,
                        "tags": {"Env": "prod"},
                        "sql_server": None,
                    }
                ],
            }
        ],
        "storage": [
            {
                "subscription_id": "sub-1",
                "accounts": [
                    {
                        "name": "web-01",
                        "kind": "StorageV2",
                        "sku": "Standard_LRS",
                        "location": "westus2",
                        "resource_group": "rg-web",
                        "blob_count": 5,
                        "tags": {"Env": "prod"},
                    }
                ],
            }
        ],
    }


def test_files_are_anonymized_and_the_summary_is_not():
    files = build_csv_files(_result(), "S", Anonymizer())
    vm = list(csv.reader(io.StringIO(files["azure_vmdisk_info-S.csv"])))
    cells = dict(zip(vm[0], vm[1]))
    assert cells["Name"] == "Name-00000" and cells["Subscription"] == "Subscription-00000"
    assert cells["Region"] == "westus2" and cells["Tag:TagName-00000"] == "TagValue-00000"
    assert "web-01" not in files["azure_vmdisk_info-S.csv"]
    assert "Contoso" not in "".join(files.values())
    assert (
        files["azure_sizing_summary_S.csv"]
        == build_csv_files(_result(), "S")["azure_sizing_summary_S.csv"]
    )


def test_a_value_in_two_files_gets_one_label_and_the_first_file_decides_the_field():
    files = build_csv_files(_result(), "S", Anonymizer())
    storage = list(csv.reader(io.StringIO(files["azure_storage_account_info-S.csv"])))
    cells = dict(zip(storage[0], storage[1]))
    assert cells["StorageAccount"] == "Name-00000"  # first met as a VM Name
    assert cells["Subscription"] == "Subscription-00000"


def test_labels_are_numbered_in_the_scripts_file_order_not_the_writing_order():
    result = _result()
    result["compute"][0]["vms"][0]["name"] = "vm-name"
    result["storage"][0]["accounts"][0]["name"] = "sa-name"
    a = Anonymizer()
    build_csv_files(result, "S", a)
    assert dict(a.key_rows())["Name-00000"] == "vm-name"
    assert dict(a.key_rows())["StorageAccount-00000"] == "sa-name"


def test_tag_columns_are_the_renamed_ones_and_files_without_rows_stay_empty():
    files = build_csv_files(_result(), "S", Anonymizer())
    assert files["azure_vmdisk_info-S.csv"].splitlines()[0].endswith('"Tag:TagName-00000"')
    assert files["azure_sql_info-S.csv"] == ""


def test_unanonymized_output_is_unchanged_by_the_new_argument():
    assert build_csv_files(_result(), "S") == build_csv_files(_result(), "S", None)


def test_skipped_files_are_not_written_when_anonymizing():
    result = {**_result(), "skipped": ["vms"]}
    assert "azure_vmdisk_info-S.csv" not in build_csv_files(result, "S", Anonymizer())


# ── a run ─────────────────────────────────────────────────────────────────────


def _run(monkeypatch, tmp_path, *flags):
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path), *flags])
    main.main()
    return list(tmp_path.glob("azure_sizing_results_*.zip"))[0]


def test_anonymize_fields_need_anonymize(monkeypatch, tmp_path, capsys):
    for flag in ("--anonymize-fields", "--not-anonymize-fields"):
        monkeypatch.setattr(sys, "argv", ["main.py", "--mock", flag, "Name"])
        with pytest.raises(SystemExit):
            main.main()
        assert "need --anonymize" in capsys.readouterr().err


def test_anonymize_cannot_be_combined_with_no_csv(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--anonymize", "--no-csv"])
    with pytest.raises(SystemExit):
        main.main()
    assert "cannot be used with --no-csv" in capsys.readouterr().err


def test_an_anonymized_run_keeps_real_names_out_of_the_zip(monkeypatch, tmp_path):
    archive = _run(monkeypatch, tmp_path, "--anonymize")
    zf = zipfile.ZipFile(archive)
    names = zf.namelist()
    # no raw discovery JSON (it holds every real name); the manifest names no resource, so it may stay
    assert [n for n in names if n.endswith(".json")] == ["manifest.json"]
    assert any(n.startswith("azure_vmdisk_info-") for n in names)
    text = "".join(zf.read(n).decode("utf-8") for n in names)
    for real in ("sql-prod-01", "stgproddata", "sap-hana-01", "rg-prod-east"):
        assert real not in text, real
    log = next(n for n in names if n.startswith("output_azure_") and n.endswith(".log"))
    assert zf.read(log).decode() == anonymized_log_note()


def test_the_key_file_and_the_real_log_sit_beside_the_zip(monkeypatch, tmp_path):
    archive = _run(monkeypatch, tmp_path, "--anonymize")
    beside = sorted(p.name for p in tmp_path.iterdir())
    key = next(n for n in beside if n.startswith(f"{KEY_FILE_PREFIX}-") and n.endswith(".csv"))
    real_log = next(n for n in beside if n.startswith("output_azure_not_anonymized_"))
    stamp = key[len(KEY_FILE_PREFIX) + 1 : -4]
    assert real_log == f"output_azure_not_anonymized_{stamp}.log"
    assert f"output_azure_{stamp}.log" in zipfile.ZipFile(archive).namelist()
    assert sorted(beside) == sorted([archive.name, key, real_log])
    keys = list(csv.reader(io.StringIO((tmp_path / key).read_text(encoding="utf-8"))))
    assert keys[0] == ["AnonymizedValue", "ActualValue"]
    assert ["Name-00000", "sql-prod-01"] in keys
    real = (tmp_path / real_log).read_text(encoding="utf-8")
    assert "00000000-0000-0000-0000-aabbccddeeff" in real  # the real log names the subscription
    assert real != anonymized_log_note()


def test_every_label_in_the_zip_can_be_mapped_back(monkeypatch, tmp_path):
    archive = _run(monkeypatch, tmp_path, "--anonymize")
    key = next(tmp_path.glob(f"{KEY_FILE_PREFIX}-*.csv"))
    labels = {row[0] for row in list(csv.reader(key.open(encoding="utf-8")))[1:]}
    zf = zipfile.ZipFile(archive)
    seen = set()
    for name in zf.namelist():
        if name.endswith(".csv"):
            for row in list(csv.reader(io.StringIO(zf.read(name).decode())))[1:]:
                seen.update(c for c in row if re.fullmatch(r"[A-Za-z]+-\d{5}", c))
    assert seen and seen <= labels


def test_keep_artifacts_keeps_the_raw_json_and_says_so(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, "--anonymize", "--keep-artifacts")
    assert list(tmp_path.glob("rubrik-discovery-*.json"))
    assert json.loads(next(tmp_path.glob("rubrik-discovery-*.json")).read_text())["tenant_id"]


def test_options_reach_the_files_in_a_run(monkeypatch, tmp_path):
    archive = _run(monkeypatch, tmp_path, "--anonymize", "--not-anonymize-fields", "Tags,Name")
    zf = zipfile.ZipFile(archive)
    vm = zf.read(next(n for n in zf.namelist() if n.startswith("azure_vmdisk_info-"))).decode()
    header, first = list(csv.reader(io.StringIO(vm)))[:2]
    cells = dict(zip(header, first))
    assert cells["Name"] == "sql-prod-01"
    assert "Tag: application" in header
    assert cells["Subscription"].startswith("Subscription-")


def test_a_run_without_anonymize_is_unchanged(monkeypatch, tmp_path):
    archive = _run(monkeypatch, tmp_path)
    names = zipfile.ZipFile(archive).namelist()
    assert any(n.endswith(".json") for n in names)
    assert not list(tmp_path.glob(f"{KEY_FILE_PREFIX}-*"))
    assert not list(tmp_path.glob("output_azure_not_anonymized_*"))

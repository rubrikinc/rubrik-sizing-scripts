"""Tests for contract/build_columns.py. The unit tests need no PowerShell."""

import json
import shutil
import subprocess
import sys

import pytest
from contract import build_columns as bc

CTX_LOOP = ["10-90"]


def _obj(keys, var="$o", fn="Get-X", line=1, how="PSCustomObject", ctx=None):
    return {
        "kind": "obj",
        "var": var,
        "fn": fn,
        "line": line,
        "how": how,
        "keys": keys,
        "ctx": ctx or [],
    }


def _am(name, line, target="$o", fn="Get-X", ctx=None, dynamic=False):
    return {
        "kind": "addmember",
        "target": target,
        "name": name,
        "line": line,
        "fn": fn,
        "ctx": ctx or [],
        "dynamic": dynamic,
    }


HELPER_FACTS = [
    _am("ResourceArn", 100, "$Row", "Add-BackupColumnsToRow"),
    _am("HasBackups", 101, "$Row", "Add-BackupColumnsToRow"),
    _am("BackupCount", 102, "$Row", "Add-BackupColumnsToRow"),
]


def test_constructor_keys_keep_order():
    facts = [_obj(["B", "A", "C"])]
    cols, dyn = bc.row_columns(facts, facts[0], bc._helper_columns(facts))
    assert [c["name"] for c in cols] == ["B", "A", "C"] and dyn == []


def test_helper_columns_appended_and_existing_resourcearn_keeps_position():
    facts = HELPER_FACTS + [
        _obj(["Id", "ResourceArn", "Size"]),
        {
            "kind": "helper",
            "helper": "Add-BackupColumnsToRow",
            "target": "$o",
            "line": 5,
            "fn": "Get-X",
            "ctx": [],
        },
    ]
    ctor = facts[3]
    cols, _ = bc.row_columns(facts, ctor, bc._helper_columns(facts))
    assert [c["name"] for c in cols] == ["Id", "ResourceArn", "Size", "HasBackups", "BackupCount"]


def test_tag_columns_are_dynamic_patterns():
    facts = [_obj(["A"], ctx=[]), _am('"Tag: $key"', 5, ctx=CTX_LOOP, dynamic=True)]
    cols, dyn = bc.row_columns(facts, facts[0], {})
    assert [c["name"] for c in cols] == ["A"]
    assert dyn == ["Tag: {key}"]


def test_column_added_in_extra_branch_is_optional_but_enclosing_loop_is_not():
    outer = ["1-1000"]
    facts = [
        _obj(["A"], ctx=outer),
        _am("Always", 5, ctx=outer),
        _am("Sometimes", 6, ctx=outer + ["50-80"]),
    ]
    cols, _ = bc.row_columns(facts, facts[0], {})
    assert {c["name"]: c["optional"] for c in cols} == {
        "A": False,
        "Always": False,
        "Sometimes": True,
    }


def test_ordered_hashtable_add_calls_become_columns():
    facts = [
        _obj([], how="ordered"),
        {
            "kind": "add",
            "target": "$o",
            "name": "One",
            "dynamic": False,
            "line": 2,
            "fn": "Get-X",
            "ctx": [],
        },
        {
            "kind": "add",
            "target": "$o",
            "name": "Two",
            "dynamic": False,
            "line": 3,
            "fn": "Get-X",
            "ctx": [],
        },
    ]
    cols, _ = bc.row_columns(facts, facts[0], {})
    assert [c["name"] for c in cols] == ["One", "Two"]


def test_events_stop_at_next_constructor_of_same_variable():
    facts = [_obj(["A"], line=1), _am("OnlyFirst", 3), _obj(["B"], line=10), _am("OnlySecond", 12)]
    first, _ = bc.row_columns(facts, facts[0], {})
    second, _ = bc.row_columns(facts, facts[2], {})
    assert [c["name"] for c in first] == ["A", "OnlyFirst"]
    assert [c["name"] for c in second] == ["B", "OnlySecond"]


def test_merge_producers_marks_missing_columns_optional():
    a = ([{"name": "X", "optional": False}, {"name": "Y", "optional": False}], [])
    b = ([{"name": "X", "optional": False}, {"name": "Z", "optional": False}], [])
    cols, _, differ = bc.merge_producers([a, b])
    assert differ is True
    assert {c["name"]: c["optional"] for c in cols} == {"X": False, "Y": True, "Z": True}


def test_parse_file_names():
    text = (
        '$outputRDS = "aws_rds_info-$date_string.csv"\n'
        '$outputAKS = "azure_aks_info-$($fileDate).csv"\n'
        '$outputSummary = "./azure_sizing_summary_$($fileDate).csv"\n'
        '$outputPlans = "aws-backup-plans-info-$date_string.json"\n'
    )
    n = bc.parse_file_names(text)
    assert n["outputRDS"] == {"prefix": "aws_rds_info", "separator": "-", "extension": "csv"}
    assert n["outputAKS"]["prefix"] == "azure_aks_info"
    assert n["outputSummary"] == {
        "prefix": "azure_sizing_summary",
        "separator": "_",
        "extension": "csv",
    }
    assert n["outputPlans"]["extension"] == "json"


def test_decision_is_carried_into_the_output_entry():
    facts = [_obj(["A"])]
    cfg = {
        "files": {
            "$outputX": {"decision": "DEC-8", "producers": [{"fn": "Get-X"}]},
            "$outputY": {"producers": [{"fn": "Get-X"}]},
        }
    }
    text = '$outputX = "x-$date_string.csv"\n$outputY = "y-$date_string.csv"'
    x, y = bc.build_cloud(facts, cfg, text)
    assert x["decision"] == "DEC-8"
    assert "decision" not in y


def test_unmatched_selector_is_an_error():
    cfg = {"files": {"$outputX": {"producers": [{"fn": "Nope"}]}}}
    with pytest.raises(ValueError):
        bc.build_cloud([_obj(["A"])], cfg, '$outputX = "x-$date_string.csv"')


# ── committed columns.json ────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def committed():
    return json.loads(bc.OUTPUT.read_text())


def _file(committed, cloud, prefix):
    return next(f for f in committed["clouds"][cloud] if f.get("prefix") == prefix)


def test_every_configured_file_is_present(committed):
    cfg = json.loads(bc.SOURCES.read_text())
    for cloud, spec in cfg.items():
        if cloud.startswith("_"):
            continue
        assert len(committed["clouds"][cloud]) == len(spec["files"])


def test_rds_columns_follow_powershell_code_not_stale_examples(committed):
    names = [c["name"] for c in _file(committed, "aws", "aws_rds_info")["columns"]]
    assert names[:8] == [
        "AwsAccountId",
        "AwsAccountAlias",
        "DBName",
        "DBInstanceIdentifier",
        "DBClusterIdentifier",
        "ResourceArn",
        "SizeGiB",
        "SizeTiB",
    ]
    assert "InstanceCount" in names and "BackupEnumerationTruncated" in names
    assert _file(committed, "aws", "aws_rds_info")["dynamic"] == ["Tag: {key}"]


def test_gcp_label_prefix_and_six_files(committed):
    files = committed["clouds"]["gcp"]
    assert [f["prefix"] for f in files] == [
        "gce_vm_info",
        "gce_attached_disk_info",
        "gce_unattached_disk_info",
        "gce_cloudsql_info",
        "gce_spanner_info",
        "gce_bigquery_info",
    ]
    assert all(f["dynamic"] == ["Label/Tag: {labelKey}"] for f in files[:5])
    # BigQuery adds its labels with Add-LabelsToObject: dataset labels get a dataset_ prefix.
    assert files[5]["dynamic"] == ["Label/Tag: dataset_{labelKey}", "Label/Tag: {labelKey}"]


def test_azure_summary_file_uses_underscore_separator(committed):
    assert _file(committed, "azure", "azure_sizing_summary")["separator"] == "_"


def test_unresolved_files_are_explained(committed):
    unresolved = [f for f in committed["clouds"]["azure"] if f["status"] == "unresolved"]
    assert len(unresolved) == 5
    assert all(f["notes"] and f["columns"] == [] for f in unresolved)


def test_columns_unique_within_each_file(committed):
    for files in committed["clouds"].values():
        for f in files:
            names = [c["name"] for c in f["columns"]]
            assert len(names) == len(set(names)), f["export_var"]


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not installed")
def test_committed_columns_match_fresh_extraction():
    proc = subprocess.run(
        [sys.executable, "-m", "contract.build_columns", "--check"],
        cwd=bc.HERE.parent,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr

"""Tests for csv_export.py (PowerShell-style CSV files).

Expected cell text for the size and float cases was taken from the PowerShell script itself:
the real row-building lines of Get-AzureSizingInfo.ps1 were run in pwsh on the same inputs.
"""

from __future__ import annotations

import csv
import io
import sys
import zipfile
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import pytest

import csv_export
from csv_export import (
    _format_float,
    _size_columns,
    _units_from_gib,
    build_csv_files,
    render,
    unique_tag_names,
)
from tests.test_storage import _make_collector as _make_storage_collector


def _parse(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def _result(**overrides) -> dict:
    result = {
        "tenant_name": "Contoso",
        "subscription_names": {"sub-1": "Sub One"},
        "tag_names": {"sub-1": ["Env", "owner"]},
        "compute": [],
        "storage": [],
        "backup_posture": [],
    }
    result.update(overrides)
    return result


def _vm(**overrides) -> dict:
    vm = {
        "name": "vm-a",
        "location": "westus2",
        "resource_group": "RG-One",
        "vm_id": "1111-2222",
        "vm_size": "Standard_D4s_v3",
        "disks": [{}, {}, {}],
        "total_disk_gb": 1536,
        "tags": {"env": "prod"},
        "sql_server": None,
    }
    vm.update(overrides)
    return vm


# ── value formatting ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value,text",
    [
        (100.0, "100"),
        (0.1, "0.1"),
        (1234.5, "1234.5"),
        (999999999999999.0, "999999999999999"),
        (1e15, "1000000000000000"),
        (1000000000000007.0, "1000000000000007"),
        (1234567890123456.8, "1234567890123456.8"),
        (1.5e16, "15000000000000000"),
        (9.999999999999998e16, "99999999999999980"),
        (1e17, "1E+17"),
        (1.1e17, "1.1E+17"),
        (1.2345678901234568e17, "1.2345678901234568E+17"),
        (1e20, "1E+20"),
        (0.000123, "0.000123"),
        (1e-05, "1E-05"),
        (1.5e-07, "1.5E-07"),
    ],
)
def test_double_text_matches_dotnet(value, text):
    assert _format_float(value) == text


def test_render_quotes_everything_but_nulls():
    text = render(["a", "b", "c", "d"], [{"a": 1, "b": None, "c": "", "d": 'x"y'}])
    assert text == '"a","b","c","d"\n"1",,,"x""y"\n'


def test_render_writes_an_empty_string_as_quoted_only_in_quoted_empty_columns():
    text = render(["a", "b"], [{"a": "", "b": ""}], frozenset({"b"}))
    assert text == '"a","b"\n,""\n'


def test_render_bool_and_missing_key():
    assert render(["a", "b"], [{"a": True}]) == '"a","b"\n"True",\n'


def test_no_rows_gives_an_empty_file():
    assert render(["a"], []) == ""


# ── size columns ──────────────────────────────────────────────────────────────


def test_size_columns_from_bytes():
    cells = _size_columns("UsedCapacity", 536870912000)
    assert cells == {
        "UsedCapacityBytes": 536870912000,
        "UsedCapacityGiB": 500.0,
        "UsedCapacityTiB": 0.4883,
        "UsedCapacityGB": 536.871,
        "UsedCapacityTB": 0.5369,
    }


def test_size_columns_null_bytes_stay_null_and_units_are_zero():
    cells = _size_columns("UsedCapacity", None)
    assert cells["UsedCapacityBytes"] is None
    assert [cells[f"UsedCapacity{s}"] for s in ("GiB", "TiB", "GB", "TB")] == [0.0] * 4


def test_gib_precision_zero_rounds_half_to_even():
    assert _size_columns("X", 1073741824 * 2.5)["XGiB"] == 2.0


def test_units_from_gib():
    assert _units_from_gib(1536) == {
        "SizeGiB": 1536,
        "SizeTiB": 1.5,
        "SizeGB": 1649.267,
        "SizeTB": 1.6493,
    }


# ── tags ──────────────────────────────────────────────────────────────────────


def test_unique_tag_names_ignore_case_across_subscriptions():
    names = unique_tag_names({"tag_names": {"a": ["owner", "Env"], "b": ["ENV", "zeta", ""]}})
    assert names == ["Env", "owner", "zeta"]


def test_tag_columns_exist_for_names_no_row_carries():
    result = _result(
        tag_names={"sub-1": ["Env", "unused"]},
        compute=[{"subscription_id": "sub-1", "vms": [_vm()]}],
    )
    header, row = _parse(build_csv_files(result, "S")["azure_vmdisk_info-S.csv"])
    assert header[-2:] == ["Tag: Env", "Tag: unused"]
    assert row[-2:] == ["prod", "-"]


def test_tag_lookup_ignores_case_and_empty_value_is_a_dash():
    result = _result(
        tag_names={"sub-1": ["ENV", "owner"]},
        compute=[{"subscription_id": "sub-1", "vms": [_vm(tags={"env": "prod", "Owner": ""})]}],
    )
    _, row = _parse(build_csv_files(result, "S")["azure_vmdisk_info-S.csv"])
    assert row[-2:] == ["prod", "-"]


# ── azure_vmdisk_info ─────────────────────────────────────────────────────────


def test_vm_row():
    result = _result(compute=[{"subscription_id": "sub-1", "vms": [_vm()]}])
    header, row = _parse(build_csv_files(result, "S")["azure_vmdisk_info-S.csv"])
    assert header[:16] == csv_export._VM_COLUMNS
    cells = dict(zip(header, row))
    assert cells["Name"] == "vm-a"
    assert cells["Disks"] == "3"
    assert [cells[c] for c in ("SizeGiB", "SizeTiB", "SizeGB", "SizeTB")] == [
        "1536",
        "1.5",
        "1649.267",
        "1.6493",
    ]
    assert cells["Subscription"] == "Sub One"
    assert cells["Tenant"] == "Contoso"
    assert cells["vmID"] == "1111-2222"
    assert cells["Status"] == "OK"
    assert cells["HasMSSQL"] == "No"
    assert cells["BackupPolicies"] == "-"
    assert cells["InBackupPolicy"] == "False"


def test_vm_with_sql_and_missing_names():
    result = _result(
        tenant_name=None,
        subscription_names={},
        compute=[{"subscription_id": "sub-1", "vms": [_vm(sql_server={"edition": "Standard"})]}],
    )
    text = build_csv_files(result, "S")["azure_vmdisk_info-S.csv"]
    header, row = _parse(text)
    cells = dict(zip(header, row))
    assert cells["HasMSSQL"] == "Yes"
    assert cells["Subscription"] == "sub-1"
    assert cells["Tenant"] == ""
    assert ',"sub-1",,"westus2"' in text


def _posture(items, vaults=None):
    return {
        "subscription_id": "SUB-1",
        "vaults": vaults or [{"name": "Vault-A", "location": "WestUS2"}],
        "protected_items": items,
    }


def _item(**overrides) -> dict:
    item = {
        "workload_type": "VM",
        "policy_name": "GoldPolicy",
        "vault_name": "vault-a",
        "source_resource_id": "/subscriptions/x/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/VM-A",
    }
    item.update(overrides)
    return item


def test_backup_policy_joins_on_subscription_vm_name_and_vault_region():
    result = _result(
        compute=[{"subscription_id": "sub-1", "vms": [_vm(), _vm(name="vm-b", location="eastus")]}],
        backup_posture=[_posture([_item()])],
    )
    header, first, second = _parse(build_csv_files(result, "S")["azure_vmdisk_info-S.csv"])
    cells = dict(zip(header, first))
    assert (cells["BackupPolicies"], cells["InBackupPolicy"]) == ("GoldPolicy", "True")
    cells = dict(zip(header, second))
    assert (cells["BackupPolicies"], cells["InBackupPolicy"]) == ("-", "False")


def test_backup_policy_ignores_other_workloads_and_items_without_a_policy():
    result = _result(
        compute=[{"subscription_id": "sub-1", "vms": [_vm()]}],
        backup_posture=[
            _posture([_item(workload_type="SQL"), _item(policy_name=None), _item(policy_name="")])
        ],
    )
    header, row = _parse(build_csv_files(result, "S")["azure_vmdisk_info-S.csv"])
    assert dict(zip(header, row))["BackupPolicies"] == "-"


def test_backup_policies_are_joined_with_comma_space():
    result = _result(
        compute=[{"subscription_id": "sub-1", "vms": [_vm()]}],
        backup_posture=[_posture([_item(), _item(policy_name="Silver")])],
    )
    header, row = _parse(build_csv_files(result, "S")["azure_vmdisk_info-S.csv"])
    assert dict(zip(header, row))["BackupPolicies"] == "GoldPolicy, Silver"


# ── azure_storage_account_info ────────────────────────────────────────────────


def _account(**overrides) -> dict:
    account = {
        "name": "sa1",
        "kind": "StorageV2",
        "hns_enabled": True,
        "sku": "Standard_LRS",
        "access_tier": "Hot",
        "location": "westus2",
        "resource_group": "rg-one",
        "capacity_bytes": 536870912000.0,
        "blob_capacity_bytes": 500000000000.0,
        "file_capacity_bytes": 36870912000.0,
        "blob_container_count": 12,
        "blob_count": 345678,
        "file_share_count": 3,
        "file_count": 9999,
        "tags": {"Env": "prod"},
    }
    account.update(overrides)
    return account


def test_storage_account_row():
    result = _result(storage=[{"subscription_id": "sub-1", "accounts": [_account()]}])
    header, row = _parse(build_csv_files(result, "S")["azure_storage_account_info-S.csv"])
    assert header[:-2] == csv_export._STORAGE_ACCOUNT_COLUMNS
    cells = dict(zip(header, row))
    assert cells["HNSEnabled(ADLSGen2)"] == "True"
    assert cells["StorageAccountType"] == "StorageV2"
    assert cells["UsedCapacityBytes"] == "536870912000"
    assert cells["UsedCapacityGiB"] == "500"
    assert cells["UsedBlobCapacityGB"] == "500"
    assert cells["BlobContainerCount"] == "12"
    assert cells["FileCountInFileShares"] == "9999"
    assert cells["Tag: Env"] == "prod"
    assert cells["Tag: owner"] == "-"


def test_storage_account_missing_metrics_are_null_in_bytes_and_zero_in_units():
    account = _account(
        hns_enabled=None,
        access_tier=None,
        capacity_bytes=None,
        blob_container_count=None,
        blob_count=None,
        file_share_count=None,
        file_count=None,
    )
    result = _result(storage=[{"subscription_id": "sub-1", "accounts": [account]}])
    header, row = _parse(build_csv_files(result, "S")["azure_storage_account_info-S.csv"])
    cells = dict(zip(header, row))
    for column in (
        "HNSEnabled(ADLSGen2)",
        "StorageAccountAccessTier",
        "UsedCapacityBytes",
        "BlobContainerCount",
        "BlobCount",
        "FileShareCount",
        "FileCountInFileShares",
    ):
        assert cells[column] == "", column
    assert cells["UsedCapacityGiB"] == "0"
    assert cells["UsedCapacityTB"] == "0"


# ── files ─────────────────────────────────────────────────────────────────────


def test_empty_result_gives_empty_files_with_powershell_names():
    files = build_csv_files(_result(), "2026-10-05_1918")
    assert files == {
        "azure_vmdisk_info-2026-10-05_1918.csv": "",
        "azure_storage_account_info-2026-10-05_1918.csv": "",
        "azure_file_share_info-2026-10-05_1918.csv": "",
        "azure_backup_vault_info-2026-10-05_1918.csv": "",
        "azure_backup_costs-2026-10-05_1918.csv": "",
        "azure_aks_info-2026-10-05_1918.csv": "",
        "azure_sizing_summary_2026-10-05_1918.csv": "",
        "azure_cosmos_db-2026-10-05_1918.csv": "",
        "azure_sql_info-2026-10-05_1918.csv": "",
        "azure_mi_sql_info-2026-10-05_1918.csv": "",
        "azure_mi_db_items-2026-10-05_1918.json": "{}\n",
    }


def test_write_csv_files(tmp_path):
    result = _result(compute=[{"subscription_id": "sub-1", "vms": [_vm()]}])
    paths = csv_export.write_csv_files(result, str(tmp_path), "S")
    assert sorted(p.rsplit("/", 1)[-1] for p in paths) == [
        "azure_aks_info-S.csv",
        "azure_backup_costs-S.csv",
        "azure_backup_vault_info-S.csv",
        "azure_cosmos_db-S.csv",
        "azure_file_share_info-S.csv",
        "azure_mi_db_items-S.json",
        "azure_mi_sql_info-S.csv",
        "azure_sizing_summary_S.csv",
        "azure_sql_info-S.csv",
        "azure_storage_account_info-S.csv",
        "azure_vmdisk_info-S.csv",
    ]
    raw = (tmp_path / "azure_vmdisk_info-S.csv").read_bytes()
    assert raw.startswith(b'"Name"') and b"\r" not in raw and raw.endswith(b"\n")


# ── data the export relies on ─────────────────────────────────────────────────


def _metric(value):
    return NS(value=[NS(timeseries=[NS(data=[NS(maximum=value)])])])


def test_storage_collector_reads_service_metrics_and_hns():
    values = {"BlobCapacity": 1000.0, "FileCapacity": 2000.0, "ContainerCount": 7.0}

    def effect(resource_uri, **kwargs):
        name = kwargs["metricnames"]
        if name in values:
            return _metric(values[name])
        raise Exception("not a metric under test")

    account = NS(
        id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
        name="sa1",
        location="westus2",
        sku=NS(name="Standard_LRS"),
        kind="StorageV2",
        access_tier="Hot",
        tags={},
        is_hns_enabled=True,
    )
    collector = _make_storage_collector(accounts=[account], metrics_effect=effect)
    (info,) = collector._list_accounts()
    assert info.hns_enabled is True
    assert info.blob_capacity_bytes == 1000.0
    assert info.file_capacity_bytes == 2000.0
    assert info.blob_container_count == 7


def test_storage_collector_skips_service_metrics_when_capacity_is_off():
    collector = _make_storage_collector(collect_capacity=False)
    assert collector._get_service_metrics("/x") == {
        "blob_capacity_bytes": None,
        "file_capacity_bytes": None,
        "blob_container_count": None,
    }


def test_collect_tag_names():
    from collectors import tags

    client = MagicMock()
    client.tags.list.return_value = iter(
        [NS(tag_name="Env"), NS(tag_name=None), NS(tag_name="owner")]
    )
    with patch.object(tags, "ResourceManagementClient", return_value=client):
        assert tags.collect_tag_names("sub", MagicMock()) == ["Env", "owner"]


def test_collect_tag_names_failure_returns_nothing():
    from collectors import tags

    with patch.object(tags, "ResourceManagementClient", side_effect=RuntimeError("denied")):
        assert tags.collect_tag_names("sub", MagicMock()) == []


def test_resolve_tenant_name():
    import auth

    client = MagicMock()
    client.tenants.list.return_value = iter(
        [NS(tenant_id="AAA", display_name="Other"), NS(tenant_id="BBB", display_name="Contoso")]
    )
    with patch.object(auth, "SubscriptionClient", return_value=client):
        assert auth.resolve_tenant_name(MagicMock(), "bbb") == "Contoso"


def test_resolve_tenant_name_is_none_when_missing_or_failing():
    import auth

    client = MagicMock()
    client.tenants.list.return_value = iter([NS(tenant_id="AAA", display_name=None)])
    with patch.object(auth, "SubscriptionClient", return_value=client):
        assert auth.resolve_tenant_name(MagicMock(), "AAA") is None
    with patch.object(auth, "SubscriptionClient", side_effect=RuntimeError("denied")):
        assert auth.resolve_tenant_name(MagicMock(), "AAA") is None


# ── the run ───────────────────────────────────────────────────────────────────


def _run_mock(monkeypatch, tmp_path, *extra):
    import main

    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path), *extra])
    main.main()


def test_run_puts_the_csv_files_in_the_zip(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path)
    (archive,) = tmp_path.glob("azure_sizing_results_*.zip")
    names = zipfile.ZipFile(archive).namelist()
    assert any(n.startswith("azure_vmdisk_info-") and n.endswith(".csv") for n in names)
    assert any(n.startswith("azure_storage_account_info-") for n in names)
    assert any(n.startswith("rubrik-discovery-") and n.endswith(".json") for n in names)
    assert any(n.startswith("output_azure_") and n.endswith(".log") for n in names)
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


def test_run_with_no_csv_writes_only_the_json_and_log(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path, "--no-csv")
    (archive,) = tmp_path.glob("azure_sizing_results_*.zip")
    assert not [n for n in zipfile.ZipFile(archive).namelist() if n.endswith(".csv")]


def test_mock_vm_file_has_a_row_per_vm_and_tag_columns(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path)
    (archive,) = tmp_path.glob("azure_sizing_results_*.zip")
    zf = zipfile.ZipFile(archive)
    name = next(n for n in zf.namelist() if n.startswith("azure_vmdisk_info-"))
    header, *rows = _parse(zf.read(name).decode("utf-8"))
    assert header[:16] == csv_export._VM_COLUMNS
    assert {"Tag: application", "Tag: owner"} <= set(header)
    assert len(rows) >= 5
    assert all(len(r) == len(header) for r in rows)

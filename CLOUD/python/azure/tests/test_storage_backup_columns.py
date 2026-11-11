"""BackupPolicies and InBackupPolicy on the storage account and file share files.

PowerShell 1.0.3 fills them from the Azure Files items of Recovery Services vaults (and, for Blob, from
Backup Vault items): ``Set-AzureStorageBackupProtection``.
"""

from __future__ import annotations

import csv
import io
from unittest.mock import MagicMock

from csv_export import _files_protection, build_csv_files
from tests.test_backup_posture import SUB_ID, _make_collector, _make_vault

ACCOUNT_ID = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct1"


def _result(items=(), accounts=None) -> dict:
    accounts = accounts or [
        {
            "name": "acct1",
            "resource_group": "rg",
            "location": "eastus",
            "file_shares": [
                {"name": "share1", "quota_gib": 100},
                {"name": "share2", "quota_gib": 50},
            ],
        },
        {"name": "acct2", "resource_group": "rg", "location": "eastus", "file_shares": []},
    ]
    return {
        "tenant_name": "T",
        "tenant_id": "t",
        "subscription_names": {"s1": "Sub1"},
        "tag_names": {},
        "skipped": [],
        "storage": [{"subscription_id": "s1", "accounts": accounts}],
        "backup_posture": [{"subscription_id": "s1", "vaults": [], "protected_items": list(items)}],
    }


def _item(**overrides) -> dict:
    item = {
        "workload_type": "Files",
        "name": "AzureFileShare;share1",
        "friendly_name": "share1",
        "source_resource_id": ACCOUNT_ID,
        "policy_name": "daily",
        "vault_name": "v",
    }
    item.update(overrides)
    return item


def _table(result, prefix) -> list[dict[str, str]]:
    files = build_csv_files(result, "2026-10-22_1102")
    text = next(t for n, t in files.items() if n.startswith(prefix))
    return list(csv.DictReader(io.StringIO(text)))


def _accounts(result) -> dict[str, dict[str, str]]:
    return {r["StorageAccount"]: r for r in _table(result, "azure_storage_account_info")}


def _shares(result) -> dict[str, dict[str, str]]:
    return {r["Name"]: r for r in _table(result, "azure_file_share_info")}


def test_the_columns_are_the_last_fixed_columns_of_both_files():
    files = build_csv_files(_result(), "2026-10-22_1102")
    for prefix, last in (
        ("azure_storage_account_info", "FileCountInFileShares"),
        ("azure_file_share_info", None),
    ):
        header = next(
            csv.reader(io.StringIO(next(t for n, t in files.items() if n.startswith(prefix))))
        )
        assert header[-2:] == ["BackupPolicies", "InBackupPolicy"]
        if last:
            assert header[-3] == last


def test_nothing_is_protected_without_a_backup_item():
    accounts, shares = _accounts(_result()), _shares(_result())
    for row in [*accounts.values(), *shares.values()]:
        assert (row["BackupPolicies"], row["InBackupPolicy"]) == ("-", "False")


def test_a_protected_share_flags_its_share_and_its_account_only():
    result = _result([_item()])
    assert _shares(result)["share1"]["InBackupPolicy"] == "True"
    assert _shares(result)["share1"]["BackupPolicies"] == "daily"
    assert _shares(result)["share2"]["InBackupPolicy"] == "False"
    assert _accounts(result)["acct1"]["InBackupPolicy"] == "True"
    assert _accounts(result)["acct1"]["BackupPolicies"] == "daily"
    assert _accounts(result)["acct2"]["InBackupPolicy"] == "False"


def test_policies_are_listed_once_each_in_the_order_met():
    items = [
        _item(policy_name="daily"),
        _item(name="AzureFileShare;share2", friendly_name="share2", policy_name="weekly"),
        _item(name="AzureFileShare;share1", friendly_name="share1", policy_name="daily"),
    ]
    assert _accounts(_result(items))["acct1"]["BackupPolicies"] == "daily, weekly"


def test_names_are_matched_without_regard_to_case():
    result = _result(
        [_item(friendly_name="SHARE1", source_resource_id=ACCOUNT_ID.replace("acct1", "ACCT1"))]
    )
    assert _shares(result)["share1"]["InBackupPolicy"] == "True"
    assert _accounts(result)["acct1"]["InBackupPolicy"] == "True"


def test_the_share_is_the_last_part_of_the_item_name_when_there_is_no_friendly_name():
    result = _result([_item(friendly_name=None, name="AzureFileShare;share2")])
    assert _shares(result)["share2"]["InBackupPolicy"] == "True"
    assert _shares(result)["share1"]["InBackupPolicy"] == "False"


def test_the_friendly_name_is_preferred_to_the_item_name():
    result = _result([_item(friendly_name="share2", name="AzureFileShare;a1b2c3")])
    assert _shares(result)["share2"]["InBackupPolicy"] == "True"
    assert _shares(result)["share1"]["InBackupPolicy"] == "False"


def test_an_item_without_a_policy_still_marks_the_row_protected():
    row = _accounts(_result([_item(policy_name=None)]))["acct1"]
    assert (row["BackupPolicies"], row["InBackupPolicy"]) == ("-", "True")


def test_an_item_whose_account_cannot_be_worked_out_is_left_out():
    result = _result([_item(source_resource_id="/subscriptions/s1/resourceGroups/rg")])
    assert _files_protection(result) == []
    assert _accounts(result)["acct1"]["InBackupPolicy"] == "False"


def test_an_item_of_another_subscription_is_not_matched():
    result = _result([_item()])
    result["backup_posture"][0]["subscription_id"] = "other"
    assert _accounts(result)["acct1"]["InBackupPolicy"] == "False"


def test_only_azure_files_items_count():
    assert _accounts(_result([_item(workload_type="VM")]))["acct1"]["InBackupPolicy"] == "False"


def test_the_collector_keeps_the_share_name_of_an_azure_files_item_and_only_of_those():
    files = MagicMock()
    files.name = "AzureFileShare;abc"
    files.id = "/vaults/v/items/files"
    files.properties = MagicMock(
        backup_management_type="AzureStorage",
        friendly_name="share1",
        source_resource_id=ACCOUNT_ID,
        policy_id="/p/daily",
    )
    vm = MagicMock()
    vm.name = "vm1"
    vm.id = "/vaults/v/items/vm"
    vm.properties = MagicMock(
        backup_management_type="AzureIaasVM",
        friendly_name="vm1",
        source_resource_id="/vms/vm1",
        policy_id="/p/daily",
    )
    inventory = _make_collector(vaults=[_make_vault("v")], protected_items=[files, vm]).collect()
    by_workload = {i.workload_type: i for i in inventory.protected_items}
    assert by_workload["Files"].friendly_name == "share1"
    assert by_workload["VM"].friendly_name is None
    assert inventory.subscription_id == SUB_ID

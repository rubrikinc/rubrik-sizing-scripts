"""Backup Vaults (Blob and PostgreSQL backup): the collector, the three files, the flags, the totals.

The policy converter is checked against the structure Az.DataProtection wrote for a real PostgreSQL
policy in a PowerShell 1.0.3 run (key names, their order, the flattened copies and the nulls).
"""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import logging
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

import csv_export
import main
import totals
from anonymize import DEFAULT_FIELDS, FILE_ORDER, Anonymizer
from collectors import data_protection
from collectors.data_protection import (
    BLOB,
    POSTGRESQL,
    DataProtectionCollector,
    _plain,
    workload_of,
)
from csv_export import az_policy_property, build_csv_files

SUB = "11111111-1111-1111-1111-111111111111"
VAULT_ID = f"/subscriptions/{SUB}/resourceGroups/rg-vault/providers/Microsoft.DataProtection/backupVaults/v1"
BLOB_TYPE = "Microsoft.Storage/storageAccounts/blobServices"
PG_TYPE = "Microsoft.DBforPostgreSQL/flexibleServers"
ACCOUNT_ID = (
    f"/subscriptions/{SUB}/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/acct1"
)
SERVER_ID = f"/subscriptions/{SUB}/resourceGroups/rg-data/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg1"
POLICY_BASE = f"{VAULT_ID}/backupPolicies"

# What the API returns for the PostgreSQL policy of the real run, and what Az.DataProtection wrote.
REST_PROPERTIES = {
    "objectType": "BackupPolicy",
    "datasourceTypes": [PG_TYPE],
    "policyRules": [
        {
            "objectType": "AzureRetentionRule",
            "name": "Default",
            "isDefault": True,
            "lifecycles": [
                {
                    "deleteAfter": {"objectType": "AbsoluteDeleteOption", "duration": "P2M"},
                    "sourceDataStore": {
                        "dataStoreType": "VaultStore",
                        "objectType": "DataStoreInfoBase",
                    },
                    "targetDataStoreCopySettings": [],
                }
            ],
        },
        {
            "objectType": "AzureBackupRule",
            "name": "BackupWeekly",
            "backupParameters": {"objectType": "AzureBackupParams", "backupType": "full"},
            "dataStore": {"dataStoreType": "VaultStore", "objectType": "DataStoreInfoBase"},
            "trigger": {
                "objectType": "ScheduleBasedTriggerContext",
                "schedule": {
                    "repeatingTimeIntervals": ["R/2026-02-25T08:00:00+05:30/P1W"],
                    "timeZone": "India Standard Time",
                },
                "taggingCriteria": [
                    {
                        "isDefault": True,
                        "taggingPriority": 99,
                        "tagInfo": {"id": "Default_", "tagName": "Default"},
                    }
                ],
            },
        },
    ],
}
AZ_PROPERTY = {
    "DatasourceType": [PG_TYPE],
    "ObjectType": "BackupPolicy",
    "PolicyRule": [
        {
            "IsDefault": True,
            "Lifecycle": [
                {
                    "DeleteAfter": {"Duration": "P2M", "ObjectType": "AbsoluteDeleteOption"},
                    "DeleteAfterDuration": "P2M",
                    "DeleteAfterObjectType": "AbsoluteDeleteOption",
                    "SourceDataStoreObjectType": "DataStoreInfoBase",
                    "SourceDataStoreType": "VaultStore",
                    "TargetDataStoreCopySetting": [],
                }
            ],
            "Name": "Default",
            "ObjectType": "AzureRetentionRule",
        },
        {
            "BackupParameter": {"BackupType": "full", "ObjectType": "AzureBackupParams"},
            "BackupParameterObjectType": "AzureBackupParams",
            "DataStoreObjectType": "DataStoreInfoBase",
            "DataStoreType": "VaultStore",
            "Name": "BackupWeekly",
            "ObjectType": "AzureBackupRule",
            "Trigger": {
                "ObjectType": "ScheduleBasedTriggerContext",
                "ScheduleRepeatingTimeInterval": ["R/2026-02-25T08:00:00+05:30/P1W"],
                "ScheduleTimeZone": "India Standard Time",
                "TaggingCriterion": [
                    {
                        "Criterion": None,
                        "IsDefault": True,
                        "TagInfoETag": None,
                        "TagInfoId": "Default_",
                        "TagInfoTagName": "Default",
                        "TaggingPriority": 99,
                    }
                ],
            },
            "TriggerObjectType": "ScheduleBasedTriggerContext",
        },
    ],
}


# ── the collector ─────────────────────────────────────────────────────────────


def _vault(name="v1", vault_id=VAULT_ID, location="eastus2") -> NS:
    return NS(
        id=vault_id, name=name, type="Microsoft.DataProtection/backupVaults", location=location
    )


def _policy(name="pg-policy", datasource_types=(PG_TYPE,), properties=None) -> NS:
    props = dict(REST_PROPERTIES if properties is None else properties)
    props["datasourceTypes"] = list(datasource_types)
    return NS(
        id=f"{POLICY_BASE}/{name}",
        name=name,
        type="Microsoft.DataProtection/backupVaults/backupPolicies",
        properties=props,
        system_data=None,
    )


def _instance(
    datasource_type,
    resource_id,
    name="inst1",
    policy="pg-policy",
    state="ProtectionConfigured",
    key="resourceID",
) -> NS:
    return NS(
        name=name,
        properties={
            "dataSourceInfo": {"datasourceType": datasource_type, key: resource_id},
            "policyInfo": {"policyId": f"{POLICY_BASE}/{policy}"},
            "currentProtectionState": state,
        },
    )


def _collector(monkeypatch, vaults=(), policies=(), instances=(), cloud=None):
    client = MagicMock()
    client.backup_vaults.get_in_subscription.return_value = list(vaults)
    client.backup_policies.list.return_value = list(policies)
    client.backup_instances.list.return_value = list(instances)
    monkeypatch.setattr(data_protection, "DataProtectionMgmtClient", MagicMock(return_value=client))
    return DataProtectionCollector(SUB, "credential"), client


def test_the_workload_is_blob_for_the_exact_type_and_postgresql_for_any_postgresql_type():
    assert workload_of(BLOB_TYPE) == BLOB
    assert workload_of(BLOB_TYPE.upper()) == BLOB
    assert workload_of(PG_TYPE) == POSTGRESQL
    assert workload_of("Microsoft.DBforPostgreSQL/servers") == POSTGRESQL
    for other in (
        BLOB_TYPE + "/containers",
        "Microsoft.Compute/disks",
        "Microsoft.DBforMySQL/flexibleServers",
        "",
        None,
    ):
        assert workload_of(other) is None


def test_a_vault_is_listed_with_its_resource_group_taken_from_its_id(monkeypatch):
    collector, _ = _collector(monkeypatch, vaults=[_vault()])
    inventory = collector.collect()
    (vault,) = inventory.vaults
    assert (vault.name, vault.resource_group, vault.location) == ("v1", "rg-vault", "eastus2")
    assert vault.type == "Microsoft.DataProtection/backupVaults"
    assert inventory.total_vaults == 1 and inventory.error is None


def test_a_vault_without_a_resource_group_in_its_id_is_skipped_with_a_warning(monkeypatch, caplog):
    collector, client = _collector(monkeypatch, vaults=[_vault(vault_id="/not/an/id")])
    with caplog.at_level(logging.WARNING):
        inventory = collector.collect()
    assert inventory.vaults == []
    assert "Could not work out the resource group for Backup Vault v1" in caplog.text
    client.backup_policies.list.assert_not_called()
    client.backup_instances.list.assert_not_called()


def test_a_null_vault_in_the_list_is_ignored(monkeypatch):
    collector, _ = _collector(monkeypatch, vaults=[None, _vault()])
    assert [v.name for v in collector.collect().vaults] == ["v1"]


def test_a_failed_vault_listing_is_a_warning_and_an_empty_inventory(monkeypatch, caplog):
    collector, client = _collector(monkeypatch)
    client.backup_vaults.get_in_subscription.side_effect = RuntimeError("AuthorizationFailed")
    with caplog.at_level(logging.WARNING):
        inventory = collector.collect()
    assert inventory.vaults == [] and "AuthorizationFailed" in (inventory.error or "")
    assert "Unable to collect Azure Backup Vault information" in caplog.text


def test_the_calls_use_the_vault_resource_group_and_name(monkeypatch):
    collector, client = _collector(monkeypatch, vaults=[_vault()])
    collector.collect()
    client.backup_policies.list.assert_called_once_with("rg-vault", "v1")
    client.backup_instances.list.assert_called_once_with("rg-vault", "v1")


def test_only_blob_and_postgresql_policies_are_kept_and_the_workload_names_them(monkeypatch):
    policies = [
        _policy("pg", [PG_TYPE]),
        _policy("blob", [BLOB_TYPE]),
        _policy("disk", ["Microsoft.Compute/disks"]),
        _policy("both", [BLOB_TYPE, PG_TYPE]),
    ]
    collector, _ = _collector(monkeypatch, vaults=[_vault()], policies=policies)
    kept = collector.collect().policies
    assert [(p.name, p.workload) for p in kept] == [
        ("pg", "AzurePostgreSQL"),
        ("blob", "AzureBlob"),
        ("both", "AzureBlob, AzurePostgreSQL"),
    ]
    assert kept[0].object_type == "BackupPolicy" and kept[0].vault_name == "v1"
    assert kept[0].datasource_types == [PG_TYPE] and kept[0].properties["policyRules"]


def test_a_failed_policy_listing_is_a_warning_and_the_instances_are_still_listed(
    monkeypatch, caplog
):
    collector, client = _collector(
        monkeypatch, vaults=[_vault()], instances=[_instance(PG_TYPE, SERVER_ID)]
    )
    client.backup_policies.list.side_effect = RuntimeError("boom")
    with caplog.at_level(logging.WARNING):
        inventory = collector.collect()
    assert inventory.policies == [] and len(inventory.items) == 1
    assert "Failed to get Azure Backup Vault policies for vault v1" in caplog.text
    assert "policy list is incomplete" in caplog.text


def test_a_blob_instance_is_named_after_its_storage_account(monkeypatch):
    collector, _ = _collector(
        monkeypatch,
        vaults=[_vault()],
        instances=[_instance(BLOB_TYPE, ACCOUNT_ID, "blob-inst", "blob-daily")],
    )
    (item,) = collector.collect().items
    assert (item.workload, item.datasource_name) == (BLOB, "acct1")
    assert (item.instance_name, item.vault_name, item.resource_group) == (
        "blob-inst",
        "v1",
        "rg-vault",
    )
    assert (item.protection_policy_name, item.policy_id) == (
        "blob-daily",
        f"{POLICY_BASE}/blob-daily",
    )
    assert item.protection_state == "ProtectionConfigured"
    assert item.datasource_resource_id == ACCOUNT_ID and item.datasource_database is None


def test_a_postgresql_instance_is_named_after_its_server(monkeypatch):
    collector, _ = _collector(
        monkeypatch, vaults=[_vault()], instances=[_instance(PG_TYPE, SERVER_ID)]
    )
    (item,) = collector.collect().items
    assert (item.workload, item.datasource_name, item.datasource_database) == (
        POSTGRESQL,
        "pg1",
        None,
    )


def test_a_database_level_postgresql_backup_keeps_the_server_name_and_names_the_database(
    monkeypatch,
):
    resource_id = SERVER_ID.replace("flexibleServers", "servers") + "/databases/orders"
    collector, _ = _collector(
        monkeypatch,
        vaults=[_vault()],
        instances=[_instance("Microsoft.DBforPostgreSQL/servers/databases", resource_id)],
    )
    (item,) = collector.collect().items
    assert (item.datasource_name, item.datasource_database) == ("pg1", "orders")


def test_the_resource_id_is_read_under_either_spelling(monkeypatch):
    collector, _ = _collector(
        monkeypatch,
        vaults=[_vault()],
        instances=[_instance(BLOB_TYPE, ACCOUNT_ID, key="resourceId")],
    )
    assert collector.collect().items[0].datasource_name == "acct1"


def test_other_datasource_types_are_counted_and_left_out(monkeypatch):
    instances = [
        _instance("Microsoft.Compute/disks", "/x/disks/d1", "i1"),
        _instance("Microsoft.Compute/disks", "/x/disks/d2", "i2"),
        _instance(PG_TYPE, SERVER_ID, "i3"),
    ]
    collector, _ = _collector(monkeypatch, vaults=[_vault()], instances=instances)
    inventory = collector.collect()
    assert inventory.instances_found == 3
    assert inventory.ignored_types == {"Microsoft.Compute/disks": 2}
    assert [i.instance_name for i in inventory.items] == ["i3"]


def test_a_failed_instance_listing_is_a_warning_and_the_vault_is_kept(monkeypatch, caplog):
    collector, client = _collector(monkeypatch, vaults=[_vault()], policies=[_policy()])
    client.backup_instances.list.side_effect = RuntimeError("boom")
    with caplog.at_level(logging.WARNING):
        inventory = collector.collect()
    assert len(inventory.vaults) == 1 and len(inventory.policies) == 1 and inventory.items == []
    assert "Failed to get Azure Backup Vault backup instances for vault v1" in caplog.text


def test_the_collector_needs_the_sdk(monkeypatch):
    monkeypatch.setattr(data_protection, "DataProtectionMgmtClient", None)
    with pytest.raises(RuntimeError, match="azure-mgmt-dataprotection is not installed"):
        DataProtectionCollector(SUB, "credential")


class _Wire(dict):
    """A model of the current SDK: a mapping over the API's own JSON."""


class _OldModel:
    def serialize(self):
        return {"objectType": "BackupPolicy", "datasourceTypes": [PG_TYPE]}


class _SnakeModel:
    def as_dict(self):
        return {
            "object_type": "BackupPolicy",
            "datasource_types": [PG_TYPE],
            "inner": {"policy_id": "p"},
        }


def test_a_model_is_read_as_plain_json_whichever_way_the_sdk_builds_it():
    assert _plain(_Wire(objectType="x", inner=_Wire(a=[_Wire(b=1)]))) == {
        "objectType": "x",
        "inner": {"a": [{"b": 1}]},
    }
    assert _plain(_OldModel()) == {"objectType": "BackupPolicy", "datasourceTypes": [PG_TYPE]}
    assert _plain(_SnakeModel()) == {
        "objectType": "BackupPolicy",
        "datasourceTypes": [PG_TYPE],
        "inner": {"policyId": "p"},
    }
    assert _plain(None) is None and _plain("text") == "text"


# ── the files ─────────────────────────────────────────────────────────────────


def _inventory(monkeypatch, vaults=None, policies=None, instances=None) -> dict:
    collector, _ = _collector(
        monkeypatch,
        vaults=[_vault()] if vaults is None else vaults,
        policies=[_policy()] if policies is None else policies,
        instances=(
            [
                _instance(PG_TYPE, SERVER_ID),
                _instance(BLOB_TYPE, ACCOUNT_ID, "blob-inst", "blob-daily"),
            ]
            if instances is None
            else instances
        ),
    )
    return dataclasses.asdict(collector.collect())


def _result(data_protection_entries, skipped=()) -> dict:
    return {
        "tenant_name": "Contoso",
        "tenant_id": "t",
        "subscription_names": {SUB: "Sub One"},
        "tag_names": {SUB: []},
        "skipped": list(skipped),
        "data_protection": data_protection_entries,
        "storage": [
            {
                "subscription_id": SUB,
                "accounts": [
                    {
                        "name": "acct1",
                        "resource_group": "rg-data",
                        "location": "eastus",
                        "file_shares": [],
                    },
                    {
                        "name": "acct2",
                        "resource_group": "rg-data",
                        "location": "eastus",
                        "file_shares": [],
                    },
                ],
            }
        ],
        "database": [
            {
                "subscription_id": SUB,
                "flexible_servers": [
                    {"engine": "PostgreSQL", "name": "pg1", "resource_group": "rg-data"},
                    {"engine": "PostgreSQL", "name": "pg2", "resource_group": "rg-data"},
                ],
            }
        ],
    }


def _files(result, anonymizer=None) -> dict[str, str]:
    return {
        name.split("-2026")[0]: text
        for name, text in build_csv_files(result, "2026-10-22_1102", anonymizer).items()
    }


def _table(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


def test_the_vault_file_has_the_powershell_columns_and_one_row_per_vault(monkeypatch):
    files = _files(_result([{"subscription_id": SUB, **_inventory(monkeypatch)}]))
    text = files["azure_backup_data_protection_vaults"]
    assert text.splitlines()[0] == '"Name","Type","Tenant","Subscription","Region","ResourceGroup"'
    (row,) = _table(text)
    assert row == {
        "Name": "v1",
        "Type": "Microsoft.DataProtection/backupVaults",
        "Tenant": "Contoso",
        "Subscription": "Sub One",
        "Region": "eastus2",
        "ResourceGroup": "rg-vault",
    }


def test_the_item_file_has_the_powershell_columns_and_one_row_per_instance(monkeypatch):
    files = _files(_result([{"subscription_id": SUB, **_inventory(monkeypatch)}]))
    text = files["azure_backup_data_protection_items"]
    assert next(csv.reader(io.StringIO(text))) == [
        "Tenant", "Subscription", "Region", "ResourceGroup", "VaultName", "InstanceName", "Workload",
        "DatasourceType", "DatasourceName", "DatasourceDatabase", "DatasourceResourceId",
        "ProtectionPolicyName", "PolicyId", "ProtectionState",
    ]  # fmt: skip
    pg, blob = _table(text)
    assert (pg["Workload"], pg["DatasourceName"], pg["DatasourceDatabase"]) == (
        "AzurePostgreSQL",
        "pg1",
        "",
    )
    assert (blob["Workload"], blob["DatasourceName"], blob["ProtectionPolicyName"]) == (
        "AzureBlob",
        "acct1",
        "blob-daily",
    )
    assert (
        pg["Subscription"] == "Sub One"
        and pg["Region"] == "eastus2"
        and pg["ProtectionState"] == "ProtectionConfigured"
    )


def test_no_backup_vault_file_is_written_when_the_vaults_were_not_collected():
    names = _files(_result(None))
    assert not [n for n in names if "data_protection" in n]


def test_skip_backup_stops_all_three_files(monkeypatch):
    result = _result([{"subscription_id": SUB, **_inventory(monkeypatch)}])
    assert len([n for n in _files(result) if "data_protection" in n]) == 3
    assert not [n for n in _files({**result, "skipped": ["backup"]}) if "data_protection" in n]


def test_no_file_is_written_for_a_vault_less_subscription(monkeypatch):
    empty = _inventory(monkeypatch, vaults=[], policies=[], instances=[])
    assert not [
        n for n in _files(_result([{"subscription_id": SUB, **empty}])) if "data_protection" in n
    ]


def test_there_is_no_policy_file_without_a_blob_or_postgresql_policy(monkeypatch):
    inventory = _inventory(monkeypatch, policies=[_policy("disk", ["Microsoft.Compute/disks"])])
    names = _files(_result([{"subscription_id": SUB, **inventory}]))
    assert "azure_backup_data_protection_policies" not in names
    assert "azure_backup_data_protection_vaults" in names


# ── the policy file ───────────────────────────────────────────────────────────


def test_a_postgresql_policy_is_converted_to_exactly_what_az_dataprotection_wrote():
    converted = az_policy_property(REST_PROPERTIES)
    assert converted == AZ_PROPERTY
    # The order of the keys matters too: PowerShell lists them alphabetically at every level.
    assert json.dumps(converted) == json.dumps(AZ_PROPERTY)


def test_the_converter_changes_nothing_but_names_and_order():
    def leaves(value):
        if isinstance(value, dict):
            return [x for v in value.values() for x in leaves(v)]
        if isinstance(value, list):
            return [x for v in value for x in leaves(v)]
        return [str(value)]

    assert set(leaves(REST_PROPERTIES)) <= set(leaves(az_policy_property(REST_PROPERTIES)))


def test_the_policy_file_is_a_json_array_with_the_powershell_top_level_layout(monkeypatch):
    files = _files(_result([{"subscription_id": SUB, **_inventory(monkeypatch)}]))
    policies = json.loads(files["azure_backup_data_protection_policies"])
    assert isinstance(policies, list) and len(policies) == 1
    (policy,) = policies
    assert list(policy) == [
        "Tenant", "Subscription", "Region", "ResourceGroup", "VaultName", "Workload", "DatasourceType",
        "Id", "Name", "ObjectType", "Property", "ResourceGroupName", "SystemDataCreatedAt",
        "SystemDataCreatedBy", "SystemDataCreatedByType", "SystemDataLastModifiedAt",
        "SystemDataLastModifiedBy", "SystemDataLastModifiedByType", "Type",
    ]  # fmt: skip
    assert (policy["Tenant"], policy["Subscription"], policy["Region"]) == (
        "Contoso",
        "Sub One",
        "eastus2",
    )
    assert (policy["VaultName"], policy["Workload"], policy["DatasourceType"]) == (
        "v1",
        "AzurePostgreSQL",
        [PG_TYPE],
    )
    assert policy["ResourceGroup"] == policy["ResourceGroupName"] == "rg-vault"
    assert policy["Property"] == AZ_PROPERTY and policy["ObjectType"] == "BackupPolicy"
    assert policy["Type"] == "Microsoft.DataProtection/backupVaults/backupPolicies"
    assert policy["SystemDataCreatedAt"] is None


def test_the_system_data_of_a_policy_is_kept_when_the_api_sends_it(monkeypatch):
    policy = _policy()
    policy.system_data = {
        "createdBy": "someone",
        "createdAt": "2026-01-01T00:00:00Z",
        "createdByType": "User",
    }
    files = _files(
        _result([{"subscription_id": SUB, **_inventory(monkeypatch, policies=[policy])}])
    )
    (row,) = json.loads(files["azure_backup_data_protection_policies"])
    assert (row["SystemDataCreatedBy"], row["SystemDataCreatedAt"], row["SystemDataCreatedByType"]) == (
        "someone", "2026-01-01T00:00:00Z", "User",
    )  # fmt: skip


# ── the flags ─────────────────────────────────────────────────────────────────


def _flags(result) -> tuple[dict, dict]:
    files = _files(result)
    accounts = {r["StorageAccount"]: r for r in _table(files["azure_storage_account_info"])}
    servers = {r["Server"]: r for r in _table(files["azure_postgres_info"])}
    return accounts, servers


def test_a_blob_backup_flags_its_storage_account_and_a_postgresql_backup_its_server(monkeypatch):
    accounts, servers = _flags(_result([{"subscription_id": SUB, **_inventory(monkeypatch)}]))
    assert (accounts["acct1"]["BackupPolicies"], accounts["acct1"]["InBackupPolicy"]) == (
        "blob-daily",
        "True",
    )
    assert (accounts["acct2"]["BackupPolicies"], accounts["acct2"]["InBackupPolicy"]) == (
        "-",
        "False",
    )
    assert (servers["pg1"]["BackupPolicies"], servers["pg1"]["InBackupPolicy"]) == (
        "pg-policy",
        "True",
    )
    assert (servers["pg2"]["BackupPolicies"], servers["pg2"]["InBackupPolicy"]) == ("-", "False")


def test_the_server_is_matched_by_its_full_resource_id_without_regard_to_case(monkeypatch):
    shouting = SERVER_ID.upper()
    inventory = _inventory(monkeypatch, instances=[_instance(PG_TYPE, shouting)])
    _, servers = _flags(_result([{"subscription_id": SUB, **inventory}]))
    assert servers["pg1"]["InBackupPolicy"] == "True"


def test_a_database_level_backup_does_not_flag_the_server(monkeypatch):
    resource_id = SERVER_ID.replace("flexibleServers", "servers") + "/databases/orders"
    inventory = _inventory(monkeypatch, instances=[_instance(PG_TYPE, resource_id)])
    _, servers = _flags(_result([{"subscription_id": SUB, **inventory}]))
    assert servers["pg1"]["InBackupPolicy"] == "False"


def test_a_backup_of_another_subscription_flags_nothing(monkeypatch):
    other = _result(
        [{**_inventory(monkeypatch), "subscription_id": "22222222-2222-2222-2222-222222222222"}]
    )
    accounts, servers = _flags(other)
    assert (
        accounts["acct1"]["InBackupPolicy"] == "False"
        and servers["pg1"]["InBackupPolicy"] == "False"
    )


def test_the_storage_account_is_matched_without_regard_to_case(monkeypatch):
    result = _result([{"subscription_id": SUB, **_inventory(monkeypatch)}])
    result["storage"][0]["accounts"][0]["name"] = "ACCT1"
    files = _files(result)
    accounts = {r["StorageAccount"]: r for r in _table(files["azure_storage_account_info"])}
    assert accounts["ACCT1"]["InBackupPolicy"] == "True"


def test_blob_and_azure_files_policies_are_listed_together_blob_first(monkeypatch):
    result = _result([{"subscription_id": SUB, **_inventory(monkeypatch)}])
    result["backup_posture"] = [
        {
            "subscription_id": SUB,
            "vaults": [],
            "protected_items": [
                {
                    "workload_type": "Files",
                    "name": "AzureFileShare;s1",
                    "friendly_name": "s1",
                    "source_resource_id": ACCOUNT_ID,
                    "policy_name": "files-daily",
                }
            ],
        }
    ]
    accounts, _ = _flags(result)
    assert accounts["acct1"]["BackupPolicies"] == "blob-daily, files-daily"


# ── the totals ────────────────────────────────────────────────────────────────


def _lines(result) -> list[str]:
    return totals.summary_lines(csv_export.rows_by_file(result))


def test_the_totals_count_vaults_and_protected_resources(monkeypatch):
    lines = _lines(_result([{"subscription_id": SUB, **_inventory(monkeypatch)}]))
    assert "Total # of Azure Backup Vaults (Backup Vault type): 1" in lines
    assert "Total # of Azure Storage Accounts with Blob protected by Azure Backup : 1" in lines
    assert "Total # of Azure PostgreSQL servers protected by Azure Backup : 1" in lines


def test_the_blob_and_postgresql_counts_are_counted_apart(monkeypatch):
    instances = [
        _instance(PG_TYPE, SERVER_ID, "i1"),
        _instance(PG_TYPE, SERVER_ID.replace("pg1", "pg2"), "i2"),
        _instance(BLOB_TYPE, ACCOUNT_ID, "i3", "blob-daily"),
    ]
    lines = _lines(
        _result([{"subscription_id": SUB, **_inventory(monkeypatch, instances=instances)}])
    )
    assert "Total # of Azure Storage Accounts with Blob protected by Azure Backup : 1" in lines
    assert "Total # of Azure PostgreSQL servers protected by Azure Backup : 2" in lines


def test_the_totals_report_zero_for_a_vault_less_run_as_the_script_does(monkeypatch):
    empty = _inventory(monkeypatch, vaults=[], policies=[], instances=[])
    lines = _lines(_result([{"subscription_id": SUB, **empty}]))
    assert "Total # of Azure Backup Vaults (Backup Vault type): 0" in lines
    assert "Total # of Azure PostgreSQL servers protected by Azure Backup : 0" in lines


def test_the_totals_leave_the_lines_out_when_the_vaults_were_not_collected():
    assert not [line for line in _lines(_result(None)) if "Backup Vault type" in line]
    assert not [
        line for line in _lines(_result([], skipped=["backup"])) if "Backup Vault type" in line
    ]


def test_the_lines_follow_the_recovery_services_lines_and_come_before_cosmos(monkeypatch):
    result = _result([{"subscription_id": SUB, **_inventory(monkeypatch)}])
    result["cosmos"] = [{"subscription_id": SUB, "accounts": [{"name": "c"}]}]
    result["backup"] = []
    rows = csv_export.rows_by_file(result)
    rows["azure_backup_vault_info"] = []
    lines = totals.summary_lines(rows)
    rsv = next(
        i for i, line in enumerate(lines) if line.startswith("Total # of Azure Backup Vaults:")
    )
    vault = next(i for i, line in enumerate(lines) if "Backup Vault type" in line)
    cosmos = next(i for i, line in enumerate(lines) if "Cosmos" in line)
    assert rsv < vault < cosmos


# ── anonymizing ───────────────────────────────────────────────────────────────


def test_the_backup_vault_files_are_anonymized_after_backup_costs_and_before_cosmos():
    order = list(FILE_ORDER)
    names = [
        "azure_backup_data_protection_vaults",
        "azure_backup_data_protection_policies",
        "azure_backup_data_protection_items",
    ]
    assert [order.index(n) for n in names] == sorted(order.index(n) for n in names)
    assert order.index("azure_backup_costs") < order.index(names[0])
    assert order.index(names[-1]) < order.index("azure_cosmos_db")
    for field in ("VaultName", "DatasourceName", "DatasourceDatabase", "DatasourceResourceId"):
        assert field in DEFAULT_FIELDS


def test_an_anonymized_run_hides_names_and_leaves_the_policy_settings(monkeypatch):
    result = _result([{"subscription_id": SUB, **_inventory(monkeypatch)}])
    files = _files(result, Anonymizer())
    items = files["azure_backup_data_protection_items"]
    for real in ("v1", "acct1", "rg-vault", "blob-daily", "Sub One", "Contoso"):
        assert real not in items, real
    # A value has one label in every file and field, so the vault is "Name-..." everywhere.
    vault_label = _table(files["azure_backup_data_protection_vaults"])[0]["Name"]
    assert vault_label.startswith("Name-") and _table(items)[0]["VaultName"] == vault_label
    policy = json.loads(files["azure_backup_data_protection_policies"])[0]
    assert policy["VaultName"] == vault_label and policy["Name"].startswith("Name-")
    assert policy["Id"].startswith("Id-") and policy["Subscription"].startswith("Subscription-")
    assert policy["Property"] == AZ_PROPERTY and policy["Workload"] == "AzurePostgreSQL"


# ── the entry point ───────────────────────────────────────────────────────────


def test_backup_vaults_are_collected_only_when_backup_is_not_skipped_and_the_sdk_is_there(
    monkeypatch,
):
    monkeypatch.setattr(data_protection, "HAS_SDK", True)
    assert main._backup_vault_scan(frozenset()) == (True, None)
    assert main._backup_vault_scan(frozenset({"backup"})) == (False, None)
    assert main._backup_vault_scan(frozenset({"vms", "aks"})) == (True, None)


def test_a_missing_sdk_is_said_once_and_how_to_fix_it(monkeypatch):
    monkeypatch.setattr(data_protection, "HAS_SDK", False)
    collect, notice = main._backup_vault_scan(frozenset())
    assert collect is False
    assert "azure-mgmt-dataprotection is not installed" in notice
    assert "pip install -r requirements.txt" in notice
    assert main._backup_vault_scan(frozenset({"backup"})) == (False, None)


class _Out:
    def __init__(self):
        self.lines = []

    def status(self, _text):
        return MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False)

    def print(self, text=""):
        self.lines.append(text)


def test_the_screen_line_says_how_many_vaults_and_backups_were_found(monkeypatch):
    collector, _ = _collector(
        monkeypatch,
        vaults=[_vault()],
        instances=[
            _instance(PG_TYPE, SERVER_ID),
            _instance("Microsoft.Compute/disks", "/x/disks/d"),
        ],
    )
    monkeypatch.setattr(
        data_protection, "DataProtectionCollector", MagicMock(return_value=collector)
    )
    out = _Out()
    inventory = main._collect_backup_vaults(SUB, "credential", None, out)
    assert inventory.total_vaults == 1
    assert "1[/cyan] vaults" in out.lines[0] and "1[/cyan] Blob/PostgreSQL backups" in out.lines[0]
    assert "Microsoft.Compute/disks x1" in out.lines[1]


def test_a_failed_listing_is_said_on_the_screen_and_the_run_goes_on(monkeypatch):
    collector, client = _collector(monkeypatch)
    client.backup_vaults.get_in_subscription.side_effect = RuntimeError("denied")
    monkeypatch.setattr(
        data_protection, "DataProtectionCollector", MagicMock(return_value=collector)
    )
    out = _Out()
    inventory = main._collect_backup_vaults(SUB, "credential", None, out)
    assert inventory.error and "could not be listed: denied" in out.lines[0]

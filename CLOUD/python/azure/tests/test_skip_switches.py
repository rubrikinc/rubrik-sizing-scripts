"""PowerShell's -Skip* switches: flags, collectors that do not run, and files that are not written."""

from __future__ import annotations

import json
import sys
import zipfile
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest

import csv_export
import main
from cloud import DEFAULT_CLOUD
from collectors.backup_jobs import BackupJobsInventory
from collectors.backup_posture import BackupPostureInventory
from collectors.compute import ComputeInventory
from collectors.cost import CostSummary
from collectors.database import DatabaseInventory
from collectors.storage import StorageCollector, StorageInventory
from csv_export import SKIPPED_FILES, build_csv_files
from main import SKIP_SWITCHES
from tests.test_database import _make_collector as _make_database_collector

_SUB = "00000000-0000-0000-0000-000000000001"


# ── the flags ─────────────────────────────────────────────────────────────────


def _parse(*argv):
    return main._build_parser().parse_args(list(argv))


def test_every_switch_is_off_by_default():
    args = _parse()
    assert all(getattr(args, f"skip_{key}") is False for key in SKIP_SWITCHES)


@pytest.mark.parametrize(
    "key,flag",
    [(key, flag) for key, (flags, _, _) in SKIP_SWITCHES.items() for flag in flags],
)
def test_each_flag_and_its_powershell_alias_turns_its_switch_on(key, flag):
    args = _parse(flag)
    assert getattr(args, f"skip_{key}") is True
    assert [k for k in SKIP_SWITCHES if getattr(args, f"skip_{k}")] == [key]


def test_the_powershell_style_flags_are_the_switch_names_in_kebab_case():
    expected = {
        "-SkipAzureVMandManagedDisks": "--skip-azure-vm-and-managed-disks",
        "-SkipAzureSQLandMI": "--skip-azure-sql-and-mi",
        "-SkipAzureStorageAccounts": "--skip-azure-storage-accounts",
        "-SkipAzureFiles": "--skip-azure-files",
        "-SkipAzureBackup": "--skip-azure-backup",
        "-SkipAzureCosmosDB": "--skip-azure-cosmos-db",
    }
    flags = {ps: flags for flags, ps, _ in SKIP_SWITCHES.values()}
    for ps, kebab in expected.items():
        assert kebab in flags[ps]
    assert flags["-SkipAKS"] == ("--skip-aks",)


def test_the_flags_do_not_clash_with_the_existing_ones():
    parser = main._build_parser()
    options = [o for action in parser._actions for o in action.option_strings]
    assert len(options) == len(set(options))


# ── collectors that do not run ────────────────────────────────────────────────


def _collect(skips, scans=None):
    """Run _collect_subscription with every collector class replaced; return the replacements."""
    results = {
        "compute.ComputeCollector": ComputeInventory(subscription_id=_SUB),
        "backup_posture.BackupPostureCollector": BackupPostureInventory(subscription_id=_SUB),
        "backup_jobs.BackupJobsCollector": BackupJobsInventory(subscription_id=_SUB),
        "storage.StorageCollector": StorageInventory(subscription_id=_SUB),
        "database.DatabaseCollector": DatabaseInventory(subscription_id=_SUB),
        "cost.CostCollector": CostSummary(subscription_id=_SUB),
    }
    classes = {}
    with ExitStack() as stack:
        for target, inventory in results.items():
            mock = MagicMock()
            mock.return_value.collect.return_value = inventory
            mock.return_value.collect_backup_months.return_value = []
            stack.enter_context(patch(f"collectors.{target}", mock))
            classes[target.split(".")[1]] = mock
        main._collect_subscription(
            _SUB, MagicMock(), None, DEFAULT_CLOUD, scans=scans or {}, skips=frozenset(skips)
        )
    return classes


def test_nothing_is_skipped_by_default():
    classes = _collect([])
    assert all(mock.called for mock in classes.values())
    assert classes["StorageCollector"].call_args.kwargs["collect_file_shares"] is True
    assert classes["DatabaseCollector"].call_args.kwargs["collect_sql_mi"] is True
    classes["CostCollector"].return_value.collect_backup_months.assert_called_once()


def test_skip_vms_does_not_collect_compute():
    classes = _collect(["vms"])
    assert not classes["ComputeCollector"].called
    assert classes["StorageCollector"].called and classes["BackupPostureCollector"].called


def test_skip_backup_skips_vaults_job_history_and_backup_costs_but_not_cost():
    classes = _collect(["backup"])
    assert not classes["BackupPostureCollector"].called
    assert not classes["BackupJobsCollector"].called
    assert classes["CostCollector"].called
    classes["CostCollector"].return_value.collect_backup_months.assert_not_called()


def test_skip_storage_accounts_does_not_collect_storage():
    classes = _collect(["storage"])
    assert not classes["StorageCollector"].called


def test_skip_files_still_collects_storage_accounts():
    classes = _collect(["files"])
    assert classes["StorageCollector"].call_args.kwargs["collect_file_shares"] is False


def test_skip_sql_mi_still_runs_the_database_collector_for_flexible_servers():
    classes = _collect(["sql_mi"])
    assert classes["DatabaseCollector"].call_args.kwargs["collect_sql_mi"] is False


def test_skips_work_next_to_the_optional_scan_choices():
    classes = _collect(["backup"], scans={"cost": False, "backup_jobs": True})
    assert not classes["CostCollector"].called
    assert not classes["BackupJobsCollector"].called


def test_storage_collector_does_not_list_shares_when_told_not_to():
    storage = MagicMock()
    storage.storage_accounts.list.return_value = iter([_storage_account()])
    storage.blob_services.get_service_properties.side_effect = Exception("not needed")
    storage.blob_inventory_policies.get.side_effect = Exception("not needed")
    with (
        patch("collectors.storage.StorageManagementClient", return_value=storage),
        patch("collectors.storage.MonitorManagementClient", return_value=MagicMock()),
    ):
        collector = StorageCollector(
            _SUB, MagicMock(), collect_capacity=False, collect_file_shares=False
        )
    (account,) = collector._list_accounts()
    assert account.name == "sa1" and account.file_shares == []
    storage.file_shares.list.assert_not_called()


def _storage_account():
    from types import SimpleNamespace as NS

    return NS(
        id=f"/subscriptions/{_SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
        name="sa1",
        location="westus2",
        sku=NS(name="Standard_LRS"),
        kind="StorageV2",
        access_tier="Hot",
        tags={},
    )


def test_database_collector_skips_sql_and_mi_but_keeps_flexible_servers():
    from collectors.database import DatabaseCollector

    reference = _make_database_collector()
    with (
        patch("collectors.database.SqlManagementClient", return_value=reference._sql),
        patch("collectors.database.PostgreSQLFlexClient", return_value=reference._pg),
        patch("collectors.database.MySQLFlexClient", return_value=reference._mysql),
        patch("collectors.database.MonitorManagementClient", return_value=reference._monitor),
    ):
        collector = DatabaseCollector(_SUB, MagicMock(), collect_sql_mi=False)
    inventory = collector.collect()
    reference._sql.servers.list.assert_not_called()
    reference._sql.managed_instances.list.assert_not_called()
    assert inventory.sql_servers == [] and inventory.managed_instances == []
    assert inventory.flexible_servers


# ── files that are not written ────────────────────────────────────────────────


def _result(skipped) -> dict:
    return {
        "tenant_name": None,
        "tenant_id": "t",
        "subscription_names": {},
        "tag_names": {},
        "skipped": skipped,
        # The Postgres file is written only when there is a server to put in it.
        "database": [
            {"subscription_id": "s", "flexible_servers": [{"engine": "PostgreSQL", "name": "pg"}]}
        ],
        # Backup Vault files are written only when there is something to put in them.
        "data_protection": [
            {
                "subscription_id": "s",
                "vaults": [{"name": "v", "resource_group": "rg"}],
                "policies": [{"name": "p", "vault_name": "v", "properties": {}}],
                "items": [{"vault_name": "v", "workload": "AzureBlob"}],
            }
        ],
        # The opt-in files: --get-key-vault-amounts and --get-container-details were given.
        "key_vaults": [{"subscription_id": "s", "vaults": []}],
        "containers": [{"subscription_id": "s", "containers": []}],
    }


def _prefixes(skipped, **changes) -> set[str]:
    return {
        name.split("-2026")[0].split("_2026")[0]
        for name in build_csv_files({**_result(skipped), **changes}, "2026-10-06_1200")
    }


def test_no_skips_writes_every_file():
    assert _prefixes([]) == {spec.prefix for spec in csv_export.FILES}


@pytest.mark.parametrize("key", list(SKIPPED_FILES))
def test_each_switch_stops_exactly_its_files(key):
    written = _prefixes([key])
    assert {spec.prefix for spec in csv_export.FILES} - written == set(SKIPPED_FILES[key])


def test_skip_storage_stops_the_share_file_too_but_skip_files_only_the_share_file():
    assert {"azure_storage_account_info", "azure_file_share_info"}.isdisjoint(
        _prefixes(["storage"])
    )
    only_files = _prefixes(["files"])
    assert "azure_file_share_info" not in only_files and "azure_storage_account_info" in only_files


def test_the_summary_is_always_written_and_unknown_keys_are_ignored():
    skips = ["vms", "sql_mi", "storage", "files", "backup", "aks", "cosmos", "postgres", "bogus"]
    written = _prefixes(skips, key_vaults=None)  # no -Skip switch touches the Key Vault file
    assert written == {"azure_sizing_summary"}


def test_every_file_is_covered_by_a_switch_or_is_the_summary_or_opt_in():
    covered = {p for prefixes in SKIPPED_FILES.values() for p in prefixes}
    # PowerShell has no -Skip switch for Key Vaults: the file is written only with -GetKeyVaultAmounts.
    assert {spec.prefix for spec in csv_export.FILES} - covered == {
        "azure_sizing_summary",
        "azure_key_vault",
    }


@pytest.mark.parametrize(
    "key, prefix",
    [("key_vaults", "azure_key_vault"), ("containers", "azure_storage_account_container_info")],
)
def test_an_opt_in_file_is_written_only_when_its_option_was_given(key, prefix):
    assert prefix in _prefixes([])
    assert prefix not in _prefixes([], **{key: None})


# ── a run ─────────────────────────────────────────────────────────────────────


def _run(monkeypatch, tmp_path, *flags):
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path), *flags])
    main.main()
    (archive,) = tmp_path.glob("azure_sizing_results_*.zip")
    zf = zipfile.ZipFile(archive)
    names = zf.namelist()
    data = json.loads(zf.read(next(n for n in names if n.endswith(".json"))))
    return names, data


def test_run_with_skips_omits_their_files_and_records_them_in_the_json(monkeypatch, tmp_path):
    names, data = _run(
        monkeypatch, tmp_path, "--skip-vms", "--skip-azure-files", "--skip-sql-mi", "--skip-aks"
    )
    assert data["skipped"] == ["aks", "files", "sql_mi", "vms"]
    for prefix in (
        "azure_vmdisk_info",
        "azure_file_share_info",
        "azure_sql_info",
        "azure_aks_info",
    ):
        assert not any(n.startswith(prefix) for n in names), prefix
    assert any(n.startswith("azure_storage_account_info") for n in names)
    assert data["total_vms"] == 0 and data["total_sql_databases"] == 0
    assert data["total_flexible_servers"] > 0 and data["total_storage_accounts"] > 0


def test_run_skipping_backup_has_no_vaults_or_jobs(monkeypatch, tmp_path):
    names, data = _run(monkeypatch, tmp_path, "--skip-backup")
    assert not any(n.startswith("azure_backup_vault_info") for n in names)
    assert data["backup_posture"][0]["vaults"] == []
    assert data["total_backup_jobs"] == 0


def test_run_skipping_storage_has_no_storage_data(monkeypatch, tmp_path):
    names, data = _run(monkeypatch, tmp_path, "--skip-storage-accounts")
    assert data["total_storage_accounts"] == 0
    assert not any(
        n.startswith(("azure_storage_account_info", "azure_file_share_info")) for n in names
    )


def test_run_without_skips_records_none(monkeypatch, tmp_path):
    _, data = _run(monkeypatch, tmp_path)
    assert data["skipped"] == []

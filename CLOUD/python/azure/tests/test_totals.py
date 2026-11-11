"""The totals block: wording and numbers are PowerShell's, and every number comes from the CSV rows."""

import csv
import io
import sys
import zipfile

import csv_export
import main
import pytest
import totals


def _line(lines, start):
    [found] = [line for line in lines if line.startswith(start)]
    return found


def _size(gib):
    return {
        "SizeGiB": gib,
        "SizeTiB": round(gib / 1024, 4),
        "SizeGB": round(gib * 1.073741824, 3),
        "SizeTB": round(gib * 1.073741824 / 1000, 4),
    }


# ── virtual machines and disks ────────────────────────────────────────────────


def test_vm_lines_use_powershells_wording_and_unit_order():
    rows = {"azure_vmdisk_info": [{"Disks": 2, **_size(100)}, {"Disks": 3, **_size(50)}]}
    lines = totals.summary_lines(rows, [], 2, 1)
    assert "Successfully collected data from 1 out of 2 found subscriptions" in lines
    assert "Total # of Azure VMs: 2" in lines
    assert "Total # of Managed Disks: 5" in lines
    assert "Total capacity of all disks: 150 GiB or 161 GB or 0.1465 TiB or 0.1611 TB" in lines


def test_counts_and_gib_and_gb_have_thousands_separators_and_no_decimals():
    rows = {"azure_vmdisk_info": [{"Disks": 1234, **_size(26162)}]}
    lines = totals.summary_lines(rows, [], 1, 1)
    assert "Total # of Managed Disks: 1,234" in lines
    assert _line(lines, "Total capacity of all disks").startswith(
        "Total capacity of all disks: 26,162 GiB or 28,091 GB or"
    )


@pytest.mark.parametrize(
    "value, expected",
    [(0, "0"), (0.5, "1"), (1.5, "2"), (2.5, "3"), (1234567.4, "1,234,567"), (None, "0")],
)
def test_n0_rounds_halves_away_from_zero_like_net(value, expected):
    assert totals._n0(value) == expected


def test_raw_sums_print_with_fifteen_significant_digits_like_powershell():
    assert totals._number(25.542299999999903) == "25.5422999999999"
    assert totals._number(1.0) == "1" and totals._number(0) == "0"


# ── SQL ───────────────────────────────────────────────────────────────────────


def _db(gib):
    return {"Database": "d", "ElasticPool": "", **_size_max(gib)}


def _pool(gib):
    return {"Database": "", "ElasticPool": "p", **_size_max(gib)}


def _mi(gib):
    return {"Database": "", "ManagedInstance": "m", **_size_max(gib)}


def _size_max(gib):
    return {f"Max{k}": v for k, v in _size(gib).items()}


def test_sql_databases_pools_and_managed_instances_are_counted_by_the_column_they_fill():
    rows = {
        "azure_sql_info": [_db(100), _db(200), _pool(50)],
        "azure_mi_sql_info": [_mi(1000)],
    }
    lines = totals.summary_lines(rows, [], 1, 1)
    assert "Total # of SQL DBs (independent): 2" in lines
    assert "Total # of SQL Elastic Pools: 1" in lines
    assert "Total # of SQL Managed Instances: 1" in lines
    assert _line(lines, "Total capacity of all SQL DBs").startswith(
        "Total capacity of all SQL DBs (independent): 300 GiB"
    )
    assert _line(lines, "Total capacity of all SQL Elastic Pools").startswith(
        "Total capacity of all SQL Elastic Pools: 50 GiB"
    )
    assert _line(lines, "Total capacity of all SQL Managed Instances").startswith(
        "Total capacity of all SQL Managed Instances: 1,000 GiB"
    )


def test_the_sql_total_counts_every_sql_row_and_every_managed_instance():
    rows = {
        "azure_sql_info": [_db(100), _db(200), _pool(50)],
        "azure_mi_sql_info": [_mi(1000)],
    }
    lines = totals.summary_lines(rows, [], 1, 1)
    assert "Total # of SQL DBs, Elastic Pools & Managed Instances: 4" in lines
    assert _line(lines, "Total capacity of all SQL:").startswith(
        "Total capacity of all SQL: 1,350 GiB or"
    )


# ── storage and file shares ───────────────────────────────────────────────────


def _account(gib, blobs, containers, files, shares, file_gib=0):
    return {
        "UsedCapacityGiB": gib,
        "UsedCapacityTiB": round(gib / 1024, 4),
        "UsedCapacityGB": round(gib * 1.073741824, 3),
        "UsedCapacityTB": round(gib * 1.073741824 / 1000, 4),
        "UsedBlobCapacityGiB": gib,
        "UsedFileShareCapacityGiB": file_gib,
        "BlobCount": blobs,
        "BlobContainerCount": containers,
        "FileCountInFileShares": files,
        "FileShareCount": shares,
    }


def test_storage_lines_sum_capacity_blobs_containers_files_and_shares():
    rows = {
        "azure_storage_account_info": [_account(100, 2000, 4, 30, 2), _account(50, 500, 1, 7, 1)]
    }
    lines = totals.summary_lines(rows, [], 1, 1)
    assert "Totals based on querying storage account metrics:" in lines
    assert "Total # of Azure Storage Accounts: 2" in lines
    assert _line(lines, "Total capacity of all Azure Storage Accounts").startswith(
        "Total capacity of all Azure Storage Accounts: 150 GiB"
    )
    assert "Total number blobs is 2,500 in 5 containers." in lines
    assert "Total number files is 37 in 3 Azure File Shares." in lines


def test_the_file_storage_line_labels_tib_which_powershell_leaves_off():
    lines = totals.summary_lines(
        {"azure_storage_account_info": [_account(1, 1, 1, 1, 1)]}, [], 1, 1
    )
    assert "GiB or 0 GB or 0 TiB or 0 TB" in _line(
        lines, "Total capacity of all Azure File storage"
    )


def test_file_shares_are_traversed_totals_only_when_the_file_share_file_is_there():
    accounts = {"azure_storage_account_info": [_account(1, 1, 1, 1, 1)]}
    assert not any("traversing" in line for line in totals.summary_lines(accounts, [], 1, 1))
    with_shares = {
        **accounts,
        "azure_file_share_info": [{"UsedCapacityGiB": 10, "UsedCapacityGB": 10.7}],
    }
    lines = totals.summary_lines(with_shares, [], 1, 1)
    assert "Totals based on traversing each Azure File Share and calculating statistics:" in lines
    assert "Total # of Azure File Shares: 1" in lines


# ── backup, Cosmos DB and AKS ─────────────────────────────────────────────────


def _posture():
    return {
        "policies": [
            {"workload_type": "VM"},
            {"workload_type": "VM"},
            {"workload_type": "SQL"},
            {"workload_type": "Files"},
        ],
        "protected_items": [
            {"workload_type": "VM"},
            {"workload_type": "SQL"},
            {"workload_type": "SQL"},
            {"workload_type": "Files"},
        ],
    }


def test_backup_lines_count_policies_and_protected_items_by_workload():
    rows = {"azure_backup_vault_info": [{}, {}]}
    lines = totals.summary_lines(rows, [_posture(), _posture()], 1, 1)
    assert "Total # of Azure Backup Vaults: 2" in lines
    assert "Total # of Azure Backup Vault policies for Virtual Machines: 4" in lines
    assert (
        "Total # of Azure Backup Vault policies for Virtual Machines with SQL databases: 2" in lines
    )
    assert "Total # of Azure Backup Vault policies for Azure SQL databases: 0" in lines
    assert "Total # of Azure Backup Vault policies for Azure Files: 2" in lines
    assert "Total # of Azure VMs protected by Azure Backup : 2" in lines
    assert "Total # of Azure VMs with MS SQL protected by Azure Backup : 4" in lines
    assert "Total # of Azure Files shares protected by Azure Backup : 2" in lines


def test_the_backup_cost_note_is_printed_only_when_there_are_cost_rows():
    rows = {"azure_backup_vault_info": [], "azure_backup_costs": []}
    assert not any("95% of the cost" in line for line in totals.summary_lines(rows, [], 1, 1))
    rows["azure_backup_costs"] = [{"CostUSD": "$1"}]
    assert any("95% of the cost" in line for line in totals.summary_lines(rows, [], 1, 1))


def test_cosmos_and_aks_lines():
    rows = {
        "azure_cosmos_db": [{}] * 4,
        "azure_aks_info": [{"TotalNodes": 2}, {"TotalNodes": 50}],
    }
    lines = totals.summary_lines(rows, [], 1, 1)
    assert "Total # of Azure Cosmos DB Accounts: 4" in lines
    assert "Total # of Azure Kubernetes Service (AKS) clusters: 2" in lines
    assert "Total # of nodes across all AKS clusters: 52" in lines


# ── what is left out ──────────────────────────────────────────────────────────


def test_a_section_whose_collector_was_skipped_is_left_out():
    only_vms = {"azure_vmdisk_info": [{"Disks": 1, **_size(10)}]}
    text = "\n".join(totals.summary_lines(only_vms, [], 1, 1))
    for gone in ("SQL", "Storage Accounts", "Backup Vaults", "Cosmos", "AKS"):
        assert gone not in text


def test_an_empty_run_prints_zeros():
    rows = {p: [] for p in ("azure_vmdisk_info", "azure_sql_info", "azure_storage_account_info")}
    lines = totals.summary_lines(rows, [], 0, 0)
    assert "Total # of Azure VMs: 0" in lines and "Total # of SQL DBs (independent): 0" in lines
    assert "Total capacity of all disks: 0 GiB or 0 GB or 0 TiB or 0 TB" in lines


def test_the_totals_hold_no_names():
    rows = {"azure_vmdisk_info": [{"Name": "payroll-vm", "Subscription": "secret-sub", "Disks": 1}]}
    text = "\n".join(totals.summary_lines(rows, [], 1, 1))
    assert "payroll-vm" not in text and "secret-sub" not in text


# ── in a run ──────────────────────────────────────────────────────────────────


def _run(tmp_path, monkeypatch, *flags):
    monkeypatch.setattr("collectors.pricing.fetch_vm_prices", lambda pairs: {})
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path), *flags])
    main.main()
    return zipfile.ZipFile(next(tmp_path.glob("azure_sizing_results_*.zip")))


def _log(zf):
    name = next(n for n in zf.namelist() if n.startswith("output_azure_") and n.endswith(".log"))
    return zf.read(name).decode()


def _csv_rows(zf, prefix):
    name = next(n for n in zf.namelist() if n.startswith(prefix))
    return list(csv.reader(io.StringIO(zf.read(name).decode("utf-8-sig"))))[1:]


def test_the_totals_are_on_the_screen_and_in_the_log_before_the_run_summary(
    tmp_path, monkeypatch, capsys
):
    zf = _run(tmp_path, monkeypatch)
    screen, log = capsys.readouterr().out, _log(zf)
    for shown in (screen, log):
        assert "Total # of Azure VMs:" in shown and "Total # of Azure Cosmos DB Accounts:" in shown
        assert shown.index("Total # of Azure VMs:") < shown.index("Run summary")


def test_the_totals_agree_with_the_csv_files_in_the_zip(tmp_path, monkeypatch):
    zf = _run(tmp_path, monkeypatch)
    log = _log(zf)
    assert f"Total # of Azure VMs: {len(_csv_rows(zf, 'azure_vmdisk_info'))}" in log
    assert (
        f"Total # of Azure Storage Accounts: {len(_csv_rows(zf, 'azure_storage_account_info'))}"
        in log
    )
    assert f"Total # of Azure Cosmos DB Accounts: {len(_csv_rows(zf, 'azure_cosmos_db'))}" in log


def test_a_skipped_collector_has_no_section_in_a_run(tmp_path, monkeypatch):
    log = _log(_run(tmp_path, monkeypatch, "--skip-aks", "--skip-cosmos-db"))
    assert "Total # of Azure VMs:" in log
    assert "Kubernetes Service" not in log.split("Run summary")[0].split("Total # of Azure VMs")[1]
    assert "Total # of Azure Cosmos DB Accounts" not in log


def test_the_totals_are_printed_even_when_no_csv_files_are_written(tmp_path, monkeypatch):
    assert "Total # of Azure VMs:" in _log(_run(tmp_path, monkeypatch, "--no-csv"))


def test_an_anonymized_run_has_the_totals_in_its_real_log(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, "--anonymize")
    kept = next(tmp_path.glob("output_azure_not_anonymized_*.log"))
    assert "Total # of Azure VMs:" in kept.read_text(encoding="utf-8")


def test_a_failure_in_the_totals_is_a_warning_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(totals, "summary_lines", lambda *a, **k: 1 / 0)
    log = _log(_run(tmp_path, monkeypatch))
    assert "Could not work out the totals" in log and "Run summary" in log


def test_the_new_module_is_packaged():
    assert '"totals"' in open("pyproject.toml", encoding="utf-8").read()


def test_rows_by_file_leaves_out_the_files_of_skipped_collectors():
    rows = csv_export.rows_by_file({"skipped": ["aks"], "subscriptions": []})
    assert "azure_aks_info" not in rows and "azure_vmdisk_info" in rows

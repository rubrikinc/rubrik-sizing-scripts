"""The totals block printed at the end of a run, worded as the PowerShell script words it.

Every number is a sum over the rows the CSV files are built from (``csv_export.rows_by_file``),
so the screen, the log and the files agree. A section is left out when its collector was skipped,
as PowerShell leaves it out.
"""

from decimal import ROUND_HALF_UP, Decimal
from typing import Any

Rows = dict[str, list[dict[str, Any]]]

_BACKUP_NOTE = (
    "This backup cost gives the cost for 95% of the cost of the vault, capacity,",
    "instance cost, etc, but does not include cost snapshots and the storage of",
    "those snapshots, restore point collections",
)


def _number(value: Any) -> str:
    """A number as PowerShell prints it raw: 15 significant digits, no ``.0`` on whole numbers."""
    if isinstance(value, float):
        return format(value, ".15g")
    return str(value)


def _n0(value: Any) -> str:
    """PowerShell's ``{0:N0}``: no decimals, thousands separators, halves rounded away from zero."""
    return f"{int(Decimal(str(value or 0)).quantize(Decimal(1), rounding=ROUND_HALF_UP)):,}"


def _n4(value: Any) -> str:
    """PowerShell's ``{0:N4}``: four decimals, thousands separators, halves rounded away from zero."""
    return f"{Decimal(str(value or 0)).quantize(Decimal('0.0001'), rounding=ROUND_HALF_UP):,}"


def _sum(rows: list[dict], column: str) -> Any:
    total: Any = 0
    for row in rows:
        value = row.get(column)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            total += value
    return total


def _filled(rows: list[dict], column: str) -> list[dict]:
    """The rows whose ``column`` is not empty: PowerShell's ``Where-Object -Property c -ne ''``."""
    return [row for row in rows if row.get(column) not in (None, "")]


def _capacity(rows: list[dict], prefix: str) -> str:
    """``N GiB or N GB or X TiB or X TB``: whole numbers for GiB and GB, raw sums for TiB and TB."""
    return (
        f"{_n0(_sum(rows, prefix + 'GiB'))} GiB or {_n0(_sum(rows, prefix + 'GB'))} GB or "
        f"{_number(_sum(rows, prefix + 'TiB'))} TiB or {_number(_sum(rows, prefix + 'TB'))} TB"
    )


def summary_lines(
    rows: Rows,
    backup: list[dict] | None = None,
    subscriptions_found: int = 0,
    subscriptions_collected: int = 0,
) -> list[str]:
    """The lines of the totals block, in the order the PowerShell script prints them."""
    lines: list[str] = []
    if "azure_vmdisk_info" in rows:
        vms = rows["azure_vmdisk_info"]
        lines += [
            "",
            f"Successfully collected data from {subscriptions_collected} out of "
            f"{subscriptions_found} found subscriptions",
            "",
            f"Total # of Azure VMs: {_n0(len(vms))}",
            f"Total # of Managed Disks: {_n0(_sum(vms, 'Disks'))}",
            f"Total capacity of all disks: {_capacity(vms, 'Size')}",
        ]
    if "azure_sql_info" in rows:
        lines += _sql_lines(rows["azure_sql_info"], rows.get("azure_mi_sql_info", []))
    if "azure_storage_account_info" in rows:
        lines += _storage_lines(rows["azure_storage_account_info"])
        if "azure_storage_account_container_info" in rows:
            lines += _container_lines(rows["azure_storage_account_container_info"])
        if "azure_file_share_info" in rows:
            lines += _file_share_lines(rows["azure_file_share_info"])
    if "azure_backup_vault_info" in rows:
        lines += _backup_lines(rows["azure_backup_vault_info"], backup or [])
    if "azure_backup_data_protection_vaults" in rows:
        lines += _data_protection_lines(
            rows["azure_backup_data_protection_vaults"],
            rows.get("azure_backup_data_protection_items", []),
        )
    if "azure_cosmos_db" in rows:
        lines.append(f"Total # of Azure Cosmos DB Accounts: {_n0(len(rows['azure_cosmos_db']))}")
    if "azure_postgres_info" in rows:
        lines += _postgres_lines(rows["azure_postgres_info"])
    if "azure_aks_info" in rows:
        aks = rows["azure_aks_info"]
        lines += [
            f"Total # of Azure Kubernetes Service (AKS) clusters: {_n0(len(aks))}",
            f"Total # of nodes across all AKS clusters: {_n0(_sum(aks, 'TotalNodes'))}",
        ]
    if "azure_key_vault" in rows:
        lines.append(f"Total # of Azure Key Vaults: {_n0(len(rows['azure_key_vault']))}")
    if "azure_backup_vault_info" in rows and rows.get("azure_backup_costs"):
        lines += ["", *_BACKUP_NOTE]
    return lines


def _data_protection_lines(vaults: list[dict], items: list[dict]) -> list[str]:
    def count(workload: str) -> str:
        return _n0(sum(1 for item in items if item.get("Workload") == workload))

    return [
        f"Total # of Azure Backup Vaults (Backup Vault type): {_n0(len(vaults))}",
        f"Total # of Azure Storage Accounts with Blob protected by Azure Backup : {count('AzureBlob')}",
        f"Total # of Azure PostgreSQL servers protected by Azure Backup : {count('AzurePostgreSQL')}",
    ]


def _postgres_lines(servers: list[dict]) -> list[str]:
    return [
        "",
        f"Total # of Azure PostgreSQL Flexible Servers: {_n0(len(servers))}",
        "Total capacity of all PostgreSQL Flexible Servers: "
        f"{_n0(_sum(servers, 'MaxSizeGiB'))} GiB or {_n0(_sum(servers, 'MaxSizeGB'))} GB or "
        f"{_n4(_sum(servers, 'MaxSizeTiB'))} TiB or {_n4(_sum(servers, 'MaxSizeTB'))} TB",
    ]


def _sql_lines(sql: list[dict], managed: list[dict]) -> list[str]:
    databases = _filled(sql, "Database")
    pools = _filled(sql, "ElasticPool")
    instances = _filled(managed, "ManagedInstance")
    all_sql = {p: _sum(sql, p) + _sum(instances, p) for p in ("MaxSizeGiB", "MaxSizeTiB")}
    total = (
        f"{_n0(all_sql['MaxSizeGiB'])} GiB or "
        f"{_n0(_sum(sql, 'MaxSizeGB') + _sum(instances, 'MaxSizeGB'))} GB or "
        f"{_number(all_sql['MaxSizeTiB'])} TiB or "
        f"{_number(_sum(sql, 'MaxSizeTB') + _sum(instances, 'MaxSizeTB'))} TB"
    )
    return [
        "",
        f"Total # of SQL DBs (independent): {_n0(len(databases))}",
        f"Total # of SQL Elastic Pools: {_n0(len(pools))}",
        f"Total # of SQL Managed Instances: {_n0(len(instances))}",
        f"Total capacity of all SQL DBs (independent): {_capacity(databases, 'MaxSize')}",
        f"Total capacity of all SQL Elastic Pools: {_capacity(pools, 'MaxSize')}",
        f"Total capacity of all SQL Managed Instances: {_capacity(instances, 'MaxSize')}",
        "",
        f"Total # of SQL DBs, Elastic Pools & Managed Instances: {_n0(len(sql) + len(managed))}",
        f"Total capacity of all SQL: {total}",
    ]


def _storage_lines(accounts: list[dict]) -> list[str]:
    return [
        "",
        "Totals based on querying storage account metrics:",
        f"Total # of Azure Storage Accounts: {_n0(len(accounts))}",
        f"Total capacity of all Azure Storage Accounts: {_capacity(accounts, 'UsedCapacity')}",
        "Total capacity of all Azure Blob storage in Azure Storage Accounts: "
        f"{_capacity(accounts, 'UsedBlobCapacity')}",
        f"Total number blobs is {_n0(_sum(accounts, 'BlobCount'))} in "
        f"{_n0(_sum(accounts, 'BlobContainerCount'))} containers.",
        "Total capacity of all Azure File storage in Azure Storage Accounts: "
        f"{_capacity(accounts, 'UsedFileShareCapacity')}",
        f"Total number files is {_n0(_sum(accounts, 'FileCountInFileShares'))} in "
        f"{_n0(_sum(accounts, 'FileShareCount'))} Azure File Shares.",
    ]


def _container_lines(containers: list[dict]) -> list[str]:
    # PowerShell sums the AllTiers columns, then overwrites the sums with columns a container row
    # does not have (UsedCapacityGiB...), so it always prints 0. The sums here are the AllTiers ones.
    return [
        "",
        "Totals based on traversing each blob store container and calculating statistics:",
        "NOTE: The totals may be different than those gathered from Storage Account metrics if",
        "some containers could not be accessed. There are also differences in the way these two metrics",
        "are calculated by Azure.",
        f"Total # of Azure Containers: {_n0(len(containers))}",
        f"Total capacity of all Azure Containers: {_capacity(containers, 'UsedCapacityAllTiers')}",
    ]


def _file_share_lines(shares: list[dict]) -> list[str]:
    return [
        "",
        "Totals based on traversing each Azure File Share and calculating statistics:",
        "Note: The totals may be different than those gathered from Storage Account metrics if",
        "the Azure File Share could not be accessed. There are also differences in the way these two metrics",
        "are calculated by Azure.",
        f"Total # of Azure File Shares: {_n0(len(shares))}",
        f"Total capacity of all Azure File Shares: {_capacity(shares, 'UsedCapacity')}",
    ]


def _backup_lines(vaults: list[dict], postures: list[dict]) -> list[str]:
    policies = [p for posture in postures for p in posture.get("policies") or []]
    items = [i for posture in postures for i in posture.get("protected_items") or []]

    def count(entries: list[dict], workload: str) -> str:
        return _n0(sum(1 for e in entries if e.get("workload_type") == workload))

    return [
        f"Total # of Azure Backup Vaults: {_n0(len(vaults))}",
        f"Total # of Azure Backup Vault policies for Virtual Machines: {count(policies, 'VM')}",
        "Total # of Azure Backup Vault policies for Virtual Machines with SQL databases: "
        f"{count(policies, 'SQL')}",
        "Total # of Azure Backup Vault policies for Azure SQL databases: "
        f"{count(policies, 'AzureSql')}",
        f"Total # of Azure Backup Vault policies for Azure Files: {count(policies, 'Files')}",
        f"Total # of Azure VMs protected by Azure Backup : {count(items, 'VM')}",
        f"Total # of Azure VMs with MS SQL protected by Azure Backup : {count(items, 'SQL')}",
        f"Total # of Azure SQL databases protected by Azure Backup : {count(items, 'AzureSql')}",
        f"Total # of Azure Files shares protected by Azure Backup : {count(items, 'Files')}",
    ]

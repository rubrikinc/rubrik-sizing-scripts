"""Audit manifest — single source of truth for what the tool reads.

Consumed by ``main.py --manifest`` and ``main.py --dry-run`` so customers
can see exactly what the installed wheel does, without grepping the
collector source.  Keep this in lock-step with the table in ``docs/audit.md``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ApiCall:
    collector: str  # file under collectors/
    api_call: str  # Python SDK call (documentation form)
    rbac_action: str  # Azure RBAC action string
    purpose: str  # human-readable one-liner
    optional: bool = False  # True if collector skips cleanly when denied


# Core collectors — always run.
CORE_API_CALLS: list[ApiCall] = [
    # Scope enumeration
    ApiCall(
        "auth.py",
        "subscriptions.list()",
        "Microsoft.Resources/subscriptions/read",
        "Enumerate accessible subscriptions",
    ),
    ApiCall(
        "auth.py",
        "subscriptions.get(sub_id)",
        "Microsoft.Resources/subscriptions/read",
        "Resolve tenant ID for the report header",
    ),
    # Compute
    ApiCall(
        "compute.py",
        "virtualMachines.list_all()",
        "Microsoft.Compute/virtualMachines/read",
        "Enumerate VMs — name, size, OS type, region, tags",
    ),
    ApiCall(
        "compute.py",
        "disks.list()",
        "Microsoft.Compute/disks/read",
        "Disk sizes, SKU (Premium/Standard/Ultra), encryption",
    ),
    # Backup posture
    ApiCall(
        "backup_posture.py",
        "vaults.list_by_subscription_id()",
        "Microsoft.RecoveryServices/vaults/read",
        "Recovery Services Vault inventory",
    ),
    ApiCall(
        "backup_posture.py",
        "backup_resource_storage_configs_non_crr.get()",
        "Microsoft.RecoveryServices/vaults/backupstorageconfig/read",
        "Vault redundancy (LRS/GRS/ZRS)",
    ),
    ApiCall(
        "backup_posture.py",
        "backup_policies.list()",
        "Microsoft.RecoveryServices/vaults/backupPolicies/read",
        "Backup policy names + retention",
    ),
    ApiCall(
        "backup_posture.py",
        "backup_protected_items.list()",
        "Microsoft.RecoveryServices/vaults/backupProtectedItems/read",
        "Which VMs are actually protected",
    ),
    # Backup jobs
    ApiCall(
        "backup_jobs.py",
        "backup_jobs.list()",
        "Microsoft.RecoveryServices/vaults/backupJobs/read",
        "60-day backup job history for per-VM success rates",
    ),
    # Storage
    ApiCall(
        "storage.py",
        "storage_accounts.list()",
        "Microsoft.Storage/storageAccounts/read",
        "Storage account inventory (name, SKU, region)",
    ),
    ApiCall(
        "storage.py",
        "blob_services.get_service_properties()",
        "Microsoft.Storage/storageAccounts/blobServices/read",
        "Soft-delete + versioning settings",
    ),
    ApiCall(
        "storage.py",
        "blob_inventory_policies.get()",
        "Microsoft.Storage/storageAccounts/blobServices/inventoryPolicies/read",
        "Inventory-policy presence",
    ),
    ApiCall(
        "storage.py",
        "monitor.metrics.list()",
        "Microsoft.Insights/metrics/read",
        "Approximate storage-account capacity (best-effort)",
        optional=True,
    ),
    # Database
    ApiCall(
        "database.py",
        "sql.servers.list() / databases.list_by_server()",
        "Microsoft.Sql/servers/read, Microsoft.Sql/servers/databases/read",
        "Azure SQL server + DB inventory",
    ),
    ApiCall(
        "database.py",
        "sql.managed_instances.list()",
        "Microsoft.Sql/managedInstances/read",
        "SQL Managed Instance inventory",
    ),
    ApiCall(
        "database.py",
        "backup_short_term_retention_policies.get() / long_term_retention_policies.get()",
        "Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies/read + .../backupLongTermRetentionPolicies/read",
        "SQL retention settings",
    ),
    ApiCall(
        "database.py",
        "postgresql_flexibleservers.servers.list() / databases.list_by_server()",
        "Microsoft.DBforPostgreSQL/flexibleServers/read + .../databases/read",
        "PostgreSQL flexible-server inventory",
    ),
    ApiCall(
        "database.py",
        "mysql_flexibleservers.servers.list() / databases.list_by_server()",
        "Microsoft.DBforMySQL/flexibleServers/read + .../databases/read",
        "MySQL flexible-server inventory",
    ),
]

# Optional collectors — skip cleanly if the identity lacks permission.
OPTIONAL_API_CALLS: list[ApiCall] = [
    ApiCall(
        "cost.py",
        "costmanagement.query.usage()",
        "Microsoft.CostManagement/query/action",
        "6-month spend aggregates by service — needs 'Cost Management Reader'",
        optional=True,
    ),
    ApiCall(
        "defender.py",
        "security.pricings.list()",
        "Microsoft.Security/pricings/read",
        "Microsoft Defender for Cloud sub-plan tiers — needs 'Security Reader'",
        optional=True,
    ),
    ApiCall(
        "purview.py",
        "purview.accounts.list_by_subscription()",
        "Microsoft.Purview/accounts/read",
        "Microsoft Purview governance summary — needs 'Reader' on Purview accounts",
        optional=True,
    ),
    ApiCall(
        "site_recovery.py",
        "replication_protected_items.list()",
        "Microsoft.RecoveryServices/vaults/replicationProtectedItems/read",
        "Azure Site Recovery protected-item counts",
        optional=True,
    ),
]


EXTERNAL_ENDPOINTS: list[tuple[str, str]] = [
    (
        "https://prices.azure.com/api/retail/prices",
        "Public Azure Retail Prices API for VM SKU pricing. Anonymous; "
        "no credentials or customer data are sent.",
    ),
]


MANIFEST_SUMMARY = """\
What this tool does
  1. Authenticates using the shell's existing identity (az login / Managed
     Identity). No credentials are prompted for or stored.
  2. Lists Azure resources in the subscriptions + regions you pass.
  3. Writes a JSON + plain-text findings file to your local disk.
  4. Exits.

What this tool does NOT do
  - No writes to Azure (no create/update/delete)
  - No credential collection or persistence
  - No blob contents, database rows, or disk contents
  - No outbound calls except to public Azure ARM + the anonymous
    Azure Retail Prices API

What gets written to disk
  - rubrik-discovery-<timestamp>.json          (full structured output)
  - rubrik-discovery-<timestamp>-findings.txt  (human-readable summary)

  Neither file contains secrets, tokens, or customer data.  Tag values
  are included — strip them with 'jq' before sharing if they contain
  sensitive info.

RBAC requirements
  - Built-in 'Reader' on each subscription in scope
    (or the narrower custom role in docs/rubrik-discovery-reader-role.json)
  - Optional: 'Cost Management Reader' for the 6-month spend trend
  - Optional: 'Security Reader' for Defender for Cloud sub-plan tiers

Full audit detail: see docs/audit.md.
"""

"""Realistic mock Azure SDK objects for offline development and testing.

Every object here is a ``types.SimpleNamespace`` that mirrors the attribute
structure the real Azure SDK returns.  The collectors use ``getattr()``
throughout, so SimpleNamespace works as a drop-in replacement.

Import from ``mock_run.py`` or unit tests — no Azure credentials required.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS
from typing import Any

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

SUB_ID = "00000000-0000-0000-0000-aabbccddeeff"
TENANT_ID = "ffffffff-0000-0000-0000-000000000001"

RG_PROD = "rg-prod-east"
RG_DATA = "rg-data-east"
RG_ANALYTICS = "rg-analytics"
RG_DEV = "rg-dev-westus"
RG_BACKUP = "rg-backup"


def _vm_id(rg: str, name: str) -> str:
    return (
        f"/subscriptions/{SUB_ID}/resourceGroups/{rg}"
        f"/providers/Microsoft.Compute/virtualMachines/{name}"
    )


def _disk_id(rg: str, name: str) -> str:
    return f"/subscriptions/{SUB_ID}/resourceGroups/{rg}/providers/Microsoft.Compute/disks/{name}"


def _vault_id(rg: str, name: str) -> str:
    return (
        f"/subscriptions/{SUB_ID}/resourceGroups/{rg}"
        f"/providers/Microsoft.RecoveryServices/vaults/{name}"
    )


def _policy_id(vault_rg: str, vault_name: str, policy_name: str) -> str:
    return f"{_vault_id(vault_rg, vault_name)}/backupPolicies/{policy_name}"


def _item_id(vault_rg: str, vault_name: str, item_name: str) -> str:
    return (
        f"{_vault_id(vault_rg, vault_name)}"
        f"/backupFabrics/Azure/protectionContainers/IaasVMContainer"
        f"/protectedItems/{item_name}"
    )


def _make_vm(
    name: str,
    rg: str,
    location: str,
    vm_size: str,
    os_type: str,
    os_disk_name: str,
    tags: dict[str, str] | None = None,
) -> NS:
    return NS(
        id=_vm_id(rg, name),
        name=name,
        location=location,
        tags=tags or {},
        hardware_profile=NS(vm_size=vm_size),
        storage_profile=NS(os_disk=NS(os_type=os_type, name=os_disk_name)),
    )


MOCK_VMS: list[NS] = [
    _make_vm(
        "sql-prod-01",
        RG_DATA,
        "eastus",
        "Standard_E64s_v3",
        "Windows",
        "sql-prod-01-osdisk",
        {
            "environment": "prod",
            "owner": "dba-team",
            "costcenter": "CC-1042",
            "application": "sql-server",
        },
    ),
    _make_vm(
        "sql-prod-02",
        RG_DATA,
        "eastus",
        "Standard_E32s_v3",
        "Windows",
        "sql-prod-02-osdisk",
        {
            "environment": "prod",
            "owner": "dba-team",
            "costcenter": "CC-1042",
            "application": "sql-server",
        },
    ),
    _make_vm(
        "sap-hana-01",
        RG_PROD,
        "eastus",
        "Standard_M128s",
        "Linux",
        "sap-hana-01-osdisk",
        {
            "environment": "prod",
            "owner": "sap-team",
            "costcenter": "CC-2001",
            "application": "sap-ecc",
        },
    ),
    _make_vm(
        "oracle-prod-01",
        RG_PROD,
        "eastus",
        "Standard_E48s_v3",
        "Linux",
        "oracle-prod-01-osdisk",
        {"environment": "prod", "owner": "dba-team", "costcenter": "CC-1042"},
    ),
    _make_vm(
        "app-prod-01",
        RG_PROD,
        "eastus",
        "Standard_D8s_v3",
        "Linux",
        "app-prod-01-osdisk",
        {
            "environment": "prod",
            "owner": "platform",
            "costcenter": "CC-1001",
            "application": "web-frontend",
        },
    ),
    _make_vm(
        "app-prod-02",
        RG_PROD,
        "eastus",
        "Standard_D8s_v3",
        "Linux",
        "app-prod-02-osdisk",
        {
            "environment": "prod",
            "owner": "platform",
            "costcenter": "CC-1001",
            "application": "web-frontend",
        },
    ),
    _make_vm(
        "app-prod-03",
        RG_PROD,
        "eastus",
        "Standard_D4s_v3",
        "Windows",
        "app-prod-03-osdisk",
        {"environment": "prod", "owner": "platform", "costcenter": "CC-1001"},
    ),
    _make_vm(
        "jumpbox-01",
        RG_PROD,
        "eastus",
        "Standard_B2ms",
        "Windows",
        "jumpbox-01-osdisk",
        {"environment": "prod", "owner": "ops-team", "costcenter": "CC-1001"},
    ),
    _make_vm(
        "analytics-01",
        RG_ANALYTICS,
        "eastus",
        "Standard_D64s_v4",
        "Linux",
        "analytics-01-osdisk",
        {"environment": "prod"},
    ),
    _make_vm(
        "analytics-02",
        RG_ANALYTICS,
        "eastus",
        "Standard_D32s_v4",
        "Linux",
        "analytics-02-osdisk",
        {},
    ),  # fully untagged
    _make_vm(
        "sql-dev-01",
        RG_DEV,
        "westus2",
        "Standard_D8s_v3",
        "Windows",
        "sql-dev-01-osdisk",
        {"environment": "dev", "owner": "dev-team", "costcenter": "CC-3000"},
    ),
    _make_vm(
        "dev-worker-01",
        RG_DEV,
        "westus2",
        "Standard_D4s_v3",
        "Linux",
        "dev-worker-01-osdisk",
        {"environment": "dev", "owner": "dev-team"},
    ),
]


def _make_disk(
    name: str,
    rg: str,
    size_gb: int,
    sku: str,
    vm_name: str,
    location: str = "eastus",
    encryption_type: str = "EncryptionAtRestWithPlatformKey",
) -> NS:
    return NS(
        id=_disk_id(rg, name),
        name=name,
        location=location,
        disk_size_gb=size_gb,
        sku=NS(name=sku),
        managed_by=_vm_id(rg, vm_name),
        encryption=NS(type=encryption_type),
    )


MOCK_DISKS: list[NS] = [
    # sql-prod-01: OS + 3 data disks (Premium)
    _make_disk("sql-prod-01-osdisk", RG_DATA, 128, "Premium_LRS", "sql-prod-01"),
    _make_disk("sql-prod-01-data-0", RG_DATA, 2048, "Premium_LRS", "sql-prod-01"),
    _make_disk("sql-prod-01-data-1", RG_DATA, 2048, "Premium_LRS", "sql-prod-01"),
    _make_disk("sql-prod-01-data-2", RG_DATA, 2048, "Premium_LRS", "sql-prod-01"),
    # sql-prod-02
    _make_disk("sql-prod-02-osdisk", RG_DATA, 128, "Premium_LRS", "sql-prod-02"),
    _make_disk("sql-prod-02-data-0", RG_DATA, 1024, "Premium_LRS", "sql-prod-02"),
    _make_disk("sql-prod-02-data-1", RG_DATA, 1024, "Premium_LRS", "sql-prod-02"),
    # sap-hana-01: OS + Ultra data disks
    _make_disk("sap-hana-01-osdisk", RG_PROD, 256, "Premium_LRS", "sap-hana-01"),
    _make_disk("sap-hana-01-data-0", RG_PROD, 2048, "UltraSSD_LRS", "sap-hana-01"),
    _make_disk("sap-hana-01-data-1", RG_PROD, 2048, "UltraSSD_LRS", "sap-hana-01"),
    # oracle-prod-01
    _make_disk("oracle-prod-01-osdisk", RG_PROD, 256, "Premium_LRS", "oracle-prod-01"),
    _make_disk("oracle-prod-01-data-0", RG_PROD, 1024, "Premium_LRS", "oracle-prod-01"),
    # app tier
    _make_disk("app-prod-01-osdisk", RG_PROD, 128, "Premium_LRS", "app-prod-01"),
    _make_disk("app-prod-02-osdisk", RG_PROD, 128, "Premium_LRS", "app-prod-02"),
    _make_disk("app-prod-03-osdisk", RG_PROD, 128, "StandardSSD_LRS", "app-prod-03"),
    _make_disk("jumpbox-01-osdisk", RG_PROD, 64, "StandardSSD_LRS", "jumpbox-01"),
    # analytics
    _make_disk("analytics-01-osdisk", RG_ANALYTICS, 256, "StandardSSD_LRS", "analytics-01"),
    _make_disk("analytics-01-data-0", RG_ANALYTICS, 1024, "Standard_LRS", "analytics-01"),
    _make_disk("analytics-02-osdisk", RG_ANALYTICS, 256, "StandardSSD_LRS", "analytics-02"),
    # dev
    _make_disk("sql-dev-01-osdisk", RG_DEV, 128, "Standard_LRS", "sql-dev-01", location="westus2"),
    _make_disk("sql-dev-01-data-0", RG_DEV, 512, "Standard_LRS", "sql-dev-01", location="westus2"),
    _make_disk(
        "dev-worker-01-osdisk", RG_DEV, 64, "Standard_LRS", "dev-worker-01", location="westus2"
    ),
]


MOCK_VAULTS: list[NS] = [
    NS(
        id=_vault_id(RG_BACKUP, "vault-prod-east"),
        name="vault-prod-east",
        location="eastus",
        tags={"environment": "prod", "owner": "ops-team", "costcenter": "CC-1001"},
    ),
    NS(
        id=_vault_id(RG_DEV, "vault-nonprod"),
        name="vault-nonprod",
        location="westus2",
        tags={"environment": "dev"},
    ),
]

# Storage configs keyed by vault name
MOCK_STORAGE_CONFIGS: dict[str, NS] = {
    "vault-prod-east": NS(properties=NS(storage_type="GeoRedundant")),
    "vault-nonprod": NS(properties=NS(storage_type="LocallyRedundant")),
}


def _make_ltr(daily=None, weekly=None, monthly=None, yearly=None) -> NS:
    """Build a LongTermRetentionPolicy namespace."""

    def _tier(count):
        return NS(retention_duration=NS(count=count)) if count else None

    ret = NS(
        retention_count=None,
        daily_schedule=_tier(daily),
        weekly_schedule=_tier(weekly),
        monthly_schedule=_tier(monthly),
        yearly_schedule=_tier(yearly),
    )
    return ret


def _make_simple_sched(frequency: str, hour: int = 2) -> NS:
    return NS(
        schedule_run_frequency=frequency,
        schedule_run_times=[datetime(2024, 1, 1, hour, 0, tzinfo=timezone.utc)],
    )


def _make_vm_policy(
    name: str,
    vault_rg: str,
    vault_name: str,
    daily=None,
    weekly=None,
    monthly=None,
    yearly=None,
    frequency="Daily",
) -> NS:
    return NS(
        id=_policy_id(vault_rg, vault_name, name),
        name=name,
        properties=NS(
            backup_management_type="AzureIaasVM",
            schedule_policy=_make_simple_sched(frequency),
            retention_policy=_make_ltr(daily, weekly, monthly, yearly),
            sub_protection_policy=None,
        ),
    )


def _make_sql_policy(name: str, vault_rg: str, vault_name: str) -> NS:
    return NS(
        id=_policy_id(vault_rg, vault_name, name),
        name=name,
        properties=NS(
            backup_management_type="AzureWorkload",
            schedule_policy=None,
            retention_policy=None,
            sub_protection_policy=[
                NS(
                    schedule_policy=_make_simple_sched("Daily"),
                    retention_policy=_make_ltr(daily=14, weekly=4, monthly=6, yearly=1),
                )
            ],
        ),
    )


MOCK_POLICIES: dict[str, list[NS]] = {
    "vault-prod-east": [
        _make_vm_policy(
            "GoldPolicy", RG_BACKUP, "vault-prod-east", daily=30, weekly=12, monthly=12, yearly=5
        ),
        _make_vm_policy("SilverPolicy", RG_BACKUP, "vault-prod-east", daily=7, weekly=4, monthly=3),
        _make_sql_policy("SQLPolicy", RG_BACKUP, "vault-prod-east"),
    ],
    "vault-nonprod": [
        _make_vm_policy("DefaultPolicy", RG_DEV, "vault-nonprod", daily=7),
    ],
}


def _make_vm_item(
    vm_name: str,
    vm_rg: str,
    vault_rg: str,
    vault_name: str,
    policy_name: str,
    protection_state: str = "Protected",
    last_backup_status: str = "Completed",
    last_backup_time: datetime | None = None,
) -> NS:
    item_name = f"VM;iaasvmcontainer;{vm_rg};{vm_name}"
    lbt = last_backup_time or datetime(2024, 6, 14, 3, 12, tzinfo=timezone.utc)
    props = NS(
        backup_management_type="AzureIaasVM",
        protection_state=protection_state,
        last_backup_status=last_backup_status,
        last_backup_time=lbt,
        policy_id=_policy_id(vault_rg, vault_name, policy_name),
        source_resource_id=_vm_id(vm_rg, vm_name),
        virtual_machine_id=_vm_id(vm_rg, vm_name),
    )
    return NS(
        id=_item_id(vault_rg, vault_name, item_name),
        name=item_name,
        properties=props,
    )


MOCK_PROTECTED_ITEMS: dict[str, list[NS]] = {
    "vault-prod-east": [
        # Protected ✓
        _make_vm_item("sql-prod-01", RG_DATA, RG_BACKUP, "vault-prod-east", "GoldPolicy"),
        _make_vm_item("sql-prod-02", RG_DATA, RG_BACKUP, "vault-prod-east", "GoldPolicy"),
        _make_vm_item("app-prod-01", RG_PROD, RG_BACKUP, "vault-prod-east", "SilverPolicy"),
        _make_vm_item("app-prod-02", RG_PROD, RG_BACKUP, "vault-prod-east", "SilverPolicy"),
        _make_vm_item("app-prod-03", RG_PROD, RG_BACKUP, "vault-prod-east", "SilverPolicy"),
        _make_vm_item("jumpbox-01", RG_PROD, RG_BACKUP, "vault-prod-east", "SilverPolicy"),
        # Protection stopped (counts as unprotected in gap analysis)
        _make_vm_item(
            "oracle-prod-01",
            RG_PROD,
            RG_BACKUP,
            "vault-prod-east",
            "GoldPolicy",
            protection_state="ProtectionStopped",
            last_backup_status="Failed",
        ),
    ],
    "vault-nonprod": [
        _make_vm_item(
            "sql-dev-01",
            RG_DEV,
            RG_DEV,
            "vault-nonprod",
            "DefaultPolicy",
            last_backup_time=datetime(2024, 6, 13, 4, 0, tzinfo=timezone.utc),
        ),
    ],
}

# VMs with NO protected item at all: sap-hana-01, analytics-01, analytics-02, dev-worker-01
# Plus oracle-prod-01 is ProtectionStopped → 5 unprotected total


def _storage_id(rg: str, name: str) -> str:
    return (
        f"/subscriptions/{SUB_ID}/resourceGroups/{rg}"
        f"/providers/Microsoft.Storage/storageAccounts/{name}"
    )


def _make_storage_account(
    name: str,
    rg: str,
    location: str,
    kind: str,
    sku_name: str,
    access_tier: str | None = None,
    tags: dict[str, str] | None = None,
) -> NS:
    return NS(
        id=_storage_id(rg, name),
        name=name,
        location=location,
        kind=kind,
        sku=NS(name=sku_name),
        access_tier=access_tier,
        tags=tags or {},
    )


MOCK_STORAGE_ACCOUNTS: list[NS] = [
    _make_storage_account(
        "stgproddata",
        RG_DATA,
        "eastus",
        "StorageV2",
        "Standard_GRS",
        access_tier="Hot",
        tags={"environment": "prod", "owner": "dba-team", "costcenter": "CC-1042"},
    ),
    _make_storage_account(
        "stgprodlogs",
        RG_PROD,
        "eastus",
        "StorageV2",
        "Standard_LRS",
        access_tier="Cool",
        tags={"environment": "prod", "owner": "ops-team", "costcenter": "CC-1001"},
    ),
    _make_storage_account(
        "stganalytics",
        RG_ANALYTICS,
        "eastus",
        "StorageV2",
        "Standard_RAGRS",
        access_tier="Hot",
        tags={"environment": "prod"},
    ),
    _make_storage_account(
        "stgdevassets",
        RG_DEV,
        "westus2",
        "StorageV2",
        "Standard_LRS",
        access_tier="Cool",
        tags={"environment": "dev", "owner": "dev-team"},
    ),
    _make_storage_account(
        "stgpremblobs",
        RG_PROD,
        "eastus",
        "BlockBlobStorage",
        "Premium_LRS",
        access_tier=None,
        tags={"environment": "prod", "owner": "platform", "costcenter": "CC-1001"},
    ),
]


def _make_blob_props(
    blob_sd_enabled: bool = False,
    blob_sd_days: int | None = None,
    container_sd_enabled: bool = False,
    container_sd_days: int | None = None,
    versioning: bool = False,
) -> NS:
    return NS(
        delete_retention_policy=NS(enabled=blob_sd_enabled, days=blob_sd_days),
        container_delete_retention_policy=NS(enabled=container_sd_enabled, days=container_sd_days),
        is_versioning_enabled=versioning,
    )


#: Blob service properties keyed by account name.
#: stgpremblobs is intentionally absent — Premium/BlockBlobStorage raises ResourceNotFoundError.
MOCK_BLOB_PROPS: dict[str, NS] = {
    "stgproddata": _make_blob_props(True, 14, True, 7, True),
    "stgprodlogs": _make_blob_props(True, 7, False, None, False),
    "stganalytics": _make_blob_props(False, None, False, None, True),
    "stgdevassets": _make_blob_props(False, None, False, None, False),
}

#: stgproddata has a blob inventory policy; all others raise ResourceNotFoundError.
MOCK_BLOB_INVENTORY_POLICIES: dict[str, NS] = {
    "stgproddata": NS(properties=NS(policy=NS(rules=[NS(name="daily-inventory")]))),
}


def _make_metric_result(bytes_value: float) -> NS:
    """Monitor metrics result with one non-null maximum data point (newest last)."""
    return NS(
        value=[
            NS(
                timeseries=[
                    NS(
                        data=[
                            NS(maximum=None),  # older null point
                            NS(maximum=bytes_value),  # latest non-null
                        ]
                    )
                ]
            )
        ]
    )


#: Capacity data for 3 of 5 accounts. stgdevassets + stgpremblobs return no metrics.
MOCK_STORAGE_METRICS: dict[str, NS] = {
    _storage_id(RG_DATA, "stgproddata"): _make_metric_result(500 * 1024**3),
    _storage_id(RG_PROD, "stgprodlogs"): _make_metric_result(200 * 1024**3),
    _storage_id(RG_ANALYTICS, "stganalytics"): _make_metric_result(1500 * 1024**3),
}


def mock_blob_props_effect(resource_group: str, account_name: str) -> NS:
    """Side-effect for ``blob_services.get_service_properties()``."""
    if account_name in MOCK_BLOB_PROPS:
        return MOCK_BLOB_PROPS[account_name]
    raise ResourceNotFoundError(message=f"Blob service properties not supported for {account_name}")


def mock_blob_inventory_effect(resource_group: str, account_name: str) -> NS:
    """Side-effect for ``blob_inventory_policies.get()``."""
    if account_name in MOCK_BLOB_INVENTORY_POLICIES:
        return MOCK_BLOB_INVENTORY_POLICIES[account_name]
    raise ResourceNotFoundError(message=f"No inventory policy for {account_name}")


def mock_monitor_metrics_effect(resource_uri: str, **kwargs: Any) -> NS:
    """Side-effect for ``MonitorManagementClient.metrics.list()``."""
    if resource_uri in MOCK_STORAGE_METRICS:
        return MOCK_STORAGE_METRICS[resource_uri]
    raise HttpResponseError(message=f"Metrics unavailable for {resource_uri}")


def _sql_server_id(rg: str, name: str) -> str:
    return f"/subscriptions/{SUB_ID}/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{name}"


def _sql_db_id(rg: str, server_name: str, db_name: str) -> str:
    return f"{_sql_server_id(rg, server_name)}/databases/{db_name}"


def _make_sql_server(
    name: str,
    rg: str,
    location: str,
    version: str = "12.0",
    tags: dict[str, str] | None = None,
) -> NS:
    return NS(
        id=_sql_server_id(rg, name),
        name=name,
        location=location,
        version=version,
        tags=tags or {},
        kind="v12.0",
    )


def _make_sql_db(
    name: str,
    server_name: str,
    rg: str,
    sku_tier: str,
    sku_name: str,
    max_size_gb: float,
    backup_redundancy: str = "Geo",
    zone_redundant: bool = False,
) -> NS:
    return NS(
        id=_sql_db_id(rg, server_name, name),
        name=name,
        sku=NS(tier=sku_tier, name=sku_name),
        max_size_bytes=int(max_size_gb * 1024**3),
        current_backup_storage_redundancy=backup_redundancy,
        zone_redundant=zone_redundant,
    )


MOCK_SQL_SERVERS: list[NS] = [
    _make_sql_server(
        "sql-prod-eastus",
        RG_DATA,
        "eastus",
        tags={"environment": "prod", "owner": "dba-team", "costcenter": "CC-1042"},
    ),
    _make_sql_server(
        "sql-dev-westus2",
        RG_DEV,
        "westus2",
        tags={"environment": "dev", "owner": "dev-team"},
    ),
]

# Databases keyed by (resource_group, server_name); include system DBs to
# verify they are filtered out.
MOCK_SQL_DATABASES: dict[tuple, list[NS]] = {
    (RG_DATA, "sql-prod-eastus"): [
        _make_sql_db(
            "AdventureWorks", "sql-prod-eastus", RG_DATA, "GeneralPurpose", "GP_Gen5_4", 256, "Geo"
        ),
        _make_sql_db(
            "SalesDB",
            "sql-prod-eastus",
            RG_DATA,
            "BusinessCritical",
            "BC_Gen5_8",
            512,
            "Geo",
            zone_redundant=True,
        ),
        _make_sql_db(
            "master", "sql-prod-eastus", RG_DATA, "System", "System0", 5
        ),  # system — should be filtered
    ],
    (RG_DEV, "sql-dev-westus2"): [
        _make_sql_db("DevDB", "sql-dev-westus2", RG_DEV, "Standard", "S2", 50, "Local"),
    ],
}

# Short-term retention keyed by (resource_group, server_name, database_name).
# DevDB is intentionally absent → ResourceNotFoundError → returns None.
MOCK_SQL_SHORT_TERM_RETENTION: dict[tuple, NS] = {
    (RG_DATA, "sql-prod-eastus", "AdventureWorks"): NS(retention_days=35),
    (RG_DATA, "sql-prod-eastus", "SalesDB"): NS(retention_days=14),
    (RG_DEV, "sql-dev-westus2", "DevDB"): NS(retention_days=7),
}

# LTR policy keyed by (resource_group, server_name, database_name).
# DevDB absent → raises → returns False.
MOCK_SQL_LTR: dict[tuple, NS] = {
    (RG_DATA, "sql-prod-eastus", "AdventureWorks"): NS(
        weekly_retention="P12W", monthly_retention="P12M", yearly_retention="P5Y"
    ),
    (RG_DATA, "sql-prod-eastus", "SalesDB"): NS(
        weekly_retention="PT0S", monthly_retention="PT0S", yearly_retention="PT0S"
    ),
}


def _mi_id(rg: str, name: str) -> str:
    return (
        f"/subscriptions/{SUB_ID}/resourceGroups/{rg}"
        f"/providers/Microsoft.Sql/managedInstances/{name}"
    )


def _make_sql_mi(
    name: str,
    rg: str,
    location: str,
    sku_tier: str = "GeneralPurpose",
    sku_name: str = "GP_Gen5",
    v_cores: int = 8,
    storage_size_gb: int = 512,
    license_type: str = "LicenseIncluded",
    backup_redundancy: str = "Geo",
    zone_redundant: bool = False,
    tags: dict[str, str] | None = None,
) -> NS:
    return NS(
        id=_mi_id(rg, name),
        name=name,
        location=location,
        sku=NS(name=sku_name, tier=sku_tier),
        v_cores=v_cores,
        storage_size_in_gb=storage_size_gb,
        license_type=license_type,
        current_backup_storage_redundancy=backup_redundancy,
        zone_redundant=zone_redundant,
        tags=tags or {},
    )


#: Realistic managed-instance fixture: two prod-sized MIs in different regions.
MOCK_SQL_MANAGED_INSTANCES: list[NS] = [
    _make_sql_mi(
        "mi-prod-eastus",
        RG_DATA,
        "eastus",
        sku_tier="BusinessCritical",
        sku_name="BC_Gen5",
        v_cores=16,
        storage_size_gb=2048,
        tags={"environment": "prod", "owner": "dba-team", "costcenter": "CC-1042"},
    ),
    _make_sql_mi(
        "mi-analytics-eastus",
        RG_ANALYTICS,
        "eastus",
        sku_tier="GeneralPurpose",
        sku_name="GP_Gen5",
        v_cores=8,
        storage_size_gb=1024,
        tags={"environment": "prod", "owner": "analytics"},
    ),
]


def _flex_server_id(rg: str, engine: str, name: str) -> str:
    provider = "Microsoft.DBforPostgreSQL" if engine == "PostgreSQL" else "Microsoft.DBforMySQL"
    return (
        f"/subscriptions/{SUB_ID}/resourceGroups/{rg}/providers/{provider}/flexibleServers/{name}"
    )


def _make_flex_server(
    name: str,
    rg: str,
    location: str,
    engine: str,
    sku_name: str,
    tier: str,
    version: str,
    storage_gb: int,
    retention_days: int,
    geo_redundant: bool,
    tags: dict[str, str] | None = None,
) -> NS:
    return NS(
        id=_flex_server_id(rg, engine, name),
        name=name,
        location=location,
        sku=NS(name=sku_name, tier=tier),
        version=version,
        storage=NS(storage_size_gb=storage_gb),
        backup=NS(
            backup_retention_days=retention_days,
            geo_redundant_backup="Enabled" if geo_redundant else "Disabled",
        ),
        tags=tags or {},
    )


def _make_flex_db(name: str) -> NS:
    return NS(name=name)


MOCK_PG_SERVERS: list[NS] = [
    _make_flex_server(
        "pg-prod-eastus",
        RG_DATA,
        "eastus",
        "PostgreSQL",
        "Standard_D4s_v3",
        "GeneralPurpose",
        "15",
        128,
        14,
        geo_redundant=True,
        tags={"environment": "prod", "owner": "dba-team", "costcenter": "CC-1042"},
    ),
    _make_flex_server(
        "pg-dev-westus2",
        RG_DEV,
        "westus2",
        "PostgreSQL",
        "Standard_B2ms",
        "Burstable",
        "15",
        32,
        7,
        geo_redundant=False,
        tags={"environment": "dev", "owner": "dev-team"},
    ),
]

# Databases keyed by (rg, server_name); include system DB to verify filtering.
MOCK_PG_DATABASES: dict[tuple, list[NS]] = {
    (RG_DATA, "pg-prod-eastus"): [
        _make_flex_db("appdb"),
        _make_flex_db("analyticsdb"),
        _make_flex_db("postgres"),  # system — filtered
    ],
    (RG_DEV, "pg-dev-westus2"): [
        _make_flex_db("testdb"),
        _make_flex_db("azure_maintenance"),  # system — filtered
    ],
}


MOCK_MYSQL_SERVERS: list[NS] = [
    _make_flex_server(
        "mysql-prod-eastus",
        RG_PROD,
        "eastus",
        "MySQL",
        "Standard_E4ds_v4",
        "MemoryOptimized",
        "8.0.21",
        64,
        7,
        geo_redundant=True,
        tags={"environment": "prod", "owner": "platform", "costcenter": "CC-1001"},
    ),
]

MOCK_MYSQL_DATABASES: dict[tuple, list[NS]] = {
    (RG_PROD, "mysql-prod-eastus"): [
        _make_flex_db("wordpressdb"),
        _make_flex_db("mysql"),  # system — filtered
        _make_flex_db("information_schema"),  # system — filtered
    ],
}


def mock_sql_dbs_effect(rg: str, server_name: str):
    """Side-effect for ``databases.list_by_server()`` (SQL)."""
    return iter(MOCK_SQL_DATABASES.get((rg, server_name), []))


def mock_sql_short_term_retention_effect(
    rg: str, server_name: str, db_name: str, policy_name: str
) -> NS:
    """Side-effect for ``backup_short_term_retention_policies.get()``."""
    key = (rg, server_name, db_name)
    if key in MOCK_SQL_SHORT_TERM_RETENTION:
        return MOCK_SQL_SHORT_TERM_RETENTION[key]
    raise ResourceNotFoundError(message=f"No retention policy for {db_name}")


def mock_sql_ltr_effect(rg: str, server_name: str, db_name: str, policy_name: str) -> NS:
    """Side-effect for ``long_term_retention_policies.get()``, which needs the policy name."""
    key = (rg, server_name, db_name)
    if key in MOCK_SQL_LTR:
        return MOCK_SQL_LTR[key]
    raise ResourceNotFoundError(message=f"No LTR policy for {db_name}")


def mock_pg_dbs_effect(rg: str, server_name: str):
    """Side-effect for PostgreSQL ``databases.list_by_server()``."""
    return iter(MOCK_PG_DATABASES.get((rg, server_name), []))


def mock_mysql_dbs_effect(rg: str, server_name: str):
    """Side-effect for MySQL ``databases.list_by_server()``."""
    return iter(MOCK_MYSQL_DATABASES.get((rg, server_name), []))


def _make_job(
    job_id: str,
    vm_name: str,
    vm_rg: str,
    vault_name: str,
    operation: str,
    status: str,
    start_time: datetime,
    duration_minutes: float,
    data_gb: float | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> NS:
    """Build a mock AzureIaaSVMJob namespace."""
    end_time = start_time + timedelta(minutes=duration_minutes)
    error_details = [NS(error_code=error_code, error_string=error_message)] if error_code else None
    data_bytes = int(data_gb * 1024**3) if data_gb is not None else None
    return NS(
        name=job_id,
        properties=NS(
            backup_management_type="AzureIaasVM",
            entity_friendly_name=vm_name,
            source_resource_id=_vm_id(vm_rg, vm_name),
            operation=operation,
            status=status,
            start_time=start_time,
            end_time=end_time,
            duration=timedelta(minutes=duration_minutes),
            extended_info=NS(data_transferred_in_bytes=data_bytes),
            error_details=error_details,
        ),
    )


# vault-prod-east jobs: 60 days of history for protected VMs
_D = lambda days_ago, hour=2: (
    datetime(2026, 4, 12, hour, 0, tzinfo=timezone.utc) - timedelta(days=days_ago)
)  # noqa: E731

MOCK_BACKUP_JOBS: dict[str, list[NS]] = {
    "vault-prod-east": [
        # sql-prod-01 — daily Gold policy, all successful
        _make_job(
            "job-sql01-1",
            "sql-prod-01",
            RG_DATA,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(1),
            42,
            data_gb=8.2,
        ),
        _make_job(
            "job-sql01-2",
            "sql-prod-01",
            RG_DATA,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(2),
            44,
            data_gb=8.1,
        ),
        _make_job(
            "job-sql01-3",
            "sql-prod-01",
            RG_DATA,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(3),
            41,
            data_gb=8.3,
        ),
        _make_job(
            "job-sql01-4",
            "sql-prod-01",
            RG_DATA,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(7),
            43,
            data_gb=8.0,
        ),
        _make_job(
            "job-sql01-5",
            "sql-prod-01",
            RG_DATA,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(14),
            40,
            data_gb=7.9,
        ),
        # sql-prod-02 — daily Gold policy, one failure
        _make_job(
            "job-sql02-1",
            "sql-prod-02",
            RG_DATA,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(1),
            28,
            data_gb=4.1,
        ),
        _make_job(
            "job-sql02-2",
            "sql-prod-02",
            RG_DATA,
            "vault-prod-east",
            "Backup",
            "Failed",
            _D(2),
            5,
            error_code="UserErrorVmNotInDesirableState",
            error_message="VM was deallocated during backup window",
        ),
        _make_job(
            "job-sql02-3",
            "sql-prod-02",
            RG_DATA,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(3),
            29,
            data_gb=4.0,
        ),
        _make_job(
            "job-sql02-4",
            "sql-prod-02",
            RG_DATA,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(7),
            27,
            data_gb=3.9,
        ),
        # app-prod-01 — Silver policy
        _make_job(
            "job-app01-1",
            "app-prod-01",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(1),
            12,
            data_gb=1.2,
        ),
        _make_job(
            "job-app01-2",
            "app-prod-01",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(2),
            11,
            data_gb=1.1,
        ),
        _make_job(
            "job-app01-3",
            "app-prod-01",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "CompletedWithWarnings",
            _D(3),
            13,
            data_gb=1.3,
        ),
        # app-prod-02 — Silver policy, all clean
        _make_job(
            "job-app02-1",
            "app-prod-02",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(1),
            11,
            data_gb=1.1,
        ),
        _make_job(
            "job-app02-2",
            "app-prod-02",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(2),
            12,
            data_gb=1.0,
        ),
        # app-prod-03 — Silver policy
        _make_job(
            "job-app03-1",
            "app-prod-03",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(1),
            8,
            data_gb=0.9,
        ),
        _make_job(
            "job-app03-2",
            "app-prod-03",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(2),
            9,
            data_gb=0.8,
        ),
        # jumpbox-01 — Silver policy
        _make_job(
            "job-jmp-1",
            "jumpbox-01",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "Completed",
            _D(1),
            6,
            data_gb=0.4,
        ),
        # oracle-prod-01 — protection stopped; shows recent failures
        _make_job(
            "job-ora-1",
            "oracle-prod-01",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "Failed",
            _D(3),
            2,
            error_code="UserErrorVMIaaSProviderError",
            error_message="Protection is stopped. Please resume protection before triggering backup.",
        ),
        _make_job(
            "job-ora-2",
            "oracle-prod-01",
            RG_PROD,
            "vault-prod-east",
            "Backup",
            "Failed",
            _D(10),
            2,
            error_code="UserErrorVMIaaSProviderError",
            error_message="Protection is stopped. Please resume protection before triggering backup.",
        ),
    ],
    "vault-nonprod": [
        # sql-dev-01 — DefaultPolicy, all healthy
        _make_job(
            "job-dev01-1",
            "sql-dev-01",
            RG_DEV,
            "vault-nonprod",
            "Backup",
            "Completed",
            _D(1),
            15,
            data_gb=1.5,
        ),
        _make_job(
            "job-dev01-2",
            "sql-dev-01",
            RG_DEV,
            "vault-nonprod",
            "Backup",
            "Completed",
            _D(2),
            14,
            data_gb=1.4,
        ),
        _make_job(
            "job-dev01-3",
            "sql-dev-01",
            RG_DEV,
            "vault-nonprod",
            "Backup",
            "Completed",
            _D(7),
            16,
            data_gb=1.6,
        ),
    ],
}


def mock_backup_jobs_effect(vault_name: str, rg: str, **kwargs) -> object:
    """Side-effect for ``backup_jobs.list(vault_name, rg, filter=...)``.

    The real API applies an OData filter; the mock ignores it and returns all
    fixture jobs for the vault.
    """
    return iter(MOCK_BACKUP_JOBS.get(vault_name, []))


# Raw rows in the format the Cost Management API returns:
#   [Cost (float), ServiceName (str), BillingMonth (str 14-digit), Currency (str)]
MOCK_COST_ROWS: list[list] = [
    # Nov 2025
    [12500.00, "Virtual Machines", "20251101000000", "USD"],
    [3200.00, "Azure Storage", "20251101000000", "USD"],
    [1800.00, "Azure SQL Database", "20251101000000", "USD"],
    [850.00, "Recovery Services", "20251101000000", "USD"],
    [620.00, "Azure Monitor", "20251101000000", "USD"],
    [410.00, "Virtual Network", "20251101000000", "USD"],
    # Dec 2025
    [13100.00, "Virtual Machines", "20251201000000", "USD"],
    [3350.00, "Azure Storage", "20251201000000", "USD"],
    [1850.00, "Azure SQL Database", "20251201000000", "USD"],
    [870.00, "Recovery Services", "20251201000000", "USD"],
    [640.00, "Azure Monitor", "20251201000000", "USD"],
    [390.00, "Virtual Network", "20251201000000", "USD"],
    # Jan 2026
    [12800.00, "Virtual Machines", "20260101000000", "USD"],
    [3100.00, "Azure Storage", "20260101000000", "USD"],
    [1920.00, "Azure SQL Database", "20260101000000", "USD"],
    [900.00, "Recovery Services", "20260101000000", "USD"],
    [580.00, "Azure Monitor", "20260101000000", "USD"],
    [430.00, "Virtual Network", "20260101000000", "USD"],
    # Feb 2026
    [11900.00, "Virtual Machines", "20260201000000", "USD"],
    [2980.00, "Azure Storage", "20260201000000", "USD"],
    [1880.00, "Azure SQL Database", "20260201000000", "USD"],
    [880.00, "Recovery Services", "20260201000000", "USD"],
    [560.00, "Azure Monitor", "20260201000000", "USD"],
    [380.00, "Virtual Network", "20260201000000", "USD"],
    # Mar 2026
    [13400.00, "Virtual Machines", "20260301000000", "USD"],
    [3500.00, "Azure Storage", "20260301000000", "USD"],
    [1950.00, "Azure SQL Database", "20260301000000", "USD"],
    [920.00, "Recovery Services", "20260301000000", "USD"],
    [610.00, "Azure Monitor", "20260301000000", "USD"],
    [450.00, "Virtual Network", "20260301000000", "USD"],
    # Apr 2026 — partial month
    [5200.00, "Virtual Machines", "20260401000000", "USD"],
    [1350.00, "Azure Storage", "20260401000000", "USD"],
    [750.00, "Azure SQL Database", "20260401000000", "USD"],
    [350.00, "Recovery Services", "20260401000000", "USD"],
    [230.00, "Azure Monitor", "20260401000000", "USD"],
    [170.00, "Virtual Network", "20260401000000", "USD"],
]


def mock_cost_query_effect(scope: str, query_def: object) -> NS:
    """Side-effect for ``CostManagementClient.query.usage()``."""
    return NS(
        columns=[
            NS(name="Cost"),
            NS(name="ServiceName"),
            NS(name="BillingMonth"),
            NS(name="Currency"),
        ],
        rows=MOCK_COST_ROWS,
    )

"""Azure Backup for Blobs and PostgreSQL, which lives in Backup Vaults (Microsoft.DataProtection).

A Recovery Services vault holds VM, SQL-in-VM, Azure SQL and Azure Files backups and is read by
``backup_posture.py``. Blob and PostgreSQL backups are stored in a Backup Vault instead, so they are not
visible there. This is the port of ``Get-AzureDataProtectionInventory`` in ``Get-AzureSizingInfo.ps1``
(1.0.3, SIZENG-1903): the vaults, their Blob and PostgreSQL policies and their Blob and PostgreSQL backup
instances.

Needs ``azure-mgmt-dataprotection`` (in ``requirements.txt``). Like the PowerShell script, which
treats ``Az.DataProtection`` as optional, the tool runs without it and skips only this collection.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Optional

from cloud import DEFAULT_CLOUD, CloudEnvironment
from collectors.utils import enum_text

logger = logging.getLogger(__name__)

#: Conditional import: azure-mgmt-dataprotection is an optional extra, so the tool detects it at import
#: time and the caller decides whether to run this collector at all.
try:
    from azure.mgmt.dataprotection import DataProtectionMgmtClient  # type: ignore[import]

    HAS_SDK = True
except ImportError:
    DataProtectionMgmtClient = None  # type: ignore[assignment,misc]
    HAS_SDK = False

BLOB = "AzureBlob"
POSTGRESQL = "AzurePostgreSQL"

_BLOB_DATASOURCE = "microsoft.storage/storageaccounts/blobservices"
_POSTGRESQL_DATASOURCE_PREFIX = "microsoft.dbforpostgresql/"
_RESOURCE_GROUP = re.compile(r"/resourceGroups/([^/]+)/", re.IGNORECASE)
_STORAGE_ACCOUNT = re.compile(r"/storageAccounts/([^/]+)", re.IGNORECASE)
_SERVER = re.compile(r"/(?:flexibleServers|servers)/([^/]+)", re.IGNORECASE)
_DATABASE = re.compile(r"/databases/([^/]+)", re.IGNORECASE)


def workload_of(datasource_type: Optional[str]) -> Optional[str]:
    """The workload name a datasource type is reported under, or None for one this tool does not
    report (``Get-AzureDataProtectionWorkload``). The Blob match is exact.
    """
    lowered = (datasource_type or "").lower()
    if lowered == _BLOB_DATASOURCE:
        return BLOB
    if lowered.startswith(_POSTGRESQL_DATASOURCE_PREFIX):
        return POSTGRESQL
    return None


@dataclass
class BackupVault:
    """One Backup Vault."""

    name: str
    type: Optional[str]
    location: Optional[str]
    resource_group: str


@dataclass
class BackupVaultPolicy:
    """One Blob or PostgreSQL policy of a vault, as the API returns it."""

    vault_name: str
    resource_group: str
    location: Optional[str]
    workload: str
    datasource_types: list[str]
    id: Optional[str]
    name: Optional[str]
    object_type: Optional[str]
    # The policy's ``properties`` in the API's own (camelCase) names.
    properties: dict[str, Any] = field(default_factory=dict)
    system_data: dict[str, Any] = field(default_factory=dict)
    type: Optional[str] = None


@dataclass
class BackupVaultItem:
    """One Blob or PostgreSQL backup instance of a vault."""

    vault_name: str
    resource_group: str
    location: Optional[str]
    instance_name: Optional[str]
    workload: str
    datasource_type: Optional[str]
    datasource_name: Optional[str]
    datasource_database: Optional[str]
    datasource_resource_id: Optional[str]
    protection_policy_name: Optional[str]
    policy_id: Optional[str]
    protection_state: Optional[str]


@dataclass
class DataProtectionInventory:
    """Backup Vault inventory of one subscription."""

    subscription_id: str
    vaults: list[BackupVault] = field(default_factory=list)
    policies: list[BackupVaultPolicy] = field(default_factory=list)
    items: list[BackupVaultItem] = field(default_factory=list)
    # How many backup instances the vaults had in all, Blob and PostgreSQL or not.
    instances_found: int = 0
    # The datasource types that were left out, with how many instances had each.
    ignored_types: dict[str, int] = field(default_factory=dict)
    # Set when the vaults could not be listed at all.
    error: Optional[str] = None

    @property
    def total_vaults(self) -> int:
        return len(self.vaults)


def _plain(value: Any) -> Any:
    """A model as the plain JSON the API sent: its own (camelCase) names, nested.

    Models of the current SDK are mappings over that JSON; older ones serialize to it. A model that is
    neither is read through ``as_dict`` and its names are converted from snake_case.
    """
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    serialize = getattr(value, "serialize", None)
    if callable(serialize):
        return _plain(serialize())
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        return _camel_keys(as_dict())
    return enum_text(value) if hasattr(value, "value") else value


def _camel_keys(value: Any) -> Any:
    """``value`` with the keys of every dict, at any depth, converted from snake_case to camelCase."""
    if isinstance(value, Mapping):
        return {_camel(str(k)): _camel_keys(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_camel_keys(v) for v in value]
    return value


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _first(pattern: re.Pattern[str], text: Optional[str]) -> Optional[str]:
    found = pattern.search(text or "")
    return found.group(1) if found else None


class DataProtectionCollector:
    """Collects the Backup Vaults of a subscription.

    Credentials are always injected, never created here. Nothing raises: a failure is a warning and the
    inventory carries what could be read, as the PowerShell function does.
    """

    def __init__(
        self,
        subscription_id: str,
        credential: Any,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
    ) -> None:
        if DataProtectionMgmtClient is None:
            raise RuntimeError("azure-mgmt-dataprotection is not installed")
        self._sub_id = subscription_id
        self._client = DataProtectionMgmtClient(
            credential, subscription_id, **cloud.client_kwargs()
        )

    def collect(self) -> DataProtectionInventory:
        inventory = DataProtectionInventory(subscription_id=self._sub_id)
        try:
            vaults = [v for v in self._client.backup_vaults.get_in_subscription() if v is not None]
        except Exception as exc:
            inventory.error = str(exc)
            logger.warning(
                "[%s] Unable to collect Azure Backup Vault information: %s", self._sub_id, exc
            )
            return inventory

        for vault in vaults:
            resource_group = _first(_RESOURCE_GROUP, getattr(vault, "id", None))
            name = getattr(vault, "name", None) or ""
            if not resource_group:
                logger.warning(
                    "[%s] Could not work out the resource group for Backup Vault %s; skipping it, "
                    "so its policies and backup instances are not collected",
                    self._sub_id,
                    name,
                )
                continue
            location = getattr(vault, "location", None)
            inventory.vaults.append(
                BackupVault(
                    name=name,
                    type=getattr(vault, "type", None),
                    location=location,
                    resource_group=resource_group,
                )
            )
            self._collect_policies(inventory, name, resource_group, location)
            self._collect_instances(inventory, name, resource_group, location)
        return inventory

    def _collect_policies(
        self, inventory: DataProtectionInventory, vault: str, resource_group: str, location: Any
    ) -> None:
        try:
            for policy in self._client.backup_policies.list(resource_group, vault):
                properties = _plain(getattr(policy, "properties", None)) or {}
                datasource_types = [str(t) for t in properties.get("datasourceTypes") or []]
                workloads = [w for w in (workload_of(t) for t in datasource_types) if w]
                if not workloads:
                    continue
                inventory.policies.append(
                    BackupVaultPolicy(
                        vault_name=vault,
                        resource_group=resource_group,
                        location=location,
                        workload=", ".join(workloads),
                        datasource_types=datasource_types,
                        id=getattr(policy, "id", None),
                        name=getattr(policy, "name", None),
                        object_type=properties.get("objectType"),
                        properties=properties,
                        system_data=_plain(getattr(policy, "system_data", None)) or {},
                        type=getattr(policy, "type", None),
                    )
                )
        except Exception as exc:
            logger.warning(
                "[%s] Failed to get Azure Backup Vault policies for vault %s in %s: %s. The policy "
                "list is incomplete; its backup instances are still listed, but their policy names "
                "may have no matching row in the policies file",
                self._sub_id,
                vault,
                resource_group,
                exc,
            )

    def _collect_instances(
        self, inventory: DataProtectionInventory, vault: str, resource_group: str, location: Any
    ) -> None:
        try:
            instances = list(self._client.backup_instances.list(resource_group, vault))
        except Exception as exc:
            logger.warning(
                "[%s] Failed to get Azure Backup Vault backup instances for vault %s in %s: %s",
                self._sub_id,
                vault,
                resource_group,
                exc,
            )
            return
        inventory.instances_found += len(instances)
        for instance in instances:
            properties = _plain(getattr(instance, "properties", None)) or {}
            source = properties.get("dataSourceInfo") or {}
            datasource_type = source.get("datasourceType")
            workload = workload_of(datasource_type)
            if not workload:
                shown = datasource_type or "<unreadable>"
                inventory.ignored_types[shown] = inventory.ignored_types.get(shown, 0) + 1
                continue
            resource_id = source.get("resourceID") or source.get("resourceId")
            pattern = _STORAGE_ACCOUNT if workload == BLOB else _SERVER
            policy_id = (properties.get("policyInfo") or {}).get("policyId")
            inventory.items.append(
                BackupVaultItem(
                    vault_name=vault,
                    resource_group=resource_group,
                    location=location,
                    instance_name=getattr(instance, "name", None),
                    workload=workload,
                    datasource_type=datasource_type,
                    datasource_name=_first(pattern, resource_id) or source.get("resourceName"),
                    datasource_database=_first(_DATABASE, resource_id),
                    datasource_resource_id=resource_id,
                    protection_policy_name=(
                        policy_id.rstrip("/").rsplit("/", 1)[-1] if policy_id else None
                    ),
                    policy_id=policy_id,
                    protection_state=enum_text(properties.get("currentProtectionState")),
                )
            )

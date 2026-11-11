"""AKS clusters and Cosmos DB accounts for Rubrik Discovery.

Both are read as ARM JSON through the ``azure-mgmt-resource`` client that is already a
dependency: a list by resource type, then a get of each resource at a pinned API version. This
adds no SDK package. The properties read are those ``Get-AzAksCluster``, ``Get-AzAksNodePool`` and
``Get-AzCosmosDBAccount`` return in ``Get-AzureSizingInfo.ps1``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from azure.core.exceptions import HttpResponseError
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from cloud import DEFAULT_CLOUD, CloudEnvironment
from collectors.utils import latest_maximum, parse_resource_group

logger = logging.getLogger(__name__)

AKS_RESOURCE_TYPE = "Microsoft.ContainerService/managedClusters"
AKS_API_VERSION = "2024-05-01"
COSMOS_RESOURCE_TYPE = "Microsoft.DocumentDB/databaseAccounts"
COSMOS_API_VERSION = "2024-05-15"
_COSMOS_METRIC_NAMESPACE = "Microsoft.DocumentDB/databaseAccounts"


@dataclass
class AksNodePool:
    """One agent pool of a cluster."""

    name: Optional[str] = None
    vm_size: Optional[str] = None
    count: Optional[int] = None
    max_count: Optional[int] = None
    os_disk_size_gb: Optional[int] = None


@dataclass
class AksCluster:
    """One AKS cluster with its node pools."""

    name: str
    resource_id: str
    resource_group: str
    location: str
    kubernetes_version: Optional[str] = None
    provisioning_state: Optional[str] = None
    power_state: Optional[str] = None
    dns_prefix: Optional[str] = None
    fqdn: Optional[str] = None
    node_resource_group: Optional[str] = None
    node_pools: list[AksNodePool] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class AksInventory:
    """AKS clusters of one subscription."""

    subscription_id: str
    clusters: list[AksCluster] = field(default_factory=list)
    total_clusters: int = 0
    total_nodes: int = 0


@dataclass
class CosmosAccount:
    """One Cosmos DB account with its backup policy and size metrics."""

    name: str
    resource_id: str
    location: str  # as the API returns it, e.g. "West US 2"
    kind: Optional[str] = None
    instance_id: Optional[str] = None
    backup_type: Optional[str] = None  # "Periodic" or "Continuous"
    backup_interval_minutes: Optional[int] = None
    backup_retention_hours: Optional[int] = None
    backup_storage_redundancy: Optional[str] = None
    backup_tier: Optional[str] = None  # continuous mode only
    minimal_tls_version: Optional[str] = None
    offer_type: Optional[str] = None
    document_count: Optional[float] = None
    data_usage: Optional[float] = None
    physical_partition_size_info: Optional[float] = None
    physical_partition_count: Optional[float] = None
    index_usage: Optional[float] = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class CosmosInventory:
    """Cosmos DB accounts of one subscription."""

    subscription_id: str
    accounts: list[CosmosAccount] = field(default_factory=list)
    total_accounts: int = 0


def _region_key(location: str) -> str:
    return location.replace(" ", "").lower()


def _read_resources(
    client: ResourceManagementClient,
    resource_type: str,
    api_version: str,
    regions: Optional[frozenset[str]],
    sub_id: str,
) -> list[Any]:
    """Every resource of a type in the subscription, fetched in full, in API order."""
    found: list[Any] = []
    try:
        listed = list(client.resources.list(filter=f"resourceType eq '{resource_type}'"))
    except HttpResponseError as exc:
        logger.warning("[%s] Failed to list %s: %s", sub_id, resource_type, exc)
        return found
    for item in listed:
        if regions and _region_key(getattr(item, "location", "") or "") not in regions:
            continue
        try:
            found.append(client.resources.get_by_id(item.id, api_version))
        except Exception as exc:
            logger.warning("[%s] Skipping %s: %s", sub_id, getattr(item, "name", "?"), exc)
    return found


def _int_or_none(value: Any) -> Optional[int]:
    return int(value) if value is not None else None


class AksCollector:
    """Collects AKS clusters and their node pools for a subscription."""

    def __init__(
        self,
        subscription_id: str,
        credential: Any,
        regions: Optional[list[str]] = None,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
    ) -> None:
        self._sub_id = subscription_id
        self._regions: Optional[frozenset[str]] = frozenset(regions) if regions else None
        self._rm = ResourceManagementClient(credential, subscription_id, **cloud.client_kwargs())

    def collect(self) -> AksInventory:
        """Return the subscription's clusters; an unreadable list gives an empty inventory."""
        clusters = [
            self._cluster(r)
            for r in _read_resources(
                self._rm, AKS_RESOURCE_TYPE, AKS_API_VERSION, self._regions, self._sub_id
            )
        ]
        return AksInventory(
            subscription_id=self._sub_id,
            clusters=clusters,
            total_clusters=len(clusters),
            total_nodes=sum(p.count or 0 for c in clusters for p in c.node_pools),
        )

    @staticmethod
    def _cluster(resource: Any) -> AksCluster:
        props = resource.properties or {}
        pools = [
            AksNodePool(
                name=pool.get("name"),
                vm_size=pool.get("vmSize"),
                count=_int_or_none(pool.get("count")),
                max_count=_int_or_none(pool.get("maxCount")),
                os_disk_size_gb=_int_or_none(pool.get("osDiskSizeGB")),
            )
            for pool in props.get("agentPoolProfiles") or []
        ]
        return AksCluster(
            name=resource.name or "",
            resource_id=resource.id or "",
            resource_group=parse_resource_group(resource.id or ""),
            location=resource.location or "",
            kubernetes_version=props.get("kubernetesVersion"),
            provisioning_state=props.get("provisioningState"),
            power_state=(props.get("powerState") or {}).get("code"),
            dns_prefix=props.get("dnsPrefix"),
            fqdn=props.get("fqdn"),
            node_resource_group=props.get("nodeResourceGroup"),
            node_pools=pools,
            tags=dict(resource.tags or {}),
        )


class CosmosCollector:
    """Collects Cosmos DB accounts, their backup policy and size metrics for a subscription."""

    def __init__(
        self,
        subscription_id: str,
        credential: Any,
        regions: Optional[list[str]] = None,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
        collect_capacity: bool = True,
    ) -> None:
        self._sub_id = subscription_id
        self._collect_capacity = collect_capacity
        self._regions: Optional[frozenset[str]] = frozenset(regions) if regions else None
        self._rm = ResourceManagementClient(credential, subscription_id, **cloud.client_kwargs())
        self._monitor = MonitorManagementClient(
            credential, subscription_id, **cloud.client_kwargs()
        )

    def collect(self) -> CosmosInventory:
        """Return the subscription's accounts; an unreadable list gives an empty inventory."""
        accounts = [
            self._account(r)
            for r in _read_resources(
                self._rm, COSMOS_RESOURCE_TYPE, COSMOS_API_VERSION, self._regions, self._sub_id
            )
        ]
        return CosmosInventory(
            subscription_id=self._sub_id, accounts=accounts, total_accounts=len(accounts)
        )

    def _metric(self, resource_id: str, name: str) -> Optional[float]:
        if not self._collect_capacity:
            return None
        return latest_maximum(self._monitor, resource_id, name, _COSMOS_METRIC_NAMESPACE)

    def _account(self, resource: Any) -> CosmosAccount:
        props = resource.properties or {}
        policy = props.get("backupPolicy") or {}
        kind = policy.get("type")
        # PowerShell fills the policy fields by mode: periodic gives the interval, retention and
        # redundancy, continuous gives only the tier, and any other type leaves them all empty.
        periodic = policy.get("periodicModeProperties") or {} if kind == "Periodic" else {}
        continuous = policy.get("continuousModeProperties") or {} if kind == "Continuous" else {}
        resource_id = resource.id or ""
        return CosmosAccount(
            name=resource.name or "",
            resource_id=resource_id,
            location=resource.location or "",
            kind=resource.kind,
            instance_id=props.get("instanceId"),
            backup_type=kind if kind in ("Periodic", "Continuous") else None,
            backup_interval_minutes=_int_or_none(periodic.get("backupIntervalInMinutes")),
            backup_retention_hours=_int_or_none(periodic.get("backupRetentionIntervalInHours")),
            backup_storage_redundancy=periodic.get("backupStorageRedundancy"),
            backup_tier=continuous.get("tier"),
            minimal_tls_version=props.get("minimalTlsVersion"),
            offer_type=props.get("databaseAccountOfferType"),
            document_count=self._metric(resource_id, "DocumentCount"),
            data_usage=self._metric(resource_id, "DataUsage"),
            physical_partition_size_info=self._metric(resource_id, "PhysicalPartitionSizeInfo"),
            physical_partition_count=self._metric(resource_id, "PhysicalPartitionCount"),
            index_usage=self._metric(resource_id, "IndexUsage"),
            tags=dict(resource.tags or {}),
        )

"""Azure Compute collector for Rubrik Discovery."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from cloud import DEFAULT_CLOUD, CloudEnvironment

from collectors.exclusion import VolumeExclusionEngine
from collectors.utils import (
    TagSummary,
    build_tag_summary,
    decimal_gb,
    decimal_tb,
    enum_text,
    parse_resource_group,
)

logger = logging.getLogger(__name__)

# ARM resource type registered by the SQL IaaS Agent extension when SQL Server
# runs on a plain VM (NOT SQL Managed Instance — that's a separate provider
# collected by database.py).  One of these exists per SQL-Server-on-VM that has
# the agent installed, which Azure auto-registers for Marketplace SQL images and
# recommends for all.  Its properties carry the edition + licensing we want.
_SQL_VM_RESOURCE_TYPE = "Microsoft.SqlVirtualMachine/sqlVirtualMachines"

# A VM only counts as "actively" ad-hoc-snapshot-protected if its newest snapshot
# is within this many days — an ancient orphaned snapshot shouldn't read as protection.
_SNAPSHOT_RECENCY_DAYS = 30


@dataclass
class DiskInfo:
    """Information about a single Azure managed disk."""

    name: str
    disk_size_gb: int
    sku: str  # e.g. Premium_LRS, Standard_LRS, UltraSSD_LRS
    os_disk: bool
    encryption_type: Optional[str]
    resource_id: str = ""  # ARM ID of the managed disk (used to match ad-hoc snapshots)
    # disk_size_gb is whole-GiB-native from the Disk API (no true bytes ever available) —
    # _derived suffix flags these as synthesized, not byte-precise.
    disk_size_bytes_derived: int = 0
    disk_size_tb: float = 0.0
    # Decimal units (GB = 1e9 bytes, TB = 1e12) alongside the binary fields above.
    disk_size_gb_decimal: Optional[float] = None
    disk_size_tb_decimal: Optional[float] = None
    excluded_from_sizing: bool = False
    sizing_exclusion_reason: str = ""


@dataclass
class SqlOnVmInfo:
    """SQL Server running on an Azure VM (IaaS), surfaced via the SQL IaaS Agent
    extension's ``Microsoft.SqlVirtualMachine`` resource.

    Distinct from a SQL Managed Instance (``database.py``) — this is SQL Server
    installed on a customer-managed VM, which Rubrik protects as a SQL workload
    rather than a plain VM image.
    """

    resource_id: str  # the sqlVirtualMachines resource (not the VM itself)
    edition: Optional[str]  # Enterprise / Standard / Developer / Web / Express (sqlImageSku)
    image_offer: Optional[str]  # e.g. SQL2019-WS2022 — OS + SQL version bundle
    license_type: Optional[str]  # PAYG / AHUB / DR
    sql_management: Optional[str]  # Full / LightWeight / NoAgent (agent management mode)


@dataclass
class VMInfo:
    """Information about a single Azure Virtual Machine."""

    name: str
    resource_id: str
    resource_group: str
    subscription_id: str
    location: str
    vm_size: str
    os_type: str  # Windows / Linux / Unknown
    power_state: Optional[str]  # running / deallocated / stopped (None = not fetched)
    tags: dict[str, str]
    disks: list[DiskInfo] = field(default_factory=list)
    total_disk_gb: float = 0.0
    # Σ disk.disk_size_bytes_derived — same derived caveat as the per-disk field.
    total_disk_bytes_derived: float = 0.0
    total_disk_gb_decimal: Optional[float] = None
    total_disk_tb_decimal: Optional[float] = None
    # Populated when this VM runs SQL Server (IaaS); None for a plain VM.
    sql_server: Optional[SqlOnVmInfo] = None
    # True if any attached disk has a manual/ad-hoc snapshot (Microsoft.Compute/snapshots)
    # taken within the last _SNAPSHOT_RECENCY_DAYS, independent of Recovery Services
    # Vault membership — see backup_posture.py for the vault-vs-snapshot-only protection
    # gap that's derived from this.
    has_adhoc_snapshot: bool = False
    # Total ad-hoc snapshots found across all attached disks, regardless of age.
    adhoc_snapshot_count: int = 0
    # Age in days of the most/least recent ad-hoc snapshot; None if there are none.
    # A VM can have adhoc_snapshot_count > 0 with has_adhoc_snapshot False if its
    # only snapshot(s) are older than the recency window — still worth surfacing.
    adhoc_snapshot_newest_days: Optional[int] = None
    adhoc_snapshot_oldest_days: Optional[int] = None
    # The VM's own GUID (``vmId``), not the ARM resource ID. PowerShell writes it as ``vmID``.
    vm_id: str = ""


@dataclass
class ComputeInventory:
    """Compute inventory for a single subscription."""

    subscription_id: str
    vms: list[VMInfo] = field(default_factory=list)

    # Roll-ups
    total_vms: int = 0
    total_disk_tb: float = 0.0
    total_disk_gb_decimal: Optional[float] = None
    total_disk_tb_decimal: Optional[float] = None
    os_breakdown: dict[str, int] = field(default_factory=dict)
    size_breakdown: dict[str, int] = field(default_factory=dict)
    sku_breakdown: dict[str, int] = field(default_factory=dict)
    region_breakdown: dict[str, int] = field(default_factory=dict)

    # SQL-Server-on-VM (IaaS) — VMs flagged by the SQL IaaS Agent extension.
    total_sql_vms: int = 0
    sql_vm_edition_breakdown: dict[str, int] = field(default_factory=dict)

    # VMs with at least one ad-hoc/manual disk snapshot (outside any vault policy).
    total_vms_with_adhoc_snapshot: int = 0

    tag_summary: Optional[TagSummary] = None


class ComputeCollector:
    """Collects Azure VM and managed-disk inventory for a subscription.

    Credentials are always injected — never instantiated inside this class.
    """

    def __init__(
        self,
        subscription_id: str,
        credential: DefaultAzureCredential,
        regions: Optional[list[str]] = None,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
        exclusion: Optional[VolumeExclusionEngine] = None,
    ) -> None:
        """
        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Validated credential injected from ``auth.get_credential()``.
            regions: Normalised region names to include, or None for all.
            cloud: Target Azure cloud (public vs. sovereign). Drives the ARM
                endpoint + token scope so Government tenants resolve correctly.
            exclusion: Flags disks excluded from sizing (tag/name regex); defaults to
                tag-only. Disks are flagged, never dropped.
        """
        self._sub_id = subscription_id
        self._exclusion = exclusion or VolumeExclusionEngine()
        self._regions: Optional[frozenset[str]] = frozenset(regions) if regions else None
        self._client = ComputeManagementClient(credential, subscription_id, **cloud.client_kwargs())
        self._rm = ResourceManagementClient(credential, subscription_id, **cloud.client_kwargs())

    def collect(self) -> ComputeInventory:
        """Run the full compute collection pass for this subscription.

        Returns:
            Populated ComputeInventory dataclass.
        """
        logger.debug("[%s] Starting compute collection", self._sub_id)

        disk_map = self._list_disks()
        sql_vm_map = self._list_sql_vms()
        snapshot_times_by_disk = self._fetch_snapshot_metadata()
        vms = self._list_vms(disk_map, sql_vm_map, snapshot_times_by_disk)

        inventory = ComputeInventory(subscription_id=self._sub_id, vms=vms)
        self._compute_rollups(inventory)
        inventory.tag_summary = build_tag_summary([vm.tags for vm in vms])

        logger.debug(
            "[%s] Compute complete: %d VMs, %.2f TB total disk",
            self._sub_id,
            inventory.total_vms,
            inventory.total_disk_tb,
        )
        return inventory

    def _list_disks(self) -> dict[str, list[DiskInfo]]:
        """List all managed disks, keyed by the VM resource ID they're attached to.

        Returns:
            Dict mapping lowercased VM resource ID → list of DiskInfo.
        """
        disk_map: dict[str, list[DiskInfo]] = {}

        try:
            for disk in self._client.disks.list():
                try:
                    if not disk.managed_by:
                        continue  # Unattached disk — skip.

                    location = (disk.location or "").lower()
                    if self._regions and location not in self._regions:
                        continue

                    vm_id = disk.managed_by.lower()
                    encryption_type = (
                        disk.encryption.type if disk.encryption and disk.encryption.type else None
                    )
                    disk_size_gb = disk.disk_size_gb or 0
                    di = DiskInfo(
                        name=disk.name or "",
                        disk_size_gb=disk_size_gb,
                        sku=disk.sku.name if disk.sku else "Unknown",
                        os_disk=False,  # Resolved when matching VMs below.
                        encryption_type=encryption_type,
                        resource_id=disk.id or "",
                        disk_size_bytes_derived=disk_size_gb * 1024**3,
                        disk_size_tb=round(disk_size_gb / 1024, 3),
                        disk_size_gb_decimal=decimal_gb(disk_size_gb * 1024**3),
                        disk_size_tb_decimal=decimal_tb(disk_size_gb * 1024**3),
                    )
                    raw_tags = getattr(disk, "tags", None)
                    reason = self._exclusion.evaluate(
                        di.name,
                        disk.managed_by.rstrip("/").rsplit("/", 1)[-1],
                        dict(raw_tags) if isinstance(raw_tags, dict) else {},
                    )
                    if reason:
                        di.excluded_from_sizing = True
                        di.sizing_exclusion_reason = reason
                    disk_map.setdefault(vm_id, []).append(di)
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping disk %s: %s",
                        self._sub_id,
                        getattr(disk, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning("[%s] Failed to list disks: %s", self._sub_id, exc)

        return disk_map

    def _fetch_snapshot_metadata(self) -> dict[str, list[datetime]]:
        """Return ad-hoc snapshot creation times, keyed by lowercased source disk ARM ID.

        Queries ``Microsoft.Compute/snapshots`` directly — independent of any
        Recovery Services Vault policy — so a VM whose only protection is a
        customer-taken (or automation-taken) disk snapshot can be distinguished
        from a genuinely unprotected VM, and its snapshot age/count surfaced.
        Mirrors AWS's ``ec2.py:_fetch_snapshotted_volume_ids``
        (``ec2:DescribeSnapshots``). No time filtering here — recency is applied
        per-VM in ``_list_vms`` so an old, stale snapshot still shows up as a
        count/age signal even though it won't count as active protection.

        Note: Azure's ``Snapshot`` resource carries no retention/expiry field —
        unlike AWS EBS snapshots under a DLM lifecycle policy, a manual Azure
        snapshot persists until deleted. We can only report *when it was taken*,
        not how long it's retained for.

        Returns:
            Dict mapping lowercased source-disk ARM ID → list of snapshot
            creation datetimes. Empty on any API error — snapshot detection is
            best-effort and must never fail the compute pass.
        """
        by_disk: dict[str, list[datetime]] = {}
        try:
            for snap in self._client.snapshots.list():
                try:
                    creation_data = getattr(snap, "creation_data", None)
                    source_id = getattr(creation_data, "source_resource_id", None)
                    time_created = getattr(snap, "time_created", None)
                    if not source_id or time_created is None:
                        continue
                    by_disk.setdefault(source_id.lower(), []).append(time_created)
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping snapshot %s: %s",
                        self._sub_id,
                        getattr(snap, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning("[%s] Failed to list snapshots: %s", self._sub_id, exc)

        return by_disk

    def _list_vms(
        self,
        disk_map: dict[str, list[DiskInfo]],
        sql_vm_map: dict[str, SqlOnVmInfo],
        snapshot_times_by_disk: Optional[dict[str, list[datetime]]] = None,
    ) -> list[VMInfo]:
        """List all VMs in scope, enriched with attached disk + SQL-on-VM data.

        Args:
            disk_map: Pre-built disk map from ``_list_disks()``.
            sql_vm_map: Pre-built SQL-on-VM map from ``_list_sql_vms()``, keyed by
                lowercased VM resource ID.
            snapshot_times_by_disk: Lowercased disk ARM ID → snapshot creation
                datetimes, from ``_fetch_snapshot_metadata()``.

        Returns:
            List of VMInfo dataclasses.
        """
        snapshot_times_by_disk = snapshot_times_by_disk or {}
        now = datetime.now(timezone.utc)
        vms: list[VMInfo] = []

        try:
            for vm in self._client.virtual_machines.list_all():
                try:
                    location = (vm.location or "").lower()
                    if self._regions and location not in self._regions:
                        continue

                    vm_id = (vm.id or "").lower()
                    disks = disk_map.get(vm_id, [])

                    # Mark OS disk by name.
                    if vm.storage_profile and vm.storage_profile.os_disk:
                        os_disk_name = vm.storage_profile.os_disk.name
                        for d in disks:
                            if d.name == os_disk_name:
                                d.os_disk = True

                    os_type = "Unknown"
                    if vm.storage_profile and vm.storage_profile.os_disk:
                        os_type = enum_text(vm.storage_profile.os_disk.os_type) or "Unknown"

                    vm_size = "Unknown"
                    if vm.hardware_profile:
                        vm_size = enum_text(vm.hardware_profile.vm_size) or "Unknown"

                    snap_times = [
                        t
                        for d in disks
                        if d.resource_id
                        for t in snapshot_times_by_disk.get(d.resource_id.lower(), [])
                    ]
                    newest = max(snap_times) if snap_times else None
                    oldest = min(snap_times) if snap_times else None
                    newest_days = (now - newest).days if newest else None
                    oldest_days = (now - oldest).days if oldest else None
                    has_adhoc_snapshot = (
                        newest_days is not None and newest_days <= _SNAPSHOT_RECENCY_DAYS
                    )

                    disk_bytes = sum(d.disk_size_bytes_derived for d in disks)
                    vms.append(
                        VMInfo(
                            name=vm.name or "",
                            resource_id=vm.id or "",
                            resource_group=parse_resource_group(vm.id or ""),
                            subscription_id=self._sub_id,
                            location=location,
                            vm_size=vm_size,
                            os_type=os_type,
                            power_state=None,  # Extra per-VM call; not fetched by default.
                            tags=dict(vm.tags) if vm.tags else {},
                            disks=disks,
                            total_disk_gb=sum(d.disk_size_gb for d in disks),
                            total_disk_bytes_derived=disk_bytes,
                            total_disk_gb_decimal=decimal_gb(disk_bytes),
                            total_disk_tb_decimal=decimal_tb(disk_bytes),
                            sql_server=sql_vm_map.get(vm_id),
                            has_adhoc_snapshot=has_adhoc_snapshot,
                            adhoc_snapshot_count=len(snap_times),
                            adhoc_snapshot_newest_days=newest_days,
                            adhoc_snapshot_oldest_days=oldest_days,
                            vm_id=getattr(vm, "vm_id", None) or "",
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping VM %s: %s",
                        self._sub_id,
                        getattr(vm, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning("[%s] Failed to list VMs: %s", self._sub_id, exc)

        return vms

    def _list_sql_vms(self) -> dict[str, SqlOnVmInfo]:
        """Detect SQL-Server-on-VM via the SQL IaaS Agent extension's resources.

        One ``resources.list`` call filtered to the ``Microsoft.SqlVirtualMachine``
        provider — no N+1 per VM.  ``expand="properties"`` returns the edition,
        offer, licensing, and the back-reference to the underlying VM.

        Returns:
            Dict mapping lowercased VM resource ID → SqlOnVmInfo.  Empty on any
            error (graceful degradation — a missing agent or restricted RBAC must
            never fail the compute pass).
        """
        sql_map: dict[str, SqlOnVmInfo] = {}
        try:
            resources = self._rm.resources.list(
                filter=f"resourceType eq '{_SQL_VM_RESOURCE_TYPE}'",
                expand="properties",
            )
            for res in resources:
                try:
                    props = getattr(res, "properties", None) or {}
                    if not isinstance(props, dict):
                        # Some SDK builds return a model object instead of a dict.
                        props = getattr(props, "additional_properties", None) or vars(props)

                    vm_id = props.get("virtualMachineResourceId") or ""
                    if not vm_id:
                        continue

                    sql_map[vm_id.lower()] = SqlOnVmInfo(
                        resource_id=getattr(res, "id", "") or "",
                        edition=props.get("sqlImageSku"),
                        image_offer=props.get("sqlImageOffer"),
                        license_type=props.get("sqlServerLicenseType"),
                        sql_management=props.get("sqlManagement"),
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping SQL VM resource %s: %s",
                        self._sub_id,
                        getattr(res, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning("[%s] Failed to list SQL VMs: %s", self._sub_id, exc)
        except Exception as exc:
            logger.warning("[%s] SQL VM detection error: %s", self._sub_id, exc)

        return sql_map

    def _compute_rollups(self, inventory: ComputeInventory) -> None:
        """Compute aggregate fields on the inventory object in-place."""
        inventory.total_vms = len(inventory.vms)
        total_gb = 0.0
        total_bytes = 0.0

        for vm in inventory.vms:
            total_gb += vm.total_disk_gb
            total_bytes += vm.total_disk_bytes_derived
            inventory.os_breakdown[vm.os_type] = inventory.os_breakdown.get(vm.os_type, 0) + 1
            family = _vm_size_family(vm.vm_size)
            inventory.size_breakdown[family] = inventory.size_breakdown.get(family, 0) + 1
            inventory.region_breakdown[vm.location] = (
                inventory.region_breakdown.get(vm.location, 0) + 1
            )
            for disk in vm.disks:
                sku = _normalise_sku(disk.sku)
                inventory.sku_breakdown[sku] = inventory.sku_breakdown.get(sku, 0) + 1

            if vm.sql_server:
                inventory.total_sql_vms += 1
                edition = vm.sql_server.edition or "Unknown"
                inventory.sql_vm_edition_breakdown[edition] = (
                    inventory.sql_vm_edition_breakdown.get(edition, 0) + 1
                )

            if vm.has_adhoc_snapshot:
                inventory.total_vms_with_adhoc_snapshot += 1

        inventory.total_disk_tb = round(total_gb / 1024, 3)
        inventory.total_disk_gb_decimal = decimal_gb(total_bytes)
        inventory.total_disk_tb_decimal = decimal_tb(total_bytes)


def _vm_size_family(vm_size: str) -> str:
    """Derive the VM size family label from a size string.

    Example: ``Standard_D4s_v3`` → ``Standard_D family``
    """
    m = re.match(r"(Standard|Basic)_([A-Za-z]+)", vm_size or "")
    if m:
        return f"{m.group(1)}_{m.group(2)} family"
    return vm_size or "Unknown"


_SKU_LABELS: dict[str, str] = {
    "Premium_LRS": "Premium SSD",
    "StandardSSD_LRS": "Standard SSD",
    "Standard_LRS": "Standard HDD",
    "UltraSSD_LRS": "Ultra SSD",
    "Premium_ZRS": "Premium SSD (ZRS)",
    "StandardSSD_ZRS": "Standard SSD (ZRS)",
}


def _normalise_sku(sku: str) -> str:
    """Return a human-readable label for a disk SKU string."""
    return _SKU_LABELS.get(sku, sku)

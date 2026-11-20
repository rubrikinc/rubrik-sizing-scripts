"""Azure Backup Posture collector for Rubrik Discovery.

This is the core of the Rubrik value conversation.  It surfaces:

* Every Recovery Services Vault — name, location, redundancy (LRS/GRS/ZRS).
* Every backup policy — workload type, schedule, full retention ladder.
* Every protected item — resource, vault, policy, last backup time/status.
* The **protection gap** — unprotected VMs cross-referenced against the
  VM list produced by ``collectors/compute.py``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from cloud import DEFAULT_CLOUD, CloudEnvironment

from collectors.utils import (
    TagSummary,
    build_tag_summary,
    enum_text,
    parse_resource_group,
    parse_resource_name,
)

logger = logging.getLogger(__name__)


def rest_payload(props: object) -> dict:
    """The REST (camelCase) form of an SDK model's ``properties``, or ``{}`` when it has none.

    The SDK's models serialise with ``as_dict()``; anything else (a test double, ``None``) gives an
    empty dict so a collector never fails on a payload it cannot read.
    """
    as_dict = getattr(props, "as_dict", None)
    if not callable(as_dict):
        return {}
    try:
        payload = as_dict()
    except Exception as exc:  # noqa: BLE001 - best effort, the typed fields still work
        logger.debug("Could not read the REST payload of %s: %s", type(props).__name__, exc)
        return {}
    return payload if isinstance(payload, dict) else {}


#: Azure backup management type → human-readable workload label.
_WORKLOAD_TYPE_MAP: dict[str, str] = {
    "AzureIaasVM": "VM",
    "AzureWorkload": "SQL",
    "AzureStorage": "Files",
    "MAB": "On-Premises",
    "DPM": "DPM",
}

#: Azure storage-type string → normalised redundancy label.
_REDUNDANCY_MAP: dict[str, str] = {
    "LocallyRedundant": "LRS",
    "GeoRedundant": "GRS",
    "ZoneRedundant": "ZRS",
    "ReadAccessGeoZoneRedundant": "RA-GZRS",
    "GeoZoneRedundant": "GZRS",
}

#: Protection states that should be treated as *not* protected.
_INACTIVE_PROTECTION_STATES = frozenset(
    {"ProtectionStopped", "ProtectionError", "IRPending", "Invalid", "Deleting"}
)


@dataclass
class VaultInfo:
    """Information about a single Recovery Services Vault."""

    name: str
    resource_id: str
    resource_group: str
    subscription_id: str
    location: str
    redundancy: str  # LRS / GRS / ZRS / RA-GZRS / Unknown
    tags: dict[str, str]
    # Vault properties PowerShell writes in azure_backup_vault_info.
    type: str = ""
    provisioning_state: Optional[str] = None
    cross_subscription_restore_state: Optional[str] = None
    # None: the vault reports no immutability settings. "": it does, with no state.
    immutability_state: Optional[str] = None


@dataclass
class BackupPolicy:
    """Information about a single backup policy within a vault."""

    name: str
    resource_id: str
    vault_name: str
    resource_group: str
    subscription_id: str
    workload_type: str  # VM / SQL / Files / etc.
    schedule_frequency: Optional[str]  # Daily / Weekly / Hourly
    schedule_time: Optional[str]  # ISO 8601 string of the first scheduled run time
    daily_retention_days: Optional[int]
    weekly_retention_weeks: Optional[int]
    monthly_retention_months: Optional[int]
    yearly_retention_years: Optional[int]
    # The policy's REST ``properties`` as the API returned them (camelCase keys). The
    # ``azure_backup_vault_*_policies`` files are built from them, as
    # ``Get-AzRecoveryServicesBackupProtectionPolicy`` shows a policy. Empty when unavailable.
    rest_properties: dict = field(default_factory=dict)


@dataclass
class ProtectedItem:
    """A single resource currently (or formerly) protected by Azure Backup."""

    name: str
    resource_id: str
    resource_type: str  # SDK model class name, e.g. AzureIaaSVMProtectedItem
    workload_type: str  # VM / SQL / Files / etc.
    vault_name: str
    resource_group: str
    subscription_id: str
    policy_name: Optional[str]
    policy_id: Optional[str]
    last_backup_status: Optional[str]  # Completed / Failed / IRPending / etc.
    last_backup_time: Optional[str]  # ISO 8601
    protection_state: str  # Protected / ProtectionStopped / etc.
    source_resource_id: Optional[str]  # ARM ID of the protected resource (e.g. the VM)
    friendly_name: Optional[str] = None  # an Azure Files item's share name
    # The item's REST ``properties`` as the API returned them (camelCase keys). The
    # ``azure_backup_vault_*_items`` files are built from them, as ``Get-AzRecoveryServicesBackupItem``
    # shows an item. Empty when unavailable.
    rest_properties: dict = field(default_factory=dict)


@dataclass
class BackupPostureInventory:
    """Full backup posture snapshot for a single subscription."""

    subscription_id: str

    vaults: list[VaultInfo] = field(default_factory=list)
    policies: list[BackupPolicy] = field(default_factory=list)
    protected_items: list[ProtectedItem] = field(default_factory=list)

    # Protection gap (populated when vm_resource_ids are supplied)
    unprotected_vms: list[str] = field(
        default_factory=list
    )  # lowercase ARM IDs; no protection at all
    unprotected_vm_count: int = 0
    total_vm_count: int = 0
    protection_coverage_pct: float = 0.0

    # VMs whose only protection is an ad-hoc/manual disk snapshot — no vault policy.
    # Populated when vm_snapshot_ids are supplied to the collector.
    snapshot_only_vms: list[str] = field(default_factory=list)  # lowercase ARM IDs
    snapshot_only_vm_count: int = 0
    vault_protected_vm_count: int = 0

    # Roll-ups
    vault_count: int = 0
    redundancy_breakdown: dict[str, int] = field(default_factory=dict)
    protected_item_count: int = 0
    policy_count: int = 0
    workload_breakdown: dict[str, int] = field(default_factory=dict)

    tag_summary: Optional[TagSummary] = None


class BackupPostureCollector:
    """Collects Azure Backup posture data for one subscription.

    Gathers Recovery Services Vaults, backup policies, and protected items,
    then derives the VM protection gap by cross-referencing against the VM
    list produced by ``ComputeCollector``.

    Credentials are always injected — never instantiated inside this class.
    """

    def __init__(
        self,
        subscription_id: str,
        credential: DefaultAzureCredential,
        regions: Optional[list[str]] = None,
        vm_resource_ids: Optional[list[str]] = None,
        vm_snapshot_ids: Optional[list[str]] = None,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
    ) -> None:
        """
        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Validated credential injected from ``auth.get_credential()``.
            regions: Normalised region names to include, or None for all.
            vm_resource_ids: ARM resource IDs of all VMs in this subscription
                (from ``ComputeCollector``).  Required for protection gap analysis;
                if omitted the gap fields are left at their zero defaults.
            vm_snapshot_ids: ARM resource IDs of VMs with at least one ad-hoc disk
                snapshot (``ComputeCollector.VMInfo.has_adhoc_snapshot``). Used to
                split the protection gap into vault-protected / snapshot-only /
                truly-unprotected; omitted VMs are treated as having no snapshot.
            cloud: Target Azure cloud (public vs. sovereign); drives ARM endpoint + token scope.
        """
        self._sub_id = subscription_id
        self._regions: Optional[frozenset[str]] = frozenset(regions) if regions else None
        # Lower-case once here; all comparisons stay lower-case throughout.
        self._vm_resource_ids: list[str] = [r.lower() for r in (vm_resource_ids or [])]
        self._vm_snapshot_ids: set[str] = {r.lower() for r in (vm_snapshot_ids or [])}

        self._rs_client = RecoveryServicesClient(
            credential, subscription_id, **cloud.client_kwargs()
        )
        self._backup_client = RecoveryServicesBackupClient(
            credential, subscription_id, **cloud.client_kwargs()
        )

    def collect(self) -> BackupPostureInventory:
        """Run the full backup posture collection pass for this subscription.

        Returns:
            Populated BackupPostureInventory dataclass.
        """
        logger.debug("[%s] Starting backup posture collection", self._sub_id)

        inventory = BackupPostureInventory(subscription_id=self._sub_id)

        # 1. Vaults — one API call for the whole subscription.
        vaults = self._list_vaults()
        inventory.vaults = vaults
        inventory.vault_count = len(vaults)
        inventory.tag_summary = build_tag_summary([v.tags for v in vaults])

        for vault in vaults:
            r = vault.redundancy
            inventory.redundancy_breakdown[r] = inventory.redundancy_breakdown.get(r, 0) + 1

        # 2. Policies + protected items — one pass per vault.
        all_policies: list[BackupPolicy] = []
        all_items: list[ProtectedItem] = []

        for vault in vaults:
            all_policies.extend(self._list_policies(vault))
            all_items.extend(self._list_protected_items(vault))

        inventory.policies = all_policies
        inventory.policy_count = len(all_policies)
        inventory.protected_items = all_items
        inventory.protected_item_count = len(all_items)

        for item in all_items:
            wt = item.workload_type
            inventory.workload_breakdown[wt] = inventory.workload_breakdown.get(wt, 0) + 1

        # 3. Protection gap.
        if self._vm_resource_ids:
            self._compute_protection_gap(inventory)

        logger.debug(
            "[%s] Backup posture complete: %d vaults, %d policies, %d protected items, "
            "%.1f%% VM coverage",
            self._sub_id,
            inventory.vault_count,
            inventory.policy_count,
            inventory.protected_item_count,
            inventory.protection_coverage_pct,
        )
        return inventory

    def _list_vaults(self) -> list[VaultInfo]:
        """Enumerate all Recovery Services Vaults in the subscription."""
        vaults: list[VaultInfo] = []

        try:
            for vault in self._rs_client.vaults.list_by_subscription_id():
                try:
                    location = (vault.location or "").lower()
                    if self._regions and location not in self._regions:
                        continue

                    rg = parse_resource_group(vault.id or "")
                    redundancy = self._get_vault_redundancy(vault.name or "", rg)
                    props = getattr(vault, "properties", None)
                    restore = getattr(
                        getattr(props, "restore_settings", None),
                        "cross_subscription_restore_settings",
                        None,
                    )
                    immutability = getattr(
                        getattr(props, "security_settings", None), "immutability_settings", None
                    )

                    vaults.append(
                        VaultInfo(
                            name=vault.name or "",
                            resource_id=vault.id or "",
                            resource_group=rg,
                            subscription_id=self._sub_id,
                            location=location,
                            redundancy=redundancy,
                            tags=dict(vault.tags) if vault.tags else {},
                            type=getattr(vault, "type", None) or "",
                            provisioning_state=enum_text(getattr(props, "provisioning_state", None)),
                            cross_subscription_restore_state=enum_text(
                                getattr(restore, "cross_subscription_restore_state", None)
                            ),
                            immutability_state=(
                                None
                                if immutability is None
                                else enum_text(getattr(immutability, "state", None)) or ""
                            ),
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping vault %s: %s",
                        self._sub_id,
                        getattr(vault, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning("[%s] Failed to list vaults: %s", self._sub_id, exc)

        return vaults

    def _get_vault_redundancy(self, vault_name: str, resource_group: str) -> str:
        """Fetch the backup storage redundancy setting for one vault.

        Returns ``"Unknown"`` on any API error so the rest of the run is
        never blocked by a missing storage-config permission.
        """
        try:
            config = self._backup_client.backup_resource_storage_configs_non_crr.get(
                vault_name, resource_group
            )
            raw: str = getattr(getattr(config, "properties", None), "storage_type", None) or ""
            return _REDUNDANCY_MAP.get(raw, raw or "Unknown")
        except Exception as exc:
            logger.warning(
                "[%s] Could not fetch storage config for vault %s: %s",
                self._sub_id,
                vault_name,
                exc,
            )
            return "Unknown"

    def _list_policies(self, vault: VaultInfo) -> list[BackupPolicy]:
        """List all backup policies for a given vault."""
        policies: list[BackupPolicy] = []

        try:
            for policy in self._backup_client.backup_policies.list(
                vault.name, vault.resource_group
            ):
                try:
                    props = getattr(policy, "properties", None)
                    if props is None:
                        continue

                    bmt: str = enum_text(getattr(props, "backup_management_type", None)) or ""
                    workload_type = _WORKLOAD_TYPE_MAP.get(bmt, bmt or "Unknown")

                    sched_freq, sched_time = _extract_schedule(props)
                    daily, weekly, monthly, yearly = _extract_retention(props)

                    policies.append(
                        BackupPolicy(
                            name=policy.name or "",
                            resource_id=policy.id or "",
                            vault_name=vault.name,
                            resource_group=vault.resource_group,
                            subscription_id=self._sub_id,
                            workload_type=workload_type,
                            schedule_frequency=sched_freq,
                            schedule_time=sched_time,
                            daily_retention_days=daily,
                            weekly_retention_weeks=weekly,
                            monthly_retention_months=monthly,
                            yearly_retention_years=yearly,
                            rest_properties=rest_payload(props),
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping policy %s in vault %s: %s",
                        self._sub_id,
                        getattr(policy, "name", "?"),
                        vault.name,
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning(
                "[%s] Failed to list policies for vault %s: %s",
                self._sub_id,
                vault.name,
                exc,
            )

        return policies

    def _list_protected_items(self, vault: VaultInfo) -> list[ProtectedItem]:
        """List all protected items for a given vault."""
        items: list[ProtectedItem] = []

        try:
            for item in self._backup_client.backup_protected_items.list(
                vault.name, vault.resource_group
            ):
                try:
                    props = getattr(item, "properties", None)
                    if props is None:
                        continue

                    bmt: str = enum_text(getattr(props, "backup_management_type", None)) or ""
                    workload_type = _WORKLOAD_TYPE_MAP.get(bmt, bmt or "Unknown")

                    policy_id: Optional[str] = getattr(props, "policy_id", None)
                    policy_name = parse_resource_name(policy_id) if policy_id else None

                    # The API sends a VM item's discriminator as "Microsoft.Compute/virtualMachines",
                    # which the SDK does not map to AzureIaaSVMProtectedItem, so it builds the base
                    # ProtectedItem: the VM-only fields are then only in the REST payload.
                    rest = rest_payload(props)

                    # The ARM ID of the underlying protected resource (e.g. the VM).
                    # Field name varies by item type — check both common aliases.
                    source_resource_id: Optional[str] = (
                        getattr(props, "source_resource_id", None)
                        or getattr(props, "virtual_machine_id", None)
                        or rest.get("virtualMachineId")
                    )

                    last_backup_time_raw = getattr(props, "last_backup_time", None) or rest.get(
                        "lastBackupTime"
                    )
                    last_backup_time: Optional[str] = (
                        last_backup_time_raw.isoformat()
                        if isinstance(last_backup_time_raw, datetime)
                        else (str(last_backup_time_raw) if last_backup_time_raw else None)
                    )

                    protection_state = (
                        enum_text(getattr(props, "protection_state", None))
                        or rest.get("protectionState")
                        or "Unknown"
                    )

                    items.append(
                        ProtectedItem(
                            name=item.name or "",
                            resource_id=item.id or "",
                            resource_type=type(props).__name__,
                            workload_type=workload_type,
                            vault_name=vault.name,
                            resource_group=vault.resource_group,
                            subscription_id=self._sub_id,
                            policy_name=policy_name,
                            policy_id=policy_id,
                            last_backup_status=enum_text(getattr(props, "last_backup_status", None))
                            or rest.get("lastBackupStatus"),
                            last_backup_time=last_backup_time,
                            protection_state=protection_state,
                            source_resource_id=source_resource_id,
                            friendly_name=(
                                getattr(props, "friendly_name", None)
                                if workload_type == "Files"
                                else None
                            ),
                            rest_properties=rest,
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping protected item %s in vault %s: %s",
                        self._sub_id,
                        getattr(item, "name", "?"),
                        vault.name,
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning(
                "[%s] Failed to list protected items for vault %s: %s",
                self._sub_id,
                vault.name,
                exc,
            )

        return items

    def _compute_protection_gap(self, inventory: BackupPostureInventory) -> None:
        """Derive the VM protection gap and populate gap fields in-place.

        A VM is considered **vault-protected** when it has at least one protected
        item with workload_type ``"VM"`` whose ``protection_state`` is not in
        ``_INACTIVE_PROTECTION_STATES``. Of the remainder, a VM with an ad-hoc
        disk snapshot (``vm_snapshot_ids``) is **snapshot-only** protected —
        still a real gap for policy/retention purposes, but not the same as
        having zero copies to recover from. Everything else is **unprotected**.

        Args:
            inventory: The BackupPostureInventory being built; mutated in-place.
        """
        # Build the set of actively-protected VM resource IDs (lower-case).
        protected_vm_ids: set[str] = set()
        for item in inventory.protected_items:
            if item.workload_type != "VM":
                continue
            if item.protection_state in _INACTIVE_PROTECTION_STATES:
                continue
            if item.source_resource_id:
                protected_vm_ids.add(item.source_resource_id.lower())

        all_vm_ids = set(self._vm_resource_ids)
        vault_protected = all_vm_ids & protected_vm_ids
        remaining = all_vm_ids - vault_protected
        snapshot_only = remaining & self._vm_snapshot_ids
        unprotected = sorted(remaining - snapshot_only)

        inventory.total_vm_count = len(all_vm_ids)
        inventory.vault_protected_vm_count = len(vault_protected)
        inventory.snapshot_only_vms = sorted(snapshot_only)
        inventory.snapshot_only_vm_count = len(snapshot_only)
        inventory.unprotected_vms = unprotected
        inventory.unprotected_vm_count = len(unprotected)

        if inventory.total_vm_count > 0:
            protected_count = inventory.total_vm_count - inventory.unprotected_vm_count
            inventory.protection_coverage_pct = round(
                protected_count / inventory.total_vm_count * 100, 1
            )
        else:
            inventory.protection_coverage_pct = 0.0


def _extract_schedule(props: object) -> tuple[Optional[str], Optional[str]]:
    """Extract schedule frequency and first run-time from a policy properties object.

    Handles both ``AzureIaaSVMProtectionPolicy`` (flat schedule) and
    ``AzureVmWorkloadProtectionPolicy`` (sub-policy list).

    Returns:
        Tuple of (frequency_string, iso_time_string); either may be None.
    """
    sched = getattr(props, "schedule_policy", None)

    if sched is None:
        # AzureVmWorkloadProtectionPolicy — schedule lives in sub_protection_policy.
        for sp in getattr(props, "sub_protection_policy", None) or []:
            sched = getattr(sp, "schedule_policy", None)
            if sched is not None:
                break

    if sched is None:
        return None, None

    frequency = getattr(sched, "schedule_run_frequency", None) or getattr(
        sched, "schedule_frequency", None
    )

    run_times = getattr(sched, "schedule_run_times", None) or []
    time_str: Optional[str] = None
    if run_times:
        t = run_times[0]
        time_str = t.isoformat() if isinstance(t, datetime) else str(t)

    return (str(frequency) if frequency else None), time_str


def _extract_retention(
    props: object,
) -> tuple[Optional[int], Optional[int], Optional[int], Optional[int]]:
    """Extract the daily / weekly / monthly / yearly retention counts from a policy.

    Works for both ``LongTermRetentionPolicy`` and ``SimpleRetentionPolicy``,
    and handles the nested sub-policy structure used for SQL workloads.

    Returns:
        ``(daily_days, weekly_weeks, monthly_months, yearly_years)`` — any
        value is None if that tier is not configured.
    """
    ret = getattr(props, "retention_policy", None)

    if ret is None:
        for sp in getattr(props, "sub_protection_policy", None) or []:
            ret = getattr(sp, "retention_policy", None)
            if ret is not None:
                break

    if ret is None:
        return None, None, None, None

    # SimpleRetentionPolicy — single count value.
    simple_count = getattr(ret, "retention_count", None)
    if simple_count is not None:
        return int(simple_count), None, None, None

    # LongTermRetentionPolicy — per-tier schedules.
    daily = _schedule_retention_count(getattr(ret, "daily_schedule", None))
    weekly = _schedule_retention_count(getattr(ret, "weekly_schedule", None))
    monthly = _schedule_retention_count(getattr(ret, "monthly_schedule", None))
    yearly = _schedule_retention_count(getattr(ret, "yearly_schedule", None))

    return daily, weekly, monthly, yearly


def _schedule_retention_count(schedule: object) -> Optional[int]:
    """Return the retention count from a tier-schedule object, or None."""
    if schedule is None:
        return None
    ret_dur = getattr(schedule, "retention_duration", None)
    if ret_dur is None:
        return None
    count = getattr(ret_dur, "count", None)
    return int(count) if count is not None else None

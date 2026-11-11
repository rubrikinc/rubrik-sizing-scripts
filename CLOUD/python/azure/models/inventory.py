"""Unified output model for Rubrik Discovery — Azure Edition.

``DiscoveryResult`` is a Pydantic model that aggregates all per-subscription
collector results into a single serialisable object.  Everything else in the
codebase uses plain dataclasses; this is the only Pydantic boundary — the
point at which data leaves the collectors and becomes JSON.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

CURRENT_SCHEMA_VERSION = "1"


def _asdict_safe(obj: Any) -> Any:
    """Recursively convert dataclasses to dicts, leaving other types unchanged.

    Handles the ``Optional[TagSummary]`` / ``Optional[str]`` fields that live
    inside the collector inventory dataclasses.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _asdict_safe(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_asdict_safe(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _asdict_safe(v) for k, v in obj.items()}
    return obj


class DiscoveryResult(BaseModel):
    """Top-level output model serialised to JSON at the end of a discovery run."""

    model_config = ConfigDict(arbitrary_types_allowed=False)

    schema_version: str = CURRENT_SCHEMA_VERSION
    tenant_id: str
    generated_at: str  # ISO 8601 UTC timestamp
    subscriptions: list[str]
    # subscription_id -> display name, best-effort (a lookup failure for one subscription
    # just omits its entry, never fails the run — see auth.resolve_subscription_names).
    # Defaults to {} so JSON from before this field existed still parses.
    subscription_names: dict[str, str] = Field(default_factory=dict)
    # Tenant display name (PowerShell's ``Tenant`` column); None when it has none or the
    # lookup failed.
    tenant_name: Optional[str] = None
    # Tag names defined in each subscription (``Get-AzTag``): subscription id -> names.
    tag_names: dict[str, list[str]] = Field(default_factory=dict)
    # Collectors the run was told to skip (PowerShell's -Skip* switches); their files are not written.
    skipped: list[str] = Field(default_factory=list)
    # The pre-flight access check: one row per service and subscription, with what was readable and
    # what the scan will therefore miss. Empty when the check was skipped (--no-preflight).
    access_check: list[dict[str, str]] = Field(default_factory=list)
    regions_in_scope: Optional[list[str]]  # None means all regions

    compute: list[dict[str, Any]]
    backup_posture: list[dict[str, Any]]
    storage: list[dict[str, Any]]
    database: list[dict[str, Any]]
    cost: list[dict[str, Any]]  # one CostSummary per subscription
    backup_jobs: list[dict[str, Any]]  # one BackupJobsInventory per subscription

    total_vms: int
    total_disk_tb: float
    total_sql_vms: int = 0  # VMs running SQL Server (IaaS); default 0 for old JSON
    total_protected_vms: int
    total_unprotected_vms: int
    protection_coverage_pct: float
    # Breakdown of total_protected_vms: vault policy vs. ad-hoc disk snapshot only.
    # Both default to 0 for old JSON that predates this split.
    total_vault_protected_vms: int = 0
    total_snapshot_only_vms: int = 0
    total_storage_accounts: int
    total_storage_gb: Optional[float]  # None if metrics unavailable across all accounts
    # Object/file counts (None = metric unavailable). Blob = cloud-native sizing; Files = NCD.
    total_blob_count: Optional[int] = None
    total_file_count: Optional[int] = None
    total_file_share_count: Optional[int] = None
    total_sql_databases: int
    total_sql_mi_instances: int = 0  # default 0 for backward compat with old JSON
    total_sql_mi_storage_tb: float = 0.0
    total_flexible_servers: int = 0
    total_6mo_spend: float  # sum of all CostSummary.total_6mo_spend
    total_completed_months: int = 0  # completed full months represented in total_6mo_spend
    total_backup_6mo_spend: float = 0.0  # subset attributed to backup-related services
    total_other_6mo_spend: float = 0.0  # everything else (workloads, storage, DB, …)
    total_backup_jobs: int  # sum across all subscriptions
    overall_backup_success_rate: Optional[float]  # None if no job data

    # Azure Retail Prices API — actual on-demand compute costs
    total_monthly_compute_cost: Optional[float]  # None if pricing unavailable
    total_monthly_unprotected_compute_cost: Optional[float]  # None if pricing unavailable

    # Optional parity-SDK signals — populated only when their packages
    # are installed AND the customer identity
    # has the relevant RBAC.  Zero means "not detected" (either the SDK
    # isn't installed, the identity lacks permission, or the feature
    # genuinely isn't configured).
    total_defender_plans_standard: int = 0
    total_defender_plans_free: int = 0
    defender_servers_tier: str = "None"  # "P2" | "P1" | "Standard" | "Free" | "None"
    total_purview_accounts: int = 0
    total_asr_protected_items: int = 0

    # AKS clusters and Cosmos DB accounts, one entry per subscription (empty before these were
    # collected, so old JSON still loads).
    aks: list[dict[str, Any]] = Field(default_factory=list)
    cosmos_db: list[dict[str, Any]] = Field(default_factory=list)
    # Backup Vaults (Blob and PostgreSQL backup), one entry per subscription. None when they were not
    # collected: the run skipped backup, or azure-mgmt-dataprotection is not installed.
    data_protection: Optional[list[dict[str, Any]]] = None
    # Key Vaults with their certificate, secret and key counts (--get-key-vault-amounts), and blob
    # containers with their per-tier sums (--get-container-details), one entry per subscription.
    # None when the option was not given.
    key_vaults: Optional[list[dict[str, Any]]] = None
    containers: Optional[list[dict[str, Any]]] = None
    total_aks_clusters: int = 0
    total_aks_nodes: int = 0
    total_cosmos_accounts: int = 0

    # Third-party backup tool detection (Veeam, Commvault, Cohesity, etc.).
    # Populated by analysis.third_party_backup.detect() after discovery.
    # Stored as plain dicts in the JSON so the schema is forward-compatible
    # with future vendor additions without a DiscoveryResult migration.
    third_party_backup: dict = Field(default_factory=dict)

    # Azure DevOps inventory — populated when the identity has DevOps access.
    devops: dict = Field(default_factory=dict)

    def to_json(self, indent: int = 2) -> str:
        """Serialise the result to a formatted JSON string."""
        return self.model_dump_json(indent=indent)

    @classmethod
    def build(
        cls,
        *,
        tenant_id: str,
        subscriptions: list[str],
        regions_in_scope: Optional[list[str]],
        subscription_names: Optional[dict[str, str]] = None,
        tenant_name: Optional[str] = None,
        tag_names: Optional[dict[str, list[str]]] = None,
        skipped: Optional[list[str]] = None,
        access_check: Optional[list[dict]] = None,
        compute_results: list,  # list[ComputeInventory]
        bp_results: list,  # list[BackupPostureInventory]
        storage_results: list,  # list[StorageInventory]
        database_results: list,  # list[DatabaseInventory]
        cost_results: Optional[list] = None,  # list[CostSummary]
        job_results: Optional[list] = None,  # list[BackupJobsInventory]
        aks_results: Optional[list] = None,  # list[AksInventory]
        cosmos_results: Optional[list] = None,  # list[CosmosInventory]
        data_protection_results: Optional[list] = None,  # list[DataProtectionInventory]
        key_vault_results: Optional[list] = None,  # list[KeyVaultInventory]
        container_results: Optional[list] = None,  # list[ContainerInventory]
        total_monthly_compute_cost: Optional[float] = None,
        total_monthly_unprotected_compute_cost: Optional[float] = None,
        defender_results: Optional[list] = None,  # list[DefenderInventory]
        purview_results: Optional[list] = None,  # list[PurviewInventory]
        asr_results: Optional[list] = None,  # list[SiteRecoveryInventory]
    ) -> "DiscoveryResult":
        """Aggregate per-subscription collector results into a single model.

        Args:
            tenant_id: Azure tenant ID (from the credential or subscription).
            subscriptions: Subscription IDs that were scanned.
            regions_in_scope: Normalised region filter, or None for all.
            compute_results: One ``ComputeInventory`` per subscription.
            bp_results: One ``BackupPostureInventory`` per subscription.
            storage_results: One ``StorageInventory`` per subscription.
            database_results: One ``DatabaseInventory`` per subscription.
            cost_results: One ``CostSummary`` per subscription (optional).
            job_results: One ``BackupJobsInventory`` per subscription (optional).

        Returns:
            Populated ``DiscoveryResult`` ready for serialisation.
        """
        total_vms = sum(c.total_vms for c in compute_results)
        total_disk_tb = round(sum(c.total_disk_tb for c in compute_results), 3)
        total_sql_vms = sum(getattr(c, "total_sql_vms", 0) or 0 for c in compute_results)

        total_protected = sum((bp.total_vm_count - bp.unprotected_vm_count) for bp in bp_results)
        total_unprotected = sum(bp.unprotected_vm_count for bp in bp_results)
        coverage_pct = round(total_protected / total_vms * 100, 1) if total_vms > 0 else 0.0
        total_vault_protected = sum(
            getattr(bp, "vault_protected_vm_count", 0) or 0 for bp in bp_results
        )
        total_snapshot_only = sum(
            getattr(bp, "snapshot_only_vm_count", 0) or 0 for bp in bp_results
        )

        total_storage_accounts = sum(s.total_accounts for s in storage_results)
        gb_values = [
            s.total_capacity_gb for s in storage_results if s.total_capacity_gb is not None
        ]
        total_storage_gb = round(sum(gb_values), 3) if gb_values else None

        # Object/file counts — Blob (cloud-native) vs Files (NCD) kept separate. None when
        # no subscription reported that metric (so the report can show "—" vs a real 0).
        def _sum_opt(attr: str) -> Optional[int]:
            vals = [getattr(s, attr) for s in storage_results if getattr(s, attr, None) is not None]
            return sum(vals) if vals else None

        total_blob_count = _sum_opt("total_blob_count")
        total_file_count = _sum_opt("total_file_count")
        total_file_share_count = _sum_opt("total_file_share_count")

        total_sql_databases = sum(d.total_sql_databases for d in database_results)
        total_flexible_servers = sum(d.total_flexible_servers for d in database_results)
        total_sql_mi_instances = sum(
            getattr(d, "total_sql_mi_instances", 0) or 0 for d in database_results
        )
        total_sql_mi_storage_gb = sum(
            getattr(d, "total_sql_mi_storage_gb", 0) or 0 for d in database_results
        )
        total_sql_mi_storage_tb = round(total_sql_mi_storage_gb / 1024.0, 3)

        # Cost roll-ups
        cost_list = cost_results or []
        total_6mo_spend = round(sum(getattr(c, "total_6mo_spend", 0) or 0 for c in cost_list), 2)
        total_backup_6mo_spend = round(
            sum(getattr(c, "backup_6mo_spend", 0) or 0 for c in cost_list), 2
        )
        total_other_6mo_spend = round(
            sum(getattr(c, "other_6mo_spend", 0) or 0 for c in cost_list), 2
        )

        # Completed months: use the maximum any subscription observed — that
        # represents the most complete picture for annualisation purposes.
        # (Subscriptions with missing months would otherwise pull this down.)
        completed_counts = [getattr(c, "completed_months_count", 0) or 0 for c in cost_list]
        total_completed_months = max(completed_counts) if completed_counts else 0

        # Parity-SDK roll-ups (optional extras)
        defender_list = defender_results or []
        total_defender_standard = sum(
            getattr(d, "total_plans_standard", 0) or 0 for d in defender_list
        )
        total_defender_free = sum(getattr(d, "total_plans_free", 0) or 0 for d in defender_list)
        # Use the highest tier observed across subscriptions — if any sub
        # has P2, it counts as the tenant's ceiling for the parity matrix.
        _tier_rank = {"None": 0, "Free": 1, "Standard": 2, "P1": 3, "P2": 4}
        defender_servers_tier = "None"
        best_rank = 0
        for d in defender_list:
            t = getattr(d, "defender_servers_tier", "None") or "None"
            if _tier_rank.get(t, 0) > best_rank:
                defender_servers_tier = t
                best_rank = _tier_rank.get(t, 0)
        purview_list = purview_results or []
        total_purview = sum(getattr(p, "total_accounts", 0) or 0 for p in purview_list)
        asr_list = asr_results or []
        total_asr = sum(getattr(a, "total_protected_items", 0) or 0 for a in asr_list)

        # Backup job roll-ups
        job_list = job_results or []
        total_backup_jobs = sum(getattr(j, "total_jobs", 0) or 0 for j in job_list)
        job_success_pairs = [
            (getattr(j, "successful_jobs", 0), getattr(j, "total_jobs", 0))
            for j in job_list
            if (getattr(j, "total_jobs", 0) or 0) > 0
        ]
        if job_success_pairs:
            overall_backup_success_rate = round(
                sum(s for s, _ in job_success_pairs) / sum(t for _, t in job_success_pairs) * 100, 1
            )
        else:
            overall_backup_success_rate = None

        return cls(
            tenant_id=tenant_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            subscriptions=subscriptions,
            subscription_names=subscription_names or {},
            tenant_name=tenant_name,
            tag_names=tag_names or {},
            skipped=sorted(skipped or []),
            access_check=access_check or [],
            regions_in_scope=regions_in_scope,
            compute=[_asdict_safe(c) for c in compute_results],
            backup_posture=[_asdict_safe(bp) for bp in bp_results],
            storage=[_asdict_safe(s) for s in storage_results],
            database=[_asdict_safe(d) for d in database_results],
            cost=[_asdict_safe(c) for c in cost_list],
            backup_jobs=[_asdict_safe(j) for j in job_list],
            aks=[_asdict_safe(a) for a in aks_results or []],
            cosmos_db=[_asdict_safe(c) for c in cosmos_results or []],
            data_protection=(
                None
                if data_protection_results is None
                else [_asdict_safe(d) for d in data_protection_results]
            ),
            key_vaults=(
                None if key_vault_results is None else [_asdict_safe(k) for k in key_vault_results]
            ),
            containers=(
                None if container_results is None else [_asdict_safe(c) for c in container_results]
            ),
            total_aks_clusters=sum(getattr(a, "total_clusters", 0) for a in aks_results or []),
            total_aks_nodes=sum(getattr(a, "total_nodes", 0) for a in aks_results or []),
            total_cosmos_accounts=sum(
                getattr(c, "total_accounts", 0) for c in cosmos_results or []
            ),
            total_vms=total_vms,
            total_disk_tb=total_disk_tb,
            total_sql_vms=total_sql_vms,
            total_protected_vms=total_protected,
            total_unprotected_vms=total_unprotected,
            protection_coverage_pct=coverage_pct,
            total_vault_protected_vms=total_vault_protected,
            total_snapshot_only_vms=total_snapshot_only,
            total_storage_accounts=total_storage_accounts,
            total_storage_gb=total_storage_gb,
            total_blob_count=total_blob_count,
            total_file_count=total_file_count,
            total_file_share_count=total_file_share_count,
            total_sql_databases=total_sql_databases,
            total_sql_mi_instances=total_sql_mi_instances,
            total_sql_mi_storage_tb=total_sql_mi_storage_tb,
            total_flexible_servers=total_flexible_servers,
            total_6mo_spend=total_6mo_spend,
            total_completed_months=total_completed_months,
            total_backup_6mo_spend=total_backup_6mo_spend,
            total_other_6mo_spend=total_other_6mo_spend,
            total_backup_jobs=total_backup_jobs,
            overall_backup_success_rate=overall_backup_success_rate,
            total_monthly_compute_cost=total_monthly_compute_cost,
            total_monthly_unprotected_compute_cost=total_monthly_unprotected_compute_cost,
            total_defender_plans_standard=total_defender_standard,
            total_defender_plans_free=total_defender_free,
            defender_servers_tier=defender_servers_tier,
            total_purview_accounts=total_purview,
            total_asr_protected_items=total_asr,
        )

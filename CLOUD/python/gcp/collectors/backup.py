"""Backup and DR posture collector for Rubrik Discovery — GCP Edition.

Collects backup plan associations and performs protection gap analysis by
cross-referencing GCE instances against Backup and DR protected workloads.
The protection gap (unprotected instances) is the headline Rubrik value insight.
"""

from __future__ import annotations

import logging
from typing import Optional

from models.inventory import (
    BackupPlan,
    BackupPlanAssociation,
    BackupPostureInventory,
)

from collectors.utils import brief_error, collection_error

logger = logging.getLogger(__name__)

# States that mean "this resource is actively protected"
_ACTIVE_STATES = {"ACTIVE", "READY"}


class BackupCollector:
    """Collect Backup and DR posture for a GCP project.

    Performs protection gap analysis: compares the full list of GCE instance
    names against the set of resources covered by Backup and DR associations.

    Credential injection rule: always receive credentials from ``main.py``.
    """

    def __init__(
        self,
        project_id: str,
        credentials,
        gce_instance_names: Optional[list[str]] = None,
        regions: Optional[list[str]] = None,
    ) -> None:
        """
        Args:
            project_id: GCP project ID.
            credentials: Authenticated google.auth Credentials instance.
            gce_instance_names: Full list of GCE instance names from
                ComputeCollector — used for protection gap analysis.
            regions: Optional list of regions to scope the backup vault search.
        """
        self._project_id = project_id
        self._credentials = credentials
        self._gce_instance_names: list[str] = gce_instance_names or []
        self._regions = regions
        self.errors: list[dict] = []
        self._associations_failed = False

    def collect(self) -> BackupPostureInventory:
        """Collect Backup and DR backup plans and associations.

        Returns:
            BackupPostureInventory. On permission error or API not enabled,
            returns an empty inventory with the full VM list marked unprotected.
        """
        try:
            from google.cloud import backupdr_v1  # deferred import
        except Exception as exc:
            logger.warning(
                "Backup and DR SDK not available for project %s: %s — skipping",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("backup", exc))
            return self._empty_with_gap()

        try:
            backup_plans = self._collect_plans(backupdr_v1)
            associations = self._collect_associations(backupdr_v1)
        except Exception as exc:
            logger.warning(
                "Backup and DR collection failed for project %s: %s "
                "(check roles/backupdr.viewer is granted and Backup and DR API is enabled)",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("backup", exc))
            return self._empty_with_gap()

        self._drop_repeated_errors()
        return self._build_inventory(backup_plans, associations)

    def _drop_repeated_errors(self) -> None:
        """One record per cause: a disabled API fails the plan and the association listing alike."""
        seen: set[tuple] = set()
        unique = []
        for error in self.errors:
            key = (error["collector"], error["category"], error["message"])
            if key not in seen:
                seen.add(key)
                unique.append(error)
        self.errors = unique

    # ── Plan collection ───────────────────────────────────────────────────────

    def _collect_plans(self, backupdr_v1) -> list[BackupPlan]:
        client = backupdr_v1.BackupDRClient(credentials=self._credentials)
        parent = f"projects/{self._project_id}/locations/-"
        plans: list[BackupPlan] = []

        try:
            from collectors.retry import retry_call

            plan_objs = retry_call(
                lambda: list(client.list_backup_plans(parent=parent)),
                description=f"list_backup_plans({self._project_id})",
            )
            for plan in plan_objs:
                plans.append(self._parse_plan(plan))
        except Exception as exc:
            logger.debug("Backup plan listing failed for project %s: %s", self._project_id, exc)
            self.errors.append(collection_error("backup", exc))

        logger.debug("Project %s: %d backup plans", self._project_id, len(plans))
        return plans

    @staticmethod
    def _parse_plan(plan) -> BackupPlan:
        name = plan.name.split("/")[-1] if plan.name else ""
        resource_type = ""
        rpo_hours: Optional[int] = None
        retention_days: Optional[int] = None

        try:
            resource_type = plan.resource_type or ""
        except Exception:
            pass

        try:
            # backup_rules is a repeated field; take the first rule's RPO/retention
            if plan.backup_rules:
                rule = plan.backup_rules[0]
                rpo_hours = getattr(rule, "rpo_config", None)
                if rpo_hours and hasattr(rpo_hours, "target_rpo_minutes"):
                    rpo_hours = rpo_hours.target_rpo_minutes // 60 or None
                else:
                    rpo_hours = None
                retention_days = getattr(rule, "backup_retention_days", None)
        except Exception:
            pass

        vault = ""
        try:
            vault = plan.backup_vault.split("/")[-1] if plan.backup_vault else ""
        except Exception:
            pass

        return BackupPlan(
            name=name,
            resource_type=resource_type,
            backup_vault=vault,
            rpo_hours=rpo_hours,
            retention_days=retention_days,
        )

    # ── Association collection ────────────────────────────────────────────────

    def _collect_associations(self, backupdr_v1) -> list[BackupPlanAssociation]:
        client = backupdr_v1.BackupDRClient(credentials=self._credentials)
        parent = f"projects/{self._project_id}/locations/-"
        associations: list[BackupPlanAssociation] = []

        try:
            from collectors.retry import retry_call

            assoc_objs = retry_call(
                lambda: list(client.list_backup_plan_associations(parent=parent)),
                description=f"list_backup_plan_associations({self._project_id})",
            )
            for assoc in assoc_objs:
                associations.append(self._parse_association(assoc))
        except Exception as exc:
            logger.debug(
                "Backup association listing failed for project %s: %s",
                self._project_id,
                exc,
            )
            self.errors.append(collection_error("backup", exc))
            self._associations_failed = True

        logger.debug(
            "Project %s: %d backup plan associations",
            self._project_id,
            len(associations),
        )
        return associations

    @staticmethod
    def _parse_association(assoc) -> BackupPlanAssociation:
        name = assoc.name.split("/")[-1] if assoc.name else ""
        resource = getattr(assoc, "resource", "") or ""
        resource_type = getattr(assoc, "resource_type", "") or ""
        backup_plan = ""
        try:
            backup_plan = assoc.backup_plan.split("/")[-1] if assoc.backup_plan else ""
        except Exception:
            pass
        state = "UNKNOWN"
        try:
            state = assoc.state.name if assoc.state else "UNKNOWN"
        except Exception:
            pass

        last_backup_time = None
        try:
            if assoc.last_successful_backup_consistency_time:
                last_backup_time = assoc.last_successful_backup_consistency_time.isoformat()
        except Exception:
            pass

        last_backup_error = None
        try:
            if assoc.last_backup_error and assoc.last_backup_error.message:
                last_backup_error = assoc.last_backup_error.message
        except Exception:
            pass

        return BackupPlanAssociation(
            name=name,
            resource=resource,
            resource_type=resource_type,
            backup_plan=backup_plan,
            state=state,
            last_backup_time=last_backup_time,
            last_backup_error=last_backup_error,
        )

    # ── Roll-up + gap analysis ────────────────────────────────────────────────

    def _build_inventory(
        self,
        backup_plans: list[BackupPlan],
        associations: list[BackupPlanAssociation],
    ) -> BackupPostureInventory:
        # Build the set of actively protected resource leaf-names.
        protected_names: set[str] = set()
        for assoc in associations:
            if assoc.state in _ACTIVE_STATES:
                # resource is a full name; extract leaf.
                leaf = assoc.resource.split("/")[-1] if assoc.resource else ""
                if leaf:
                    protected_names.add(leaf)

        # Gap analysis: which GCE instances have no active protection?
        unprotected = [name for name in self._gce_instance_names if name not in protected_names]
        total_vms = len(self._gce_instance_names)
        protected_count = total_vms - len(unprotected)
        coverage_pct = round(protected_count / total_vms * 100, 1) if total_vms else 0.0

        logger.debug(
            "Project %s: %d/%d GCE instances protected (%.1f%%)",
            self._project_id,
            protected_count,
            total_vms,
            coverage_pct,
        )

        return BackupPostureInventory(
            project_id=self._project_id,
            backup_plans=backup_plans,
            associations=associations,
            total_associations=len(associations),
            protected_instance_count=protected_count,
            unprotected_instance_count=len(unprotected),
            unprotected_instances=unprotected,
            protection_coverage_pct=coverage_pct,
            available=not self._associations_failed,
        )

    def _empty_with_gap(self) -> BackupPostureInventory:
        """Return an empty inventory treating all known VMs as unprotected (and marked unavailable)."""
        total_vms = len(self._gce_instance_names)
        return BackupPostureInventory(
            project_id=self._project_id,
            unprotected_instance_count=total_vms,
            unprotected_instances=list(self._gce_instance_names),
            protection_coverage_pct=0.0,
            available=False,
        )

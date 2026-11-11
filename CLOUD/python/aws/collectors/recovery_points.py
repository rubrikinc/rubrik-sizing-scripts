"""AWS Backup recovery points. Port of ``Get-AWSBackupRecoveryPointInventory``.

Every COMPLETED recovery point of every vault in the region becomes a row of
``aws_backup_recovery_points``; per resource, the count and the latest recovery point's date
and size feed the backup columns of the workload rows.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime
from typing import Optional

from models.discovery import RecoveryPointAggregate, RecoveryPointRow

from collectors import DenialTracker, record_metric_failures
from collectors.context import recovery_point_timeout_minutes
from collectors.snapshots import _iso

log = logging.getLogger(__name__)

_DENIED = re.compile(r"AccessDenied|UnauthorizedOperation|AuthFailure")


def is_access_denied(exc: Exception) -> bool:
    """The family of IAM denials that degrade gracefully (anything else is a real failure)."""
    response = getattr(exc, "response", None)
    code = str(response.get("Error", {}).get("Code", "")) if isinstance(response, dict) else ""
    return bool(_DENIED.search(code) or _DENIED.search(type(exc).__name__))


def resource_id_from_arn(arn: str) -> str:
    """``i-0123``, ``vol-0123`` or a bucket name out of a resource ARN; "" if there is none."""
    if not arn:
        return ""
    resource = arn.split(":", 5)[-1]
    parts = re.split(r"[/:]", resource) if re.search(r"[/:]", resource) else [resource]
    return parts[-1]


def list_plan_names(session, region: str) -> dict[str, str]:
    """Backup plan id -> name for ``region``, to name the plans recovery points came from.

    Used when the ``backup`` service (which already lists the plans) is not being collected.
    A failure only leaves the names blank.
    """
    client = session.client("backup", region_name=region)
    try:
        return {
            p["BackupPlanId"]: p.get("BackupPlanName", "")
            for page in client.get_paginator("list_backup_plans").paginate()
            for p in page.get("BackupPlansList", [])
        }
    except Exception as exc:
        log.debug("Could not list backup plan names in %s: %s", region, exc)
        return {}


class RecoveryPointResult:
    def __init__(self) -> None:
        self.rows: list[RecoveryPointRow] = []
        self.aggregates: list[RecoveryPointAggregate] = []
        self.truncated = False
        self.vaults_access_denied = 0


def _row(
    rp: dict, region: str, account_id: str, account_alias: str, plan_names: dict[str, str]
) -> RecoveryPointRow:
    created_by = rp.get("CreatedBy") or {}
    plan_id = created_by.get("BackupPlanId") or ""
    # ListRecoveryPointsByBackupVault never fills the plan name, so look it up by id.
    plan_name = created_by.get("BackupPlanName") or plan_names.get(plan_id, "")
    arn = rp.get("ResourceArn") or ""
    return RecoveryPointRow(
        account_id=account_id,
        account_alias=account_alias,
        region=region,
        backup_vault_name=rp.get("BackupVaultName", ""),
        backup_vault_arn=rp.get("BackupVaultArn", ""),
        recovery_point_arn=rp.get("RecoveryPointArn", ""),
        resource_arn=arn,
        resource_id=resource_id_from_arn(arn),
        resource_name=rp.get("ResourceName", ""),
        resource_type=rp.get("ResourceType", ""),
        backup_size_bytes=int(rp.get("BackupSizeInBytes") or 0),
        creation_date=_iso(rp.get("CreationDate")),
        backup_plan_id=plan_id,
        backup_plan_name=plan_name,
        status=str(rp.get("Status", "")),
        is_parent=bool(rp.get("IsParent")),
        parent_recovery_point_arn=rp.get("ParentRecoveryPointArn"),
    )


def _fold(
    aggregates: dict[str, RecoveryPointAggregate], row: RecoveryPointRow, size_was_null: bool
) -> None:
    """Add one recovery point to its resource's aggregate; composite parents are left out
    because they would count their children's bytes twice."""
    if row.is_parent or not row.resource_arn:
        return
    state = aggregates.get(row.resource_arn)
    if state is None:
        state = aggregates[row.resource_arn] = RecoveryPointAggregate(
            account_id=row.account_id,
            region=row.region,
            resource_arn=row.resource_arn,
            resource_type=row.resource_type,
            resource_name=row.resource_name,
        )
    state.recovery_point_count += 1
    if size_was_null:
        state.null_size_recovery_point_count += 1
    if row.backup_plan_name and row.backup_plan_name not in state.backup_plan_names:
        state.backup_plan_names.append(row.backup_plan_name)
    if row.backup_vault_name and row.backup_vault_name not in state.backup_vault_names:
        state.backup_vault_names.append(row.backup_vault_name)
    if state.latest_recovery_point_date is None or (
        row.creation_date
        and datetime.fromisoformat(row.creation_date)
        > datetime.fromisoformat(state.latest_recovery_point_date)
    ):
        state.latest_recovery_point_date = row.creation_date
        state.latest_recovery_point_arn = row.recovery_point_arn
        state.latest_recovery_point_size_bytes = row.backup_size_bytes


def fetch_recovery_points(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    plan_names: Optional[dict[str, str]] = None,
    tracker: "DenialTracker | None" = None,
    timeout_minutes: Optional[float] = None,
) -> RecoveryPointResult:
    """Recovery points of every vault in ``region``.

    Stops after ``timeout_minutes`` (``truncated`` is then set and sizes are lower bounds).
    A denied vault listing skips the region; denied vaults are counted and skipped.
    """
    if timeout_minutes is None:
        timeout_minutes = recovery_point_timeout_minutes()
    result = RecoveryPointResult()
    plan_names = plan_names or {}
    client = session.client("backup", region_name=region)
    errors: list[Exception] = []

    try:
        vaults = [
            v
            for page in client.get_paginator("list_backup_vaults").paginate()
            for v in page.get("BackupVaultList", [])
        ]
    except Exception as exc:
        if is_access_denied(exc):
            log.warning(
                "Access denied listing backup vaults in %s; skipping recovery points", region
            )
        errors.append(exc)
        record_metric_failures(
            tracker, region, "AWS Backup vault listing", errors, service="backup"
        )
        return result

    deadline = time.monotonic() + timeout_minutes * 60
    aggregates: dict[str, RecoveryPointAggregate] = {}
    for vault in vaults:
        if time.monotonic() > deadline:
            result.truncated = True
            break
        name = vault.get("BackupVaultName", "")
        try:
            for page in client.get_paginator("list_recovery_points_by_backup_vault").paginate(
                BackupVaultName=name
            ):
                if time.monotonic() > deadline:
                    result.truncated = True
                    break
                for rp in page.get("RecoveryPoints", []):
                    # PARTIAL, DELETING and EXPIRED points have unreliable sizes; skipping them
                    # keeps a newer incomplete one from zeroing a correct size.
                    if str(rp.get("Status", "")) != "COMPLETED":
                        continue
                    row = _row(rp, region, account_id, account_alias, plan_names)
                    result.rows.append(row)
                    _fold(aggregates, row, rp.get("BackupSizeInBytes") is None)
        except Exception as exc:
            if is_access_denied(exc):
                result.vaults_access_denied += 1
                continue
            errors.append(exc)

    if result.vaults_access_denied:
        errors.append(
            Exception(
                f"AccessDenied on backup:ListRecoveryPointsByBackupVault for "
                f"{result.vaults_access_denied} vault(s); those vaults are skipped"
            )
        )
    if result.truncated:
        log.warning(
            "Recovery point listing in %s stopped after %s min; sizes are lower bounds",
            region,
            timeout_minutes,
        )
    record_metric_failures(tracker, region, "AWS Backup recovery points", errors, service="backup")
    result.aggregates = list(aggregates.values())
    return result

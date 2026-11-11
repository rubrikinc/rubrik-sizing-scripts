"""Azure Backup Job History collector for Rubrik Discovery.

Fetches the last 60 days of VM backup job records from every Recovery Services
Vault in the subscription.  Produces per-job detail rows and per-VM success-rate
summaries — the primary input for the Excel 'Backup Job History' and
'VM Job Summary' sheets.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from cloud import DEFAULT_CLOUD, CloudEnvironment

from collectors.utils import enum_text, parse_resource_group

logger = logging.getLogger(__name__)

#: How far back to fetch job history.
_LOOKBACK_DAYS = 60

#: Status values we consider "successful" for success-rate calculations.
_SUCCESS_STATUSES = frozenset({"completed", "completedwithwarnings"})


@dataclass
class BackupJobInfo:
    """Detail record for a single Azure Backup job."""

    job_id: str
    vault_name: str
    resource_group: str
    subscription_id: str
    vm_name: Optional[str]  # entity_friendly_name from the SDK
    source_resource_id: Optional[str]  # ARM ID of the VM
    operation: str  # Backup / Restore / ConfigureBackup / etc.
    status: str  # Completed / Failed / InProgress / Cancelled
    start_time: Optional[str]  # ISO 8601 UTC
    end_time: Optional[str]  # ISO 8601 UTC; None if in-progress
    duration_minutes: Optional[float]
    data_transferred_mb: Optional[float]
    error_code: Optional[str]
    error_message: Optional[str]
    # Recovered from the SDK's native data_transferred_in_bytes (bytes-native, was
    # converted to MB then discarded) — true byte precision, not derived.
    data_transferred_bytes: Optional[int] = None
    data_transferred_gb: Optional[float] = None
    data_transferred_tb: Optional[float] = None  # /1024 conversion, mirrors compute.py


@dataclass
class VmJobSummary:
    """Aggregated Backup-operation statistics for a single VM."""

    vm_name: str
    source_resource_id: Optional[str]
    vault_name: str
    subscription_id: str
    total_jobs: int
    successful_jobs: int  # Completed + CompletedWithWarnings
    failed_jobs: int
    success_rate_pct: float
    last_successful_backup: Optional[str]  # ISO 8601 of most recent success
    avg_duration_minutes: Optional[float]


@dataclass
class BackupJobsInventory:
    """Full backup job history snapshot for a single subscription."""

    subscription_id: str
    jobs: list[BackupJobInfo] = field(default_factory=list)
    vm_summaries: list[VmJobSummary] = field(default_factory=list)
    total_jobs: int = 0
    successful_jobs: int = 0
    failed_jobs: int = 0
    days_collected: int = 0


class BackupJobsCollector:
    """Fetches Azure Backup job history for one subscription.

    Iterates every Recovery Services Vault in the subscription and fetches
    VM backup jobs for the configured lookback window.  Derives per-VM
    success-rate summaries from the raw job list.

    Credentials are always injected — never instantiated inside this class.
    """

    def __init__(
        self,
        subscription_id: str,
        credential: DefaultAzureCredential,
        lookback_days: int = _LOOKBACK_DAYS,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
    ) -> None:
        """
        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Validated credential injected from ``auth.get_credential()``.
            lookback_days: How many days of job history to retrieve (default: 60).
            cloud: Target Azure cloud (public vs. sovereign); drives ARM endpoint + token scope.
        """
        self._sub_id = subscription_id
        self._lookback_days = lookback_days
        self._rs_client = RecoveryServicesClient(
            credential, subscription_id, **cloud.client_kwargs()
        )
        self._backup_client = RecoveryServicesBackupClient(
            credential, subscription_id, **cloud.client_kwargs()
        )

    def collect(self) -> BackupJobsInventory:
        """Run the full backup job history collection pass for this subscription.

        Returns:
            Populated BackupJobsInventory dataclass.
        """
        logger.debug("[%s] Starting backup job history collection", self._sub_id)

        inventory = BackupJobsInventory(
            subscription_id=self._sub_id,
            days_collected=self._lookback_days,
        )

        try:
            vaults = list(self._rs_client.vaults.list_by_subscription_id())
        except HttpResponseError as exc:
            logger.warning("[%s] Failed to list vaults for job history: %s", self._sub_id, exc)
            return inventory

        all_jobs: list[BackupJobInfo] = []
        for vault in vaults:
            rg = parse_resource_group(vault.id or "")
            vault_name = vault.name or ""
            all_jobs.extend(self._list_jobs(vault_name, rg))

        inventory.jobs = all_jobs
        inventory.total_jobs = len(all_jobs)
        inventory.successful_jobs = sum(
            1 for j in all_jobs if j.status.lower() in _SUCCESS_STATUSES
        )
        inventory.failed_jobs = sum(1 for j in all_jobs if j.status.lower() == "failed")
        inventory.vm_summaries = _build_vm_summaries(all_jobs, self._sub_id)

        logger.debug(
            "[%s] Backup jobs: %d jobs (%d successful, %d failed) across %d vault(s)",
            self._sub_id,
            inventory.total_jobs,
            inventory.successful_jobs,
            inventory.failed_jobs,
            len(vaults),
        )
        return inventory

    def _list_jobs(self, vault_name: str, resource_group: str) -> list[BackupJobInfo]:
        """Fetch VM backup jobs from one vault for the configured lookback window."""
        jobs: list[BackupJobInfo] = []

        since = datetime.now(timezone.utc) - timedelta(days=self._lookback_days)
        # OData filter: VM jobs only, within the lookback window.
        filter_str = (
            f"backupManagementType eq 'AzureIaasVM' and "
            f"startTime ge '{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
        )

        try:
            for job in self._backup_client.backup_jobs.list(
                vault_name, resource_group, filter=filter_str
            ):
                try:
                    info = _parse_job(job, vault_name, resource_group, self._sub_id)
                    if info is not None:
                        jobs.append(info)
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping job %s in vault %s: %s",
                        self._sub_id,
                        getattr(job, "name", "?"),
                        vault_name,
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning(
                "[%s] Failed to list jobs for vault %s: %s",
                self._sub_id,
                vault_name,
                exc,
            )

        return jobs


def _parse_job(
    job: object,
    vault_name: str,
    resource_group: str,
    subscription_id: str,
) -> Optional[BackupJobInfo]:
    """Convert one SDK job object into a ``BackupJobInfo``.

    Returns None for non-VM jobs so the caller can filter them out.
    """
    props = getattr(job, "properties", None)
    if props is None:
        return None

    bmt = getattr(props, "backup_management_type", "") or ""
    if bmt != "AzureIaasVM":
        return None

    start_raw = getattr(props, "start_time", None)
    end_raw = getattr(props, "end_time", None)

    start_time: Optional[str] = (
        start_raw.isoformat()
        if isinstance(start_raw, datetime)
        else (str(start_raw) if start_raw else None)
    )
    end_time: Optional[str] = (
        end_raw.isoformat()
        if isinstance(end_raw, datetime)
        else (str(end_raw) if end_raw else None)
    )

    dur_raw = getattr(props, "duration", None)
    duration_minutes: Optional[float] = None
    if isinstance(dur_raw, timedelta):
        duration_minutes = round(dur_raw.total_seconds() / 60, 1)
    elif isinstance(dur_raw, str) and dur_raw:
        duration_minutes = _parse_iso_duration_minutes(dur_raw)

    ext = getattr(props, "extended_info", None)
    data_bytes = getattr(ext, "data_transferred_in_bytes", None)
    data_mb: Optional[float] = round(data_bytes / (1024**2), 2) if data_bytes is not None else None
    data_bytes_val: Optional[int] = int(data_bytes) if data_bytes is not None else None
    data_gb: Optional[float] = round(data_bytes / (1024**3), 3) if data_bytes is not None else None
    data_tb: Optional[float] = round(data_gb / 1024, 3) if data_gb else None

    err_code: Optional[str] = None
    err_message: Optional[str] = None
    error_details = getattr(props, "error_details", None) or []
    if error_details:
        first = error_details[0]
        err_code = getattr(first, "error_code", None)
        err_message = getattr(first, "error_string", None) or getattr(first, "message", None)

    return BackupJobInfo(
        job_id=getattr(job, "name", "") or "",
        vault_name=vault_name,
        resource_group=resource_group,
        subscription_id=subscription_id,
        vm_name=getattr(props, "entity_friendly_name", None),
        source_resource_id=getattr(props, "source_resource_id", None),
        operation=enum_text(getattr(props, "operation", None)) or "",
        status=enum_text(getattr(props, "status", None)) or "",
        start_time=start_time,
        end_time=end_time,
        duration_minutes=duration_minutes,
        data_transferred_mb=data_mb,
        data_transferred_bytes=data_bytes_val,
        data_transferred_gb=data_gb,
        data_transferred_tb=data_tb,
        error_code=err_code,
        error_message=err_message,
    )


def _build_vm_summaries(jobs: list[BackupJobInfo], subscription_id: str) -> list[VmJobSummary]:
    """Aggregate per-VM job statistics from the raw job list.

    Only ``Backup`` operations are included in the per-VM summary — Restore
    and ConfigureBackup jobs are excluded so the success rate reflects backup
    health rather than recovery activity.
    """
    backup_ops = [j for j in jobs if j.operation.lower() == "backup"]

    # Group by (source_resource_id or vm_name, vault_name)
    groups: dict[tuple[str, str], list[BackupJobInfo]] = {}
    for job in backup_ops:
        key_resource = (job.source_resource_id or "").lower() or (job.vm_name or "")
        groups.setdefault((key_resource, job.vault_name), []).append(job)

    summaries: list[VmJobSummary] = []
    for (key_resource, vault_name), job_list in groups.items():
        vm_name = next((j.vm_name for j in job_list if j.vm_name), key_resource)
        src_id = next((j.source_resource_id for j in job_list if j.source_resource_id), None)

        successful = [j for j in job_list if j.status.lower() in _SUCCESS_STATUSES]
        failed = [j for j in job_list if j.status.lower() == "failed"]
        total = len(job_list)
        rate = round(len(successful) / total * 100, 1) if total else 0.0

        # Most recent successful backup time
        last_success: Optional[str] = None
        success_times = [j.start_time for j in successful if j.start_time]
        if success_times:
            last_success = max(success_times)

        # Average duration across successful jobs
        durs = [j.duration_minutes for j in successful if j.duration_minutes is not None]
        avg_dur = round(sum(durs) / len(durs), 1) if durs else None

        summaries.append(
            VmJobSummary(
                vm_name=vm_name,
                source_resource_id=src_id,
                vault_name=vault_name,
                subscription_id=subscription_id,
                total_jobs=total,
                successful_jobs=len(successful),
                failed_jobs=len(failed),
                success_rate_pct=rate,
                last_successful_backup=last_success,
                avg_duration_minutes=avg_dur,
            )
        )

    # Sort: worst success rate first so problem VMs are at the top
    summaries.sort(key=lambda s: (s.success_rate_pct, s.vm_name))
    return summaries


def _parse_iso_duration_minutes(s: str) -> Optional[float]:
    """Parse an ISO 8601 duration string (``PT1H30M45S``) into minutes.

    Returns None if the string cannot be parsed.
    """
    m = re.match(
        r"P(?:(\d+)D)?T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?",
        s.upper(),
    )
    if not m:
        return None
    days, hours, mins, secs = m.groups()
    total = (
        float(days or 0) * 1440 + float(hours or 0) * 60 + float(mins or 0) + float(secs or 0) / 60
    )
    return round(total, 1) if total else None

"""Tests for collectors/backup_jobs.py — Azure SDK is fully mocked."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError
from collectors.backup_jobs import (
    BackupJobInfo,
    BackupJobsCollector,
    BackupJobsInventory,
    VmJobSummary,
    _build_vm_summaries,
    _parse_iso_duration_minutes,
    _parse_job,
)

from tests.fixtures import (
    MOCK_BACKUP_JOBS,
    MOCK_VAULTS,
    RG_BACKUP,
    RG_DEV,
    SUB_ID,
    _vault_id,
    _vm_id,
    mock_backup_jobs_effect,
)


def _make_collector(vaults=None, jobs_effect=None) -> BackupJobsCollector:
    """Return a BackupJobsCollector with mocked Azure clients."""
    mock_rs = MagicMock()
    mock_rs.vaults.list_by_subscription_id.return_value = iter(
        MOCK_VAULTS if vaults is None else vaults
    )

    mock_backup = MagicMock()
    mock_backup.backup_jobs.list.side_effect = (
        mock_backup_jobs_effect if jobs_effect is None else jobs_effect
    )

    with (
        patch("collectors.backup_jobs.RecoveryServicesClient", return_value=mock_rs),
        patch("collectors.backup_jobs.RecoveryServicesBackupClient", return_value=mock_backup),
    ):
        collector = BackupJobsCollector(SUB_ID, MagicMock())
        collector._rs_client = mock_rs
        collector._backup_client = mock_backup

    return collector


def _make_job_ns(
    job_id: str = "job-1",
    vm_name: str = "vm-1",
    vm_rg: str = "rg-prod",
    operation: str = "Backup",
    status: str = "Completed",
    start: datetime | None = None,
    duration_minutes: float = 30.0,
    data_gb: float | None = 5.0,
    error_code: str | None = None,
    error_message: str | None = None,
) -> NS:
    """Build a minimal mock job namespace."""
    if start is None:
        start = datetime(2026, 4, 11, 2, 0, tzinfo=timezone.utc)
    end = start + timedelta(minutes=duration_minutes)
    error_details = [NS(error_code=error_code, error_string=error_message)] if error_code else None
    return NS(
        name=job_id,
        properties=NS(
            backup_management_type="AzureIaasVM",
            entity_friendly_name=vm_name,
            source_resource_id=_vm_id(vm_rg, vm_name),
            operation=operation,
            status=status,
            start_time=start,
            end_time=end,
            duration=timedelta(minutes=duration_minutes),
            extended_info=NS(data_transferred_in_bytes=int(data_gb * 1024**3) if data_gb else None),
            error_details=error_details,
        ),
    )


def test_collect_returns_inventory():
    collector = _make_collector()
    result = collector.collect()
    assert isinstance(result, BackupJobsInventory)
    assert result.subscription_id == SUB_ID


def test_collect_parses_all_fixture_jobs():
    collector = _make_collector()
    result = collector.collect()

    # vault-prod-east has 19 VM jobs; vault-nonprod has 3
    assert result.total_jobs == 22


def test_collect_counts_successful_and_failed():
    collector = _make_collector()
    result = collector.collect()

    # All jobs from fixture: 18 Completed/CompletedWithWarnings, 4 Failed (oracle×2 + sql02×1 + app01×0)
    # oracle: 2 Failed; sql-prod-02: 1 Failed; others: Completed or CompletedWithWarnings
    assert result.successful_jobs > 0
    assert result.failed_jobs > 0
    assert result.successful_jobs + result.failed_jobs <= result.total_jobs


def test_collect_builds_vm_summaries():
    collector = _make_collector()
    result = collector.collect()

    assert len(result.vm_summaries) > 0
    # oracle-prod-01 should be first (0% success rate)
    assert result.vm_summaries[0].vm_name == "oracle-prod-01"
    assert result.vm_summaries[0].success_rate_pct == 0.0


def test_collect_days_collected():
    collector = _make_collector()
    result = collector.collect()
    assert result.days_collected == 60


def test_collect_returns_empty_when_vault_list_fails():
    mock_rs = MagicMock()
    mock_rs.vaults.list_by_subscription_id.side_effect = HttpResponseError(message="403 Forbidden")
    mock_backup = MagicMock()

    with (
        patch("collectors.backup_jobs.RecoveryServicesClient", return_value=mock_rs),
        patch("collectors.backup_jobs.RecoveryServicesBackupClient", return_value=mock_backup),
    ):
        collector = BackupJobsCollector(SUB_ID, MagicMock())
        collector._rs_client = mock_rs
        collector._backup_client = mock_backup

    result = collector.collect()
    assert result.total_jobs == 0
    assert result.vm_summaries == []


def test_collect_skips_vault_that_fails_job_list():
    """Job list failure for one vault should not stop processing other vaults."""
    vault_ok = NS(id=_vault_id(RG_BACKUP, "vault-ok"), name="vault-ok", location="eastus")
    vault_bad = NS(id=_vault_id(RG_BACKUP, "vault-bad"), name="vault-bad", location="eastus")

    def _jobs_effect(vault_name: str, rg: str, **kwargs):
        if vault_name == "vault-bad":
            raise HttpResponseError(message="permission denied")
        return iter([_make_job_ns("j1")])

    mock_rs = MagicMock()
    mock_rs.vaults.list_by_subscription_id.return_value = iter([vault_ok, vault_bad])
    mock_backup = MagicMock()
    mock_backup.backup_jobs.list.side_effect = _jobs_effect

    with (
        patch("collectors.backup_jobs.RecoveryServicesClient", return_value=mock_rs),
        patch("collectors.backup_jobs.RecoveryServicesBackupClient", return_value=mock_backup),
    ):
        collector = BackupJobsCollector(SUB_ID, MagicMock())
        collector._rs_client = mock_rs
        collector._backup_client = mock_backup

    result = collector.collect()
    assert result.total_jobs == 1  # vault-ok contributed one job


def test_collect_skips_malformed_job_without_crashing():
    """A job with no .properties should be skipped silently."""
    bad_job = NS(name="bad-job")  # no .properties attribute

    def _jobs_effect(vault_name: str, rg: str, **kwargs):
        return iter([bad_job, _make_job_ns("good-job")])

    collector = _make_collector(
        vaults=[
            NS(
                id=_vault_id(RG_BACKUP, "vault-prod-east"),
                name="vault-prod-east",
                location="eastus",
            )
        ],
        jobs_effect=_jobs_effect,
    )
    result = collector.collect()
    assert result.total_jobs == 1


def test_collect_filters_non_vm_jobs():
    """Jobs with backup_management_type != AzureIaasVM are excluded."""
    sql_job = NS(
        name="sql-job",
        properties=NS(
            backup_management_type="AzureWorkload",
            entity_friendly_name="sqldb",
            source_resource_id=None,
            operation="Backup",
            status="Completed",
            start_time=datetime(2026, 4, 11, tzinfo=timezone.utc),
            end_time=datetime(2026, 4, 11, 1, tzinfo=timezone.utc),
            duration=timedelta(hours=1),
            extended_info=None,
            error_details=None,
        ),
    )

    def _jobs_effect(vault_name: str, rg: str, **kwargs):
        return iter([sql_job, _make_job_ns("vm-job")])

    collector = _make_collector(
        vaults=[NS(id=_vault_id(RG_BACKUP, "v"), name="v", location="eastus")],
        jobs_effect=_jobs_effect,
    )
    result = collector.collect()
    assert result.total_jobs == 1
    assert result.jobs[0].job_id == "vm-job"


def test_parse_job_returns_job_info():
    job_ns = _make_job_ns("job-abc", "my-vm", "rg-prod")
    info = _parse_job(job_ns, "vault-1", "rg-prod", SUB_ID)

    assert info is not None
    assert info.job_id == "job-abc"
    assert info.vm_name == "my-vm"
    assert info.status == "Completed"
    assert info.operation == "Backup"
    assert info.duration_minutes == 30.0
    assert info.vault_name == "vault-1"
    assert info.subscription_id == SUB_ID


def test_parse_job_calculates_data_mb():
    job_ns = _make_job_ns(data_gb=2.0)
    info = _parse_job(job_ns, "v", "rg", SUB_ID)

    expected_mb = round(2.0 * 1024, 2)
    assert info.data_transferred_mb == expected_mb


def test_parse_job_calculates_data_bytes_gb_tb():
    """data_transferred_bytes is recovered from the SDK's native bytes value (not
    re-derived from the rounded MB figure); gb/tb are straight conversions of it."""
    job_ns = _make_job_ns(data_gb=2.0)
    info = _parse_job(job_ns, "v", "rg", SUB_ID)

    expected_bytes = int(2.0 * 1024**3)
    assert info.data_transferred_bytes == expected_bytes
    assert info.data_transferred_gb == round(expected_bytes / 1024**3, 3)
    assert info.data_transferred_tb == round(info.data_transferred_gb / 1024, 3)


def test_parse_job_extracts_error_details():
    job_ns = _make_job_ns(
        status="Failed",
        error_code="UserErrorVmNotInDesirableState",
        error_message="VM was deallocated",
    )
    info = _parse_job(job_ns, "v", "rg", SUB_ID)

    assert info.error_code == "UserErrorVmNotInDesirableState"
    assert info.error_message == "VM was deallocated"


def test_parse_job_returns_none_for_non_vm_type():
    job_ns = NS(
        name="x",
        properties=NS(
            backup_management_type="AzureStorage",
            entity_friendly_name="blob",
            source_resource_id=None,
            operation="Backup",
            status="Completed",
            start_time=datetime(2026, 4, 11, tzinfo=timezone.utc),
            end_time=None,
            duration=None,
            extended_info=None,
            error_details=None,
        ),
    )
    assert _parse_job(job_ns, "v", "rg", SUB_ID) is None


def test_parse_job_returns_none_when_no_properties():
    assert _parse_job(NS(name="x"), "v", "rg", SUB_ID) is None


def test_parse_job_handles_timedelta_duration():
    job_ns = _make_job_ns(duration_minutes=90.0)
    info = _parse_job(job_ns, "v", "rg", SUB_ID)
    assert info.duration_minutes == 90.0


def test_parse_job_handles_none_end_time():
    job_ns = _make_job_ns()
    job_ns.properties.end_time = None
    info = _parse_job(job_ns, "v", "rg", SUB_ID)
    assert info is not None
    assert info.end_time is None


def test_parse_job_handles_none_data():
    job_ns = _make_job_ns(data_gb=None)
    info = _parse_job(job_ns, "v", "rg", SUB_ID)
    assert info.data_transferred_mb is None
    assert info.data_transferred_bytes is None
    assert info.data_transferred_gb is None
    assert info.data_transferred_tb is None


def _make_jobs(vm_name: str, statuses: list[str], vault: str = "v") -> list[BackupJobInfo]:
    base = datetime(2026, 4, 1, tzinfo=timezone.utc)
    return [
        BackupJobInfo(
            job_id=f"{vm_name}-{i}",
            vault_name=vault,
            resource_group="rg",
            subscription_id=SUB_ID,
            vm_name=vm_name,
            source_resource_id=f"/subs/{SUB_ID}/vms/{vm_name}",
            operation="Backup",
            status=s,
            start_time=(base + timedelta(days=i)).isoformat(),
            end_time=None,
            duration_minutes=30.0,
            data_transferred_mb=None,
            error_code=None,
            error_message=None,
        )
        for i, s in enumerate(statuses)
    ]


def test_build_vm_summaries_success_rate():
    jobs = _make_jobs("vm-1", ["Completed", "Completed", "Failed", "Completed"])
    summaries = _build_vm_summaries(jobs, SUB_ID)

    assert len(summaries) == 1
    s = summaries[0]
    assert s.total_jobs == 4
    assert s.successful_jobs == 3
    assert s.failed_jobs == 1
    assert s.success_rate_pct == 75.0


def test_build_vm_summaries_sorted_worst_first():
    jobs = (
        _make_jobs("vm-good", ["Completed", "Completed"])
        + _make_jobs("vm-bad", ["Failed", "Failed"])
        + _make_jobs("vm-mid", ["Completed", "Failed"])
    )
    summaries = _build_vm_summaries(jobs, SUB_ID)

    rates = [s.success_rate_pct for s in summaries]
    assert rates == sorted(rates)  # ascending = worst first
    assert summaries[0].vm_name == "vm-bad"


def test_build_vm_summaries_last_successful_backup():
    jobs = _make_jobs("vm-1", ["Completed", "Failed", "Completed"])
    summaries = _build_vm_summaries(jobs, SUB_ID)

    # start_time is set by _make_jobs; last successful is the latest start_time
    # among completed jobs (index 0 and 2)
    expected = max(j.start_time for j in jobs if j.status == "Completed")
    assert summaries[0].last_successful_backup == expected


def test_build_vm_summaries_avg_duration():
    jobs = _make_jobs("vm-1", ["Completed", "Completed"])
    jobs[0] = BackupJobInfo(**{**jobs[0].__dict__, "duration_minutes": 30.0})
    jobs[1] = BackupJobInfo(**{**jobs[1].__dict__, "duration_minutes": 50.0})
    summaries = _build_vm_summaries(jobs, SUB_ID)

    assert summaries[0].avg_duration_minutes == 40.0


def test_build_vm_summaries_excludes_restore_jobs():
    backup_jobs = _make_jobs("vm-1", ["Completed"])
    restore_job = BackupJobInfo(
        **{**backup_jobs[0].__dict__, "job_id": "restore-1", "operation": "Restore"}
    )
    summaries = _build_vm_summaries(backup_jobs + [restore_job], SUB_ID)

    assert summaries[0].total_jobs == 1  # restore excluded


def test_build_vm_summaries_empty_returns_empty():
    assert _build_vm_summaries([], SUB_ID) == []


def test_build_vm_summaries_completedwithwarnings_counts_as_success():
    jobs = _make_jobs("vm-1", ["CompletedWithWarnings", "CompletedWithWarnings"])
    summaries = _build_vm_summaries(jobs, SUB_ID)

    assert summaries[0].success_rate_pct == 100.0
    assert summaries[0].successful_jobs == 2


@pytest.mark.parametrize(
    "s,expected",
    [
        ("PT45M", 45.0),
        ("PT1H", 60.0),
        ("PT1H30M", 90.0),
        ("PT1H30M45S", 90.8),
        ("P1DT2H", 1560.0),  # 1 day + 2 hours
        ("PT0S", None),  # zero duration
        ("garbage", None),
    ],
)
def test_parse_iso_duration_minutes(s, expected):
    assert _parse_iso_duration_minutes(s) == expected

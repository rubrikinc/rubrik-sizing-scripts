"""Tests for collectors/backup.py — all GCP SDK calls are mocked."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from collectors.backup import BackupCollector

from tests.conftest import PROJECT_ID

_BACKUPDR_CLIENT = "google.cloud.backupdr_v1.BackupDRClient"


def _make_plan(name: str = "projects/p/locations/us-central1/backupPlans/plan-1"):
    plan = MagicMock()
    plan.name = name
    plan.resource_type = "compute.googleapis.com/Instance"
    plan.backup_vault = "projects/p/locations/us-central1/backupVaults/vault-1"
    plan.backup_rules = []
    return plan


def _make_association(
    name: str,
    resource_name: str,
    state: str = "ACTIVE",
    backup_plan: str = "plan-1",
):
    assoc = MagicMock()
    assoc.name = f"projects/p/locations/us-central1/backupPlanAssociations/{name}"
    assoc.resource = resource_name
    assoc.resource_type = "compute.googleapis.com/Instance"
    assoc.backup_plan = f"projects/p/locations/us-central1/backupPlans/{backup_plan}"
    assoc.state = MagicMock()
    assoc.state.name = state
    assoc.last_successful_backup_consistency_time = None
    assoc.last_backup_error = None
    return assoc


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_backup_collector_empty_project():
    mock_client = MagicMock()
    mock_client.list_backup_plans.return_value = iter([])
    mock_client.list_backup_plan_associations.return_value = iter([])

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        result = BackupCollector(PROJECT_ID, MagicMock()).collect()

    assert result.total_associations == 0
    assert result.protected_instance_count == 0
    assert result.protection_coverage_pct == 0.0


def test_backup_collector_100_percent_coverage():
    associations = [
        _make_association("assoc-1", "//compute.googleapis.com/projects/p/zones/z/instances/vm-1"),
        _make_association("assoc-2", "//compute.googleapis.com/projects/p/zones/z/instances/vm-2"),
    ]
    mock_client = MagicMock()
    mock_client.list_backup_plans.return_value = iter([_make_plan()])
    mock_client.list_backup_plan_associations.return_value = iter(associations)

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        result = BackupCollector(
            PROJECT_ID,
            MagicMock(),
            gce_instance_names=["vm-1", "vm-2"],
        ).collect()

    assert result.protected_instance_count == 2
    assert result.unprotected_instance_count == 0
    assert result.protection_coverage_pct == 100.0


def test_backup_collector_partial_coverage():
    associations = [
        _make_association("assoc-1", "//compute.googleapis.com/projects/p/zones/z/instances/vm-1"),
    ]
    mock_client = MagicMock()
    mock_client.list_backup_plans.return_value = iter([])
    mock_client.list_backup_plan_associations.return_value = iter(associations)

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        result = BackupCollector(
            PROJECT_ID,
            MagicMock(),
            gce_instance_names=["vm-1", "vm-2", "vm-3"],
        ).collect()

    assert result.protected_instance_count == 1
    assert result.unprotected_instance_count == 2
    assert "vm-2" in result.unprotected_instances
    assert "vm-3" in result.unprotected_instances
    assert result.protection_coverage_pct == round(1 / 3 * 100, 1)


def test_backup_collector_inactive_association_not_counted():
    associations = [
        _make_association(
            "assoc-1",
            "//compute.googleapis.com/projects/p/zones/z/instances/vm-1",
            state="DELETING",
        ),
    ]
    mock_client = MagicMock()
    mock_client.list_backup_plans.return_value = iter([])
    mock_client.list_backup_plan_associations.return_value = iter(associations)

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        result = BackupCollector(
            PROJECT_ID,
            MagicMock(),
            gce_instance_names=["vm-1"],
        ).collect()

    assert result.unprotected_instance_count == 1
    assert result.protection_coverage_pct == 0.0


def test_backup_collector_graceful_on_api_error():
    mock_client = MagicMock()
    mock_client.list_backup_plans.side_effect = Exception("API not enabled")

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        result = BackupCollector(
            PROJECT_ID,
            MagicMock(),
            gce_instance_names=["vm-1", "vm-2"],
        ).collect()

    # All VMs unprotected when API fails
    assert result.unprotected_instance_count == 2
    assert result.protection_coverage_pct == 0.0


def test_backup_collector_no_vms_gives_zero_coverage():
    mock_client = MagicMock()
    mock_client.list_backup_plans.return_value = iter([])
    mock_client.list_backup_plan_associations.return_value = iter([])

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        result = BackupCollector(PROJECT_ID, MagicMock(), gce_instance_names=[]).collect()

    assert result.protection_coverage_pct == 0.0
    assert result.protected_instance_count == 0


def test_backup_collector_sdk_import_error_returns_empty():
    # Simulate the backupdr_v1 SDK not being installed at all.
    with patch(
        "builtins.__import__", side_effect=ImportError("No module named 'google.cloud.backupdr_v1'")
    ):
        result = BackupCollector(
            PROJECT_ID,
            MagicMock(),
            gce_instance_names=["vm-1"],
        ).collect()

    assert result.unprotected_instance_count == 1
    assert result.protection_coverage_pct == 0.0


def test_backup_collector_plan_count():
    plans = [
        _make_plan("projects/p/locations/us/backupPlans/plan-1"),
        _make_plan("projects/p/locations/us/backupPlans/plan-2"),
    ]
    mock_client = MagicMock()
    mock_client.list_backup_plans.return_value = iter(plans)
    mock_client.list_backup_plan_associations.return_value = iter([])

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        result = BackupCollector(PROJECT_ID, MagicMock()).collect()

    assert len(result.backup_plans) == 2


# ── API disabled, permission denied and what the roll-up says about them ──────

_API_DISABLED = (
    "403 Backup and DR Service API has not been used in project p before or it is disabled. "
    "Enable it by visiting https://console.developers.google.com/apis/api/backupdr.googleapis.com/"
    "overview?project=p then retry."
)


def test_a_disabled_backup_api_is_recorded_once_and_the_coverage_is_marked_unavailable():
    mock_client = MagicMock()
    mock_client.list_backup_plans.side_effect = Exception(_API_DISABLED)
    mock_client.list_backup_plan_associations.side_effect = Exception(_API_DISABLED)

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        collector = BackupCollector(PROJECT_ID, MagicMock(), gce_instance_names=["vm-1", "vm-2"])
        result = collector.collect()

    assert result.available is False
    assert [(e["collector"], e["category"]) for e in collector.errors] == [
        ("backup", "API_DISABLED")
    ]
    assert "backupdr.googleapis.com" in collector.errors[0]["message"]
    # the earlier behaviour is kept: with nothing known, every VM is listed as unprotected
    assert result.unprotected_instance_count == 2
    assert result.protection_coverage_pct == 0.0


def test_a_failed_association_listing_alone_makes_the_coverage_unavailable():
    mock_client = MagicMock()
    mock_client.list_backup_plans.return_value = iter([_make_plan()])
    mock_client.list_backup_plan_associations.side_effect = Exception(
        "403 Permission 'backupdr.backupPlanAssociations.list' denied on 'projects/p'"
    )

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        collector = BackupCollector(PROJECT_ID, MagicMock(), gce_instance_names=["vm-1"])
        result = collector.collect()

    assert result.available is False
    assert len(result.backup_plans) == 1
    assert [e["category"] for e in collector.errors] == ["PERMISSION_DENIED"]


def test_a_failed_plan_listing_is_recorded_but_the_coverage_is_still_known():
    assoc = _make_association("a1", "//compute.googleapis.com/projects/p/zones/z/instances/vm-1")
    mock_client = MagicMock()
    mock_client.list_backup_plans.side_effect = Exception("403 Permission denied on plans")
    mock_client.list_backup_plan_associations.return_value = iter([assoc])

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        collector = BackupCollector(PROJECT_ID, MagicMock(), gce_instance_names=["vm-1", "vm-2"])
        result = collector.collect()

    assert result.available is True
    assert result.protected_instance_count == 1
    assert result.protection_coverage_pct == 50.0
    assert [e["collector"] for e in collector.errors] == ["backup"]


def test_two_different_failures_are_both_recorded():
    mock_client = MagicMock()
    mock_client.list_backup_plans.side_effect = Exception("403 Permission denied on plans")
    mock_client.list_backup_plan_associations.side_effect = Exception(_API_DISABLED)

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        collector = BackupCollector(PROJECT_ID, MagicMock())
        collector.collect()

    assert sorted(e["category"] for e in collector.errors) == ["API_DISABLED", "PERMISSION_DENIED"]


def test_a_clean_run_records_nothing_and_is_available():
    mock_client = MagicMock()
    mock_client.list_backup_plans.return_value = iter([_make_plan()])
    mock_client.list_backup_plan_associations.return_value = iter([])

    with patch(_BACKUPDR_CLIENT, return_value=mock_client):
        collector = BackupCollector(PROJECT_ID, MagicMock(), gce_instance_names=["vm-1"])
        result = collector.collect()

    assert collector.errors == [] and result.available is True


def test_a_missing_sdk_marks_the_coverage_unavailable_and_records_it():
    with patch(
        "builtins.__import__", side_effect=ImportError("No module named 'google.cloud.backupdr_v1'")
    ):
        collector = BackupCollector(PROJECT_ID, MagicMock(), gce_instance_names=["vm-1"])
        result = collector.collect()

    assert result.available is False
    assert [e["category"] for e in collector.errors] == ["SDK_MISSING"]

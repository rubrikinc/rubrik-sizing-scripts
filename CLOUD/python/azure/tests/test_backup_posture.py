"""Tests for collectors/backup_posture.py — Azure SDK is fully mocked."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from collectors.backup_posture import (
    BackupPolicy,
    BackupPostureCollector,
    BackupPostureInventory,
    ProtectedItem,
    VaultInfo,
    _extract_retention,
    _extract_schedule,
    _schedule_retention_count,
)

SUB_ID = "00000000-0000-0000-0000-000000000002"

_VM_ID_1 = (
    f"/subscriptions/{SUB_ID}/resourceGroups/rg-prod"
    "/providers/Microsoft.Compute/virtualMachines/vm-01"
).lower()
_VM_ID_2 = (
    f"/subscriptions/{SUB_ID}/resourceGroups/rg-prod"
    "/providers/Microsoft.Compute/virtualMachines/vm-02"
).lower()
_VM_ID_3 = (
    f"/subscriptions/{SUB_ID}/resourceGroups/rg-prod"
    "/providers/Microsoft.Compute/virtualMachines/vm-03"
).lower()

_VAULT_ID = (
    f"/subscriptions/{SUB_ID}/resourceGroups/rg-backup"
    "/providers/Microsoft.RecoveryServices/vaults/vault-01"
)
_POLICY_ID = f"{_VAULT_ID}/backupPolicies/DailyPolicy"


def _make_vault(
    name="vault-01",
    location="eastus",
    rg="rg-backup",
    tags=None,
    resource_id=None,
):
    v = MagicMock()
    v.name = name
    v.location = location
    v.id = resource_id or (
        f"/subscriptions/{SUB_ID}/resourceGroups/{rg}"
        f"/providers/Microsoft.RecoveryServices/vaults/{name}"
    )
    v.tags = tags or {}
    return v


def _make_storage_config(storage_type="GeoRedundant"):
    cfg = MagicMock()
    cfg.properties = MagicMock()
    cfg.properties.storage_type = storage_type
    return cfg


def _make_policy_vm_daily(
    name="DailyPolicy",
    daily_days=30,
    weekly_weeks=12,
    monthly_months=12,
    yearly_years=5,
):
    """Mock an AzureIaaSVMProtectionPolicy with LongTermRetentionPolicy."""
    policy = MagicMock()
    policy.name = name
    policy.id = _POLICY_ID

    props = MagicMock()
    props.backup_management_type = "AzureIaasVM"

    # Schedule
    sched = MagicMock()
    sched.schedule_run_frequency = "Daily"
    sched.schedule_run_times = [datetime(2024, 1, 1, 2, 0, tzinfo=timezone.utc)]
    props.schedule_policy = sched

    # Retention (LongTermRetentionPolicy) — explicitly set retention_count=None
    # so _extract_retention doesn't mistake this for a SimpleRetentionPolicy.
    ret = MagicMock()
    ret.retention_count = None
    _set_retention_tier(ret, "daily_schedule", daily_days)
    _set_retention_tier(ret, "weekly_schedule", weekly_weeks)
    _set_retention_tier(ret, "monthly_schedule", monthly_months)
    _set_retention_tier(ret, "yearly_schedule", yearly_years)
    props.retention_policy = ret
    props.sub_protection_policy = None

    policy.properties = props
    return policy


def _set_retention_tier(ret_mock, attr_name, count):
    tier = MagicMock()
    tier.retention_duration = MagicMock()
    tier.retention_duration.count = count
    setattr(ret_mock, attr_name, tier)


def _make_protected_item_vm(
    name="vm-backup-01",
    vm_id=_VM_ID_1,
    protection_state="Protected",
    last_backup_status="Completed",
    last_backup_time=None,
    policy_id=_POLICY_ID,
):
    item = MagicMock()
    item.name = name
    item.id = (
        f"/subscriptions/{SUB_ID}/resourceGroups/rg-backup"
        "/providers/Microsoft.RecoveryServices/vaults/vault-01"
        f"/backupFabrics/Azure/protectionContainers/IaasVMContainer/protectedItems/{name}"
    )

    props = MagicMock()
    props.backup_management_type = "AzureIaasVM"
    props.protection_state = protection_state
    props.last_backup_status = last_backup_status
    props.last_backup_time = last_backup_time or datetime(2024, 6, 1, 3, 0, tzinfo=timezone.utc)
    props.policy_id = policy_id
    props.source_resource_id = vm_id
    props.virtual_machine_id = vm_id  # older SDK field alias

    # SDK class name used as resource_type
    type(props).__name__ = "AzureIaaSVMProtectedItem"

    item.properties = props
    return item


def _make_collector(
    vaults=None,
    storage_config=None,
    policies=None,
    protected_items=None,
    vm_resource_ids=None,
    regions=None,
):
    """Build a BackupPostureCollector with fully mocked Azure clients."""
    mock_rs = MagicMock()
    mock_rs.vaults.list_by_subscription_id.return_value = iter(vaults or [])

    mock_backup = MagicMock()
    mock_backup.backup_resource_storage_configs_non_crr.get.return_value = (
        storage_config or _make_storage_config()
    )
    mock_backup.backup_policies.list.return_value = iter(policies or [])
    mock_backup.backup_protected_items.list.return_value = iter(protected_items or [])

    with patch("collectors.backup_posture.RecoveryServicesClient", return_value=mock_rs):
        with patch(
            "collectors.backup_posture.RecoveryServicesBackupClient",
            return_value=mock_backup,
        ):
            collector = BackupPostureCollector(SUB_ID, MagicMock(), regions, vm_resource_ids)
            collector._rs_client = mock_rs
            collector._backup_client = mock_backup
    return collector


def test_collect_returns_inventory():
    collector = _make_collector()
    result = collector.collect()
    assert isinstance(result, BackupPostureInventory)
    assert result.subscription_id == SUB_ID


def test_collect_empty_subscription():
    collector = _make_collector()
    result = collector.collect()
    assert result.vault_count == 0
    assert result.policy_count == 0
    assert result.protected_item_count == 0


def test_collect_vault_count():
    vaults = [_make_vault("v1"), _make_vault("v2")]
    collector = _make_collector(vaults=vaults)
    result = collector.collect()
    assert result.vault_count == 2


def test_collect_vault_redundancy_grs():
    vaults = [_make_vault()]
    collector = _make_collector(vaults=vaults, storage_config=_make_storage_config("GeoRedundant"))
    result = collector.collect()
    assert result.vaults[0].redundancy == "GRS"


def test_collect_vault_redundancy_lrs():
    vaults = [_make_vault()]
    collector = _make_collector(
        vaults=vaults, storage_config=_make_storage_config("LocallyRedundant")
    )
    result = collector.collect()
    assert result.vaults[0].redundancy == "LRS"


def test_collect_vault_redundancy_zrs():
    vaults = [_make_vault()]
    collector = _make_collector(vaults=vaults, storage_config=_make_storage_config("ZoneRedundant"))
    result = collector.collect()
    assert result.vaults[0].redundancy == "ZRS"


def test_collect_vault_redundancy_unknown_on_api_error():
    mock_rs = MagicMock()
    mock_rs.vaults.list_by_subscription_id.return_value = iter([_make_vault()])
    mock_backup = MagicMock()
    mock_backup.backup_resource_storage_configs_non_crr.get.side_effect = Exception(
        "permission denied"
    )
    mock_backup.backup_policies.list.return_value = iter([])
    mock_backup.backup_protected_items.list.return_value = iter([])

    with patch("collectors.backup_posture.RecoveryServicesClient", return_value=mock_rs):
        with patch(
            "collectors.backup_posture.RecoveryServicesBackupClient",
            return_value=mock_backup,
        ):
            collector = BackupPostureCollector(SUB_ID, MagicMock())
            collector._rs_client = mock_rs
            collector._backup_client = mock_backup

    result = collector.collect()
    assert result.vaults[0].redundancy == "Unknown"


def test_collect_vault_region_filter():
    v_east = _make_vault("v-east", location="eastus")
    v_west = _make_vault("v-west", location="westus2")
    collector = _make_collector(vaults=[v_east, v_west], regions=["eastus"])
    result = collector.collect()
    assert result.vault_count == 1
    assert result.vaults[0].name == "v-east"


def test_collect_vault_tag_summary():
    vault = _make_vault(tags={"env": "prod", "owner": "ops"})
    collector = _make_collector(vaults=[vault])
    result = collector.collect()
    assert result.tag_summary is not None
    assert "env" in result.tag_summary.key_coverage


def test_collect_redundancy_breakdown():
    v1 = _make_vault("v1")
    v2 = _make_vault("v2")
    mock_rs = MagicMock()
    mock_rs.vaults.list_by_subscription_id.return_value = iter([v1, v2])

    configs = iter([_make_storage_config("GeoRedundant"), _make_storage_config("LocallyRedundant")])
    mock_backup = MagicMock()
    mock_backup.backup_resource_storage_configs_non_crr.get.side_effect = lambda *a, **kw: next(
        configs
    )
    mock_backup.backup_policies.list.return_value = iter([])
    mock_backup.backup_protected_items.list.return_value = iter([])

    with patch("collectors.backup_posture.RecoveryServicesClient", return_value=mock_rs):
        with patch(
            "collectors.backup_posture.RecoveryServicesBackupClient", return_value=mock_backup
        ):
            collector = BackupPostureCollector(SUB_ID, MagicMock())
            collector._rs_client = mock_rs
            collector._backup_client = mock_backup

    result = collector.collect()
    assert result.redundancy_breakdown["GRS"] == 1
    assert result.redundancy_breakdown["LRS"] == 1


def test_collect_policy_count():
    vaults = [_make_vault()]
    policies = [_make_policy_vm_daily("P1"), _make_policy_vm_daily("P2")]
    collector = _make_collector(vaults=vaults, policies=policies)
    result = collector.collect()
    assert result.policy_count == 2


def test_collect_policy_workload_type_vm():
    vaults = [_make_vault()]
    policies = [_make_policy_vm_daily()]
    collector = _make_collector(vaults=vaults, policies=policies)
    result = collector.collect()
    assert result.policies[0].workload_type == "VM"


def test_collect_policy_retention_fields():
    vaults = [_make_vault()]
    policies = [
        _make_policy_vm_daily(daily_days=7, weekly_weeks=4, monthly_months=6, yearly_years=1)
    ]
    collector = _make_collector(vaults=vaults, policies=policies)
    result = collector.collect()
    p = result.policies[0]
    assert p.daily_retention_days == 7
    assert p.weekly_retention_weeks == 4
    assert p.monthly_retention_months == 6
    assert p.yearly_retention_years == 1


def test_collect_policy_schedule_frequency():
    vaults = [_make_vault()]
    policies = [_make_policy_vm_daily()]
    collector = _make_collector(vaults=vaults, policies=policies)
    result = collector.collect()
    assert result.policies[0].schedule_frequency == "Daily"


def test_collect_policy_schedule_time_iso():
    vaults = [_make_vault()]
    policies = [_make_policy_vm_daily()]
    collector = _make_collector(vaults=vaults, policies=policies)
    result = collector.collect()
    assert result.policies[0].schedule_time is not None
    assert "2024" in result.policies[0].schedule_time


def test_collect_protected_item_count():
    vaults = [_make_vault()]
    items = [_make_protected_item_vm("pi-1"), _make_protected_item_vm("pi-2")]
    collector = _make_collector(vaults=vaults, protected_items=items)
    result = collector.collect()
    assert result.protected_item_count == 2


def test_collect_protected_item_workload_type():
    vaults = [_make_vault()]
    items = [_make_protected_item_vm()]
    collector = _make_collector(vaults=vaults, protected_items=items)
    result = collector.collect()
    assert result.protected_items[0].workload_type == "VM"


def test_collect_protected_item_policy_name_extracted():
    vaults = [_make_vault()]
    items = [_make_protected_item_vm()]
    collector = _make_collector(vaults=vaults, protected_items=items)
    result = collector.collect()
    assert result.protected_items[0].policy_name == "DailyPolicy"


def test_collect_protected_item_last_backup_time_iso():
    dt = datetime(2024, 6, 15, 12, 0, tzinfo=timezone.utc)
    vaults = [_make_vault()]
    items = [_make_protected_item_vm(last_backup_time=dt)]
    collector = _make_collector(vaults=vaults, protected_items=items)
    result = collector.collect()
    assert "2024-06-15" in result.protected_items[0].last_backup_time


def test_collect_workload_breakdown():
    vaults = [_make_vault()]
    items = [_make_protected_item_vm("pi-1"), _make_protected_item_vm("pi-2")]
    collector = _make_collector(vaults=vaults, protected_items=items)
    result = collector.collect()
    assert result.workload_breakdown.get("VM") == 2


def test_protection_gap_all_protected():
    vaults = [_make_vault()]
    items = [
        _make_protected_item_vm("pi-1", vm_id=_VM_ID_1, protection_state="Protected"),
        _make_protected_item_vm("pi-2", vm_id=_VM_ID_2, protection_state="Protected"),
    ]
    collector = _make_collector(
        vaults=vaults,
        protected_items=items,
        vm_resource_ids=[_VM_ID_1, _VM_ID_2],
    )
    result = collector.collect()
    assert result.protection_coverage_pct == 100.0
    assert result.unprotected_vm_count == 0
    assert result.unprotected_vms == []


def test_protection_gap_none_protected():
    vaults = [_make_vault()]
    collector = _make_collector(
        vaults=vaults,
        protected_items=[],
        vm_resource_ids=[_VM_ID_1, _VM_ID_2],
    )
    result = collector.collect()
    assert result.protection_coverage_pct == 0.0
    assert result.unprotected_vm_count == 2


def test_protection_gap_partial():
    vaults = [_make_vault()]
    items = [
        _make_protected_item_vm("pi-1", vm_id=_VM_ID_1, protection_state="Protected"),
    ]
    collector = _make_collector(
        vaults=vaults,
        protected_items=items,
        vm_resource_ids=[_VM_ID_1, _VM_ID_2, _VM_ID_3],
    )
    result = collector.collect()
    # 1 of 3 protected = 33.3%
    assert result.total_vm_count == 3
    assert result.unprotected_vm_count == 2
    assert round(result.protection_coverage_pct, 1) == 33.3


def test_protection_gap_stopped_counts_as_unprotected():
    """A VM with ProtectionStopped should NOT count as protected."""
    vaults = [_make_vault()]
    items = [
        _make_protected_item_vm("pi-1", vm_id=_VM_ID_1, protection_state="ProtectionStopped"),
    ]
    collector = _make_collector(
        vaults=vaults,
        protected_items=items,
        vm_resource_ids=[_VM_ID_1],
    )
    result = collector.collect()
    assert result.protection_coverage_pct == 0.0
    assert result.unprotected_vm_count == 1


def test_protection_gap_error_state_counts_as_unprotected():
    vaults = [_make_vault()]
    items = [
        _make_protected_item_vm("pi-1", vm_id=_VM_ID_1, protection_state="ProtectionError"),
    ]
    collector = _make_collector(
        vaults=vaults,
        protected_items=items,
        vm_resource_ids=[_VM_ID_1],
    )
    result = collector.collect()
    assert result.unprotected_vm_count == 1


def test_protection_gap_skipped_when_no_vm_ids():
    """Gap fields should stay at defaults when vm_resource_ids is not provided."""
    vaults = [_make_vault()]
    items = [_make_protected_item_vm()]
    collector = _make_collector(vaults=vaults, protected_items=items)  # no vm_resource_ids
    result = collector.collect()
    assert result.total_vm_count == 0
    assert result.protection_coverage_pct == 0.0


def test_protection_gap_vm_id_case_insensitive():
    """Comparison should be case-insensitive (ARM IDs vary in case)."""
    mixed_case_id = _VM_ID_1.upper()
    vaults = [_make_vault()]
    items = [_make_protected_item_vm("pi-1", vm_id=_VM_ID_1, protection_state="Protected")]
    collector = _make_collector(
        vaults=vaults,
        protected_items=items,
        vm_resource_ids=[mixed_case_id],
    )
    result = collector.collect()
    assert result.protection_coverage_pct == 100.0


def test_collect_skips_bad_vault_without_crashing():
    bad_vault = MagicMock()
    bad_vault.name = "bad-vault"
    bad_vault.location = "eastus"
    type(bad_vault).id = PropertyMock(side_effect=Exception("API error"))

    good_vault = _make_vault("good-vault")

    mock_rs = MagicMock()
    mock_rs.vaults.list_by_subscription_id.return_value = iter([bad_vault, good_vault])

    mock_backup = MagicMock()
    mock_backup.backup_resource_storage_configs_non_crr.get.return_value = _make_storage_config()
    mock_backup.backup_policies.list.return_value = iter([])
    mock_backup.backup_protected_items.list.return_value = iter([])

    with patch("collectors.backup_posture.RecoveryServicesClient", return_value=mock_rs):
        with patch(
            "collectors.backup_posture.RecoveryServicesBackupClient",
            return_value=mock_backup,
        ):
            collector = BackupPostureCollector(SUB_ID, MagicMock())
            collector._rs_client = mock_rs
            collector._backup_client = mock_backup

    result = collector.collect()
    assert result.vault_count == 1
    assert result.vaults[0].name == "good-vault"


def test_collect_handles_vault_list_http_error():
    from azure.core.exceptions import HttpResponseError

    mock_rs = MagicMock()
    mock_rs.vaults.list_by_subscription_id.side_effect = HttpResponseError(message="Forbidden")
    mock_backup = MagicMock()

    with patch("collectors.backup_posture.RecoveryServicesClient", return_value=mock_rs):
        with patch(
            "collectors.backup_posture.RecoveryServicesBackupClient",
            return_value=mock_backup,
        ):
            collector = BackupPostureCollector(SUB_ID, MagicMock())
            collector._rs_client = mock_rs
            collector._backup_client = mock_backup

    # Should not raise — just return an empty inventory.
    result = collector.collect()
    assert result.vault_count == 0


def test_extract_schedule_daily():
    sched = MagicMock()
    sched.schedule_run_frequency = "Daily"
    sched.schedule_run_times = [datetime(2024, 1, 1, 2, 0, tzinfo=timezone.utc)]

    props = MagicMock()
    props.schedule_policy = sched
    props.sub_protection_policy = None

    freq, time_str = _extract_schedule(props)
    assert freq == "Daily"
    assert "2024" in time_str


def test_extract_schedule_none_when_no_policy():
    props = MagicMock()
    props.schedule_policy = None
    props.sub_protection_policy = None
    freq, time_str = _extract_schedule(props)
    assert freq is None
    assert time_str is None


def test_extract_schedule_from_sub_policy():
    """AzureVmWorkloadProtectionPolicy — schedule is in sub_protection_policy."""
    sched = MagicMock()
    sched.schedule_run_frequency = "Weekly"
    sched.schedule_run_times = []

    sub_policy = MagicMock()
    sub_policy.schedule_policy = sched

    props = MagicMock()
    props.schedule_policy = None
    props.sub_protection_policy = [sub_policy]

    freq, _ = _extract_schedule(props)
    assert freq == "Weekly"


def test_extract_retention_long_term():
    ret = MagicMock()
    _set_retention_tier(ret, "daily_schedule", 30)
    _set_retention_tier(ret, "weekly_schedule", 12)
    _set_retention_tier(ret, "monthly_schedule", 6)
    _set_retention_tier(ret, "yearly_schedule", 2)

    # Ensure SimpleRetentionPolicy path is skipped
    ret.retention_count = None

    props = MagicMock()
    props.retention_policy = ret
    props.sub_protection_policy = None

    daily, weekly, monthly, yearly = _extract_retention(props)
    assert daily == 30
    assert weekly == 12
    assert monthly == 6
    assert yearly == 2


def test_extract_retention_simple():
    ret = MagicMock()
    ret.retention_count = 14

    props = MagicMock()
    props.retention_policy = ret
    props.sub_protection_policy = None

    daily, weekly, monthly, yearly = _extract_retention(props)
    assert daily == 14
    assert weekly is None
    assert monthly is None
    assert yearly is None


def test_extract_retention_none_when_missing():
    props = MagicMock()
    props.retention_policy = None
    props.sub_protection_policy = None

    result = _extract_retention(props)
    assert result == (None, None, None, None)


def test_extract_retention_missing_tier_returns_none():
    """A policy with only daily configured should return None for others."""
    ret = MagicMock()
    ret.retention_count = None
    _set_retention_tier(ret, "daily_schedule", 7)
    ret.weekly_schedule = None
    ret.monthly_schedule = None
    ret.yearly_schedule = None

    props = MagicMock()
    props.retention_policy = ret
    props.sub_protection_policy = None

    daily, weekly, monthly, yearly = _extract_retention(props)
    assert daily == 7
    assert weekly is None
    assert monthly is None
    assert yearly is None


def test_schedule_retention_count_valid():
    schedule = MagicMock()
    schedule.retention_duration = MagicMock()
    schedule.retention_duration.count = 30
    assert _schedule_retention_count(schedule) == 30


def test_schedule_retention_count_none_schedule():
    assert _schedule_retention_count(None) is None


def test_schedule_retention_count_none_duration():
    schedule = MagicMock()
    schedule.retention_duration = None
    assert _schedule_retention_count(schedule) is None

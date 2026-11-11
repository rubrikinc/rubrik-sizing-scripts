"""SDK enum members must reach the discovery data as plain API values.

``str()`` of an Azure SDK enum member gives ``Kind.STORAGE_V2``. These tests feed the collectors
real SDK enum members, which the mocks elsewhere do not.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from azure.mgmt.compute.models import OperatingSystemTypes
from azure.mgmt.storage.models import AccessTier, Kind, SkuName, StorageAccount
from collectors.compute import ComputeCollector
from collectors.storage import StorageCollector
from collectors.utils import enum_text

from tests.test_compute import _VM_ID_1, SUB_ID, _make_disk, _make_vm


def test_enum_text_returns_the_api_value():
    assert enum_text(AccessTier.HOT) == "Hot"
    assert enum_text(Kind.STORAGE_V2) == "StorageV2"
    assert enum_text("StorageV2") == "StorageV2"
    assert enum_text(None) is None


def test_sdk_enum_str_is_not_the_api_value():
    assert str(Kind.STORAGE_V2) != "StorageV2"


def _storage_collector(account):
    storage = MagicMock()
    storage.storage_accounts.list.return_value = iter([account])
    storage.blob_services.get_service_properties.side_effect = Exception("not needed")
    storage.blob_inventory_policies.get.side_effect = Exception("not needed")
    with (
        patch("collectors.storage.StorageManagementClient", return_value=storage),
        patch("collectors.storage.MonitorManagementClient", return_value=MagicMock()),
    ):
        return StorageCollector(SUB_ID, MagicMock(), collect_capacity=False)


def test_storage_account_kind_tier_and_sku_are_api_values():
    account = StorageAccount(
        {
            "id": f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
            "name": "sa1",
            "location": "westus",
            "kind": "StorageV2",
            "sku": {"name": "Standard_LRS", "tier": "Standard"},
            "properties": {"accessTier": "Hot"},
        }
    )
    assert account.kind is Kind.STORAGE_V2
    assert account.access_tier is AccessTier.HOT
    assert account.sku.name is SkuName.STANDARD_LRS

    (info,) = _storage_collector(account)._list_accounts()
    assert info.kind == "StorageV2"
    assert info.access_tier == "Hot"
    assert info.sku == "Standard_LRS"
    assert info.redundancy == "LRS"
    assert type(info.kind) is str and type(info.sku) is str


def test_vm_os_type_is_the_api_value():
    vm = _make_vm(_VM_ID_1, "vm-prod-01", os_type=OperatingSystemTypes.LINUX)
    disk = _make_disk("osdisk", 64, "Premium_LRS", _VM_ID_1)
    client = MagicMock()
    client.virtual_machines.list_all.return_value = iter([vm])
    client.disks.list.return_value = iter([disk])
    rm = MagicMock()
    rm.resources.list.return_value = iter([])
    with (
        patch("collectors.compute.ComputeManagementClient", return_value=client),
        patch("collectors.compute.ResourceManagementClient", return_value=rm),
    ):
        collector = ComputeCollector(SUB_ID, MagicMock(), None)
    collector._client = client
    collector._rm = rm

    inventory = collector.collect()
    assert [v.os_type for v in inventory.vms] == ["Linux"]
    assert inventory.os_breakdown == {"Linux": 1}


def test_backup_protection_state_and_workload_use_api_values():
    from azure.mgmt.recoveryservicesbackup.models import BackupManagementType, ProtectionState

    from tests.test_backup_posture import _make_collector, _make_protected_item_vm, _make_vault

    item = _make_protected_item_vm(protection_state=ProtectionState.PROTECTION_STOPPED)
    item.properties.backup_management_type = BackupManagementType.AZURE_IAAS_VM
    result = _make_collector(vaults=[_make_vault()], protected_items=[item]).collect()

    assert result.protected_items[0].protection_state == "ProtectionStopped"
    assert result.protected_items[0].workload_type == "VM"

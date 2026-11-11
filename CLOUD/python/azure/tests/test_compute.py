"""Tests for collectors/compute.py — Azure SDK is fully mocked."""

from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from collectors.compute import (
    ComputeCollector,
    ComputeInventory,
    DiskInfo,
    SqlOnVmInfo,
    VMInfo,
    _normalise_sku,
    _vm_size_family,
)

SUB_ID = "00000000-0000-0000-0000-000000000001"

_VM_ID_1 = (
    f"/subscriptions/{SUB_ID}/resourceGroups/rg-prod"
    "/providers/Microsoft.Compute/virtualMachines/vm-prod-01"
)
_VM_ID_2 = (
    f"/subscriptions/{SUB_ID}/resourceGroups/rg-dev"
    "/providers/Microsoft.Compute/virtualMachines/vm-dev-01"
)


def _make_disk(name, size_gb, sku, managed_by, location="eastus"):
    d = MagicMock()
    d.name = name
    d.disk_size_gb = size_gb
    d.sku = MagicMock()
    d.sku.name = sku
    d.managed_by = managed_by
    d.location = location
    d.encryption = MagicMock()
    d.encryption.type = "EncryptionAtRestWithPlatformKey"
    return d


def _make_vm(
    vm_id,
    name,
    rg_from_id=None,
    location="eastus",
    vm_size="Standard_D4s_v3",
    os_type="Linux",
    tags=None,
    os_disk_name="osdisk",
):
    vm = MagicMock()
    vm.id = vm_id
    vm.name = name
    vm.location = location
    vm.tags = tags or {}

    vm.hardware_profile = MagicMock()
    vm.hardware_profile.vm_size = vm_size

    vm.storage_profile = MagicMock()
    vm.storage_profile.os_disk = MagicMock()
    vm.storage_profile.os_disk.os_type = os_type
    vm.storage_profile.os_disk.name = os_disk_name
    return vm


def _make_sql_vm_resource(
    vm_id,
    sql_image_sku="Enterprise",
    offer="SQL2019-WS2022",
    license_type="PAYG",
    management="Full",
    res_id=None,
):
    """Build a GenericResource-like mock for a Microsoft.SqlVirtualMachine resource."""
    res = MagicMock()
    res.id = res_id or (
        vm_id.replace(
            "Microsoft.Compute/virtualMachines", "Microsoft.SqlVirtualMachine/sqlVirtualMachines"
        )
    )
    res.name = vm_id.rsplit("/", 1)[-1]
    res.properties = {
        "virtualMachineResourceId": vm_id,
        "sqlImageSku": sql_image_sku,
        "sqlImageOffer": offer,
        "sqlServerLicenseType": license_type,
        "sqlManagement": management,
    }
    return res


def _make_collector(vms=None, disks=None, regions=None, sql_vms=None):
    """Build a ComputeCollector with mocked Azure clients."""
    mock_compute_client = MagicMock()
    mock_compute_client.virtual_machines.list_all.return_value = iter(vms or [])
    mock_compute_client.disks.list.return_value = iter(disks or [])

    mock_rm_client = MagicMock()
    mock_rm_client.resources.list.return_value = iter(sql_vms or [])

    with (
        patch(
            "collectors.compute.ComputeManagementClient",
            return_value=mock_compute_client,
        ),
        patch(
            "collectors.compute.ResourceManagementClient",
            return_value=mock_rm_client,
        ),
    ):
        collector = ComputeCollector(SUB_ID, MagicMock(), regions)
        # Swap out the already-constructed clients so collect() uses our mocks.
        collector._client = mock_compute_client
        collector._rm = mock_rm_client
    return collector


def test_collect_returns_inventory():
    collector = _make_collector()
    result = collector.collect()
    assert isinstance(result, ComputeInventory)
    assert result.subscription_id == SUB_ID


def test_collect_empty_subscription():
    collector = _make_collector()
    result = collector.collect()
    assert result.total_vms == 0
    assert result.total_disk_tb == 0.0


def test_collect_counts_vms():
    vms = [_make_vm(_VM_ID_1, "vm-prod-01"), _make_vm(_VM_ID_2, "vm-dev-01")]
    collector = _make_collector(vms=vms)
    result = collector.collect()
    assert result.total_vms == 2


def test_collect_attaches_disks_to_correct_vm():
    disk = _make_disk("osdisk", 128, "Premium_LRS", _VM_ID_1.lower())
    vm = _make_vm(_VM_ID_1, "vm-prod-01", os_disk_name="osdisk")
    collector = _make_collector(vms=[vm], disks=[disk])
    result = collector.collect()

    assert len(result.vms) == 1
    assert len(result.vms[0].disks) == 1
    assert result.vms[0].disks[0].name == "osdisk"
    assert result.vms[0].disks[0].os_disk is True


def test_collect_marks_os_disk():
    os_disk = _make_disk("osdisk", 128, "Premium_LRS", _VM_ID_1.lower())
    data_disk = _make_disk("datadisk-0", 512, "Standard_LRS", _VM_ID_1.lower())
    vm = _make_vm(_VM_ID_1, "vm-prod-01", os_disk_name="osdisk")
    collector = _make_collector(vms=[vm], disks=[os_disk, data_disk])
    result = collector.collect()

    disks_by_name = {d.name: d for d in result.vms[0].disks}
    assert disks_by_name["osdisk"].os_disk is True
    assert disks_by_name["datadisk-0"].os_disk is False


def test_collect_total_disk_tb():
    # 512 GB + 512 GB = 1024 GB = 1.0 TB
    disk1 = _make_disk("d1", 512, "Premium_LRS", _VM_ID_1.lower())
    disk2 = _make_disk("d2", 512, "Standard_LRS", _VM_ID_1.lower())
    vm = _make_vm(_VM_ID_1, "vm-prod-01")
    collector = _make_collector(vms=[vm], disks=[disk1, disk2])
    result = collector.collect()
    assert result.total_disk_tb == 1.0


def test_disk_size_bytes_derived_and_tb():
    disk = _make_disk("d1", 512, "Premium_LRS", _VM_ID_1.lower())
    vm = _make_vm(_VM_ID_1, "vm-prod-01")
    collector = _make_collector(vms=[vm], disks=[disk])
    result = collector.collect()

    d = result.vms[0].disks[0]
    assert d.disk_size_bytes_derived == 512 * 1024**3
    assert d.disk_size_tb == round(512 / 1024, 3)
    assert d.disk_size_gb_decimal == 549.756  # 512 GiB in decimal GB
    assert d.disk_size_tb_decimal == 0.5498
    assert result.vms[0].total_disk_gb_decimal == 549.756
    assert result.total_disk_gb_decimal == 549.756
    assert result.total_disk_tb_decimal == 0.5498


def test_vm_total_disk_bytes_derived_sums_disks():
    disk1 = _make_disk("d1", 512, "Premium_LRS", _VM_ID_1.lower())
    disk2 = _make_disk("d2", 512, "Standard_LRS", _VM_ID_1.lower())
    vm = _make_vm(_VM_ID_1, "vm-prod-01")
    collector = _make_collector(vms=[vm], disks=[disk1, disk2])
    result = collector.collect()

    assert result.vms[0].total_disk_bytes_derived == (512 + 512) * 1024**3


def test_collect_region_filter_excludes_vms():
    vm_east = _make_vm(_VM_ID_1, "vm-east", location="eastus")
    vm_west = _make_vm(_VM_ID_2, "vm-west", location="westus2")
    collector = _make_collector(vms=[vm_east, vm_west], regions=["eastus"])
    result = collector.collect()
    assert result.total_vms == 1
    assert result.vms[0].name == "vm-east"


def test_collect_region_filter_excludes_disks():
    # Disk is in westus2 but we only want eastus — it should not appear.
    disk = _make_disk("d1", 512, "Premium_LRS", _VM_ID_1.lower(), location="westus2")
    vm = _make_vm(_VM_ID_1, "vm-east", location="eastus")
    collector = _make_collector(vms=[vm], disks=[disk], regions=["eastus"])
    result = collector.collect()
    assert len(result.vms[0].disks) == 0


def test_collect_os_breakdown():
    vms = [
        _make_vm(_VM_ID_1, "vm1", os_type="Linux"),
        _make_vm(_VM_ID_2, "vm2", os_type="Windows"),
    ]
    collector = _make_collector(vms=vms)
    result = collector.collect()
    assert result.os_breakdown.get("Linux") == 1
    assert result.os_breakdown.get("Windows") == 1


def test_collect_sku_breakdown():
    disk = _make_disk("d1", 128, "Premium_LRS", _VM_ID_1.lower())
    vm = _make_vm(_VM_ID_1, "vm1")
    collector = _make_collector(vms=[vm], disks=[disk])
    result = collector.collect()
    assert result.sku_breakdown.get("Premium SSD") == 1


def test_collect_region_breakdown():
    vm = _make_vm(_VM_ID_1, "vm1", location="eastus")
    collector = _make_collector(vms=[vm])
    result = collector.collect()
    assert result.region_breakdown.get("eastus") == 1


def test_collect_tag_summary_populated():
    vm = _make_vm(_VM_ID_1, "vm1", tags={"env": "prod"})
    collector = _make_collector(vms=[vm])
    result = collector.collect()
    assert result.tag_summary is not None
    assert "env" in result.tag_summary.key_coverage


def test_collect_skips_bad_disk_without_crashing():
    bad_disk = MagicMock()
    bad_disk.name = "bad-disk"
    bad_disk.managed_by = _VM_ID_1.lower()
    bad_disk.location = "eastus"
    # Accessing .disk_size_gb raises unexpectedly
    type(bad_disk).disk_size_gb = PropertyMock(side_effect=Exception("API error"))

    vm = _make_vm(_VM_ID_1, "vm1")
    collector = _make_collector(vms=[vm], disks=[bad_disk])
    result = collector.collect()
    # The VM still appears, just with no disks.
    assert result.total_vms == 1
    assert len(result.vms[0].disks) == 0


def test_collect_skips_bad_vm_without_crashing():
    bad_vm = MagicMock()
    bad_vm.name = "bad-vm"
    bad_vm.location = "eastus"
    type(bad_vm).id = PropertyMock(side_effect=Exception("API error"))

    good_vm = _make_vm(_VM_ID_2, "good-vm")
    collector = _make_collector(vms=[bad_vm, good_vm])
    result = collector.collect()
    assert result.total_vms == 1
    assert result.vms[0].name == "good-vm"


@pytest.mark.parametrize(
    "size,expected",
    [
        ("Standard_D4s_v3", "Standard_D family"),
        ("Standard_E8s_v4", "Standard_E family"),
        ("Basic_A2", "Basic_A family"),
        ("Unknown", "Unknown"),
        ("", "Unknown"),
    ],
)
def test_vm_size_family(size, expected):
    assert _vm_size_family(size) == expected


@pytest.mark.parametrize(
    "sku,expected",
    [
        ("Premium_LRS", "Premium SSD"),
        ("Standard_LRS", "Standard HDD"),
        ("StandardSSD_LRS", "Standard SSD"),
        ("UltraSSD_LRS", "Ultra SSD"),
        ("SomeNewSku", "SomeNewSku"),  # pass-through for unknown SKUs
    ],
)
def test_normalise_sku(sku, expected):
    assert _normalise_sku(sku) == expected


# ── SQL-Server-on-VM detection ────────────────────────────────────────────────


def test_sql_vm_flags_matching_vm():
    vm = _make_vm(_VM_ID_1, "vm-sql-01", os_type="Windows")
    sql_res = _make_sql_vm_resource(_VM_ID_1)
    collector = _make_collector(vms=[vm], sql_vms=[sql_res])
    result = collector.collect()

    assert result.vms[0].sql_server is not None
    assert result.vms[0].sql_server.edition == "Enterprise"
    assert result.vms[0].sql_server.image_offer == "SQL2019-WS2022"
    assert result.vms[0].sql_server.license_type == "PAYG"
    assert result.vms[0].sql_server.sql_management == "Full"


def test_non_sql_vm_has_no_sql_server():
    vm = _make_vm(_VM_ID_2, "vm-plain-01")
    sql_res = _make_sql_vm_resource(_VM_ID_1)  # references a different VM
    collector = _make_collector(vms=[vm], sql_vms=[sql_res])
    result = collector.collect()
    assert result.vms[0].sql_server is None


def test_sql_vm_id_match_is_case_insensitive():
    # SQL VM resource references the VM id in a different case than list_all returns.
    vm = _make_vm(_VM_ID_1.upper(), "vm-sql-01")
    sql_res = _make_sql_vm_resource(_VM_ID_1.lower())
    collector = _make_collector(vms=[vm], sql_vms=[sql_res])
    result = collector.collect()
    assert result.vms[0].sql_server is not None


def test_sql_vm_rollups():
    vms = [
        _make_vm(_VM_ID_1, "vm-sql-ent"),
        _make_vm(_VM_ID_2, "vm-sql-std"),
    ]
    sql_vms = [
        _make_sql_vm_resource(_VM_ID_1, sql_image_sku="Enterprise"),
        _make_sql_vm_resource(_VM_ID_2, sql_image_sku="Standard"),
    ]
    collector = _make_collector(vms=vms, sql_vms=sql_vms)
    result = collector.collect()

    assert result.total_sql_vms == 2
    assert result.sql_vm_edition_breakdown == {"Enterprise": 1, "Standard": 1}


def test_sql_vm_no_resources_means_no_sql():
    vm = _make_vm(_VM_ID_1, "vm1")
    collector = _make_collector(vms=[vm], sql_vms=[])
    result = collector.collect()
    assert result.total_sql_vms == 0
    assert result.vms[0].sql_server is None


def test_sql_vm_listing_error_degrades_gracefully():
    vm = _make_vm(_VM_ID_1, "vm1")
    collector = _make_collector(vms=[vm])
    collector._rm.resources.list.side_effect = Exception("RBAC denied")
    result = collector.collect()
    # VM still collected; SQL detection just yields nothing.
    assert result.total_vms == 1
    assert result.vms[0].sql_server is None
    assert result.total_sql_vms == 0


def test_sql_vm_resource_missing_vm_ref_is_skipped():
    vm = _make_vm(_VM_ID_1, "vm1")
    bad_res = _make_sql_vm_resource(_VM_ID_1)
    bad_res.properties = {"sqlImageSku": "Enterprise"}  # no virtualMachineResourceId
    collector = _make_collector(vms=[vm], sql_vms=[bad_res])
    result = collector.collect()
    assert result.vms[0].sql_server is None


def test_sql_vm_properties_as_model_object():
    # Some SDK builds return a model object (with additional_properties) not a dict.
    vm = _make_vm(_VM_ID_1, "vm1")
    res = MagicMock()
    res.id = "/sqlvm/res-1"
    res.name = "vm1"
    props_obj = MagicMock(spec=["additional_properties"])
    props_obj.additional_properties = {
        "virtualMachineResourceId": _VM_ID_1,
        "sqlImageSku": "Developer",
        "sqlImageOffer": "SQL2022-WS2022",
        "sqlServerLicenseType": "AHUB",
        "sqlManagement": "LightWeight",
    }
    res.properties = props_obj
    collector = _make_collector(vms=[vm], sql_vms=[res])
    result = collector.collect()
    assert result.vms[0].sql_server is not None
    assert result.vms[0].sql_server.edition == "Developer"
    assert result.vms[0].sql_server.license_type == "AHUB"


def test_sql_on_vm_info_dataclass_shape():
    info = SqlOnVmInfo(
        resource_id="/sqlvm/1",
        edition="Standard",
        image_offer="SQL2019-WS2022",
        license_type="PAYG",
        sql_management="Full",
    )
    assert info.edition == "Standard"


def test_a_vm_size_the_sdk_returns_as_an_enum_member_is_written_as_its_api_value():
    from azure.mgmt.compute.models import VirtualMachineSizeTypes

    vms = [
        _make_vm(_VM_ID_1, "vm-a", vm_size=VirtualMachineSizeTypes.STANDARD_B1_S),
        _make_vm(_VM_ID_2, "vm-b", vm_size="Standard_D32s_v5"),
    ]
    sizes = [vm.vm_size for vm in _make_collector(vms=vms).collect().vms]
    assert sizes == ["Standard_B1s", "Standard_D32s_v5"]


def test_a_vm_with_no_size_is_unknown():
    vm = _make_vm(_VM_ID_1, "vm-a", vm_size=None)
    assert _make_collector(vms=[vm]).collect().vms[0].vm_size == "Unknown"

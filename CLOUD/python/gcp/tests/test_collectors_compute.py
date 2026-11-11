"""Tests for collectors/compute.py — all GCP SDK calls are mocked."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from collectors.compute import ComputeCollector

from tests.conftest import PROJECT_ID, REGION, ZONE

_INSTANCES_CLIENT = "google.cloud.compute_v1.InstancesClient"
_DISKS_CLIENT = "google.cloud.compute_v1.DisksClient"
_AGG_INSTANCES_REQ = "google.cloud.compute_v1.AggregatedListInstancesRequest"
_AGG_DISKS_REQ = "google.cloud.compute_v1.AggregatedListDisksRequest"


def _make_attached_disk(name: str, boot: bool = False, licenses: list[str] = None):
    d = MagicMock()
    d.boot = boot
    d.source = f"projects/{PROJECT_ID}/zones/{ZONE}/disks/{name}"
    d.licenses = licenses or []
    return d


def _make_instance(
    name: str,
    zone: str = ZONE,
    machine_type: str = f"zones/{ZONE}/machineTypes/n2-standard-4",
    status: str = "RUNNING",
    labels: dict = None,
    disks: list = None,
):
    inst = MagicMock()
    inst.name = name
    inst.zone = zone
    inst.machine_type = machine_type
    inst.status = status
    inst.labels = labels or {}
    inst.disks = disks or []
    return inst


def _make_disk(name: str, size_gb: int = 100, disk_type: str = "pd-ssd"):
    disk = MagicMock()
    disk.name = name
    disk.size_gb = size_gb
    disk.type_ = f"zones/{ZONE}/diskTypes/{disk_type}"
    disk.status = "READY"
    return disk


def _make_scoped_instances(zone: str, instances: list):
    scoped = MagicMock()
    scoped.instances = instances
    return (f"zones/{zone}", scoped)


def _make_scoped_disks(zone: str, disks: list):
    scoped = MagicMock()
    scoped.disks = disks
    return (f"zones/{zone}", scoped)


def test_compute_collector_empty_project():
    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter([])
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([])

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()

    assert result.total_instances == 0
    assert result.instances == []
    assert result.total_disk_tb == 0.0


def test_compute_collector_counts_instances():
    disks = [_make_disk("disk-1"), _make_disk("disk-2")]
    attached = [
        _make_attached_disk("disk-1", boot=True),
        _make_attached_disk("disk-2"),
    ]
    instances = [_make_instance("vm-1", disks=attached), _make_instance("vm-2")]

    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter([_make_scoped_instances(ZONE, instances)])
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([_make_scoped_disks(ZONE, disks)])

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()

    assert result.total_instances == 2
    assert result.project_id == PROJECT_ID


def test_compute_collector_machine_family_breakdown():
    instances = [
        _make_instance("vm-n2", machine_type=f"zones/{ZONE}/machineTypes/n2-standard-4"),
        _make_instance("vm-e2", machine_type=f"zones/{ZONE}/machineTypes/e2-medium"),
        _make_instance("vm-n2b", machine_type=f"zones/{ZONE}/machineTypes/n2-standard-8"),
    ]

    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter([_make_scoped_instances(ZONE, instances)])
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([])

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()

    assert result.machine_family_breakdown["n2"] == 2
    assert result.machine_family_breakdown["e2"] == 1


def test_compute_collector_os_detection_windows():
    attached = [
        _make_attached_disk(
            "boot-disk",
            boot=True,
            licenses=[
                "https://www.googleapis.com/compute/v1/projects/windows-cloud/global/licenses/windows-server-2022"
            ],
        )
    ]
    instances = [_make_instance("vm-win", disks=attached)]

    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter([_make_scoped_instances(ZONE, instances)])
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([])

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()

    assert result.instances[0].os_type == "windows"
    assert result.os_breakdown.get("windows", 0) == 1


def test_compute_collector_region_filter():
    instances_us = [_make_instance("vm-us", zone="us-central1-a")]
    instances_eu = [_make_instance("vm-eu", zone="europe-west1-b")]

    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter(
        [
            ("zones/us-central1-a", _scoped_instances(instances_us)),
            ("zones/europe-west1-b", _scoped_instances(instances_eu)),
        ]
    )
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([])

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock(), regions=["us-central1"]).collect()

    assert result.total_instances == 1
    assert result.instances[0].name == "vm-us"


def test_compute_collector_graceful_on_api_error():
    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.side_effect = Exception("403 permission denied")
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([])

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()

    assert result.total_instances == 0
    assert result.instances == []


def test_compute_collector_label_summary_populated():
    instances = [
        _make_instance("vm-1", labels={"env": "prod", "team": "eng"}),
        _make_instance("vm-2", labels={"env": "dev"}),
        _make_instance("vm-3", labels={}),
    ]

    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter([_make_scoped_instances(ZONE, instances)])
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([])

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()

    assert result.label_summary is not None
    assert result.label_summary.unlabelled_count == 1
    assert "env" in result.label_summary.key_coverage


def test_compute_collector_disk_total():
    disks_data = [_make_disk("d1", size_gb=100), _make_disk("d2", size_gb=200)]
    attached = [_make_attached_disk("d1", boot=True), _make_attached_disk("d2")]
    instances = [_make_instance("vm-1", disks=attached)]

    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter([_make_scoped_instances(ZONE, instances)])
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([_make_scoped_disks(ZONE, disks_data)])

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()

    assert result.instances[0].total_disk_gb == 300.0
    assert result.total_disk_tb == round(300.0 / 1000, 4)
    assert result.instances[0].total_disk_bytes_derived == 300.0 * 2**30
    assert result.instances[0].disks[0].size_bytes_derived == 100 * 2**30
    assert result.instances[0].disks[0].size_tb == round(100 / 1000, 4)
    assert result.instances[0].disks[1].size_bytes_derived == 200 * 2**30


# ── helpers ───────────────────────────────────────────────────────────────────


def _scoped_instances(instances: list):
    scoped = MagicMock()
    scoped.instances = instances
    return scoped


def test_same_disk_name_in_two_zones_not_conflated():
    zone_b = "us-central1-b"
    d_a = _make_disk("data", size_gb=100)
    d_b = _make_disk("data", size_gb=500)
    att_a = _make_attached_disk("data")
    att_b = _make_attached_disk("data")
    att_b.source = f"projects/{PROJECT_ID}/zones/{zone_b}/disks/data"
    inst_a = _make_instance("vm-a", disks=[att_a])
    inst_b = _make_instance("vm-b", zone=zone_b, disks=[att_b])

    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter(
        [_make_scoped_instances(ZONE, [inst_a]), _make_scoped_instances(zone_b, [inst_b])]
    )
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter(
        [_make_scoped_disks(ZONE, [d_a]), _make_scoped_disks(zone_b, [d_b])]
    )

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()

    sizes = {i.name: i.total_disk_gb for i in result.instances}
    assert sizes == {"vm-a": 100.0, "vm-b": 500.0}


def test_disk_listing_failure_is_recorded():
    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter(
        [_make_scoped_instances(ZONE, [_make_instance("vm-1", disks=[_make_attached_disk("d1")])])]
    )
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.side_effect = Exception("403 permission denied")

    collector = ComputeCollector(PROJECT_ID, MagicMock())
    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = collector.collect()

    assert result.total_instances == 1
    assert [e["collector"] for e in collector.errors] == ["compute_disks"]


def _run_with_disks(disks_data, instances):
    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter(
        [_make_scoped_instances(ZONE, instances)] if instances else []
    )
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([_make_scoped_disks(ZONE, disks_data)])
    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        return ComputeCollector(PROJECT_ID, MagicMock()).collect()


def test_unattached_disks_collected_and_counted_in_total():
    attached = _make_disk("d1", size_gb=100)
    attached.users = [f"projects/{PROJECT_ID}/zones/{ZONE}/instances/vm-1"]
    orphan = _make_disk("orphan", size_gb=400)
    orphan.users = []
    inst = _make_instance("vm-1", disks=[_make_attached_disk("d1", boot=True)])

    result = _run_with_disks([attached, orphan], [inst])

    assert [d.name for d in result.unattached_disks] == ["orphan"]
    assert result.total_unattached_disks == 1
    assert result.total_unattached_disk_tb == 0.4
    assert result.total_disk_tb == 0.5
    assert result.instances[0].total_disk_gb == 100.0


def test_unattached_disks_reported_with_no_instances():
    orphan = _make_disk("orphan", size_gb=250)
    orphan.users = []

    result = _run_with_disks([orphan], [])

    assert result.total_instances == 0
    assert result.total_unattached_disks == 1
    assert result.total_disk_tb == 0.25


def test_disks_keyed_by_self_link_even_if_aggregated_list_key_has_no_prefix():
    """Attached-disk lookup must not depend on the shape of the aggregated-list key."""
    disk = _make_disk("data", size_gb=100)
    disk.self_link = (
        f"https://www.googleapis.com/compute/v1/projects/{PROJECT_ID}/zones/{ZONE}/disks/data"
    )
    disk.users = ["x"]
    inst = _make_instance("vm-1", disks=[_make_attached_disk("data", boot=True)])

    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter([_make_scoped_instances(ZONE, [inst])])
    mock_disk_client = MagicMock()
    scoped = MagicMock()
    scoped.disks = [disk]
    mock_disk_client.aggregated_list.return_value = iter([(ZONE, scoped)])  # bare key

    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()

    assert result.instances[0].total_disk_gb == 100.0


def test_unattached_keys_do_not_accumulate_across_collect_calls():
    orphan = _make_disk("orphan", size_gb=10)
    orphan.users = []
    collector = ComputeCollector(PROJECT_ID, MagicMock())
    for _ in range(2):
        mock_inst_client = MagicMock()
        mock_inst_client.aggregated_list.return_value = iter([])
        mock_disk_client = MagicMock()
        mock_disk_client.aggregated_list.return_value = iter([_make_scoped_disks(ZONE, [orphan])])
        with (
            patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
            patch(_DISKS_CLIENT, return_value=mock_disk_client),
        ):
            result = collector.collect()
    assert result.total_unattached_disks == 1


# ── the order of the results does not depend on the order the API lists the zones in ──────────

import dataclasses  # noqa: E402
import itertools  # noqa: E402

import csv_export  # noqa: E402
import pytest  # noqa: E402

ZONES = ["us-central1-b", "europe-west1-c", "us-central1-a"]
_ZONE_ORDERS = list(itertools.permutations(ZONES))


def _instances_in(zone: str):
    """Two VMs per zone, listed by name in reverse, each with a label of its own."""
    return [
        _make_instance(f"vm-{zone[-1]}2", labels={f"label_{zone[-1]}2": "x"}),
        _make_instance(f"vm-{zone[-1]}1", labels={f"label_{zone[-1]}1": "x"}),
    ]


def _collect_in_order(zone_order, unattached=False):
    instances_pages = [_make_scoped_instances(z, _instances_in(z)) for z in zone_order]
    disk_pages = []
    for z in zone_order:
        disks = [_make_disk(f"disk-{z[-1]}2"), _make_disk(f"disk-{z[-1]}1")]
        for disk in disks:
            disk.users = []
            disk.labels = {}
            disk.disk_encryption_key = None
            disk.id = abs(hash(disk.name)) % 10**9
        disk_pages.append(_make_scoped_disks(z, disks))
    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter(instances_pages)
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter(disk_pages)
    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        return ComputeCollector(PROJECT_ID, MagicMock()).collect()


@pytest.mark.parametrize("zone_order", _ZONE_ORDERS)
def test_vms_are_in_zone_then_name_order_whatever_order_the_api_lists_the_zones(zone_order):
    result = _collect_in_order(zone_order)
    keys = [(i.zone, i.name) for i in result.instances]
    assert len(keys) == 6 and keys == sorted(keys)


@pytest.mark.parametrize("zone_order", _ZONE_ORDERS)
def test_unattached_disks_are_in_zone_then_name_order_whatever_order_the_api_lists_the_zones(
    zone_order,
):
    result = _collect_in_order(zone_order)
    keys = [(d.zone, d.name) for d in result.unattached_disks]
    assert len(keys) == 6 and keys == sorted(keys)


def test_the_csv_files_are_identical_whatever_order_the_api_lists_the_zones():
    def files(zone_order):
        inventory = dataclasses.asdict(_collect_in_order(zone_order))
        result = {"projects_scanned": [PROJECT_ID], "compute": [inventory]}
        return csv_export.build_csv_files(result, "stamp")

    first = files(_ZONE_ORDERS[0])
    for order in _ZONE_ORDERS[1:]:
        assert files(order) == first
    header = first["gce_vm_info-stamp.csv"].splitlines()[0]
    labels = [c.strip('"').split("Tag: ")[1] for c in header.split(",") if "Tag: " in c]
    assert labels == ["label_c1", "label_c2", "label_a1", "label_a2", "label_b1", "label_b2"]


def test_the_disks_of_one_vm_keep_the_order_the_vm_lists_them_in():
    disks = [_make_disk("disk-b"), _make_disk("disk-a")]
    attached = [_make_attached_disk("disk-b", boot=True), _make_attached_disk("disk-a")]
    mock_inst_client = MagicMock()
    mock_inst_client.aggregated_list.return_value = iter(
        [_make_scoped_instances(ZONE, [_make_instance("vm-1", disks=attached)])]
    )
    mock_disk_client = MagicMock()
    mock_disk_client.aggregated_list.return_value = iter([_make_scoped_disks(ZONE, disks)])
    with (
        patch(_INSTANCES_CLIENT, return_value=mock_inst_client),
        patch(_DISKS_CLIENT, return_value=mock_disk_client),
    ):
        result = ComputeCollector(PROJECT_ID, MagicMock()).collect()
    assert [d.name for d in result.instances[0].disks] == ["disk-b", "disk-a"]

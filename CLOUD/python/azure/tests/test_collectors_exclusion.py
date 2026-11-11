"""Tests for collectors/exclusion.py and its wiring into collectors/compute.py."""

import dataclasses
from unittest.mock import MagicMock, patch

import pytest
from collectors.compute import ComputeCollector
from collectors.exclusion import (
    EXCLUDE_TAG,
    REASON_PATTERN,
    REASON_TAG,
    VolumeExclusionEngine,
)

SUB_ID = "00000000-0000-0000-0000-000000000001"


class TestEngineTag:
    @pytest.mark.parametrize("value", ["true", "True", "TRUE", "yes", "y", "1", "exclude", "  true  "])
    def test_truthy_values_exclude(self, value):
        assert VolumeExclusionEngine().evaluate("disk", "vm", {EXCLUDE_TAG: value}) == REASON_TAG

    @pytest.mark.parametrize("value", ["false", "no", "0", "", "maybe"])
    def test_other_values_do_not_exclude(self, value):
        assert VolumeExclusionEngine().evaluate("disk", "vm", {EXCLUDE_TAG: value}) is None

    def test_absent_or_empty_tags_do_not_exclude(self):
        engine = VolumeExclusionEngine()
        assert engine.evaluate("disk", "vm", {}) is None
        assert engine.evaluate("disk", "vm", None) is None

    def test_none_tag_value_does_not_exclude(self):
        assert VolumeExclusionEngine().evaluate("d", "v", {EXCLUDE_TAG: None}) is None

    def test_tag_key_is_case_insensitive(self):
        # Azure tag names are case-insensitive, unlike AWS.
        engine = VolumeExclusionEngine()
        assert engine.evaluate("d", "v", {EXCLUDE_TAG.upper(): "true"}) == REASON_TAG
        assert engine.evaluate("d", "v", {"Rubrik:Sizing:Exclude": "true"}) == REASON_TAG

    def test_tag_wins_over_pattern(self):
        engine = VolumeExclusionEngine([r"scratch"])
        assert engine.evaluate("scratch-disk", "", {EXCLUDE_TAG: "true"}) == REASON_TAG


class TestEnginePatterns:
    def test_matches_disk_name(self):
        reason = VolumeExclusionEngine([r"^tmp-"]).evaluate("tmp-data", "vm-1", {})
        assert reason is not None
        assert reason.startswith(REASON_PATTERN)
        assert "^tmp-" in reason

    def test_matches_vm_name(self):
        reason = VolumeExclusionEngine([r"-scratch$"]).evaluate("data", "build-scratch", {})
        assert reason is not None
        assert reason.startswith(REASON_PATTERN)

    def test_no_match_returns_none(self):
        assert VolumeExclusionEngine([r"^tmp-"]).evaluate("data", "vm-1", {}) is None

    def test_empty_names_never_match(self):
        assert VolumeExclusionEngine([r".*"]).evaluate("", "", {}) is None

    def test_no_patterns_means_tag_only(self):
        assert VolumeExclusionEngine().evaluate("tmp-data", "scratch", {}) is None

    def test_invalid_pattern_is_skipped_with_warning(self, caplog):
        with caplog.at_level("WARNING"):
            engine = VolumeExclusionEngine([r"(unclosed", r"^tmp-"])

        assert any("(unclosed" in r.getMessage() for r in caplog.records)
        assert engine.evaluate("tmp-data", "", {}) is not None
        assert engine.evaluate("(unclosed", "", {}) is None


def _vm_id(name):
    return (
        f"/subscriptions/{SUB_ID}/resourceGroups/rg-prod"
        f"/providers/Microsoft.Compute/virtualMachines/{name}"
    )


def _disk(name, size_gb, vm_name, tags=None):
    d = MagicMock()
    d.id = f"/subscriptions/{SUB_ID}/resourceGroups/rg-prod/providers/Microsoft.Compute/disks/{name}"
    d.name = name
    d.disk_size_gb = size_gb
    d.sku = MagicMock()
    d.sku.name = "Premium_LRS"
    d.managed_by = _vm_id(vm_name)
    d.location = "eastus"
    d.encryption = MagicMock()
    d.encryption.type = "EncryptionAtRestWithPlatformKey"
    d.tags = tags
    return d


def _vm(name, os_disk_name="osdisk"):
    vm = MagicMock()
    vm.id = _vm_id(name)
    vm.name = name
    vm.location = "eastus"
    vm.tags = {}
    vm.hardware_profile = MagicMock()
    vm.hardware_profile.vm_size = "Standard_D4s_v3"
    vm.storage_profile = MagicMock()
    vm.storage_profile.os_disk = MagicMock()
    vm.storage_profile.os_disk.os_type = "Linux"
    vm.storage_profile.os_disk.name = os_disk_name
    return vm


def _collect(vms, disks, exclusion=None):
    compute = MagicMock()
    compute.virtual_machines.list_all.return_value = iter(vms)
    compute.disks.list.return_value = iter(disks)
    compute.snapshots.list.return_value = iter([])
    rm = MagicMock()
    rm.resources.list.return_value = iter([])

    with (
        patch("collectors.compute.ComputeManagementClient", return_value=compute),
        patch("collectors.compute.ResourceManagementClient", return_value=rm),
    ):
        collector = ComputeCollector(SUB_ID, MagicMock(), exclusion=exclusion)
    return collector.collect()


def _by_name(inventory):
    return {d.name: d for vm in inventory.vms for d in vm.disks}


class TestComputeCollectorExclusion:
    def test_tagged_disk_is_flagged_not_removed(self):
        inv = _collect(
            [_vm("vm-1")],
            [
                _disk("keep", 100, "vm-1"),
                _disk("skip", 500, "vm-1", tags={EXCLUDE_TAG: "true"}),
            ],
        )
        disks = _by_name(inv)

        assert set(disks) == {"keep", "skip"}
        assert disks["keep"].excluded_from_sizing is False
        assert disks["keep"].sizing_exclusion_reason == ""
        assert disks["skip"].excluded_from_sizing is True
        assert disks["skip"].sizing_exclusion_reason == REASON_TAG
        assert disks["skip"].disk_size_gb == 500

    def test_vm_totals_stay_raw(self):
        inv = _collect(
            [_vm("vm-1")],
            [
                _disk("keep", 100, "vm-1"),
                _disk("skip", 500, "vm-1", tags={EXCLUDE_TAG: "true"}),
            ],
        )

        assert inv.vms[0].total_disk_gb == 600
        assert inv.total_disk_tb == round(600 / 1024, 3)

    def test_name_pattern_on_disk_name(self):
        inv = _collect(
            [_vm("vm-1")],
            [_disk("tmp-cache", 50, "vm-1")],
            exclusion=VolumeExclusionEngine([r"^tmp-"]),
        )

        disk = _by_name(inv)["tmp-cache"]
        assert disk.excluded_from_sizing is True
        assert disk.sizing_exclusion_reason.startswith(REASON_PATTERN)

    def test_name_pattern_on_owning_vm_name(self):
        inv = _collect(
            [_vm("build-scratch")],
            [_disk("data", 50, "build-scratch")],
            exclusion=VolumeExclusionEngine([r"-scratch$"]),
        )

        disk = _by_name(inv)["data"]
        assert disk.excluded_from_sizing is True
        assert disk.sizing_exclusion_reason.startswith(REASON_PATTERN)

    def test_default_engine_is_tag_only(self):
        inv = _collect([_vm("build-scratch")], [_disk("tmp-data", 50, "build-scratch")])

        disk = _by_name(inv)["tmp-data"]
        assert disk.excluded_from_sizing is False
        assert disk.sizing_exclusion_reason == ""

    def test_disk_without_tags_attribute_or_none_tags(self):
        no_tags = _disk("plain", 10, "vm-1", tags=None)
        del no_tags.tags  # SDK stubs that omit the attribute entirely

        inv = _collect([_vm("vm-1")], [no_tags, _disk("none-tags", 10, "vm-1", tags=None)])

        assert all(not d.excluded_from_sizing for d in _by_name(inv).values())

    def test_flag_serializes_into_discovery_dict(self):
        inv = _collect(
            [_vm("vm-1")],
            [_disk("skip", 500, "vm-1", tags={EXCLUDE_TAG: "yes"})],
        )

        disk = dataclasses.asdict(inv)["vms"][0]["disks"][0]
        assert disk["excluded_from_sizing"] is True
        assert disk["sizing_exclusion_reason"] == REASON_TAG

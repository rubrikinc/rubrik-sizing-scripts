"""Tests for collectors/exclusion.py and its wiring into collectors/compute.py."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from collectors.compute import ComputeCollector
from collectors.exclusion import (
    EXCLUDE_LABEL,
    REASON_LABEL,
    REASON_PATTERN,
    VolumeExclusionEngine,
)

from tests.conftest import PROJECT_ID, ZONE

_INSTANCES_CLIENT = "google.cloud.compute_v1.InstancesClient"
_DISKS_CLIENT = "google.cloud.compute_v1.DisksClient"

AWS_STYLE_KEY = "rubrik:sizing:exclude"


class TestEngineLabel:
    @pytest.mark.parametrize(
        "value", ["true", "True", "TRUE", "yes", "y", "1", "exclude", "  true  "]
    )
    def test_truthy_values_exclude(self, value):
        engine = VolumeExclusionEngine()
        assert engine.evaluate("disk", "inst", {EXCLUDE_LABEL: value}) == REASON_LABEL

    @pytest.mark.parametrize("value", ["false", "no", "0", "", "maybe"])
    def test_other_values_do_not_exclude(self, value):
        assert VolumeExclusionEngine().evaluate("disk", "inst", {EXCLUDE_LABEL: value}) is None

    def test_absent_or_empty_labels_do_not_exclude(self):
        engine = VolumeExclusionEngine()
        assert engine.evaluate("disk", "inst", {}) is None
        assert engine.evaluate("disk", "inst", None) is None

    def test_label_key_is_case_sensitive(self):
        assert VolumeExclusionEngine().evaluate("d", "i", {EXCLUDE_LABEL.upper(): "true"}) is None

    def test_aws_style_key_is_also_honored(self):
        reason = VolumeExclusionEngine().evaluate("d", "i", {AWS_STYLE_KEY: "true"})
        assert reason == f"label {AWS_STYLE_KEY}"

    def test_label_wins_over_pattern(self):
        engine = VolumeExclusionEngine([r"scratch"])
        assert engine.evaluate("scratch-disk", "", {EXCLUDE_LABEL: "true"}) == REASON_LABEL


class TestEnginePatterns:
    def test_matches_disk_name(self):
        reason = VolumeExclusionEngine([r"^tmp-"]).evaluate("tmp-data", "web-1", {})
        assert reason is not None
        assert reason.startswith(REASON_PATTERN)
        assert "^tmp-" in reason

    def test_matches_instance_name(self):
        reason = VolumeExclusionEngine([r"-scratch$"]).evaluate("data", "build-scratch", {})
        assert reason is not None
        assert reason.startswith(REASON_PATTERN)

    def test_no_match_returns_none(self):
        assert VolumeExclusionEngine([r"^tmp-"]).evaluate("data", "web-1", {}) is None

    def test_empty_names_never_match(self):
        assert VolumeExclusionEngine([r".*"]).evaluate("", "", {}) is None

    def test_no_patterns_means_label_only(self):
        assert VolumeExclusionEngine().evaluate("tmp-data", "scratch", {}) is None

    def test_invalid_pattern_is_skipped_with_warning(self, caplog):
        with caplog.at_level("WARNING"):
            engine = VolumeExclusionEngine([r"(unclosed", r"^tmp-"])

        assert any("(unclosed" in r.getMessage() for r in caplog.records)
        assert engine.evaluate("tmp-data", "", {}) is not None
        assert engine.evaluate("(unclosed", "", {}) is None


def _attached(name: str, boot: bool = False):
    d = MagicMock()
    d.boot = boot
    d.source = f"projects/{PROJECT_ID}/zones/{ZONE}/disks/{name}"
    d.licenses = []
    return d


def _instance(name: str, disk_names: list[str]):
    inst = MagicMock()
    inst.name = name
    inst.machine_type = f"zones/{ZONE}/machineTypes/n2-standard-4"
    inst.status = "RUNNING"
    inst.labels = {}
    inst.disks = [_attached(n, boot=(i == 0)) for i, n in enumerate(disk_names)]
    return inst


def _disk(name: str, size_gb: int = 100, labels: dict | None = None, user: str | None = None):
    disk = MagicMock()
    disk.name = name
    disk.size_gb = size_gb
    disk.type_ = f"zones/{ZONE}/diskTypes/pd-ssd"
    disk.status = "READY"
    disk.labels = labels or {}
    disk.users = (
        [f"https://www.googleapis.com/compute/v1/projects/{PROJECT_ID}/zones/{ZONE}/instances/{user}"]
        if user
        else []
    )
    return disk


def _collect(disks, instances, exclusion=None):
    inst_client = MagicMock()
    scoped_i = MagicMock()
    scoped_i.instances = instances
    inst_client.aggregated_list.return_value = iter([(f"zones/{ZONE}", scoped_i)])

    disk_client = MagicMock()
    scoped_d = MagicMock()
    scoped_d.disks = disks
    disk_client.aggregated_list.return_value = iter([(f"zones/{ZONE}", scoped_d)])

    with (
        patch(_INSTANCES_CLIENT, return_value=inst_client),
        patch(_DISKS_CLIENT, return_value=disk_client),
    ):
        return ComputeCollector(PROJECT_ID, MagicMock(), exclusion=exclusion).collect()


def _by_name(inventory):
    return {d.name: d for inst in inventory.instances for d in inst.disks}


class TestComputeExclusion:
    def test_labelled_disk_is_flagged_not_removed(self):
        inv = _collect(
            disks=[
                _disk("keep", 100, user="web-1"),
                _disk("skip", 500, labels={EXCLUDE_LABEL: "true"}, user="web-1"),
            ],
            instances=[_instance("web-1", ["keep", "skip"])],
        )
        disks = _by_name(inv)

        assert set(disks) == {"keep", "skip"}
        assert disks["keep"].excluded_from_sizing is False
        assert disks["keep"].sizing_exclusion_reason == ""
        assert disks["skip"].excluded_from_sizing is True
        assert disks["skip"].sizing_exclusion_reason == REASON_LABEL
        assert disks["skip"].size_gb == 500

    def test_instance_totals_stay_raw(self):
        inv = _collect(
            disks=[
                _disk("keep", 100, user="web-1"),
                _disk("skip", 500, labels={EXCLUDE_LABEL: "true"}, user="web-1"),
            ],
            instances=[_instance("web-1", ["keep", "skip"])],
        )

        assert inv.instances[0].total_disk_gb == 600.0
        assert inv.total_disk_tb == round(600.0 / 1000, 4)

    def test_name_pattern_on_instance_name_from_users_url(self):
        inv = _collect(
            disks=[_disk("data", 50, user="build-scratch")],
            instances=[_instance("build-scratch", ["data"])],
            exclusion=VolumeExclusionEngine([r"-scratch$"]),
        )
        disk = _by_name(inv)["data"]

        assert disk.excluded_from_sizing is True
        assert disk.sizing_exclusion_reason.startswith(REASON_PATTERN)

    def test_name_pattern_on_disk_name(self):
        inv = _collect(
            disks=[_disk("tmp-cache", 50, user="web-1")],
            instances=[_instance("web-1", ["tmp-cache"])],
            exclusion=VolumeExclusionEngine([r"^tmp-"]),
        )

        assert _by_name(inv)["tmp-cache"].excluded_from_sizing is True

    def test_default_engine_is_label_only(self):
        inv = _collect(
            disks=[_disk("tmp-cache", 50, user="build-scratch")],
            instances=[_instance("build-scratch", ["tmp-cache"])],
        )
        disk = _by_name(inv)["tmp-cache"]

        assert disk.excluded_from_sizing is False
        assert disk.sizing_exclusion_reason == ""

    def test_stub_disk_still_matches_name_patterns(self):
        # Instance references a disk missing from the disk listing -> stub.
        inv = _collect(
            disks=[],
            instances=[_instance("build-scratch", ["ghost"])],
            exclusion=VolumeExclusionEngine([r"-scratch$"]),
        )
        disk = _by_name(inv)["ghost"]

        assert disk.size_gb == 0
        assert disk.excluded_from_sizing is True

    def test_unattached_disk_is_flagged(self):
        compute_v1 = MagicMock()
        disk_client = MagicMock()
        scoped = MagicMock()
        scoped.disks = [
            _disk("orphan-a", 10),
            _disk("orphan-b", 20, labels={EXCLUDE_LABEL: "yes"}),
        ]
        disk_client.aggregated_list.return_value = iter([(f"zones/{ZONE}", scoped)])
        compute_v1.DisksClient.return_value = disk_client

        disks = ComputeCollector(PROJECT_ID, MagicMock())._collect_disks(compute_v1)

        # Disks are keyed by scope + name (see ``_disk_key``).
        orphan_a = disks[f"zones/{ZONE}/orphan-a"]
        orphan_b = disks[f"zones/{ZONE}/orphan-b"]
        assert orphan_a.excluded_from_sizing is False
        assert orphan_b.excluded_from_sizing is True
        assert orphan_b.sizing_exclusion_reason == REASON_LABEL

    def test_excluded_unattached_disk_keeps_flag_and_raw_totals(self):
        inv = _collect(
            disks=[_disk("orphan", 200, labels={EXCLUDE_LABEL: "yes"})],
            instances=[],
        )

        assert [d.name for d in inv.unattached_disks] == ["orphan"]
        assert inv.unattached_disks[0].excluded_from_sizing is True
        assert inv.total_unattached_disk_tb == round(200 / 1000, 4)
        assert inv.total_disk_tb == round(200 / 1000, 4)


class TestSerialization:
    def _inventory(self):
        return _collect(
            disks=[
                _disk("keep", 100, user="web-1"),
                _disk("skip", 500, labels={EXCLUDE_LABEL: "true"}, user="web-1"),
            ],
            instances=[_instance("web-1", ["keep", "skip"])],
        )

    @staticmethod
    def _disks_from_json(doc: dict) -> dict:
        return {d["name"]: d for inst in doc["compute"][0]["instances"] for d in inst["disks"]}

    def test_fields_reach_in_memory_json(self):
        import main

        doc = main._build_result(
            [PROJECT_ID], ["us-central1"], {PROJECT_ID: {"compute": self._inventory()}}
        ).to_json_dict()
        disks = self._disks_from_json(doc)

        assert disks["keep"]["excluded_from_sizing"] is False
        assert disks["keep"]["sizing_exclusion_reason"] == ""
        assert disks["skip"]["excluded_from_sizing"] is True
        assert disks["skip"]["sizing_exclusion_reason"] == REASON_LABEL

    def test_fields_reach_streamed_json(self, tmp_path):
        from streaming_writer import StreamingDiscoveryWriter, slice_from_result

        writer = StreamingDiscoveryWriter(tmp_path, "20260101-000000")
        writer.add(PROJECT_ID, slice_from_result(PROJECT_ID, {"compute": self._inventory()}))
        meta = {"schema_version": "1.0", "generated_at": "2026-01-01T00:00:00Z"}
        out = writer.finalize(meta=meta, filename="streamed.json")
        disks = self._disks_from_json(json.loads(out.read_text()))

        assert disks["keep"]["excluded_from_sizing"] is False
        assert disks["skip"]["excluded_from_sizing"] is True
        assert disks["skip"]["sizing_exclusion_reason"] == REASON_LABEL

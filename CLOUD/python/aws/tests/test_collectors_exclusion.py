"""Tests for collectors/exclusion.py and its wiring into collectors/ec2.py."""

from unittest.mock import MagicMock

import pytest
from collectors.ec2 import fetch_instances, fetch_unattached_volumes
from collectors.exclusion import (
    EXCLUDE_TAG,
    REASON_PATTERN,
    REASON_TAG,
    VolumeExclusionEngine,
)

ACCT = "123456789012"
ALIAS = "test-account"
REGION = "us-east-1"


class TestEngineTag:
    @pytest.mark.parametrize("value", ["true", "True", "TRUE", "yes", "y", "1", "exclude", "  true  "])
    def test_truthy_values_exclude(self, value):
        assert VolumeExclusionEngine().evaluate("vol", "inst", {EXCLUDE_TAG: value}) == REASON_TAG

    @pytest.mark.parametrize("value", ["false", "no", "0", "", "maybe"])
    def test_other_values_do_not_exclude(self, value):
        assert VolumeExclusionEngine().evaluate("vol", "inst", {EXCLUDE_TAG: value}) is None

    def test_absent_or_empty_tags_do_not_exclude(self):
        engine = VolumeExclusionEngine()
        assert engine.evaluate("vol", "inst", {}) is None
        assert engine.evaluate("vol", "inst", None) is None

    def test_tag_key_is_case_sensitive(self):
        assert VolumeExclusionEngine().evaluate("v", "i", {EXCLUDE_TAG.upper(): "true"}) is None

    def test_tag_wins_over_pattern(self):
        engine = VolumeExclusionEngine([r"scratch"])
        assert engine.evaluate("scratch-disk", "", {EXCLUDE_TAG: "true"}) == REASON_TAG


class TestEnginePatterns:
    def test_matches_volume_name(self):
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

    def test_no_patterns_means_tag_only(self):
        assert VolumeExclusionEngine().evaluate("tmp-data", "scratch", {}) is None

    def test_invalid_pattern_is_skipped_with_warning(self, caplog):
        with caplog.at_level("WARNING"):
            engine = VolumeExclusionEngine([r"(unclosed", r"^tmp-"])

        assert any("(unclosed" in r.getMessage() for r in caplog.records)
        assert engine.evaluate("tmp-data", "", {}) is not None
        assert engine.evaluate("(unclosed", "", {}) is None


def _tags(**kv):
    return [{"Key": k, "Value": v} for k, v in kv.items()]


def _session(volumes, instances=None):
    """Session mock for fetch_instances / fetch_unattached_volumes."""
    pages = {
        "describe_instances": [{"Reservations": [{"Instances": instances or []}]}],
        "describe_volumes": [{"Volumes": volumes}],
        "describe_snapshots": [{"Snapshots": []}],
    }

    def get_paginator(op):
        paginator = MagicMock()
        paginator.paginate.return_value = pages.get(op, [{}])
        return paginator

    ec2 = MagicMock()
    ec2.get_paginator.side_effect = get_paginator
    ec2.describe_instance_types.return_value = {"InstanceTypes": []}

    cw = MagicMock()
    cw.get_metric_data.return_value = {"MetricDataResults": []}

    session = MagicMock()
    session.client.side_effect = lambda service, **kw: ec2 if service == "ec2" else cw
    return session


def _instance(inst_id, name, vol_ids):
    return {
        "InstanceId": inst_id,
        "InstanceType": "m5.large",
        "Tags": _tags(Name=name),
        "BlockDeviceMappings": [
            {"DeviceName": f"/dev/sd{chr(ord('f') + i)}", "Ebs": {"VolumeId": v}}
            for i, v in enumerate(vol_ids)
        ],
    }


def _volume(vol_id, size, **tags):
    return {"VolumeId": vol_id, "Size": size, "Tags": _tags(**tags)}


class TestFetchInstancesExclusion:
    def test_tagged_attached_volume_is_flagged_not_removed(self):
        session = _session(
            volumes=[
                _volume("vol-keep", 100),
                _volume("vol-skip", 500, **{EXCLUDE_TAG: "true"}),
            ],
            instances=[_instance("i-1", "web-1", ["vol-keep", "vol-skip"])],
        )

        _, volumes = fetch_instances(session, REGION, ACCT, ALIAS, set())
        by_id = {v.volume_id: v for v in volumes}

        assert set(by_id) == {"vol-keep", "vol-skip"}
        assert by_id["vol-keep"].excluded_from_sizing is False
        assert by_id["vol-skip"].excluded_from_sizing is True
        assert by_id["vol-skip"].sizing_exclusion_reason == REASON_TAG
        assert by_id["vol-skip"].size_gib == 500

    def test_instance_totals_stay_raw(self):
        session = _session(
            volumes=[
                _volume("vol-keep", 100),
                _volume("vol-skip", 500, **{EXCLUDE_TAG: "true"}),
            ],
            instances=[_instance("i-1", "web-1", ["vol-keep", "vol-skip"])],
        )

        instances, _ = fetch_instances(session, REGION, ACCT, ALIAS, set())

        assert instances[0].size_gib == 600

    def test_name_pattern_on_instance_name(self):
        session = _session(
            volumes=[_volume("vol-1", 50)],
            instances=[_instance("i-1", "build-scratch", ["vol-1"])],
        )

        _, volumes = fetch_instances(
            session, REGION, ACCT, ALIAS, set(), exclusion=VolumeExclusionEngine([r"-scratch$"])
        )

        assert volumes[0].excluded_from_sizing is True
        assert volumes[0].sizing_exclusion_reason.startswith(REASON_PATTERN)

    def test_default_engine_is_tag_only(self):
        session = _session(
            volumes=[_volume("vol-1", 50)],
            instances=[_instance("i-1", "build-scratch", ["vol-1"])],
        )

        _, volumes = fetch_instances(session, REGION, ACCT, ALIAS, set())

        assert volumes[0].excluded_from_sizing is False
        assert volumes[0].sizing_exclusion_reason in ("", None)

    def test_explicit_reason_survives_archival_heuristic(self):
        """A volume that is both operator-excluded and archival-looking keeps the tag reason."""
        session = _session(
            volumes=[_volume("vol-1", 50, Name="old-archive", **{EXCLUDE_TAG: "true"})],
            instances=[_instance("i-1", "web-1", ["vol-1"])],
        )

        _, volumes = fetch_instances(session, REGION, ACCT, ALIAS, set())

        assert volumes[0].excluded_from_sizing is True
        assert volumes[0].sizing_exclusion_reason == REASON_TAG


class TestFetchUnattachedExclusion:
    def test_tagged_unattached_volume_is_flagged(self):
        session = _session(
            volumes=[
                _volume("vol-a", 10),
                _volume("vol-b", 20, **{EXCLUDE_TAG: "yes"}),
            ]
        )

        result = fetch_unattached_volumes(session, REGION, ACCT, ALIAS, set())
        by_id = {v.volume_id: v for v in result}

        assert by_id["vol-a"].excluded_from_sizing is False
        assert by_id["vol-b"].excluded_from_sizing is True
        assert by_id["vol-b"].sizing_exclusion_reason == REASON_TAG

    def test_name_pattern_on_volume_name(self):
        session = _session(volumes=[_volume("vol-a", 10, Name="tmp-cache")])

        result = fetch_unattached_volumes(
            session, REGION, ACCT, ALIAS, set(), exclusion=VolumeExclusionEngine([r"^tmp-"])
        )

        assert result[0].excluded_from_sizing is True
        assert result[0].sizing_exclusion_reason.startswith(REASON_PATTERN)

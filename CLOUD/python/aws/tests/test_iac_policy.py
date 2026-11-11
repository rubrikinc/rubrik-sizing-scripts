"""Tests for the spoke IAM role policy in iac/2-sizing-tool-spokes.yaml.

_scan_region() probes ec2:DescribeAvailabilityZones before running any
collector in a region (see main.py). If the spoke role's policy doesn't
grant that action, the probe fails with a plain AccessDenied (not an SCP
denial) on every region, every account, and the whole scan silently comes
back empty — indistinguishable in the logs from a genuinely empty account.
"""

from __future__ import annotations

from pathlib import Path

import yaml

TEMPLATE_PATH = Path(__file__).parent.parent / "iac" / "2-sizing-tool-spokes.yaml"


class _IgnoreUnknownTagsLoader(yaml.SafeLoader):
    """SafeLoader that treats CloudFormation's short-form intrinsics

    (!Sub, !Ref, !GetAtt, ...) as opaque scalars/sequences instead of
    raising a constructor error.
    """


def _construct_undefined(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_IgnoreUnknownTagsLoader.add_multi_constructor("!", _construct_undefined)


def _load_template() -> dict:
    return yaml.load(TEMPLATE_PATH.read_text(), Loader=_IgnoreUnknownTagsLoader)


def _spoke_role_actions() -> list[str]:
    template = _load_template()
    role = template["Resources"]["RubrikDiscoveryRole"]["Properties"]
    statements = role["Policies"][0]["PolicyDocument"]["Statement"]
    actions: list[str] = []
    for statement in statements:
        actions.extend(statement["Action"])
    return actions


class TestSpokeRolePermissions:
    def test_grants_availability_zone_probe_action(self):
        assert "ec2:DescribeAvailabilityZones" in _spoke_role_actions()

    def test_grants_actions_used_by_collectors(self):
        actions = _spoke_role_actions()
        for required in (
            "ec2:DescribeInstances",
            "ec2:DescribeRegions",
            "ec2:DescribeVolumes",
            "rds:DescribeDBInstances",
            "backup:ListProtectedResources",
        ):
            assert required in actions, f"spoke role policy is missing {required}"

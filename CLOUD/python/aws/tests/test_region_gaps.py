"""A region that could not be scanned is a gap in its account, and is recorded as one.

Before, a region that raised, or whose probe failed for a reason other than an SCP, was logged and
dropped: the account still wrote its file, which a resume counts as finished. It is now a scan error,
so the JSON says so and --resume rescans the account (unless --keep-partial).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import main
import pytest
from botocore.exceptions import ClientError
from collectors import DenialTracker

SERVICES = frozenset({"ec2"})


def _client_error(code, message, operation="DescribeAvailabilityZones"):
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _session(probe_errors=None):
    """A session whose ec2 probe fails for the regions named in probe_errors ({region: exception})."""
    probe_errors = probe_errors or {}
    session = MagicMock()

    def client(service, region_name=None, **kwargs):
        c = MagicMock()
        error = probe_errors.get(region_name)
        c.describe_availability_zones.side_effect = error if error else None
        return c

    session.client.side_effect = client
    return session


def _scan(session, regions, tracker, monkeypatch, region_fn=None):
    if region_fn is not None:
        monkeypatch.setattr(main, "_scan_region", region_fn)
    return main._scan_all_regions(session, regions, "111122223333", "", SERVICES, tracker)


def _regions_recorded(tracker):
    return sorted(e["region"] for e in tracker.permission_errors() if e["service"] == "region")


# ── a region that raises ──────────────────────────────────────────────────────


def test_a_region_that_raises_is_recorded_and_the_others_are_kept(monkeypatch):
    def region_fn(session, region, *args, **kwargs):
        if region == "eu-west-1":
            raise RuntimeError("endpoint exploded")
        return {**_empty(), "instances": [f"i-{region}"]}

    tracker = DenialTracker()
    result = _scan(
        MagicMock(), ["us-east-1", "eu-west-1", "us-west-2"], tracker, monkeypatch, region_fn
    )
    assert sorted(result["instances"]) == ["i-us-east-1", "i-us-west-2"]  # the healthy ones survive
    assert _regions_recorded(tracker) == ["eu-west-1"]
    (error,) = tracker.permission_errors()
    assert error["service"] == main.REGION_SERVICE == "region"
    assert "endpoint exploded" in error["error"]


def _empty():
    keys = (
        "instances attached unattached rds dynamodb efs fsx s3 kms secrets sqs plans vaults cfn "
        "native_backups rds_snapshots ebs_ami vpcs load_balancers eks_clusters eks_nodegroups "
        "kms_keys redshift fsx_volumes s3_tables glue_iceberg recovery_points recovery_aggregates "
        "truncated_backup_regions"
    ).split()
    return {k: [] for k in keys}


# ── a region whose probe fails ────────────────────────────────────────────────


def test_a_region_that_cannot_be_reached_is_recorded(monkeypatch):
    unreachable = _client_error("RequestExpired", "The region endpoint is not reachable")
    tracker = DenialTracker()
    result = main._scan_region(
        _session({"af-south-1": unreachable}), "af-south-1", "111122223333", "", SERVICES, tracker
    )
    assert result == _empty()
    assert _regions_recorded(tracker) == ["af-south-1"]


def test_a_region_denied_by_an_scp_stays_quiet_as_it_always_did():
    scp = _client_error(
        "UnauthorizedOperation",
        "explicit deny in a service control policy: service_control_policy",
    )
    tracker = DenialTracker()
    main._scan_region(
        _session({"ap-east-1": scp}), "ap-east-1", "111122223333", "", SERVICES, tracker
    )
    assert _regions_recorded(tracker) == []  # orgs routinely deny regions: not a gap to chase


def test_a_missing_ec2_probe_permission_still_scans_the_region(monkeypatch):
    """The probe is only a shortcut: without ec2:DescribeAvailabilityZones the collectors still run.

    A collector that leaves a trace is needed to tell "scanned" from "skipped": with none selected
    both give the same empty result.
    """
    denied = _client_error(
        "UnauthorizedOperation", "You are not authorized to perform this operation"
    )
    monkeypatch.setattr(main, "fetch_instances", lambda *a, **k: (["i-from-the-collector"], []))
    tracker = DenialTracker()
    result = main._scan_region(
        _session({"us-east-1": denied}), "us-east-1", "111122223333", "", SERVICES, tracker
    )
    assert result["instances"] == ["i-from-the-collector"]
    assert _regions_recorded(tracker) == []


# ── what a recorded gap does to the account ───────────────────────────────────


def test_an_account_with_a_recorded_region_gap_is_partial(tmp_path):
    folder = tmp_path / "111122223333"
    folder.mkdir()
    (folder / "aws_sizing_discovery.json").write_text(
        json.dumps({"scan_errors": [{"service": "region", "region": "eu-west-1", "error": "x"}]})
    )
    assert main._partial_accounts(str(tmp_path), {"111122223333"}) == {"111122223333"}


def test_a_clean_account_is_not_partial(tmp_path):
    folder = tmp_path / "111122223333"
    folder.mkdir()
    (folder / "aws_sizing_discovery.json").write_text(json.dumps({"scan_errors": []}))
    assert main._partial_accounts(str(tmp_path), {"111122223333"}) == set()

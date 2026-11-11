"""Tests for collectors/ec2.py."""

from unittest.mock import MagicMock

import pytest
from collectors.ec2 import fetch_instances, fetch_unattached_volumes

ACCT = "123456789012"
ALIAS = "test-account"
REGION = "us-east-1"


def _make_client(inst_pages, vol_pages=None):
    """Return a mock EC2 client with separate paginators for instances and volumes."""
    if vol_pages is None:
        vol_pages = [{"Volumes": []}]

    inst_pag = MagicMock()
    inst_pag.paginate.return_value = inst_pages

    vol_pag = MagicMock()
    vol_pag.paginate.return_value = vol_pages

    client = MagicMock()

    def get_pag(name):
        if name == "describe_instances":
            return inst_pag
        return vol_pag

    client.get_paginator.side_effect = get_pag
    return client


def _mock_cw_client():
    """CloudWatch mock that returns empty MetricDataResults with no NextToken."""
    cw = MagicMock()
    cw.get_metric_data.return_value = {"MetricDataResults": [], "NextToken": None}
    return cw


def _mock_session(client):
    s = MagicMock()
    cw = _mock_cw_client()
    s.client.side_effect = lambda svc, **_kw: cw if svc == "cloudwatch" else client
    return s


class TestFetchInstances:
    def _inst(self, inst_id="i-1", inst_type="t3.micro", platform="", vol_ids=None):
        bdms = []
        for vid in vol_ids or []:
            bdms.append({"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": vid}})
        return {
            "InstanceId": inst_id,
            "InstanceType": inst_type,
            "Platform": platform,
            "Tags": [{"Key": "Name", "Value": f"host-{inst_id}"}],
            "BlockDeviceMappings": bdms,
        }

    def _vol(self, vol_id, size_gib=50):
        return {
            "VolumeId": vol_id,
            "Size": size_gib,
            "VolumeType": "gp3",
            "AvailabilityZone": "us-east-1a",
            "State": "in-use",
            "Iops": 3000,
            "Throughput": 125,
            "Encrypted": True,
            "Tags": [],
        }

    def test_basic_instance_returned(self):
        inst = self._inst("i-1", vol_ids=["vol-1"])
        vol = self._vol("vol-1", 100)
        client = _make_client(
            inst_pages=[{"Reservations": [{"Instances": [inst]}]}],
            vol_pages=[{"Volumes": [vol]}],
        )
        instances, attached = fetch_instances(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(instances) == 1
        assert instances[0].instance_id == "i-1"
        assert instances[0].name == "host-i-1"
        assert instances[0].size_gib == 100
        assert instances[0].size_bytes_derived == 100 * 1024**3
        assert len(attached) == 1
        assert attached[0].volume_id == "vol-1"
        assert attached[0].size_gib == 100
        assert attached[0].size_bytes_derived == 100 * 1024**3

    def test_backup_protection_marked(self):
        inst = self._inst("i-1", vol_ids=["vol-1"])
        vol = self._vol("vol-1")
        inst_arn = f"arn:aws:ec2:{REGION}:{ACCT}:instance/i-1"
        vol_arn = f"arn:aws:ec2:{REGION}:{ACCT}:volume/vol-1"
        protected = {inst_arn, vol_arn}
        client = _make_client(
            inst_pages=[{"Reservations": [{"Instances": [inst]}]}],
            vol_pages=[{"Volumes": [vol]}],
        )
        instances, attached = fetch_instances(_mock_session(client), REGION, ACCT, ALIAS, protected)
        assert instances[0].in_backup_plan is True
        assert instances[0].backup_plans == ["AWS Backup"]
        assert attached[0].in_backup_plan is True

    def test_unprotected_instance(self):
        inst = self._inst("i-2")
        client = _make_client(
            inst_pages=[{"Reservations": [{"Instances": [inst]}]}],
        )
        instances, _ = fetch_instances(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert instances[0].in_backup_plan is False
        assert instances[0].backup_plans == []

    def test_windows_platform_detection(self):
        inst = self._inst("i-win", platform="Windows")
        client = _make_client(
            inst_pages=[{"Reservations": [{"Instances": [inst]}]}],
        )
        instances, _ = fetch_instances(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert instances[0].platform == "windows"

    def test_linux_platform_default(self):
        inst = self._inst("i-linux", platform="")
        client = _make_client(
            inst_pages=[{"Reservations": [{"Instances": [inst]}]}],
        )
        instances, _ = fetch_instances(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert instances[0].platform == "linux"

    def test_api_error_returns_empty(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("AccessDenied")
        instances, attached = fetch_instances(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert instances == []
        assert attached == []

    def test_volume_batch_fetch_error_graceful(self):
        inst = self._inst("i-1", vol_ids=["vol-1"])
        inst_pag = MagicMock()
        inst_pag.paginate.return_value = [{"Reservations": [{"Instances": [inst]}]}]
        vol_pag = MagicMock()
        vol_pag.paginate.side_effect = Exception("VolumeError")
        client = MagicMock()
        client.get_paginator.side_effect = lambda n: (
            inst_pag if n == "describe_instances" else vol_pag
        )
        instances, attached = fetch_instances(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(instances) == 1
        assert instances[0].size_gib == 0

    def test_size_tb_conversion(self):
        inst = self._inst("i-1", vol_ids=["vol-1"])
        vol = self._vol("vol-1", 1024)
        client = _make_client(
            inst_pages=[{"Reservations": [{"Instances": [inst]}]}],
            vol_pages=[{"Volumes": [vol]}],
        )
        instances, _ = fetch_instances(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert instances[0].size_tb == pytest.approx(1.0, abs=0.001)

    def test_multi_page_instances(self):
        inst1 = self._inst("i-1")
        inst2 = self._inst("i-2")
        client = _make_client(
            inst_pages=[
                {"Reservations": [{"Instances": [inst1]}]},
                {"Reservations": [{"Instances": [inst2]}]},
            ],
        )
        instances, _ = fetch_instances(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(instances) == 2


class TestFetchUnattachedVolumes:
    def _avail_vol(self, vol_id, size_gib=200):
        return {
            "VolumeId": vol_id,
            "Size": size_gib,
            "VolumeType": "gp2",
            "AvailabilityZone": "us-east-1b",
            "Iops": None,
            "Throughput": None,
            "Encrypted": False,
            "Tags": [{"Key": "Name", "Value": "orphan"}],
        }

    def _make_client(self, pages):
        pag = MagicMock()
        pag.paginate.return_value = pages
        client = MagicMock()
        client.get_paginator.return_value = pag
        return client

    def test_basic_unattached_volume(self):
        vol = self._avail_vol("vol-avail-1", 200)
        client = self._make_client([{"Volumes": [vol]}])
        result = fetch_unattached_volumes(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(result) == 1
        v = result[0]
        assert v.volume_id == "vol-avail-1"
        assert v.instance_id == ""
        assert v.state == "available"
        assert v.name == "orphan"
        assert v.size_gib == 200

    def test_backup_protection_marked(self):
        vol = self._avail_vol("vol-2")
        vol_arn = f"arn:aws:ec2:{REGION}:{ACCT}:volume/vol-2"
        client = self._make_client([{"Volumes": [vol]}])
        result = fetch_unattached_volumes(_mock_session(client), REGION, ACCT, ALIAS, {vol_arn})
        assert result[0].in_backup_plan is True
        assert result[0].backup_plans == ["AWS Backup"]

    def test_api_error_returns_empty(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("Throttled")
        result = fetch_unattached_volumes(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result == []

    def test_iops_none_becomes_zero(self):
        vol = self._avail_vol("vol-3")
        client = self._make_client([{"Volumes": [vol]}])
        result = fetch_unattached_volumes(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].iops == 0
        assert result[0].throughput == 0


def test_change_rate_failure_recorded_in_tracker():
    from collectors import DenialTracker
    from collectors.ec2 import _enrich_with_change_rates
    from models.discovery import EC2Volume

    vol = EC2Volume(
        account_id=ACCT, account_alias=ALIAS, volume_id="vol-1", instance_id="i-1",
        instance_name="", name="", device_name="/dev/sda1", size_gib=10, size_tb=0.01,
        size_bytes_derived=10 * 1024**3, region=REGION, availability_zone="us-east-1a",
        volume_type="gp3", state="in-use", iops=0, throughput=0, encrypted=False,
        in_backup_plan=False, backup_plans=[], tags={},
    )
    cw = MagicMock()
    cw.get_metric_data.side_effect = Exception("ThrottlingException")
    tracker = DenialTracker()

    _enrich_with_change_rates(cw, [vol], REGION, tracker)

    errs = tracker.permission_errors()
    assert [e["service"] for e in errs] == ["cloudwatch"]
    assert "ThrottlingException" in errs[0]["error"]
    assert vol.avg_daily_write_gib == 0


def test_change_rate_success_records_nothing():
    from collectors import DenialTracker
    from collectors.ec2 import _enrich_with_change_rates

    tracker = DenialTracker()
    _enrich_with_change_rates(_mock_cw_client(), [], REGION, tracker)
    assert tracker.permission_errors() == []

"""Tests for collectors/efs.py."""

from unittest.mock import MagicMock

import pytest
from collectors.efs import fetch_efs

ACCT = "123456789012"
ALIAS = "test-account"
REGION = "us-east-1"

GIB = 1024**3


def _mock_session(client):
    s = MagicMock()
    s.client.return_value = client
    return s


def _make_client(pages):
    pag = MagicMock()
    pag.paginate.return_value = pages
    client = MagicMock()
    client.get_paginator.return_value = pag
    return client


def _fs(fs_id, size_bytes=0, arn=None, name=""):
    return {
        "FileSystemId": fs_id,
        "FileSystemArn": arn or f"arn:aws:elasticfilesystem:{REGION}:{ACCT}:file-system/{fs_id}",
        "SizeInBytes": {"Value": size_bytes},
        "NumberOfMountTargets": 2,
        "OwnerId": ACCT,
        "PerformanceMode": "generalPurpose",
        "ThroughputMode": "bursting",
        "ProvisionedThroughputInMibps": None,
        "Tags": [{"Key": "Name", "Value": name}] if name else [],
    }


class TestFetchEFS:
    def test_basic_filesystem_returned(self):
        fs = _fs("fs-1", size_bytes=2 * GIB, name="shared")
        client = _make_client([{"FileSystems": [fs]}])
        result = fetch_efs(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(result) == 1
        f = result[0]
        assert f.file_system_id == "fs-1"
        assert f.name == "shared"
        assert f.mount_targets == 2

    def test_sizeinbytes_is_dict(self):
        fs = _fs("fs-2", size_bytes=GIB)
        client = _make_client([{"FileSystems": [fs]}])
        result = fetch_efs(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].size_bytes == GIB
        assert result[0].size_gib == pytest.approx(1.0, abs=0.001)

    def test_size_gib_to_tb(self):
        fs = _fs("fs-3", size_bytes=1024 * GIB)
        client = _make_client([{"FileSystems": [fs]}])
        result = fetch_efs(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].size_tb == pytest.approx(1.0, abs=0.001)

    def test_backup_protection_marked(self):
        fs_arn = f"arn:aws:elasticfilesystem:{REGION}:{ACCT}:file-system/fs-4"
        fs = _fs("fs-4", arn=fs_arn)
        client = _make_client([{"FileSystems": [fs]}])
        result = fetch_efs(_mock_session(client), REGION, ACCT, ALIAS, {fs_arn})
        assert result[0].in_backup_plan is True
        assert result[0].backup_plans == ["AWS Backup"]

    def test_unprotected_filesystem(self):
        fs = _fs("fs-5")
        client = _make_client([{"FileSystems": [fs]}])
        result = fetch_efs(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].in_backup_plan is False

    def test_api_error_returns_empty(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("AccessDenied")
        result = fetch_efs(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result == []

    def test_zero_size_filesystem(self):
        fs = _fs("fs-6", size_bytes=0)
        client = _make_client([{"FileSystems": [fs]}])
        result = fetch_efs(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].size_bytes == 0
        assert result[0].size_gib == 0.0
        assert result[0].size_tb == 0.0

    def test_no_name_tag_defaults_empty(self):
        fs = _fs("fs-7")
        client = _make_client([{"FileSystems": [fs]}])
        result = fetch_efs(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].name == ""

    def test_multi_page_results(self):
        fs1 = _fs("fs-a")
        fs2 = _fs("fs-b")
        client = _make_client([{"FileSystems": [fs1]}, {"FileSystems": [fs2]}])
        result = fetch_efs(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(result) == 2

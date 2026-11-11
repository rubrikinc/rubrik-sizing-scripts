"""Tests for cloud.py — Azure cloud-environment resolution."""

from unittest.mock import MagicMock, patch

import cloud


def test_default_cloud_is_public():
    assert cloud.DEFAULT_CLOUD.name == "AzureCloud"
    assert cloud.DEFAULT_CLOUD.arm_endpoint == "https://management.azure.com"


def test_credential_scope_derives_from_arm_endpoint():
    gov = cloud._CLOUDS["AzureUSGovernment"]
    assert gov.arm_endpoint == "https://management.usgovcloudapi.net"
    assert gov.credential_scope == "https://management.usgovcloudapi.net/.default"


def test_client_kwargs_carries_endpoint_and_scope():
    gov = cloud._CLOUDS["AzureUSGovernment"]
    kwargs = gov.client_kwargs()
    assert kwargs == {
        "base_url": "https://management.usgovcloudapi.net",
        "credential_scopes": ["https://management.usgovcloudapi.net/.default"],
    }


def test_resolve_explicit_canonical_name():
    with patch("cloud._detect_from_cli", return_value=None):
        assert cloud.resolve_cloud("AzureUSGovernment").name == "AzureUSGovernment"


def test_resolve_explicit_alias():
    with patch("cloud._detect_from_cli", return_value=None):
        assert cloud.resolve_cloud("gov").name == "AzureUSGovernment"
        assert cloud.resolve_cloud("GOVERNMENT").name == "AzureUSGovernment"
        assert cloud.resolve_cloud("public").name == "AzureCloud"


def test_explicit_flag_wins_over_env_and_cli():
    with (
        patch.dict("os.environ", {"AZURE_CLOUD": "AzureCloud"}),
        patch("cloud._detect_from_cli", return_value="AzureCloud"),
    ):
        assert cloud.resolve_cloud("AzureUSGovernment").name == "AzureUSGovernment"


def test_env_var_used_when_no_flag():
    with (
        patch.dict("os.environ", {"AZURE_CLOUD": "AzureUSGovernment"}),
        patch("cloud._detect_from_cli", return_value="AzureCloud"),
    ):
        assert cloud.resolve_cloud(None).name == "AzureUSGovernment"


def test_cli_detection_used_when_no_flag_or_env():
    with (
        patch.dict("os.environ", {}, clear=True),
        patch("cloud._detect_from_cli", return_value="AzureUSGovernment"),
    ):
        assert cloud.resolve_cloud(None).name == "AzureUSGovernment"


def test_defaults_to_public_when_nothing_set():
    with (
        patch.dict("os.environ", {}, clear=True),
        patch("cloud._detect_from_cli", return_value=None),
    ):
        assert cloud.resolve_cloud(None) is cloud.DEFAULT_CLOUD


def test_unrecognised_value_falls_through_to_next_source():
    # A typo on --cloud should not crash; env var (valid) takes over.
    with (
        patch.dict("os.environ", {"AZURE_CLOUD": "AzureUSGovernment"}),
        patch("cloud._detect_from_cli", return_value=None),
    ):
        assert cloud.resolve_cloud("AzureBogusCloud").name == "AzureUSGovernment"


def test_unrecognised_everywhere_defaults_to_public():
    with (
        patch.dict("os.environ", {}, clear=True),
        patch("cloud._detect_from_cli", return_value=None),
    ):
        assert cloud.resolve_cloud("nonsense") is cloud.DEFAULT_CLOUD


def test_detect_from_cli_reads_az_cloud_show():
    fake = MagicMock(returncode=0, stdout="AzureUSGovernment\n")
    with patch("cloud.subprocess.run", return_value=fake) as run:
        assert cloud._detect_from_cli() == "AzureUSGovernment"
    run.assert_called_once()


def test_detect_from_cli_returns_none_on_failure():
    with patch("cloud.subprocess.run", side_effect=FileNotFoundError):
        assert cloud._detect_from_cli() is None

"""Pytest configuration and shared fixtures for GCP collector tests.

All GCP SDK calls are mocked — no credentials or live APIs are needed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

PROJECT_ID = "test-project-123"
ORG_ID = "123456789"
ZONE = "us-central1-a"
REGION = "us-central1"


@pytest.fixture(autouse=True)
def no_real_monitoring_calls():
    """Cloud Monitoring is never reached from a test.

    The storage collector asks Monitoring for bucket sizes. Without this, a test that only
    patches the Storage client would send a real request to Google with fake credentials (and
    get a 401). A test that wants Monitoring data patches ``MetricServiceClient`` itself, which
    replaces this.
    """
    refused = MagicMock(side_effect=RuntimeError("a test reached the real Cloud Monitoring API"))
    with patch("google.cloud.monitoring_v3.MetricServiceClient", refused):
        yield


@pytest.fixture
def mock_credentials():
    """Fake google.auth Credentials that passes isinstance checks."""
    cred = MagicMock()
    cred.token = "fake-token"
    cred.valid = True
    cred.expired = False
    return cred


@pytest.fixture
def mock_project():
    """A single ACTIVE project mock."""
    proj = MagicMock()
    proj.project_id = PROJECT_ID
    proj.display_name = "Test Project"
    proj.state = MagicMock()
    proj.state.name = "ACTIVE"
    return proj


@pytest.fixture
def mock_asset_instance():
    """A single CAI asset representing a GCE instance."""
    asset = MagicMock()
    asset.name = f"//compute.googleapis.com/projects/{PROJECT_ID}/zones/{ZONE}/instances/test-vm-1"
    asset.asset_type = "compute.googleapis.com/Instance"
    return asset


@pytest.fixture
def mock_asset_bucket():
    """A single CAI asset representing a GCS bucket."""
    asset = MagicMock()
    asset.name = f"//storage.googleapis.com/projects/{PROJECT_ID}/buckets/test-bucket"
    asset.asset_type = "storage.googleapis.com/Bucket"
    return asset

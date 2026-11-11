"""Tests for collectors/devops.py — Azure DevOps repository discovery."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from collectors.devops import (
    DevOpsCollector,
    DevOpsInventory,
    DevOpsOrg,
    DevOpsProject,
    DevOpsRepo,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_credential():
    cred = MagicMock()
    token = MagicMock()
    token.token = "fake-token"
    cred.get_token.return_value = token
    return cred


def _mock_responses(profile=None, accounts=None, projects=None, repos=None):
    """Build a side_effect function for requests.get that returns canned data."""

    def _get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200

        if "profile/profiles/me" in url:
            resp.json.return_value = profile or {"id": "member-123", "displayName": "Test"}
        elif "_apis/accounts" in url:
            resp.json.return_value = accounts or {"value": []}
        elif "_apis/projects" in url:
            resp.json.return_value = projects or {"value": []}
        elif "_apis/git/repositories" in url:
            resp.json.return_value = repos or {"value": []}
        else:
            resp.json.return_value = {}

        return resp

    return _get


# ---------------------------------------------------------------------------
# Dataclass construction
# ---------------------------------------------------------------------------


def test_devops_repo_defaults():
    r = DevOpsRepo(name="my-repo", project_name="proj", org_name="org")
    assert r.size_bytes == 0
    assert r.default_branch is None
    assert not r.is_disabled


def test_devops_inventory_empty():
    inv = DevOpsInventory()
    assert inv.total_orgs == 0
    assert inv.total_repos == 0
    assert inv.total_repo_size_gb == 0.0


# ---------------------------------------------------------------------------
# Token acquisition
# ---------------------------------------------------------------------------


def test_token_failure_returns_empty_inventory():
    cred = MagicMock()
    cred.get_token.side_effect = Exception("No DevOps access")
    collector = DevOpsCollector(cred)
    result = collector.collect()
    assert isinstance(result, DevOpsInventory)
    assert result.total_repos == 0
    assert "token unavailable" in result.data_note.lower()


# ---------------------------------------------------------------------------
# Org discovery
# ---------------------------------------------------------------------------


@patch("collectors.devops.requests.get")
def test_discover_orgs_returns_list(mock_get):
    mock_get.side_effect = _mock_responses(
        accounts={
            "value": [
                {"accountName": "my-org", "accountId": "id-1"},
                {"accountName": "other-org", "accountId": "id-2"},
            ]
        }
    )
    collector = DevOpsCollector(_fake_credential())
    orgs = collector.discover_orgs()
    assert len(orgs) == 2
    assert orgs[0]["accountName"] == "my-org"


@patch("collectors.devops.requests.get")
def test_discover_orgs_with_filter(mock_get):
    mock_get.side_effect = _mock_responses(
        accounts={
            "value": [
                {"accountName": "my-org", "accountId": "id-1"},
                {"accountName": "other-org", "accountId": "id-2"},
            ]
        }
    )
    collector = DevOpsCollector(_fake_credential(), org_filter=["my-org"])
    orgs = collector.discover_orgs()
    assert len(orgs) == 1
    assert orgs[0]["accountName"] == "my-org"


@patch("collectors.devops.requests.get")
def test_discover_orgs_filter_case_insensitive(mock_get):
    mock_get.side_effect = _mock_responses(
        accounts={
            "value": [
                {"accountName": "MyOrg", "accountId": "id-1"},
            ]
        }
    )
    collector = DevOpsCollector(_fake_credential(), org_filter=["myorg"])
    orgs = collector.discover_orgs()
    assert len(orgs) == 1


@patch("collectors.devops.requests.get")
def test_discover_orgs_empty_profile(mock_get):
    mock_get.side_effect = _mock_responses(profile={})
    collector = DevOpsCollector(_fake_credential())
    orgs = collector.discover_orgs()
    assert orgs == []


# ---------------------------------------------------------------------------
# Full collect
# ---------------------------------------------------------------------------


@patch("collectors.devops.requests.get")
def test_collect_full_inventory(mock_get):
    call_count = {"n": 0}

    def _get(url, **kwargs):
        call_count["n"] += 1
        resp = MagicMock()
        resp.status_code = 200

        if "profile/profiles/me" in url:
            resp.json.return_value = {"id": "member-1"}
        elif "_apis/accounts" in url:
            resp.json.return_value = {
                "value": [
                    {"accountName": "test-org", "accountId": "org-1"},
                ]
            }
        elif "_apis/projects" in url:
            resp.json.return_value = {
                "value": [
                    {"name": "Project-A", "id": "p1", "state": "wellFormed"},
                    {"name": "Project-B", "id": "p2", "state": "wellFormed"},
                ]
            }
        elif "Project-A" in url and "repositories" in url:
            resp.json.return_value = {
                "value": [
                    {
                        "name": "repo-1",
                        "size": 1048576,
                        "defaultBranch": "refs/heads/main",
                        "webUrl": "https://dev.azure.com/test-org/Project-A/_git/repo-1",
                        "isDisabled": False,
                    },
                    {
                        "name": "repo-2",
                        "size": 2097152,
                        "defaultBranch": "refs/heads/main",
                        "webUrl": "https://dev.azure.com/test-org/Project-A/_git/repo-2",
                        "isDisabled": False,
                    },
                ]
            }
        elif "Project-B" in url and "repositories" in url:
            resp.json.return_value = {
                "value": [
                    {
                        "name": "repo-3",
                        "size": 524288,
                        "defaultBranch": "refs/heads/develop",
                        "webUrl": "https://dev.azure.com/test-org/Project-B/_git/repo-3",
                        "isDisabled": False,
                    },
                ]
            }
        else:
            resp.json.return_value = {"value": []}
        return resp

    mock_get.side_effect = _get
    collector = DevOpsCollector(_fake_credential())
    result = collector.collect()

    assert result.total_orgs == 1
    assert result.total_projects == 2
    assert result.total_repos == 3
    assert result.total_repo_size_gb > 0
    assert len(result.orgs) == 1
    assert result.orgs[0].name == "test-org"
    assert result.orgs[0].total_repos == 3
    assert result.org_names == ["test-org"]


@patch("collectors.devops.requests.get")
def test_collect_no_orgs_returns_note(mock_get):
    mock_get.side_effect = _mock_responses(accounts={"value": []})
    collector = DevOpsCollector(_fake_credential())
    result = collector.collect()
    assert result.total_repos == 0
    assert "no azure devops" in result.data_note.lower()


@patch("collectors.devops.requests.get")
def test_collect_handles_401(mock_get):
    def _get(url, **kwargs):
        resp = MagicMock()
        if "profile/profiles/me" in url:
            resp.status_code = 200
            resp.json.return_value = {"id": "m1"}
        elif "_apis/accounts" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "value": [
                    {"accountName": "org-1", "accountId": "x"},
                ]
            }
        elif "_apis/projects" in url:
            resp.status_code = 401
            resp.json.return_value = {}
        else:
            resp.status_code = 200
            resp.json.return_value = {"value": []}
        return resp

    mock_get.side_effect = _get
    collector = DevOpsCollector(_fake_credential())
    result = collector.collect()
    assert result.total_orgs == 1
    assert result.total_repos == 0


# ---------------------------------------------------------------------------
# Serialization (for DiscoveryResult)
# ---------------------------------------------------------------------------


def test_inventory_serializable():
    import dataclasses

    inv = DevOpsInventory(
        orgs=[
            DevOpsOrg(
                name="org1",
                account_id="id1",
                projects=[
                    DevOpsProject(
                        name="proj1",
                        org_name="org1",
                        repos=[
                            DevOpsRepo(
                                name="r1", project_name="proj1", org_name="org1", size_bytes=1000
                            )
                        ],
                        repo_count=1,
                    )
                ],
                total_projects=1,
                total_repos=1,
                total_repo_size_bytes=1000,
            )
        ],
        total_orgs=1,
        total_projects=1,
        total_repos=1,
        total_repo_size_gb=0.01,
        org_names=["org1"],
    )
    d = dataclasses.asdict(inv)
    assert d["total_repos"] == 1
    assert d["orgs"][0]["name"] == "org1"
    assert d["orgs"][0]["projects"][0]["repos"][0]["name"] == "r1"

    import json

    json.dumps(d)

"""Tests for auth.py — all GCP SDK calls are mocked."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import auth

# ── normalise_regions ──────────────────────────────────────────────────────────


def test_normalise_regions_none():
    assert auth.normalise_regions(None) is None


def test_normalise_regions_empty_list():
    assert auth.normalise_regions([]) is None


def test_normalise_regions_strips_spaces():
    assert auth.normalise_regions([" us-central1 ", "us-east1"]) == [
        "us-central1",
        "us-east1",
    ]


def test_normalise_regions_lowercases():
    assert auth.normalise_regions(["US-CENTRAL1"]) == ["us-central1"]


def test_normalise_regions_filters_blank_entries():
    assert auth.normalise_regions(["us-central1", "", "  "]) == ["us-central1"]


def test_normalise_regions_all_blank_returns_none():
    assert auth.normalise_regions(["", "  "]) is None


# ── zone_to_region ─────────────────────────────────────────────────────────────


def test_zone_to_region_standard():
    assert auth.zone_to_region("us-central1-a") == "us-central1"


def test_zone_to_region_europe():
    assert auth.zone_to_region("europe-west1-b") == "europe-west1"


def test_zone_to_region_asia():
    assert auth.zone_to_region("asia-east1-c") == "asia-east1"


def test_zone_to_region_already_region():
    # A region string (no trailing single letter) should be returned as-is.
    assert auth.zone_to_region("us-central1") == "us-central1"


def test_zone_to_region_empty():
    assert auth.zone_to_region("") == ""


def test_zone_to_region_does_not_strip_multi_char_suffix():
    # "us-central1-ab" does not look like a zone — should return unchanged.
    assert auth.zone_to_region("us-central1-ab") == "us-central1-ab"


# ── resolve_projects — explicit IDs ───────────────────────────────────────────


def _make_project(project_id: str, display_name: str = "Test", state: str = "ACTIVE"):
    proj = MagicMock()
    proj.project_id = project_id
    proj.display_name = display_name
    proj.state = MagicMock()
    proj.state.name = state
    return proj


_RM_CLIENT = "google.cloud.resourcemanager_v3.ProjectsClient"


def test_resolve_projects_validates_explicit_ids():
    mock_client = MagicMock()
    mock_client.get_project.return_value = _make_project("my-project")

    with patch(_RM_CLIENT, return_value=mock_client):
        result = auth.resolve_projects(MagicMock(), ["my-project"], all_projects=False)

    assert result == ["my-project"]
    mock_client.get_project.assert_called_once_with(name="projects/my-project")


def test_resolve_projects_skips_inaccessible():
    mock_client = MagicMock()
    mock_client.get_project.side_effect = [
        Exception("permission denied"),
        _make_project("good-project"),
    ]

    with patch(_RM_CLIENT, return_value=mock_client):
        result = auth.resolve_projects(
            MagicMock(), ["bad-project", "good-project"], all_projects=False
        )

    assert result == ["good-project"]


def test_resolve_projects_exits_when_all_invalid():
    mock_client = MagicMock()
    mock_client.get_project.side_effect = Exception("not found")

    with patch(_RM_CLIENT, return_value=mock_client):
        with patch("auth._exit_no_projects") as mock_exit:
            mock_exit.side_effect = SystemExit(1)
            with pytest.raises(SystemExit):
                auth.resolve_projects(MagicMock(), ["bad-id"], all_projects=False)
    mock_exit.assert_called_once()


def test_resolve_projects_strips_whitespace_from_ids():
    mock_client = MagicMock()
    mock_client.get_project.return_value = _make_project("my-project")

    with patch(_RM_CLIENT, return_value=mock_client):
        result = auth.resolve_projects(MagicMock(), ["  my-project  "], all_projects=False)

    assert result == ["my-project"]
    mock_client.get_project.assert_called_once_with(name="projects/my-project")


# ── resolve_projects — --all ───────────────────────────────────────────────────


def test_resolve_projects_all_flag_returns_active_only():
    projects = [
        _make_project("p1", state="ACTIVE"),
        _make_project("p2", state="DELETE_REQUESTED"),
        _make_project("p3", state="ACTIVE"),
    ]
    mock_client = MagicMock()
    mock_client.search_projects.return_value = iter(projects)

    with patch(_RM_CLIENT, return_value=mock_client):
        result = auth.resolve_projects(MagicMock(), None, all_projects=True)

    assert "p1" in result
    assert "p3" in result


@pytest.mark.parametrize(
    "project_id, expected",
    [
        ("sys-13654623767126417327133771", True),
        ("sys-1", True),
        ("sys-", False),
        ("sys-abc", False),
        ("sys-123-prod", False),
        ("my-sys-123", False),
        ("sys-123x", False),
        ("prod-project", False),
    ],
)
def test_is_google_system_project(project_id, expected):
    assert auth.is_google_system_project(project_id) is expected


def test_resolve_projects_all_flag_leaves_out_google_system_projects(caplog):
    projects = [
        _make_project("p1"),
        _make_project("sys-13654623767126417327133771"),
        _make_project("sys-my-own-project"),
        _make_project("sys-98765"),
    ]
    mock_client = MagicMock()
    mock_client.search_projects.return_value = iter(projects)

    with patch(_RM_CLIENT, return_value=mock_client):
        with caplog.at_level("INFO", logger=auth.logger.name):
            result = auth.resolve_projects(MagicMock(), None, all_projects=True)

    assert result == ["p1", "sys-my-own-project"]
    assert "Left out 2 Google system project(s)" in caplog.text


def test_resolve_projects_all_flag_exits_when_only_system_projects():
    mock_client = MagicMock()
    mock_client.search_projects.return_value = iter([_make_project("sys-123")])

    with patch(_RM_CLIENT, return_value=mock_client):
        with patch("auth._exit_no_projects") as mock_exit:
            mock_exit.side_effect = SystemExit(1)
            with pytest.raises(SystemExit):
                auth.resolve_projects(MagicMock(), None, all_projects=True)
    mock_exit.assert_called_once()


def test_resolve_projects_include_system_projects_keeps_them(caplog):
    projects = [_make_project("p1"), _make_project("sys-13654623767126417327133771")]
    mock_client = MagicMock()
    mock_client.search_projects.return_value = iter(projects)

    with patch(_RM_CLIENT, return_value=mock_client):
        with caplog.at_level("INFO", logger=auth.logger.name):
            result = auth.resolve_projects(
                MagicMock(), None, all_projects=True, include_system_projects=True
            )

    assert result == ["p1", "sys-13654623767126417327133771"]
    assert "Left out" not in caplog.text


def test_include_system_projects_flag_defaults_off_and_parses():
    import main

    parser = main._build_parser()
    assert parser.parse_args([]).include_system_projects is False
    assert parser.parse_args(["--include-system-projects"]).include_system_projects is True


def test_resolve_projects_explicit_system_project_is_still_scanned():
    mock_client = MagicMock()
    mock_client.get_project.return_value = _make_project("sys-123")

    with patch(_RM_CLIENT, return_value=mock_client):
        result = auth.resolve_projects(MagicMock(), ["sys-123"], all_projects=False)

    assert result == ["sys-123"]


def test_resolve_projects_all_flag_exits_when_empty():
    mock_client = MagicMock()
    mock_client.search_projects.return_value = iter([])

    with patch(_RM_CLIENT, return_value=mock_client):
        with patch("auth._exit_no_projects") as mock_exit:
            mock_exit.side_effect = SystemExit(1)
            with pytest.raises(SystemExit):
                auth.resolve_projects(MagicMock(), None, all_projects=True)


# ── resolve_projects — auto-detect ────────────────────────────────────────────


def test_resolve_projects_autodetect_via_gcloud():
    mock_client = MagicMock()
    mock_client.get_project.return_value = _make_project("detected-project")

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "detected-project\n"

    with patch("auth.google.auth.default", return_value=(MagicMock(), None)):
        with patch(_RM_CLIENT, return_value=mock_client):
            with patch("auth.subprocess.run", return_value=mock_proc):
                result = auth.resolve_projects(MagicMock(), None, all_projects=False)

    assert result == ["detected-project"]


def test_resolve_projects_autodetect_via_adc_default_project():
    mock_client = MagicMock()
    mock_client.get_project.return_value = _make_project("adc-project")

    with patch("auth.google.auth.default", return_value=(MagicMock(), "adc-project")):
        with patch(_RM_CLIENT, return_value=mock_client):
            result = auth.resolve_projects(MagicMock(), None, all_projects=False)

    assert result == ["adc-project"]


def test_resolve_projects_autodetect_falls_back_to_exit_on_failure():
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""

    with patch("auth.google.auth.default", return_value=(MagicMock(), None)):
        with patch("auth.subprocess.run", return_value=mock_proc):
            with patch("auth._exit_no_projects") as mock_exit:
                mock_exit.side_effect = SystemExit(1)
                with pytest.raises(SystemExit):
                    auth.resolve_projects(MagicMock(), None, all_projects=False)

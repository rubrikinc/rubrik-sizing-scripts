"""Tests for default project scope and --project-file."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import auth
import main
import pytest


def _args(argv):
    return main._build_parser().parse_args(argv)


def _project(pid):
    p = MagicMock()
    p.project_id = pid
    p.state = "ACTIVE"
    return p


def test_default_scope_is_all_accessible_projects():
    client = MagicMock()
    client.search_projects.return_value = iter([_project("p1"), _project("p2")])
    with patch("google.cloud.resourcemanager_v3.ProjectsClient", return_value=client):
        assert auth.resolve_projects(MagicMock(), None) == ["p1", "p2"]


def test_current_project_flag_parses_and_is_exclusive():
    assert _args(["--current-project"]).current_project is True
    with pytest.raises(SystemExit):
        _args(["--current-project", "--projects", "a"])
    with pytest.raises(SystemExit):
        _args(["--project-file", "f.txt", "--projects", "a"])


def test_all_flag_still_accepted():
    assert _args(["--all"]).all is True


def test_read_project_file_trims_and_skips_blanks_comments_dupes(tmp_path):
    f = tmp_path / "projects.txt"
    f.write_text("  proj-a  \n\n# note\nproj-b\nproj-a\r\n")
    assert main._read_project_file(f) == ["proj-a", "proj-b"]


def test_read_project_file_empty_exits(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("\n# only a comment\n")
    with pytest.raises(SystemExit):
        main._read_project_file(f)


def test_read_project_file_missing_exits(tmp_path):
    with pytest.raises(SystemExit):
        main._read_project_file(tmp_path / "nope.txt")


def _cfg(**scope):
    from types import SimpleNamespace

    from config import ScopeConfig

    return SimpleNamespace(scope=ScopeConfig(**scope))


def test_default_with_no_config_is_all_projects():
    assert main._current_project_only(_args([]), _cfg()) is False


def test_explicit_config_all_projects_false_means_current_project():
    assert main._current_project_only(_args([]), _cfg(all_projects=False)) is True
    assert main._current_project_only(_args([]), _cfg(all=False)) is True


def test_config_all_projects_true_means_all():
    assert main._current_project_only(_args([]), _cfg(all_projects=True)) is False


def test_cli_flags_override_config():
    assert main._current_project_only(_args(["--current-project"]), _cfg(all_projects=True)) is True
    assert main._current_project_only(_args(["--all"]), _cfg(all_projects=False)) is False
    assert main._current_project_only(_args(["--projects", "a"]), _cfg(all_projects=False)) is False


def test_bad_project_file_fails_before_credentials_are_loaded(tmp_path, monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_credentials",
        lambda: pytest.fail("credentials were loaded before the project file was checked"),
    )
    monkeypatch.setattr(sys, "argv", ["main.py", "--project-file", str(tmp_path / "missing.txt")])
    with pytest.raises(SystemExit):
        main.main()

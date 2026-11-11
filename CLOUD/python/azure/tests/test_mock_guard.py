"""--mock needs tests/fixtures, which the public distribution does not ship."""

import importlib.util
import sys

import main
import pytest


def _run(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["rubrik-discovery", *argv])
    main.main()


def test_fixtures_are_available_in_a_development_checkout():
    assert main._mock_fixtures_available() is True


def test_fixtures_are_unavailable_when_the_tests_package_is_absent(monkeypatch):
    def missing_parent(name):
        raise ModuleNotFoundError("No module named 'tests'")

    monkeypatch.setattr(importlib.util, "find_spec", missing_parent)
    assert main._mock_fixtures_available() is False


def test_mock_without_fixtures_exits_cleanly_before_creating_any_output(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "_mock_fixtures_available", lambda: False)
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, ["--mock"])
    assert exc.value.code == 1
    assert "not available in the public distribution" in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == [], "no output directory or log file may be created"


def test_mock_requested_through_the_config_file_is_guarded_too(monkeypatch, tmp_path, capsys):
    cfg = tmp_path / "rubrik.yaml"
    cfg.write_text("discovery:\n  mock: true\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "_mock_fixtures_available", lambda: False)
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, ["--config", str(cfg)])
    assert exc.value.code == 1
    assert "not available in the public distribution" in capsys.readouterr().out


def test_the_manifest_still_works_without_fixtures(monkeypatch, capsys):
    monkeypatch.setattr(main, "_mock_fixtures_available", lambda: False)
    _run(monkeypatch, ["--manifest", "--mock"])
    assert "Audit Manifest" in capsys.readouterr().out

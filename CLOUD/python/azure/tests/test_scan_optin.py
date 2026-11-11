"""Tests for the optional-scan opt-in (prompts + flags) in main.py."""

from __future__ import annotations

import builtins
import sys

import pytest
from main import _ask_yes_no, _build_parser, _resolve_scans, _unavailable_scans


class _FakeStdin:
    def __init__(self, tty: bool):
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _args(argv):
    return _build_parser().parse_args(argv)


class TestAskYesNo:
    @pytest.mark.parametrize(
        "typed,default,expected",
        [
            ("", True, True),
            ("", False, False),
            ("y", False, True),
            ("yes", False, True),
            ("n", True, False),
            ("nope", True, False),  # anything not y/yes is "no"
        ],
    )
    def test_answers(self, monkeypatch, typed, default, expected):
        monkeypatch.setattr(builtins, "input", lambda *_: typed)
        assert _ask_yes_no("Scan?", default=default) is expected

    def test_eof_returns_default(self, monkeypatch):
        def _raise(*_):
            raise EOFError

        monkeypatch.setattr(builtins, "input", _raise)
        assert _ask_yes_no("Scan?", default=True) is True


class TestResolveScans:
    @pytest.fixture(autouse=True)
    def _defender_available(self, monkeypatch):
        # These tests are about prompts and flags; the Defender SDK is covered below.
        monkeypatch.setattr("main._unavailable_scans", lambda: {})

    def test_non_interactive_defaults_all_on(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(False))
        choices = _resolve_scans(_args([]))
        assert choices == {"cost": True, "capacity": True, "security": True, "backup_jobs": True}

    def test_flags_hard_skip_without_prompting_for_them(self, monkeypatch):
        # isatty True: flagged scans skip with NO prompt; only the unflagged one prompts.
        monkeypatch.setattr("sys.stdin", _FakeStdin(True))
        prompts: list[str] = []

        def _record(prompt=""):
            prompts.append(prompt)
            return "y"

        monkeypatch.setattr(builtins, "input", _record)
        choices = _resolve_scans(_args(["--no-cost", "--no-capacity", "--no-security"]))
        assert choices["cost"] is False
        assert choices["capacity"] is False
        assert choices["security"] is False
        assert choices["backup_jobs"] is True  # unflagged → prompted, answered "y"
        assert len(prompts) == 1  # only the one unflagged scan prompted

    def test_interactive_prompts_when_not_flagged(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(True))
        monkeypatch.setattr(builtins, "input", lambda *_: "n")  # decline everything
        choices = _resolve_scans(_args([]))
        assert choices == {
            "cost": False,
            "capacity": False,
            "security": False,
            "backup_jobs": False,
        }

    def test_mock_run_never_prompts(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(True))
        monkeypatch.setattr(builtins, "input", lambda *_: pytest.fail("mock runs must not prompt"))
        choices = _resolve_scans(_args(["--mock"]))
        assert all(choices.values())  # mock → non-interactive → all default on


class TestScanThatCannotRun:
    """Defender needs azure-mgmt-security; without it in the environment, do not ask about it."""

    @pytest.fixture(autouse=True)
    def _no_defender_sdk(self, monkeypatch):
        monkeypatch.setattr("collectors.defender.HAS_SDK", False)

    def test_it_is_not_prompted_for_and_is_off(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(True))
        prompts: list[str] = []

        def _record(prompt=""):
            prompts.append(prompt)
            return "y"

        monkeypatch.setattr(builtins, "input", _record)
        choices = _resolve_scans(_args(["--no-cost"]))
        assert choices == {"cost": False, "capacity": True, "security": False, "backup_jobs": True}
        assert len(prompts) == 2 and not any("Defender" in p for p in prompts)

    def test_the_note_says_why_and_how_to_install_it(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", _FakeStdin(False))
        _resolve_scans(_args([]))
        out = capsys.readouterr().out
        assert "Skipping the security scan" in out and "Microsoft Defender" in out
        assert "To enable it: pip install -r requirements.txt" in out.splitlines()[1]

    def test_a_run_that_is_not_interactive_leaves_it_off_too(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(False))
        choices = _resolve_scans(_args([]))
        assert choices == {"cost": True, "capacity": True, "security": False, "backup_jobs": True}

    def test_asking_for_it_off_with_the_flag_is_silent(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", _FakeStdin(False))
        choices = _resolve_scans(_args(["--no-security"]))
        assert choices["security"] is False
        assert "Skipping the security scan" not in capsys.readouterr().out

    def test_the_other_scans_are_still_offered(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(True))
        monkeypatch.setattr(builtins, "input", lambda *_: "n")
        choices = _resolve_scans(_args([]))
        assert choices == {
            "cost": False,
            "capacity": False,
            "security": False,
            "backup_jobs": False,
        }

    def test_with_the_sdk_installed_nothing_is_reported_unavailable(self, monkeypatch):
        monkeypatch.setattr("collectors.defender.HAS_SDK", True)
        assert _unavailable_scans() == {}

    def test_without_the_sdk_defender_is_the_one_scan_reported(self):
        unavailable = _unavailable_scans()
        assert (
            list(unavailable) == ["security"] and "azure-mgmt-security" in unavailable["security"]
        )

    def test_a_failure_while_checking_leaves_every_scan_as_it_was(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "collectors.defender", None)
        assert _unavailable_scans() == {}


class TestPreflightMonitorAccess:
    """The Monitor pre-flight warns up front when capacity will be blank."""

    def _patch_probe(self, monkeypatch, status: str):
        from unittest.mock import MagicMock

        instance = MagicMock()
        instance.probe_monitor_access.return_value = status
        factory = MagicMock(return_value=instance)
        monkeypatch.setattr("collectors.storage.StorageCollector", factory)
        return factory

    def test_denied_emits_warning(self, monkeypatch, capsys):
        from main import _preflight_monitor_access

        self._patch_probe(monkeypatch, "denied")
        _preflight_monitor_access(["sub-1"], object(), None, object())
        out = capsys.readouterr().out
        assert "Monitoring Reader" in out and "denied" in out.lower()

    def test_ok_is_silent(self, monkeypatch, capsys):
        from main import _preflight_monitor_access

        self._patch_probe(monkeypatch, "ok")
        _preflight_monitor_access(["sub-1"], object(), None, object())
        assert "Monitoring Reader" not in capsys.readouterr().out

    def test_skips_subs_without_accounts(self, monkeypatch, capsys):
        from unittest.mock import MagicMock

        from main import _preflight_monitor_access

        # First sub has no accounts → keep probing; second is denied → warn.
        empty, denied = MagicMock(), MagicMock()
        empty.probe_monitor_access.return_value = "no_accounts"
        denied.probe_monitor_access.return_value = "denied"
        factory = MagicMock(side_effect=[empty, denied])
        monkeypatch.setattr("collectors.storage.StorageCollector", factory)

        _preflight_monitor_access(["sub-empty", "sub-denied"], object(), None, object())
        assert factory.call_count == 2
        assert "Monitoring Reader" in capsys.readouterr().out

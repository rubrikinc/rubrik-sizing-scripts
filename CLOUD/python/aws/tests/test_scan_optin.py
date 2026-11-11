"""Tests for the optional-scan opt-in (prompts + flags) in main.py."""

from __future__ import annotations

import builtins
from types import SimpleNamespace

import pytest
from main import _ask_yes_no, _resolve_scans


class _FakeStdin:
    def __init__(self, tty: bool):
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _args(no_cost: bool = False, no_capacity: bool = False) -> SimpleNamespace:
    return SimpleNamespace(no_cost=no_cost, no_capacity=no_capacity)


class TestAskYesNo:
    @pytest.mark.parametrize(
        "typed,default,expected",
        [
            ("", True, True),
            ("", False, False),
            ("y", False, True),
            ("yes", False, True),
            ("n", True, False),
            ("nah", True, False),
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
    def test_non_interactive_defaults_all_on(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(False))
        assert _resolve_scans(_args()) == {"cost": True, "capacity": True}

    def test_flags_hard_skip_without_prompt(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(True))
        monkeypatch.setattr(
            builtins, "input", lambda *_: pytest.fail("flagged scans must not prompt")
        )
        assert _resolve_scans(_args(no_cost=True, no_capacity=True)) == {
            "cost": False,
            "capacity": False,
        }

    def test_interactive_prompts_only_prompted_scans(self, monkeypatch):
        # cost prompts (declined here); capacity has prompt=False so it is
        # always on in an interactive terminal unless --no-capacity is passed.
        monkeypatch.setattr("sys.stdin", _FakeStdin(True))
        monkeypatch.setattr(builtins, "input", lambda *_: "n")
        assert _resolve_scans(_args()) == {"cost": False, "capacity": True}

"""--growth-days and --no-growth: the defaults, the limits, and the value reaching the collector."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

import main


def _args(*argv):
    return main._build_parser().parse_args(list(argv))


def _exits_with(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["main.py", *argv])
    with pytest.raises(SystemExit) as stopped:
        main._main()
    return stopped.value.code, capsys.readouterr().err


# ── parsing and the default ───────────────────────────────────────────────────


def test_growth_is_on_for_thirty_days_unless_told_otherwise():
    assert main._DEFAULT_GROWTH_DAYS == 30
    args = _args()
    assert args.growth_days is None and args.no_growth is False
    assert main._resolve_growth_days(args, set(main._CORE_COLLECTORS)) == 30


def test_growth_days_sets_the_window():
    args = _args("--growth-days", "90")
    assert main._resolve_growth_days(args, set(main._CORE_COLLECTORS)) == 90


def test_no_growth_turns_it_off():
    assert main._resolve_growth_days(_args("--no-growth"), set(main._CORE_COLLECTORS)) is None


def test_growth_is_off_when_the_storage_collector_is_not_running():
    args = _args()
    assert main._resolve_growth_days(args, {"compute", "asset"}) is None
    assert main._resolve_growth_days(args, {"storage"}) == 30


# ── validation ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", ["0", "-5", str(main._MAX_GROWTH_DAYS + 1)])
def test_a_window_outside_the_limits_is_refused_before_any_scan(monkeypatch, capsys, value):
    code, err = _exits_with(monkeypatch, capsys, "--growth-days", value)
    assert code == 2
    assert f"between 1 and {main._MAX_GROWTH_DAYS}" in err


@pytest.mark.parametrize("value", ["1", "30", str(main._MAX_GROWTH_DAYS)])
def test_the_limits_themselves_are_allowed(monkeypatch, capsys, value):
    # Parsing and validation pass; the run is stopped right after by an unrelated conflict.
    code, err = _exits_with(
        monkeypatch, capsys, "--growth-days", value, "--preflight-only", "--no-preflight"
    )
    assert code == 2 and "growth-days must be" not in err


def test_no_growth_with_a_window_is_a_contradiction(monkeypatch, capsys):
    code, err = _exits_with(monkeypatch, capsys, "--no-growth", "--growth-days", "7")
    assert code == 2 and "--no-growth turns growth off" in err


def test_a_window_that_is_not_a_number_is_refused(monkeypatch, capsys):
    code, _ = _exits_with(monkeypatch, capsys, "--growth-days", "month")
    assert code == 2


# ── reaching the collector ────────────────────────────────────────────────────


def test_the_window_is_handed_to_the_storage_collector(mock_credentials):
    with patch("collectors.storage.StorageCollector") as collector:
        collector.return_value.collect.return_value = MagicMock(total_buckets=0)
        collector.return_value.errors = []
        main._collect_project("p", mock_credentials, None, selected={"storage"}, growth_days=14)
    collector.assert_called_once()
    assert collector.call_args.kwargs["growth_days"] == 14


def test_a_run_that_does_not_ask_for_growth_hands_the_collector_none(mock_credentials):
    with patch("collectors.storage.StorageCollector") as collector:
        collector.return_value.collect.return_value = MagicMock(total_buckets=0)
        collector.return_value.errors = []
        main._collect_project("p", mock_credentials, None, selected={"storage"})
    assert collector.call_args.kwargs["growth_days"] is None

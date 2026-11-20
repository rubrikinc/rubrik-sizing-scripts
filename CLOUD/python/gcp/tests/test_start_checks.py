"""The start-of-run checks: a missing Google library fails fast, and a quota project that cannot
serve the calls is confirmed with the user before the scan."""

from __future__ import annotations

import builtins
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import main
import pytest

import preflight

ALL = set(main._CORE_COLLECTORS)


def _hide(monkeypatch, *prefixes):
    """Make imports of the named Google modules fail, as in an environment without them."""
    real = builtins.__import__

    def fake(name, *args, **kwargs):
        if any(name == p or name.startswith(p + ".") for p in prefixes):
            raise ImportError(f"No module named {name!r}")
        return real(name, *args, **kwargs)

    for key in [k for k in sys.modules if any(k.startswith(p) for p in prefixes)]:
        monkeypatch.delitem(sys.modules, key)
    monkeypatch.setattr(builtins, "__import__", fake)


# ── SDK check ─────────────────────────────────────────────────────────────────


def test_with_every_library_installed_nothing_is_missing():
    assert preflight.missing_sdks(ALL) == []


def test_a_missing_library_is_named_with_the_collectors_that_need_it(monkeypatch):
    _hide(monkeypatch, "google.cloud.compute_v1", "google.cloud.asset_v1")
    assert preflight.missing_sdks(ALL) == [
        ("google-cloud-asset", ["asset"]),
        ("google-cloud-compute", ["compute"]),
    ]


def test_a_library_only_a_collector_left_out_needs_is_not_required(monkeypatch):
    _hide(monkeypatch, "google.cloud.compute_v1", "google.cloud.backupdr_v1")
    assert preflight.missing_sdks({"storage", "bigquery"}) == []


def test_every_collector_has_its_libraries_listed():
    assert set(preflight.COLLECTOR_SDKS) == set(main._CORE_COLLECTORS)


def test_the_message_gives_the_install_command_and_the_ways_around_it():
    text = "\n".join(preflight.sdk_problem_lines([("google-cloud-asset", ["asset"])]))
    assert "pip install -r requirements.txt" in text
    assert "pip install google-cloud-asset" in text
    assert "--collectors" in text and "--no-sdk-check" in text


def test_the_run_stops_with_exit_code_2_and_no_log(monkeypatch, capsys):
    _hide(monkeypatch, "google.cloud.compute_v1")
    discarded = []
    monkeypatch.setattr(main, "_discard_run_log", lambda handler, tmp: discarded.append(tmp))
    with pytest.raises(SystemExit) as stop:
        main._require_sdks(ALL, object(), "/tmp/x.log")
    assert stop.value.code == 2 and discarded == ["/tmp/x.log"]
    assert "google-cloud-compute" in capsys.readouterr().out


def test_nothing_happens_when_the_libraries_are_there():
    main._require_sdks(ALL, object(), "/tmp/x.log")  # returns, does not exit


def test_the_check_runs_before_sign_in(monkeypatch, tmp_path):
    import auth

    def boom():
        raise AssertionError("signed in before the library check")

    monkeypatch.setattr(auth, "get_credentials", boom)
    _hide(monkeypatch, "google.cloud.asset_v1")
    monkeypatch.setattr(sys, "argv", ["main.py", "--output", str(tmp_path)])
    with pytest.raises(SystemExit) as stop:
        main._main()
    assert stop.value.code == 2


# ── quota project question ────────────────────────────────────────────────────


def _row(detail, service="compute instances", owner="p1"):
    return {"Owner": owner, "Service": service, "Detail": detail, "Access": "could not be checked"}


QUOTA_ROWS = [_row(preflight.QUOTA_API_OFF), _row(preflight.QUOTA_API_OFF, "compute disks", "p2")]


def _terminal(monkeypatch, answer):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    asked = []
    monkeypatch.setattr(builtins, "input", lambda prompt="": asked.append(prompt) or answer)
    return asked


def test_rows_the_quota_project_refuses_are_found_and_others_are_not():
    other = _row("PermissionDenied")
    assert preflight.quota_blocking_rows([*QUOTA_ROWS, other]) == QUOTA_ROWS
    assert preflight.quota_blocking_rows([other, _row("")]) == []


@pytest.mark.parametrize("answer", ["", "n", "no", "anything"])
def test_at_a_terminal_anything_but_yes_stops_the_run(monkeypatch, answer):
    _terminal(monkeypatch, answer)
    ended = []
    monkeypatch.setattr(main.runlog.core, "end_run", lambda *a, **k: ended.append(a[0]))
    with pytest.raises(SystemExit) as stop:
        main._confirm_quota_project(QUOTA_ROWS)
    assert stop.value.code == 1 and "quota project question" in ended[0]


@pytest.mark.parametrize("answer", ["y", "Y", " yes "])
def test_at_a_terminal_yes_carries_on(monkeypatch, answer):
    asked = _terminal(monkeypatch, answer)
    main._confirm_quota_project(QUOTA_ROWS)
    assert len(asked) == 1


def test_a_closed_input_counts_as_no(monkeypatch):
    _terminal(monkeypatch, "")

    def eof(prompt=""):
        raise EOFError

    monkeypatch.setattr(builtins, "input", eof)
    with pytest.raises(SystemExit):
        main._confirm_quota_project(QUOTA_ROWS)


def test_dash_dash_yes_does_not_ask(monkeypatch):
    asked = _terminal(monkeypatch, "n")
    main._confirm_quota_project(QUOTA_ROWS, assume_yes=True)
    assert asked == []


def test_without_a_terminal_the_run_carries_on_and_says_so(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    main._confirm_quota_project(QUOTA_ROWS)
    assert "No terminal to ask on" in capsys.readouterr().out


def test_no_question_when_the_quota_project_is_fine(monkeypatch):
    asked = _terminal(monkeypatch, "n")
    main._confirm_quota_project([_row("PermissionDenied"), _row("")])
    assert asked == []


def test_the_options_exist():
    args = main._build_parser().parse_args(["--no-sdk-check", "--yes"])
    assert args.no_sdk_check and args.yes

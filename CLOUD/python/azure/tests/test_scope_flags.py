"""Scope flags of the Azure CLI: default is all subscriptions, like PowerShell."""

from unittest.mock import MagicMock, patch

import main
import pytest


def _args(*argv):
    return main._build_parser().parse_args(list(argv))


def _resolve(*argv):
    with patch("auth.resolve_subscriptions", return_value=["x"]) as resolve:
        main._resolve_scope(MagicMock(), _args(*argv), MagicMock())
    return resolve.call_args


def test_no_flag_scans_all_subscriptions():
    call = _resolve()
    assert call.args[1] is None and call.args[2] is True


def test_current_subscription_keeps_the_current_login_only():
    assert _resolve("--current-subscription").args[2] is False


def test_subscription_names_and_groups_are_passed_through_and_not_all():
    call = _resolve("--subscriptions", "Prod, Dev")
    assert call.kwargs["names"] == ["Prod", "Dev"] and call.args[2] is False
    call = _resolve("--management-groups", "mg1")
    assert call.kwargs["management_groups"] == ["mg1"] and call.args[2] is False


def test_subs_ids_stay_explicit():
    call = _resolve("--subs", "a,b")
    assert call.args[1] == ["a", "b"] and call.args[2] is False


def test_scope_flags_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        _args("--subscriptions", "A", "--current-subscription")


@pytest.mark.parametrize("flag", ["--subs", "--subscriptions", "--management-groups"])
@pytest.mark.parametrize("value", ["", "   ", " , ,"])
def test_a_scope_flag_with_no_values_is_refused_and_does_not_widen_to_all(
    monkeypatch, capsys, flag, value
):
    monkeypatch.setattr("sys.argv", ["main.py", flag, value])
    with pytest.raises(SystemExit) as exc:
        main.main()
    err = capsys.readouterr().err
    assert exc.value.code == 2 and flag in err and "every subscription" in err


def test_a_scope_flag_with_values_is_still_accepted():
    assert main._split_csv("a, b") == ["a", "b"]
    assert main._scope_kind(_args("--subs", "a")) == "subs"

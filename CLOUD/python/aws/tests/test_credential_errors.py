"""Sign-in problems get a short, actionable message; every other error keeps its traceback."""

from pathlib import Path

import pytest
from accounts import explain_credential_error
from botocore import exceptions as be

AWS_DIR = Path(__file__).resolve().parents[1]


def client_error(code):
    return be.ClientError({"Error": {"Code": code, "Message": "m"}}, "GetCallerIdentity")


CRT = be.MissingDependencyException(
    msg='Using the login credential provider requires an additional dependency. You will need to pip install "botocore[crt]" before proceeding.'
)
REFRESHED = RuntimeError(
    "Credentials were refreshed, but the refreshed credentials are still expired."
)


def test_missing_crt_package_says_how_to_install_it_or_go_around_it():
    message = explain_credential_error(CRT)
    assert 'pip install "botocore[crt]"' in message
    assert "export-credentials" in message


@pytest.mark.parametrize(
    "exc",
    [
        REFRESHED,
        client_error("ExpiredToken"),
        client_error("ExpiredTokenException"),
        client_error("RequestExpired"),
        be.SSOTokenLoadError(error_msg="cached token is missing"),
        be.UnauthorizedSSOTokenError(),
        be.TokenRetrievalError(provider="sso", error_msg="expired"),
        be.LoginTokenLoadError(error_msg="login session expired"),
    ],
)
def test_expired_sign_ins_say_to_sign_in_again_and_not_to_install_anything(exc):
    message = explain_credential_error(exc)
    assert "sign-in has expired" in message
    assert "aws sso login" in message
    assert "botocore[crt]" not in message


def test_credentials_aws_rejects_are_reported_as_rejected():
    for code in ("InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch"):
        assert "rejected the credentials" in explain_credential_error(client_error(code))


def test_no_credentials_and_partial_credentials_and_unknown_profile():
    assert "No AWS credentials were found" in explain_credential_error(be.NoCredentialsError())
    partial = be.PartialCredentialsError(provider="env", cred_var="AWS_SECRET_ACCESS_KEY")
    assert "AWS_SECRET_ACCESS_KEY" in explain_credential_error(partial)
    unknown = explain_credential_error(be.ProfileNotFound(profile="nope"))
    assert "nope" in unknown and "aws configure list-profiles" in unknown


@pytest.mark.parametrize(
    "exc",
    [
        client_error("AccessDenied"),
        client_error("AccessDeniedException"),
        client_error("Throttling"),
        client_error("UnauthorizedOperation"),
        ValueError("anything else"),
        RuntimeError("some other failure"),
        KeyError("account_id"),
    ],
)
def test_other_errors_are_not_claimed(exc):
    assert explain_credential_error(exc) is None


def test_a_sign_in_problem_inside_another_error_is_still_found():
    try:
        try:
            raise be.NoCredentialsError()
        except be.NoCredentialsError as inner:
            raise RuntimeError("wrapped by a worker") from inner
    except RuntimeError as outer:
        assert "No AWS credentials were found" in explain_credential_error(outer)


def test_a_cycle_in_the_error_chain_does_not_loop():
    first, second = ValueError("a"), ValueError("b")
    first.__context__, second.__context__ = second, first
    assert explain_credential_error(first) is None


def test_the_message_names_the_error_but_never_prints_a_secret():
    exc = be.PartialCredentialsError(provider="env", cred_var="AWS_SECRET_ACCESS_KEY")
    message = explain_credential_error(exc)
    assert "PartialCredentialsError" in message
    assert "AKIA" not in message


class TestMainWrapper:
    def test_a_sign_in_problem_ends_with_a_message_and_exit_code_1(self, monkeypatch, capsys):
        import main

        def fail(argv=None):
            raise REFRESHED

        monkeypatch.setattr(main, "_main", fail)
        with pytest.raises(SystemExit) as stop:
            main.main([])
        assert stop.value.code == 1
        err = capsys.readouterr().err
        assert "sign-in has expired" in err
        assert "Traceback" not in err

    def test_any_other_error_still_raises(self, monkeypatch):
        import main

        def fail(argv=None):
            raise ValueError("a real bug")

        monkeypatch.setattr(main, "_main", fail)
        with pytest.raises(ValueError, match="a real bug"):
            main.main([])

    def test_argument_errors_and_normal_runs_are_untouched(self, monkeypatch):
        import main

        monkeypatch.setattr(main, "_main", lambda argv=None: None)
        assert main.main([]) is None

        def usage(argv=None):
            raise SystemExit(2)

        monkeypatch.setattr(main, "_main", usage)
        with pytest.raises(SystemExit) as stop:
            main.main([])
        assert stop.value.code == 2

    def test_arguments_reach_the_real_entry_point(self, monkeypatch):
        import main

        seen = []
        monkeypatch.setattr(main, "_main", lambda argv=None: seen.append(argv))
        main.main(["--no-cost"])
        assert seen == [["--no-cost"]]


def test_the_login_package_is_a_dependency_of_both_install_paths():
    declared = (AWS_DIR / "requirements.in").read_text().splitlines()
    assert any(line.startswith("botocore[crt]") for line in declared)
    # The pinned requirements.txt lists the extra's package itself, for each supported Python.
    pinned = [
        l
        for l in (AWS_DIR / "requirements.txt").read_text().splitlines()
        if l.startswith("awscrt==")
    ]
    assert pinned, "awscrt, the package botocore[crt] adds, is not pinned"
    assert len(pinned) == 1 or all("python_full_version" in line for line in pinned)
    assert '"botocore[crt]"' in (AWS_DIR / "pyproject.toml").read_text()


# ── what main() does with them ────────────────────────────────────────────────

import logging  # noqa: E402
import tempfile  # noqa: E402

import main  # noqa: E402
from collectors import context  # noqa: E402
from runlog_core import TranscriptHandler  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_partition():
    context.configure()
    yield
    context.configure()


def _failing_run(tmp_path, monkeypatch, error):
    """``main.main()`` for one account, where the scan raises ``error`` after the log is open."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(main, "_resolve_scans", lambda args: {"cost": False, "capacity": True})

    def scan(**kwargs):
        raise error

    monkeypatch.setattr(main, "run", scan)
    main.main(["--output", str(tmp_path / "out")])


def _left_behind(tmp_path):
    handlers = [h for h in logging.getLogger().handlers if isinstance(h, TranscriptHandler)]
    return sorted(p.name for p in tmp_path.glob("aws-sizing-run-*.log")), handlers


@pytest.mark.parametrize(
    "error, said",
    [
        (client_error("ExpiredToken"), "Your AWS sign-in has expired"),
        (be.NoCredentialsError(), "No AWS credentials were found"),
        (CRT, 'pip install "botocore[crt]"'),
    ],
)
def test_a_sign_in_problem_ends_the_run_with_the_message_and_exit_code_1(
    tmp_path, monkeypatch, capsys, error, said
):
    with pytest.raises(SystemExit) as stopped:
        _failing_run(tmp_path, monkeypatch, error)
    captured = capsys.readouterr()
    assert stopped.value.code == 1
    assert said in captured.err and said not in captured.out
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("error", [client_error("ExpiredToken"), RuntimeError("boom")])
def test_a_run_that_fails_leaves_no_log_file_and_no_log_handler_behind(
    tmp_path, monkeypatch, error
):
    with pytest.raises((SystemExit, RuntimeError)):
        _failing_run(tmp_path, monkeypatch, error)
    assert _left_behind(tmp_path) == ([], [])
    assert main._open_run_logs == []


def test_any_other_error_keeps_its_traceback(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match="boom"):
        _failing_run(tmp_path, monkeypatch, RuntimeError("boom"))


def test_an_access_denied_on_one_service_is_not_called_a_sign_in_problem(tmp_path, monkeypatch):
    with pytest.raises(be.ClientError):
        _failing_run(tmp_path, monkeypatch, client_error("AccessDenied"))
    assert _left_behind(tmp_path) == ([], [])


def test_an_interrupt_is_not_swallowed_and_still_cleans_up(tmp_path, monkeypatch):
    with pytest.raises(KeyboardInterrupt):
        _failing_run(tmp_path, monkeypatch, KeyboardInterrupt())
    assert _left_behind(tmp_path) == ([], [])


def test_a_run_that_succeeds_leaves_nothing_registered_and_its_log_in_the_zip(
    tmp_path, monkeypatch
):
    from tests.test_runlog import _single_run

    text = _single_run(tmp_path, monkeypatch)
    assert "Discovery run started." in text
    assert main._open_run_logs == []
    assert _left_behind(tmp_path)[1] == []

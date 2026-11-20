"""What a multi-account scan says about access to each account.

Every account that is not scanned keeps rows in the pre-flight CSV and is named at the end, and
``--preflight-only`` checks every account without collecting anything.
"""

import csv
import io
import json
import logging
import os
import re
import zipfile

import checkpoint_core
import preflight
import pytest
from botocore.exceptions import ClientError
from tests.test_modes import ACCT_A, ACCT_B, FakeSession, _result_for, cli, runner  # noqa: F401

ACCT_SCP = "333333333333"
STAMP = "2026-10-05_140650"
CSV_NAME = f"aws_preflight_check-{STAMP}.csv"


def _client_error(code, message="", operation="AssumeRole"):
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _box_column(out, label):
    """The column the label starts in on its closing-box line, colours removed."""
    (line,) = [ln for ln in re.sub(r"\x1b\[[0-9;]*m", "", out).splitlines() if label in ln]
    return line.index(label)


def _csv_rows(zip_path):
    text = zipfile.ZipFile(zip_path).read(CSV_NAME).decode()
    return list(csv.DictReader(io.StringIO(text)))


def _row(owner, service, scope="us-east-1", access="readable"):
    return {
        "Owner": owner,
        "OwnerName": "",
        "Scope": scope,
        "Service": service,
        "Permission": "ec2:DescribeInstances",
        "Access": access,
        "Outcome": "captured" if access == "readable" else "dropped",
        "ResourcesFound": "yes",
        "Detail": "",
        "OutputFilesAffected": "",
    }


@pytest.fixture()
def denied_role(monkeypatch):
    """Assuming a role whose name contains Broken fails as AWS fails it."""

    def assume(RoleArn, **kwargs):
        FakeSession.assumed.append(RoleArn)
        if "Broken" in RoleArn:
            raise _client_error("AccessDenied", "not authorized to perform: sts:AssumeRole")
        return {"Credentials": {"AccessKeyId": "k", "SecretAccessKey": "s", "SessionToken": "t"}}

    monkeypatch.setattr(FakeSession, "_assume", staticmethod(assume))


@pytest.fixture()
def scans_with_access_rows(runner, monkeypatch):
    """run() writes each account's access-check rows; the SCP account is blocked, one may fail."""
    failing = set()

    def fake_run(output_dir, session, **kwargs):
        account = os.path.basename(output_dir)
        if account in failing:
            raise ValueError("boom")
        if account == ACCT_SCP:
            kwargs["denial_tracker"].record("ec2")
        data = json.loads(json.dumps(_result_for(account)))
        data["access_check"] = [
            _row(
                account,
                "ec2 instances",
                access="access denied" if account == ACCT_SCP else "readable",
            )
        ]
        path = os.path.join(output_dir, "aws_sizing_discovery.json")
        with open(path, "w") as f:
            json.dump(data, f)
        runner.scanned.append((account, session))
        return path

    monkeypatch.setattr(runner.main, "run", fake_run)
    runner.failing = failing
    return runner


# ── accounts that are not scanned stay in the report ──────────────────────────


def test_an_account_that_cannot_be_signed_in_to_has_a_sign_in_row_and_is_named(
    runner, denied_role, capsys
):
    zip_path = runner.main.run_org(
        zip_dir=str(runner.dir), role_name="Broken", account_ids=[ACCT_A], stamp=STAMP
    )
    (row,) = _csv_rows(zip_path)
    assert row["Owner"] == ACCT_A and row["Service"] == preflight.SIGN_IN
    assert row["Permission"] == "sts:AssumeRole" and row["Access"] == "access denied"
    assert row["Detail"] == "AccessDenied" and row["Outcome"] == "dropped"
    assert row["OutputFilesAffected"] == preflight.EVERY_FILE
    out = capsys.readouterr().out
    assert "Not scanned:" in out and f"{ACCT_A}  sign in: AccessDenied" in out


def test_the_sign_in_row_names_what_each_mode_needs(runner, monkeypatch):
    def broken(**kwargs):
        raise _client_error("InvalidClientTokenId", operation="GetCallerIdentity")

    monkeypatch.setattr(runner.main.boto3.session, "Session", broken)
    zip_path = runner.main.run_profiles(["bad"], zip_dir=str(runner.dir), stamp=STAMP)
    (row,) = _csv_rows(zip_path)
    assert row["OwnerName"] == "bad" and row["Owner"] == ""
    assert row["Permission"] == "sts:GetCallerIdentity" and row["Access"] == "access denied"


def test_an_account_held_back_by_an_scp_keeps_its_access_rows_but_not_its_results(
    scans_with_access_rows, capsys
):
    zip_path = scans_with_access_rows.main.run_org(
        zip_dir=str(scans_with_access_rows.dir),
        role_name="R",
        account_ids=[ACCT_A, ACCT_SCP],
        stamp=STAMP,
    )
    names = zipfile.ZipFile(zip_path).namelist()
    assert f"{ACCT_SCP}/aws_sizing_discovery.json" not in names
    owners = {(r["Owner"], r["Access"]) for r in _csv_rows(zip_path)}
    assert owners == {(ACCT_A, "readable"), (ACCT_SCP, "access denied")}
    assert f"{ACCT_SCP}  blocked by a service control policy: ec2" in capsys.readouterr().out


def test_an_account_whose_scan_stops_has_a_scan_row(scans_with_access_rows, capsys):
    scans_with_access_rows.failing.add(ACCT_B)
    zip_path = scans_with_access_rows.main.run_org(
        zip_dir=str(scans_with_access_rows.dir),
        role_name="R",
        account_ids=[ACCT_A, ACCT_B],
        stamp=STAMP,
    )
    failed = [r for r in _csv_rows(zip_path) if r["Owner"] == ACCT_B]
    assert [(r["Service"], r["Access"], r["Detail"]) for r in failed] == [
        (preflight.SCAN, "could not be checked", "ValueError")
    ]
    assert f"{ACCT_B}  scan failed: ValueError" in capsys.readouterr().out


def test_a_rerun_lists_only_the_accounts_still_not_scanned(scans_with_access_rows, capsys):
    main = scans_with_access_rows.main
    main.run_org(
        zip_dir=str(scans_with_access_rows.dir), role_name="R", account_ids=[ACCT_A, ACCT_SCP]
    )
    capsys.readouterr()
    zip_path = main.run_org(
        zip_dir=str(scans_with_access_rows.dir),
        role_name="R",
        account_ids=[ACCT_A, ACCT_SCP],
        stamp=STAMP,
        resume_mode=checkpoint_core.RESUME,
    )
    rows = _csv_rows(zip_path)
    assert sorted(r["Owner"] for r in rows) == [ACCT_A, ACCT_SCP]  # one row each, no repeats
    out = capsys.readouterr().out
    assert out.count(ACCT_SCP + "  blocked") == 1 and f"{ACCT_A}  " not in out


def test_the_closing_box_names_twenty_accounts_and_points_to_the_csv_for_the_rest():
    import main

    entries = [
        {"id": f"1000000000{i:02d}", "name": "", "why": "sign in: X", "rows": []} for i in range(25)
    ]
    lines = main._not_scanned_lines(entries)
    assert sum("sign in: X" in line for line in lines) == 20
    assert "5 more" in lines[-1] and "aws_preflight_check" in lines[-1]
    assert main._not_scanned_lines([]) == []


@pytest.mark.parametrize("role", ["R", "Broken"])
def test_the_closing_box_lines_up_its_counts(
    runner, denied_role, scans_with_access_rows, capsys, role
):
    runner.main.run_org(zip_dir=str(runner.dir), role_name=role, account_ids=[ACCT_A], stamp=STAMP)
    out = capsys.readouterr().out
    columns = {_box_column(out, label) for label in ("Accounts scanned", "Failed / skipped")}
    assert columns == {_box_column(out, "Elapsed time")}


def test_sign_in_rows_are_anonymized_like_the_other_files(runner, denied_role):
    from anonymize import Anonymizer

    zip_path = runner.main.run_org(
        zip_dir=str(runner.dir),
        role_name="Broken",
        account_ids=[ACCT_A],
        anonymizer=Anonymizer(),
        stamp=STAMP,
    )
    (row,) = _csv_rows(zip_path)
    assert row["Owner"] != ACCT_A and row["Owner"].startswith("AwsAccountId-")


# ── the sign-in row itself ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "code, access",
    [
        ("AccessDenied", "access denied"),
        ("ForbiddenException", "access denied"),
        ("UnauthorizedException", "access denied"),
        ("InvalidClientTokenId", "access denied"),
        ("RequestTimeout", "could not be checked"),
    ],
)
def test_a_sign_in_failure_is_classified_by_the_aws_error_under_the_wrapper(code, access):
    try:
        try:
            raise _client_error(code, operation="GetRoleCredentials")
        except ClientError as inner:
            raise RuntimeError("cannot assume arn") from inner
    except RuntimeError as exc:
        check = preflight.sign_in_check(ACCT_A, "prod", exc, "sso:GetRoleCredentials")
    row = check.to_row()
    assert (row["Detail"], row["Access"], row["Permission"]) == (
        code,
        access,
        "sso:GetRoleCredentials",
    )
    assert "cannot assume" not in check.message  # the AWS message, not the wrapper's


def test_a_sign_in_row_names_no_account_or_resource_beyond_its_owner():
    exc = _client_error(
        "AccessDenied", f"User arn:aws:sts::{ACCT_B}:assumed-role/x is not authorized"
    )
    row = preflight.sign_in_check(ACCT_A, "prod", exc, "sts:AssumeRole").to_row()
    assert ACCT_B not in json.dumps(row)


# ── --preflight-only ──────────────────────────────────────────────────────────


@pytest.fixture()
def access_only(runner, denied_role, monkeypatch):
    """check_access() returns one row per account; run() must never be called."""
    checked = []

    def fake_check(session, **kwargs):
        account = session.kwargs.get("account", ACCT_A)
        checked.append((account, kwargs))
        return [_row(account, "ec2 instances")]

    def no_run(*args, **kwargs):
        raise AssertionError("--preflight-only must not collect anything")

    monkeypatch.setattr(runner.main, "check_access", fake_check)
    monkeypatch.setattr(runner.main, "run", no_run)
    runner.checked = checked
    return runner


def test_preflight_only_checks_every_account_and_writes_only_the_access_report(access_only, capsys):
    zip_path = access_only.main.run_org(
        zip_dir=str(access_only.dir),
        role_name="R",
        account_ids=[ACCT_A, ACCT_B],
        stamp=STAMP,
        preflight_only=True,
    )
    assert os.path.basename(zip_path) == f"aws_access_check_{STAMP}.zip"
    assert sorted(zipfile.ZipFile(zip_path).namelist()) == [CSV_NAME, "manifest.json"]
    assert len(access_only.checked) == 2
    assert not list(access_only.dir.glob("aws-sizing-progress-*"))
    out = capsys.readouterr().out
    assert "Access Check Complete" in out and "Accounts checked   " in out


def test_preflight_only_reports_the_accounts_it_cannot_sign_in_to(access_only, capsys):
    zip_path = access_only.main.run_org(
        zip_dir=str(access_only.dir),
        role_name="Broken",
        account_ids=[ACCT_A],
        stamp=STAMP,
        preflight_only=True,
    )
    (row,) = _csv_rows(zip_path)
    assert row["Service"] == preflight.SIGN_IN and row["Detail"] == "AccessDenied"
    out = capsys.readouterr().out
    assert "Not checked:" in out
    columns = {_box_column(out, label) for label in ("Accounts checked", "Not checked  ")}
    assert columns == {_box_column(out, "Elapsed time")}


def test_preflight_only_neither_resumes_from_nor_changes_a_progress_folder(access_only):
    progress = access_only.dir / "aws-sizing-progress-20260101-000000" / ACCT_A
    progress.mkdir(parents=True)
    (progress / "aws_sizing_discovery.json").write_text("{}")
    before = sorted(p.name for p in access_only.dir.iterdir())
    access_only.main.run_org(
        zip_dir=str(access_only.dir),
        role_name="R",
        account_ids=[ACCT_A, ACCT_B],
        stamp=STAMP,
        preflight_only=True,
    )
    assert len(access_only.checked) == 2  # the finished account is checked too
    after = sorted(p.name for p in access_only.dir.iterdir())
    assert after == sorted([*before, f"aws_access_check_{STAMP}.zip"])


def test_preflight_only_passes_the_scope_to_the_access_check(access_only):
    access_only.main.run_org(
        zip_dir=str(access_only.dir),
        role_name="R",
        account_ids=[ACCT_A],
        regions=["us-east-1"],
        services=frozenset({"ec2"}),
        collect_cost=False,
        preflight_only=True,
    )
    ((_, kwargs),) = access_only.checked
    assert kwargs["regions"] == ["us-east-1"] and kwargs["services"] == frozenset({"ec2"})
    assert kwargs["collect_cost"] is False


# ── command line ──────────────────────────────────────────────────────────────


def test_preflight_only_reaches_every_multi_account_runner(cli):
    cli.main.main(["--org", "--preflight-only"])
    assert cli.calls["run_org"][1]["preflight_only"] is True
    cli.main.main(["--org"])
    assert cli.calls["run_org"][1]["preflight_only"] is False


def test_preflight_only_for_the_current_account_writes_the_report_and_the_log(
    cli, monkeypatch, tmp_path
):
    main = cli.main
    monkeypatch.setattr(main, "check_access", lambda session, **kw: [_row(ACCT_A, "ec2 instances")])
    monkeypatch.setattr(main, "run", lambda *a, **k: pytest.fail("nothing may be collected"))
    out = tmp_path / "out"
    main.main(["--preflight-only", "--output", str(out)])
    (zip_path,) = out.glob("aws_access_check_*.zip")
    names = zipfile.ZipFile(zip_path).namelist()
    assert any(n.startswith("aws_preflight_check-") for n in names)
    assert any(n.startswith("output_aws_") and n.endswith(".log") for n in names)


def test_preflight_only_for_the_current_account_reports_how_long_the_check_took(
    cli, monkeypatch, tmp_path, capsys
):
    main = cli.main
    clock = iter([100.0, 165.0])
    monkeypatch.setattr(main.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(main, "check_access", lambda session, **kw: [_row(ACCT_A, "ec2 instances")])
    main._check_single_account(str(tmp_path), None, None, None, False, STAMP, None)
    assert "Elapsed time       1m 5s" in re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)


@pytest.mark.parametrize("aliases, logged", [([], f"Account: {ACCT_A}"), (["prod"], "(prod)")])
def test_the_account_line_shows_an_alias_only_when_there_is_one(cli, caplog, aliases, logged):
    class Client:
        def get_caller_identity(self):
            return {"Account": ACCT_A}

        def list_account_aliases(self):
            return {"AccountAliases": aliases}

    class Session:
        def client(self, *args, **kwargs):
            return Client()

    with caplog.at_level(logging.INFO):
        assert cli.main._account_identity(Session()) == (ACCT_A, "prod" if aliases else "")
    (line,) = [r.getMessage() for r in caplog.records if r.getMessage().startswith("Account:")]
    assert line.endswith(logged) and "()" not in line


@pytest.mark.parametrize(
    "argv, message",
    [
        (["--org", "--preflight-only", "--no-preflight"], "cannot skip it"),
        (["--org", "--preflight-only", "--no-csv"], "--no-csv"),
    ],
)
def test_preflight_only_refuses_options_that_contradict_it(cli, capsys, argv, message):
    with pytest.raises(SystemExit) as exc:
        cli.main.main(argv)
    assert exc.value.code == 2 and message in capsys.readouterr().err

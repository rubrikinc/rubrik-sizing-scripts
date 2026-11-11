"""The AWS run log: a transcript of the screen, a digest of the problems with their fixes."""

from __future__ import annotations

import builtins
import io
import json
import logging
import re
import zipfile

import main
import pytest
import runlog
import runlog_core as core
from botocore.exceptions import ClientError
from collectors import context
from logging_setup import ColorFormatter, add_log_file
from tests.test_modes import ACCT_A, _result_for

STAMP_LOG = re.compile(r"output_aws_(\d{4}-\d\d-\d\d_\d{6})\.log")


@pytest.fixture(autouse=True)
def _fresh():
    context.configure()
    core.ISSUES.reset()
    yield
    core.ISSUES.reset()
    context.configure()


def _log_of(zip_path):
    zf = zipfile.ZipFile(zip_path)
    name = next(n for n in zf.namelist() if STAMP_LOG.fullmatch(n))
    return zf.read(name).decode("utf-8")


def _single_run(tmp_path, monkeypatch, argv=(), during=lambda: None, cost=False):
    out = tmp_path / "out"
    out.mkdir()
    json_path = out / "aws_sizing_discovery.json"
    json_path.write_text(json.dumps(_result_for(ACCT_A)))

    def fake_run(**kwargs):
        during()
        return str(json_path)

    monkeypatch.setattr(main, "run", fake_run)
    monkeypatch.setattr(main, "_resolve_scans", lambda args: {"cost": cost, "capacity": True})
    # The fake discovery data has resources in a region with no backup plans, which makes the CSV
    # export warn. That warning is real but unrelated to what these tests are about.
    monkeypatch.setattr(main.csv_export.log, "warning", lambda *a, **k: None)
    main.main(["--output", str(out), *argv])
    return _log_of(next(out.glob("aws_sizing_results_*.zip")))


# ── what the log holds ────────────────────────────────────────────────────────


def test_the_log_is_a_transcript_not_a_debug_dump(tmp_path, monkeypatch):
    def noise():
        logging.getLogger("botocore.hooks").debug("wire noise")
        logging.getLogger("collectors.ec2").debug("a debug detail")
        logging.getLogger("collectors.ec2").info("Region us-east-1: 3 instances")

    text = _single_run(tmp_path, monkeypatch, during=noise)
    assert "wire noise" not in text and "a debug detail" not in text
    assert "Region us-east-1: 3 instances" in text
    assert " DEBUG " not in text and len(text.splitlines()) < 140


def test_the_log_has_a_header_that_explains_it(tmp_path, monkeypatch):
    text = _single_run(tmp_path, monkeypatch, argv=["--no-cost"])
    head = text.splitlines()[:8]
    assert head[0] == "# Run log: AWS sizing tool"
    assert any(line.startswith("# Code: ") for line in head)
    assert any(line.startswith("# Packages: boto3 ") for line in head)
    assert any(line.startswith("# Command line: ") and "--no-cost" in line for line in head)


def test_the_screens_closing_lines_are_in_the_log(tmp_path, monkeypatch):
    text = _single_run(tmp_path, monkeypatch)
    assert "Discovery run started." in text and "Discovery complete. Results written to:" in text


def test_a_clean_run_ends_with_a_summary_that_says_so(tmp_path, monkeypatch):
    text = _single_run(tmp_path, monkeypatch)
    lines = text.rstrip().splitlines()
    assert lines[-3:-1] == ["Run summary", "No warnings or errors were recorded."]
    assert lines[-1].startswith("Run ended: scan finished at ")


def test_a_problem_is_reported_once_with_its_count_and_what_to_do(tmp_path, monkeypatch):
    def failures():
        for region in ("us-east-1", "eu-west-1", "ap-south-1"):
            logging.getLogger("collectors.rds").warning(
                "RDS scan failed in %s: An error occurred (AccessDenied) when calling the "
                "DescribeDBInstances operation: not authorized to perform: rds:DescribeDBInstances",
                region,
            )

    text = _single_run(tmp_path, monkeypatch, during=failures)
    summary = text.split("Run summary", 1)[1]
    assert "1 distinct problem (3 warnings and errors in all):" in summary
    assert "3x RDS scan failed in us-east-1" in summary
    assert "Fix: The role cannot make this read call." in summary
    assert "(docs/troubleshooting.md#aws-access-denied)" in summary


def test_the_log_has_no_colour_codes_even_though_the_console_adds_them(tmp_path, monkeypatch):
    def colourful():
        console = logging.StreamHandler(io.StringIO())
        console.setFormatter(ColorFormatter("%(levelname)s %(message)s"))
        logging.getLogger().addHandler(console)
        try:
            logging.getLogger("collectors.ec2").warning("coloured on the console")
        finally:
            logging.getLogger().removeHandler(console)

    text = _single_run(tmp_path, monkeypatch, during=colourful)
    assert "\x1b" not in text and re.search(
        r"WARNING collectors\.ec2 — coloured on the console", text
    )


# ── boxes and prompts ─────────────────────────────────────────────────────────


def test_a_box_is_printed_and_written_to_the_log_without_its_colours(tmp_path, capsys):
    handler = add_log_file(str(tmp_path / "x.log"))
    try:
        main._print_box(["Scan Complete", "", "Zip: /tmp/x.zip"])
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()
    assert "Scan Complete" in capsys.readouterr().out
    logged = (tmp_path / "x.log").read_text(encoding="utf-8")
    assert "┌" in logged and "│  Scan Complete" in logged and "\x1b" not in logged


@pytest.mark.parametrize("typed, shown", [("y", "y"), ("", "(default)"), ("n", "n")])
def test_a_prompt_and_its_answer_are_in_the_log(tmp_path, monkeypatch, typed, shown):
    monkeypatch.setattr(builtins, "input", lambda *_: typed)
    handler = add_log_file(str(tmp_path / "p.log"))
    try:
        main._ask_yes_no("Scan cost data?")
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()
    assert (tmp_path / "p.log").read_text(
        encoding="utf-8"
    ).strip() == f"Scan cost data? [Y/n] {shown}"


def test_a_prompt_with_no_input_says_so(tmp_path, monkeypatch):
    def eof(*_):
        raise EOFError

    monkeypatch.setattr(builtins, "input", eof)
    handler = add_log_file(str(tmp_path / "e.log"))
    try:
        assert main._ask_yes_no("Scan?", default=False) is False
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()
    assert "(no input)" in (tmp_path / "e.log").read_text(encoding="utf-8")


# ── the pre-flight problems ───────────────────────────────────────────────────


def _denied(code, message):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Operation")


def test_a_blocked_service_is_reported_with_the_error_and_the_fix(tmp_path, monkeypatch):
    import preflight
    from tests.test_preflight import FakeSession, err

    session = FakeSession(
        **{
            "rds.describe_db_instances": err(
                "AccessDeniedException", "explicit deny in a service_control_policy"
            )
        }
    )
    checks = preflight.run_access_check(
        session, "111111111111", "", ["us-east-1", "eu-west-1"], frozenset({"rds"}), False
    )
    handler = add_log_file(str(tmp_path / "pf.log"))
    try:
        preflight.report(checks, "111111111111", "", True)
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()
    text = (tmp_path / "pf.log").read_text(encoding="utf-8")
    assert "Problems found by the pre-flight check:" in text
    assert "rds instances (us-east-1, eu-west-1): ServiceControlPolicy" in text
    assert "Error: An error occurred (AccessDeniedException)" in text
    assert "(docs/troubleshooting.md#aws-scp-deny)" in text
    assert "ServiceControlPolicy" in "\n".join(
        line for line in text.splitlines() if "Fix:" not in line
    )


def test_pre_flight_problems_are_counted_in_the_final_digest(tmp_path, monkeypatch):
    import preflight
    from tests.test_preflight import FakeSession, err

    def blocked():
        session = FakeSession(
            **{"sqs.list_queues": err("AccessDenied", "not authorized to perform: sqs:ListQueues")}
        )
        checks = preflight.run_access_check(
            session,
            "111111111111",
            "",
            ["us-east-1", "eu-west-1", "us-west-2"],
            frozenset({"sqs"}),
            False,
        )
        preflight.report(checks, "111111111111", "", False)

    text = _single_run(tmp_path, monkeypatch, during=blocked)
    summary = text.split("Run summary", 1)[1]
    assert "sqs queues: AccessDenied" in summary and "3x" in summary
    assert "aws-access-denied" in summary


# ── what to do about each error ───────────────────────────────────────────────

REAL_MESSAGES = [
    (
        "An error occurred (ExpiredToken) when calling the GetCallerIdentity operation: "
        "The security token included in the request is expired",
        "aws-sign-in-expired",
    ),
    (
        "Missing Dependency: Using the login credential provider requires an additional dependency. "
        'You will need to pip install "botocore[crt]" before proceeding.',
        "aws-crt-missing",
    ),
    ("Unable to locate credentials", "aws-no-credentials"),
    ("The config profile (prod) could not be found ProfileNotFound", "aws-no-credentials"),
    (
        "An error occurred (AccessDenied) when calling the DescribeDBInstances operation: User: "
        "arn:aws:sts::123456789012:assumed-role/r/u is not authorized to perform: "
        "rds:DescribeDBInstances with an explicit deny in a service control policy",
        "aws-scp-deny",
    ),
    (
        "An error occurred (AccessDeniedException) when calling the GetCostAndUsage operation: "
        "User is not authorized to perform: ce:GetCostAndUsage",
        "aws-cost-explorer",
    ),
    (
        "An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: "
        "You are not authorized to perform this operation.",
        "aws-access-denied",
    ),
    (
        "An error occurred (OptInRequired) when calling the DescribeVolumes operation",
        "aws-region-not-enabled",
    ),
    (
        "An error occurred (Throttling) when calling the ListTagsForResource operation: Rate exceeded",
        "aws-throttled",
    ),
    (
        'Could not connect to the endpoint URL: "https://ec2.me-south-1.amazonaws.com/"',
        "aws-endpoint-unreachable",
    ),
    (
        "Error when retrieving token from sso: Token has expired and refresh failed",
        "aws-sign-in-expired",
    ),
    (
        "An error occurred (RequestExpired) when calling the DescribeInstances operation: "
        "Request has expired.",
        "aws-clock-skew",
    ),
    (
        "An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: "
        "The security token included in the request is invalid.",
        "aws-credentials-rejected",
    ),
    (
        "An error occurred (SignatureDoesNotMatch) when calling the GetCallerIdentity operation: "
        "The request signature we calculated does not match the signature you provided.",
        "aws-credentials-rejected",
    ),
    (
        "[2/9] Cannot sign in to prod: cannot assume arn:aws:iam::111122223333:role/RubrikDiscoveryRole: "
        "An error occurred (AccessDenied) when calling the AssumeRole operation: User: "
        "arn:aws:sts::444455556666:assumed-role/a/b is not authorized to perform: sts:AssumeRole "
        "on resource: arn:aws:iam::111122223333:role/RubrikDiscoveryRole \u2014 skipping",
        "aws-assume-role-failed",
    ),
    (
        "Failed to assume role arn:aws:iam::111122223333:role/Runner: An error occurred "
        "(AccessDenied) when calling the AssumeRole operation: not authorized",
        "aws-assume-role-failed",
    ),
    (
        "Cannot list organization accounts: An error occurred (AWSOrganizationsNotInUseException) "
        "when calling the ListAccounts operation: Your account is not a member of an organization.",
        "aws-org-accounts-unlisted",
    ),
    (
        "Cannot list organization accounts: An error occurred (AccessDeniedException) when calling "
        "the ListAccounts operation: You don't have permissions to access this resource.",
        "aws-org-accounts-unlisted",
    ),
    (
        "[3/9] Cannot sign in to dev: An error occurred (ForbiddenException) when calling the "
        "GetRoleCredentials operation: No access \u2014 skipping",
        "aws-sso",
    ),
    (
        "[4/9] Cannot sign in to test: An error occurred (UnauthorizedException) when calling the "
        "GetRoleCredentials operation: Session token not found or invalid \u2014 skipping",
        "aws-sso",
    ),
    (
        "No SSO session configured for 'https://a.awsapps.com/start' \u2014 using session 'b' "
        "(https://b.awsapps.com/start). Pass the correct --sso-start-url to suppress this warning.",
        "aws-sso",
    ),
    (
        "[1/3] [111122223333 / prod] SCP blocked read access for services: ec2, rds. This account "
        "will NOT be counted as complete \u2014 it will be retried on resume.",
        "aws-scp-deny",
    ),
    (
        "Account 111122223333: 3 IAM permission error(s) prevented full collection \u2014 some "
        "resources may be missing. Check 'scan_errors' in the output JSON.",
        "aws-access-denied",
    ),
    (
        "Recovery point listing in us-east-1 stopped after 60 min; sizes are lower bounds",
        "aws-recovery-points-truncated",
    ),
    (
        "Account 111122223333: backup plan details are missing or incomplete in us-east-1, so "
        "InBackupPlan there comes from AWS Backup's protected resources and BackupPlans is empty",
        "aws-backup-plans-incomplete",
    ),
    (
        "Access denied listing backup vaults in eu-west-1; skipping recovery points",
        "aws-backup-plans-incomplete",
    ),
    (
        "SSL validation failed for https://ec2.us-east-1.amazonaws.com/ [SSL: "
        "CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in "
        "certificate chain (_ssl.c:1006)",
        "aws-certificate-verify-failed",
    ),
    ("Region eu-west-1 scan failed: list index out of range", "aws-account-or-region-failed"),
    (
        "[5/9] Scan failed for 111122223333 (prod): 'NoneType' object is not subscriptable",
        "aws-account-or-region-failed",
    ),
]


@pytest.mark.parametrize("message, expected", REAL_MESSAGES)
def test_each_kind_of_error_gets_its_fix(message, expected):
    found = core.solve(message)
    assert found is not None and found[0] == expected, message


def test_an_error_nobody_has_seen_says_there_is_no_specific_advice():
    assert core.solve("Something entirely unexpected happened") is None
    assert "no specific advice" in runlog.fix_lines("Something entirely unexpected happened")[0]


def test_an_organization_policy_beats_a_plain_denial_and_cost_beats_both():
    scp = "AccessDenied: not authorized to perform: rds:Describe with an explicit deny"
    cost = "AccessDenied: not authorized to perform: ce:GetCostAndUsage"
    assert core.solve(scp)[0] == "aws-scp-deny" and core.solve(cost)[0] == "aws-cost-explorer"


def test_a_failed_role_switch_gets_its_own_fix_not_the_read_permission_one():
    message = (
        "Cannot sign in to prod: cannot assume arn:aws:iam::111122223333:role/R: AccessDenied: "
        "not authorized to perform: sts:AssumeRole"
    )
    assert core.solve(message)[0] == "aws-assume-role-failed"


def test_an_scp_that_denies_the_role_switch_gets_the_role_switch_fix():
    message = (
        "Cannot sign in to prod: cannot assume arn:aws:iam::111122223333:role/R: AccessDenied: "
        "not authorized to perform: sts:AssumeRole with an explicit deny in a service control policy"
    )
    assert core.solve(message)[0] == "aws-assume-role-failed"
    fix = next(s for s in runlog.SOLUTIONS if s.id == "aws-assume-role-failed").fix
    assert "trust policy" in fix


def test_unrecognized_client_is_a_region_during_a_scan_and_rejected_credentials_at_the_start():
    during_scan = (
        "An error occurred (UnrecognizedClientException) when calling the ListTables operation: "
        "The security token included in the request is invalid."
    )
    at_start = (
        "AWS rejected the credentials (ClientError: An error occurred "
        "(UnrecognizedClientException) when calling the GetCallerIdentity operation)"
    )
    assert core.solve(during_scan)[0] == "aws-region-not-enabled"
    assert core.solve(at_start)[0] == "aws-credentials-rejected"


@pytest.mark.parametrize(
    "inner, expected",
    [
        (
            "An error occurred (ExpiredToken): The security token included in the request is expired",
            "aws-sign-in-expired",
        ),
        ("An error occurred (Throttling): Rate exceeded", "aws-throttled"),
        ("AccessDenied: not authorized to perform: ec2:DescribeInstances", "aws-access-denied"),
    ],
)
def test_a_failed_account_or_region_gets_the_fix_of_the_error_inside_it(inner, expected):
    assert core.solve(f"[1/2] Scan failed for 111122223333 (prod): {inner}")[0] == expected
    assert core.solve(f"Region us-east-1 scan failed: {inner}")[0] == expected


def test_the_same_failure_in_other_regions_and_accounts_is_one_problem():
    a = core.normalize(
        "Scan failed in us-east-1 for 123456789012: arn:aws:sts::123456789012:assumed-role/a/b"
    )
    b = core.normalize(
        "Scan failed in eu-west-1 for 999999999999: arn:aws:sts::999999999999:assumed-role/c/d"
    )
    assert a == b


def test_every_fix_has_a_unique_id_and_says_what_to_do():
    ids = [s.id for s in runlog.SOLUTIONS]
    assert len(ids) == len(set(ids)) and all(i.startswith("aws-") for i in ids)
    assert all(len(s.fix) > 40 for s in runlog.SOLUTIONS)


def test_the_new_modules_are_packaged():
    text = open("pyproject.toml", encoding="utf-8").read()
    assert '"runlog"' in text and '"runlog_core"' in text and '"totals"' in text


# ── the totals block ──────────────────────────────────────────────────────────


def test_the_totals_block_is_on_the_screen_and_in_the_log_before_the_closing_line(
    tmp_path, monkeypatch, capsys
):
    text = _single_run(tmp_path, monkeypatch)
    screen = capsys.readouterr().out
    for shown in (screen, text):
        assert "Total # of EC2 instances:" in shown and "Total # of S3 buckets:" in shown
        assert shown.index("Total # of EC2 instances:") < shown.index("Discovery complete.")


def test_a_run_without_cost_says_the_cost_summary_is_missing_on_purpose(tmp_path, monkeypatch):
    text = _single_run(tmp_path, monkeypatch, argv=["--no-cost"])
    assert "Cost data was not collected" in text and "Combined upper bound" not in text


def test_a_run_with_cost_prints_the_cost_summary(tmp_path, monkeypatch):
    text = _single_run(tmp_path, monkeypatch, cost=True)
    assert "AWS Backup cost summary (past 12 months + MTD):" in text
    assert "Combined upper bound" in text and "Cost data was not collected" not in text


def test_the_totals_are_printed_even_when_no_csv_files_are_written(tmp_path, monkeypatch):
    text = _single_run(tmp_path, monkeypatch, argv=["--no-csv"])
    assert "Total # of EC2 instances:" in text


def test_the_totals_agree_with_the_csv_files_in_the_zip(tmp_path, monkeypatch):
    text = _single_run(tmp_path, monkeypatch)
    zf = zipfile.ZipFile(next((tmp_path / "out").glob("aws_sizing_results_*.zip")))
    ec2 = next(n for n in zf.namelist() if n.startswith("aws_ec2_instance_info-"))
    rows = max(zf.read(ec2).decode().count("\n") - 1, 0)
    assert f"Total # of EC2 instances: {rows}" in text


def test_a_failure_in_the_totals_is_a_warning_not_a_crash(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(main.totals, "print_totals", lambda *a, **k: 1 / 0)
    with caplog.at_level("WARNING"):
        text = _single_run(tmp_path, monkeypatch)
    assert "Could not work out the totals" in text and "Discovery complete." in text


def test_an_organization_run_prints_the_totals_of_every_account(tmp_path, capsys):
    progress = tmp_path / "progress"
    for account in (ACCT_A, "999988887777"):
        (progress / account).mkdir(parents=True)
        (progress / account / "aws_sizing_discovery.json").write_text(
            json.dumps(_result_for(account))
        )
    main._package_results(str(progress), str(tmp_path / "all.zip"), 2, 0, collect_cost=False)
    shown = capsys.readouterr().out
    assert "Total # of EC2 instances:" in shown and "Cost data was not collected" in shown


# ── the colour of the totals block ────────────────────────────────────────────

GREEN, RESET = "\033[32m", "\033[0m"


def _totals_region(text):
    start = text.index("Total # of EC2 instances:")
    return text[max(0, start - len(GREEN)) :]


def test_every_line_of_the_totals_is_green_on_the_screen_as_powershell_prints_it(
    tmp_path, monkeypatch, capsys
):
    _single_run(tmp_path, monkeypatch)
    screen = capsys.readouterr().out
    lines = [
        l for l in _totals_region(screen).splitlines() if l.strip().startswith(GREEN + "Total #")
    ]
    assert len(lines) > 10
    assert all(l.startswith(GREEN) and l.endswith(RESET) for l in lines)


def test_the_blank_lines_between_the_totals_carry_no_colour_codes(tmp_path, monkeypatch, capsys):
    _single_run(tmp_path, monkeypatch)
    region = _totals_region(capsys.readouterr().out).split("Discovery complete")[0]
    blank = [l for l in region.splitlines() if not l.replace(GREEN, "").replace(RESET, "").strip()]
    assert blank and all(l == "" for l in blank)


def test_the_log_keeps_the_totals_as_plain_text(tmp_path, monkeypatch):
    text = _single_run(tmp_path, monkeypatch)
    assert "\033" not in text and "[32m" not in text
    assert "Total # of EC2 instances:" in text and "Total # of S3 buckets:" in text


def test_the_green_lines_have_the_same_words_as_the_plain_log_lines(tmp_path, monkeypatch, capsys):
    text = _single_run(tmp_path, monkeypatch)
    screen = capsys.readouterr().out.replace(GREEN, "").replace(RESET, "")
    for line in (l for l in text.splitlines() if l.startswith("Total #")):
        assert line in screen

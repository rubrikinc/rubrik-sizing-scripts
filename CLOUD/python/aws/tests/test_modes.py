"""Tests for the scan modes: accounts, profiles, SSO sign-in, partition, packaging, the CLI."""

import json
import os
import re
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import accounts
import csv_export
import pytest
from accounts import (
    SsoLoginError,
    read_accounts_file,
    resolve_account_ids,
    role_arn,
    select_profiles,
    split_list,
    sso_device_login,
    use_profile_location,
)
from collectors import context

ACCT_A, ACCT_B = "111111111111", "222222222222"


@pytest.fixture(autouse=True)
def _default_partition():
    context.configure()
    yield
    context.configure()


# ── account lists ─────────────────────────────────────────────────────────────


def test_split_list_trims_and_drops_empty_items():
    assert split_list(" a, b ,,c ") == ["a", "b", "c"]
    assert split_list("") == [] and split_list(None) == []


def test_accounts_file_skips_blank_lines_and_a_byte_order_mark(tmp_path):
    path = tmp_path / "accounts.txt"
    path.write_bytes(f"\xef\xbb\xbf{ACCT_A}\n\n  {ACCT_B}  \n\n".encode("latin-1"))
    assert read_accounts_file(str(path)) == [ACCT_A, ACCT_B]


def test_account_ids_come_from_the_option_or_the_file_but_not_both(tmp_path):
    path = tmp_path / "accounts.txt"
    path.write_text(f"{ACCT_B}\n")
    assert resolve_account_ids(f"{ACCT_A}, {ACCT_B}") == [ACCT_A, ACCT_B]
    assert resolve_account_ids("", str(path)) == [ACCT_B]
    assert resolve_account_ids("", "") is None
    with pytest.raises(ValueError, match="not both"):
        resolve_account_ids(ACCT_A, str(path))


def test_role_arn_follows_the_partition():
    assert role_arn(ACCT_A, "Role") == f"arn:aws:iam::{ACCT_A}:role/Role"
    context.configure(govcloud=True)
    assert role_arn(ACCT_A, "Role") == f"arn:aws-us-gov:iam::{ACCT_A}:role/Role"


# ── profiles ──────────────────────────────────────────────────────────────────


def test_profile_selection(monkeypatch):
    monkeypatch.setattr(accounts, "local_profile_names", lambda: ["default", "prod", "staging"])
    assert select_profiles(all_profiles=True) == ["default", "prod", "staging"]
    assert select_profiles("prod, staging") == ["prod", "staging"]
    with pytest.raises(ValueError, match="nope"):
        select_profiles("prod,nope")


def test_local_profile_names_come_from_the_credentials_file(tmp_path, monkeypatch):
    path = tmp_path / "credentials"
    path.write_text("[alpha]\nregion = us-east-1\n[beta]\nregion = us-east-1\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(path))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    assert accounts.local_profile_names() == ["alpha", "beta"]


def test_profile_location_points_boto_at_the_file(tmp_path, monkeypatch):
    path = tmp_path / "creds"
    path.write_text("[x]\n")
    monkeypatch.delenv("AWS_SHARED_CREDENTIALS_FILE", raising=False)
    use_profile_location(str(path))
    assert os.environ["AWS_SHARED_CREDENTIALS_FILE"] == str(path)
    monkeypatch.delenv("AWS_SHARED_CREDENTIALS_FILE")
    with pytest.raises(FileNotFoundError):
        use_profile_location(str(tmp_path / "missing"))


# ── SSO sign-in ───────────────────────────────────────────────────────────────


def _oidc(token_errors=(), start_error=None):
    client = MagicMock()
    client.register_client.return_value = {"clientId": "id", "clientSecret": "value"}
    if start_error:
        client.start_device_authorization.side_effect = start_error
    else:
        client.start_device_authorization.return_value = {
            "deviceCode": "dev",
            "userCode": "ABCD-EFGH",
            "verificationUriComplete": "https://device.example/?code=ABCD-EFGH",
            "expiresIn": 600,
            "interval": 5,
        }
    errors = [
        (
            Exception("pending")
            if e == "pending"
            else type("Err", (Exception,), {"response": {"Error": {"Code": e}}})(e)
        )
        for e in token_errors
    ]
    client.create_token.side_effect = [*errors, {"accessToken": "tok"}]
    return client


def _fake_clock():
    now = {"t": 0.0}
    return (lambda s: now.__setitem__("t", now["t"] + s)), (lambda: now["t"])


def _pending():
    return "AuthorizationPendingException"


def test_device_login_prints_the_link_and_code_and_waits_until_approved():
    shown, (sleep, clock) = [], _fake_clock()
    token = sso_device_login(
        "https://x.awsapps.com/start",
        "eu-west-1",
        client=_oidc([_pending(), _pending()]),
        show=shown.append,
        sleep=sleep,
        now=clock,
    )
    assert token == "tok"
    text = "\n".join(shown)
    assert "https://device.example/?code=ABCD-EFGH" in text and "ABCD-EFGH" in text


def test_device_login_requests_a_public_client_and_the_device_grant():
    client = _oidc()
    sleep, clock = _fake_clock()
    sso_device_login(
        "https://x.awsapps.com/start", client=client, show=lambda _: None, sleep=sleep, now=clock
    )
    client.register_client.assert_called_once_with(clientName="aws-sizing", clientType="public")
    assert (
        client.start_device_authorization.call_args.kwargs["startUrl"]
        == "https://x.awsapps.com/start"
    )
    grant = client.create_token.call_args.kwargs
    assert grant["grantType"] == "urn:ietf:params:oauth:grant-type:device_code"
    assert grant["deviceCode"] == "dev"


def test_device_login_polls_slower_after_a_slow_down_answer():
    waits = []
    sleep, clock = _fake_clock()
    sso_device_login(
        "https://x",
        client=_oidc(["SlowDownException"]),
        show=lambda _: None,
        sleep=lambda s: (waits.append(s), sleep(s))[0],
        now=clock,
    )
    assert waits == [5, 10]


def test_device_login_gives_up_when_the_authorization_expires():
    client = _oidc([_pending()] * 1000)
    sleep, clock = _fake_clock()
    with pytest.raises(SsoLoginError, match="expired"):
        sso_device_login("https://x", client=client, show=lambda _: None, sleep=sleep, now=clock)


def test_device_login_reports_a_denied_or_failed_sign_in():
    sleep, clock = _fake_clock()
    with pytest.raises(SsoLoginError, match="Unable to sign in"):
        sso_device_login(
            "https://x",
            client=_oidc(["AccessDeniedException"]),
            show=lambda _: None,
            sleep=sleep,
            now=clock,
        )
    with pytest.raises(SsoLoginError, match="Unable to start"):
        sso_device_login(
            "https://x", client=_oidc(start_error=Exception("bad url")), show=lambda _: None
        )


def test_sso_token_prefers_the_cache_and_an_explicit_region(monkeypatch):
    import main

    monkeypatch.setattr(main, "_load_sso_token", lambda url: ("cached", "us-west-2"))
    assert main._sso_token("https://x") == ("cached", "us-west-2")
    assert main._sso_token("https://x", "eu-west-1") == ("cached", "eu-west-1")


def test_sso_token_falls_back_to_the_device_flow(monkeypatch):
    import main

    def no_cache(url):
        raise RuntimeError("no cache")

    seen = {}
    monkeypatch.setattr(main, "_load_sso_token", no_cache)
    monkeypatch.setattr(
        main, "sso_device_login", lambda url, region: seen.update(url=url, region=region) or "fresh"
    )
    assert main._sso_token("https://x", "ap-south-1") == ("fresh", "ap-south-1")
    assert seen == {"url": "https://x", "region": "ap-south-1"}
    assert main._sso_token("https://x")[1] == "us-east-1"
    with pytest.raises(SsoLoginError, match="--sso-start-url"):
        main._sso_token("")


# ── partition and query region ────────────────────────────────────────────────


def test_defaults_and_govcloud():
    assert (context.partition_id(), context.query_region()) == ("aws", "us-east-1")
    assert context.cost_explorer_available()
    context.configure(govcloud=True)
    assert (context.partition_id(), context.query_region()) == ("aws-us-gov", "us-gov-east-1")
    assert not context.cost_explorer_available()


def test_a_query_region_names_its_own_partition():
    context.configure(region_to_query="us-gov-west-1")
    assert (context.partition_id(), context.query_region()) == ("aws-us-gov", "us-gov-west-1")
    context.configure(region_to_query="cn-north-1")
    assert context.partition_id() == "aws-cn" and not context.cost_explorer_available()
    context.configure(region_to_query="eu-west-1")
    assert (context.partition_id(), context.query_region()) == ("aws", "eu-west-1")
    context.configure(govcloud=True, region_to_query="us-east-1")
    assert (context.partition_id(), context.query_region()) == ("aws-us-gov", "us-east-1")


def test_account_wide_collectors_call_the_query_region():
    from collectors.route53 import fetch_iam_summary, fetch_route53_zones

    context.configure(govcloud=True)
    session = MagicMock()
    fetch_route53_zones(session, ACCT_A, "")
    fetch_iam_summary(session, ACCT_A, "")
    regions = {c.kwargs["region_name"] for c in session.client.call_args_list}
    assert regions == {"us-gov-east-1"}


def test_no_collector_hard_codes_the_commercial_partition():
    root = Path(__file__).resolve().parents[1] / "collectors"
    offenders = [
        f"{path.name}:{n}"
        for path in root.glob("*.py")
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if "arn:aws:" in line and not line.lstrip().startswith("#")
    ]
    assert offenders == []


def test_cost_explorer_is_skipped_in_govcloud(tmp_path, monkeypatch):
    import main

    context.configure(govcloud=True)
    monkeypatch.setattr(main, "_scan_all_regions", lambda *a, **k: {k2: [] for k2 in _EMPTY_KEYS})
    called = []
    for name in (
        "fetch_backup_costs",
        "fetch_service_costs",
        "fetch_backup_cost_months",
        "fetch_snapshot_storage_costs",
    ):
        monkeypatch.setattr(main, name, lambda *a, _n=name, **k: called.append(_n) or [])
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {"Account": ACCT_A}
    session.client.return_value.list_account_aliases.return_value = {"AccountAliases": []}
    main.run(
        output_dir=str(tmp_path),
        session=session,
        regions=["us-gov-west-1"],
        collect_cost=True,
        access_check=False,
    )
    assert called == []
    assert {c.kwargs.get("region_name") for c in session.client.call_args_list} == {"us-gov-east-1"}


_EMPTY_KEYS = (
    "instances attached unattached rds dynamodb efs fsx s3 kms secrets sqs plans vaults cfn "
    "native_backups rds_snapshots ebs_ami vpcs load_balancers eks_clusters eks_nodegroups kms_keys "
    "redshift fsx_volumes s3_tables glue_iceberg recovery_points recovery_aggregates "
    "truncated_backup_regions"
).split()


# ── the shared account runner ─────────────────────────────────────────────────


class FakeSession:
    """Stands in for boto3.session.Session; remembers how it was made."""

    made: list = []
    assumed: list = []
    sts_account = ACCT_A

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        FakeSession.made.append(self)

    def client(self, service, **kwargs):
        client = MagicMock()
        if service == "sts":
            client.assume_role.side_effect = self._assume
            client.get_caller_identity.return_value = {
                "Account": self.kwargs.get("account", self.sts_account)
            }
        return client

    @staticmethod
    def _assume(RoleArn, **kwargs):
        FakeSession.assumed.append(RoleArn)
        if "Broken" in RoleArn:
            raise Exception("AccessDenied")
        return {
            "Credentials": {
                "AccessKeyId": "k",
                "SecretAccessKey": "s",
                "SessionToken": "t",
                "RoleArn": RoleArn,
            }
        }


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    """main with boto3 sessions faked and run() writing a one-resource JSON per account."""
    import main

    FakeSession.made = []
    FakeSession.assumed = []
    monkeypatch.setattr(main.boto3.session, "Session", FakeSession)
    scanned = []

    def fake_run(output_dir, session, **kwargs):
        account = os.path.basename(output_dir)
        scanned.append((account, session))
        tracker = kwargs["denial_tracker"]
        if account == "333333333333":
            tracker.record("ec2")
        path = os.path.join(output_dir, "aws_sizing_discovery.json")
        data = json.loads(json.dumps(_result_for(account)))
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    monkeypatch.setattr(main, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    return SimpleNamespace(main=main, scanned=scanned, dir=tmp_path)


def _result_for(account):
    from tests.test_csv_export import _result

    return _result(account=account)


def _zip_names(path):
    return zipfile.ZipFile(path).namelist()


def test_org_scan_assumes_the_role_in_each_account_and_zips_with_powershell_names(runner):
    zip_path = runner.main.run_org(
        zip_dir=str(runner.dir),
        role_name="MyRole",
        account_ids=[ACCT_A, ACCT_B],
        stamp="2026-10-05_140650",
    )
    assert os.path.basename(zip_path) == "aws_sizing_results_2026-10-05_140650.zip"
    names = _zip_names(zip_path)
    assert (
        f"{ACCT_A}/aws_sizing_discovery.json" in names
        and f"{ACCT_B}/aws_sizing_discovery.json" in names
    )
    assert "aws_ec2_instance_info-2026-10-05_140650.csv" in names
    assert sorted(a for a, _ in runner.scanned) == [ACCT_A, ACCT_B]
    assert sorted(FakeSession.assumed) == [
        f"arn:aws:iam::{ACCT_A}:role/MyRole",
        f"arn:aws:iam::{ACCT_B}:role/MyRole",
    ]
    keys = [
        s.kwargs["aws_access_key_id"] for s in FakeSession.made if "aws_access_key_id" in s.kwargs
    ]
    assert keys == ["k", "k"]


def test_org_scan_uses_the_govcloud_role_arn(runner):
    context.configure(govcloud=True)
    runner.main.run_org(zip_dir=str(runner.dir), role_name="R", account_ids=[ACCT_A])
    assert FakeSession.assumed == [f"arn:aws-us-gov:iam::{ACCT_A}:role/R"]
    assert all(s.kwargs.get("region_name") == "us-gov-east-1" for s in FakeSession.made)


def test_an_account_whose_role_cannot_be_assumed_is_counted_failed_and_not_scanned(runner, caplog):
    zip_path = runner.main.run_org(
        zip_dir=str(runner.dir), role_name="Broken", account_ids=[ACCT_A]
    )
    assert runner.scanned == []
    assert not [n for n in _zip_names(zip_path) if n.endswith("aws_sizing_discovery.json")]
    assert "cannot assume arn:aws:iam::111111111111:role/Broken" in caplog.text


def test_an_account_blocked_by_an_scp_is_not_kept(runner):
    zip_path = runner.main.run_org(
        zip_dir=str(runner.dir), role_name="R", account_ids=[ACCT_A, "333333333333"]
    )
    names = _zip_names(zip_path)
    assert f"{ACCT_A}/aws_sizing_discovery.json" in names
    assert "333333333333/aws_sizing_discovery.json" not in names


def test_a_rerun_resumes_and_skips_accounts_that_are_complete(runner):
    runner.main.run_org(
        zip_dir=str(runner.dir), role_name="R", account_ids=[ACCT_A, "333333333333"]
    )
    runner.scanned.clear()
    runner.main.run_org(
        zip_dir=str(runner.dir), role_name="R", account_ids=[ACCT_A, "333333333333"]
    )
    assert [a for a, _ in runner.scanned] == ["333333333333"]  # only the blocked one is retried


def test_profile_scan_opens_each_profile_and_learns_the_account_from_sts(runner):
    zip_path = runner.main.run_profiles(["prod", "staging"], zip_dir=str(runner.dir), max_workers=1)
    profiles = [
        s.kwargs.get("profile_name") for s in FakeSession.made if "profile_name" in s.kwargs
    ]
    assert profiles == ["prod", "staging"]
    assert len(_zip_names(zip_path)) > 0 and runner.scanned[0][0] == ACCT_A


def test_two_profiles_for_the_same_account_are_scanned_once(runner):
    runner.main.run_profiles(["one", "two"], zip_dir=str(runner.dir), max_workers=1)
    assert [a for a, _ in runner.scanned] == [ACCT_A]


def test_a_profile_that_cannot_sign_in_is_skipped(runner, monkeypatch):
    def broken(**kwargs):
        raise Exception("The config profile (bad) could not be found")

    monkeypatch.setattr(runner.main.boto3.session, "Session", broken)
    runner.main.run_profiles(["bad"], zip_dir=str(runner.dir))
    assert runner.scanned == []


def test_sso_scan_vends_credentials_per_account_in_the_chosen_region(runner, monkeypatch):
    main = runner.main
    clients = {}

    def client(service, region_name=None, **kw):
        clients[service] = region_name
        sso = MagicMock()
        sso.get_role_credentials.return_value = {
            "roleCredentials": {"accessKeyId": "k", "secretAccessKey": "s", "sessionToken": "t"}
        }
        return sso

    monkeypatch.setattr(main.boto3, "client", client)
    monkeypatch.setattr(main, "_load_sso_token", lambda url: ("tok", "us-west-2"))
    zip_path = main.run_org_sso(
        "https://x",
        "PermSet",
        account_ids=[ACCT_A],
        zip_dir=str(runner.dir),
        sso_region="eu-central-1",
    )
    assert clients["sso"] == "eu-central-1"
    assert f"{ACCT_A}/aws_sizing_discovery.json" in _zip_names(zip_path)


def test_sso_scan_stops_with_a_message_when_it_cannot_sign_in(runner, monkeypatch):
    main = runner.main

    def no_cache(url):
        raise RuntimeError("none")

    monkeypatch.setattr(main, "_load_sso_token", no_cache)
    with pytest.raises(SystemExit):
        main.run_org_sso("", "PermSet", account_ids=[ACCT_A], zip_dir=str(runner.dir))


# ── anonymized packaging ──────────────────────────────────────────────────────


def test_an_anonymized_org_zip_has_no_raw_json_and_the_key_file_stays_outside(runner):
    from anonymize import Anonymizer

    zip_path = runner.main.run_org(
        zip_dir=str(runner.dir),
        role_name="R",
        account_ids=[ACCT_A],
        anonymizer=Anonymizer(),
        stamp="2026-10-05_140650",
    )
    names = _zip_names(zip_path)
    # no raw discovery JSON (it holds every real name); the manifest names no resource, so it may stay
    assert [n for n in names if n.endswith(".json")] == ["manifest.json"]
    text = zipfile.ZipFile(zip_path).read("aws_ec2_instance_info-2026-10-05_140650.csv").decode()
    assert ACCT_A not in text and "AwsAccountId-00000" in text
    key_file = Path(zip_path).parent / "aws_anonymized_keys_to_actual_values-2026-10-05_140650.csv"
    assert key_file.exists() and ACCT_A in key_file.read_text()
    assert "aws_anonymized_keys_to_actual_values" not in " ".join(names)


# ── command line ──────────────────────────────────────────────────────────────


@pytest.fixture()
def cli(runner, monkeypatch):
    """main.main(argv) with every runner recorded instead of run."""
    main = runner.main
    calls = {}

    def recorder(name):
        def fn(*args, **kwargs):
            calls[name] = (args, kwargs)
            zip_path = runner.dir / "fake.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("x.csv", "x")
            return str(zip_path)

        return fn

    for name in ("run_org", "run_org_sso", "run_profiles"):
        monkeypatch.setattr(main, name, recorder(name))
    monkeypatch.setattr(main, "_resolve_scans", lambda args: {"cost": False, "capacity": True})
    return SimpleNamespace(main=main, calls=calls, dir=runner.dir)


def test_cross_account_role_is_org_mode_with_the_given_accounts(cli):
    cli.main.main(["--cross-account-role", "OrgRole", "--accounts", f"{ACCT_A},{ACCT_B}"])
    _, kwargs = cli.calls["run_org"]
    assert kwargs["role_name"] == "OrgRole" and kwargs["account_ids"] == [ACCT_A, ACCT_B]


def test_org_role_name_is_an_alias_of_role_name(cli):
    cli.main.main(["--org", "--org-role-name", "OrganizationAccountAccessRole"])
    assert cli.calls["run_org"][1]["role_name"] == "OrganizationAccountAccessRole"
    cli.main.main(["--org"])
    assert cli.calls["run_org"][1]["role_name"] == "RubrikDiscoveryRole"


def test_accounts_file_feeds_sso_with_the_sso_region(cli, tmp_path):
    path = tmp_path / "ids.txt"
    path.write_text(f"{ACCT_A}\n{ACCT_B}\n")
    cli.main.main(
        [
            "--sso",
            "--sso-start-url",
            "https://x",
            "--role-name",
            "ReadOnlyAccess",
            "--accounts-file",
            str(path),
            "--sso-region",
            "eu-west-1",
        ]
    )
    _, kwargs = cli.calls["run_org_sso"]
    assert kwargs["account_ids"] == [ACCT_A, ACCT_B] and kwargs["sso_region"] == "eu-west-1"
    assert kwargs["sso_start_url"] == "https://x"


def test_profiles_and_all_profiles_choose_the_profile_runner(cli, monkeypatch):
    monkeypatch.setattr(accounts, "local_profile_names", lambda: ["default", "prod"])
    cli.main.main(["--profiles", "prod"])
    assert cli.calls["run_profiles"][0][0] == ["prod"]
    cli.main.main(["--all-profiles"])
    assert cli.calls["run_profiles"][0][0] == ["default", "prod"]


@pytest.mark.parametrize(
    "argv, runner_name",
    [
        (["--sso", "--sso-start-url", "https://x", "--role-name", "P"], "run_org_sso"),
        (["--org"], "run_org"),
        (["--cross-account-role", "R", "--accounts", ACCT_A], "run_org"),
        (["--profiles", "prod"], "run_profiles"),
    ],
)
def test_every_multi_account_mode_writes_to_the_output_folder(
    cli, monkeypatch, tmp_path, argv, runner_name
):
    monkeypatch.setattr(accounts, "local_profile_names", lambda: ["prod"])
    out = tmp_path / "out"
    logs = []
    real_add_log_file = cli.main.add_log_file
    monkeypatch.setattr(
        cli.main, "add_log_file", lambda path: logs.append(path) or real_add_log_file(path)
    )
    cli.main.main([*argv, "--output", str(out)])
    assert cli.calls[runner_name][1]["zip_dir"] == str(out)
    assert out.is_dir() and os.path.dirname(logs[0]) == str(out)


def test_without_output_several_accounts_still_go_to_the_current_folder(cli):
    cli.main.main(["--org"])
    assert cli.calls["run_org"][1]["zip_dir"] == "."


def test_without_output_one_account_still_goes_to_outputs(cli, monkeypatch):
    seen = {}

    def fake_check(output_dir, *args):
        seen["dir"] = output_dir
        return None

    monkeypatch.setattr(cli.main, "_check_single_account", fake_check)
    cli.main.main(["--preflight-only"])
    assert seen["dir"] == "./outputs"


def test_sso_uses_the_permission_set_it_is_given_and_org_keeps_its_default_role(cli):
    cli.main.main(["--sso", "--role-name", "Sizing-Ps"])
    assert cli.calls["run_org_sso"][1]["role_name"] == "Sizing-Ps"
    cli.main.main(["--org"])
    assert (
        cli.calls["run_org"][1]["role_name"] == cli.main.DEFAULT_ORG_ROLE == "RubrikDiscoveryRole"
    )


def test_sso_without_a_permission_set_stops_before_the_log_opens(cli, tmp_path):
    with pytest.raises(SystemExit):
        cli.main.main(["--sso", "--output", str(tmp_path / "out")])
    assert "run_org_sso" not in cli.calls and not (tmp_path / "out").exists()


def test_govcloud_flags_set_the_partition_before_anything_runs(cli):
    cli.main.main(["--org", "--partition", "GovCloud"])
    assert (context.partition_id(), context.query_region()) == ("aws-us-gov", "us-gov-east-1")
    cli.main.main(["--org", "--region-to-query", "us-gov-west-1"])
    assert context.query_region() == "us-gov-west-1"


def test_anonymize_options_reach_the_runner(cli):
    cli.main.main(
        [
            "--org",
            "--anonymize",
            "--anonymize-fields",
            "Region",
            "--not-anonymize-fields",
            "Name,Tags",
        ]
    )
    anonymizer = cli.calls["run_org"][1]["anonymizer"]
    assert "region" in anonymizer.fields and "name" not in anonymizer.fields
    assert anonymizer.anonymize_tags is False
    cli.main.main(["--org"])
    assert cli.calls["run_org"][1]["anonymizer"] is None


def test_the_same_stamp_names_the_zip_the_log_and_the_files(cli):
    cli.main.main(["--org"])
    stamp = cli.calls["run_org"][1]["stamp"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{6}", stamp)
    names = zipfile.ZipFile(cli.dir / "fake.zip").namelist()
    assert f"output_aws_{stamp}.log" in names


def test_anonymized_runs_keep_the_real_log_outside_the_zip(cli):
    cli.main.main(["--org", "--anonymize"])
    stamp = cli.calls["run_org"][1]["stamp"]
    zf = zipfile.ZipFile(cli.dir / "fake.zip")
    assert (
        zf.read(f"output_aws_{stamp}.log")
        .decode()
        .startswith("Anonymized file; customer has original")
    )
    assert (cli.dir / f"output_aws_not_anonymized_{stamp}.log").exists()


@pytest.mark.parametrize(
    "argv, message",
    [
        (["--cross-account-role", "R"], "needs --accounts"),
        (["--org", "--anonymize-fields", "X"], "need --anonymize"),
        (["--org", "--anonymize", "--no-csv"], "--no-csv"),
        (["--org", "--accounts", "1", "--accounts-file", "f"], "not both"),
        (["--org", "--sso"], "not allowed with"),
        (["--org", "--all-profiles"], "not allowed with"),
        (["--profiles", "nope"], "Profile not found"),
        (["--sso"], "--sso needs --role-name"),
        (["--sso", "--sso-start-url", "https://x", "--accounts", "1"], "--sso needs --role-name"),
    ],
)
def test_bad_combinations_are_refused_with_a_message(cli, monkeypatch, capsys, argv, message):
    monkeypatch.setattr(accounts, "local_profile_names", lambda: ["default"])
    with pytest.raises(SystemExit) as exc:
        cli.main.main(argv)
    assert exc.value.code == 2 and message in capsys.readouterr().err


@pytest.mark.parametrize("option", ["--accounts-file", "--profile-location"])
def test_a_missing_accounts_file_or_profile_location_is_refused(cli, capsys, tmp_path, option):
    with pytest.raises(SystemExit) as exc:
        cli.main.main(["--org", option, str(tmp_path / "missing")])
    assert exc.value.code == 2
    assert "missing" in capsys.readouterr().err


def test_single_account_mode_writes_an_anonymized_zip_and_key_file(cli, monkeypatch, tmp_path):
    main = cli.main
    out = tmp_path / "out"
    out.mkdir()
    json_path = out / "aws_sizing_discovery.json"
    json_path.write_text(json.dumps(_result_for(ACCT_A)))
    monkeypatch.setattr(main, "run", lambda **kwargs: str(json_path))
    main.main(["--output", str(out), "--anonymize", "--not-anonymize-fields", "Tags"])
    zip_path = next(out.glob("aws_sizing_results_*.zip"))
    stamp = zip_path.stem[len("aws_sizing_results_") :]
    names = zipfile.ZipFile(zip_path).namelist()
    assert "aws_sizing_discovery.json" not in names
    assert f"aws_ec2_instance_info-{stamp}.csv" in names and f"output_aws_{stamp}.log" in names
    assert (out / f"aws_anonymized_keys_to_actual_values-{stamp}.csv").exists()
    assert (out / f"output_aws_not_anonymized_{stamp}.log").exists()
    assert not json_path.exists()  # the loose JSON holds the real names, so it is removed
    assert sorted(p.name for p in out.iterdir()) == sorted(
        [
            zip_path.name,
            f"aws_anonymized_keys_to_actual_values-{stamp}.csv",
            f"output_aws_not_anonymized_{stamp}.log",
        ]
    )
    assert (
        ACCT_A not in zipfile.ZipFile(zip_path).read(f"aws_ec2_instance_info-{stamp}.csv").decode()
    )


# ── -SkipBucketTags and -BackupRecoveryPointTimeoutMinutes ────────────────────


def test_collection_options_have_powershells_defaults_and_can_be_set():
    assert context.recovery_point_timeout_minutes() == 60 and context.skip_bucket_tags() is False
    context.configure(recovery_point_timeout_minutes=5, skip_bucket_tags=True)
    assert context.recovery_point_timeout_minutes() == 5 and context.skip_bucket_tags() is True
    context.configure()
    assert context.recovery_point_timeout_minutes() == 60 and context.skip_bucket_tags() is False


def test_recovery_points_use_the_configured_time_budget():
    from collectors.recovery_points import fetch_recovery_points

    session = MagicMock()
    session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {"BackupVaultList": [{"BackupVaultName": "v"}]}
    ]
    context.configure(recovery_point_timeout_minutes=-1)  # already over budget
    assert fetch_recovery_points(session, "us-west-2", ACCT_A, "").truncated is True
    context.configure()
    assert fetch_recovery_points(session, "us-west-2", ACCT_A, "").truncated is False


def test_skipping_bucket_tags_makes_no_tag_call_and_records_no_error():
    from collectors import DenialTracker
    from collectors.s3 import fetch_s3

    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "b1"}]}
    s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    cw = MagicMock()
    cw.get_metric_statistics.return_value = {"Datapoints": []}
    session = MagicMock()
    session.client.side_effect = lambda service, **kw: {"s3": s3, "cloudwatch": cw}[service]
    tracker = DenialTracker()
    context.configure(skip_bucket_tags=True)
    [bucket] = fetch_s3(session, "us-east-1", ACCT_A, "", set(), tracker)
    s3.get_bucket_tagging.assert_not_called()
    assert bucket.tags == {} and bucket.tags_lookup_failed is False


def test_command_line_passes_the_options_on_and_checks_the_time_budget(cli):
    cli.main.main(["--org", "--skip-bucket-tags", "--backup-recovery-point-timeout-minutes", "15"])
    assert context.skip_bucket_tags() is True and context.recovery_point_timeout_minutes() == 15
    cli.main.main(["--org"])
    assert context.skip_bucket_tags() is False and context.recovery_point_timeout_minutes() == 60
    with pytest.raises(SystemExit):
        cli.main.main(["--org", "--backup-recovery-point-timeout-minutes", "0"])

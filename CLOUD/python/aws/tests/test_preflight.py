"""The pre-flight access check: what it reports, that it follows the scan, and where it lands."""

from __future__ import annotations

import csv
import io
import json
import logging
import zipfile

import boto3
import csv_export
import main
import preflight
import preflight_core as core
import pytest
from anonymize import Anonymizer
from botocore.exceptions import ClientError
from botocore.validate import ParamValidator
from collectors import context
from tests.test_csv_export import ACCT, STAMP, _result

ACCOUNT = "111111111111"
OTHER_NUMBER = "999999999999"


def err(code, message="denied"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Operation")


class FakeClient:
    def __init__(self, session, name, region):
        self._session, self._name, self._region = session, name, region

    def __getattr__(self, method):
        def call(**kwargs):
            self._session.calls.append((self._name, method, self._region, kwargs))
            table = self._session.behaviors
            outcome = table.get((self._name, method, self._region), table.get((self._name, method)))
            if isinstance(outcome, BaseException):
                raise outcome
            return {} if outcome is None else outcome

        return call


class FakeSession:
    def __init__(self, **behaviors):
        self.behaviors = {tuple(key.split(".")): value for key, value in behaviors.items()}
        self.created = []
        self.calls = []

    def client(self, name, region_name=None, config=None):
        self.created.append((name, region_name))
        return FakeClient(self, name, region_name)


@pytest.fixture(autouse=True)
def _default_partition():
    context.configure()
    yield
    context.configure()


def _check(session, regions=("us-east-1", "eu-west-1"), services=("ec2",), cost=False):
    return preflight.run_access_check(
        session, ACCOUNT, "alias", list(regions), frozenset(services), cost
    )


def _rows(checks, **match):
    return [c for c in checks if all(getattr(c, key) == value for key, value in match.items())]


# ── what it reports ───────────────────────────────────────────────────────────


def test_a_readable_service_is_captured_and_says_whether_a_resource_was_seen():
    session = FakeSession(**{"sqs.list_queues": {"QueueUrls": ["u"]}})
    checks = _check(session, services=("ec2", "sqs"))
    (sqs,) = _rows(checks, service="sqs queues", scope="us-east-1")
    (ec2,) = _rows(checks, service="ec2 instances", scope="us-east-1")
    assert (sqs.status, sqs.found, sqs.outcome) == (core.OK, True, core.CAPTURED)
    assert (ec2.status, ec2.found) == (core.OK, False)


def test_a_denied_service_is_dropped_and_names_the_files_it_empties():
    session = FakeSession(**{"rds.describe_db_instances": err("AccessDeniedException")})
    checks = _check(session, services=("rds",))
    rds = _rows(checks, service="rds instances")
    assert {c.scope for c in rds} == {"us-east-1", "eu-west-1"}
    assert all(c.status == core.DENIED and c.outcome == core.DROPPED for c in rds)
    assert rds[0].to_row()["OutputFilesAffected"] == "aws_rds_info"
    assert [c.status for c in _rows(checks, service="backup protected resources")] == [core.OK] * 2


def test_a_region_blocked_by_a_service_control_policy_is_one_line_not_one_per_service():
    blocked = err("AccessDeniedException", "explicit deny in a service_control_policy")
    session = FakeSession(**{"ec2.describe_availability_zones.eu-west-1": blocked})
    checks = _check(session, services=("ec2", "rds"))
    (region,) = _rows(checks, scope="eu-west-1")
    assert (region.service, region.status, region.code) == (
        "all services in region",
        core.DENIED,
        "ServiceControlPolicy",
    )
    assert "aws_rds_info" in region.affects and "aws_ec2_instance_info" in region.affects
    assert not set(region.affects) & preflight.NON_FILE_EFFECTS
    assert {c.status for c in _rows(checks, scope="us-east-1")} == {core.OK}


def test_a_region_that_is_not_enabled_is_one_line_too():
    session = FakeSession(
        **{"ec2.describe_availability_zones.eu-west-1": err("UnrecognizedClientException")}
    )
    (region,) = _rows(_check(session), scope="eu-west-1")
    assert (region.status, region.code) == (core.NOT_ENABLED, "UnrecognizedClientException")


def test_a_region_whose_zone_listing_is_not_allowed_still_gets_its_services_checked():
    session = FakeSession(**{"ec2.describe_availability_zones": err("UnauthorizedOperation")})
    checks = _check(session)
    assert {c.status for c in checks if c.scope == "eu-west-1"} == {core.OK}
    assert _rows(checks, scope="eu-west-1", service="ec2 instances")


@pytest.mark.parametrize(
    "failure",
    [
        err("AccessDeniedException", "explicit deny in a service_control_policy"),
        err("UnrecognizedClientException"),
        err("AuthFailure"),
        RuntimeError("endpoint unreachable"),
    ],
)
def test_the_check_blocks_the_same_regions_the_scan_skips(failure):
    session = FakeSession(**{"ec2.describe_availability_zones": failure})
    scanned = main._scan_region(session, "eu-west-1", ACCOUNT, "", frozenset({"ec2"}))
    assert all(value == [] for value in scanned.values())
    checks = [c for c in _check(session, regions=("eu-west-1",)) if c.status != core.SKIPPED]
    assert [c.service for c in checks] == ["all services in region"]
    assert checks[0].outcome == core.DROPPED


def test_services_the_run_does_not_collect_are_listed_as_not_requested():
    checks = _check(FakeSession(), services=("ec2",))
    skipped = _rows(checks, status=core.SKIPPED, service="rds instances")
    assert len(skipped) == 1 and skipped[0].code == "not in --services"
    assert skipped[0].affects == ("aws_rds_info",)
    assert not _rows(checks, service="rds instances", status=core.OK)


def test_account_wide_services_are_checked_once_in_the_global_scope():
    session = FakeSession(**{"s3.list_buckets": {"Buckets": [{"Name": "x"}]}})
    checks = _check(session, services=("s3", "iam", "route53"))
    assert {c.scope for c in checks if c.service in ("s3 buckets", "iam account summary")} == {
        "global"
    }
    (s3,) = _rows(checks, service="s3 buckets")
    assert s3.found is True


# ── cost data ─────────────────────────────────────────────────────────────────


def test_cost_explorer_is_checked_once_per_account_when_cost_is_collected():
    session = FakeSession(**{"ce.get_cost_and_usage": err("AccessDeniedException")})
    checks = _check(session, cost=True)
    (cost,) = _rows(checks, service="cost explorer")
    assert (cost.status, cost.scope) == (core.DENIED, "global")
    assert cost.affects == ("aws_backup_costs", "aws_snapshot_storage_costs")
    assert [name for name, _ in session.created].count("ce") == 1


def test_cost_explorer_is_not_called_when_cost_is_off():
    session = FakeSession()
    checks = _check(session, cost=False)
    assert "ce" not in [name for name, _ in session.created]
    (cost,) = _rows(checks, service="cost explorer")
    assert (cost.status, cost.code) == (core.SKIPPED, "--no-cost")


def test_cost_explorer_is_not_called_in_govcloud():
    context.configure(govcloud=True)
    session = FakeSession()
    checks = _check(session, regions=("us-gov-west-1",), services=("ec2", "iam"), cost=True)
    assert "ce" not in [name for name, _ in session.created]
    (cost,) = _rows(checks, service="cost explorer")
    assert (cost.status, cost.code) == (core.SKIPPED, "not available in this partition")
    assert {r for _, r in session.created} == {"us-gov-east-1", "us-gov-west-1"}


# ── it can never stop a scan, and it keeps no message ─────────────────────────


def test_a_session_that_cannot_make_clients_does_not_raise():
    class Broken:
        def client(self, *args, **kwargs):
            raise RuntimeError("no clients today")

    assert isinstance(_check(Broken()), list)


def test_an_unexpected_failure_inside_the_check_gives_no_rows_instead_of_raising(monkeypatch):
    monkeypatch.setattr(preflight, "_run", lambda *a, **k: 1 / 0)
    assert _check(FakeSession()) == []


def test_the_provider_message_is_never_written_to_the_report():
    message = f"User arn:aws:iam::{OTHER_NUMBER}:user/someone is not authorized to perform it"
    session = FakeSession(**{"rds.describe_db_instances": err("AccessDenied", message)})
    checks = _check(session, services=("rds",))
    text = core.csv_text(c.to_row() for c in checks)
    assert OTHER_NUMBER not in text and "arn:aws" not in text and "someone" not in text


@pytest.mark.parametrize(
    "exc, expected",
    [
        (err("AccessDenied"), (core.DENIED, "AccessDenied")),
        (err("UnauthorizedOperation"), (core.DENIED, "UnauthorizedOperation")),
        (
            err("ValidationException", "caller is not authorized"),
            (core.DENIED, "ValidationException"),
        ),
        (
            err("AccessDeniedException", "explicit deny service_control_policy"),
            (core.DENIED, "ServiceControlPolicy"),
        ),
        (err("OptInRequired"), (core.NOT_ENABLED, "OptInRequired")),
        (err("SubscriptionRequiredException"), (core.NOT_ENABLED, "SubscriptionRequiredException")),
        (err("Throttling"), (core.ERROR, "Throttling")),
        (ValueError("x"), (core.ERROR, "ValueError")),
    ],
)
def test_classification(exc, expected):
    assert preflight.classify(exc) == expected


# ── the probe table itself ────────────────────────────────────────────────────

ALL_APIS = (*preflight.ACCOUNT_APIS, preflight.COST_API, *preflight.REGIONAL_APIS)

TABLE_BUCKET = "arn:aws:s3tables:us-east-1:111111111111:bucket/first-bucket"
OTHER_BUCKET = "arn:aws:s3tables:us-east-1:111111111111:bucket/second-bucket"
TABLE = {"namespace": ["sales", "emea"], "name": "orders", "type": "customer"}
METADATA = "s3://managed--table-s3/metadata/00001.metadata.json"

# What the probe before a chained probe leaves for it, by that probe's label.
SAMPLE_FINDINGS = {
    "glue databases": "analytics",
    "glue tables": ("analytics", "events"),
    "s3 table buckets": TABLE_BUCKET,
    "s3 tables": (TABLE_BUCKET, TABLE),
    "s3 table metadata location": METADATA,
}


def test_every_file_a_probe_names_is_a_real_output_file_or_a_known_effect():
    files = {spec.prefix for spec in csv_export.FILES}
    for api in ALL_APIS:
        for name in api.affects:
            assert name in files or name in preflight.NON_FILE_EFFECTS, (api.label, name)


def test_every_collected_output_file_is_covered_by_a_probe_or_is_derived():
    covered = {name for api in ALL_APIS for name in api.affects}
    derived = {"aws_ebs_and_ami_info"} - covered
    missing = {spec.prefix for spec in csv_export.FILES} - covered - derived
    assert missing == set(), "no probe tells whether these files can be filled"


def test_every_service_the_scan_can_collect_has_a_probe():
    gated = set().union(*(api.gate for api in ALL_APIS))
    assert main.ALL_SERVICES <= gated, sorted(main.ALL_SERVICES - gated)


def test_probe_labels_are_unique():
    labels = [api.label for api in ALL_APIS]
    assert len(labels) == len(set(labels))


def test_probe_arguments_and_response_keys_match_the_aws_api_models():
    session = boto3.session.Session(
        aws_access_key_id="a", aws_secret_access_key="b", region_name="us-east-1"
    )
    for api in ALL_APIS:
        try:
            client = session.client(api.client, region_name="us-east-1")
        except Exception:
            pytest.skip(f"this botocore has no {api.client} client")
        operation = client.meta.service_model.operation_model(
            client.meta.method_to_api_mapping[api.method]
        )
        if api.from_item is not None:
            kwargs = api.from_item(SAMPLE_FINDINGS[api.needs], "us-east-1", ACCOUNT)
        else:
            kwargs = api.kwargs() if callable(api.kwargs) else api.kwargs
        if operation.input_shape is not None:
            report = ParamValidator().validate(kwargs, operation.input_shape)
            assert not report.has_errors(), (api.label, report.generate_report())
        else:
            assert kwargs == {}, (api.label, "takes no arguments")
        if api.key:
            assert api.key in operation.output_shape.members, (api.label, api.key)


# ── where it lands ────────────────────────────────────────────────────────────


def _rows_for(account=ACCT, alias="the-alias"):
    session = FakeSession(**{"rds.describe_db_instances": err("AccessDenied")})
    checks = preflight.run_access_check(
        session, account, alias, ["us-east-1"], frozenset({"rds"}), False
    )
    return [c.to_row() for c in checks]


def _discovery(account=ACCT, alias="the-alias", rows=None):
    result = _result()
    result["access_check"] = _rows_for(account, alias) if rows is None else rows
    return result


def test_run_writes_the_rows_into_the_account_json_and_skips_them_when_turned_off(
    tmp_path, monkeypatch
):
    empty = {
        key: []
        for key in "instances attached unattached rds dynamodb efs fsx s3 kms secrets sqs plans vaults cfn native_backups rds_snapshots ebs_ami vpcs load_balancers eks_clusters eks_nodegroups kms_keys redshift fsx_volumes s3_tables glue_iceberg recovery_points recovery_aggregates truncated_backup_regions".split()
    }
    monkeypatch.setattr(main, "_scan_all_regions", lambda *a, **k: dict(empty))
    session = FakeSession(
        **{
            "sts.get_caller_identity": {"Account": ACCOUNT},
            "iam.list_account_aliases": {"AccountAliases": []},
            "rds.describe_db_instances": err("AccessDenied"),
        }
    )
    for access_check, folder in ((True, "on"), (False, "off")):
        out = tmp_path / folder
        out.mkdir()
        path = main.run(
            output_dir=str(out),
            session=session,
            regions=["us-east-1"],
            services=frozenset({"rds"}),
            collect_cost=False,
            access_check=access_check,
        )
        rows = json.loads(open(path, encoding="utf-8").read())["access_check"]
        assert bool(rows) is access_check
        if access_check:
            assert any(r["Service"] == "rds instances" and r["Outcome"] == "dropped" for r in rows)


def test_the_flag_defaults_to_running_the_check():
    parser = main._build_parser()
    assert parser.parse_args([]).no_preflight is False
    assert parser.parse_args(["--no-preflight"]).no_preflight is True


def _names(zip_path):
    return zipfile.ZipFile(zip_path).namelist()


def test_a_single_account_zip_holds_the_report_beside_the_other_csv_files(tmp_path):
    path = tmp_path / "aws_sizing_discovery.json"
    path.write_text(json.dumps(_discovery()), encoding="utf-8")
    zip_path = main._finish_single_account(str(path), str(tmp_path), STAMP, True, None)
    name = f"aws_preflight_check-{STAMP}.csv"
    assert name in _names(zip_path)
    rows = list(csv.DictReader(io.StringIO(zipfile.ZipFile(zip_path).read(name).decode("utf-8"))))
    assert rows and rows[0]["Owner"] == ACCT


def test_no_csv_leaves_the_report_out_with_the_other_csv_files(tmp_path):
    path = tmp_path / "aws_sizing_discovery.json"
    path.write_text(json.dumps(_discovery()), encoding="utf-8")
    zip_path = main._finish_single_account(str(path), str(tmp_path), STAMP, False, None)
    assert not [n for n in _names(zip_path) if "preflight" in n]


def test_a_run_without_the_check_adds_no_report_file(tmp_path):
    path = tmp_path / "aws_sizing_discovery.json"
    path.write_text(json.dumps(_discovery(rows=[])), encoding="utf-8")
    zip_path = main._finish_single_account(str(path), str(tmp_path), STAMP, True, None)
    assert not [n for n in _names(zip_path) if "preflight" in n]


def test_an_older_account_file_with_no_report_still_packages(tmp_path):
    path = tmp_path / "aws_sizing_discovery.json"
    path.write_text(json.dumps(_result()), encoding="utf-8")
    zip_path = main._finish_single_account(str(path), str(tmp_path), STAMP, True, None)
    assert not [n for n in _names(zip_path) if "preflight" in n]


def test_anonymizing_replaces_the_account_in_the_report_and_the_key_file_maps_it_back(tmp_path):
    path = tmp_path / "aws_sizing_discovery.json"
    path.write_text(json.dumps(_discovery(alias="secret-alias")), encoding="utf-8")
    zip_path = main._finish_single_account(
        str(path), str(tmp_path), STAMP, True, Anonymizer.from_options()
    )
    text = zipfile.ZipFile(zip_path).read(f"aws_preflight_check-{STAMP}.csv").decode("utf-8")
    assert ACCT not in text and "secret-alias" not in text
    key = next(p for p in tmp_path.iterdir() if p.name.startswith("aws_anonymized_key")).read_text()
    assert ACCT in key


def test_a_field_left_out_of_anonymizing_stays_readable_in_the_report(tmp_path):
    path = tmp_path / "aws_sizing_discovery.json"
    path.write_text(json.dumps(_discovery()), encoding="utf-8")
    keep = Anonymizer.from_options("", "AwsAccountId")
    zip_path = main._finish_single_account(str(path), str(tmp_path), STAMP, True, keep)
    text = zipfile.ZipFile(zip_path).read(f"aws_preflight_check-{STAMP}.csv").decode("utf-8")
    assert ACCT in text


def test_the_report_cannot_change_how_the_other_files_are_numbered():
    discoveries = [_discovery()]
    plain = csv_export.build_csv_files([_result()], STAMP, Anonymizer.from_options())
    shared = Anonymizer.from_options()
    files = csv_export.build_csv_files([_result()], STAMP, shared)
    main._access_check_csv(discoveries, STAMP, shared)
    assert files == plain


def test_a_multi_account_zip_has_one_report_with_every_account(tmp_path):
    progress = tmp_path / "progress"
    for account in ("111111111111", "222222222222"):
        folder = progress / account
        folder.mkdir(parents=True)
        (folder / "aws_sizing_discovery.json").write_text(
            json.dumps(_discovery(account=account)), encoding="utf-8"
        )
    zip_path = str(tmp_path / "out.zip")
    main._package_results(str(progress), zip_path, 2, 0, stamp=STAMP)
    reports = [n for n in _names(zip_path) if "preflight" in n]
    assert reports == [f"aws_preflight_check-{STAMP}.csv"]
    text = zipfile.ZipFile(zip_path).read(reports[0]).decode("utf-8")
    assert "111111111111" in text and "222222222222" in text


def test_the_new_modules_are_packaged():
    text = open("pyproject.toml", encoding="utf-8").read()
    assert '"preflight"' in text and '"preflight_core"' in text


# ── the opt-out reaches every mode ────────────────────────────────────────────


@pytest.mark.parametrize("given, expected", [({}, True), ({"access_check": False}, False)])
def test_every_multi_account_mode_hands_the_option_on(monkeypatch, given, expected):
    seen = []
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setattr(main, "_scan_accounts", lambda *a, **k: seen.append(k["access_check"]))
    monkeypatch.setattr(main, "_sso_token", lambda *a, **k: ("token", "us-east-1"))
    main.run_profiles(["p1"], **given)
    main.run_org(account_ids=[ACCOUNT], **given)
    main.run_org_sso("https://x.awsapps.com/start", "Role", account_ids=[ACCOUNT], **given)
    assert seen == [expected] * 3


@pytest.mark.parametrize("given, expected", [({}, True), ({"access_check": False}, False)])
def test_each_account_in_a_multi_account_run_gets_the_option(
    tmp_path, monkeypatch, given, expected
):
    seen = []

    def fake_run(output_dir, **kwargs):
        seen.append(kwargs["access_check"])
        path = tmp_path / "aws_sizing_discovery.json"
        path.write_text("{}", encoding="utf-8")
        return str(path)

    monkeypatch.setattr(main, "run", fake_run)
    monkeypatch.setattr(main, "_package_results", lambda *a, **k: "zip")
    main._scan_accounts(
        [{"id": ACCOUNT, "name": "n"}],
        lambda target: FakeSession(),
        label="Test",
        zip_dir=str(tmp_path),
        **given,
    )
    assert seen == [expected]


# ── permissions and the table ─────────────────────────────────────────────────

NAME_DIFFERS_FROM_THE_API = {
    "list_buckets": "s3:ListAllMyBuckets",
    "get_metric_statistics": "cloudwatch:GetMetricStatistics",
    "head_object": "s3:GetObject",  # AWS's service reference: HeadObject is authorized by GetObject
}


def test_every_probe_permission_is_the_iam_action_of_the_call_it_makes():
    session = boto3.session.Session(
        aws_access_key_id="a", aws_secret_access_key="b", region_name="us-east-1"
    )
    for api in ALL_APIS:
        try:
            client = session.client(api.client, region_name="us-east-1")
        except Exception:
            pytest.skip(f"this botocore has no {api.client} client")
        operation = client.meta.method_to_api_mapping[api.method]
        derived = f"{client.meta.service_model.signing_name}:{operation}"
        expected = NAME_DIFFERS_FROM_THE_API.get(api.method, derived)
        assert api.permission == expected, (api.label, api.permission, expected)


def test_the_permission_table_has_exactly_the_probes_there_are():
    assert set(preflight.PERMISSIONS) == {api.label for api in ALL_APIS}


def test_the_rows_carry_the_permission_for_every_check_including_not_requested():
    checks = _check(FakeSession(), services=("ec2",), cost=False)
    probed = _rows(checks, status=core.OK)
    skipped = _rows(checks, status=core.SKIPPED)
    assert probed and skipped
    assert all(c.permission for c in probed + skipped)
    assert (
        _rows(checks, service="ec2 instances")[0].to_row()["Permission"] == "ec2:DescribeInstances"
    )


def test_a_region_that_is_blocked_has_no_single_permission_to_name():
    session = FakeSession(
        **{"ec2.describe_availability_zones.eu-west-1": err("UnrecognizedClientException")}
    )
    (region,) = _rows(_check(session), scope="eu-west-1")
    assert region.permission == ""


def _logged(caplog, checks, table):
    caplog.clear()
    with caplog.at_level("INFO", logger="preflight"):
        preflight.report(checks, ACCOUNT, "alias", table)
    return [r for r in caplog.records if r.name == "preflight"]


def test_the_report_logs_the_headline_and_the_permissions_table(caplog):
    session = FakeSession(**{"rds.describe_db_instances": err("AccessDeniedException")})
    checks = _check(session, services=("rds", "sqs"))
    records = _logged(caplog, checks, table=True)
    message = records[0].getMessage()
    assert message.startswith(f"Pre-flight access check for {ACCOUNT} (alias):")
    assert "rds:DescribeDBInstances" in message and "MISSING" in message and "granted" in message
    assert "aws_rds_info" in message and "us-east-1, eu-west-1" in message


def test_something_blocked_always_gets_the_table_and_a_warning(caplog):
    session = FakeSession(**{"rds.describe_db_instances": err("AccessDeniedException")})
    records = _logged(caplog, _check(session, services=("rds",)), table=False)
    assert "rds:DescribeDBInstances" in records[0].getMessage()
    warnings = [r for r in records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "rds instances" in warnings[0].getMessage()


def test_a_clean_account_in_a_large_run_logs_only_the_headline(caplog):
    records = _logged(caplog, _check(FakeSession(), services=("sqs",)), table=False)
    assert len(records) == 1 and "nothing blocked" in records[0].getMessage()
    assert "\n" not in records[0].getMessage()


def test_the_report_says_nothing_when_no_checks_were_made(caplog):
    assert _logged(caplog, [], table=True) == []


@pytest.mark.parametrize("accounts, expected", [(1, True), (3, True), (4, False)])
def test_a_large_run_prints_the_full_table_only_for_accounts_with_something_blocked(
    tmp_path, monkeypatch, accounts, expected
):
    seen = []

    def fake_run(output_dir, **kwargs):
        seen.append(kwargs["access_table"])
        path = tmp_path / "aws_sizing_discovery.json"
        path.write_text("{}", encoding="utf-8")
        return str(path)

    monkeypatch.setattr(main, "run", fake_run)
    monkeypatch.setattr(main, "_package_results", lambda *a, **k: "zip")
    targets = [{"id": f"{i:012d}", "name": "n"} for i in range(1, accounts + 1)]
    main._scan_accounts(
        targets, lambda target: FakeSession(), label="Test", zip_dir=str(tmp_path), max_workers=1
    )
    assert seen == [expected] * accounts


def test_run_hands_the_table_choice_to_the_report(tmp_path, monkeypatch):
    empty = {
        key: []
        for key in "instances attached unattached rds dynamodb efs fsx s3 kms secrets sqs plans vaults cfn native_backups rds_snapshots ebs_ami vpcs load_balancers eks_clusters eks_nodegroups kms_keys redshift fsx_volumes s3_tables glue_iceberg recovery_points recovery_aggregates truncated_backup_regions".split()
    }
    monkeypatch.setattr(main, "_scan_all_regions", lambda *a, **k: dict(empty))
    seen = []
    monkeypatch.setattr(
        preflight, "report", lambda checks, acct, alias, table=True: seen.append(table)
    )
    session = FakeSession(
        **{
            "sts.get_caller_identity": {"Account": ACCOUNT},
            "iam.list_account_aliases": {"AccountAliases": []},
        }
    )
    for flag in (True, False):
        main.run(
            output_dir=str(tmp_path),
            session=session,
            regions=["us-east-1"],
            services=frozenset({"sqs"}),
            collect_cost=False,
            access_table=flag,
        )
    assert seen == [True, False]


def test_every_permission_name_and_a_17_region_count_fit_the_table_without_being_clipped():
    regions = [f"region-{i}" for i in range(17)]
    checks = [
        core.Check(
            ACCOUNT,
            "",
            region,
            api.label,
            core.OK,
            region != "region-0",
            "",
            api.affects,
            "",
            api.permission,
        )
        for api in preflight.REGIONAL_APIS
        for region in regions
    ]
    text = "\n".join(core.table_lines(checks, "region"))
    assert all(api.permission in text for api in preflight.REGIONAL_APIS)
    assert "yes (16 of 17)" in text and "..." not in text


# ── the per-table calls of S3 Tables and Glue, tried on the first table found ─────────────────


def _s3_tables_session(**extra):
    behaviors = {
        "s3tables.list_table_buckets": {
            "tableBuckets": [{"arn": TABLE_BUCKET}, {"arn": OTHER_BUCKET}]
        },
        "s3tables.list_tables": {"tables": [TABLE]},
        "s3tables.get_table_metadata_location": {"metadataLocation": METADATA},
        **extra,
    }
    return FakeSession(**behaviors)


def _table_services(checks):
    return sorted(c.service for c in checks if c.service.startswith("s3 table"))


def _calls(session, name, method):
    return [kwargs for n, m, _, kwargs in session.calls if (n, m) == (name, method)]


def test_a_table_is_tried_with_every_call_the_collector_makes_on_it():
    session = _s3_tables_session()
    checks = _check(session, regions=("us-east-1",), services=("s3tables",))
    assert _table_services(checks) == [
        "s3 table buckets",
        "s3 table details",
        "s3 table maintenance settings",
        "s3 table metadata file",
        "s3 table metadata location",
        "s3 tables",
    ]
    assert all(c.status == core.OK for c in checks if c.service.startswith("s3 table"))


def test_the_calls_use_the_first_bucket_and_the_first_table_the_listing_found():
    session = _s3_tables_session()
    _check(session, regions=("us-east-1",), services=("s3tables",))
    assert _calls(session, "s3tables", "list_tables") == [
        {"tableBucketARN": TABLE_BUCKET, "maxTables": 1}
    ]
    ids = {"tableBucketARN": TABLE_BUCKET, "namespace": "sales/emea", "name": "orders"}
    for method in (
        "get_table",
        "get_table_metadata_location",
        "get_table_maintenance_configuration",
    ):
        assert _calls(session, "s3tables", method) == [ids]


def test_the_metadata_file_is_read_the_way_the_collector_reads_it():
    session = _s3_tables_session()
    _check(session, regions=("us-east-1",), services=("s3tables",))
    assert _calls(session, "s3", "head_object") == [
        {
            "Bucket": "managed--table-s3",
            "Key": "metadata/00001.metadata.json",
            "RequestPayer": "requester",
        }
    ]


def test_each_row_carries_the_iam_action_of_its_call_and_the_file_it_fills():
    checks = _check(_s3_tables_session(), regions=("us-east-1",), services=("s3tables",))
    wanted = {
        "s3 tables": "s3tables:ListTables",
        "s3 table details": "s3tables:GetTable",
        "s3 table metadata location": "s3tables:GetTableMetadataLocation",
        "s3 table maintenance settings": "s3tables:GetTableMaintenanceConfiguration",
        "s3 table metadata file": "s3:GetObject",
    }
    for service, permission in wanted.items():
        (row,) = _rows(checks, service=service)
        assert (row.permission, row.affects) == (permission, ("aws_s3_tables_info",))


def test_a_denied_per_table_call_is_reported_although_the_listing_is_readable():
    session = _s3_tables_session(
        **{"s3tables.get_table_maintenance_configuration": err("AccessDeniedException")}
    )
    checks = _check(session, regions=("us-east-1",), services=("s3tables",))
    (bucket_list,) = _rows(checks, service="s3 table buckets")
    (maintenance,) = _rows(checks, service="s3 table maintenance settings")
    assert bucket_list.status == core.OK
    assert (maintenance.status, maintenance.outcome) == (core.DENIED, core.DROPPED)
    assert maintenance.permission == "s3tables:GetTableMaintenanceConfiguration"
    assert maintenance.affects == ("aws_s3_tables_info",)


def test_a_denied_metadata_file_is_reported_with_the_object_permission():
    session = _s3_tables_session(**{"s3.head_object": err("AccessDenied")})
    checks = _check(session, regions=("us-east-1",), services=("s3tables",))
    (row,) = _rows(checks, service="s3 table metadata file")
    assert (row.status, row.permission) == (core.DENIED, "s3:GetObject")


def test_a_region_with_no_table_bucket_gets_no_per_table_rows():
    checks = _check(FakeSession(), regions=("us-east-1",), services=("s3tables",))
    assert _table_services(checks) == ["s3 table buckets"]
    (row,) = _rows(checks, service="s3 table buckets")
    assert (row.status, row.found) == (core.OK, False)


def test_a_bucket_with_no_table_stops_at_the_table_listing():
    session = FakeSession(
        **{"s3tables.list_table_buckets": {"tableBuckets": [{"arn": TABLE_BUCKET}]}}
    )
    checks = _check(session, regions=("us-east-1",), services=("s3tables",))
    assert _table_services(checks) == ["s3 table buckets", "s3 tables"]
    (row,) = _rows(checks, service="s3 tables")
    assert (row.status, row.found) == (core.OK, False)


def test_a_table_with_no_metadata_location_gets_no_metadata_file_row():
    session = _s3_tables_session(**{"s3tables.get_table_metadata_location": {}})
    checks = _check(session, regions=("us-east-1",), services=("s3tables",))
    assert "s3 table metadata file" not in _table_services(checks)
    assert _calls(session, "s3", "head_object") == []
    assert "s3 table metadata location" in _table_services(checks)


def test_a_failed_listing_leaves_nothing_to_try_so_no_per_table_rows():
    session = FakeSession(**{"s3tables.list_table_buckets": err("AccessDeniedException")})
    checks = _check(session, regions=("us-east-1",), services=("s3tables",))
    assert _table_services(checks) == ["s3 table buckets"]
    assert _rows(checks, service="s3 table buckets")[0].status == core.DENIED


def test_only_the_regions_that_have_a_table_get_per_table_rows():
    session = _s3_tables_session(**{"s3tables.list_table_buckets.eu-west-1": {"tableBuckets": []}})
    checks = _check(session, regions=("us-east-1", "eu-west-1"), services=("s3tables",))
    where = {c.scope for c in checks if c.service == "s3 table details"}
    assert where == {"us-east-1"}
    assert {c.scope for c in checks if c.service == "s3 table buckets"} == {
        "us-east-1",
        "eu-west-1",
    }


def test_the_per_table_rows_are_listed_as_not_requested_when_the_service_is_not_collected():
    checks = _check(FakeSession(), regions=("us-east-1",), services=("ec2",))
    for service in ("s3 tables", "s3 table details", "s3 table metadata file", "glue tables"):
        (row,) = _rows(checks, service=service)
        assert (row.status, row.code) == (core.SKIPPED, "not in --services")


def test_glue_tries_the_first_database_then_its_first_table_then_that_tables_tags():
    session = FakeSession(
        **{
            "glue.get_databases": {"DatabaseList": [{"Name": "analytics"}, {"Name": "other"}]},
            "glue.get_tables": {"TableList": [{"Name": "events"}]},
        }
    )
    checks = _check(session, regions=("us-east-1",), services=("glue",))
    assert _calls(session, "glue", "get_tables") == [{"DatabaseName": "analytics", "MaxResults": 1}]
    assert _calls(session, "glue", "get_tags") == [
        {"ResourceArn": f"arn:aws:glue:us-east-1:{ACCOUNT}:table/analytics/events"}
    ]
    for service, permission in (
        ("glue tables", "glue:GetTables"),
        ("glue table tags", "glue:GetTags"),
    ):
        (row,) = _rows(checks, service=service)
        assert (row.status, row.permission, row.affects) == (
            core.OK,
            permission,
            ("aws_glue_iceberg_info",),
        )


def test_the_glue_table_arn_uses_the_partition_of_the_region():
    context.configure(govcloud=True)
    session = FakeSession(
        **{
            "glue.get_databases": {"DatabaseList": [{"Name": "analytics"}]},
            "glue.get_tables": {"TableList": [{"Name": "events"}]},
        }
    )
    _check(session, regions=("us-gov-west-1",), services=("glue",))
    assert _calls(session, "glue", "get_tags")[0]["ResourceArn"].startswith(
        f"arn:aws-us-gov:glue:us-gov-west-1:{ACCOUNT}:table/"
    )


def test_a_glue_database_with_no_table_stops_at_the_table_listing():
    session = FakeSession(**{"glue.get_databases": {"DatabaseList": [{"Name": "analytics"}]}})
    checks = _check(session, regions=("us-east-1",), services=("glue",))
    assert [c.service for c in checks if c.service.startswith("glue")] == [
        "glue databases",
        "glue tables",
    ]


def test_a_denied_glue_tag_call_is_reported_although_the_listings_are_readable():
    session = FakeSession(
        **{
            "glue.get_databases": {"DatabaseList": [{"Name": "analytics"}]},
            "glue.get_tables": {"TableList": [{"Name": "events"}]},
            "glue.get_tags": err("AccessDeniedException"),
        }
    )
    checks = _check(session, regions=("us-east-1",), services=("glue",))
    (row,) = _rows(checks, service="glue table tags")
    assert (row.status, row.permission) == (core.DENIED, "glue:GetTags")


def test_an_account_with_no_tables_or_databases_has_the_rows_it_had_before():
    plain = _check(FakeSession(), regions=("us-east-1",), services=("s3tables", "glue"))
    labels = {c.service for c in plain}
    assert {"s3 table buckets", "glue databases"} <= labels
    assert not labels & {
        "s3 table details",
        "s3 table maintenance settings",
        "s3 table metadata location",
        "s3 table metadata file",
        "glue table tags",
    }

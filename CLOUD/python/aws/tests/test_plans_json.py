"""aws-backup-plans-info-<stamp>.json: built into the results zip with the CSVs."""

import json
import sys
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import main
import plans_json
import pytest
from anonymize import Anonymizer
from collectors.backup import _plan_export
from models.discovery import BackupPlan
from tests.test_csv_export import ACCT, _result

EXAMPLE = Path(__file__).resolve().parents[3] / "EXAMPLES" / "aws-backup-plans-info-example.json"
STAMP = "2026-10-05_140650"
SDK_KEYS = {"ResponseMetadata", "ContentLength", "HttpStatusCode"}


def plan(name, *resources, readable=True, account=ACCT, region="us-west-2"):
    """A plan dict as the discovery JSON has it; ``readable=False`` is a placeholder plan."""
    item = {
        "BackupPlanId": f"id-{name}",
        "BackupPlanArn": f"arn:aws:backup:{region}:{account}:backup-plan:id-{name}",
        "BackupPlanName": name,
        "VersionId": "v1",
        "CreationDate": datetime(2022, 6, 6, 23, 33, 40, 22000, tzinfo=timezone.utc),
    }
    detail = {
        "BackupPlan": {
            "BackupPlanName": name,
            "Rules": [
                {
                    "RuleName": "daily",
                    "TargetBackupVaultName": "Default",
                    "ScheduleExpression": "cron(0 5 ? * * *)",
                    "Lifecycle": {"DeleteAfterDays": 35},
                }
            ],
        }
    }
    return asdict(
        BackupPlan(
            account,
            "",
            region,
            f"id-{name}",
            item["BackupPlanArn"],
            name,
            "v1",
            "",
            "",
            [],
            list(resources),
            plan_export=_plan_export(item, detail) if readable else {},
            selections_complete=readable,
        )
    )


def titles(text):
    return [element["BackupPlan"]["BackupPlanName"] for element in json.loads(text)]


# ── the file ──────────────────────────────────────────────────────────────────────────────────


def test_file_name_follows_the_powershell_pattern():
    assert plans_json.file_name(STAMP) == f"aws-backup-plans-info-{STAMP}.json"


def test_one_element_per_readable_plan_with_only_explicit_arns_as_resources():
    plans = [
        plan("Daily", "arn:aws:ec2:*:*:instance/*", "arn:aws:rds:us-west-2:1:db:a"),
        plan("TagOnly"),  # selects by tag: no explicit ARNs
        plan("Lost", readable=False),  # get_backup_plan failed: left out
    ]
    elements = json.loads(plans_json.build(plans))
    assert [e["BackupPlan"]["BackupPlanName"] for e in elements] == ["Daily", "TagOnly"]
    assert elements[0]["Resources"] == [
        "arn:aws:ec2:*:*:instance/*",
        "arn:aws:rds:us-west-2:1:db:a",
    ]
    assert elements[1]["Resources"] == []
    assert not SDK_KEYS & set(elements[0])


def test_no_plans_is_an_empty_list_like_powershell():
    assert plans_json.build([]) == "[]\n"
    assert plans_json.build([plan("Lost", readable=False)]) == "[]\n"


def test_keys_and_their_order_match_powershell_with_awstools_5():
    """A real PowerShell run (AWS.Tools 5.0.313, ids sanitized): the same keys in the same order,
    with ``Resources`` after them because the SDK transport fields are left out."""
    path = Path(__file__).parent / "data" / "ps_backup_plan_awstools_5_0_313.json"
    real = json.loads(path.read_text(encoding="utf-8"))
    (ours,) = json.loads(plans_json.build([plan("Daily", "arn:a")]))
    assert list(ours) == [*real, "Resources"]
    assert list(ours["BackupPlan"]) == list(real["BackupPlan"])
    assert list(ours["BackupPlan"]["Rules"][0]) == list(real["BackupPlan"]["Rules"][0])
    assert list(ours["BackupPlan"]["Rules"][0]["Lifecycle"]) == list(
        real["BackupPlan"]["Rules"][0]["Lifecycle"]
    )
    assert ours["DeletionDate"] is None and ours["LastExecutionDate"] is None
    assert ours["CreationDate"] == "2022-06-06T23:33:40.022Z"


def test_every_key_of_the_older_powershell_example_is_still_there():
    """The repo's example file comes from AWS.Tools 4.x, which wrote defaults instead of nulls
    and fewer keys: everything it has (but the SDK fields) is in ours too."""
    example = json.loads(EXAMPLE.read_text(encoding="utf-8"))[3]
    (ours,) = json.loads(plans_json.build([plan("Daily", "arn:a")]))
    assert set(example) - SDK_KEYS <= set(ours)
    assert set(example["BackupPlan"]) <= set(ours["BackupPlan"])
    assert set(example["BackupPlan"]["Rules"][0]) <= set(ours["BackupPlan"]["Rules"][0])


def test_plans_come_in_region_scan_order_not_completion_order():
    regions = ["ca-central-1", "us-east-1", "us-east-2", "us-west-2"]
    discovery = {
        "regions_scanned": regions,
        "backup_plans": [  # the order the regions finished in
            plan("W", region="us-west-2"),
            plan("E2b", region="us-east-2"),
            plan("E2a", region="us-east-2"),
            plan("C", region="ca-central-1"),
            plan("Unknown", region="mars-1"),
            plan("E1", region="us-east-1"),
        ],
    }
    ordered = [p["plan_name"] for p in plans_json.plans_of(discovery)]
    # scan order; the API's order kept within a region; a region not scanned goes last
    assert ordered == ["C", "E1", "E2b", "E2a", "W", "Unknown"]
    assert plans_json.plans_of({}) == []


# ── packaging: organization, SSO and profile runs ─────────────────────────────────────────────


def _progress(tmp_path, accounts):
    """A progress folder holding one discovery file per account, as a resumed run has."""
    progress = tmp_path / "progress"
    progress.mkdir()
    for account, plans in accounts.items():
        folder = progress / account
        folder.mkdir()
        (folder / "aws_sizing_discovery.json").write_text(
            json.dumps(_result(account=account, backup_plans=plans))
        )
    return str(progress)


def _package(tmp_path, accounts, **kwargs):
    zip_path = str(tmp_path / "out.zip")
    main._package_results(
        _progress(tmp_path, accounts), zip_path, len(accounts), 0, stamp=STAMP, **kwargs
    )
    return zipfile.ZipFile(zip_path)


ACCOUNTS = {
    "111111111111": [plan("First", "arn:a", account="111111111111")],
    "222222222222": [plan("Second", account="222222222222"), plan("Third", account="222222222222")],
}


def test_org_zip_holds_the_plans_of_every_account_in_account_order(tmp_path):
    archive = _package(tmp_path, ACCOUNTS)
    text = archive.read(plans_json.file_name(STAMP)).decode()
    assert titles(text) == ["First", "Second", "Third"]


def test_plans_come_from_the_progress_folder_so_resumed_accounts_are_included(tmp_path):
    # the account files are the only source here: nothing was scanned in this process
    archive = _package(tmp_path, {"333333333333": [plan("Resumed", account="333333333333")]})
    assert titles(archive.read(plans_json.file_name(STAMP)).decode()) == ["Resumed"]


def test_org_zip_without_csv_still_has_the_plans_file(tmp_path):
    archive = _package(tmp_path, ACCOUNTS, write_csv=False)
    assert not [n for n in archive.namelist() if n.endswith(".csv")]
    assert titles(archive.read(plans_json.file_name(STAMP)).decode()) == [
        "First",
        "Second",
        "Third",
    ]


def test_org_zip_lists_each_accounts_plans_in_region_scan_order(tmp_path):
    progress = tmp_path / "progress"
    progress.mkdir()
    for account in ("111111111111", "222222222222"):
        folder = progress / account
        folder.mkdir()
        discovery = _result(
            account=account,
            regions_scanned=["ca-central-1", "us-east-1", "us-west-2"],
            backup_plans=[  # region completion order, as the collector leaves them
                plan(f"{account[0]}-west", account=account, region="us-west-2"),
                plan(f"{account[0]}-central", account=account, region="ca-central-1"),
                plan(f"{account[0]}-east", account=account, region="us-east-1"),
            ],
        )
        (folder / "aws_sizing_discovery.json").write_text(json.dumps(discovery))
    zip_path = str(tmp_path / "out.zip")
    main._package_results(str(progress), zip_path, 2, 0, stamp=STAMP)
    text = zipfile.ZipFile(zip_path).read(plans_json.file_name(STAMP)).decode()
    assert titles(text) == [
        "1-central",
        "1-east",
        "1-west",
        "2-central",
        "2-east",
        "2-west",
    ]


def test_anonymized_org_zip_has_no_plans_file(tmp_path):
    archive = _package(tmp_path, ACCOUNTS, anonymizer=Anonymizer())
    assert plans_json.file_name(STAMP) not in archive.namelist()


def test_org_zip_without_plans_has_an_empty_list(tmp_path):
    archive = _package(tmp_path, {"111111111111": []})
    assert archive.read(plans_json.file_name(STAMP)).decode() == "[]\n"


def test_a_plans_file_failure_does_not_cost_the_csvs_or_the_zip(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(plans_json, "build", lambda plans: 1 / 0)
    archive = _package(tmp_path, ACCOUNTS)
    names = archive.namelist()
    assert plans_json.file_name(STAMP) not in names
    assert [n for n in names if n.endswith(".csv")] and any(
        n.endswith("discovery.json") for n in names
    )
    assert any(plans_json.file_name(STAMP) in r.getMessage() for r in caplog.records)


# ── packaging: a single account ───────────────────────────────────────────────────────────────


def _single(tmp_path, monkeypatch, extra):
    out = tmp_path / "out"
    out.mkdir()
    json_path = out / "aws_sizing_discovery.json"
    json_path.write_text(json.dumps(_result(backup_plans=[plan("Daily", "arn:a"), plan("Weekly")])))
    monkeypatch.setattr(main, "run", lambda **kwargs: str(json_path))
    monkeypatch.setattr(sys, "argv", ["main.py", "--output", str(out), "--no-cost", *extra])
    main.main()
    zip_path = next(out.glob("aws_sizing_results_*.zip"))
    stamp = zip_path.stem[len("aws_sizing_results_") :]
    return out, zipfile.ZipFile(zip_path), stamp


@pytest.mark.parametrize("extra", [[], ["--no-csv"]], ids=["with-csv", "no-csv"])
def test_single_account_puts_the_plans_file_in_the_zip_and_only_the_zip_is_left(
    tmp_path, monkeypatch, extra
):
    out, archive, stamp = _single(tmp_path, monkeypatch, extra)
    name = plans_json.file_name(stamp)
    assert titles(archive.read(name).decode()) == ["Daily", "Weekly"]
    assert not (out / name).exists()


def test_keep_artifacts_also_writes_the_plans_file_beside_the_zip(tmp_path, monkeypatch):
    out, archive, stamp = _single(tmp_path, monkeypatch, ["--keep-artifacts"])
    name = plans_json.file_name(stamp)
    assert (out / name).read_text(encoding="utf-8") == archive.read(name).decode()
    assert titles((out / name).read_text(encoding="utf-8")) == ["Daily", "Weekly"]


def test_single_account_file_lists_plans_in_region_scan_order(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    json_path = out / "aws_sizing_discovery.json"
    json_path.write_text(
        json.dumps(
            _result(
                regions_scanned=["ca-central-1", "us-east-1", "us-west-2"],
                backup_plans=[
                    plan("west", region="us-west-2"),
                    plan("central", region="ca-central-1"),
                    plan("east", region="us-east-1"),
                ],
            )
        )
    )
    zip_path = main._finish_single_account(str(json_path), str(out), STAMP, False, None)
    text = zipfile.ZipFile(zip_path).read(plans_json.file_name(STAMP)).decode()
    assert titles(text) == ["central", "east", "west"]


def test_anonymized_single_account_has_no_plans_file(tmp_path, monkeypatch):
    out, archive, stamp = _single(tmp_path, monkeypatch, ["--anonymize"])
    assert plans_json.file_name(stamp) not in archive.namelist()
    assert not list(out.glob("aws-backup-plans-info-*"))


def test_single_account_plans_file_failure_does_not_cost_the_zip(tmp_path, monkeypatch):
    monkeypatch.setattr(plans_json, "build", lambda plans: 1 / 0)
    out, archive, stamp = _single(tmp_path, monkeypatch, [])
    names = archive.namelist()
    assert "aws_sizing_discovery.json" in names and [n for n in names if n.endswith(".csv")]
    assert plans_json.file_name(stamp) not in names

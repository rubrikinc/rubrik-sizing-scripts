"""A 403 about the quota project (the project Google charges every call to) is reported once, as
not checked, instead of as a disabled API or billing in every scanned project.

The fixtures are worded as in real six-project runs: one with quota project whatlab-prod, where
Spanner and Bigtable were off there only, and one with a quota project whose billing was off.
"""

from __future__ import annotations

import csv
import io
import logging
from io import StringIO

import auth
import main
import preflight
import preflight_core as core
import pytest
import runlog
from google.api_core import exceptions as gexc
from rich.console import Console

QUOTA = "whatlab-prod"
NO_BILLING = "discovery-project-500523"
SIX = [
    "kd-test-512519",
    "alpha-proj-1",
    "beta-proj-22",
    "gamma-proj-3",
    "delta-proj-4",
    "epsilon-proj-5",
]
ALL = set(main._CORE_COLLECTORS)


def api_off(api: str, service: str, project: str = QUOTA) -> str:
    return (
        f"403 {api} has not been used in project {project} before or it is disabled. Enable it by "
        f"visiting https://console.developers.google.com/apis/api/{service}/overview"
        f"?project={project} then retry. If you enabled this API recently, wait a few minutes for "
        "the action to propagate to our systems and retry."
    )


SPANNER_OFF = api_off("Cloud Spanner API", "spanner.googleapis.com")
BIGTABLE_OFF = api_off("Cloud Bigtable Admin API", "bigtableadmin.googleapis.com")
ASSET_OFF = api_off("Cloud Asset API", "cloudasset.googleapis.com")
BILLING_OFF = (
    "403 This API method requires billing to be enabled. Please enable billing on project "
    f"#{NO_BILLING} by visiting https://console.developers.google.com/billing/enable?project="
    f"{NO_BILLING} then retry. If you enabled billing for this project recently, wait a few "
    'minutes for the action to propagate to our systems and retry. [reason: "BillingDisabled"\n'
    f'domain: "googleapis.com"\nmetadata {{\n  key: "consumer"\n  value: "projects/{NO_BILLING}"\n}}]'
)
USER_PROJECT_DENIED = (
    f"403 Caller does not have required permission to use project {QUOTA}. Grant the caller the "
    'roles/serviceusage.serviceUsageConsumer role. [reason: "USER_PROJECT_DENIED"]'
)
IAM_DENIED = (
    "403 Permission 'storage.buckets.list' denied on resource (or it may not exist). "
    '[reason: "IAM_PERMISSION_DENIED"]'
)


def compute_off(project: str) -> str:
    return api_off("Compute Engine API", "compute.googleapis.com", project)


def scanned_billing_off(project: str) -> str:
    return (
        "403 This API method requires billing to be enabled. Please enable billing on project "
        f"#{project} by visiting https://console.developers.google.com/billing/enable?project="
        f"{project} then retry."
    )


def failed(project: str, service: str, exc: BaseException) -> core.Check:
    """The check a probe gives when it raises ``exc``, as ``run_probes`` builds it."""
    api = next(a for a in preflight.APIS if a.label == service)
    status, code = preflight.classify(exc)
    return core.Check(
        project,
        "",
        project,
        service,
        status,
        None,
        code,
        api.affects,
        "",
        api.permission,
        core.brief_message(exc),
    )


def ok(project: str, service: str) -> core.Check:
    api = next(a for a in preflight.APIS if a.label == service)
    return core.Check(
        project, "", project, service, core.OK, None, "", api.affects, "", api.permission
    )


@pytest.fixture(autouse=True)
def _fresh_issues():
    runlog.core.ISSUES.reset()
    yield
    runlog.core.ISSUES.reset()


# ── classifying one 403 ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "message, project",
    [
        (SPANNER_OFF, QUOTA),
        (compute_off("kd-test-512519"), "kd-test-512519"),
        (BILLING_OFF, NO_BILLING),
        (scanned_billing_off("alpha-proj-1"), "alpha-proj-1"),
        (USER_PROJECT_DENIED, QUOTA),
        (
            "403 Compute Engine API has not been enabled because billing must be enabled for project p1",
            "p1",
        ),
        ("Project 'p2' requires billing to be enabled", "p2"),
        (IAM_DENIED, ""),
    ],
)
def test_the_project_an_error_names_is_found(message, project):
    assert preflight.named_project(message) == project


@pytest.mark.parametrize(
    "scanned, message, quota, expected",
    [
        # (a) API off in the scanned project
        (
            "kd-test-512519",
            compute_off("kd-test-512519"),
            QUOTA,
            (core.NOT_ENABLED, "ServiceDisabled"),
        ),
        # (b) API off in the quota project
        ("alpha-proj-1", SPANNER_OFF, QUOTA, (core.ERROR, preflight.QUOTA_API_OFF)),
        # (c) billing off in the quota project
        ("alpha-proj-1", BILLING_OFF, NO_BILLING, (core.ERROR, preflight.QUOTA_BILLING_OFF)),
        # (d) billing off in the scanned project
        (
            "alpha-proj-1",
            scanned_billing_off("alpha-proj-1"),
            QUOTA,
            (core.NOT_ENABLED, "BillingDisabled"),
        ),
        # (e) a missing IAM permission
        ("alpha-proj-1", IAM_DENIED, QUOTA, (core.DENIED, "PermissionDenied")),
        # the quota project refuses the caller outright
        ("alpha-proj-1", USER_PROJECT_DENIED, QUOTA, (core.ERROR, preflight.QUOTA_DENIED)),
    ],
)
def test_each_kind_of_403_is_told_apart(scanned, message, quota, expected):
    (check,) = preflight.attribute(
        [failed(scanned, "spanner instances", gexc.PermissionDenied(message))], quota
    )
    assert (check.status, check.code) == expected


def test_the_quota_project_scanned_itself_keeps_its_own_disabled_api():
    (check,) = preflight.attribute(
        [failed(QUOTA, "spanner instances", gexc.PermissionDenied(SPANNER_OFF))], QUOTA
    )
    assert (check.status, check.code) == (core.NOT_ENABLED, "ServiceDisabled")


def test_an_unknown_quota_project_is_found_by_the_errors_naming_another_project():
    (check,) = preflight.attribute(
        [failed("alpha-proj-1", "spanner instances", gexc.PermissionDenied(SPANNER_OFF))], ""
    )
    assert check.code == preflight.QUOTA_API_OFF


def test_a_project_number_named_by_one_project_only_is_left_as_it_is():
    """A number can be the scanned project's own (Google sometimes names it that way)."""
    message = api_off("Cloud Spanner API", "spanner.googleapis.com", "123456789")
    (check,) = preflight.attribute(
        [failed("alpha-proj-1", "spanner instances", gexc.PermissionDenied(message))], ""
    )
    assert check.code == "ServiceDisabled"
    two = preflight.attribute(
        [failed(p, "spanner instances", gexc.PermissionDenied(message)) for p in SIX[:2]], ""
    )
    assert {c.code for c in two} == {preflight.QUOTA_API_OFF}


def test_a_login_without_a_quota_project_is_not_checked():
    exc = gexc.PermissionDenied(
        "Your application is authenticating by using local Application Default Credentials. The "
        "cloudasset.googleapis.com API requires a quota project, which is not set by default."
    )
    assert preflight.classify(exc) == (core.ERROR, preflight.NO_QUOTA_PROJECT)


# ── the quota project's problem is reported once ─────────────────────────────


def _six_project_run(message=SPANNER_OFF, services=("spanner instances",)):
    checks = []
    for project in SIX:
        for service in services:
            checks.append(failed(project, service, gexc.PermissionDenied(message)))
        checks.append(ok(project, "compute instances"))
    return checks


def test_the_same_error_in_six_projects_is_one_problem_not_six():
    checks = preflight.attribute(_six_project_run(), QUOTA)
    problems = preflight.quota_problems(checks)
    assert len(problems) == 1
    assert problems[0]["project"] == QUOTA and problems[0]["scopes"] == SIX
    assert preflight.project_groups(checks) == []
    lines = runlog.quota_block(problems, len(SIX))
    assert lines[0] == (
        f"  Quota project {QUOTA} has spanner.googleapis.com disabled; this affects all 6 projects."
    )
    assert sum("Quota project" in line for line in lines) == 1


def test_every_api_off_in_the_quota_project_is_in_one_enable_command():
    checks = []
    for project in SIX:
        checks += [
            failed(project, "spanner instances", gexc.PermissionDenied(SPANNER_OFF)),
            failed(project, "bigtable instances", gexc.PermissionDenied(BIGTABLE_OFF)),
            failed(project, "cloud asset inventory", gexc.PermissionDenied(ASSET_OFF)),
        ]
    problems = preflight.quota_problems(preflight.attribute(checks, QUOTA))
    assert len(problems) == 1
    text = "\n".join(runlog.quota_block(problems, len(SIX)))
    assert (
        "Run: gcloud services enable spanner.googleapis.com bigtableadmin.googleapis.com "
        f"cloudasset.googleapis.com --project {QUOTA}"
    ) in text
    assert "Run: gcloud auth application-default set-quota-project <other-project>" in text
    assert "<scanned-project>" not in text


def test_the_fix_follows_where_the_quota_project_came_from():
    problems = preflight.quota_problems(preflight.attribute(_six_project_run(), QUOTA))
    text = "\n".join(runlog.quota_block(problems, len(SIX), auth.QUOTA_FROM_ENV))
    assert "Run: export GOOGLE_CLOUD_QUOTA_PROJECT=<other-project>" in text


def test_billing_off_in_the_quota_project_gets_a_specific_fix():
    checks = preflight.attribute(
        _six_project_run(BILLING_OFF, ("spanner instances", "bigtable instances")), NO_BILLING
    )
    (problem,) = preflight.quota_problems(checks)
    assert problem["code"] == preflight.QUOTA_BILLING_OFF and problem["project"] == NO_BILLING
    text = "\n".join(runlog.quota_block([problem], len(SIX)))
    assert f"Quota project {NO_BILLING} has billing disabled; this affects all 6 projects" in text
    assert (
        f"Run: gcloud billing projects link {NO_BILLING} --billing-account=<BILLING_ACCOUNT_ID>"
        in text
    )
    assert "gcloud billing projects describe" in text and "gcloud services list --enabled" in text
    assert "no specific advice" not in text
    assert "#gcp-quota-project-billing-disabled" in text


def test_the_quota_projects_rows_are_not_checked_in_the_table_and_the_csv():
    checks = preflight.attribute(_six_project_run(), QUOTA)
    spanner = next(
        line for line in preflight.table_lines(checks) if line.lstrip().startswith("spanner")
    )
    assert "NOT CHECKED" in spanner and "API NOT ENABLED" not in spanner
    assert "QuotaProjectServiceDisabled" in spanner
    rows = list(csv.DictReader(io.StringIO(preflight.csv_for([c.to_row() for c in checks]))))
    spanner_rows = [r for r in rows if r["Service"] == "spanner instances"]
    assert len(spanner_rows) == 6
    assert {(r["Access"], r["Outcome"], r["Detail"]) for r in spanner_rows} == {
        ("could not be checked", "unknown", "QuotaProjectServiceDisabled")
    }
    assert list(rows[0]) == list(core.CSV_COLUMNS)


def test_a_service_off_only_in_the_quota_project_is_still_collected():
    """Not checked is not "switched off": the scan still tries it, and may well find data."""
    rows = [c.to_row() for c in preflight.attribute(_six_project_run(), QUOTA)]
    assert preflight.switched_off_collectors(rows) == {}


def test_the_quota_problem_is_one_entry_in_the_digest_per_service():
    checks = preflight.attribute(_six_project_run(), QUOTA)
    runlog.quota_block(preflight.quota_problems(checks), len(SIX))
    for project in SIX:
        runlog.core.ISSUES.add(
            logging.WARNING,
            "x",
            f"Spanner collection failed for project {project}: {SPANNER_OFF}",
        )
    [group] = runlog.core.ISSUES.groups()
    assert group["scopes"] == SIX


# ── per-project problems name each project ───────────────────────────────────


def test_compute_off_in_two_projects_names_both_in_the_fix():
    checks = preflight.attribute(
        [
            failed(
                "kd-test-512519",
                "compute instances",
                gexc.PermissionDenied(compute_off("kd-test-512519")),
            ),
            failed(
                "alpha-proj-1",
                "compute instances",
                gexc.PermissionDenied(compute_off("alpha-proj-1")),
            ),
            ok("beta-proj-22", "compute instances"),
        ],
        QUOTA,
    )
    assert preflight.quota_problems(checks) == []
    (group,) = preflight.project_groups(checks)
    text = "\n".join(runlog.problem_block([group]))
    assert "Run: gcloud services enable compute.googleapis.com --project kd-test-512519" in text
    assert "Run: gcloud services enable compute.googleapis.com --project alpha-proj-1" in text
    assert "beta-proj-22" not in text
    assert "set-quota-project" not in text


def test_billing_off_in_scanned_projects_gets_a_specific_fix_per_project():
    checks = preflight.attribute(
        [
            failed(p, "spanner instances", gexc.PermissionDenied(scanned_billing_off(p)))
            for p in SIX[:2]
        ],
        QUOTA,
    )
    (group,) = preflight.project_groups(checks)
    assert group["code"] == "BillingDisabled"
    text = "\n".join(runlog.problem_block([group]))
    assert "no specific advice" not in text
    for project in SIX[:2]:
        assert f"gcloud billing projects link {project} --billing-account=" in text
    assert "#gcp-billing-disabled" in text


def test_a_missing_permission_names_each_project_and_the_permission():
    checks = [
        failed(p, "cloud storage buckets", gexc.PermissionDenied(IAM_DENIED)) for p in SIX[:3]
    ]
    (group,) = preflight.project_groups(preflight.attribute(checks, QUOTA))
    text = "\n".join(runlog.problem_block([group]))
    assert "storage.buckets.list" in text
    for project in SIX[:3]:
        assert f"add-iam-policy-binding {project} " in text


def test_a_long_project_list_is_cut_and_points_at_the_csv():
    projects = [f"proj-{i:03d}" for i in range(14)]
    checks = [
        failed(p, "compute instances", gexc.PermissionDenied(compute_off(p))) for p in projects
    ]
    (group,) = preflight.project_groups(preflight.attribute(checks, QUOTA))
    lines = runlog.problem_block([group])
    assert sum("gcloud services enable" in line for line in lines) == 10
    assert any("and 4 more projects" in line and "gcp_preflight_check" in line for line in lines)


# ── the effective quota project ──────────────────────────────────────────────


class _Creds:
    def __init__(self, quota):
        self.quota_project_id = quota


def test_the_quota_project_from_the_environment_says_so(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLOUD_QUOTA_PROJECT", QUOTA)
    assert auth.effective_quota_project(_Creds(QUOTA)) == (QUOTA, auth.QUOTA_FROM_ENV)


def test_the_quota_project_from_the_login_says_so(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_QUOTA_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    assert auth.effective_quota_project(_Creds(QUOTA)) == (QUOTA, auth.QUOTA_FROM_ADC)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/key.json")
    assert auth.effective_quota_project(_Creds(QUOTA)) == (QUOTA, auth.QUOTA_FROM_KEY_FILE)


def test_no_quota_project_is_empty(monkeypatch):
    assert auth.effective_quota_project(_Creds(None)) == ("", "")
    assert auth.effective_quota_project(object()) == ("", "")


def test_main_prints_the_quota_project_first_and_reports_its_problem_once(monkeypatch):
    out = StringIO()
    monkeypatch.setattr(main, "console", Console(file=out, width=240, force_terminal=False))
    monkeypatch.delenv("GOOGLE_CLOUD_QUOTA_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)

    def fake_run_all(projects, credentials, selected, workers):
        return [
            [
                failed(p, "spanner instances", gexc.PermissionDenied(SPANNER_OFF)),
                failed(p, "bigtable instances", gexc.PermissionDenied(BIGTABLE_OFF)),
                (
                    failed(p, "compute instances", gexc.PermissionDenied(compute_off(p)))
                    if p == SIX[0]
                    else ok(p, "compute instances")
                ),
            ]
            for p in projects
        ]

    monkeypatch.setattr(preflight, "run_all", fake_run_all)
    rows = main._run_access_check(SIX, _Creds(QUOTA), ALL, 4)
    text = out.getvalue()
    assert text.splitlines()[0] == (
        f"Quota project: {QUOTA} (from the application-default login); every API call is "
        "charged to it"
    )
    assert text.count(f"Quota project {QUOTA} has") == 1
    assert "this affects all 6 projects" in text
    assert "compute instances (kd-test-512519): ServiceDisabled" in text
    assert "Run: gcloud services enable compute.googleapis.com --project kd-test-512519" in text
    assert len(rows) == 18
    assert sum(r["Detail"] == "QuotaProjectServiceDisabled" for r in rows) == 12

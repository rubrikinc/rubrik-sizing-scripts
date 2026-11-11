"""The GCP run log: a transcript of the screen, a digest of the problems with their fixes."""

from __future__ import annotations

import logging
import re
import sys
import zipfile
from io import StringIO

import collectors.utils  # noqa: F401
import main
import pytest
import runlog
import runlog_core as core
from logging_setup import add_log_file
from rich.control import Control
from rich.panel import Panel
from rich.table import Table

PROJECT = "sample-project-1"


@pytest.fixture(autouse=True)
def _fresh():
    core.ISSUES.reset()
    yield
    core.ISSUES.reset()


@pytest.fixture
def log(tmp_path):
    handler = add_log_file(str(tmp_path / "run.log"))
    root = logging.getLogger()
    previous = root.level
    root.setLevel(logging.DEBUG)
    yield tmp_path / "run.log"
    root.setLevel(previous)
    root.removeHandler(handler)
    handler.close()


def _text(path):
    return path.read_text(encoding="utf-8")


# ── the console that logs itself ──────────────────────────────────────────────


def test_what_the_console_prints_is_in_the_log_as_plain_text(log):
    console = runlog.LoggedConsole(file=StringIO(), width=100, force_terminal=True)
    console.print("[bold green]✓[/bold green] 1/5 [cyan]sample-project-1[/cyan]  0 assets")
    assert "✓ 1/5 sample-project-1  0 assets" in _text(log) and "\x1b" not in _text(log)


def test_a_panel_and_a_table_are_logged_as_the_screen_drew_them(log):
    console = runlog.LoggedConsole(file=StringIO(), width=70, force_terminal=False)
    console.print(Panel("Rubrik Discovery — GCP Edition"))
    table = Table("Project", "Instances")
    table.add_row("alpha", "3")
    console.print(table)
    text = _text(log)
    assert "Rubrik Discovery — GCP Edition" in text and "Project" in text and "alpha" in text


def test_an_empty_print_is_a_blank_line_and_a_print_that_shows_nothing_is_skipped(log):
    console = runlog.LoggedConsole(file=StringIO())
    console.print()
    console.print(Control())
    assert _text(log) == "\n"


def test_a_spinner_is_on_the_screen_but_not_in_the_log(log):
    console = runlog.LoggedConsole(file=StringIO(), force_terminal=True, width=80)
    with console.status("Checking access…"):
        console.print("done")
    assert _text(log) == "done\n"


def test_the_console_works_when_no_log_is_open():
    out = StringIO()
    runlog.LoggedConsole(file=out, width=80).print("hello")
    assert "hello" in out.getvalue()


# ── what the log holds ────────────────────────────────────────────────────────


def test_warnings_are_logged_and_info_and_debug_are_not(log):
    logger = logging.getLogger("collectors.compute")
    logger.debug("a debug detail")
    logger.info("an info detail")
    logger.warning("Compute collection failed for project p: 403")
    text = _text(log)
    assert "a debug detail" not in text and "an info detail" not in text
    assert re.search(
        r"WARNING collectors\.compute — Compute collection failed for project p: 403", text
    )


def test_library_debug_noise_never_reaches_the_log_but_library_warnings_do(log):
    logging.getLogger("googleapiclient.discovery").debug("URL being requested: GET https://x")
    logging.getLogger("urllib3.connectionpool").debug("Starting new HTTPS connection")
    logging.getLogger("googleapiclient.http").warning("Encountered 503 Service Unavailable")
    text = _text(log)
    assert "URL being requested" not in text and "Starting new" not in text
    assert "Encountered 503 Service Unavailable" in text


def test_the_header_names_the_tool_the_code_and_the_packages(log):
    runlog.start(["--projects", "a,b", "--output", "./output"])
    head = _text(log).splitlines()
    assert head[0] == "# Run log: GCP sizing tool"
    assert any(line.startswith("# Packages: google-auth ") for line in head)
    assert "# Command line: --projects a,b --output ./output" in head


# ── a whole run ───────────────────────────────────────────────────────────────


def _mock_run(tmp_path, monkeypatch, during=lambda: None, argv=()):
    original = main._run_mock

    def wrapped():
        during()
        return original()

    monkeypatch.setattr(main, "_run_mock", wrapped)
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path), *argv])
    main.main()
    zf = zipfile.ZipFile(next(tmp_path.glob("gcp_sizing_results_*.zip")))
    name = next(n for n in zf.namelist() if n.startswith("output_gcp_") and n.endswith(".log"))
    return zf.read(name).decode()


def test_a_run_leaves_a_transcript_with_the_header_the_summary_table_and_a_digest(
    tmp_path, monkeypatch
):
    text = _mock_run(tmp_path, monkeypatch)
    lines = text.splitlines()
    assert lines[0] == "# Run log: GCP sizing tool"
    assert "Discovery Summary" in text and "TOTAL" in text, "the table the screen showed"
    assert "Run summary" in lines
    assert " DEBUG " not in text and len(lines) < 150


def test_the_summary_table_is_in_the_log_before_the_run_summary(tmp_path, monkeypatch):
    text = _mock_run(tmp_path, monkeypatch)
    assert text.index("Discovery Summary") < text.index("Run summary")


def test_a_problem_is_reported_once_with_its_count_and_what_to_do(tmp_path, monkeypatch):
    def failures():
        for name in ("alpha-proj-1", "beta-proj-22", "gamma-proj-3"):
            logging.getLogger("collectors.compute").warning(
                "Compute collection failed for project %s: 403 GET https://compute.googleapis.com/x: "
                "Required 'compute.instances.list' permission for 'projects/%s'",
                name,
                name,
            )

    text = _mock_run(tmp_path, monkeypatch, during=failures)
    summary = text.split("Run summary", 1)[1]
    assert "1 distinct problem (3 warnings and errors in all):" in summary
    assert "3 projects: Compute collection failed for project alpha-proj-1" in summary
    assert "Projects: alpha-proj-1, beta-proj-22, gamma-proj-3" in summary
    assert "Fix: The identity cannot read this project." in summary
    assert "(docs/troubleshooting.md#gcp-permission-denied)" in summary


def test_an_api_that_must_be_enabled_in_the_billing_project_says_which_project_and_how(
    tmp_path, monkeypatch
):
    def failures():
        for name in ("alpha-proj-1", "beta-proj-22"):
            logging.getLogger("collectors.database").warning(
                "Bigtable collection failed for project %s: 403 Cloud Bigtable Admin API has not been "
                "used in project cnp-bigquery-dev-1 before or it is disabled. Enable it by visiting "
                "https://console.developers.google.com/apis/api/bigtableadmin.googleapis.com/overview"
                "?project=cnp-bigquery-dev-1 then retry.",
                name,
            )

    text = _mock_run(tmp_path, monkeypatch, during=failures)
    summary = text.split("Run summary", 1)[1]
    assert "2 projects: Bigtable collection failed" in summary
    assert "Projects: alpha-proj-1, beta-proj-22" in summary
    assert (
        "gcloud services enable bigtableadmin.googleapis.com --project cnp-bigquery-dev-1"
        in summary
    )
    assert "set-quota-project" in summary


# ── what to do about each error (real messages from a run) ────────────────────

EMAIL = "someone@example.com"
REAL_MESSAGES = [
    (
        "Asset enumeration failed for project p: 403 Request denied by Cloud IAM. Missing required IAM "
        "permission on requested scope. For required permissions, please refer to "
        "https://cloud.google.com/asset-inventory/docs/roles-permissions. (check that Cloud Asset "
        "Inventory API is enabled and roles/cloudasset.viewer is granted)",
        "gcp-permission-denied",
    ),
    (
        "Disk listing failed for project p: 403 GET https://compute.googleapis.com/compute/v1/projects/p/"
        "aggregated/disks: Required 'compute.disks.list' permission for 'projects/p' — disk sizes will be missing",
        "gcp-permission-denied",
    ),
    (
        f"Storage collection failed for project p: 403 GET https://storage.googleapis.com/storage/v1/b?project=p: "
        f"{EMAIL} does not have storage.buckets.list access to the Google Cloud project. Permission "
        "'storage.buckets.list' denied on resource (or it may not exist).",
        "gcp-permission-denied",
    ),
    (
        "Cloud SQL collection failed for project p: <HttpError 403 when requesting https://sqladmin.googleapis.com/"
        'sql/v1beta4/projects/p/instances?alt=json returned "The client is not authorized to make this request.". '
        "Details: \"[{'message': 'The client is not authorized to make this request.', 'domain': 'global', "
        "'reason': 'notAuthorized'}]\">",
        "gcp-permission-denied",
    ),
    (
        "Spanner collection failed for project p: 403 Operation denied by [IAM permission "
        "'spanner.instances.list' on resource '//spanner.googleapis.com/projects/p']. "
        '[reason: "IAM_PERMISSION_DENIED" domain: "iam.googleapis.com" metadata { key: "resource" '
        'value: "projects/p" } metadata { key: "permission" value: "spanner.instances.list" } ]',
        "gcp-permission-denied",
    ),
    (
        "Spanner collection failed for project p: 403 Operation denied by org policy: "
        "[customerMessage=Constraint constraints/gcp.resourceLocations violated]",
        "gcp-org-policy",
    ),
    (
        "Storage collection failed for project p: 403 Request is prohibited by organization's "
        "policy. vpcServiceControlsUniqueIdentifier: abc123",
        "gcp-org-policy",
    ),
    (
        "AlloyDB collection failed for project p: 403 Permission 'alloydb.clusters.list' denied on "
        "'projects/p/locations/-/clusters'",
        "gcp-permission-denied",
    ),
    (
        "AlloyDB collection failed for project sizing-eng-test: 403 AlloyDB API has not been used in project "
        "sizing-eng-test before or it is disabled. Enable it by visiting https://console.developers.google.com/"
        "apis/api/alloydb.googleapis.com/overview?project=sizing-eng-test then retry. If you enabled this API "
        "recently, wait a few minutes for the action to propagate to our systems and retry.",
        "gcp-api-disabled-in-billing-project",
    ),
    (
        "Bigtable collection failed for project p: 403 Cloud Bigtable Admin API has not been used in project "
        "cnp-bigquery-dev-1 before or it is disabled. Enable it by visiting https://console.developers.google.com/"
        "apis/api/bigtableadmin.googleapis.com/overview?project=cnp-bigquery-dev-1 then retry.",
        "gcp-api-disabled-in-billing-project",
    ),
    ("403 SERVICE_DISABLED for backupdr.googleapis.com", "gcp-api-disabled"),
    (
        "Your default credentials were not found. To set up Application Default Credentials",
        "gcp-no-credentials",
    ),
    ("429 Quota exceeded for quota metric 'Read requests'", "gcp-rate-limited"),
    ("404 PROJECT_NOT_FOUND", "gcp-project-not-found"),
    (
        "ImportError: cannot import name 'backupdr_v1' from 'google.cloud'",
        "gcp-client-library-missing",
    ),
    (
        "RefreshError: ('invalid_grant: Token has been expired or revoked.', {'error': "
        "'invalid_grant', 'error_description': 'Token has been expired or revoked.'})",
        "gcp-credentials-expired",
    ),
    (
        "Reauthentication is needed. Please run `gcloud auth application-default login` to "
        "reauthenticate.",
        "gcp-credentials-expired",
    ),
    (
        "Project bad-proj-1 not accessible: 403 The caller does not have permission \u2014 skipping",
        "gcp-no-projects",
    ),
    (
        "scope.projects in the config file is not used for project selection; pass --projects or "
        "--project-file. Scanning: all accessible projects",
        "gcp-no-projects",
    ),
    (
        "Transient GCP error during list_databases(projects/p/instances/i), backing off and "
        "retrying: 429 Too Many Requests",
        "gcp-transient-retry",
    ),
    (
        "Org-wide asset enumeration failed for scope organizations/1234: 503 Service Unavailable "
        "(check Cloud Asset Inventory API is enabled and roles/cloudasset.viewer is granted at the "
        "org/folder level) \u2014 falling back to per-project asset collection",
        "gcp-asset-inventory",
    ),
    (
        "Asset enumeration failed for project p: 503 Service Unavailable (check that Cloud Asset "
        "Inventory API is enabled and roles/cloudasset.viewer is granted)",
        "gcp-asset-inventory",
    ),
    ("404 Project 'shop-4290' not found or deleted. PROJECT_NOT_FOUND", "gcp-project-not-found"),
    (
        "ServiceDisabled 403 Your application is authenticating by using local Application Default "
        "Credentials. The cloudasset.googleapis.com API requires a quota project, which is not set "
        "by default.",
        "gcp-quota-project-warning",
    ),
    (
        "Spanner collection failed for project p: 403 Operation denied by\n[IAM permission "
        "'spanner.instances.list' on resource '//spanner.googleapis.com/projects/p']. "
        '[reason: "IAM_PERMISSION_DENIED" domain: "iam.googleapis.com"',
        "gcp-permission-denied",
    ),
    (
        "Bigtable collection failed for project p: 403 Access denied. Missing IAM permission: "
        "bigtable.instances.list.",
        "gcp-permission-denied",
    ),
    ("403 Operation denied by org policy on resource 'projects/p'", "gcp-org-policy"),
]


@pytest.mark.parametrize("message, expected", REAL_MESSAGES)
def test_each_kind_of_error_gets_its_fix(message, expected):
    found = core.solve(message)
    assert found is not None and found[0] == expected, message


def test_the_fix_for_a_disabled_api_names_the_service_and_the_project_from_the_error():
    message = next(m for m, _ in REAL_MESSAGES if "bigtableadmin" in m)
    solution_id, fix = core.solve(message)
    assert solution_id == "gcp-api-disabled-in-billing-project"
    assert (
        "Run: gcloud services enable bigtableadmin.googleapis.com --project cnp-bigquery-dev-1"
        in fix
    )
    assert "That is the project Google charges the call to" in fix


def test_an_error_nobody_has_seen_says_there_is_no_specific_advice():
    assert core.solve("Something entirely unexpected happened") is None


@pytest.mark.parametrize(
    "message",
    [
        "404 Project 'shop-429' not found PROJECT_NOT_FOUND",
        "Compute collection failed for project p: 404 projects/842901234 PROJECT_NOT_FOUND",
        "Compute collection failed for project p: 404 projects/429 PROJECT_NOT_FOUND",
    ],
)
def test_429_inside_a_project_id_or_number_is_not_a_rate_limit(message):
    assert core.solve(message)[0] == "gcp-project-not-found"


def test_a_project_that_cannot_be_read_because_an_api_is_off_gets_the_billing_project_fix():
    message = (
        "Project p1 not accessible: 403 Cloud Resource Manager API has not been used in project "
        "cnp-example-1 before or it is disabled. Enable it by visiting https://console.developers."
        "google.com/apis/api/cloudresourcemanager.googleapis.com/overview?project=cnp-example-1"
    )
    assert core.solve(message)[0] == "gcp-api-disabled-in-billing-project"


def test_a_denied_project_listing_gets_the_permission_fix_and_any_other_failure_the_no_projects_one():
    denied = (
        "Failed to enumerate projects: 403 PERMISSION_DENIED: The caller does not have permission"
    )
    other = "Failed to enumerate projects: 503 Service Unavailable"
    assert core.solve(denied)[0] == "gcp-permission-denied"
    assert core.solve(other)[0] == "gcp-no-projects"


def test_the_same_failure_on_different_projects_is_one_problem():
    a = core.normalize(
        "Compute collection failed for project alpha-proj-1: 403 for 'projects/alpha-proj-1'"
    )
    b = core.normalize(
        "Compute collection failed for project beta-proj-22: 403 for 'projects/beta-proj-22'"
    )
    assert a == b


def test_every_fix_has_a_unique_id_and_says_what_to_do():
    ids = [s.id for s in runlog.SOLUTIONS]
    assert len(ids) == len(set(ids)) and all(i.startswith("gcp-") for i in ids)
    assert all(len(s.fix) > 40 for s in runlog.SOLUTIONS)


def test_the_new_modules_are_packaged():
    text = open("pyproject.toml", encoding="utf-8").read()
    assert '"runlog"' in text and '"runlog_core"' in text


# ── one problem per cause ─────────────────────────────────────────────────────

BILLING = "cnp-bigquery-dev-1"


def _api_off(api, service, billing=BILLING):
    return (
        f"403 {api} has not been used in project {billing} before or it is disabled. Enable it by "
        f"visiting https://console.developers.google.com/apis/api/{service}/overview"
        f"?project={billing} then retry."
    )


def _scan_warning(label, project, message):
    return f"{label} collection failed for project {project}: {message}"


def _preflight(service, code, message, scopes):
    return [
        {
            "service": service,
            "code": code,
            "status": "blocked",
            "message": message,
            "scopes": scopes,
        }
    ]


def test_the_access_check_and_the_collector_report_one_problem_when_they_name_the_same_cause():
    projects = ["alpha-proj-1", "beta-proj-22", "gamma-proj-3"]
    message = _api_off("Cloud Bigtable Admin API", "bigtableadmin.googleapis.com")
    runlog.problem_block(_preflight("bigtable instances", "ServiceDisabled", message, projects))
    for project in projects:
        core.ISSUES.add(logging.WARNING, "x", _scan_warning("Bigtable", project, message))
    [group] = core.ISSUES.groups()
    assert group["scopes"] == projects and group["count"] == 6


def test_an_api_that_is_off_in_two_billing_projects_is_two_problems_because_the_fixes_differ():
    core.ISSUES.add(
        logging.WARNING,
        "x",
        _scan_warning("AlloyDB", "alpha-proj-1", _api_off("AlloyDB API", "alloydb.googleapis.com")),
    )
    core.ISSUES.add(
        logging.WARNING,
        "x",
        _scan_warning(
            "AlloyDB",
            "beta-proj-22",
            _api_off("AlloyDB API", "alloydb.googleapis.com", "beta-proj-22"),
        ),
    )
    assert len(core.ISSUES.groups()) == 2


def test_two_calls_of_one_service_denied_for_the_same_reason_are_one_problem():
    denied = (
        "403 GET https://compute.googleapis.com/x: Required 'compute.instances.list' permission"
    )
    core.ISSUES.add(logging.WARNING, "x", _scan_warning("Compute", "alpha-proj-1", denied))
    core.ISSUES.add(logging.WARNING, "x", f"Disk listing failed for project alpha-proj-1: {denied}")
    core.ISSUES.add(
        logging.WARNING, "x", f"compute disks: PermissionDenied {denied}", "beta-proj-22"
    )
    [group] = core.ISSUES.groups()
    assert group["scopes"] == ["alpha-proj-1", "beta-proj-22"]


def test_different_services_denied_are_different_problems():
    denied = "403 Required 'x.y.list' permission for 'projects/alpha-proj-1'"
    for label in ("Compute", "Storage", "Cloud SQL", "Asset enumeration"):
        core.ISSUES.add(
            logging.WARNING,
            "x",
            f"{label} collection failed for project alpha-proj-1: {denied}",
        )
    assert len(core.ISSUES.groups()) == 4


def test_a_project_named_after_a_service_does_not_change_what_the_message_is_about():
    denied = "403 Required 'x.y.list' permission"
    a = runlog.cause(f"Compute collection failed for project backup-prod-1: {denied}")
    b = runlog.cause(f"Compute collection failed for project alpha-proj-1: {denied}")
    assert a[0] == b[0] and a[1] == "backup-prod-1"


def test_a_message_with_no_known_fix_is_left_to_the_ordinary_grouping():
    assert runlog.cause("something nobody has seen: boom") is None
    core.ISSUES.add(logging.WARNING, "x", "something nobody has seen: boom")
    [group] = core.ISSUES.groups()
    assert group["scopes"] == []


def test_the_run_of_the_five_projects_collapses_to_one_entry_per_cause():
    """Messages worded as in a real five-project run: 32 events were listed as 14 problems."""
    bigtable = _api_off("Cloud Bigtable Admin API", "bigtableadmin.googleapis.com")
    backup = _api_off("Backup and DR Service API", "backupdr.googleapis.com")
    alloy = _api_off("AlloyDB API", "alloydb.googleapis.com")
    iam = "403 Request denied by Cloud IAM. Missing required IAM permission on requested scope."
    five = ["cnp-bigquery-dev-1", "galactus-gcp-1", "mysql-dev-1", "mysql-dev-2", "sizing-eng-test"]
    block = (
        _preflight("alloydb clusters", "ServiceDisabled", alloy, [five[0], five[4]])
        + _preflight("bigtable instances", "ServiceDisabled", bigtable, five)
        + _preflight("backup and dr plans", "ServiceDisabled", backup, [five[0], five[2], five[4]])
        + _preflight(
            "backup and dr associations", "ServiceDisabled", backup, [five[0], five[2], five[4]]
        )
        + _preflight("cloud asset inventory", "PermissionDenied", iam, [five[2], five[4]])
        + _preflight("cloud storage buckets", "PermissionDenied", iam, [five[2], five[4]])
        + _preflight("compute instances", "PermissionDenied", iam, [five[2]])
        + _preflight("compute disks", "PermissionDenied", iam, [five[2]])
    )
    runlog.problem_block(block)
    for project in five:
        core.ISSUES.add(logging.WARNING, "x", _scan_warning("Bigtable", project, bigtable))
    for project in (five[2], five[4]):
        core.ISSUES.add(
            logging.WARNING, "x", f"Asset enumeration failed for project {project}: {iam}"
        )
        core.ISSUES.add(logging.WARNING, "x", _scan_warning("Storage", project, iam))
    core.ISSUES.add(logging.WARNING, "x", _scan_warning("Compute", five[2], iam))
    core.ISSUES.add(logging.WARNING, "x", f"Disk listing failed for project {five[2]}: {iam}")
    core.ISSUES.add(logging.WARNING, "x", _scan_warning("AlloyDB", five[0], alloy))
    core.ISSUES.add(
        logging.WARNING,
        "x",
        _scan_warning(
            "AlloyDB", five[4], _api_off("AlloyDB API", "alloydb.googleapis.com", five[4])
        ),
    )
    groups = core.ISSUES.groups()
    assert core.ISSUES.total == 32 and len(groups) == 7
    assert sorted(len(g["scopes"]) for g in groups) == [1, 1, 2, 2, 2, 3, 5]


# ── the client library's own 4xx warning ──────────────────────────────────────


def test_the_client_librarys_own_403_warning_is_dropped_because_the_collector_reports_it(tmp_path):
    from logging_setup import setup_logging

    root = logging.getLogger()
    saved, level = root.handlers[:], root.level
    try:
        setup_logging()
        handler = add_log_file(str(tmp_path / "run.log"))
        http = logging.getLogger("googleapiclient.http")
        http.warning('Encountered 403 Forbidden with reason "notAuthorized"')
        http.warning("Encountered 404 Not Found")
        http.warning("Encountered 429 Too Many Requests, retrying")
        http.warning("Encountered 503 Service Unavailable")
        handler.close()
        text = _text(tmp_path / "run.log")
    finally:
        root.handlers[:] = saved
        root.setLevel(level)
    assert "403 Forbidden" not in text and "404 Not Found" not in text
    assert "429 Too Many Requests" in text and "503 Service Unavailable" in text


def test_setting_up_logging_twice_adds_the_filter_once():
    from logging_setup import _ReportedClientErrors, setup_logging

    setup_logging()
    setup_logging()
    filters = logging.getLogger("googleapiclient.http").filters
    assert sum(isinstance(f, _ReportedClientErrors) for f in filters) == 1

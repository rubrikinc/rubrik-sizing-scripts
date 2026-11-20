"""The GCP pre-flight access check: what it reports, that it follows the scan, and where it lands."""

from __future__ import annotations

import csv
import io
import json
import sys
import zipfile
from io import StringIO
from types import SimpleNamespace
from unittest.mock import MagicMock

import csv_export
import httplib2
import main
import preflight
import preflight_core as core
import pytest
from anonymize import Anonymizer
from google.api_core import exceptions as gexc
from googleapiclient.errors import HttpError
from models.inventory import DiscoveryResult
from rich.console import Console

PROJECT = "sample-project-1"
OTHER = "other-project-999"
CTX = preflight.Context(PROJECT, "credentials")
ALL = set(main._CORE_COLLECTORS)

# label, the client class the collector builds, the call it makes first
CLIENT_PROBES = [
    ("cloud asset inventory", "google.cloud.asset_v1.AssetServiceClient", "list_assets"),
    (
        "spanner instances",
        "google.cloud.spanner_admin_instance_v1.InstanceAdminClient",
        "list_instances",
    ),
    ("alloydb clusters", "google.cloud.alloydb_v1.AlloyDBAdminClient", "list_clusters"),
    ("backup and dr plans", "google.cloud.backupdr_v1.BackupDRClient", "list_backup_plans"),
    (
        "backup and dr associations",
        "google.cloud.backupdr_v1.BackupDRClient",
        "list_backup_plan_associations",
    ),
    ("cloud storage buckets", "google.cloud.storage.Client", "list_buckets"),
]
AGGREGATED = [
    ("compute instances", "google.cloud.compute_v1.InstancesClient"),
    ("compute disks", "google.cloud.compute_v1.DisksClient"),
]
MONITORING_CLIENT = "google.cloud.monitoring_v3.MetricServiceClient"
API = {api.label: api for api in preflight.APIS}


def http_error(status, message="boom", reason="Forbidden"):
    return HttpError(httplib2.Response({"status": status, "reason": reason}), message.encode())


def install(monkeypatch, target, method, items=(), error=None):
    client = MagicMock()
    call = getattr(client, method)
    if error is not None:
        call.side_effect = error
    else:
        call.return_value = list(items)
    constructor = MagicMock(return_value=client)
    monkeypatch.setattr(target, constructor)
    return constructor, call


def install_rest(monkeypatch, response=None, error=None):
    """Stand in for ``googleapiclient.discovery.build``: every list call answers the same."""
    service = MagicMock()
    for resource in ("instances", "datasets"):
        execute = getattr(service, resource).return_value.list.return_value.execute
        if error is not None:
            execute.side_effect = error
        else:
            execute.return_value = response or {}
    build = MagicMock(return_value=service)
    monkeypatch.setattr("googleapiclient.discovery.build", build)
    return build, service


@pytest.fixture
def all_sdk(monkeypatch):
    """Every client the probes use, answering with no resources."""
    for _label, target, method in CLIENT_PROBES:
        install(monkeypatch, target, method)
    for _label, target in AGGREGATED:
        _, call = install(monkeypatch, target, "aggregated_list")
        call.return_value = SimpleNamespace(pages=[])
    _, call = install(monkeypatch, MONITORING_CLIENT, "list_time_series")
    call.return_value = SimpleNamespace(pages=[])
    bigtable = MagicMock()
    bigtable.return_value.list_instances.return_value = ([], [])
    monkeypatch.setattr("google.cloud.bigtable.Client", bigtable)
    install_rest(monkeypatch)


def check(selected=None, **kw):
    return preflight.run_access_check(PROJECT, "credentials", set(selected or ALL), **kw)


def rows(checks, **match):
    return [c for c in checks if all(getattr(c, key) == value for key, value in match.items())]


def run_one(label):
    probe = core.Probe(label, PROJECT, lambda: API[label].probe(CTX), API[label].affects)
    (result,) = core.run_probes(PROJECT, "", [probe], preflight.classify)
    return result


# ── each probe is the collector's own first call ──────────────────────────────


@pytest.mark.parametrize("label, target, method", CLIENT_PROBES)
def test_a_probe_uses_the_collectors_client_and_says_whether_it_saw_a_resource(
    monkeypatch, label, target, method
):
    constructor, call = install(monkeypatch, target, method, items=[object()])
    assert API[label].probe(CTX) is True
    assert constructor.call_args.kwargs.get("credentials") == "credentials"
    install(monkeypatch, target, method, items=[])
    assert API[label].probe(CTX) is False


@pytest.mark.parametrize("label, target, method", CLIENT_PROBES)
def test_a_forbidden_answer_means_denied(monkeypatch, label, target, method):
    install(monkeypatch, target, method, error=gexc.PermissionDenied("IAM_PERMISSION_DENIED"))
    result = run_one(label)
    assert (result.status, result.code) == (core.DENIED, "PermissionDenied")
    assert result.outcome == core.DROPPED


@pytest.mark.parametrize(
    "label, target, method, parent",
    [
        ("cloud asset inventory", CLIENT_PROBES[0][1], "list_assets", f"projects/{PROJECT}"),
        ("spanner instances", CLIENT_PROBES[1][1], "list_instances", f"projects/{PROJECT}"),
        (
            "alloydb clusters",
            CLIENT_PROBES[2][1],
            "list_clusters",
            f"projects/{PROJECT}/locations/-",
        ),
        (
            "backup and dr plans",
            CLIENT_PROBES[3][1],
            "list_backup_plans",
            f"projects/{PROJECT}/locations/-",
        ),
        (
            "backup and dr associations",
            CLIENT_PROBES[4][1],
            "list_backup_plan_associations",
            f"projects/{PROJECT}/locations/-",
        ),
    ],
)
def test_the_request_is_the_collectors_own_limited_to_one_result(
    monkeypatch, label, target, method, parent
):
    _, call = install(monkeypatch, target, method, items=[1])
    API[label].probe(CTX)
    request = call.call_args.kwargs["request"]
    assert request.parent == parent and request.page_size == 1


@pytest.mark.parametrize("label, target", AGGREGATED)
def test_an_aggregated_list_makes_one_request_and_says_nothing_about_what_it_held(
    monkeypatch, label, target
):
    constructor, call = install(monkeypatch, target, "aggregated_list")
    pager = MagicMock()
    pager.pages = iter([object()])
    call.return_value = pager
    assert API[label].probe(CTX) is None
    request = call.call_args.kwargs["request"]
    assert request.project == PROJECT and request.max_results == 1


def test_an_aggregated_list_reads_only_the_first_page(monkeypatch):
    def pages():
        yield 1
        raise AssertionError("read past the first page")

    _, call = install(monkeypatch, "google.cloud.compute_v1.InstancesClient", "aggregated_list")
    call.return_value = SimpleNamespace(pages=pages())
    API["compute instances"].probe(CTX)


def test_the_bucket_size_probe_reads_one_page_of_headers_for_this_project(monkeypatch):
    constructor, call = install(monkeypatch, MONITORING_CLIENT, "list_time_series")
    pager = MagicMock()
    pager.pages = iter([object()])
    call.return_value = pager
    # The pager says nothing about whether a bucket was seen: an empty project has no series.
    assert API["cloud monitoring bucket sizes"].probe(CTX) is None
    assert constructor.call_args.kwargs.get("credentials") == "credentials"
    request = call.call_args.kwargs["request"]
    assert request.name == f"projects/{PROJECT}" and request.page_size == 1
    assert "storage/v2/total_bytes" in request.filter and "gcs_bucket" in request.filter
    # Headers only: the probe checks access, it must not pull the data.
    assert request.view.name == "HEADERS"


def test_a_forbidden_bucket_size_read_means_denied_and_names_the_output(monkeypatch):
    install(
        monkeypatch,
        MONITORING_CLIENT,
        "list_time_series",
        error=gexc.PermissionDenied("IAM_PERMISSION_DENIED"),
    )
    result = run_one("cloud monitoring bucket sizes")
    assert (result.status, result.code) == (core.DENIED, "PermissionDenied")
    assert "gce_storage_info" in result.affects


def test_the_bucket_probe_is_for_this_project_and_asks_for_one(monkeypatch):
    constructor, call = install(
        monkeypatch, "google.cloud.storage.Client", "list_buckets", items=[1]
    )
    API["cloud storage buckets"].probe(CTX)
    constructor.assert_called_once_with(project=PROJECT, credentials="credentials")
    call.assert_called_once_with(max_results=1)


def test_the_cloud_sql_and_bigquery_probes_use_the_rest_apis_with_one_result(monkeypatch):
    build, service = install_rest(monkeypatch, {"items": [1], "datasets": [1]})
    assert API["cloud sql instances"].probe(CTX) is True
    assert API["bigquery datasets"].probe(CTX) is True
    assert [c.args for c in build.call_args_list] == [("sqladmin", "v1beta4"), ("bigquery", "v2")]
    assert all(c.kwargs["cache_discovery"] is False for c in build.call_args_list)
    service.instances.return_value.list.assert_called_once_with(project=PROJECT, maxResults=1)
    service.datasets.return_value.list.assert_called_once_with(projectId=PROJECT, maxResults=1)


def test_the_rest_probes_say_no_when_nothing_is_listed(monkeypatch):
    install_rest(monkeypatch, {})
    assert API["cloud sql instances"].probe(CTX) is False
    assert API["bigquery datasets"].probe(CTX) is False


def test_the_bigtable_probe_reads_the_instance_list(monkeypatch):
    client = MagicMock()
    client.return_value.list_instances.return_value = (["instance"], [])
    monkeypatch.setattr("google.cloud.bigtable.Client", client)
    assert API["bigtable instances"].probe(CTX) is True
    client.assert_called_once_with(project=PROJECT, credentials="credentials", admin=True)
    client.return_value.list_instances.return_value = ([], [])
    assert API["bigtable instances"].probe(CTX) is False


# ── what a failure means ──────────────────────────────────────────────────────

DISABLED = "Cloud SQL Admin API has not been used in project 123 before or it is disabled."


@pytest.mark.parametrize(
    "exc, expected",
    [
        (
            gexc.PermissionDenied("IAM_PERMISSION_DENIED on resource"),
            (core.DENIED, "PermissionDenied"),
        ),
        (gexc.Forbidden("caller does not have permission"), (core.DENIED, "PermissionDenied")),
        (gexc.PermissionDenied("SERVICE_DISABLED"), (core.NOT_ENABLED, "ServiceDisabled")),
        (gexc.Forbidden(DISABLED), (core.NOT_ENABLED, "ServiceDisabled")),
        (http_error(403, DISABLED), (core.NOT_ENABLED, "ServiceDisabled")),
        (http_error(403, "The caller does not have access"), (core.DENIED, "PermissionDenied")),
        (gexc.Unauthenticated("bad credentials"), (core.DENIED, "Unauthenticated")),
        (gexc.ResourceExhausted("quota"), (core.ERROR, "TooManyRequests")),
        (gexc.NotFound("no such project"), (core.ERROR, "NotFound")),
        (ImportError("cannot import name x"), (core.ERROR, "SdkMissing")),
        (ValueError("x"), (core.ERROR, "ValueError")),
    ],
)
def test_classification(exc, expected):
    assert preflight.classify(exc) == expected


def test_a_disabled_api_is_not_enabled_and_its_message_is_kept_for_the_fix(all_sdk, monkeypatch):
    message = (
        "403 Cloud Bigtable Admin API has not been used in project cnp-bigquery-dev-1 before or it "
        "is disabled. Enable it by visiting https://console.developers.google.com/apis/api/"
        "bigtableadmin.googleapis.com/overview?project=cnp-bigquery-dev-1 then retry."
    )
    install(
        monkeypatch,
        "google.cloud.spanner_admin_instance_v1.InstanceAdminClient",
        "list_instances",
        error=gexc.PermissionDenied(message),
    )
    (spanner,) = rows(check(), service="spanner instances")
    assert (spanner.status, spanner.outcome) == (core.NOT_ENABLED, core.DROPPED)
    assert "has not been used in project cnp-bigquery-dev-1" in spanner.message
    assert spanner.hint == "" and rows(check(), service="compute instances")[0].message == ""


def test_a_permission_gap_is_denied_not_not_enabled(all_sdk, monkeypatch):
    install(
        monkeypatch,
        "google.cloud.storage.Client",
        "list_buckets",
        error=gexc.PermissionDenied("IAM_PERMISSION_DENIED"),
    )
    (storage,) = rows(check(), service="cloud storage buckets")
    assert storage.status == core.DENIED and storage.hint == ""


def test_the_provider_message_is_never_written_to_the_report(monkeypatch):
    message = f"Permission denied on resource project {OTHER} for user secret-user@example.com"
    install(
        monkeypatch,
        "google.cloud.storage.Client",
        "list_buckets",
        error=gexc.PermissionDenied(message),
    )
    text = core.csv_text(run_one("cloud storage buckets").to_row() for _ in range(1))
    assert OTHER not in text and "secret-user" not in text


# ── the whole check ───────────────────────────────────────────────────────────


def test_a_clean_run_reads_everything_it_was_asked_to(all_sdk):
    checks = check()
    assert {c.status for c in checks} == {core.OK}
    assert {c.service for c in checks} == {api.label for api in preflight.APIS}
    assert all(c.owner == PROJECT and c.scope == PROJECT and c.owner_name == "" for c in checks)


def test_a_denied_service_names_the_files_it_empties(all_sdk, monkeypatch):
    install_rest(monkeypatch, error=http_error(403, "The caller does not have access"))
    (sql,) = rows(check(), service="cloud sql instances")
    assert sql.status == core.DENIED
    assert sql.to_row()["OutputFilesAffected"] == "gce_cloudsql_info"


def test_collectors_left_out_are_listed_as_not_requested_and_not_called(all_sdk, monkeypatch):
    constructor, _ = install(
        monkeypatch, "google.cloud.compute_v1.InstancesClient", "aggregated_list"
    )
    checks = check(selected={"asset"})
    skipped = rows(checks, status=core.SKIPPED)
    assert {c.service for c in skipped} == {
        api.label for api in preflight.APIS if api.collector != "asset"
    }
    assert {c.code for c in skipped} == {"collector not selected"}
    assert rows(checks, service="cloud asset inventory")[0].status == core.OK
    constructor.assert_not_called()


def test_the_check_cannot_stop_a_scan(monkeypatch):
    monkeypatch.setattr(preflight, "_run", lambda *a, **k: 1 / 0)
    assert check() == []


def test_an_sdk_that_cannot_be_used_gives_unchecked_services_not_an_error(monkeypatch):
    monkeypatch.setattr("google.cloud.storage.Client", MagicMock(side_effect=RuntimeError("no")))
    (storage,) = rows(check(selected={"storage"}), service="cloud storage buckets")
    assert (storage.status, storage.code) == (core.ERROR, "RuntimeError")


def test_every_project_gets_its_own_checks_in_order(all_sdk):
    projects = [f"proj-{i}" for i in range(7)]
    result = preflight.run_all(projects, "credentials", ALL, workers=4)
    assert [checks[0].owner for checks in result] == projects
    assert preflight.run_all([], "credentials", ALL) == []


# ── what the terminal shows ───────────────────────────────────────────────────


def test_one_blocked_service_is_one_line_that_lists_its_projects(all_sdk, monkeypatch):
    install(
        monkeypatch,
        "google.cloud.spanner_admin_instance_v1.InstanceAdminClient",
        "list_instances",
        error=gexc.PermissionDenied("SERVICE_DISABLED"),
    )
    checks = [c for p in ("p1", "p2", "p3") for c in preflight.run_access_check(p, "c", ALL)]
    lines = preflight.report_lines(checks, "3 project(s)")
    assert lines[0].startswith("Pre-flight access check for 3 project(s):")
    blocked = [line for line in lines if "spanner instances" in line]
    assert blocked == [
        "  not enabled: spanner instances (p1, p2, p3) -> gce_spanner_info will be empty or partial"
    ]


def test_main_prints_the_summary_and_one_permissions_table_across_projects(monkeypatch, all_sdk):
    out = StringIO()
    monkeypatch.setattr(main, "console", Console(file=out, width=220, force_terminal=False))

    def fake_run_all(projects, credentials, selected, workers):
        return [
            [
                core.Check(
                    p,
                    "",
                    p,
                    "compute instances",
                    core.OK,
                    None,
                    "",
                    (),
                    "",
                    "compute.instances.list",
                ),
                core.Check(
                    p,
                    "",
                    p,
                    "cloud sql instances",
                    core.NOT_ENABLED,
                    None,
                    "ServiceDisabled",
                    ("gce_cloudsql_info",),
                    "",
                    "cloudsql.instances.list",
                    "Cloud SQL Admin API has not been used in project cnp-1 before or it is disabled. "
                    "Enable it by visiting https://console.developers.google.com/apis/api/"
                    "sqladmin.googleapis.com/overview?project=cnp-1 then retry.",
                ),
            ]
            for p in projects
        ]

    monkeypatch.setattr(preflight, "run_all", fake_run_all)
    result = main._run_access_check(["p1", "p2 [x]"], "credentials", ALL, 2)
    text = out.getvalue()
    assert "Pre-flight access check for 2 project(s): 2 of 4 checks readable" in text
    assert text.count("SERVICE") == 1
    # Both projects' errors name cnp-1, which is neither of them: the project the calls are charged
    # to has the API off, so the rows are not checked and the problem is reported once.
    assert "cloudsql.instances.list" in text and "NOT CHECKED" in text
    assert "API NOT ENABLED" not in text
    assert "2 of 2 projects: p1, p2 [x]" in text
    assert "Quota project cnp-1 has sqladmin.googleapis.com disabled; this affects all 2" in text
    assert "Error: Cloud SQL Admin API has not been used in project cnp-1" in text
    assert "Run: gcloud services enable sqladmin.googleapis.com --project cnp-1" in text
    assert "Problems found by the pre-flight check:" not in text
    assert len(result) == 4 and {r["Owner"] for r in result} == {"p1", "p2 [x]"}
    assert {r["Detail"] for r in result if r["Service"] == "cloud sql instances"} == {
        "QuotaProjectServiceDisabled"
    }


def test_a_clean_run_prints_the_table_with_nothing_to_warn_about(monkeypatch):
    out = StringIO()
    monkeypatch.setattr(main, "console", Console(file=out, width=220, force_terminal=False))
    monkeypatch.setattr(
        preflight,
        "run_all",
        lambda projects, *a, **k: [
            [core.Check(p, "", p, "compute disks", core.OK, None, "", (), "", "compute.disks.list")]
            for p in projects
        ],
    )
    main._run_access_check(["p1", "p2"], "credentials", ALL, 2)
    text = out.getvalue()
    assert "all 2 checks readable, nothing blocked" in text and "all 2 projects" in text
    assert "Problems found" not in text


# ── permissions ───────────────────────────────────────────────────────────────


def test_every_probe_has_a_permission_and_the_table_has_no_extras():
    assert {api.label for api in preflight.APIS} == set(preflight.PERMISSIONS)
    assert all("." in api.permission for api in preflight.APIS)


def test_the_rows_carry_the_permission_including_for_collectors_not_selected(all_sdk):
    checks = check(selected={"compute"})
    assert all(c.permission for c in checks)
    (instances,) = rows(checks, service="compute instances")
    assert instances.to_row()["Permission"] == "compute.instances.list"
    (sql,) = rows(checks, service="cloud sql instances")
    assert (sql.status, sql.permission) == (core.SKIPPED, "cloudsql.instances.list")


def test_the_table_across_projects_says_where_a_permission_is_missing(all_sdk, monkeypatch):
    install(
        monkeypatch,
        "google.cloud.spanner_admin_instance_v1.InstanceAdminClient",
        "list_instances",
        error=gexc.PermissionDenied("SERVICE_DISABLED"),
    )
    checks = [c for p in ("p1", "p2", "p3") for c in preflight.run_access_check(p, "c", ALL)]
    lines = preflight.table_lines(checks)
    spanner = next(line for line in lines if line.lstrip().startswith("spanner instances"))
    assert "spanner.instances.list" in spanner and "API NOT ENABLED" in spanner
    assert "3 of 3 projects: p1, p2 +1 more" in spanner and "gce_spanner_info" in spanner
    assert lines[2].lstrip().startswith("spanner instances")
    compute = next(line for line in lines if line.lstrip().startswith("compute instances"))
    assert "granted" in compute and "all 3 projects" in compute


def test_there_is_no_table_for_no_checks():
    assert preflight.table_lines([]) == []


def test_main_prints_nothing_when_no_checks_were_made(monkeypatch):
    monkeypatch.setattr(preflight, "run_all", lambda *a, **k: [[], []])
    assert main._run_access_check(["p1", "p2"], "credentials", ALL, 2) == []


# ── where it lands ────────────────────────────────────────────────────────────


def _rows():
    check_row = core.Check(
        PROJECT,
        "",
        PROJECT,
        "cloud sql instances",
        core.DENIED,
        None,
        "PermissionDenied",
        ("gce_cloudsql_info",),
    )
    return [check_row.to_row()]


def _csv(rows_in, anonymizer=None):
    return list(csv.DictReader(io.StringIO(preflight.csv_for(rows_in, anonymizer))))


def test_the_report_holds_the_rows():
    (row,) = _csv(_rows())
    assert row["Owner"] == PROJECT and row["Scope"] == PROJECT and row["Outcome"] == "dropped"


def test_anonymizing_labels_the_project_in_both_columns_and_leaves_the_input_alone():
    original = _rows()
    (row,) = _csv(original, Anonymizer.from_options())
    assert PROJECT not in (row["Owner"], row["Scope"]) and row["Owner"] == row["Scope"]
    assert original == _rows()


def test_the_report_gets_the_label_the_other_files_use():
    anonymizer = Anonymizer.from_options()
    label = anonymizer.anonymize_row({"Project": PROJECT})["Project"]
    assert _csv(_rows(), anonymizer)[0]["Owner"] == label


def test_a_field_left_out_of_anonymizing_stays_readable_in_the_report():
    (row,) = _csv(_rows(), Anonymizer.from_options("", "Project"))
    assert row["Owner"] == PROJECT


def _zip_with_rows(tmp_path, rows_in, write_csv=True, anonymizer=None):
    projects, regions, per_project = main._run_mock()
    result = main._build_result(projects, regions, per_project, access_check=rows_in)
    out_path = main._write_output(result, tmp_path)
    handler, log_tmp = main._start_run_log()
    return main._finalise_zip(
        out_path, handler, log_tmp, write_csv=write_csv, anonymizer=anonymizer, access_rows=rows_in
    )


def _report_in(zip_path):
    zf = zipfile.ZipFile(zip_path)
    names = [n for n in zf.namelist() if "preflight" in n]
    return names, [zf.read(n).decode("utf-8") for n in names]


def test_the_zip_holds_the_report_beside_the_other_csv_files(tmp_path):
    names, (text,) = _report_in(_zip_with_rows(tmp_path, _rows()))
    assert len(names) == 1 and names[0].startswith("gcp_preflight_check-")
    assert PROJECT in text


def test_no_csv_leaves_the_report_out_with_the_other_csv_files(tmp_path):
    assert _report_in(_zip_with_rows(tmp_path, _rows(), write_csv=False))[0] == []


def test_no_rows_means_no_report_file(tmp_path):
    assert _report_in(_zip_with_rows(tmp_path, []))[0] == []


def test_an_anonymized_zip_labels_the_project_in_the_report(tmp_path):
    _, (text,) = _report_in(_zip_with_rows(tmp_path, _rows(), anonymizer=Anonymizer.from_options()))
    assert PROJECT not in text


def test_the_result_model_carries_the_rows_and_older_json_still_loads():
    projects, regions, per_project = main._run_mock()
    data = main._build_result(projects, regions, per_project).to_json_dict()
    assert data["access_check"] == []
    del data["access_check"]
    assert DiscoveryResult.model_validate(data).access_check == []
    data["access_check"] = _rows()
    assert DiscoveryResult.model_validate(data).access_check == _rows()


def test_the_flag_defaults_to_running_the_check():
    parser = main._build_parser()
    assert parser.parse_args([]).no_preflight is False
    assert parser.parse_args(["--no-preflight"]).no_preflight is True


# ── the real (non-mock) run, with every cloud call stubbed ────────────────────


@pytest.fixture
def real_run(monkeypatch, tmp_path):
    """``main.main()`` on its real path for one project, with nothing leaving the machine."""
    import auth

    mock_projects, _regions, mock_per_project = main._run_mock()
    pid = mock_projects[0]
    monkeypatch.setattr(auth, "get_credentials", lambda: "credentials")
    monkeypatch.setattr(auth, "normalise_regions", lambda regions: regions)
    monkeypatch.setattr(
        auth, "resolve_projects", lambda creds, ids, all_projects=True, **k: list(ids)
    )
    monkeypatch.setattr(auth, "normalise_scope", lambda *a, **k: None)
    monkeypatch.setattr(main, "_collect_project", lambda project, *a, **k: mock_per_project[pid])
    calls = SimpleNamespace(access=[])

    def fake_run_all(projects, credentials, selected, workers):
        calls.access.append((list(projects), set(selected)))
        return [
            [
                core.Check(p, "", p, "compute instances", core.OK, None),
                core.Check(
                    p,
                    "",
                    p,
                    "cloud sql instances",
                    core.NOT_ENABLED,
                    None,
                    "ServiceDisabled",
                    ("gce_cloudsql_info",),
                ),
            ]
            for p in projects
        ]

    monkeypatch.setattr(preflight, "run_all", fake_run_all)

    def run(*flags):
        monkeypatch.setattr(
            sys, "argv", ["main.py", "--projects", pid, "--output", str(tmp_path), *flags]
        )
        main.main()
        return next(tmp_path.glob("gcp_sizing_results_*.zip")), calls, pid

    return run


def test_a_real_run_puts_the_report_in_the_zip(real_run):
    zip_path, calls, pid = real_run()
    names, (text,) = _report_in(zip_path)
    assert len(names) == 1 and names[0].startswith("gcp_preflight_check-")
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert {r["Service"]: r["Outcome"] for r in parsed} == {
        "compute instances": "captured",
        "cloud sql instances": "dropped",
    }
    assert calls.access == [([pid], ALL)]


def test_the_check_is_given_the_collectors_the_run_will_use(real_run):
    _, calls, pid = real_run("--collectors", "asset,compute")
    assert calls.access == [([pid], {"asset", "compute"})]


def test_no_preflight_runs_no_check_and_adds_no_file(real_run):
    zip_path, calls, _ = real_run("--no-preflight")
    assert calls.access == [] and _report_in(zip_path)[0] == []


def test_no_csv_leaves_the_report_out_but_still_runs_the_check(real_run):
    zip_path, calls, _ = real_run("--no-csv")
    assert _report_in(zip_path)[0] == [] and len(calls.access) == 1


def test_an_anonymized_real_run_labels_the_project_in_the_report(real_run):
    zip_path, _, pid = real_run("--anonymize")
    assert pid not in _report_in(zip_path)[1][0]


def test_the_rows_are_in_the_json_of_a_real_run(real_run):
    zip_path, _, _ = real_run()
    zf = zipfile.ZipFile(zip_path)
    data = json.loads(zf.read(next(n for n in zf.namelist() if n.endswith(".json"))))
    assert [r["Service"] for r in data["access_check"]] == [
        "compute instances",
        "cloud sql instances",
    ]


def test_the_rows_are_in_the_streamed_json_too(real_run, monkeypatch):
    monkeypatch.setattr(main, "_STREAMING_THRESHOLD", 0)
    zip_path, _, _ = real_run()
    zf = zipfile.ZipFile(zip_path)
    data = json.loads(zf.read(next(n for n in zf.namelist() if n.endswith(".json"))))
    assert [r["Service"] for r in data["access_check"]] == [
        "compute instances",
        "cloud sql instances",
    ]


# ── the probe table itself ────────────────────────────────────────────────────


def test_every_file_a_probe_names_is_a_real_output_file_or_a_known_effect():
    files = {spec.prefix for spec in csv_export.FILES}
    for api in preflight.APIS:
        for name in api.affects:
            assert name in files or name in preflight.NON_FILE_EFFECTS, (api.label, name)


def test_every_output_file_is_covered_by_a_probe():
    covered = {name for api in preflight.APIS for name in api.affects}
    assert {spec.prefix for spec in csv_export.FILES} - covered == set()


def test_every_core_collector_has_a_probe_and_no_probe_names_an_unknown_collector():
    assert {api.collector for api in preflight.APIS} == set(main._CORE_COLLECTORS)


def test_probe_labels_are_unique():
    labels = [api.label for api in preflight.APIS]
    assert len(labels) == len(set(labels))


def test_the_new_modules_are_packaged():
    text = open("pyproject.toml", encoding="utf-8").read()
    assert '"preflight"' in text and '"preflight_core"' in text


def test_every_permission_name_fits_the_table_without_being_clipped():
    checks = [
        core.Check(
            "p", "", f"proj-{i}", api.label, core.OK, True, "", api.affects, "", api.permission
        )
        for api in preflight.APIS
        for i in range(17)
    ]
    text = "\n".join(preflight.table_lines(checks))
    assert all(api.permission in text for api in preflight.APIS) and "..." not in text

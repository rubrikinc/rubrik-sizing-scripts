"""The Azure run log: a transcript of the screen, a digest of the problems with their fixes."""

from __future__ import annotations

import builtins
import io
import logging
import re
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from io import StringIO
from types import SimpleNamespace
from unittest.mock import MagicMock

import collectors.storage  # noqa: F401  (bind the real warn_once before any test patches it)
import main
import preflight
import pytest
import runlog
import runlog_core as core
from azure.core.exceptions import HttpResponseError
from cloud import DEFAULT_CLOUD
from collectors import utils
from logging_setup import add_log_file
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

GUID = "9d73069d-8df8-4b1b-874d-174ca86f447a"


@pytest.fixture(autouse=True)
def _fresh():
    core.ISSUES.reset()
    utils._warned.clear()
    yield
    core.ISSUES.reset()
    utils._warned.clear()


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
    console.print("[bold green]✓[/bold green] Compute  [cyan]7[/cyan] VMs")
    assert "✓ Compute  7 VMs" in _text(log) and "\x1b" not in _text(log)


def test_a_panel_and_a_table_are_logged_as_the_screen_drew_them(log):
    console = runlog.LoggedConsole(file=StringIO(), width=60, force_terminal=False)
    console.print(Panel("Rubrik Discovery — Azure Edition"))
    table = Table("Project", "Coverage")
    table.add_row("alpha", "0%")
    console.print(table)
    text = _text(log)
    assert "Rubrik Discovery — Azure Edition" in text and "╭" in text
    assert "Project" in text and "alpha" in text and "0%" in text


def test_an_empty_print_is_a_blank_line_in_the_log(log):
    runlog.LoggedConsole(file=StringIO()).print()
    assert _text(log) == "\n"


def test_a_print_that_shows_nothing_is_skipped(log):
    from rich.control import Control

    runlog.LoggedConsole(file=StringIO()).print(Control())
    assert _text(log) == ""


def test_a_spinner_is_on_the_screen_but_not_in_the_log(log):
    console = runlog.LoggedConsole(file=StringIO(), force_terminal=True, width=80)
    with console.status("Working…"):
        console.print("done")
    assert _text(log) == "done\n"


def test_the_console_works_when_no_log_is_open():
    out = StringIO()
    runlog.LoggedConsole(file=out, width=80).print("hello")
    assert "hello" in out.getvalue()


# ── what the log holds ────────────────────────────────────────────────────────


def test_warnings_are_logged_with_the_screen_format_and_info_and_debug_are_not(log):
    logger = logging.getLogger("collectors.storage")
    logger.debug("a debug detail")
    logger.info("an info detail")
    logger.warning("[sub] Used-capacity unavailable")
    text = _text(log)
    assert "a debug detail" not in text and "an info detail" not in text
    assert re.search(
        r"\d\d:\d\d:\d\d WARNING collectors\.storage — \[sub\] Used-capacity unavailable", text
    )


def test_library_debug_noise_never_reaches_the_log_but_library_warnings_do(log):
    logging.getLogger("azure.identity._credentials.chained").debug("credential chain noise")
    logging.getLogger("urllib3.connectionpool").debug("Starting new HTTPS connection")
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").warning(
        "Response status: 403"
    )
    text = _text(log)
    assert "noise" not in text and "Starting new" not in text and "Response status: 403" in text


@pytest.mark.parametrize("typed, shown", [("y", "y"), ("", "(default)"), ("n", "n")])
def test_a_prompt_and_its_answer_are_in_the_log(log, monkeypatch, typed, shown):
    monkeypatch.setattr(builtins, "input", lambda *_: typed)
    main._ask_yes_no("Scan security posture (Microsoft Defender)?")
    assert _text(log).strip() == f"Scan security posture (Microsoft Defender)? [Y/n] {shown}"


def test_the_header_names_the_tool_the_code_and_the_packages(log):
    runlog.start(["--subs", GUID, "--no-cost"])
    head = _text(log).splitlines()
    assert head[0] == "# Run log: Azure sizing tool"
    assert any(line.startswith("# Packages: azure-identity ") for line in head)
    assert any(line == f"# Command line: --subs {GUID} --no-cost" for line in head)


# ── a whole run ───────────────────────────────────────────────────────────────


def _mock_run(tmp_path, monkeypatch, during=lambda: None):
    monkeypatch.setattr("collectors.pricing.fetch_vm_prices", lambda pairs: {})
    # The mock fixtures make a metrics query fail on purpose, which now warns once. That is real
    # behavior but not what these tests are about.
    monkeypatch.setattr("collectors.utils.warn_once", lambda *a, **k: None)
    monkeypatch.setattr("collectors.storage.warn_once", lambda *a, **k: None)
    original = main._run_mock

    def wrapped(skips):
        during()
        return original(skips)

    monkeypatch.setattr(main, "_run_mock", wrapped)
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path)])
    main.main()
    zf = zipfile.ZipFile(next(tmp_path.glob("azure_sizing_results_*.zip")))
    return zf.read(
        next(n for n in zf.namelist() if n.startswith("output_azure_") and n.endswith(".log"))
    ).decode()


def test_a_run_leaves_a_transcript_with_the_header_the_screen_and_a_summary(tmp_path, monkeypatch):
    text = _mock_run(tmp_path, monkeypatch)
    lines = text.splitlines()
    assert lines[0] == "# Run log: Azure sizing tool"
    assert "Rubrik Discovery — Azure Edition" in text and "Running with mock fixture data" in text
    assert lines[-3:-1] == ["Run summary", "No warnings or errors were recorded."]
    assert lines[-1].startswith("Run ended: scan finished at ")
    assert " DEBUG " not in text and len(lines) < 200


def test_a_problem_is_reported_once_with_its_count_and_what_to_do(tmp_path, monkeypatch):
    def failures():
        for n in range(249):
            logging.getLogger("collectors.storage").warning(
                "[%s] UsedCapacity(P1D) unavailable for /subscriptions/%s/resourceGroups/rg%d/providers/"
                "Microsoft.Storage/storageAccounts/acct%d: (AuthorizationFailed) does not have authorization",
                GUID,
                GUID,
                n,
                n,
            )

    text = _mock_run(tmp_path, monkeypatch, during=failures)
    summary = text.split("Run summary", 1)[1]
    assert "1 distinct problem (249 warnings and errors in all):" in summary
    assert "249x" in summary and "Fix: The identity lacks permission on this scope." in summary
    assert "(docs/troubleshooting.md#az-authorization-failed)" in summary


# ── the pre-flight problems ───────────────────────────────────────────────────


def test_a_blocked_service_shows_the_error_and_the_fix_in_the_log_and_the_digest(log, monkeypatch):
    from preflight_core import Check, DENIED

    check = Check(
        GUID,
        "Sub",
        "subscription",
        "storage metrics (capacity)",
        DENIED,
        None,
        "MetricsDenied",
        ("azure_storage_account_info",),
        "",
        "Microsoft.Insights/Metrics/Read",
        "Metrics read denied",
    )
    monkeypatch.setattr(preflight, "run_all", lambda *a, **k: [[check]])
    monkeypatch.setattr(main, "console", runlog.LoggedConsole(file=StringIO(), width=200))
    main._run_access_check([GUID], {GUID: "Sub"}, "cred", None, DEFAULT_CLOUD, {}, frozenset(), 1)
    text = _text(log)
    assert "Problems found by the pre-flight check:" in text
    assert "storage metrics (capacity) (subscription): MetricsDenied" in text
    assert "Error: Metrics read denied" in text
    assert "Fix: The identity cannot read Azure Monitor metrics." in text
    assert any("storage metrics" in g["examples"][0] for g in core.ISSUES.groups())


# ── what to do about each error ───────────────────────────────────────────────

REAL_MESSAGES = [
    (
        "Subscription 9d73069d is not accessible: (AuthorizationFailed) The client 'a@b.com' with object id "
        "'646f' does not have authorization to perform action 'Microsoft.Resources/subscriptions/read' over "
        "scope '/subscriptions/9d73069d' or the scope is invalid.",
        "az-authorization-failed",
    ),
    (
        "(BadRequest) Detected invalid time interval input: 2026-10-11T07:43:08.151577 00:00/2026-10-14T07:43:08.151577 "
        "00:00, supported Iso 8601 time interval format: (Datetime/Datetime, Datetime/Duration, Duration/Datetime, Duration)",
        "az-metrics-time-interval",
    ),
    ("storage metrics (capacity) | MetricsDenied | Metrics read denied", "az-metrics-denied"),
    (
        "(MissingSubscriptionRegistration) The subscription is not registered to use namespace 'Microsoft.Insights'",
        "az-provider-not-registered",
    ),
    ("(TooManyRequests) Too many requests; retry after 30s", "az-throttled"),
    ("Please run 'az login' to set up an account.", "az-not-signed-in"),
    (
        "DefaultAzureCredential failed to retrieve a token from the included credentials",
        "az-not-signed-in",
    ),
    ("No accessible subscriptions found.", "az-no-subscriptions"),
    ("microsoft defender | azure-mgmt-security is not installed", "az-optional-package-missing"),
    (
        "VM pricing: found 0 of 9 SKUs; 9 price request(s) failed (first error: URLError: <urlopen error timed out>)",
        "az-pricing-unreachable",
    ),
    (
        "VM pricing: found 0 of 4 SKUs; 0 price request(s) failed (the prices service answered but "
        "had nothing for these SKUs and regions)",
        "az-pricing-no-match",
    ),
    (
        "Could not read the tenant of subscription 11111111-2222-3333-4444-555555555555: 403 "
        "Forbidden. The Tenant column is left blank (the SQL files show 'unknown').",
        "az-tenant-lookup-failed",
    ),
    (
        "Could not read the display name of tenant aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee: 401 "
        "Unauthorized. The Tenant column is left blank.",
        "az-tenant-lookup-failed",
    ),
    (
        "[11111111-2222-3333-4444-555555555555] Long-term retention policy could not be read for 3 "
        "database(s); their LTR columns are blank (first error: forbidden)",
        "az-ltr-unreadable",
    ),
    ("backup vaults | azure-mgmt-dataprotection is not installed", "az-optional-package-missing"),
    (
        "[11111111-2222-3333-4444-555555555555] Unable to collect Azure Backup Vault information: "
        "azure-mgmt-dataprotection is not installed",
        "az-optional-package-missing",
    ),
    (
        "Could not acquire Azure DevOps token \u2014 identity may not have DevOps access. Skipping "
        "DevOps discovery. (AzureCliCredential: Please run 'az login' to set up an account)",
        "az-devops",
    ),
    (
        "Azure DevOps: 401 Unauthorized for https://app.vssps.visualstudio.com/_apis/profile/profiles/me",
        "az-devops",
    ),
    ("Could not fetch Azure DevOps profile \u2014 skipping org discovery.", "az-devops"),
    (
        "[11111111-2222-3333-4444-555555555555] Cost Management 403 (permission denied): "
        "(RBACAccessDenied) The client 'a@b.com' does not have authorization to perform action "
        "'Microsoft.CostManagement/query/action'",
        "az-cost-management",
    ),
    (
        "[11111111-2222-3333-4444-555555555555] Cost Management 404 (provider not registered?): "
        "Not found",
        "az-cost-management",
    ),
    (
        "[11111111-2222-3333-4444-555555555555] Cost data requested but none returned",
        "az-cost-management",
    ),
    (
        "[11111111-2222-3333-4444-555555555555] Cost Management still throttled after 4 attempts",
        "az-throttled",
    ),
    (
        "[11111111-2222-3333-4444-555555555555] Unable to collect Azure Backup Vault information: "
        "(AuthorizationFailed) The client does not have authorization to perform action",
        "az-authorization-failed",
    ),
    (
        "[11111111-2222-3333-4444-555555555555] Unable to collect Azure Backup Vault information: "
        "(MissingSubscriptionRegistration) The subscription is not registered to use namespace "
        "'Microsoft.DataProtection'",
        "az-provider-not-registered",
    ),
    (
        "[11111111-2222-3333-4444-555555555555] Failed to get Azure Backup Vault policies for vault "
        "v1 in rg1: Connection reset. The policy list is incomplete",
        "az-backup-vaults-unlisted",
    ),
    (
        "[11111111-2222-3333-4444-555555555555] Used-capacity unavailable for ALL 4 storage "
        "account(s): every Azure Monitor metrics query failed, so storage capacity will be blank "
        "in the report and Explorer. Most common cause (4x ServiceRequestError: timed out)",
        "az-storage-capacity-blank",
    ),
    ("Unrecognised Azure cloud 'usgovt' from --cloud \u2014 ignoring", "az-government-cloud"),
    (
        "[11111111-2222-3333-4444-555555555555] subscription scan failed: KeyError: 'id'",
        "az-subscription-failed",
    ),
]


@pytest.mark.parametrize("message, expected", REAL_MESSAGES)
def test_each_kind_of_error_gets_its_fix(message, expected):
    found = core.solve(message)
    assert found is not None and found[0] == expected, message


@pytest.mark.parametrize(
    "message",
    [
        "[s] Cost Management 429 (throttled): Too many requests",
        "[s] Cost Management query failed (HTTP 429): Too many requests",
    ],
)
def test_a_throttled_cost_query_gets_the_throttle_fix_not_the_cost_permission_one(message):
    assert core.solve(message)[0] == "az-throttled"


def test_blank_capacity_gets_the_fix_of_its_cause_when_the_cause_has_one():
    message = (
        "[s] Used-capacity unavailable for ALL 4 storage account(s): every Azure Monitor metrics "
        "query failed. Most common cause (4x HttpResponseError: (MetricsDenied) denied)"
    )
    assert core.solve(message)[0] == "az-metrics-denied"


def test_a_failed_subscription_gets_the_fix_of_the_error_inside_it():
    message = (
        "[s] subscription scan failed: (AuthorizationFailed) The client does not have "
        "authorization to perform action"
    )
    assert core.solve(message)[0] == "az-authorization-failed"


def test_the_same_failure_on_every_storage_account_is_one_problem():
    a = core.normalize(
        f"[{GUID}] UsedCapacity(P1D) unavailable for /subscriptions/{GUID}/resourceGroups/a/providers/x/storageAccounts/one: (BadRequest) x at 2026-10-14T07:43:08Z"
    )
    b = core.normalize(
        "[11111111-1111-1111-1111-111111111111] UsedCapacity(P1D) unavailable for /subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/b/providers/x/storageAccounts/two: (BadRequest) x at 2026-10-13T01:00:00Z"
    )
    assert a == b


def test_every_fix_has_a_unique_id_and_says_what_to_do():
    ids = [s.id for s in runlog.SOLUTIONS]
    assert len(ids) == len(set(ids)) and all(i.startswith("az-") for i in ids)
    assert all(len(s.fix) > 40 for s in runlog.SOLUTIONS)


# ── the bug: Azure Monitor rejected every time interval ───────────────────────

Z_FORM = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")


def test_the_time_interval_is_two_utc_instants_ending_in_z():
    end = datetime(2026, 10, 14, 7, 43, 8, 151577, tzinfo=timezone.utc)
    span = utils.metric_timespan(end - timedelta(days=1), end)
    assert span == "2026-10-13T07:43:08Z/2026-10-14T07:43:08Z"
    assert "+" not in span and "." not in span


def test_an_instant_in_another_zone_is_converted_to_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    start = datetime(2026, 10, 14, 13, 13, 8, tzinfo=ist)
    end = datetime(2026, 10, 14, 13, 43, 8, tzinfo=ist)
    assert utils.metric_timespan(start, end) == "2026-10-14T07:43:08Z/2026-10-14T08:13:08Z"


def test_no_metrics_query_builds_its_interval_from_isoformat_any_more():
    import pathlib

    offenders = []
    for path in pathlib.Path("collectors").glob("*.py"):
        if path.name == "backup_jobs.py":
            continue  # an OData filter for another API, not a metrics interval
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "timespan" in line and ".isoformat()" in line:
                offenders.append(f"{path}:{number}")
    assert offenders == []


def test_a_storage_collection_sends_azure_monitor_the_accepted_form_in_every_query():
    from tests.test_storage import _make_collector

    collector = _make_collector()
    collector.collect()
    spans = [
        call.kwargs["timespan"] for call in collector._test_monitor.metrics.list.call_args_list
    ]
    assert spans and all(Z_FORM.match(span) for span in spans), spans[:2]


def test_the_latest_maximum_helper_sends_the_accepted_form():
    monitor = MagicMock()
    monitor.metrics.list.return_value = SimpleNamespace(value=[])
    utils.latest_maximum(monitor, "/subscriptions/s/x", "Metric")
    assert Z_FORM.match(monitor.metrics.list.call_args.kwargs["timespan"])


def test_a_failure_on_every_account_names_its_cause_on_the_screen(caplog):
    from tests.test_storage import _make_collector

    def rejected(*_a, **_k):
        raise HttpResponseError(
            "(BadRequest) Detected invalid time interval input: 2026-10-11T07:43:08.151577 00:00/x"
        )

    with caplog.at_level("WARNING", logger="collectors.storage"):
        inventory = _make_collector(metrics_effect=rejected).collect()
    assert inventory.capacity_available is False
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    aggregate = next(m for m in warnings if "Used-capacity unavailable for ALL" in m)
    assert (
        "Most common cause (" in aggregate
        and "(BadRequest) Detected invalid time interval" in aggregate
    )
    assert (
        "Re-run with --verbose" not in aggregate
        and "Likely the discovery identity" not in aggregate
    )
    assert sum("the same failure is not repeated" in m for m in warnings) == 1


def test_a_failure_with_no_error_says_the_metric_had_no_data():
    from collectors.storage import StorageCollector

    collector = StorageCollector.__new__(StorageCollector)
    collector._metric_failures = []
    assert "no error was returned" in collector._top_metric_failure()


def test_the_cause_counts_failures_that_differ_only_in_digits():
    from collectors.storage import StorageCollector

    collector = StorageCollector.__new__(StorageCollector)
    collector._sub_id = "s"
    collector._metric_failures = [
        f"HttpResponseError: (BadRequest) at 07:43:{n:02d}" for n in range(10)
    ] + ["ValueError: odd"]
    assert collector._top_metric_failure().startswith(
        "10 of 11 failed queries: HttpResponseError: (BadRequest) at 07:43:"
    )


def test_the_same_failure_in_other_helpers_is_warned_about_once(caplog):
    with caplog.at_level("WARNING", logger="collectors.utils"):
        for n in range(5):
            utils.warn_once("metric failed at 07:43:%02d: boom", n)
        utils.warn_once("a different failure")
    assert [r.getMessage() for r in caplog.records].count("a different failure") == 1
    assert sum("metric failed" in r.getMessage() for r in caplog.records) == 1


def test_a_failing_helper_query_warns_with_the_cause(caplog):
    monitor = MagicMock()
    monitor.metrics.list.side_effect = HttpResponseError("(BadRequest) nope")
    with caplog.at_level("WARNING", logger="collectors.utils"):
        assert utils.latest_maximum(monitor, "/subscriptions/s/x", "Metric") is None
    assert any(
        "Azure Monitor metric query failed" in r.getMessage() and "BadRequest" in r.getMessage()
        for r in caplog.records
    )


# ── the bug: "no SKUs found" without a reason ─────────────────────────────────


def test_a_pricing_lookup_that_cannot_reach_the_service_says_why(monkeypatch, caplog):
    from collectors import pricing
    from urllib.error import URLError

    def unreachable(*_a, **_k):
        raise URLError("timed out")

    monkeypatch.setattr(pricing, "urlopen", unreachable)
    with caplog.at_level("WARNING", logger="collectors.pricing"):
        assert (
            pricing.fetch_vm_prices([("standard_d2s_v3", "eastus")], _delay_between_calls=0) == {}
        )
    message = next(r.getMessage() for r in caplog.records if r.levelname == "WARNING")
    assert (
        "found 0 of 1 SKUs" in message
        and "1 price request(s) failed" in message
        and "URLError" in message
    )


def test_a_pricing_lookup_the_service_answered_but_found_nothing_says_so(monkeypatch, caplog):
    from collectors import pricing

    monkeypatch.setattr(pricing, "_get_all_pages", lambda *a, **k: [])
    with caplog.at_level("WARNING", logger="collectors.pricing"):
        pricing.fetch_vm_prices([("standard_d2s_v3", "eastus")], _delay_between_calls=0)
    assert any("had nothing for these SKUs and regions" in r.getMessage() for r in caplog.records)


def test_a_pricing_lookup_that_found_prices_does_not_warn(monkeypatch, caplog):
    from collectors import pricing

    price = pricing.VmPriceInfo("standard_d2s_v3", "eastus", 0.1, 0.2)
    monkeypatch.setattr(pricing, "_fetch_one", lambda *a, **k: price)
    with caplog.at_level("WARNING", logger="collectors.pricing"):
        assert pricing.fetch_vm_prices([("standard_d2s_v3", "eastus")], _delay_between_calls=0)
    assert not [r for r in caplog.records if r.levelname == "WARNING"]


def test_the_new_modules_are_packaged():
    text = open("pyproject.toml", encoding="utf-8").read()
    assert '"runlog"' in text and '"runlog_core"' in text

"""Projects with services switched off (API or billing): not queried, not reported as incomplete.

Background: a customer scanned 305 service projects that had almost nothing enabled. A project where
the Compute API is off holds nothing to size, so the scan should skip those calls and say so, not
make them, fail, and count the project as an incomplete scan.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import main
import preflight
import preflight_core as core
from collectors.utils import classify_error
from rich.console import Console

NOT_ENABLED = core.STATUS_TEXT[core.NOT_ENABLED]
READABLE = core.STATUS_TEXT[core.OK]
DENIED = core.STATUS_TEXT[core.DENIED]

BILLING_MESSAGES = [
    "403 Compute Engine API has not been enabled because billing must be enabled for project p",
    "Project 'p' requires billing to be enabled",
    "BILLING_DISABLED: This API method requires billing to be enabled.",
    "Absent billing account for project p",
]


def _row(project, service, access):
    return {"Owner": project, "Service": service, "Access": access}


def _all_services(project, access):
    return [_row(project, api.label, access) for api in preflight.APIS]


# ── billing-off errors get their own category ───────────────────────────────


def test_billing_disabled_messages_are_classified():
    for message in BILLING_MESSAGES:
        assert classify_error(Exception(message)) == "BILLING_DISABLED", message


def test_billing_disabled_is_reported_as_not_enabled_with_its_own_code():
    exc = Exception(BILLING_MESSAGES[1])
    assert preflight.classify(exc) == (core.NOT_ENABLED, "BillingDisabled")


def test_api_disabled_and_permission_denied_are_unchanged():
    assert classify_error(Exception("API has not been used in project p or it is disabled")) == (
        "API_DISABLED"
    )
    assert classify_error(Exception("403 Request denied by Cloud IAM")) == "PERMISSION_DENIED"


# ── which collectors count as switched off ──────────────────────────────────


def test_a_project_with_every_service_off_has_every_collector_switched_off():
    off = preflight.switched_off_collectors(_all_services("empty", NOT_ENABLED))
    assert off == {"empty": {api.collector for api in preflight.APIS}}


def test_a_collector_is_off_only_when_all_of_its_services_are_off():
    rows = _all_services("p", READABLE)
    for row in rows:
        if row["Service"] == "compute instances":
            row["Access"] = NOT_ENABLED  # compute disks stays readable
    assert preflight.switched_off_collectors(rows) == {}


def test_a_denied_or_unchecked_service_is_never_treated_as_off():
    rows = _all_services("p", NOT_ENABLED)
    for row in rows:
        if row["Service"] == "spanner instances":
            row["Access"] = DENIED
    off = preflight.switched_off_collectors(rows)
    # database has a denied member, so it still runs; the other collectors are off
    assert "database" not in off["p"] and "compute" in off["p"]


def test_projects_are_judged_separately():
    rows = _all_services("empty", NOT_ENABLED) + _all_services("busy", READABLE)
    off = preflight.switched_off_collectors(rows)
    assert "empty" in off and "busy" not in off


def test_no_rows_means_nothing_is_skipped():
    assert preflight.switched_off_collectors([]) == {}


# ── the scan honours it ─────────────────────────────────────────────────────


def test_collect_project_does_not_call_a_switched_off_collector(mock_credentials):
    with (
        patch("collectors.asset.AssetCollector") as asset_cls,
        patch("collectors.compute.ComputeCollector") as compute_cls,
        patch("collectors.storage.StorageCollector") as storage_cls,
        patch("collectors.database.DatabaseCollector") as db_cls,
        patch("collectors.bigquery.BigQueryCollector") as bq_cls,
        patch("collectors.backup.BackupCollector") as backup_cls,
    ):
        asset_cls.return_value.collect.return_value = MagicMock(total_assets=0, assets_by_type={})
        asset_cls.return_value.errors = []
        main._collect_project(
            "p",
            mock_credentials,
            None,
            selected=set(main._CORE_COLLECTORS),
            switched_off={"compute", "database", "bigquery", "backup"},
        )
    asset_cls.assert_called_once()
    storage_cls.assert_called_once()
    for cls in (compute_cls, db_cls, bq_cls, backup_cls):
        cls.assert_not_called()


def test_a_switched_off_project_gives_no_errors_so_it_is_not_incomplete(mock_credentials):
    everything = set(main._CORE_COLLECTORS)
    result = main._collect_project(
        "p", mock_credentials, None, selected=everything, switched_off=everything
    )
    assert result == {}
    assert main._summarise_project("p", result)["incomplete"] is False


def test_without_a_pre_flight_result_nothing_is_skipped(mock_credentials):
    with patch("collectors.compute.ComputeCollector") as compute_cls:
        compute_cls.return_value.collect.return_value = MagicMock(total_instances=0)
        compute_cls.return_value.errors = []
        main._collect_project("p", mock_credentials, None, selected={"compute"})
    compute_cls.assert_called_once()


def test_an_all_off_project_line_says_why_and_is_not_a_red_failure(monkeypatch):
    console = Console(record=True, width=120)
    monkeypatch.setattr(main, "console", console)
    main._print_project_line("empty-proj", {}, 1, 2, {"compute", "database"})
    text = console.export_text()
    assert "nothing enabled to read" in text and "collection failed" not in text


def test_an_empty_result_without_a_reason_is_still_a_failure(monkeypatch):
    console = Console(record=True, width=120)
    monkeypatch.setattr(main, "console", console)
    main._print_project_line("broken", {}, 1, 2, None)
    assert "collection failed" in console.export_text()

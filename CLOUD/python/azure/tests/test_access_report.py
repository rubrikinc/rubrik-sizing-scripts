"""What a run of several subscriptions says about each one it could not scan, and --preflight-only.

A subscription named with --subs that cannot be read, and one whose scan stopped, keep rows in
the pre-flight CSV and are named at the end. --preflight-only checks access and collects nothing.
"""

from __future__ import annotations

import csv
import io
import sys
import zipfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import auth
import main
import preflight
import pytest
import runlog_core
from collectors.utils import _warned as warn_once_memory
from azure.core.exceptions import HttpResponseError, ServiceRequestError
from tests.test_preflight import SUB, real_run  # noqa: F401


@pytest.fixture(autouse=True)
def _fresh_digest():
    """The run summary and the warn-once memory are per process: these tests run real main() calls,
    so each starts and ends clean and cannot hide a warning from a later test."""
    runlog_core.ISSUES.reset()
    warn_once_memory.clear()
    yield
    runlog_core.ISSUES.reset()
    warn_once_memory.clear()


BAD = "22222222-2222-2222-2222-222222222222"
SUB2 = "33333333-3333-3333-3333-333333333333"


def _http_error(code, status):
    exc = HttpResponseError(message=f"({code}) The subscription could not be read.")
    exc.status_code = status
    exc.error = SimpleNamespace(code=code)
    return exc


def _zip_file(zip_path, prefix):
    zf = zipfile.ZipFile(zip_path)
    (name,) = [n for n in zf.namelist() if n.startswith(prefix)]
    return zf.read(name).decode("utf-8")


def _rows(zip_path):
    return list(csv.DictReader(io.StringIO(_zip_file(zip_path, "azure_preflight_check-"))))


def _unreadable(*bad_ids, code="SubscriptionNotFound", status=404, readable=(SUB,)):
    def resolve(credential, sub_ids, all_subs, cloud=None, skipped=None):
        if skipped is not None:
            skipped.extend((bad, _http_error(code, status)) for bad in bad_ids)
        return list(readable)

    return resolve


def _run_main(monkeypatch, tmp_path, *flags):
    argv = ["main.py", "--output", str(tmp_path), "--no-devops", "--subs", f"{SUB},{BAD}", *flags]
    monkeypatch.setattr(sys, "argv", argv)
    main.main()


# ── subscriptions that are not scanned stay in the report ─────────────────────


def test_a_subscription_named_with_subs_that_cannot_be_read_has_a_row_and_is_named(
    real_run, monkeypatch
):
    monkeypatch.setattr(auth, "resolve_subscriptions", _unreadable(BAD))
    zip_path, _ = real_run("--subs", f"{SUB},{BAD}")
    bad = [r for r in _rows(zip_path) if r["Owner"] == BAD]
    assert [
        (r["Service"], r["Scope"], r["Permission"], r["Access"], r["Detail"], r["Outcome"])
        for r in bad
    ] == [
        (
            preflight.SUBSCRIPTION,
            "subscription",
            preflight.SUBSCRIPTION_READ,
            "access denied",
            "SubscriptionNotFound",
            "dropped",
        )
    ]
    assert bad[0]["OutputFilesAffected"] == preflight.EVERY_FILE
    log = _zip_file(zip_path, "output_azure_")
    assert (
        "Not scanned:" in log
        and f"{BAD}  cannot read the subscription: SubscriptionNotFound" in log
    )


def test_a_subscription_whose_scan_fails_keeps_its_access_rows_and_gets_a_scan_row(
    real_run, monkeypatch
):
    good = main._run_mock(frozenset())
    scanned = [(good[0][0], good[1][0], good[2][0], good[3][0], good[4][0], good[5][0]), None]
    monkeypatch.setattr(auth, "resolve_subscriptions", lambda *a, **k: [SUB, SUB2])
    monkeypatch.setattr(main, "_collect_all", lambda *a, **k: (scanned, {1: ValueError("boom")}))
    zip_path, _ = real_run("--subs", f"{SUB},{SUB2}")
    services = sorted(r["Service"] for r in _rows(zip_path) if r["Owner"] == SUB2)
    assert services == sorted(["virtual machines", "sql servers", preflight.SCAN])
    (scan,) = [r for r in _rows(zip_path) if r["Service"] == preflight.SCAN]
    assert (scan["Access"], scan["Detail"]) == ("could not be checked", "ValueError")
    assert f"{SUB2}  scan failed: ValueError" in _zip_file(zip_path, "output_azure_")


def test_a_run_where_everything_was_read_has_no_not_scanned_list(real_run):
    zip_path, _ = real_run()
    assert "Not scanned:" not in _zip_file(zip_path, "output_azure_")
    assert {r["Service"] for r in _rows(zip_path)} == {"virtual machines", "sql servers"}


# ── --preflight-only ──────────────────────────────────────────────────────────


def test_preflight_only_writes_only_the_access_report_and_collects_nothing(
    real_run, monkeypatch, tmp_path
):
    monkeypatch.setattr(auth, "resolve_subscriptions", _unreadable(BAD))
    monkeypatch.setattr(main, "_collect_all", lambda *a, **k: pytest.fail("nothing is collected"))
    _run_main(monkeypatch, tmp_path, "--preflight-only")
    assert not list(tmp_path.glob("azure_sizing_results_*.zip"))
    (zip_path,) = tmp_path.glob("azure_access_check_*.zip")
    names = sorted(zipfile.ZipFile(zip_path).namelist())
    assert len(names) == 3 and names[0].startswith("azure_preflight_check-")
    assert names[1] == "manifest.json" and names[2].startswith("output_azure_")
    owners = {(r["Owner"], r["Service"]) for r in _rows(zip_path)}
    assert (BAD, preflight.SUBSCRIPTION) in owners and (SUB, "virtual machines") in owners
    log = _zip_file(zip_path, "output_azure_")
    assert "Not checked:" in log and "Access check complete:" in log
    assert "Run ended: scan finished" in log
    assert sorted(p.name for p in tmp_path.iterdir()) == [zip_path.name]  # the loose log is gone


def test_an_anonymized_preflight_only_run_labels_every_row_and_keeps_the_key_file_outside(
    real_run, monkeypatch, tmp_path
):
    monkeypatch.setattr(auth, "resolve_subscriptions", _unreadable(BAD))
    _run_main(monkeypatch, tmp_path, "--preflight-only", "--anonymize")
    (zip_path,) = tmp_path.glob("azure_access_check_*.zip")
    owners = {r["Owner"] for r in _rows(zip_path)}
    assert SUB not in owners and BAD not in owners
    assert list(tmp_path.glob("azure_anonymized_keys_to_actual_values-*.csv"))
    assert list(tmp_path.glob("output_azure_not_anonymized_*.log"))
    assert BAD not in _zip_file(zip_path, "output_azure_")


@pytest.mark.parametrize(
    "flags, message",
    [
        (["--no-preflight"], "cannot skip it"),
        (["--no-csv"], "--no-csv"),
        (["--dry-run"], "--dry-run"),
        (["--mock"], "--mock"),
    ],
)
def test_preflight_only_refuses_options_that_contradict_it(monkeypatch, capsys, flags, message):
    monkeypatch.setattr(sys, "argv", ["main.py", "--preflight-only", *flags])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 2 and message in capsys.readouterr().err


# ── the rows themselves ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "exc, access, code",
    [
        (_http_error("AuthorizationFailed", 403), "access denied", "AuthorizationFailed"),
        (_http_error("SubscriptionNotFound", 404), "access denied", "SubscriptionNotFound"),
        (_http_error("InvalidSubscriptionId", 400), "access denied", "InvalidSubscriptionId"),
        (ServiceRequestError("timed out"), "could not be checked", "ServiceRequestError"),
    ],
)
def test_an_unreadable_subscription_is_classified_by_the_azure_error(exc, access, code):
    row = preflight.unreadable_check(BAD, exc).to_row()
    assert (row["Access"], row["Detail"], row["Permission"]) == (
        access,
        code,
        preflight.SUBSCRIPTION_READ,
    )
    assert "could not be read" not in str(row)  # the message stays out of the CSV


def test_resolve_subscriptions_reports_each_id_it_could_not_read():
    client = MagicMock()
    sub = MagicMock(subscription_id=SUB)
    failure = _http_error("AuthorizationFailed", 403)
    client.subscriptions.get.side_effect = [failure, sub]
    skipped: list = []
    with patch("auth.SubscriptionClient", return_value=client):
        result = auth.resolve_subscriptions(
            MagicMock(), [BAD, SUB], all_subs=False, skipped=skipped
        )
    assert result == [SUB] and skipped == [(BAD, failure)]


def test_the_not_scanned_list_names_twenty_and_points_to_the_csv(capsys):
    entries = [
        {"id": f"sub-{i:02d}", "name": "", "why": "scan failed: X", "rows": []} for i in range(23)
    ]
    main._print_not_scanned(entries, "Not scanned:")
    out = capsys.readouterr().out
    assert out.count("scan failed: X") == 20 and "3 more" in out and preflight.FILE_PREFIX in out
    main._print_not_scanned([], "Not scanned:")
    assert capsys.readouterr().out == ""


def test_a_scan_row_names_no_other_subscription():
    row = preflight.scan_failed_check(SUB2, "name", RuntimeError(f"failed in {BAD}")).to_row()
    assert BAD not in str(row) and row["Service"] == preflight.SCAN

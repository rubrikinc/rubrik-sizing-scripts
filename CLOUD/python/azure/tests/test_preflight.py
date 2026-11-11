"""The Azure pre-flight access check: what it reports, that it follows the scan, and where it lands."""

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
import main
import preflight
import preflight_core as core
import pytest
from anonymize import Anonymizer
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from cloud import DEFAULT_CLOUD
from models.inventory import DiscoveryResult
from rich.console import Console

SUB = "11111111-1111-1111-1111-111111111111"
OTHER = "99999999-9999-9999-9999-999999999999"
CTX = preflight.Context(SUB, "credential", DEFAULT_CLOUD, None)

COMPUTE = "azure.mgmt.compute.ComputeManagementClient"
RESOURCE = "azure.mgmt.resource.ResourceManagementClient"
SQL = "azure.mgmt.sql.SqlManagementClient"

# label, the client the collector builds, the call it makes first, whether the client takes the
# subscription id
PROBES = [
    ("virtual machines", COMPUTE, "virtual_machines.list_all", True),
    ("managed disks", COMPUTE, "disks.list", True),
    ("disk snapshots", COMPUTE, "snapshots.list", True),
    (
        "storage accounts",
        "azure.mgmt.storage.StorageManagementClient",
        "storage_accounts.list",
        True,
    ),
    ("sql servers", SQL, "servers.list", True),
    ("sql managed instances", SQL, "managed_instances.list", True),
    (
        "postgresql flexible servers",
        "collectors.database.PostgreSQLFlexClient",
        "servers.list",
        True,
    ),
    ("mysql flexible servers", "collectors.database.MySQLFlexClient", "servers.list", True),
    (
        "backup vaults",
        "azure.mgmt.recoveryservices.RecoveryServicesClient",
        "vaults.list_by_subscription_id",
        True,
    ),
    ("cost management", "azure.mgmt.costmanagement.CostManagementClient", "dimensions.list", False),
    ("aks clusters", RESOURCE, "resources.list", True),
    ("cosmos db accounts", RESOURCE, "resources.list", True),
    ("tag names", RESOURCE, "tags.list", True),
]
API = {api.label: api for api in preflight.APIS}


def http_error(status, code=None, message="boom"):
    exc = HttpResponseError(message)
    exc.status_code = status
    exc.error = SimpleNamespace(code=code) if code else None
    return exc


def install(monkeypatch, target, chain, items=(), error=None):
    """Replace one SDK client class; its first call returns ``items`` or raises ``error``."""
    client = MagicMock()
    node = client
    *parents, last = chain.split(".")
    for part in parents:
        node = getattr(node, part)
    method = getattr(node, last)
    if error is not None:
        method.side_effect = error
    else:
        method.return_value = list(items)
    constructor = MagicMock(return_value=client)
    monkeypatch.setattr(target, constructor)
    return constructor, method


@pytest.fixture
def all_sdk(monkeypatch):
    """Every SDK client the probes use, answering with no resources."""
    for _label, target, chain, _sub in PROBES:
        install(monkeypatch, target, chain)
    storage = MagicMock()
    storage.return_value.probe_monitor_access.return_value = "ok"
    monkeypatch.setattr("collectors.storage.StorageCollector", storage)
    install(monkeypatch, "collectors.defender._SecurityCenter", "pricings.list")
    install(monkeypatch, "collectors.purview._PurviewClient", "accounts.list_by_subscription")
    install(
        monkeypatch,
        "collectors.data_protection.DataProtectionMgmtClient",
        "backup_vaults.get_in_subscription",
    )
    monkeypatch.setattr("collectors.defender.HAS_SDK", True)
    monkeypatch.setattr("collectors.purview.HAS_SDK", True)
    monkeypatch.setattr("collectors.data_protection.HAS_SDK", True)
    return storage


def check(scans=None, skips=frozenset(), **kw):
    return preflight.run_access_check(
        SUB, "Sub Name", "credential", DEFAULT_CLOUD, None, scans or {}, frozenset(skips), **kw
    )


def rows(checks, **match):
    return [c for c in checks if all(getattr(c, key) == value for key, value in match.items())]


# ── each probe is the collector's own first call ──────────────────────────────


@pytest.mark.parametrize("label, target, chain, takes_sub", PROBES)
def test_a_probe_uses_the_collectors_client_and_says_whether_it_saw_a_resource(
    monkeypatch, label, target, chain, takes_sub
):
    constructor, _ = install(monkeypatch, target, chain, items=[object()])
    assert API[label].probe(CTX) is True
    expected = ("credential", SUB) if takes_sub else ("credential",)
    constructor.assert_called_with(*expected, **DEFAULT_CLOUD.client_kwargs())
    install(monkeypatch, target, chain, items=[])
    assert API[label].probe(CTX) is False


@pytest.mark.parametrize("label, target, chain, takes_sub", PROBES)
def test_a_forbidden_answer_means_denied(monkeypatch, label, target, chain, takes_sub):
    install(monkeypatch, target, chain, error=http_error(403, "AuthorizationFailed"))
    probe = core.Probe(label, "subscription", lambda: API[label].probe(CTX), API[label].affects)
    (result,) = core.run_probes(SUB, "n", [probe], preflight.classify)
    assert (result.status, result.code) == (core.DENIED, "AuthorizationFailed")
    assert result.outcome == core.DROPPED


def test_only_the_first_page_is_read(monkeypatch):
    def endless():
        yield 1
        raise AssertionError("read past the first item")

    constructor, method = install(monkeypatch, COMPUTE, "virtual_machines.list_all")
    method.return_value = endless()
    assert preflight._vms(CTX) is True


def test_the_aks_and_cosmos_probes_ask_for_their_own_resource_type(monkeypatch):
    _, method = install(monkeypatch, RESOURCE, "resources.list", items=[1])
    API["aks clusters"].probe(CTX)
    API["cosmos db accounts"].probe(CTX)
    filters = [call.kwargs["filter"] for call in method.call_args_list]
    assert filters == [
        "resourceType eq 'Microsoft.ContainerService/managedClusters'",
        "resourceType eq 'Microsoft.DocumentDB/databaseAccounts'",
    ]


def test_the_cost_probe_asks_for_this_subscriptions_scope(monkeypatch):
    _, method = install(
        monkeypatch, "azure.mgmt.costmanagement.CostManagementClient", "dimensions.list", items=[1]
    )
    API["cost management"].probe(CTX)
    method.assert_called_once_with(f"/subscriptions/{SUB}")


@pytest.mark.parametrize(
    "status, expected",
    [
        ("ok", (core.OK, "")),
        ("denied", (core.DENIED, "MetricsDenied")),
        ("no_accounts", (core.SKIPPED, "no storage accounts to test against")),
        ("error", (core.ERROR, "MetricsInconclusive")),
    ],
)
def test_the_storage_metrics_probe_reports_what_the_scans_own_test_found(
    monkeypatch, status, expected
):
    storage = MagicMock()
    storage.return_value.probe_monitor_access.return_value = status
    monkeypatch.setattr("collectors.storage.StorageCollector", storage)
    probe = core.Probe("m", "subscription", lambda: preflight._monitor(CTX))
    (result,) = core.run_probes(SUB, "n", [probe], preflight.classify)
    assert (result.status, result.code) == expected
    storage.assert_called_with(SUB, "credential", None, cloud=DEFAULT_CLOUD, collect_capacity=True)


def test_defender_and_purview_say_so_when_their_sdk_is_missing(monkeypatch):
    monkeypatch.setattr("collectors.defender.HAS_SDK", False)
    monkeypatch.setattr("collectors.purview.HAS_SDK", False)
    for label in ("microsoft defender", "microsoft purview"):
        probe = core.Probe(label, "subscription", lambda label=label: API[label].probe(CTX))
        (result,) = core.run_probes(SUB, "n", [probe], preflight.classify)
        assert result.status == core.SKIPPED and "not installed" in result.code


def test_backup_vaults_say_so_when_their_sdk_is_missing(monkeypatch):
    monkeypatch.setattr("collectors.data_protection.HAS_SDK", False)
    label = "data protection backup vaults"
    probe = core.Probe(label, "subscription", lambda: API[label].probe(CTX))
    (result,) = core.run_probes(SUB, "n", [probe], preflight.classify)
    assert result.status == core.SKIPPED and "azure-mgmt-dataprotection" in result.code


def test_a_missing_backup_vault_sdk_is_the_reason_in_a_full_check(all_sdk, monkeypatch):
    monkeypatch.setattr("collectors.data_protection.HAS_SDK", False)
    (vaults,) = rows(check(), service="data protection backup vaults")
    assert (vaults.status, vaults.code) == (
        core.SKIPPED,
        "azure-mgmt-dataprotection is not installed",
    )


def test_the_backup_vault_probe_follows_skip_backup_and_names_its_files(all_sdk, monkeypatch):
    constructor, _ = install(
        monkeypatch,
        "collectors.data_protection.DataProtectionMgmtClient",
        "backup_vaults.get_in_subscription",
    )
    (skipped,) = rows(check(skips={"backup"}), service="data protection backup vaults")
    assert (skipped.status, skipped.code) == (core.SKIPPED, "skipped by a --skip switch")
    constructor.assert_not_called()
    (vaults,) = rows(check(), service="data protection backup vaults")
    assert vaults.status == core.OK
    assert "azure_backup_data_protection_items" in API["data protection backup vaults"].affects


def test_denied_backup_vaults_are_dropped_and_leave_the_flags_at_not_protected(
    all_sdk, monkeypatch
):
    install(
        monkeypatch,
        "collectors.data_protection.DataProtectionMgmtClient",
        "backup_vaults.get_in_subscription",
        error=http_error(403, "AuthorizationFailed"),
    )
    (vaults,) = rows(check(), service="data protection backup vaults")
    assert (vaults.status, vaults.outcome) == (core.DENIED, core.DROPPED)


# ── what a failure means ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "exc, expected",
    [
        (http_error(403, "AuthorizationFailed"), (core.DENIED, "AuthorizationFailed")),
        (http_error(403), (core.DENIED, "HTTP 403")),
        (http_error(401), (core.DENIED, "HTTP 401")),
        (http_error(400, "AuthorizationFailed"), (core.DENIED, "AuthorizationFailed")),
        (
            http_error(409, "MissingSubscriptionRegistration"),
            (core.NOT_ENABLED, "MissingSubscriptionRegistration"),
        ),
        (http_error(429, "TooManyRequests"), (core.ERROR, "TooManyRequests")),
        (http_error(500, "InternalServerError"), (core.ERROR, "InternalServerError")),
        (http_error(400, "has spaces and a [subscription]"), (core.ERROR, "HTTP 400")),
        (ClientAuthenticationError("expired"), (core.DENIED, "AuthenticationFailed")),
        (ValueError("x"), (core.ERROR, "ValueError")),
    ],
)
def test_classification(exc, expected):
    assert preflight.classify(exc) == expected


def test_the_provider_message_is_never_written_to_the_report(monkeypatch):
    message = f"The client does not have authorization over /subscriptions/{OTHER}/resourceGroups/secret-rg"
    install(
        monkeypatch,
        COMPUTE,
        "virtual_machines.list_all",
        error=http_error(403, "AuthorizationFailed", message),
    )
    checks = check(skips={"storage"})
    text = core.csv_text(c.to_row() for c in checks)
    assert OTHER not in text and "secret-rg" not in text


# ── the whole check ───────────────────────────────────────────────────────────


OPT_IN = {api.label: api.opt_in for api in preflight.APIS if api.opt_in}


def test_a_clean_run_reads_everything_it_was_asked_to(all_sdk):
    checks = check()
    assert {c.status for c in checks if c.service not in OPT_IN} == {core.OK}
    assert {c.service for c in checks} == {api.label for api in preflight.APIS}
    assert all(c.owner == SUB and c.owner_name == "Sub Name" for c in checks)


def test_an_opt_in_check_runs_only_when_its_option_was_given(all_sdk):
    assert set(OPT_IN) == {"blob containers", "key vaults", "key vault contents"}
    for c in check():
        if c.service in OPT_IN:
            assert (c.status, c.code) == (core.SKIPPED, f"not asked for (add {OPT_IN[c.service]})")


def _key_vault_setup(monkeypatch, vaults, error=None):
    install(monkeypatch, RESOURCE, "resources.list", items=vaults)
    certificates = MagicMock()
    if error is not None:
        certificates.return_value.list_properties_of_certificates.side_effect = error
    else:
        certificates.return_value.list_properties_of_certificates.return_value = iter([])
    monkeypatch.setattr("collectors.key_vault.CertificateClient", certificates)
    return certificates


def test_the_key_vault_checks_list_the_vaults_and_read_one_vaults_contents(all_sdk, monkeypatch):
    certificates = _key_vault_setup(monkeypatch, [SimpleNamespace(name="kv1", location="eastus")])
    checks = check({"key_vault": True})
    assert [c.status for c in rows(checks, service="key vaults")] == [core.OK]
    assert [c.status for c in rows(checks, service="key vault contents")] == [core.OK]
    assert certificates.call_args.args[0] == "https://kv1.vault.azure.net/"


def test_a_vault_whose_contents_cannot_be_read_is_denied(all_sdk, monkeypatch):
    _key_vault_setup(
        monkeypatch, [SimpleNamespace(name="kv1", location="eastus")], http_error(403, "Forbidden")
    )
    (contents,) = rows(check({"key_vault": True}), service="key vault contents")
    assert (contents.status, contents.code) == (core.DENIED, "Forbidden")
    assert contents.to_row()["OutputFilesAffected"] == "azure_key_vault"


def test_without_a_vault_the_contents_check_says_there_is_nothing_to_test(all_sdk, monkeypatch):
    _key_vault_setup(monkeypatch, [])
    (contents,) = rows(check({"key_vault": True}), service="key vault contents")
    assert (contents.status, contents.code) == (core.SKIPPED, "no key vaults to test against")


def _blob_setup(monkeypatch, accounts, error=None):
    install(
        monkeypatch, "azure.mgmt.storage.StorageManagementClient", "storage_accounts.list", accounts
    )
    service = MagicMock()
    if error is not None:
        service.return_value.list_containers.side_effect = error
    else:
        service.return_value.list_containers.return_value = iter([SimpleNamespace(name="c1")])
        client = service.return_value.get_container_client.return_value
        client.list_blobs.return_value = iter([SimpleNamespace(name="b", size=1)])
    monkeypatch.setattr("collectors.containers.BlobServiceClient", service)
    return service


def test_the_blob_check_reads_containers_and_blobs_of_a_blob_account(all_sdk, monkeypatch):
    accounts = [
        SimpleNamespace(name="files", kind="FileStorage"),
        SimpleNamespace(name="blobs", kind="StorageV2"),
    ]
    service = _blob_setup(monkeypatch, accounts)
    (blob,) = rows(check({"containers": True}), service="blob containers")
    assert (blob.status, blob.found) == (core.OK, True)
    assert service.call_args.kwargs["account_url"] == "https://blobs.blob.core.windows.net"


def test_a_blob_account_without_a_data_role_is_denied(all_sdk, monkeypatch):
    accounts = [SimpleNamespace(name="blobs", kind="StorageV2")]
    _blob_setup(monkeypatch, accounts, http_error(403, "AuthorizationPermissionMismatch"))
    (blob,) = rows(check({"containers": True}), service="blob containers")
    assert (blob.status, blob.code) == (core.DENIED, "AuthorizationPermissionMismatch")
    assert "Storage Blob Data Reader" in blob.hint


def test_skipping_storage_skips_the_blob_check_too(all_sdk, monkeypatch):
    (blob,) = rows(check({"containers": True}, skips={"storage"}), service="blob containers")
    assert (blob.status, blob.code) == (core.SKIPPED, "skipped by a --skip switch")


def test_a_denied_service_is_dropped_and_names_the_files_it_empties(all_sdk, monkeypatch):
    install(monkeypatch, SQL, "servers.list", error=http_error(403, "AuthorizationFailed"))
    checks = check()
    (sql,) = rows(checks, service="sql servers")
    assert (sql.status, sql.outcome) == (core.DENIED, core.DROPPED)
    assert sql.to_row()["OutputFilesAffected"] == "azure_sql_info"
    assert [c.status for c in rows(checks, service="sql managed instances")] == [core.OK]
    assert rows(checks, service="virtual machines")[0].status == core.OK


def test_a_resource_provider_that_is_not_registered_is_not_enabled(all_sdk, monkeypatch):
    install(
        monkeypatch, RESOURCE, "tags.list", error=http_error(409, "MissingSubscriptionRegistration")
    )
    (tags,) = rows(check(), service="tag names")
    assert tags.status == core.NOT_ENABLED


def test_skipped_collectors_are_listed_as_not_requested_and_not_called(all_sdk, monkeypatch):
    constructor, _ = install(monkeypatch, COMPUTE, "virtual_machines.list_all")
    checks = check(skips={"vms"})
    for label in ("virtual machines", "managed disks", "disk snapshots"):
        (skipped,) = rows(checks, service=label)
        assert (skipped.status, skipped.code) == (core.SKIPPED, "skipped by a --skip switch")
    constructor.assert_not_called()


def test_optional_scans_that_are_off_are_not_called(all_sdk):
    checks = check(scans={"cost": False, "capacity": False, "security": False})
    for label in ("cost management", "storage metrics (capacity)", "microsoft defender"):
        (skipped,) = rows(checks, service=label)
        assert (skipped.status, skipped.code) == (core.SKIPPED, "optional scan is off")
    all_sdk.assert_not_called()


def test_a_missing_defender_sdk_is_the_reason_even_though_the_scan_was_turned_off(
    all_sdk, monkeypatch
):
    monkeypatch.setattr("collectors.defender.HAS_SDK", False)
    (defender,) = rows(check(scans={"security": False}), service="microsoft defender")
    assert (defender.status, defender.code) == (
        core.SKIPPED,
        "azure-mgmt-security is not installed",
    )


def test_with_the_defender_sdk_a_scan_that_is_off_says_so(all_sdk):
    (defender,) = rows(check(scans={"security": False}), service="microsoft defender")
    assert (defender.status, defender.code) == (core.SKIPPED, "optional scan is off")


def test_a_scan_the_user_has_not_decided_runs_like_the_scan_does(all_sdk):
    checks = check(scans={})
    assert rows(checks, service="cost management")[0].status == core.OK


def test_a_subscription_with_no_storage_accounts_is_not_called_unreadable(all_sdk):
    all_sdk.return_value.probe_monitor_access.return_value = "no_accounts"
    (monitor,) = rows(check(), service="storage metrics (capacity)")
    assert monitor.status == core.SKIPPED and monitor.outcome == core.NOT_REQUESTED


def test_the_check_cannot_stop_a_scan(monkeypatch):
    monkeypatch.setattr(preflight, "_run", lambda *a, **k: 1 / 0)
    assert check() == []


def test_a_cloud_that_cannot_make_client_settings_gives_unchecked_services_not_an_error():
    broken = SimpleNamespace(client_kwargs=MagicMock(side_effect=RuntimeError("no")))
    checks = preflight.run_access_check(SUB, "n", "c", broken, None, {}, frozenset())
    assert checks and all(c.status in (core.ERROR, core.SKIPPED) for c in checks)


def test_every_subscription_gets_its_own_checks_in_order(all_sdk):
    subs = [f"sub-{i}" for i in range(7)]
    names = {"sub-3": "Three"}
    result = preflight.run_all(subs, names, "cred", DEFAULT_CLOUD, None, {}, frozenset(), workers=4)
    assert [checks[0].owner for checks in result] == subs
    assert result[3][0].owner_name == "Three" and result[0][0].owner_name == ""
    assert preflight.run_all([], {}, "c", DEFAULT_CLOUD, None, {}, frozenset()) == []


# ── what the terminal shows ───────────────────────────────────────────────────


def test_the_summary_names_the_blocked_service_and_how_to_fix_the_metrics_one(all_sdk):
    all_sdk.return_value.probe_monitor_access.return_value = "denied"
    lines = preflight.report_lines(check(), "Sub Name")
    assert lines[0].startswith("Pre-flight access check for Sub Name:")
    assert any("storage metrics (capacity)" in line for line in lines)
    assert "(subscription)" not in "".join(lines)
    assert any(
        line.strip()
        == "to fix: grant Monitoring Reader (or Reader) at subscription scope, or run with --no-capacity"
        for line in lines
    )


def _canned(sub, name, denied):
    ok = core.Check(
        sub,
        name,
        "subscription",
        "storage accounts",
        core.OK,
        True,
        "",
        (),
        "",
        "Microsoft.Storage/storageAccounts/read",
    )
    if not denied:
        return [ok]
    return [
        ok,
        core.Check(
            sub,
            name,
            "subscription",
            "virtual machines",
            core.DENIED,
            None,
            "AuthorizationFailed",
            ("azure_vmdisk_info",),
            "",
            "Microsoft.Compute/virtualMachines/read",
        ),
    ]


def _print_checks(monkeypatch, subs, denied_for):
    out = StringIO()
    monkeypatch.setattr(main, "console", Console(file=out, width=220, force_terminal=False))
    monkeypatch.setattr(
        preflight,
        "run_access_check",
        lambda sub, name, *a, **k: _canned(sub, name, sub in denied_for),
    )
    names = {s: f"Name {s}" for s in subs}
    result = main._run_access_check(subs, names, "cred", None, DEFAULT_CLOUD, {}, frozenset(), 2)
    return out.getvalue(), result


def test_main_prints_a_summary_and_the_permissions_table_per_subscription(monkeypatch):
    text, result = _print_checks(monkeypatch, ["s1", "s2"], denied_for={"s2"})
    assert "Pre-flight access check for Name s1: all 1 check readable, nothing blocked" in text
    assert "Pre-flight access check for Name s2: 1 of 2 checks readable" in text
    assert "Microsoft.Compute/virtualMachines/read" in text and "MISSING" in text
    assert "azure_vmdisk_info" in text and "Microsoft.Storage/storageAccounts/read" in text
    assert "Problems found by the pre-flight check:" in text
    assert "virtual machines (subscription): AuthorizationFailed" in text
    assert "Fix: The identity lacks permission on this scope." in text
    assert [r["Owner"] for r in result] == ["s1", "s2", "s2"]


def test_a_few_subscriptions_each_get_the_table_even_when_clean(monkeypatch):
    text, _ = _print_checks(monkeypatch, ["s1", "s2", "s3"], denied_for=set())
    assert text.count("SERVICE") == 3 and "Blocked or unchecked" not in text


def test_a_large_run_prints_the_table_only_for_a_subscription_with_something_blocked(monkeypatch):
    subs = [f"s{i}" for i in range(1, 6)]
    text, _ = _print_checks(monkeypatch, subs, denied_for={"s4"})
    assert text.count("SERVICE") == 1 and text.count("Pre-flight access check for") == 5
    assert text.index("Pre-flight access check for Name s4") < text.index("SERVICE")


def test_main_prints_nothing_for_a_subscription_with_no_checks(monkeypatch):
    monkeypatch.setattr(preflight, "run_all", lambda *a, **k: [[], []])
    assert (
        main._run_access_check(["a", "b"], {}, "c", None, DEFAULT_CLOUD, {}, frozenset(), 2) == []
    )


def test_a_name_that_looks_like_markup_is_printed_as_text(monkeypatch):
    out = StringIO()
    monkeypatch.setattr(main, "console", Console(file=out, width=220, force_terminal=False))
    monkeypatch.setattr(
        preflight, "run_all", lambda *a, **k: [_canned("s1", "A [bold]B[/bold]", True)]
    )
    main._run_access_check(
        ["s1"], {"s1": "A [bold]B[/bold]"}, "c", None, DEFAULT_CLOUD, {}, frozenset(), 1
    )
    assert "A [bold]B[/bold]" in out.getvalue()


# ── permissions ───────────────────────────────────────────────────────────────


def test_every_probe_has_a_permission_and_the_table_has_no_extras():
    assert {api.label for api in preflight.APIS} == set(preflight.PERMISSIONS)
    assert all("/" in api.permission for api in preflight.APIS)


def test_the_rows_carry_the_permission_including_for_services_not_requested(all_sdk):
    checks = check(skips={"vms"})
    assert all(c.permission for c in checks)
    (vm,) = rows(checks, service="virtual machines")
    assert (vm.status, vm.permission) == (core.SKIPPED, "Microsoft.Compute/virtualMachines/read")
    (sql,) = rows(checks, service="sql servers")
    assert sql.to_row()["Permission"] == "Microsoft.Sql/servers/read"


def test_the_permissions_table_names_what_is_missing_and_what_it_affects(all_sdk, monkeypatch):
    install(monkeypatch, SQL, "servers.list", error=http_error(403, "AuthorizationFailed"))
    lines = preflight.table_lines(check())
    sql = next(line for line in lines if line.lstrip().startswith("sql servers"))
    assert "Microsoft.Sql/servers/read" in sql and "MISSING" in sql and "azure_sql_info" in sql
    assert lines[2].lstrip().startswith("sql servers")


def test_there_is_no_table_for_no_checks():
    assert preflight.table_lines([]) == []


# ── where it lands ────────────────────────────────────────────────────────────


def _rows():
    return [
        c.to_row()
        for c in [
            core.Check(
                SUB,
                "Sub Name",
                "subscription",
                "tag names",
                core.DENIED,
                None,
                "HTTP 403",
                ("azure_vmdisk_info",),
            )
        ]
    ]


def test_the_report_file_is_named_like_the_other_files_and_holds_the_rows(tmp_path):
    path = main._write_access_report(tmp_path, "2026-10-05_140650", _rows(), None)
    assert path.endswith("azure_preflight_check-2026-10-05_140650.csv")
    parsed = list(csv.DictReader(open(path, encoding="utf-8", newline="")))
    assert parsed[0]["Owner"] == SUB and parsed[0]["Outcome"] == "dropped"


def test_anonymizing_replaces_the_subscription_in_the_report(tmp_path):
    path = main._write_access_report(tmp_path, "s", _rows(), Anonymizer.from_options())
    text = open(path, encoding="utf-8").read()
    assert SUB not in text and "Sub Name" not in text


def test_the_report_gets_the_labels_the_other_files_use():
    anonymizer = Anonymizer.from_options()
    label = anonymizer.anonymize_row({"SubscriptionId": SUB})["SubscriptionId"]
    text = preflight.csv_for(_rows(), anonymizer)
    assert label in text


def test_a_field_left_out_of_anonymizing_stays_readable_in_the_report():
    text = preflight.csv_for(_rows(), Anonymizer.from_options("", "SubscriptionId"))
    assert SUB in text and "Sub Name" not in text


def test_the_input_rows_are_not_changed_by_anonymizing():
    original = _rows()
    preflight.csv_for(original, Anonymizer.from_options())
    assert original == _rows()


def test_the_result_model_carries_the_rows_and_older_json_still_loads(monkeypatch, tmp_path):
    monkeypatch.setattr("collectors.pricing.fetch_vm_prices", lambda pairs: {})
    monkeypatch.setattr(
        sys, "argv", ["main.py", "--mock", "--output", str(tmp_path), "--keep-artifacts"]
    )
    main.main()
    data = json.loads(next(tmp_path.glob("rubrik-discovery-*.json")).read_text())
    assert data["access_check"] == []
    del data["access_check"]
    assert DiscoveryResult.model_validate(data).access_check == []
    data["access_check"] = _rows()
    assert DiscoveryResult.model_validate(data).model_dump()["access_check"] == _rows()


def test_a_mock_run_has_no_credentials_so_it_writes_no_report(monkeypatch, tmp_path):
    monkeypatch.setattr("collectors.pricing.fetch_vm_prices", lambda pairs: {})
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path)])
    main.main()
    zip_path = next(tmp_path.glob("azure_sizing_results_*.zip"))
    assert not [n for n in zipfile.ZipFile(zip_path).namelist() if "preflight" in n]


def test_the_flag_defaults_to_running_the_check():
    parser = main._build_parser()
    assert parser.parse_args([]).no_preflight is False
    assert parser.parse_args(["--no-preflight"]).no_preflight is True


# ── the probe table itself ────────────────────────────────────────────────────

NEEDS_A_RESOURCE_NAME = {"skip": {"files"}, "scan": {"backup_jobs"}}


def test_every_file_a_probe_names_is_a_real_output_file_or_a_known_effect():
    files = {spec.prefix for spec in csv_export.FILES}
    for api in preflight.APIS:
        for name in api.affects:
            assert name in files or name in preflight.NON_FILE_EFFECTS, (api.label, name)


def test_every_output_file_is_covered_by_a_probe():
    covered = {name for api in preflight.APIS for name in api.affects}
    assert {spec.prefix for spec in csv_export.FILES} - covered == set()


def test_every_skip_switch_and_optional_scan_is_covered_or_needs_a_resource_name():
    skips = {api.skip for api in preflight.APIS if api.skip}
    scans = {api.scan for api in preflight.APIS if api.scan}
    assert set(main.SKIP_SWITCHES) - skips == NEEDS_A_RESOURCE_NAME["skip"]
    assert {key for key, _, _ in main._OPTIONAL_SCANS} - scans == NEEDS_A_RESOURCE_NAME["scan"]


def test_probe_labels_are_unique():
    labels = [api.label for api in preflight.APIS]
    assert len(labels) == len(set(labels))


def test_the_new_modules_are_packaged():
    text = open("pyproject.toml", encoding="utf-8").read()
    assert '"preflight"' in text and '"preflight_core"' in text


# ── the real (non-mock) run, with every cloud call stubbed ────────────────────


@pytest.fixture
def real_run(monkeypatch, tmp_path):
    """``main.main()`` on its real path for one subscription, with nothing leaving the machine."""
    import auth
    import cloud as cloud_module
    from collectors.aks_cosmos import AksInventory, CosmosInventory

    comp, bp, stor, db, jobs, cost, _tenant = main._run_mock(frozenset())
    scanned = [(comp[0], bp[0], stor[0], db[0], jobs[0], cost[0])]
    monkeypatch.setattr(auth, "get_credential", lambda cloud: "credential")
    monkeypatch.setattr(auth, "normalise_regions", lambda regions: regions)
    monkeypatch.setattr(auth, "resolve_subscriptions", lambda *a, **k: [SUB])
    monkeypatch.setattr(auth, "resolve_subscription_names", lambda *a, **k: {SUB: "Sub Name"})
    monkeypatch.setattr(auth, "resolve_tenant_id", lambda *a, **k: "tenant-id-1")
    monkeypatch.setattr(auth, "resolve_tenant_name", lambda *a, **k: "Tenant")
    monkeypatch.setattr(cloud_module, "resolve_cloud", lambda name=None: DEFAULT_CLOUD)
    monkeypatch.setattr(main, "_collect_all", lambda *a, **k: (scanned, {}))
    monkeypatch.setattr("collectors.tags.collect_tag_names", lambda *a, **k: [])
    monkeypatch.setattr("collectors.pricing.fetch_vm_prices", lambda pairs: {})
    for name, inventory in (("AksCollector", AksInventory), ("CosmosCollector", CosmosInventory)):
        fake = MagicMock()
        fake.return_value.collect.return_value = inventory(subscription_id=SUB)
        monkeypatch.setattr(f"collectors.aks_cosmos.{name}", fake)
    for module in ("defender", "purview", "site_recovery"):
        monkeypatch.setattr(f"collectors.{module}.HAS_SDK", False)

    calls = SimpleNamespace(monitor=[], access=[])
    monkeypatch.setattr(main, "_preflight_monitor_access", lambda *a, **k: calls.monitor.append(a))

    def fake_run_all(subs, names, *args, **kwargs):
        calls.access.append(subs)
        return [
            [
                core.Check(
                    s,
                    names.get(s, ""),
                    "subscription",
                    "virtual machines",
                    core.OK,
                    True,
                    "",
                    (),
                    "",
                    "Microsoft.Compute/virtualMachines/read",
                ),
                core.Check(
                    s,
                    names.get(s, ""),
                    "subscription",
                    "sql servers",
                    core.DENIED,
                    None,
                    "AuthorizationFailed",
                    ("azure_sql_info",),
                ),
            ]
            for s in subs
        ]

    monkeypatch.setattr(preflight, "run_all", fake_run_all)

    def run(*flags):
        argv = ["main.py", "--output", str(tmp_path), "--no-devops", *flags]
        monkeypatch.setattr(sys, "argv", argv)
        main.main()
        return next(tmp_path.glob("azure_sizing_results_*.zip")), calls

    return run


def _report(zip_path):
    zf = zipfile.ZipFile(zip_path)
    names = [n for n in zf.namelist() if "preflight" in n]
    return names, [list(csv.DictReader(io.StringIO(zf.read(n).decode("utf-8")))) for n in names]


def test_a_real_run_puts_the_report_in_the_zip_and_skips_the_old_monitor_warning(real_run):
    zip_path, calls = real_run()
    names, (rows_in_zip,) = _report(zip_path)
    assert len(names) == 1 and names[0].startswith("azure_preflight_check-")
    assert {r["Service"]: r["Outcome"] for r in rows_in_zip} == {
        "virtual machines": "captured",
        "sql servers": "dropped",
    }
    assert rows_in_zip[1]["OutputFilesAffected"] == "azure_sql_info"
    assert rows_in_zip[0]["Permission"] == "Microsoft.Compute/virtualMachines/read"
    assert calls.access == [[SUB]] and calls.monitor == []


def test_no_preflight_runs_neither_the_check_nor_adds_a_file_and_keeps_the_old_warning(real_run):
    zip_path, calls = real_run("--no-preflight")
    assert _report(zip_path)[0] == []
    assert calls.access == [] and len(calls.monitor) == 1


def test_no_preflight_with_no_capacity_also_skips_the_old_warning(real_run):
    _, calls = real_run("--no-preflight", "--no-capacity")
    assert calls.monitor == []


def test_no_csv_leaves_the_report_out_with_the_other_csv_files(real_run):
    zip_path, calls = real_run("--no-csv")
    assert _report(zip_path)[0] == []
    assert calls.access == [[SUB]]


def test_an_anonymized_real_run_labels_the_subscription_in_the_report(real_run):
    zip_path, _ = real_run("--anonymize")
    text = zipfile.ZipFile(zip_path).read(_report(zip_path)[0][0]).decode("utf-8")
    assert SUB not in text and "Sub Name" not in text


def test_the_rows_are_in_the_json_a_real_run_keeps(real_run, tmp_path):
    real_run("--keep-artifacts")
    data = json.loads(next(tmp_path.glob("rubrik-discovery-*.json")).read_text())
    assert [r["Service"] for r in data["access_check"]] == ["virtual machines", "sql servers"]


def test_every_permission_name_fits_the_table_without_being_clipped():
    checks = [
        core.Check(
            "s", "n", "subscription", api.label, core.OK, True, "", api.affects, "", api.permission
        )
        for api in preflight.APIS
    ]
    text = "\n".join(preflight.table_lines(checks))
    assert all(api.permission in text for api in preflight.APIS) and "..." not in text


# ── the tenant, as a real run writes it ───────────────────────────────────────


def _vm_rows(zip_path):
    zf = zipfile.ZipFile(zip_path)
    name = next(n for n in zf.namelist() if n.startswith("azure_vmdisk_info-"))
    return list(csv.DictReader(io.StringIO(zf.read(name).decode("utf-8-sig"))))


def test_the_tenant_a_real_run_resolves_is_in_the_json_and_the_csv_files(real_run, tmp_path):
    zip_path, _ = real_run("--keep-artifacts")
    data = json.loads(next(tmp_path.glob("rubrik-discovery-*.json")).read_text())
    assert (data["tenant_id"], data["tenant_name"]) == ("tenant-id-1", "Tenant")
    assert {row["Tenant"] for row in _vm_rows(zip_path)} == {"Tenant"}


def test_the_tenant_is_looked_up_for_the_first_subscription_of_the_scope(real_run, monkeypatch):
    import auth

    asked = []
    monkeypatch.setattr(
        auth, "resolve_tenant_id", lambda cred, sub, cloud: asked.append(sub) or "tenant-id-1"
    )
    real_run()
    assert asked == [SUB]


def test_a_tenant_that_cannot_be_read_leaves_the_documented_blank_and_unknown(
    real_run, monkeypatch, tmp_path
):
    import auth

    monkeypatch.setattr(auth, "resolve_tenant_id", lambda *a, **k: None)
    zip_path, _ = real_run("--keep-artifacts")
    data = json.loads(next(tmp_path.glob("rubrik-discovery-*.json")).read_text())
    assert (data["tenant_id"], data["tenant_name"]) == ("unknown", None)
    assert {row["Tenant"] for row in _vm_rows(zip_path)} == {""}

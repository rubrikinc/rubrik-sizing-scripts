"""--get-key-vault-amounts and --get-container-details: the collectors, the two files and the totals,
checked against Get-AzureSizingInfo.ps1's rules (Get-AzureKeyVaultInventory and the container loop of
Get-AzureStorageAndFilesInventory)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import csv_export
import main
import pytest
import totals
from azure.core.exceptions import HttpResponseError
from cloud import _CLOUDS, DEFAULT_CLOUD
from collectors import containers, key_vault

CONTRACT = json.loads(
    (Path(__file__).resolve().parents[2] / "contract" / "columns.json").read_text(encoding="utf-8")
)
GOV = _CLOUDS["AzureUSGovernment"]


def _contract_columns(prefix: str) -> list[str]:
    spec = next(f for f in CONTRACT["clouds"]["azure"] if f["prefix"] == prefix)
    return [c["name"] for c in spec["columns"]]


def _denied(code="Forbidden", status=403):
    exc = HttpResponseError("denied")
    exc.status_code = status
    exc.error = NS(code=code)
    return exc


def _blob(size, tier, snapshot=None):
    return NS(name="b", size=size, blob_tier=tier, snapshot=snapshot)


# ── container sums ────────────────────────────────────────────────────────────


def test_blobs_are_summed_per_tier_without_regard_to_case_and_snapshots_are_left_out():
    blobs = [
        _blob(100, "Hot"),
        _blob(50, "hot"),
        _blob(10, "Cool"),
        _blob(7, "Archive"),
        _blob(3, "Cold"),  # PowerShell has no Cold column: unknown
        _blob(2, "P10"),  # a premium page blob tier: unknown
        _blob(1, None),
        _blob(999, "Hot", snapshot="2026-10-01T00:00:00Z"),
    ]
    stats = containers.tally("c", "acct", blobs)
    assert (stats.hot_bytes, stats.hot_count) == (150, 2)
    assert (stats.cool_bytes, stats.cool_count) == (10, 1)
    assert (stats.archive_bytes, stats.archive_count) == (7, 1)
    assert (stats.unknown_bytes, stats.unknown_count) == (6, 3)
    assert (stats.all_bytes, stats.all_count) == (173, 7)


def test_an_sdk_enum_tier_is_read_by_its_value():
    from azure.storage.blob import StandardBlobTier

    stats = containers.tally("c", "acct", [_blob(4, StandardBlobTier.ARCHIVE)])
    assert (stats.archive_bytes, stats.archive_count) == (4, 1)


def _service(container_names, blobs_by_container=None, error=None, container_errors=None):
    service = MagicMock()
    if error is not None:
        service.list_containers.side_effect = error
    else:
        service.list_containers.return_value = [NS(name=n) for n in container_names]

    def client(name):
        c = MagicMock()
        if container_errors and name in container_errors:
            c.list_blobs.side_effect = container_errors[name]
        else:
            c.list_blobs.return_value = (blobs_by_container or {}).get(name, [])
        return c

    service.get_container_client.side_effect = client
    return service


def _collect(monkeypatch, accounts, services, cloud=DEFAULT_CLOUD):
    made = []

    def build(account_url, credential):
        made.append(account_url)
        return services[account_url.split("//")[1].split(".")[0]]

    monkeypatch.setattr(containers, "BlobServiceClient", build)
    monkeypatch.setattr(containers, "HAS_SDK", True)
    inventory = containers.ContainerCollector("sub", "cred", accounts, cloud=cloud).collect()
    return inventory, made


def test_file_storage_accounts_are_not_listed_and_the_cloud_sets_the_address(monkeypatch):
    accounts = [NS(name="files", kind="FileStorage"), NS(name="blobs", kind="StorageV2")]
    inventory, made = _collect(
        monkeypatch, accounts, {"blobs": _service(["c1"], {"c1": [_blob(5, "Hot")]})}, cloud=GOV
    )
    assert made == ["https://blobs.blob.core.usgovcloudapi.net"]
    assert [(c.storage_account, c.name, c.hot_bytes) for c in inventory.containers] == [
        ("blobs", "c1", 5)
    ]
    assert inventory.total_containers == 1


def test_an_account_whose_containers_cannot_be_listed_has_no_rows_and_a_reason(monkeypatch, caplog):
    accounts = [NS(name="denied", kind="StorageV2"), NS(name="ok", kind="StorageV2")]
    services = {
        "denied": _service([], error=_denied("AuthorizationPermissionMismatch")),
        "ok": _service(["c"]),
    }
    with caplog.at_level(logging.WARNING):
        inventory, _ = _collect(monkeypatch, accounts, services)
    assert inventory.account_errors == {"denied": "AuthorizationPermissionMismatch"}
    assert [c.storage_account for c in inventory.containers] == ["ok"]
    assert "AuthorizationPermissionMismatch" in caplog.text


def test_a_container_whose_blobs_fail_keeps_a_row_with_empty_values_not_the_previous_ones(
    monkeypatch,
):
    """PowerShell keeps the previous container's $azConBlobs here and writes its numbers again."""
    services = {
        "acct": _service(
            ["full", "broken"],
            {"full": [_blob(100, "Hot")]},
            container_errors={"broken": _denied()},
        )
    }
    inventory, _ = _collect(monkeypatch, [NS(name="acct", kind="StorageV2")], services)
    full, broken = inventory.containers
    assert full.hot_bytes == 100
    assert broken.error == "Forbidden"
    assert broken.hot_bytes is None and broken.all_count is None


def _refusing_accounts(count, code="AuthorizationPermissionMismatch", readable=()):
    accounts, services = [], {}
    for n in range(count):
        name = f"acct{n}"
        accounts.append(NS(name=name, kind="StorageV2"))
        if name in readable:
            services[name] = _service(["c"], {"c": [_blob(1, "Hot")]})
        else:
            services[name] = _service(["c"], container_errors={"c": _denied(code)})
    return accounts, services


def _tried(services):
    return sum(s.get_container_client.call_count for s in services.values())


def test_a_missing_data_role_stops_the_blob_listing_but_every_container_keeps_its_row(
    monkeypatch, caplog
):
    limit = containers.STOP_AFTER_REFUSED_ACCOUNTS
    accounts, services = _refusing_accounts(limit + 3)
    with caplog.at_level(logging.WARNING):
        inventory, _ = _collect(monkeypatch, accounts, services)

    assert _tried(services) == limit
    assert len(inventory.containers) == limit + 3
    assert all(c.all_count is None for c in inventory.containers)
    first = [c.error for c in inventory.containers[:limit]]
    assert first == ["AuthorizationPermissionMismatch"] * limit
    assert all("not tried" in c.error for c in inventory.containers[limit:])
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == limit
    assert "none could be read" in warnings[-1]


def test_the_listing_never_stops_once_a_container_was_read(monkeypatch):
    limit = containers.STOP_AFTER_REFUSED_ACCOUNTS
    accounts, services = _refusing_accounts(limit + 3, readable={"acct0"})
    inventory, _ = _collect(monkeypatch, accounts, services)

    assert _tried(services) == limit + 3
    assert inventory.containers[0].hot_bytes == 1
    assert not any("not tried" in (c.error or "") for c in inventory.containers)


@pytest.mark.parametrize("code", ["AuthorizationFailure", "Forbidden"])
def test_other_refusals_such_as_a_firewall_never_stop_the_listing(monkeypatch, code):
    limit = containers.STOP_AFTER_REFUSED_ACCOUNTS
    accounts, services = _refusing_accounts(limit + 3, code=code)
    _collect(monkeypatch, accounts, services)

    assert _tried(services) == limit + 3


# ── Key Vault counts ──────────────────────────────────────────────────────────


def _vault_resource(name, uri=None):
    return NS(
        name=name,
        id=f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}",
        location="eastus",
        properties={"vaultUri": uri} if uri else {},
    )


def _kv_clients(monkeypatch, counts=None, errors=None):
    counts, errors = counts or {}, errors or {}
    seen = []

    def client(kind, method):
        def build(url, credential):
            seen.append((kind, url))
            c = MagicMock()
            if (url, kind) in errors:
                getattr(c, method).side_effect = errors[(url, kind)]
            else:
                getattr(c, method).return_value = iter(range(counts.get((url, kind), 0)))
            return c

        return build

    monkeypatch.setattr(
        key_vault, "CertificateClient", client("certificates", "list_properties_of_certificates")
    )
    monkeypatch.setattr(key_vault, "SecretClient", client("secrets", "list_properties_of_secrets"))
    monkeypatch.setattr(key_vault, "KeyClient", client("keys", "list_properties_of_keys"))
    monkeypatch.setattr(key_vault, "HAS_SDK", True)
    return seen


def _collect_vaults(monkeypatch, resources, cloud=DEFAULT_CLOUD):
    monkeypatch.setattr(key_vault, "ResourceManagementClient", MagicMock())
    monkeypatch.setattr(key_vault, "_read_resources", lambda *a, **k: resources)
    return key_vault.KeyVaultCollector("sub", "cred", cloud=cloud).collect()


def test_each_vault_gets_its_three_counts_and_an_empty_vault_is_zero(monkeypatch):
    uri = "https://kv1.vault.azure.net/"
    _kv_clients(monkeypatch, {(uri, "certificates"): 2, (uri, "secrets"): 5, (uri, "keys"): 1})
    inventory = _collect_vaults(monkeypatch, [_vault_resource("kv1", uri), _vault_resource("kv2")])
    kv1, kv2 = inventory.vaults
    assert (kv1.certificates, kv1.secrets, kv1.keys) == (2, 5, 1)
    assert (kv2.certificates, kv2.secrets, kv2.keys) == (0, 0, 0)
    assert (kv1.resource_group, kv1.location, inventory.total_vaults) == ("rg", "eastus", 2)


def test_a_count_that_cannot_be_read_is_blank_with_its_reason(monkeypatch, caplog):
    uri = "https://kv1.vault.azure.net/"
    _kv_clients(monkeypatch, {(uri, "keys"): 3}, {(uri, "secrets"): _denied("Forbidden")})
    with caplog.at_level(logging.WARNING):
        (vault,) = _collect_vaults(monkeypatch, [_vault_resource("kv1", uri)]).vaults
    assert (vault.certificates, vault.secrets, vault.keys) == (0, None, 3)
    assert vault.errors == {"secrets": "Forbidden"}
    assert "kv1" in caplog.text and "secrets" in caplog.text and "Forbidden" in caplog.text


def test_without_a_vault_uri_the_address_follows_the_cloud(monkeypatch):
    seen = _kv_clients(monkeypatch)
    _collect_vaults(monkeypatch, [_vault_resource("kv")], cloud=GOV)
    assert {url for _, url in seen} == {"https://kv.vault.usgovcloudapi.net/"}


# ── the files ─────────────────────────────────────────────────────────────────


def _result(**changes):
    result = {
        "tenant_name": "Contoso",
        "tenant_id": "t",
        "subscription_names": {"sub": "Sub One"},
        "tag_names": {"sub": ["env", "Owner"]},
        "skipped": [],
        "storage": [
            {
                "subscription_id": "sub",
                "accounts": [
                    {
                        "name": "acct",
                        "kind": "StorageV2",
                        "hns_enabled": False,
                        "sku": "Standard_LRS",
                        "access_tier": "Hot",
                        "location": "eastus",
                        "resource_group": "rg",
                        "tags": {"env": "prod"},
                    }
                ],
            }
        ],
        "containers": [
            {
                "subscription_id": "sub",
                "containers": [
                    {
                        "name": "data",
                        "storage_account": "acct",
                        "hot_bytes": 3 * 1024**3,
                        "hot_count": 2,
                        "cool_bytes": 0,
                        "cool_count": 0,
                        "archive_bytes": 1024**3,
                        "archive_count": 1,
                        "unknown_bytes": 0,
                        "unknown_count": 0,
                        "all_bytes": 4 * 1024**3,
                        "all_count": 3,
                        "error": None,
                    },
                    {
                        "name": "broken",
                        "storage_account": "acct",
                        **{
                            f"{t}_{k}": None
                            for t in (*containers.TIERS, "unknown", "all")
                            for k in ("bytes", "count")
                        },
                        "error": "Forbidden",
                    },
                ],
            }
        ],
        "key_vaults": [
            {
                "subscription_id": "sub",
                "vaults": [
                    {
                        "name": "kv1",
                        "location": "eastus",
                        "certificates": 2,
                        "secrets": None,
                        "keys": 0,
                    }
                ],
            }
        ],
    }
    result.update(changes)
    return result


def _rows(prefix, result=None):
    return csv_export.rows_by_file(result or _result())[prefix]


def test_both_headers_are_the_contracts_columns():
    files = csv_export.build_csv_files(_result(), "2026-10-27_1200")
    container = files["azure_storage_account_container_info-2026-10-27_1200.csv"].splitlines()[0]
    vault = files["azure_key_vault-2026-10-27_1200.csv"].splitlines()[0]
    columns = [c.strip('"') for c in container.split('","')]
    assert columns[:39] == _contract_columns("azure_storage_account_container_info")
    assert columns[39:] == ["Tag: env", "Tag: Owner"]
    assert [c.strip('"') for c in vault.split('","')] == _contract_columns("azure_key_vault")


def test_a_container_row_has_its_accounts_columns_the_tier_sizes_and_dashes_for_tags():
    data, _ = _rows("azure_storage_account_container_info")
    assert (data["StorageAccount"], data["StorageAccountType"], data["StorageAccountSkuName"]) == (
        "acct",
        "StorageV2",
        "Standard_LRS",
    )
    assert (data["Region"], data["ResourceGroup"], data["Subscription"], data["Tenant"]) == (
        "eastus",
        "rg",
        "Sub One",
        "Contoso",
    )
    assert (data["UsedCapacityHotTierBytes"], data["UsedCapacityHotTierGiB"]) == (3 * 1024**3, 3)
    assert data["HotTierBlobCount"] == 2 and data["ArchiveTierBlobCount"] == 1
    assert data["UsedCapacityAllTiersGB"] == 4.295 and data["UsedCapacityAllTiersTiB"] == 0.0039
    # Containers have no tags; the storage account's tag is not copied onto them.
    assert data["Tag: env"] == "-" and data["Tag: Owner"] == "-"


def test_unknown_tier_blob_count_counts_every_blob_as_powershell_does():
    data, _ = _rows("azure_storage_account_container_info")
    assert data["UnknownTierBlobCount"] == 3


def test_a_container_that_failed_has_empty_cells_and_no_borrowed_numbers():
    _, broken = _rows("azure_storage_account_container_info")
    sized = [c for c in broken if c.startswith("UsedCapacity") or c.endswith("BlobCount")]
    assert sized and all(broken[c] is None for c in sized)


def test_a_key_vault_row_leaves_an_unread_count_blank_and_keeps_zero():
    (row,) = _rows("azure_key_vault")
    assert row == {
        "VaultName": "kv1",
        "Location": "eastus",
        "Tenant": "Contoso",
        "Subscription": "Sub One",
        "NumCertificates": 2,
        "NumSecrets": None,
        "NumKeys": 0,
    }


# ── the totals ────────────────────────────────────────────────────────────────


def test_the_container_totals_are_the_real_sum_not_powershells_zero():
    lines = totals.summary_lines(csv_export.rows_by_file(_result()))
    assert "Total # of Azure Containers: 2" in lines
    assert (
        "Total capacity of all Azure Containers: 4 GiB or 4 GB or 0.0039 TiB or 0.0043 TB" in lines
    )


def test_the_totals_follow_powershells_order():
    lines = totals.summary_lines(csv_export.rows_by_file(_result()))
    start = lines.index("Totals based on querying storage account metrics:")
    containers_at = lines.index(
        "Totals based on traversing each blob store container and calculating statistics:"
    )
    assert start < containers_at
    assert lines[-1] == "Total # of Azure Key Vaults: 1"


def test_without_the_options_neither_section_is_printed():
    lines = totals.summary_lines(csv_export.rows_by_file(_result(containers=None, key_vaults=None)))
    assert not any("Container" in line or "Key Vault" in line for line in lines)


# ── the options ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text, service, code, expected",
    [
        ("[s] Key Vault kv1: could not count secrets (Forbidden); left blank", "", "", "key-vault"),
        ("denied", "key vault contents", "Forbidden", "key-vault"),
        (
            "[s] Blob containers of 2 storage account(s) could not be listed (Forbidden): a, b",
            "",
            "",
            "blob",
        ),
        (
            "[s] Blobs of container c in storage account a could not be listed (Forbidden)",
            "",
            "",
            "blob",
        ),
        ("denied", "blob containers", "AuthorizationPermissionMismatch", "blob"),
    ],
)
def test_a_data_plane_denial_gets_the_data_role_fix(text, service, code, expected):
    import runlog  # noqa: F401 - importing it configures runlog_core with the Azure fixes
    import runlog_core as core

    solution_id, fix = core.solve(text, service, code)
    if expected == "key-vault":
        assert solution_id == "az-key-vault-contents-denied" and "Key Vault Reader" in fix
    else:
        assert solution_id == "az-blob-data-denied" and "Storage Blob Data Reader" in fix


@pytest.mark.parametrize("flag", ["get_container_details", "get_key_vault_amounts"])
def test_each_option_is_off_by_default(flag):
    parser = main._build_parser()
    assert getattr(parser.parse_args([]), flag) is False
    option = "--" + flag.replace("_", "-")
    assert getattr(parser.parse_args([option]), flag) is True

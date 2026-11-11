"""azure_file_share_info and the file share collection behind it.

Expected cell text and the account rule come from the real PowerShell code
(``Get-AzureFileSAs`` and the ``$azFSObj`` block) run in pwsh on the same inputs.
"""

from __future__ import annotations

import csv
import io
from types import SimpleNamespace as NS

import pytest

import csv_export
from collectors.storage import FileShareInfo, supports_azure_files
from csv_export import build_csv_files
from tests.test_storage import _make_collector


def _parse(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def _account(shares, **overrides) -> dict:
    account = {
        "name": "sa1",
        "kind": "FileStorage",
        "sku": "Premium_LRS",
        "access_tier": None,
        "location": "westus2",
        "resource_group": "rg-one",
        "file_shares": shares,
    }
    account.update(overrides)
    return account


def _result(*accounts) -> dict:
    return {
        "tenant_name": None,
        "tenant_id": "t",
        "subscription_names": {"sub-1": "Sub One"},
        "tag_names": {"sub-1": ["Env"]},
        "storage": [{"subscription_id": "sub-1", "accounts": list(accounts)}],
    }


def _file(result: dict) -> str:
    return build_csv_files(result, "S")["azure_file_share_info-S.csv"]


# ── which accounts hold file shares ───────────────────────────────────────────


@pytest.mark.parametrize(
    "kind,sku,expected",
    [
        ("StorageV2", "Standard_LRS", True),
        ("StorageV2", "Standard_GRS", True),
        ("StorageV2", "Premium_LRS", False),
        ("StorageV2", "Premium_ZRS", False),
        ("Storage", "Standard_RAGRS", True),
        ("Storage", "Premium_LRS", False),
        ("FileStorage", "Premium_LRS", True),
        ("FileStorage", "Premium_ZRS", True),
        ("FileStorage", "Standard_LRS", False),
        ("BlobStorage", "Standard_LRS", False),
        ("BlockBlobStorage", "Premium_LRS", False),
        ("Unknown", "Unknown", False),
    ],
)
def test_supports_azure_files_matches_powershell(kind, sku, expected):
    assert supports_azure_files(kind, sku) is expected


# ── the file ──────────────────────────────────────────────────────────────────


def test_file_matches_powershell_lines():
    shares = [
        {"name": "share1", "quota_gib": 100, "usage_bytes": 536870912000},
        {"name": "share2", "quota_gib": 5120, "usage_bytes": None},
        {"name": "share3", "quota_gib": None, "usage_bytes": 0},
        {"name": "share4", "quota_gib": 1, "usage_bytes": 1.2345678901234568e17},
        {"name": "share5", "quota_gib": 3, "usage_bytes": 1073741824 * 2.5},
    ]
    lines = _file(_result(_account(shares))).splitlines()
    assert lines[0].split(",")[:11] == [f'"{c}"' for c in csv_export._FILE_SHARE_COLUMNS[:11]]
    assert lines[1:] == [
        '"share1","sa1","FileStorage","Premium_LRS",,,"Sub One","westus2","rg-one","100","0.098","536870912000","500","0.4883","536.871","0.5369","-","False"',
        '"share2","sa1","FileStorage","Premium_LRS",,,"Sub One","westus2","rg-one","5120","5",,"0","0","0","0","-","False"',
        '"share3","sa1","FileStorage","Premium_LRS",,,"Sub One","westus2","rg-one",,"0","0","0","0","0","0","-","False"',
        '"share4","sa1","FileStorage","Premium_LRS",,,"Sub One","westus2","rg-one","1","0.001","1.2345678901234568E+17","114978095","112283.2955","123456789.012","123456.789","-","False"',
        '"share5","sa1","FileStorage","Premium_LRS",,,"Sub One","westus2","rg-one","3","0.003","2684354560","2","0.0024","2.684","0.0027","-","False"',
    ]


def test_header_has_no_tag_columns():
    header = _parse(_file(_result(_account([{"name": "s", "quota_gib": 1, "usage_bytes": 1}]))))[0]
    assert header == csv_export._FILE_SHARE_COLUMNS


def test_rows_follow_accounts_then_shares():
    result = _result(
        _account([{"name": "b"}, {"name": "a"}], name="sa1"),
        _account([{"name": "c"}], name="sa2"),
    )
    rows = _parse(_file(result))[1:]
    assert [(r[1], r[0]) for r in rows] == [("sa1", "b"), ("sa1", "a"), ("sa2", "c")]


def test_account_without_shares_adds_no_rows_and_no_shares_gives_an_empty_file():
    assert _file(_result(_account([]))) == ""
    assert _file(_result()) == ""


# ── collection ────────────────────────────────────────────────────────────────

_ACCOUNT_ID = (
    "/subscriptions/s/resourceGroups/rg-one/providers/Microsoft.Storage/storageAccounts/sa1"
)


def _storage_account(kind="StorageV2", sku="Standard_LRS"):
    return NS(
        id=_ACCOUNT_ID,
        name="sa1",
        location="westus2",
        sku=NS(name=sku),
        kind=kind,
        access_tier="Hot",
        tags={},
    )


def _collector(account, shares, details, **kwargs):
    collector = _make_collector(accounts=[account], **kwargs)
    storage = collector._storage
    storage.file_shares.list.side_effect = lambda *a, **k: iter(shares)
    storage.file_shares.get.side_effect = details
    return collector, storage


def test_shares_are_listed_with_quota_and_usage_from_the_stats_expansion():
    seen = []

    def details(rg, account, name, **kwargs):
        seen.append((rg, account, name, kwargs.get("expand")))
        return NS(share_quota=200, share_usage_bytes=12345)

    collector, _ = _collector(_storage_account(), [NS(name="share1", share_quota=100)], details)
    (info,) = collector._list_accounts()
    assert info.file_shares == [FileShareInfo(name="share1", quota_gib=200, usage_bytes=12345)]
    assert seen == [("rg-one", "sa1", "share1", "stats")]


def test_a_share_whose_usage_cannot_be_read_keeps_its_quota():
    def details(*args, **kwargs):
        raise RuntimeError("denied")

    collector, _ = _collector(_storage_account(), [NS(name="share1", share_quota=100)], details)
    (info,) = collector._list_accounts()
    assert info.file_shares == [FileShareInfo(name="share1", quota_gib=100, usage_bytes=None)]


def test_usage_is_not_read_when_capacity_collection_is_off():
    collector, storage = _collector(
        _storage_account(),
        [NS(name="share1", share_quota=100)],
        lambda *a, **k: NS(share_quota=1, share_usage_bytes=1),
        collect_capacity=False,
    )
    (info,) = collector._list_accounts()
    assert info.file_shares == [FileShareInfo(name="share1", quota_gib=100, usage_bytes=None)]
    storage.file_shares.get.assert_not_called()


def test_accounts_that_do_not_support_azure_files_are_not_queried():
    collector, storage = _collector(
        _storage_account(kind="BlobStorage"), [NS(name="x", share_quota=1)], lambda *a, **k: NS()
    )
    (info,) = collector._list_accounts()
    assert info.file_shares == []
    storage.file_shares.list.assert_not_called()


def test_a_failing_share_list_leaves_the_account_without_shares():
    collector, storage = _collector(_storage_account(), [], lambda *a, **k: NS())
    storage.file_shares.list.side_effect = RuntimeError("denied")
    (info,) = collector._list_accounts()
    assert info.file_shares == []
    assert info.name == "sa1"

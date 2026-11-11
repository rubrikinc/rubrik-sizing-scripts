"""azure_backup_vault_info, azure_backup_costs and the rounding they depend on.

Expected cells come from the real PowerShell code run in pwsh: the vault block (with the
Az.RecoveryServices ``ImmutabilitySettings`` class compiled in) and the cost loop (fed through
``ConvertFrom-Json`` as the script does), on the same inputs as the cases below.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import pytest

import csv_export
from azure.core.exceptions import HttpResponseError
from azure.mgmt.recoveryservices.models import Vault
from collectors import cost as cost_module
from collectors.cost import (
    BackupCostMonth,
    CostCollector,
    _add_months,
    _month_start,
)
from csv_export import (
    _immutability_text,
    _money,
    _ps_datetime,
    _ps_round,
    build_csv_files,
)


def _parse(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


# ── [math]::round ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value,digits,expected",
    [
        (12.345, 2, 12.34),
        (2.675, 2, 2.68),
        (2.665, 2, 2.66),
        (0.125, 2, 0.12),
        (0.135, 2, 0.14),
        (-3.14159, 2, -3.14),
        (2.5, 0, 2.0),
        (3.5, 0, 4.0),
        (1e16, 2, 1e16),
        (0.0, 3, 0.0),
    ],
)
def test_ps_round_matches_dotnet(value, digits, expected):
    assert _ps_round(value, digits) == expected


def test_python_round_would_have_differed():
    assert round(12.345, 2) == 12.35 and _ps_round(12.345, 2) == 12.34


def test_sizes_use_dotnet_rounding():
    cells = csv_export._units_from_bytes(1073741824 * 2.5, "X")
    assert cells["XGiB"] == 2.0


# ── azure_backup_vault_info ───────────────────────────────────────────────────


def _vault(**overrides) -> dict:
    vault = {
        "name": "v1",
        "type": "Microsoft.RecoveryServices/vaults",
        "location": "westus2",
        "resource_group": "rg-1",
        "provisioning_state": "Succeeded",
        "cross_subscription_restore_state": "Enabled",
        "immutability_state": "Unlocked",
    }
    vault.update(overrides)
    return vault


def _result(vaults=(), months=()) -> dict:
    return {
        "tenant_name": None,
        "tenant_id": "t",
        "subscription_names": {"sub-1": "Sub One"},
        "tag_names": {"sub-1": ["Env"]},
        "backup_posture": [{"subscription_id": "sub-1", "vaults": list(vaults)}],
        "cost": [{"subscription_id": "sub-1", "backup_cost_months": list(months)}],
    }


def test_vault_rows_match_powershell():
    vaults = [
        _vault(),
        _vault(
            name="v2",
            location="eastus",
            resource_group="rg-2",
            cross_subscription_restore_state="Disabled",
            immutability_state="disabled",
        ),
        _vault(
            name="v3",
            location="eastus",
            resource_group="rg-2",
            provisioning_state=None,
            cross_subscription_restore_state=None,
            immutability_state=None,
        ),
        _vault(
            name="v4",
            location="northeurope",
            resource_group="rg-3",
            provisioning_state="Updating",
            cross_subscription_restore_state="PermanentlyDisabled",
            immutability_state="LOCKED",
        ),
        _vault(
            name="v5",
            location="eastus",
            resource_group="rg-2",
            cross_subscription_restore_state=None,
            immutability_state="Weird",
        ),
    ]
    lines = build_csv_files(_result(vaults), "S")["azure_backup_vault_info-S.csv"].splitlines()
    assert lines == [
        '"Name","Type","Tenant","Subscription","Region","ResourceGroup","ProvisioningState","CrossSubscriptionRestoreState","ImmutabilitySettings"',
        '"v1","Microsoft.RecoveryServices/vaults",,"Sub One","westus2","rg-1","Succeeded","Enabled","ImmutabilityState: Unlocked"',
        '"v2","Microsoft.RecoveryServices/vaults",,"Sub One","eastus","rg-2","Succeeded","Disabled","ImmutabilityState: Disabled"',
        '"v3","Microsoft.RecoveryServices/vaults",,"Sub One","eastus","rg-2",,,',
        '"v4","Microsoft.RecoveryServices/vaults",,"Sub One","northeurope","rg-3","Updating","PermanentlyDisabled","ImmutabilityState: Locked"',
        '"v5","Microsoft.RecoveryServices/vaults",,"Sub One","eastus","rg-2","Succeeded",,"ImmutabilityState: 0"',
    ]


def test_immutability_text():
    assert _immutability_text(None) is None
    assert _immutability_text("") == "ImmutabilityState: 0"
    assert _immutability_text("Unlocked") == "ImmutabilityState: Unlocked"
    assert _immutability_text("locked") == "ImmutabilityState: Locked"
    assert _immutability_text("nonsense") == "ImmutabilityState: 0"


def test_vault_file_has_no_tag_columns_and_empty_without_vaults():
    files = build_csv_files(_result([_vault()]), "S")
    assert "Tag: Env" not in files["azure_backup_vault_info-S.csv"]
    assert build_csv_files(_result(), "S")["azure_backup_vault_info-S.csv"] == ""


# ── azure_backup_costs ────────────────────────────────────────────────────────

_MONTHS = [
    ("2025-11-01T00:00:00", 12.345, 15.678),
    ("2025-12-01T00:00:00", 0.004, 0.0),
    ("2026-01-01T00:00:00", 1234567.891, 1234567.891),
    ("2026-02-01T00:00:00", 5.0, 5.5),
    ("2026-03-01T00:00:00", 1e-05, 2.5),
    ("2026-04-01T00:00:00", 2.675, 2.665),
    ("2026-05-01T00:00:00", -3.14159, 0),
    ("2026-06-01T00:00:00", 0.125, 0.135),
]


def test_cost_rows_match_powershell():
    months = [
        {"billing_month": m, "pre_tax_cost_usd": pre, "cost_usd": cost} for m, pre, cost in _MONTHS
    ]
    lines = build_csv_files(_result(months=months), "S")["azure_backup_costs-S.csv"].splitlines()
    assert lines == [
        '"SubscriptionId","Subscription","Tenant","BillingMonth","PreTaxCostUSD","CostUSD"',
        '"sub-1","Sub One",,"11/1/2025 12:00:00 AM","$12.34","$15.68"',
        '"sub-1","Sub One",,"12/1/2025 12:00:00 AM","$0","$0"',
        '"sub-1","Sub One",,"1/1/2026 12:00:00 AM","$1234567.89","$1234567.89"',
        '"sub-1","Sub One",,"2/1/2026 12:00:00 AM","$5","$5.5"',
        '"sub-1","Sub One",,"3/1/2026 12:00:00 AM","$0","$2.5"',
        '"sub-1","Sub One",,"4/1/2026 12:00:00 AM","$2.68","$2.66"',
        '"sub-1","Sub One",,"5/1/2026 12:00:00 AM","$-3.14","$0"',
        '"sub-1","Sub One",,"6/1/2026 12:00:00 AM","$0.12","$0.14"',
    ]


def test_money_and_datetime_text():
    assert _money(None) == "$0"
    assert _money(1234.5) == "$1234.5"
    assert _ps_datetime("2026-09-01T00:00:00") == "9/1/2026 12:00:00 AM"
    assert _ps_datetime("2026-09-30T13:05:09") == "9/30/2026 1:05:09 PM"
    assert _ps_datetime("2026-09-30T12:00:00") == "9/30/2026 12:00:00 PM"


def test_no_months_gives_an_empty_file():
    assert build_csv_files(_result(), "S")["azure_backup_costs-S.csv"] == ""


# ── cost collection ───────────────────────────────────────────────────────────

_SUB = "00000000-0000-0000-0000-000000000001"


def _cost_collector(rows=None, columns=None, error=None):
    client = MagicMock()
    if error is not None:
        client.query.usage.side_effect = error
    else:
        names = columns or ["PreTaxCostUSD", "CostUSD", "BillingMonth", "Currency"]
        client.query.usage.return_value = NS(columns=[NS(name=n) for n in names], rows=rows or [])
    with patch.object(cost_module, "CostManagementClient", return_value=client):
        collector = CostCollector(_SUB, MagicMock())
    return collector, client


_NOW = datetime(2026, 10, 6, 15, 30, tzinfo=timezone.utc)


def test_backup_months_query_matches_the_script():
    collector, client = _cost_collector(
        rows=[[1.5, 2.5, "2026-09-01T00:00:00", "USD"], [0.0, 0.0, "2026-10-01T00:00:00", "USD"]]
    )
    months = collector.collect_backup_months(_NOW)
    assert months == [
        BackupCostMonth("2026-09-01T00:00:00", 1.5, 2.5),
        BackupCostMonth("2026-10-01T00:00:00", 0.0, 0.0),
    ]
    scope, query = client.query.usage.call_args[0]
    assert scope == f"/subscriptions/{_SUB}"
    assert query.type == "Usage" and query.timeframe == "Custom"
    assert query.time_period.from_property == datetime(2025, 11, 6, 15, 30, tzinfo=timezone.utc)
    assert query.time_period.to == _NOW
    assert query.dataset.granularity == "Monthly"
    assert {a.name: a.function for a in query.dataset.aggregation.values()} == {
        "CostUSD": "Sum",
        "PreTaxCostUSD": "Sum",
    }
    cost_filter = query.dataset.filter.dimensions
    assert (cost_filter.name, cost_filter.operator, cost_filter.values_property) == (
        "ServiceName",
        "In",
        ["Backup"],
    )


def test_columns_are_found_by_name_not_position():
    collector, _ = _cost_collector(
        rows=[["2026-09-01T00:00:00", "USD", 2.5, 1.5]],
        columns=["BillingMonth", "Currency", "CostUSD", "PreTaxCostUSD"],
    )
    (month,) = collector.collect_backup_months(_NOW)
    assert (month.pre_tax_cost_usd, month.cost_usd) == (1.5, 2.5)


def test_digit_month_values_are_accepted_and_bad_rows_skipped():
    collector, _ = _cost_collector(
        rows=[[1.0, 2.0, "20260901000000", "USD"], ["x", 2.0, "2026-09-01T00:00:00", "USD"], [1.0]]
    )
    assert collector.collect_backup_months(_NOW) == [
        BackupCostMonth("2026-09-01T00:00:00", 1.0, 2.0)
    ]


def test_a_failed_query_gives_no_months():
    collector, _ = _cost_collector(error=HttpResponseError(message="boom"))
    assert collector.collect_backup_months(_NOW) == []


@pytest.mark.parametrize(
    "reason",
    [
        cost_module._REASON_THROTTLED,
        cost_module._REASON_PERMISSION,
        cost_module._REASON_NOT_REGISTERED,
        cost_module._REASON_SERVER_ERROR,
    ],
)
def test_the_backup_query_is_not_repeated_after_a_persistent_failure(reason):
    collector, client = _cost_collector(rows=[[1.0, 2.0, "2026-09-01T00:00:00", "USD"]])
    collector._main_reason = reason
    assert collector.collect_backup_months(_NOW) == []
    client.query.usage.assert_not_called()


def test_collect_records_why_the_main_query_failed():
    collector, _ = _cost_collector(error=HttpResponseError(message="denied"))
    collector._client.query.usage.side_effect = _forbidden
    collector.collect()
    assert collector._main_reason == cost_module._REASON_PERMISSION
    assert collector.collect_backup_months(_NOW) == []


def _forbidden(*args, **kwargs):
    error = HttpResponseError(message="denied")
    error.status_code = 403
    raise error


@pytest.mark.parametrize(
    "moment,months,expected",
    [
        (datetime(2026, 10, 6), -11, datetime(2025, 11, 6)),
        (datetime(2026, 3, 31), -1, datetime(2026, 2, 28)),
        (datetime(2024, 3, 31), -1, datetime(2024, 2, 29)),
        (datetime(2026, 1, 15), -11, datetime(2025, 2, 15)),
        (datetime(2026, 1, 31), -2, datetime(2025, 11, 30)),
        (datetime(2026, 12, 1), 1, datetime(2027, 1, 1)),
    ],
)
def test_add_months_clamps_like_dotnet(moment, months, expected):
    assert _add_months(moment, months) == expected


@pytest.mark.parametrize(
    "raw,text",
    [
        ("2026-09-01T00:00:00", "2026-09-01T00:00:00"),
        ("20260901000000", "2026-09-01T00:00:00"),
        ("20260901", "2026-09-01T00:00:00"),
        (datetime(2026, 9, 1, tzinfo=timezone.utc), "2026-09-01T00:00:00"),
    ],
)
def test_month_start(raw, text):
    assert _month_start(raw) == text


# ── vault collection ──────────────────────────────────────────────────────────


def test_vault_properties_are_collected_as_api_values():
    from collectors.backup_posture import BackupPostureCollector

    vault = Vault(
        {
            "id": f"/subscriptions/{_SUB}/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/v1",
            "name": "v1",
            "location": "WestUS2",
            "type": "Microsoft.RecoveryServices/vaults",
            "properties": {
                "provisioningState": "Succeeded",
                "restoreSettings": {
                    "crossSubscriptionRestoreSettings": {"crossSubscriptionRestoreState": "Enabled"}
                },
                "securitySettings": {"immutabilitySettings": {"state": "Unlocked"}},
            },
        }
    )
    bare = Vault(
        {
            "id": f"/subscriptions/{_SUB}/resourceGroups/rg-2/providers/Microsoft.RecoveryServices/vaults/v2",
            "name": "v2",
            "location": "eastus",
            "properties": {},
        }
    )
    rs = MagicMock()
    rs.vaults.list_by_subscription_id.return_value = iter([vault, bare])
    backup = MagicMock()
    with (
        patch("collectors.backup_posture.RecoveryServicesClient", return_value=rs),
        patch("collectors.backup_posture.RecoveryServicesBackupClient", return_value=backup),
    ):
        collector = BackupPostureCollector(_SUB, MagicMock())
    collector._rs_client = rs
    collector._backup_client = backup

    first, second = collector._list_vaults()
    assert first.type == "Microsoft.RecoveryServices/vaults"
    assert first.provisioning_state == "Succeeded"
    assert first.cross_subscription_restore_state == "Enabled"
    assert first.immutability_state == "Unlocked"
    assert type(first.cross_subscription_restore_state) is str
    assert (second.provisioning_state, second.cross_subscription_restore_state) == (None, None)
    assert second.immutability_state is None

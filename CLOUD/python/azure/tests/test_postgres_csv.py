"""azure_postgres_info, its summary section and totals, and the collector data behind them.

The expected cell text comes from the rows Get-AzureSizingInfo.ps1 1.0.3 wrote for real PostgreSQL
flexible servers (for example 1139772465152 bytes used is 1061.4958 GiB, 1.0366 TiB, 1139.7725 GB and
1.1398 TB, and 2048 GiB provisioned is 2.199 TB).
"""

from __future__ import annotations

import csv
import io
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError

import csv_export
import totals
from anonymize import DEFAULT_FIELDS, FILE_ORDER, Anonymizer
from collectors.database import DatabaseCollector
from csv_export import build_csv_files
from preflight import APIS
from tests.fixtures import _make_flex_server
from tests.test_database import SUB_ID, _make_collector

COLUMNS = [
    "Server",
    "ResourceGroup",
    "Subscription",
    "Tenant",
    "Region",
    "Version",
    "SkuName",
    "SkuTier",
    "SkuCapacity",
    "MaxSizeGiB",
    "MaxSizeTiB",
    "MaxSizeGB",
    "MaxSizeTB",
    "SizeBucket",
    "Status",
    "AdministratorLogin",
    "BackupRetentionDays",
    "GeoRedundantBackup",
    "HighAvailabilityMode",
    "DatabaseCount",
    "Utilized_Bytes",
    "Utilized_GiB",
    "Utilized_TiB",
    "Utilized_GB",
    "Utilized_TB",
    "BackupPolicies",
    "InBackupPolicy",
]


def _server(**overrides) -> dict:
    server = {
        "name": "pg1",
        "resource_group": "rg-1",
        "location": "canadacentral",
        "raw_location": "Canada Central",
        "engine": "PostgreSQL",
        "sku_name": "Standard_D4ds_v5",
        "tier": "GeneralPurpose",
        "version": "17",
        "storage_gb": 2048,
        "backup_retention_days": 7,
        "geo_redundant_backup_text": "Disabled",
        "high_availability_mode": "Disabled",
        "state": "Ready",
        "administrator_login": "pgadmin",
        "database_count": 3,
        "utilized_bytes": 1139772465152.0,
        "tags": {"env": "dev"},
    }
    server.update(overrides)
    return server


def _result(*servers, skipped=(), tag_names=("env",)) -> dict:
    return {
        "tenant_name": "Contoso",
        "tenant_id": "t",
        "subscription_names": {"sub-1": "Sub One"},
        "tag_names": {"sub-1": list(tag_names)},
        "skipped": list(skipped),
        "database": [{"subscription_id": "sub-1", "flexible_servers": list(servers)}],
    }


def _csv(result) -> str:
    files = build_csv_files(result, "2026-10-22_1102")
    return next(text for name, text in files.items() if name.startswith("azure_postgres_info"))


def _table(result) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(_csv(result))))


def _row(**overrides) -> dict[str, str]:
    return _table(_result(_server(**overrides)))[0]


# ── the file ──────────────────────────────────────────────────────────────────


def test_the_columns_are_the_powershell_columns_in_order_then_the_tags():
    header = next(csv.reader(io.StringIO(_csv(_result(_server())))))
    assert header == [*COLUMNS, "Tag: env"]


def test_a_row_has_the_cells_powershell_writes():
    row = _row()
    assert row["Server"] == "pg1"
    assert (row["Subscription"], row["Tenant"]) == ("Sub One", "Contoso")
    assert row["Region"] == "Canada Central"
    assert (row["Version"], row["SkuName"], row["SkuTier"]) == (
        "17",
        "Standard_D4ds_v5",
        "GeneralPurpose",
    )
    assert row["SkuCapacity"] == "4"
    assert (row["MaxSizeGiB"], row["MaxSizeTiB"], row["MaxSizeGB"], row["MaxSizeTB"]) == (
        "2048",
        "2",
        "2199.023",
        "2.199",
    )
    assert row["SizeBucket"] == "1 TiB and over"
    assert (row["Status"], row["AdministratorLogin"]) == ("Ready", "pgadmin")
    assert (row["BackupRetentionDays"], row["GeoRedundantBackup"]) == ("7", "Disabled")
    assert (row["HighAvailabilityMode"], row["DatabaseCount"]) == ("Disabled", "3")
    assert row["Utilized_Bytes"] == "1139772465152"
    assert (row["Utilized_GiB"], row["Utilized_TiB"], row["Utilized_GB"], row["Utilized_TB"]) == (
        "1061.4958",
        "1.0366",
        "1139.7725",
        "1.1398",
    )


def test_the_region_is_kept_as_azure_returns_it_and_falls_back_to_the_normalised_one():
    assert _row()["Region"] == "Canada Central"
    assert _row(raw_location=None)["Region"] == "canadacentral"


def test_the_backup_columns_say_not_protected_until_a_backup_vault_item_is_found():
    row = _row()
    assert (row["BackupPolicies"], row["InBackupPolicy"]) == ("-", "False")


@pytest.mark.parametrize(
    ("sku", "vcores"),
    [
        ("Standard_B1ms", "1"),
        ("Standard_B2s", "2"),
        ("Standard_D2ds_v5", "2"),
        ("Standard_E16ds_v5", "16"),
        ("Standard_D32ads_v5", "32"),
        ("Unknown", ""),
    ],
)
def test_the_vcores_are_the_number_after_the_series_letters(sku, vcores):
    assert _row(sku_name=sku)["SkuCapacity"] == vcores


@pytest.mark.parametrize(
    ("gib", "bucket"),
    [
        (32, "Under 1 TiB"),
        (1023, "Under 1 TiB"),
        (1024, "1 TiB and over"),
        (16384, "1 TiB and over"),
    ],
)
def test_one_tib_is_in_the_larger_size_range(gib, bucket):
    assert _row(storage_gb=gib)["SizeBucket"] == bucket


def test_an_unknown_size_is_blank_not_zero_and_has_no_bucket():
    row = _row(storage_gb=None)
    assert [
        row[c] for c in ("MaxSizeGiB", "MaxSizeTiB", "MaxSizeGB", "MaxSizeTB", "SizeBucket")
    ] == [""] * 5


def test_unknown_usage_and_database_count_are_blank_not_zero():
    row = _row(utilized_bytes=None, database_count=None)
    assert [
        row[c]
        for c in ("Utilized_Bytes", "Utilized_GiB", "Utilized_TiB", "Utilized_GB", "Utilized_TB")
    ] == [""] * 5
    assert row["DatabaseCount"] == ""


def test_zero_usage_is_zero_not_blank():
    row = _row(utilized_bytes=0.0)
    assert (row["Utilized_Bytes"], row["Utilized_GiB"]) == ("0", "0")


def test_tag_lookup_is_case_sensitive_empty_values_are_kept_and_missing_tags_are_a_dash():
    result = _result(_server(tags={"Env": "dev", "owner": ""}), tag_names=("Env", "owner", "none"))
    row = _table(result)[0]
    assert row["Tag: Env"] == "dev"
    assert row["Tag: owner"] == ""
    assert row["Tag: none"] == "-"


def test_a_tag_spelled_in_another_case_is_not_found_by_the_listed_spelling():
    row = _table(_result(_server(tags={"env": "dev"}), tag_names=("Env",)))[0]
    assert row["Tag: Env"] == "-"


def test_an_empty_tag_value_is_written_as_a_quoted_empty_string_a_missing_value_as_nothing():
    text = _csv(_result(_server(tags={"owner": ""}, database_count=None), tag_names=("owner",)))
    data = text.splitlines()[1]
    assert data.endswith(',"-","False",""')
    assert ",," in data  # DatabaseCount is unknown, which is nothing between the commas


def test_only_postgresql_servers_are_in_the_file():
    result = _result(_server(name="pg1"), _server(name="my1", engine="MySQL"))
    assert [r["Server"] for r in _table(result)] == ["pg1"]


def test_rows_of_all_subscriptions_are_in_the_file():
    result = _result(_server(name="a"))
    result["database"].append({"subscription_id": "sub-2", "flexible_servers": [_server(name="b")]})
    result["subscription_names"]["sub-2"] = "Sub Two"
    rows = _table(result)
    assert [(r["Server"], r["Subscription"]) for r in rows] == [("a", "Sub One"), ("b", "Sub Two")]


# ── when the file is written ──────────────────────────────────────────────────


def _names(result) -> set[str]:
    return {
        n.split("-2026")[0].split("_2026")[0] for n in build_csv_files(result, "2026-10-22_1102")
    }


def test_no_file_is_written_when_there_is_no_postgresql_server():
    assert "azure_postgres_info" not in _names(_result())
    assert "azure_postgres_info" not in _names(_result(_server(engine="MySQL")))


def test_the_file_is_written_when_there_is_one_server():
    assert "azure_postgres_info" in _names(_result(_server()))


def test_the_skip_switch_stops_the_file_and_nothing_else():
    full = _names(_result(_server()))
    assert full - _names(_result(_server(), skipped=["postgres"])) == {"azure_postgres_info"}


# ── the summary and the totals ────────────────────────────────────────────────


def _summary(result) -> list[dict]:
    return csv_export.rows_by_file(result)["azure_sizing_summary"]


def test_the_summary_has_a_section_with_all_regions_then_each_region_by_name():
    result = _result(
        _server(name="a", raw_location="West US", storage_gb=100),
        _server(name="b", raw_location="East US 2", storage_gb=2048),
        _server(name="c", raw_location="East US 2", storage_gb=1024),
    )
    section = _summary(result)
    start = next(
        i
        for i, r in enumerate(section)
        if r["ResourceType"] == "[ Azure PostgreSQL Flexible Servers ]"
    )
    lines = section[start : start + 4]
    assert [(r["Region"], r["Count"]) for r in lines[1:]] == [
        ("All Regions", 3),
        ("East US 2", 2),
        ("West US", 1),
    ]
    assert lines[0]["TotalSizeTiB"] is None and lines[0].get("Count") is None
    assert lines[2]["TotalSizeTiB"] == 3.0
    assert lines[2]["TotalSizeTB"] == pytest.approx(2.199 + 1.0995)


def test_the_summary_has_no_section_without_servers():
    assert all("PostgreSQL" not in r["ResourceType"] for r in _summary(_result()))


def test_the_section_comes_after_the_aks_section():
    result = _result(_server())
    result["aks"] = [
        {
            "subscription_id": "sub-1",
            "clusters": [{"name": "k", "location": "eastus", "node_pools": [{"count": 1}]}],
        }
    ]
    types = [r["ResourceType"] for r in _summary(result) if r["ResourceType"]]
    assert types.index("[ Azure PostgreSQL Flexible Servers ]") > types.index(
        "[ Azure Kubernetes Service (AKS) Clusters ]"
    )


def _lines(result) -> list[str]:
    return totals.summary_lines(csv_export.rows_by_file(result))


def test_the_totals_say_how_many_servers_and_how_much_capacity():
    result = _result(_server(name="a", storage_gb=2048), _server(name="b", storage_gb=2048))
    lines = _lines(result)
    assert "Total # of Azure PostgreSQL Flexible Servers: 2" in lines
    assert (
        "Total capacity of all PostgreSQL Flexible Servers: 4,096 GiB or 4,398 GB or 4.0000 TiB or 4.3980 TB"
        in lines
    )


def test_the_capacity_keeps_four_decimals_and_thousands_separators():
    lines = _lines(_result(*[_server(name=f"s{i}", storage_gb=1024) for i in range(70)]))
    assert (
        "Total capacity of all PostgreSQL Flexible Servers: 71,680 GiB or 76,966 GB or 70.0000 TiB or 76.9650 TB"
        in lines
    )


def test_the_totals_follow_the_cosmos_line_and_come_before_the_aks_lines():
    result = _result(_server())
    result["cosmos"] = [{"subscription_id": "sub-1", "accounts": [{"name": "c"}]}]
    result["aks"] = [{"subscription_id": "sub-1", "clusters": [{"name": "k", "node_pools": []}]}]
    lines = _lines(result)
    cosmos = next(i for i, l in enumerate(lines) if l.startswith("Total # of Azure Cosmos DB"))
    pg = next(i for i, l in enumerate(lines) if l.startswith("Total # of Azure PostgreSQL"))
    aks = next(i for i, l in enumerate(lines) if l.startswith("Total # of Azure Kubernetes"))
    assert cosmos < pg < aks
    assert lines[pg - 1] == ""


def test_with_no_server_the_totals_still_report_zero_as_the_script_does():
    lines = _lines(_result())
    assert "Total # of Azure PostgreSQL Flexible Servers: 0" in lines
    assert (
        "Total capacity of all PostgreSQL Flexible Servers: 0 GiB or 0 GB or 0.0000 TiB or 0.0000 TB"
        in lines
    )


def test_the_totals_leave_the_section_out_when_it_is_skipped():
    assert not [l for l in _lines(_result(_server(), skipped=["postgres"])) if "PostgreSQL" in l]


# ── anonymizing ───────────────────────────────────────────────────────────────


def test_the_new_fields_are_anonymized_by_default():
    for field in (
        "AdministratorLogin",
        "VaultName",
        "DatasourceName",
        "DatasourceDatabase",
        "DatasourceResourceId",
        "BackupPolicies",
    ):
        assert field in DEFAULT_FIELDS


def test_the_postgres_file_is_anonymized_after_cosmos_and_before_aks():
    order = list(FILE_ORDER)
    assert (
        order.index("azure_cosmos_db")
        < order.index("azure_postgres_info")
        < order.index("azure_aks_info")
    )


def test_an_anonymized_run_hides_the_server_name_and_the_administrator_login():
    files = build_csv_files(_result(_server()), "2026-10-22_1102", Anonymizer())
    text = next(t for n, t in files.items() if n.startswith("azure_postgres_info"))
    assert "pg1" not in text and "pgadmin" not in text
    row = next(csv.DictReader(io.StringIO(text)))
    assert row["Server"] == "Server-00000"
    assert row["AdministratorLogin"] == "AdministratorLogin-00000"
    assert row["Utilized_GiB"] == "1061.4958"


# ── the access check ──────────────────────────────────────────────────────────


def test_the_access_check_row_feeds_the_file_and_follows_the_skip_switch():
    api = next(a for a in APIS if a.label == "postgresql flexible servers")
    assert "azure_postgres_info" in api.affects
    assert api.skip == "postgres"


# ── the collector ─────────────────────────────────────────────────────────────


def _pg(**kw) -> NS:
    server = _make_flex_server(
        "pg1",
        "rg-1",
        kw.pop("location", "Canada Central"),
        "PostgreSQL",
        "Standard_D4ds_v5",
        "GeneralPurpose",
        "17",
        2048,
        7,
        False,
        tags={"env": "dev"},
    )
    server.state = kw.pop("state", "Ready")
    server.administrator_login = kw.pop("administrator_login", "pgadmin")
    server.high_availability = kw.pop("high_availability", NS(mode="ZoneRedundant"))
    for key, value in kw.items():
        setattr(server, key, value)
    return server


def _series(*maxima) -> NS:
    return NS(value=[NS(timeseries=[NS(data=[NS(maximum=m) for m in maxima])])])


def _only(collector) -> NS:
    (server,) = [s for s in collector.collect().flexible_servers if s.engine == "PostgreSQL"]
    return server


def test_the_collector_reads_state_administrator_availability_and_the_raw_region():
    server = _only(_make_collector(pg_servers=[_pg()], mysql_servers=[]))
    assert server.state == "Ready"
    assert server.administrator_login == "pgadmin"
    assert server.high_availability_mode == "ZoneRedundant"
    assert server.geo_redundant_backup_text == "Disabled"
    assert server.raw_location == "Canada Central"
    assert server.location == "canadacentral"
    assert server.version == "17"


def test_a_server_without_availability_settings_has_no_mode():
    server = _only(_make_collector(pg_servers=[_pg(high_availability=None)], mysql_servers=[]))
    assert server.high_availability_mode is None


def test_enum_values_are_read_as_their_text_not_their_python_name():
    class Mode(str):
        value = "SameZone"

        def __str__(self) -> str:
            return "HighAvailabilityMode.SAME_ZONE"

    server = _only(
        _make_collector(
            pg_servers=[_pg(high_availability=NS(mode=Mode("SameZone")))], mysql_servers=[]
        )
    )
    assert server.high_availability_mode == "SameZone"


def test_the_utilized_bytes_are_the_highest_datapoint_and_a_trailing_empty_sample_is_ignored():
    effect = lambda **kw: _series(100.0, 900.0, 500.0, None)  # noqa: E731
    server = _only(_make_collector(pg_servers=[_pg()], mysql_servers=[], monitor_effect=effect))
    assert server.utilized_bytes == 900.0


def test_the_utilized_bytes_are_unknown_when_every_sample_is_empty_or_the_call_fails():
    assert (
        _only(
            _make_collector(
                pg_servers=[_pg()],
                mysql_servers=[],
                monitor_effect=lambda **kw: _series(None, None),
            )
        ).utilized_bytes
        is None
    )

    def fail(**kw):
        raise HttpResponseError(message="Forbidden")

    assert (
        _only(
            _make_collector(pg_servers=[_pg()], mysql_servers=[], monitor_effect=fail)
        ).utilized_bytes
        is None
    )


def test_the_utilized_metric_is_asked_for_as_a_maximum_over_a_day():
    calls = []

    def effect(**kw):
        calls.append(kw)
        return _series(1.0)

    _only(_make_collector(pg_servers=[_pg()], mysql_servers=[], monitor_effect=effect))
    used = [
        c for c in calls if c["metricnames"] == "storage_used" and c["aggregation"] == "Maximum"
    ]
    assert used and used[0]["metricnamespace"] == "Microsoft.DBforPostgreSQL/flexibleServers"


def test_a_region_filter_matches_the_display_name_of_a_server():
    pg = _pg(location="Canada Central")
    mock = _make_collector(pg_servers=[pg], mysql_servers=[])
    mock._regions = frozenset({"canadacentral"})
    assert [s.name for s in mock.collect().flexible_servers if s.engine == "PostgreSQL"] == ["pg1"]
    mock2 = _make_collector(pg_servers=[_pg()], mysql_servers=[])
    mock2._regions = frozenset({"eastus"})
    assert [s for s in mock2.collect().flexible_servers if s.engine == "PostgreSQL"] == []


def test_skipping_postgres_lists_no_postgres_server_but_still_the_mysql_ones():
    reference = _make_collector()
    with (
        patch("collectors.database.SqlManagementClient", return_value=reference._sql),
        patch("collectors.database.PostgreSQLFlexClient", return_value=reference._pg),
        patch("collectors.database.MySQLFlexClient", return_value=reference._mysql),
        patch("collectors.database.MonitorManagementClient", return_value=reference._monitor),
    ):
        collector = DatabaseCollector(SUB_ID, MagicMock(), collect_postgres=False)
    inventory = collector.collect()
    reference._pg.servers.list.assert_not_called()
    engines = {s.engine for s in inventory.flexible_servers}
    assert engines == {"MySQL"}


def test_an_unknown_database_count_does_not_break_the_roll_ups():
    def fail(rg, name):
        raise HttpResponseError(message="Forbidden")

    inventory = _make_collector(pg_servers=[_pg()], mysql_servers=[], pg_dbs_effect=fail).collect()
    assert inventory.total_databases == inventory.total_sql_databases

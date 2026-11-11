"""SQL database, elastic pool and managed instance files, and the data behind them.

Expected cell text comes from the real row blocks of Get-AzureSizingInfo.ps1 run in pwsh with the
Az cmdlets stubbed (same inputs as the cases below).
"""

from __future__ import annotations

import csv
import io
from types import SimpleNamespace as NS

import csv_export
from csv_export import build_csv_files
from tests.test_database import _make_collector


def _parse(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def _rows(text: str) -> list[dict[str, str]]:
    header, *rows = _parse(text)
    return [dict(zip(header, row)) for row in rows]


def _db(**overrides) -> dict:
    db = {
        "name": "d1",
        "server_name": "srv1",
        "location": "westus2",
        "resource_group": "rg-1",
        "database_id": "aaaaaaaa-0000-0000-0000-000000000001",
        "sku_name": "GP_Gen5_2",
        "status": "Online",
        "max_size_bytes": 34359738368,
        "allocated_bytes": 3.2e9,
        "utilized_bytes": 1.5e9,
        "ltr_weekly": "P1W",
        "ltr_monthly": "P4W",
        "ltr_yearly": "P5Y",
        "ltr_week_of_year": 3,
        "short_term_retention_days": 7,
        "diff_backup_interval_hours": 12,
        "db_tags": {"Env": "prod", "owner": ""},
    }
    db.update(overrides)
    return db


def _pool(name="poolA", **overrides) -> dict:
    pool = {
        "name": name,
        "server_name": "srv1",
        "resource_group": "rg-1",
        "location": "westus2",
        "sku_name": "GP_Gen5",
        "max_size_bytes": 219902325555,
    }
    pool.update(overrides)
    return pool


def _result(servers=(), instances=(), **overrides) -> dict:
    result = {
        "tenant_name": None,
        "tenant_id": "tenant-id-1",
        "subscription_names": {"sub-1": "Sub One"},
        "tag_names": {"sub-1": ["Env", "owner"]},
        "database": [
            {
                "subscription_id": "sub-1",
                "sql_servers": list(servers),
                "managed_instances": list(instances),
            }
        ],
    }
    result.update(overrides)
    return result


def _server(databases, pools=(), name="srv1") -> dict:
    return {"name": name, "databases": list(databases), "elastic_pools": list(pools)}


def _sql(result: dict) -> str:
    return build_csv_files(result, "S")["azure_sql_info-S.csv"]


def _mi(result: dict) -> str:
    return build_csv_files(result, "S")["azure_mi_sql_info-S.csv"]


# ── azure_sql_info ────────────────────────────────────────────────────────────


def test_database_row_matches_powershell():
    text = _sql(_result([_server([_db()])]))
    assert text.splitlines()[1] == (
        '"d1","srv1","","","32","0.0312","34.36","0.0344","Sub One","tenant-id-1","westus2",'
        '"rg-1","aaaaaaaa-0000-0000-0000-000000000001","GP_Gen5","Online","3200000000",'
        '"1500000000","P1W","P4W","P5Y","3","7","12","prod","-"'
    )
    assert _parse(text)[0][:23] == csv_export._SQL_COLUMNS


def test_empty_identity_columns_are_quoted_and_other_nulls_are_bare():
    db = _db(allocated_bytes=None, utilized_bytes=None, ltr_weekly=None, database_id="")
    (row,) = _parse(_sql(_result([_server([db])])))[1:]
    line = _sql(_result([_server([db])])).splitlines()[1]
    assert line.startswith('"d1","srv1","","",')
    assert ',"rg-1","","GP_Gen5","Online",,,' in line
    assert len(row) == 25


def test_tenant_and_subscription_fall_back_to_ids():
    result = _result([_server([_db()])], subscription_names={})
    (row,) = _rows(_sql(result))
    assert row["Subscription"] == "sub-1"
    assert row["Tenant"] == "tenant-id-1"
    result = _result([_server([_db()])], tenant_name="Contoso")
    assert _rows(_sql(result))[0]["Tenant"] == "Contoso"


def test_database_tag_lookup_is_case_sensitive():
    db = _db(db_tags={"env": "lower", "Owner": "x"})
    (row,) = _rows(_sql(_result([_server([db])])))
    assert row["Tag: Env"] == "-"
    assert row["Tag: owner"] == "-"


def test_a_pooled_database_is_replaced_by_every_pool_of_its_server():
    pooled = _db(name="d2", sku_name="ElasticPool")
    servers = [
        _server(
            [_db(), pooled, _db(name="d5", sku_name="ElasticPool")],
            [_pool("poolA"), _pool("poolB")],
        )
    ]
    rows = _rows(_sql(_result(servers)))
    assert [(r["Database"], r["ElasticPool"]) for r in rows] == [
        ("d1", ""),
        ("", "poolA"),
        ("", "poolB"),
    ]


def test_pool_row_matches_powershell():
    servers = [_server([_db(), _db(name="d2", sku_name="ElasticPool")], [_pool("poolA")])]
    line = _sql(_result(servers)).splitlines()[2]
    assert line == (
        '"","","poolA","","205","0.2","219.902","0.2199","Sub One","tenant-id-1","westus2","rg-1",'
        '"","GP_Gen5",,,,,,,,,,"-","-"'
    )


def test_pool_without_size_or_sku_has_zero_units_and_a_null_instance_type():
    servers = [
        _server([_db(sku_name="ElasticPool")], [_pool("poolB", sku_name=None, max_size_bytes=None)])
    ]
    (row,) = _rows(_sql(_result(servers)))
    assert (row["MaxSizeGiB"], row["MaxSizeTB"], row["InstanceType"], row["Status"]) == (
        "0",
        "0",
        "",
        "",
    )


def test_each_server_lists_its_own_pool_even_when_another_server_used_the_name():
    servers = [
        _server([_db(sku_name="ElasticPool")], [_pool("shared")]),
        _server(
            [_db(name="x", server_name="srv2", sku_name="ElasticPool")],
            [_pool("shared", server_name="srv2")],
            name="srv2",
        ),
    ]
    assert [r["ElasticPool"] for r in _rows(_sql(_result(servers)))] == ["shared", "shared"]


def test_system_databases_are_skipped():
    rows = _rows(_sql(_result([_server([_db(name="master", sku_name="System"), _db()])])))
    assert [r["Database"] for r in rows] == ["d1"]


def test_no_servers_gives_an_empty_file():
    assert _sql(_result()) == ""


# ── azure_mi_sql_info ─────────────────────────────────────────────────────────


def _instance(**overrides) -> dict:
    mi = {
        "name": "mi1",
        "location": "westus2",
        "resource_group": "rg-1",
        "storage_size_gb": 256,
        "sku_name": "GP_Gen5",
        "database_count": 4,
        "storage_space_used_mb": 123456.0,
        "tags": {"Env": "prod", "env": "lower"},
    }
    mi.update(overrides)
    return mi


def test_managed_instance_row_matches_powershell():
    text = _mi(_result(instances=[_instance()]))
    assert text.splitlines()[1] == (
        '"","","","mi1","256","0.25","274.878","0.2749","Sub One","tenant-id-1","westus2","rg-1",'
        '"","GP_Gen5",,"4","123456","prod","-"'
    )
    assert _parse(text)[0][:17] == csv_export._MI_COLUMNS


def test_managed_instance_without_size_database_count_or_metric():
    mi = _instance(
        storage_size_gb=None, database_count=None, storage_space_used_mb=None, sku_name=None
    )
    (row,) = _rows(_mi(_result(instances=[mi])))
    assert [row[c] for c in ("MaxSizeGiB", "MaxSizeGB", "Databases", "storage_space_used_mb")] == [
        "0",
        "0",
        "",
        "",
    ]
    assert row["InstanceType"] == ""


def test_managed_instance_tag_lookup_is_case_sensitive():
    (row,) = _rows(_mi(_result(instances=[_instance(tags={"env": "lower"})])))
    assert row["Tag: Env"] == "-"


def test_small_metric_value_is_written_like_dotnet():
    (row,) = _rows(_mi(_result(instances=[_instance(storage_space_used_mb=1.5e-05)])))
    assert row["storage_space_used_mb"] == "1.5E-05"


# ── data the files rely on ────────────────────────────────────────────────────


def _sql_server(name="srv1"):
    return NS(
        id=f"/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Sql/servers/{name}",
        name=name,
        location="westus2",
        version="12.0",
        tags={"srv": "tag"},
    )


def _sql_db(name, sku="GP_Gen5_2", **extra):
    return NS(
        id=f"/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Sql/servers/srv1/databases/{name}",
        name=name,
        sku=NS(name=sku, tier="GeneralPurpose"),
        max_size_bytes=34359738368,
        zone_redundant=False,
        **extra,
    )


def _metric(value):
    return NS(value=[NS(timeseries=[NS(data=[NS(maximum=None), NS(maximum=value)])])])


def test_database_fields_and_policies_are_collected():
    seen = []

    def monitor(resource_uri, **kwargs):
        seen.append((kwargs["metricnames"], kwargs["aggregation"]))
        if kwargs["aggregation"] != "Maximum":
            return NS(value=[])
        return _metric({"allocated_data_storage": 3.2e9, "storage": 1.5e9}[kwargs["metricnames"]])

    db = _sql_db(
        "d1",
        database_id="AAAAAAAA-0000-0000-0000-000000000001",
        status="Online",
        tags={"Env": "prod"},
    )
    collector = _make_collector(
        sql_servers=[_sql_server()],
        sql_dbs_effect=lambda rg, server: iter([db]),
        sql_str_effect=lambda *a: NS(retention_days=7, diff_backup_interval_in_hours=12),
        sql_ltr_effect=lambda *a: NS(
            weekly_retention="P1W", monthly_retention="P4W", yearly_retention="P5Y", week_of_year=3
        ),
        managed_instances=[],
        monitor_effect=monitor,
    )
    (server,) = collector.collect().sql_servers
    (info,) = server.databases
    assert info.database_id == "AAAAAAAA-0000-0000-0000-000000000001"
    assert info.status == "Online"
    assert info.db_tags == {"Env": "prod"}
    assert info.tags == {"srv": "tag"}
    assert (info.allocated_bytes, info.utilized_bytes) == (3.2e9, 1.5e9)
    assert (info.ltr_weekly, info.ltr_monthly, info.ltr_yearly, info.ltr_week_of_year) == (
        "P1W",
        "P4W",
        "P5Y",
        3,
    )
    assert (info.short_term_retention_days, info.diff_backup_interval_hours) == (7, 12)
    assert info.long_term_retention_enabled is True
    assert ("storage", "Maximum") in seen and ("allocated_data_storage", "Maximum") in seen


def test_failed_policy_lookups_leave_the_fields_empty_and_ltr_disabled():
    def fail(*args):
        raise RuntimeError("denied")

    collector = _make_collector(
        sql_servers=[_sql_server()],
        sql_dbs_effect=lambda rg, server: iter([_sql_db("d1")]),
        sql_str_effect=fail,
        sql_ltr_effect=fail,
        managed_instances=[],
    )
    (info,) = collector.collect().sql_servers[0].databases
    assert info.ltr_weekly is None and info.ltr_week_of_year is None
    assert info.short_term_retention_days is None and info.diff_backup_interval_hours is None
    assert info.long_term_retention_enabled is False


def test_pools_are_listed_only_for_a_server_with_a_pooled_database():
    pool = NS(name="poolA", location="WestUS2", sku=NS(name="GP_Gen5"), max_size_bytes=219902325555)
    collector = _make_collector(
        sql_servers=[_sql_server()],
        sql_dbs_effect=lambda rg, server: iter([_sql_db("d1"), _sql_db("d2", sku="ElasticPool")]),
        managed_instances=[],
    )
    collector._sql.elastic_pools.list_by_server.return_value = iter([pool])
    (server,) = collector.collect().sql_servers
    (info,) = server.elastic_pools
    assert (info.name, info.server_name, info.resource_group) == ("poolA", "srv1", "rg-1")
    assert (info.location, info.sku_name, info.max_size_bytes) == (
        "westus2",
        "GP_Gen5",
        219902325555,
    )

    plain = _make_collector(
        sql_servers=[_sql_server()],
        sql_dbs_effect=lambda rg, server: iter([_sql_db("d1")]),
        managed_instances=[],
    )
    plain.collect()
    plain._sql.elastic_pools.list_by_server.assert_not_called()


def test_managed_instance_database_count_and_maximum_metric():
    mi = NS(
        id="/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Sql/managedInstances/mi1",
        name="mi1",
        location="westus2",
        sku=NS(name="GP_Gen5", tier="GeneralPurpose"),
        storage_size_in_gb=256,
        v_cores=8,
        license_type="LicenseIncluded",
        zone_redundant=False,
        tags={},
    )

    def monitor(resource_uri, **kwargs):
        if kwargs["aggregation"] == "Maximum":
            return _metric(123456.0)
        return NS(value=[])

    collector = _make_collector(sql_servers=[], managed_instances=[mi], monitor_effect=monitor)
    collector._sql.managed_databases.list_by_instance.return_value = iter([NS(), NS(), NS()])
    (info,) = collector.collect().managed_instances
    assert info.database_count == 3
    assert info.storage_space_used_mb == 123456.0
    assert info.license_type == "LicenseIncluded"


def test_managed_instance_database_count_is_none_when_the_list_fails():
    mi = NS(
        id="/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Sql/managedInstances/mi1",
        name="mi1",
        location="westus2",
        sku=NS(name="GP_Gen5", tier="GeneralPurpose"),
        storage_size_in_gb=256,
        zone_redundant=False,
        tags={},
    )
    collector = _make_collector(sql_servers=[], managed_instances=[mi])
    collector._sql.managed_databases.list_by_instance.side_effect = RuntimeError("denied")
    (info,) = collector.collect().managed_instances
    assert info.database_count is None

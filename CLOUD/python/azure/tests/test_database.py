"""Tests for collectors/database.py."""

from __future__ import annotations

from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from collectors.database import (
    _LTR_EMPTY,
    _MYSQL_SYSTEM_DBS,
    _PG_SYSTEM_DBS,
    _SQL_SYSTEM_DBS,
    DatabaseCollector,
)

from tests.fixtures import (
    MOCK_MYSQL_DATABASES,
    MOCK_MYSQL_SERVERS,
    MOCK_PG_DATABASES,
    MOCK_PG_SERVERS,
    MOCK_SQL_DATABASES,
    MOCK_SQL_LTR,
    MOCK_SQL_MANAGED_INSTANCES,
    MOCK_SQL_SERVERS,
    MOCK_SQL_SHORT_TERM_RETENTION,
    RG_ANALYTICS,
    RG_DATA,
    RG_DEV,
    RG_PROD,
    SUB_ID,
    mock_mysql_dbs_effect,
    mock_pg_dbs_effect,
    mock_sql_dbs_effect,
    mock_sql_ltr_effect,
    mock_sql_short_term_retention_effect,
)


def _make_collector(
    sql_servers=None,
    sql_dbs_effect=None,
    sql_str_effect=None,
    sql_ltr_effect=None,
    managed_instances=None,
    pg_servers=None,
    pg_dbs_effect=None,
    mysql_servers=None,
    mysql_dbs_effect=None,
    monitor_effect=None,
) -> DatabaseCollector:
    """Return a DatabaseCollector with fully mocked Azure clients."""
    mock_sql = MagicMock()
    mock_sql.servers.list.return_value = iter(
        MOCK_SQL_SERVERS if sql_servers is None else sql_servers
    )
    mock_sql.databases.list_by_server.side_effect = sql_dbs_effect or mock_sql_dbs_effect
    mock_sql.backup_short_term_retention_policies.get.side_effect = (
        sql_str_effect or mock_sql_short_term_retention_effect
    )
    mock_sql.long_term_retention_policies.get.side_effect = sql_ltr_effect or mock_sql_ltr_effect
    mock_sql.managed_instances.list.return_value = iter(
        MOCK_SQL_MANAGED_INSTANCES if managed_instances is None else managed_instances
    )

    mock_pg = MagicMock()
    mock_pg.servers.list.return_value = iter(MOCK_PG_SERVERS if pg_servers is None else pg_servers)
    mock_pg.databases.list_by_server.side_effect = pg_dbs_effect or mock_pg_dbs_effect

    mock_mysql = MagicMock()
    mock_mysql.servers.list.return_value = iter(
        MOCK_MYSQL_SERVERS if mysql_servers is None else mysql_servers
    )
    mock_mysql.databases.list_by_server.side_effect = mysql_dbs_effect or mock_mysql_dbs_effect

    # Monitor metrics (used-storage lookups) default to "no data" → collectors fall back
    # to the provisioned size, so existing assertions hold. Override via monitor_effect.
    mock_monitor = MagicMock()
    if monitor_effect is not None:
        mock_monitor.metrics.list.side_effect = monitor_effect
    else:
        mock_monitor.metrics.list.return_value = NS(value=[])

    with (
        patch("collectors.database.SqlManagementClient", return_value=mock_sql),
        patch("collectors.database.PostgreSQLFlexClient", return_value=mock_pg),
        patch("collectors.database.MySQLFlexClient", return_value=mock_mysql),
        patch("collectors.database.MonitorManagementClient", return_value=mock_monitor),
    ):
        collector = DatabaseCollector(SUB_ID, MagicMock())

    return collector


class TestSystemDbConstants:
    def test_sql_system_dbs_contains_master(self):
        assert "master" in _SQL_SYSTEM_DBS

    def test_pg_system_dbs_contains_postgres(self):
        assert "postgres" in _PG_SYSTEM_DBS

    def test_mysql_system_dbs_contains_information_schema(self):
        assert "information_schema" in _MYSQL_SYSTEM_DBS

    def test_ltr_empty_contains_pt0s(self):
        assert "PT0S" in _LTR_EMPTY

    def test_ltr_empty_contains_none(self):
        assert None in _LTR_EMPTY


class TestSqlServers:
    def test_server_count(self):
        inventory = _make_collector().collect()
        assert inventory.total_sql_servers == 2

    def test_server_fields(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        assert srv.resource_group == RG_DATA
        assert srv.subscription_id == SUB_ID
        assert srv.location == "eastus"
        assert srv.version == "12.0"

    def test_server_tags(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        assert srv.tags["environment"] == "prod"
        assert srv.tags["owner"] == "dba-team"

    def test_http_error_returns_empty_server_list(self):
        mock_sql = MagicMock()
        mock_sql.servers.list.side_effect = HttpResponseError(message="Forbidden")
        mock_pg = MagicMock()
        mock_pg.servers.list.return_value = iter([])
        mock_mysql = MagicMock()
        mock_mysql.servers.list.return_value = iter([])

        with (
            patch("collectors.database.SqlManagementClient", return_value=mock_sql),
            patch("collectors.database.PostgreSQLFlexClient", return_value=mock_pg),
            patch("collectors.database.MySQLFlexClient", return_value=mock_mysql),
        ):
            collector = DatabaseCollector(SUB_ID, MagicMock())

        assert collector._list_sql_servers() == []

    def test_bad_server_skipped(self):
        # tags=5 is truthy so the guard passes, but dict(5) raises TypeError → skipped
        bad = NS(id=None, name=None, location="eastus", version=None, tags=5, sku=None)
        collector = _make_collector(sql_servers=list(MOCK_SQL_SERVERS) + [bad])
        inventory = collector.collect()
        assert inventory.total_sql_servers == 2
        assert all(s.tags != 5 for s in inventory.sql_servers)


class TestSqlDatabases:
    def test_user_database_count(self):
        inventory = _make_collector().collect()
        assert inventory.total_sql_databases == 3  # AW + SalesDB + DevDB (master filtered)

    def test_system_databases_excluded(self):
        inventory = _make_collector().collect()
        all_db_names = {db.name for srv in inventory.sql_servers for db in srv.databases}
        assert "master" not in all_db_names
        assert "tempdb" not in all_db_names

    def test_database_edition(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        aw = next(d for d in srv.databases if d.name == "AdventureWorks")
        assert aw.edition == "GeneralPurpose"

    def test_database_sku_name(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        aw = next(d for d in srv.databases if d.name == "AdventureWorks")
        assert aw.sku_name == "GP_Gen5_4"

    def test_database_max_size_gb(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        sales = next(d for d in srv.databases if d.name == "SalesDB")
        assert sales.max_size_gb == 512.0

    def test_database_max_size_bytes_and_tb(self):
        """max_size_bytes is recovered from the SDK's native bytes value (not re-derived
        from the rounded GB figure); max_size_tb is a straight /1024 conversion."""
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        sales = next(d for d in srv.databases if d.name == "SalesDB")
        assert sales.max_size_bytes == int(512.0 * 1024**3)
        assert sales.max_size_tb == round(512.0 / 1024, 3)
        assert sales.max_size_gb_decimal == 549.756
        assert sales.max_size_tb_decimal == 0.5498

    def test_database_backup_redundancy(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        aw = next(d for d in srv.databases if d.name == "AdventureWorks")
        assert aw.backup_storage_redundancy == "Geo"

    def test_database_zone_redundant_true(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        sales = next(d for d in srv.databases if d.name == "SalesDB")
        assert sales.zone_redundant is True

    def test_database_zone_redundant_false(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        aw = next(d for d in srv.databases if d.name == "AdventureWorks")
        assert aw.zone_redundant is False

    def test_database_tags_inherited_from_server(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        for db in srv.databases:
            assert db.tags["environment"] == "prod"

    def test_database_list_http_error_server_still_added(self):
        """If database listing fails the server is still added (with 0 dbs)."""

        def fail_db_list(rg, server_name):
            raise HttpResponseError(message="Forbidden")

        inventory = _make_collector(sql_dbs_effect=fail_db_list).collect()
        assert inventory.total_sql_servers == 2
        assert inventory.total_sql_databases == 0


class TestManagedInstances:
    def test_mi_count(self):
        inventory = _make_collector().collect()
        assert inventory.total_sql_mi_instances == 2

    def test_mi_fields(self):
        inventory = _make_collector().collect()
        mi = next(m for m in inventory.managed_instances if m.name == "mi-prod-eastus")
        assert mi.resource_group == RG_DATA
        assert mi.subscription_id == SUB_ID
        assert mi.location == "eastus"
        assert mi.sku_tier == "BusinessCritical"
        assert mi.sku_name == "BC_Gen5"
        assert mi.v_cores == 16
        assert mi.storage_size_gb == 2048
        assert mi.license_type == "LicenseIncluded"
        assert mi.backup_storage_redundancy == "Geo"
        # storage_size_gb is whole-GB-native (no true bytes possible) — both derived siblings
        # are computed straight from it.
        assert mi.storage_size_bytes_derived == 2048 * 1024**3
        assert mi.storage_size_tb == round(2048 / 1024, 3)
        assert mi.storage_size_gb_decimal == 2199.023
        assert mi.storage_size_tb_decimal == 2.199

    def test_mi_storage_rollup_gb(self):
        inventory = _make_collector().collect()
        # 2048 + 1024 GB from the fixture
        assert inventory.total_sql_mi_storage_gb == 3072

    def test_mi_tags_preserved(self):
        inventory = _make_collector().collect()
        mi = next(m for m in inventory.managed_instances if m.name == "mi-prod-eastus")
        assert mi.tags["environment"] == "prod"
        assert mi.tags["owner"] == "dba-team"

    def test_mi_empty_list_no_crash(self):
        inventory = _make_collector(managed_instances=[]).collect()
        assert inventory.total_sql_mi_instances == 0
        assert inventory.total_sql_mi_storage_gb == 0
        assert inventory.managed_instances == []

    def test_mi_http_error_returns_empty(self):
        def _raise_on_list():
            raise HttpResponseError(message="403")

        coll = _make_collector()
        coll._sql.managed_instances.list.side_effect = _raise_on_list
        coll._sql.managed_instances.list.return_value = None
        inventory = coll.collect()
        assert inventory.total_sql_mi_instances == 0

    def test_mi_skipped_when_region_filter_excludes(self):
        # Filter to westus2 only — both MIs are in eastus → both excluded.
        with (
            patch("collectors.database.SqlManagementClient"),
            patch("collectors.database.PostgreSQLFlexClient"),
            patch("collectors.database.MySQLFlexClient"),
        ):
            pass
        coll = _make_collector()
        coll._regions = frozenset({"westus2"})
        inventory = coll.collect()
        assert inventory.total_sql_mi_instances == 0

    def test_mi_engine_breakdown_entry(self):
        inventory = _make_collector().collect()
        assert inventory.engine_breakdown.get("SQL MI") == 2


class TestSqlShortTermRetention:
    def test_retention_days_populated(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        aw = next(d for d in srv.databases if d.name == "AdventureWorks")
        assert aw.short_term_retention_days == 35

    def test_retention_days_dev_db(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-dev-westus2")
        dev = next(d for d in srv.databases if d.name == "DevDB")
        assert dev.short_term_retention_days == 7

    def test_retention_exception_returns_none(self):
        def always_error(rg, server, db, policy):
            raise HttpResponseError(message="Unavailable")

        inventory = _make_collector(sql_str_effect=always_error).collect()
        for srv in inventory.sql_servers:
            for db in srv.databases:
                assert db.short_term_retention_days is None


class TestSqlLongTermRetention:
    def test_ltr_enabled_for_adventureworks(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        aw = next(d for d in srv.databases if d.name == "AdventureWorks")
        assert aw.long_term_retention_enabled is True

    def test_ltr_disabled_for_salesdb(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-prod-eastus")
        sales = next(d for d in srv.databases if d.name == "SalesDB")
        assert sales.long_term_retention_enabled is False

    def test_ltr_disabled_when_absent(self):
        """DevDB has no LTR entry → raises → returns False."""
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.sql_servers if s.name == "sql-dev-westus2")
        dev = next(d for d in srv.databases if d.name == "DevDB")
        assert dev.long_term_retention_enabled is False

    def test_ltr_exception_returns_false(self):
        def always_error(rg, server, db):
            raise HttpResponseError(message="Forbidden")

        inventory = _make_collector(sql_ltr_effect=always_error).collect()
        for srv in inventory.sql_servers:
            for db in srv.databases:
                assert db.long_term_retention_enabled is False


class TestPostgresFlexible:
    def test_pg_server_count(self):
        inventory = _make_collector().collect()
        pg = [s for s in inventory.flexible_servers if s.engine == "PostgreSQL"]
        assert len(pg) == 2

    def test_pg_server_fields(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.flexible_servers if s.name == "pg-prod-eastus")
        assert srv.resource_group == RG_DATA
        assert srv.location == "eastus"
        assert srv.engine == "PostgreSQL"
        assert srv.sku_name == "Standard_D4s_v3"
        assert srv.tier == "GeneralPurpose"
        assert srv.storage_gb == 128
        assert srv.backup_retention_days == 14
        assert srv.geo_redundant_backup is True
        # storage_gb is whole-GB-native from the SDK — the bytes sibling is derived.
        assert srv.storage_bytes_derived == 128 * 1024**3
        assert srv.storage_tb == round(128 / 1024, 3)
        assert srv.storage_gb_decimal == 137.439
        assert srv.storage_tb_decimal == 0.1374

    def test_pg_dev_geo_redundant_false(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.flexible_servers if s.name == "pg-dev-westus2")
        assert srv.geo_redundant_backup is False

    def test_pg_database_count_excludes_system_dbs(self):
        inventory = _make_collector().collect()
        prod = next(s for s in inventory.flexible_servers if s.name == "pg-prod-eastus")
        # appdb + analyticsdb (postgres filtered)
        assert prod.database_count == 2

    def test_pg_dev_database_count(self):
        inventory = _make_collector().collect()
        dev = next(s for s in inventory.flexible_servers if s.name == "pg-dev-westus2")
        # testdb only (azure_maintenance filtered)
        assert dev.database_count == 1

    def test_pg_database_count_is_unknown_not_zero_when_the_list_fails(self):
        def fail_dbs(rg, server_name):
            raise HttpResponseError(message="Forbidden")

        collector = _make_collector(pg_dbs_effect=fail_dbs)
        inventory = collector.collect()
        postgres = [s for s in inventory.flexible_servers if s.engine == "PostgreSQL"]
        assert postgres and all(srv.database_count is None for srv in postgres)

    def test_pg_http_error_returns_empty(self):
        mock_pg = MagicMock()
        mock_pg.servers.list.side_effect = HttpResponseError(message="Forbidden")
        mock_pg.databases.list_by_server.return_value = iter([])

        mock_sql = MagicMock()
        mock_sql.servers.list.return_value = iter([])
        mock_mysql = MagicMock()
        mock_mysql.servers.list.return_value = iter([])

        with (
            patch("collectors.database.SqlManagementClient", return_value=mock_sql),
            patch("collectors.database.PostgreSQLFlexClient", return_value=mock_pg),
            patch("collectors.database.MySQLFlexClient", return_value=mock_mysql),
        ):
            collector = DatabaseCollector(SUB_ID, MagicMock())

        pg_servers = collector._list_flexible_servers("PostgreSQL")
        assert pg_servers == []


class TestMySQLFlexible:
    def test_mysql_server_count(self):
        inventory = _make_collector().collect()
        mysql = [s for s in inventory.flexible_servers if s.engine == "MySQL"]
        assert len(mysql) == 1

    def test_mysql_server_fields(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.flexible_servers if s.engine == "MySQL")
        assert srv.name == "mysql-prod-eastus"
        assert srv.tier == "MemoryOptimized"
        assert srv.storage_gb == 64
        assert srv.backup_retention_days == 7
        assert srv.geo_redundant_backup is True

    def test_mysql_database_count_excludes_system_dbs(self):
        inventory = _make_collector().collect()
        srv = next(s for s in inventory.flexible_servers if s.engine == "MySQL")
        # wordpressdb only (mysql + information_schema filtered)
        assert srv.database_count == 1


class TestRegionFilter:
    def test_sql_eastus_only(self):
        collector = _make_collector()
        collector._regions = frozenset(["eastus"])
        servers = collector._list_sql_servers()
        assert len(servers) == 1
        assert servers[0].name == "sql-prod-eastus"

    def test_sql_westus2_only(self):
        collector = _make_collector()
        collector._regions = frozenset(["westus2"])
        servers = collector._list_sql_servers()
        assert len(servers) == 1
        assert servers[0].name == "sql-dev-westus2"

    def test_pg_westus2_only(self):
        collector = _make_collector()
        collector._regions = frozenset(["westus2"])
        servers = collector._list_flexible_servers("PostgreSQL")
        assert len(servers) == 1
        assert servers[0].name == "pg-dev-westus2"

    def test_mysql_eastus_only(self):
        collector = _make_collector()
        collector._regions = frozenset(["eastus"])
        servers = collector._list_flexible_servers("MySQL")
        assert len(servers) == 1

    def test_no_filter_returns_all(self):
        collector = _make_collector()
        assert collector._regions is None
        inventory = collector.collect()
        assert inventory.total_sql_servers == 2
        assert inventory.total_flexible_servers == 3


class TestRollups:
    def test_total_sql_servers(self):
        assert _make_collector().collect().total_sql_servers == 2

    def test_total_sql_databases(self):
        assert _make_collector().collect().total_sql_databases == 3

    def test_total_flexible_servers(self):
        assert _make_collector().collect().total_flexible_servers == 3

    def test_total_databases(self):
        # 3 SQL user dbs + 3 PG user dbs + 1 MySQL user db = 7
        assert _make_collector().collect().total_databases == 7

    def test_engine_breakdown_azure_sql(self):
        assert _make_collector().collect().engine_breakdown["Azure SQL"] == 3

    def test_engine_breakdown_postgresql(self):
        # appdb + analyticsdb + testdb = 3
        assert _make_collector().collect().engine_breakdown["PostgreSQL"] == 3

    def test_engine_breakdown_mysql(self):
        assert _make_collector().collect().engine_breakdown["MySQL"] == 1

    def test_edition_breakdown(self):
        eb = _make_collector().collect().edition_breakdown
        assert eb["GeneralPurpose"] == 1  # AdventureWorks
        assert eb["BusinessCritical"] == 1  # SalesDB
        assert eb["Standard"] == 1  # DevDB

    def test_tier_breakdown(self):
        tb = _make_collector().collect().tier_breakdown
        assert tb["GeneralPurpose"] == 1  # pg-prod
        assert tb["Burstable"] == 1  # pg-dev
        assert tb["MemoryOptimized"] == 1  # mysql-prod

    def test_avg_short_term_retention(self):
        inv = _make_collector().collect()
        # (35 + 14 + 7) / 3 = 56/3 ≈ 18.7
        assert inv.avg_short_term_retention_days == 18.7

    def test_avg_retention_none_when_all_unavailable(self):
        def always_error(rg, server, db, policy):
            raise ResourceNotFoundError(message="Unavailable")

        inv = _make_collector(sql_str_effect=always_error).collect()
        assert inv.avg_short_term_retention_days is None

    def test_tag_summary_built(self):
        inv = _make_collector().collect()
        assert inv.tag_summary is not None
        assert "environment" in inv.tag_summary.key_coverage

    def test_tag_summary_environment_coverage(self):
        inv = _make_collector().collect()
        # All 5 servers have "environment" tag → 100%
        assert inv.tag_summary.key_coverage["environment"] == 100.0


# ── Actual used-storage via Monitor metrics (parity with AWS Aurora cluster sizing) ──


def _metric_result(value):
    """Shape a MonitorManagementClient.metrics.list() result with one datapoint."""
    return NS(value=[NS(timeseries=[NS(data=[NS(average=value)])])])


class TestUsedStorageMetric:
    def test_sql_db_used_storage_from_metric_not_provisioned_max(self):
        # "storage" metric (bytes) → used_storage_gb; max_size_gb still the provisioned ceiling.
        def eff(resource_uri, **kw):
            if kw.get("metricnames") == "storage":
                return _metric_result(50 * 1024**3)  # 50 GB used
            return NS(value=[])

        inv = _make_collector(monitor_effect=eff).collect()
        dbs = [d for s in inv.sql_servers for d in s.databases]
        assert dbs, "expected at least one SQL database in the mock data"
        assert all(d.used_storage_gb == 50.0 for d in dbs)
        assert all(d.max_size_gb is not None for d in dbs)  # provisioned still captured
        # used_storage_bytes is recovered from the raw Monitor "storage" metric (bytes-native,
        # not re-derived from the rounded GB value); used_storage_tb is a /1024 conversion.
        assert all(d.used_storage_bytes == 50 * 1024**3 for d in dbs)
        assert all(d.used_storage_tb == round(50.0 / 1024, 3) for d in dbs)
        assert all(d.used_storage_gb_decimal == 53.687 for d in dbs)
        assert all(d.used_storage_tb_decimal == 0.0537 for d in dbs)

    def test_used_storage_none_when_metric_unavailable(self):
        # Default monitor mock returns no data → used_storage_gb None (falls back downstream).
        inv = _make_collector().collect()
        dbs = [d for s in inv.sql_servers for d in s.databases]
        assert all(d.used_storage_gb is None for d in dbs)
        assert all(d.used_storage_bytes is None for d in dbs)
        assert all(d.used_storage_tb is None for d in dbs)

    def test_mi_used_storage_mb_converted_to_gb(self):
        def eff(resource_uri, **kw):
            if kw.get("metricnames") == "storage_space_used_mb":
                return _metric_result(20480)  # 20480 MB = 20 GB
            return NS(value=[])

        inv = _make_collector(monitor_effect=eff).collect()
        assert inv.managed_instances, "expected at least one managed instance"
        assert all(mi.used_storage_gb == 20.0 for mi in inv.managed_instances)
        # SQL MI's native metric is MB, not bytes — the bytes sibling is explicitly
        # _derived (mb * 1024**2), never claimed as true byte precision.
        assert all(mi.used_storage_bytes_derived == 20480 * 1024**2 for mi in inv.managed_instances)
        assert all(mi.used_storage_tb == round(20.0 / 1024, 3) for mi in inv.managed_instances)

    def test_flexible_namespace_is_engine_specific(self):
        seen = {}

        def eff(resource_uri, **kw):
            seen[kw.get("metricnamespace")] = kw.get("metricnames")
            return NS(value=[])

        _make_collector(monitor_effect=eff).collect()
        assert "Microsoft.DBforPostgreSQL/flexibleServers" in seen
        assert "Microsoft.DBforMySQL/flexibleServers" in seen
        assert seen["Microsoft.DBforPostgreSQL/flexibleServers"] == "storage_used"


# ── long-term retention policy ────────────────────────────────────────────────


class TestLongTermRetention:
    @staticmethod
    def _databases(collector):
        return [d for s in collector.collect().sql_servers for d in s.databases]

    def test_the_policy_is_asked_for_by_name(self):
        collector = _make_collector()
        collector.collect()
        calls = collector._sql.long_term_retention_policies.get.call_args_list
        assert calls and all(c.args[3] == "default" for c in calls)

    def test_the_policy_values_reach_the_database(self):
        by_name = {d.name: d for d in self._databases(_make_collector())}
        assert (by_name["AdventureWorks"].ltr_weekly, by_name["AdventureWorks"].ltr_yearly) == (
            "P12W",
            "P5Y",
        )
        assert by_name["AdventureWorks"].long_term_retention_enabled is True
        assert by_name["SalesDB"].long_term_retention_enabled is False

    def test_a_database_with_no_policy_is_an_answer_not_a_failure(self, caplog):
        with caplog.at_level("WARNING"):
            self._databases(_make_collector())
        assert not [r for r in caplog.records if "Long-term retention" in r.getMessage()]

    @pytest.mark.parametrize("status", [400, 404])
    def test_not_supported_and_not_found_answers_are_not_failures(self, status, caplog):
        error = HttpResponseError(message="Long Term Retention is not supported")
        error.status_code = status

        def effect(*args):
            raise error

        with caplog.at_level("WARNING"):
            self._databases(_make_collector(sql_ltr_effect=effect))
        assert not [r for r in caplog.records if "Long-term retention" in r.getMessage()]

    @pytest.mark.parametrize(
        "error",
        [
            TypeError("get() missing 1 required positional argument: 'policy_name'"),
            HttpResponseError(message="forbidden"),
        ],
    )
    def test_any_other_error_is_a_warning_that_counts_the_databases(self, error, caplog):
        if isinstance(error, HttpResponseError):
            error.status_code = 403

        def effect(*args):
            raise error

        with caplog.at_level("WARNING"):
            databases = self._databases(_make_collector(sql_ltr_effect=effect))
        [message] = [
            r.getMessage() for r in caplog.records if "Long-term retention" in r.getMessage()
        ]
        assert f"for {len(databases)} database(s)" in message and str(error) in message
        assert all(d.ltr_weekly is None for d in databases)

    def test_the_warning_is_once_per_collection_not_once_per_database(self, caplog):
        def effect(*args):
            raise TypeError("boom")

        with caplog.at_level("WARNING"):
            self._databases(_make_collector(sql_ltr_effect=effect))
        assert len([r for r in caplog.records if "Long-term retention" in r.getMessage()]) == 1

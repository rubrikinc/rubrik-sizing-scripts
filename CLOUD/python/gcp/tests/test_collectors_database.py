"""Tests for collectors/database.py — all GCP SDK calls are mocked."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from collectors.database import DatabaseCollector

from tests.conftest import PROJECT_ID

_SQLADMIN_BUILD = "googleapiclient.discovery.build"
_SPANNER_CLIENT = "google.cloud.spanner_admin_instance_v1.InstanceAdminClient"
_SPANNER_DB_CLIENT = "google.cloud.spanner_admin_database_v1.DatabaseAdminClient"
_ALLOYDB_CLIENT = "google.cloud.alloydb_v1.AlloyDBAdminClient"
_BIGTABLE_CLIENT = "google.cloud.bigtable.Client"


@pytest.fixture(autouse=True)
def _no_spanner_database_listing():
    """Default: the database admin client lists no databases. Tests that care patch it."""
    with patch(_SPANNER_DB_CLIENT, return_value=MagicMock(list_databases=lambda **_: [])):
        yield


# ── Cloud SQL helpers ─────────────────────────────────────────────────────────


def _make_sql_response(items: list[dict]) -> dict:
    return {"items": items}


def _sql_item(
    name: str = "sql-1",
    region: str = "us-central1",
    database_version: str = "MYSQL_8_0",
    tier: str = "db-n1-standard-2",
    state: str = "RUNNABLE",
):
    return {
        "name": name,
        "region": region,
        "databaseVersion": database_version,
        "state": state,
        "settings": {
            "tier": tier,
            "dataDiskType": "PD_SSD",
            "dataDiskSizeGb": "100",
            "availabilityType": "ZONAL",
            "backupConfiguration": {"enabled": True},
        },
        "userLabels": {"env": "prod"},
    }


def _mock_sqladmin_service(items: list[dict]):
    """Return a mock sqladmin service that returns items in one page."""
    mock_service = MagicMock()
    mock_list = MagicMock()
    mock_list.execute.return_value = _make_sql_response(items)
    mock_service.instances.return_value.list.return_value = mock_list
    mock_service.instances.return_value.list_next.return_value = None
    return mock_service


# ── Spanner helpers ───────────────────────────────────────────────────────────


def _make_spanner_instance(name: str = "projects/p/instances/span-1", node_count: int = 3):
    inst = MagicMock()
    inst.name = name
    inst.config = "projects/p/instanceConfigs/nam6"
    inst.display_name = "Spanner Instance"
    inst.node_count = node_count
    inst.processing_units = 0
    inst.state = MagicMock()
    inst.state.name = "READY"
    inst.labels = {}
    return inst


# ── Tests: Cloud SQL ──────────────────────────────────────────────────────────


def test_database_collector_cloud_sql_instances():
    items = [
        _sql_item("sql-1", database_version="MYSQL_8_0"),
        _sql_item("sql-2", database_version="POSTGRES_15"),
    ]
    mock_svc = _mock_sqladmin_service(items)

    with patch(_SQLADMIN_BUILD, return_value=mock_svc):
        with patch(_SPANNER_CLIENT, return_value=MagicMock(list_instances=lambda **_: [])):
            with patch(_ALLOYDB_CLIENT, return_value=MagicMock(list_clusters=lambda **_: [])):
                with patch(_BIGTABLE_CLIENT, return_value=MagicMock(list_instances=lambda: ([],))):
                    result = DatabaseCollector(PROJECT_ID, MagicMock()).collect()

    assert len(result.cloud_sql_instances) == 2
    assert result.cloud_sql_instances[0].database_version == "MYSQL_8_0"
    assert result.cloud_sql_instances[0].storage_size_gb == 100
    assert result.cloud_sql_instances[0].storage_size_bytes_derived == 100 * 1_000_000_000
    assert result.cloud_sql_instances[0].storage_size_tb == round(100 / 1000, 4)


def test_database_collector_engine_breakdown():
    items = [
        _sql_item("sql-mysql", database_version="MYSQL_8_0"),
        _sql_item("sql-pg", database_version="POSTGRES_15"),
        _sql_item("sql-mssql", database_version="SQLSERVER_2019_STANDARD"),
    ]
    mock_svc = _mock_sqladmin_service(items)

    with patch(_SQLADMIN_BUILD, return_value=mock_svc):
        with patch(_SPANNER_CLIENT, return_value=MagicMock(list_instances=lambda **_: [])):
            with patch(_ALLOYDB_CLIENT, return_value=MagicMock(list_clusters=lambda **_: [])):
                with patch(_BIGTABLE_CLIENT, return_value=MagicMock(list_instances=lambda: ([],))):
                    result = DatabaseCollector(PROJECT_ID, MagicMock()).collect()

    assert result.engine_breakdown["MYSQL"] == 1
    assert result.engine_breakdown["POSTGRES"] == 1
    assert result.engine_breakdown["SQLSERVER"] == 1


def test_database_collector_sql_graceful_on_error():
    with patch(_SQLADMIN_BUILD, side_effect=Exception("403 sqladmin API not enabled")):
        with patch(_SPANNER_CLIENT, return_value=MagicMock(list_instances=lambda **_: [])):
            with patch(_ALLOYDB_CLIENT, return_value=MagicMock(list_clusters=lambda **_: [])):
                with patch(_BIGTABLE_CLIENT, return_value=MagicMock(list_instances=lambda: ([],))):
                    result = DatabaseCollector(PROJECT_ID, MagicMock()).collect()

    assert result.cloud_sql_instances == []
    assert result.total_databases == 0


# ── Tests: Spanner ────────────────────────────────────────────────────────────


def test_database_collector_spanner_instances():
    spanner_instances = [_make_spanner_instance("projects/p/instances/span-1", node_count=3)]
    mock_spanner_client = MagicMock()
    mock_spanner_client.list_instances.return_value = iter(spanner_instances)

    with patch(_SQLADMIN_BUILD, return_value=_mock_sqladmin_service([])):
        with patch(_SPANNER_CLIENT, return_value=mock_spanner_client):
            with patch(_ALLOYDB_CLIENT, return_value=MagicMock(list_clusters=lambda **_: [])):
                with patch(_BIGTABLE_CLIENT, return_value=MagicMock(list_instances=lambda: ([],))):
                    result = DatabaseCollector(PROJECT_ID, MagicMock()).collect()

    assert len(result.spanner_instances) == 1
    assert result.spanner_instances[0].node_count == 3
    assert result.engine_breakdown.get("SPANNER") == 1


def test_database_collector_spanner_graceful_on_error():
    mock_spanner_client = MagicMock()
    mock_spanner_client.list_instances.side_effect = Exception("API not enabled")

    with patch(_SQLADMIN_BUILD, return_value=_mock_sqladmin_service([])):
        with patch(_SPANNER_CLIENT, return_value=mock_spanner_client):
            with patch(_ALLOYDB_CLIENT, return_value=MagicMock(list_clusters=lambda **_: [])):
                with patch(_BIGTABLE_CLIENT, return_value=MagicMock(list_instances=lambda: ([],))):
                    result = DatabaseCollector(PROJECT_ID, MagicMock()).collect()

    assert result.spanner_instances == []


# ── Tests: total count ────────────────────────────────────────────────────────


def test_database_collector_total_count():
    sql_items = [_sql_item("sql-1"), _sql_item("sql-2")]
    spanner_inst = [_make_spanner_instance()]
    mock_spanner = MagicMock()
    mock_spanner.list_instances.return_value = iter(spanner_inst)

    with patch(_SQLADMIN_BUILD, return_value=_mock_sqladmin_service(sql_items)):
        with patch(_SPANNER_CLIENT, return_value=mock_spanner):
            with patch(_ALLOYDB_CLIENT, return_value=MagicMock(list_clusters=lambda **_: [])):
                with patch(_BIGTABLE_CLIENT, return_value=MagicMock(list_instances=lambda: ([],))):
                    result = DatabaseCollector(PROJECT_ID, MagicMock()).collect()

    assert result.total_databases == 3  # 2 SQL + 1 Spanner


def test_database_collector_label_summary():
    items = [_sql_item("sql-1")]
    mock_svc = _mock_sqladmin_service(items)

    with patch(_SQLADMIN_BUILD, return_value=mock_svc):
        with patch(_SPANNER_CLIENT, return_value=MagicMock(list_instances=lambda **_: [])):
            with patch(_ALLOYDB_CLIENT, return_value=MagicMock(list_clusters=lambda **_: [])):
                with patch(_BIGTABLE_CLIENT, return_value=MagicMock(list_instances=lambda: ([],))):
                    result = DatabaseCollector(PROJECT_ID, MagicMock()).collect()

    assert result.label_summary is not None
    assert "env" in result.label_summary.key_coverage


# ── Structured error capture ────────────────────────────────────────────────────


def test_engine_failure_records_structured_error():
    """A failing engine records a categorised CollectionError on the collector."""
    collector = DatabaseCollector(PROJECT_ID, MagicMock())
    with patch(
        _SPANNER_CLIENT,
        side_effect=Exception(
            "403 Cloud Spanner API has not been used in project foo or it is disabled. "
            '[reason: "SERVICE_DISABLED"]'
        ),
    ):
        result = collector._collect_spanner()

    assert result == []
    assert len(collector.errors) == 1
    err = collector.errors[0]
    assert err["collector"] == "database:spanner"
    assert err["category"] == "API_DISABLED"
    assert "[reason" not in err["message"]  # protobuf detail stripped


def test_spanner_database_count_per_instance():
    mock_spanner = MagicMock()
    mock_spanner.list_instances.return_value = iter(
        [
            _make_spanner_instance("projects/p/instances/a"),
            _make_spanner_instance("projects/p/instances/b"),
        ]
    )
    counts = {"projects/p/instances/a": 3, "projects/p/instances/b": 0}
    db_client = MagicMock()
    db_client.list_databases.side_effect = lambda parent: [object()] * counts[parent]

    collector = DatabaseCollector(PROJECT_ID, MagicMock())
    with patch(_SPANNER_CLIENT, return_value=mock_spanner), patch(
        _SPANNER_DB_CLIENT, return_value=db_client
    ):
        instances = collector._collect_spanner()

    assert {i.name: i.database_count for i in instances} == {"a": 3, "b": 0}
    assert collector.errors == []


def test_spanner_database_listing_failure_is_zero_and_recorded():
    mock_spanner = MagicMock()
    mock_spanner.list_instances.return_value = iter([_make_spanner_instance()])
    db_client = MagicMock()
    db_client.list_databases.side_effect = Exception("403 permission denied")

    collector = DatabaseCollector(PROJECT_ID, MagicMock())
    with patch(_SPANNER_CLIENT, return_value=mock_spanner), patch(
        _SPANNER_DB_CLIENT, return_value=db_client
    ):
        instances = collector._collect_spanner()

    assert instances[0].database_count == 0
    assert [e["collector"] for e in collector.errors] == ["database:spanner_databases"]


def test_spanner_processing_units_not_derived_from_node_count():
    reported = _make_spanner_instance("projects/p/instances/pu", node_count=0)
    reported.processing_units = 500
    node_only = _make_spanner_instance("projects/p/instances/nodes", node_count=3)
    node_only.processing_units = 0
    mock_spanner = MagicMock()
    mock_spanner.list_instances.return_value = iter([reported, node_only])

    collector = DatabaseCollector(PROJECT_ID, MagicMock())
    with patch(_SPANNER_CLIENT, return_value=mock_spanner):
        instances = {i.name: i for i in collector._collect_spanner()}

    assert instances["pu"].processing_units == 500
    assert instances["nodes"].processing_units == 0 and instances["nodes"].node_count == 3

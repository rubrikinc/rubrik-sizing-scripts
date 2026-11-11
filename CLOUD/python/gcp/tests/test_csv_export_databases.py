"""gce_cloudsql_info and gce_spanner_info, and the collector data behind them.

Expected lines were produced by the real ``Get-GCPCloudSQLInstances`` and ``Get-GCPSpannerInstances``
of Get-GCPSizingInfo.ps1, run in pwsh with a ``gcloud`` function returning fixture JSON. The Python
side of that comparison ran the real ``DatabaseCollector`` on the same JSON.
"""

from __future__ import annotations

import csv
import io
from unittest.mock import MagicMock, patch

import pytest

from collectors.database import DatabaseCollector, _system_databases
from csv_export import _engine, build_csv_files


def _parse(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def _sql(name, version, **kwargs) -> dict:
    base = {
        "name": name,
        "database_version": version,
        "instance_type": "CLOUD_SQL_INSTANCE",
        "region": "us-central1",
        "tier": "db-custom-2-7680",
        "data_disk_size_gb": 100.0,
        "storage_type": "PD_SSD",
        "state": "RUNNABLE",
        "number_of_databases": 2,
        "automated_backup_enabled": False,
        "backup_retention_count": None,
        "backup_start_time": None,
        "availability_type": "REGIONAL",
        "labels": {"env": "x", "team": "y"},
    }
    base.update(kwargs)
    return base


def _spanner(name, **kwargs) -> dict:
    base = {
        "name": name,
        "display_name": "Spanner",
        "config": "nam6",
        "state": "READY",
        "database_count": 0,
        "node_count": 0,
        "processing_units": 0,
        "labels": {"env": "x", "team": "y"},
    }
    base.update(kwargs)
    return base


def _result() -> dict:
    backup = {
        "automated_backup_enabled": True,
        "backup_retention_count": 7,
        "backup_start_time": "03:00",
    }
    return {
        "projects_scanned": ["proj-a", "proj-b"],
        "databases": [
            {
                "project_id": "proj-b",
                "cloud_sql_instances": [
                    _sql("pg2", "POSTGRES_16", number_of_databases=1, **backup)
                ],
                "spanner_instances": [],
            },
            {
                "project_id": "proj-a",
                "cloud_sql_instances": [
                    _sql("pg1", "POSTGRES_15", **backup),
                    _sql(
                        "my1",
                        "MYSQL_8_0",
                        instance_type="READ_REPLICA_INSTANCE",
                        data_disk_size_gb=250.0,
                        availability_type="ZONAL",
                        number_of_databases=1,
                    ),
                    _sql(
                        "ss1",
                        "SQLSERVER_2019_STANDARD",
                        data_disk_size_gb=0.0,
                        number_of_databases=3,
                        automated_backup_enabled=True,
                        backup_retention_count=30,
                    ),
                    _sql("other1", "FIREBIRD_1_0"),
                    _sql(
                        "min1",
                        "MYSQL_5_7",
                        tier="db-f1-micro",
                        data_disk_size_gb=None,
                        availability_type=None,
                        number_of_databases=0,
                    ),
                    _sql("fail1", "POSTGRES_14", number_of_databases=None),
                ],
                "spanner_instances": [
                    _spanner(
                        "sp1",
                        display_name="Spanner One",
                        config="regional-us-central1",
                        database_count=2,
                        node_count=3,
                        processing_units=3000,
                    ),
                    _spanner(
                        "sp2", display_name="Spanner Two", database_count=1, processing_units=500
                    ),
                    _spanner("sp3", display_name="Spanner Three", config="eur3", state="CREATING"),
                    _spanner(
                        "sp4",
                        display_name="Spanner Four",
                        config="regional-us-east1",
                        node_count=1,
                        processing_units=1000,
                    ),
                ],
            },
        ],
    }


def test_cloudsql_file_matches_powershell():
    lines = build_csv_files(_result(), "S")["gce_cloudsql_info-S.csv"].splitlines()
    assert lines == [
        '"Project","InstanceName","InstanceType","DatabaseEngine","EngineVersion","Region","Tier","StorageSizeGb","StorageSizeTb","StorageType","State","NumberOfDatabases","BackupEnabled","BackupRetentionCount","BackupStartTime","AvailabilityType","Label/Tag: env","Label/Tag: team"',
        '"proj-a","pg1","CLOUD_SQL_INSTANCE","PostgreSQL","POSTGRES_15","us-central1","db-custom-2-7680","100","0.1","PD_SSD","RUNNABLE","2","True","7","03:00","REGIONAL","x","y"',
        '"proj-a","my1","READ_REPLICA_INSTANCE","MySQL","MYSQL_8_0","us-central1","db-custom-2-7680","250","0.25","PD_SSD","RUNNABLE","1","False",,,"ZONAL","x","y"',
        '"proj-a","ss1","CLOUD_SQL_INSTANCE","SQL Server","SQLSERVER_2019_STANDARD","us-central1","db-custom-2-7680","0","0","PD_SSD","RUNNABLE","3","True","30",,"REGIONAL","x","y"',
        '"proj-a","other1","CLOUD_SQL_INSTANCE","FIREBIRD_1_0","FIREBIRD_1_0","us-central1","db-custom-2-7680","100","0.1","PD_SSD","RUNNABLE","2","False",,,"REGIONAL","x","y"',
        '"proj-a","min1","CLOUD_SQL_INSTANCE","MySQL","MYSQL_5_7","us-central1","db-f1-micro","0","0","PD_SSD","RUNNABLE","0","False",,,,"x","y"',
        # PowerShell writes 0 for a database listing that failed; the count is empty here.
        '"proj-a","fail1","CLOUD_SQL_INSTANCE","PostgreSQL","POSTGRES_14","us-central1","db-custom-2-7680","100","0.1","PD_SSD","RUNNABLE",,"False",,,"REGIONAL","x","y"',
        '"proj-b","pg2","CLOUD_SQL_INSTANCE","PostgreSQL","POSTGRES_16","us-central1","db-custom-2-7680","100","0.1","PD_SSD","RUNNABLE","1","True","7","03:00","REGIONAL","x","y"',
    ]


def test_spanner_file_matches_powershell():
    lines = build_csv_files(_result(), "S")["gce_spanner_info-S.csv"].splitlines()
    assert lines == [
        '"Project","InstanceName","DisplayName","Config","State","NumberOfDatabases","NodeCount","ProcessingUnits","Label/Tag: env","Label/Tag: team"',
        '"proj-a","sp1","Spanner One","regional-us-central1","READY","2","3","3000","x","y"',
        '"proj-a","sp2","Spanner Two","nam6","READY","1","0","500","x","y"',
        '"proj-a","sp3","Spanner Three","eur3","CREATING","0","0","0","x","y"',
        '"proj-a","sp4","Spanner Four","regional-us-east1","READY","0","1","1000","x","y"',
    ]


@pytest.mark.parametrize(
    "version,engine",
    [
        ("POSTGRES_15", "PostgreSQL"),
        ("postgres_9_6", "PostgreSQL"),
        ("MYSQL_8_0", "MySQL"),
        ("SQLSERVER_2019_STANDARD", "SQL Server"),
        ("FIREBIRD_1_0", "FIREBIRD_1_0"),
        ("", None),
        (None, None),
    ],
)
def test_engine_is_derived_from_the_version_prefix(version, engine):
    assert _engine(version) == engine


def test_a_missing_backup_flag_is_false_and_a_missing_size_is_zero():
    row = _parse(build_csv_files(_result(), "S")["gce_cloudsql_info-S.csv"])
    cells = dict(zip(row[0], row[5]))  # min1
    assert (cells["StorageSizeGb"], cells["StorageSizeTb"], cells["BackupEnabled"]) == (
        "0",
        "0",
        "False",
    )
    assert cells["AvailabilityType"] == ""


def test_a_label_value_that_is_empty_is_a_value():
    result = _result()
    result["databases"][1]["cloud_sql_instances"][0]["labels"] = {"env": "x", "team": ""}
    assert (
        build_csv_files(result, "S")["gce_cloudsql_info-S.csv"]
        .splitlines()[1]
        .endswith('"REGIONAL","x",""')
    )


def test_rows_follow_the_order_the_projects_were_scanned():
    assert [
        r[0] for r in _parse(build_csv_files(_result(), "S")["gce_cloudsql_info-S.csv"])[1:]
    ] == ["proj-a"] * 6 + ["proj-b"]


# ── the collector records what the files need ─────────────────────────────────

_ITEM = {
    "name": "pg1",
    "databaseVersion": "POSTGRES_15",
    "instanceType": "CLOUD_SQL_INSTANCE",
    "region": "us-central1",
    "state": "RUNNABLE",
    "settings": {
        "tier": "db-custom-2-7680",
        "dataDiskSizeGb": "100",
        "dataDiskType": "PD_SSD",
        "availabilityType": "REGIONAL",
        "userLabels": {"env": "prod"},
        "backupConfiguration": {
            "enabled": True,
            "startTime": "03:00",
            "backupRetentionSettings": {"retainedBackups": 7},
        },
    },
}


def test_the_new_fields_are_read_from_the_api_item():
    sql = DatabaseCollector._parse_cloud_sql(_ITEM)
    assert (sql.instance_type, sql.data_disk_size_gb, sql.availability_type) == (
        "CLOUD_SQL_INSTANCE",
        100.0,
        "REGIONAL",
    )
    assert (sql.backup_retention_count, sql.backup_start_time) == (7, "03:00")
    assert sql.automated_backup_enabled is True


def test_labels_are_read_from_settings_user_labels():
    assert DatabaseCollector._parse_cloud_sql(_ITEM).labels == {"env": "prod"}
    legacy = {
        **_ITEM,
        "settings": {k: v for k, v in _ITEM["settings"].items() if k != "userLabels"},
        "userLabels": {"a": "b"},
    }
    assert DatabaseCollector._parse_cloud_sql(legacy).labels == {"a": "b"}


def test_fields_the_api_leaves_out_are_none():
    sql = DatabaseCollector._parse_cloud_sql({"name": "x", "settings": {}})
    assert (
        sql.data_disk_size_gb,
        sql.availability_type,
        sql.backup_retention_count,
        sql.backup_start_time,
    ) == (None, None, None, None)
    assert sql.instance_type == ""


@pytest.mark.parametrize(
    "version,names,count",
    [
        (
            "POSTGRES_15",
            ["postgres", "template0", "template1", "cloudsqladmin", "Template1", "app"],
            1,
        ),
        (
            "MYSQL_8_0",
            ["information_schema", "mysql", "performance_schema", "sys", "SYS", "shop"],
            1,
        ),
        ("SQLSERVER_2019_STANDARD", ["master", "tempdb", "model", "msdb", "MSDB", "a", "b"], 2),
        ("FIREBIRD_1_0", ["postgres", "master", "a"], 3),
    ],
)
def test_the_database_count_leaves_out_the_engines_system_databases(version, names, count):
    service = MagicMock()
    service.databases.return_value.list.return_value.execute.return_value = {
        "items": [{"name": n} for n in names]
    }
    collector = DatabaseCollector("p", MagicMock())
    assert collector._cloud_sql_database_count(service, "inst", version) == count


def test_a_failed_database_listing_gives_none_and_one_error_per_project():
    service = MagicMock()
    service.databases.return_value.list.return_value.execute.side_effect = RuntimeError(
        "no permission"
    )
    collector = DatabaseCollector("p", MagicMock())
    assert collector._cloud_sql_database_count(service, "a", "POSTGRES_15") is None
    assert collector._cloud_sql_database_count(service, "b", "POSTGRES_15") is None
    assert [e["collector"] for e in collector.errors] == ["database:cloud_sql_databases"]


def test_system_database_lists_match_the_script():
    assert _system_databases("MYSQL_8_0") == {
        "information_schema",
        "mysql",
        "performance_schema",
        "sys",
    }
    assert "cloudsqladmin" in _system_databases("POSTGRES_15")
    assert "msdb" in _system_databases("SQLSERVER_2022_ENTERPRISE")
    assert _system_databases("OTHER") == frozenset()


def test_collect_cloud_sql_records_the_database_count_on_each_instance():
    service = MagicMock()
    service.instances.return_value.list.return_value.execute.return_value = {"items": [_ITEM]}
    service.instances.return_value.list_next.return_value = None
    service.databases.return_value.list.return_value.execute.return_value = {
        "items": [{"name": "postgres"}, {"name": "app"}]
    }
    with patch("googleapiclient.discovery.build", return_value=service):
        (instance,) = DatabaseCollector("p", MagicMock())._collect_cloud_sql()
    assert instance.number_of_databases == 1

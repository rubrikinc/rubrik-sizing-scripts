"""azure_mi_db_items: the managed-instance databases with their retention policies, as JSON.

The key names, their order, the date format and the nesting come from the file a PowerShell 1.0.3 run
wrote for four managed instances and 81 databases.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

from anonymize import Anonymizer
from collectors.database import az_managed_database, az_time
from csv_export import build_csv_files
from tests.test_database import _make_collector

DATABASE_KEYS = [
    "Location", "Tags", "Collation", "Status", "RestorePointInTime", "DefaultSecondaryLocation",
    "CatalogCollation", "CreateMode", "StorageContainerUri", "StorageContainerSasToken",
    "SourceDatabaseId", "FailoverGroupId", "RecoverableDatabaseId", "RestorableDroppedDatabaseId",
    "LongTermRetentionBackupResourceId", "AutoCompleteRestore", "LastBackupName",
    "StorageContainerIdentity", "CrossSubscriptionSourceDatabaseId",
    "CrossSubscriptionRestorableDroppedDatabaseId", "CrossSubscriptionTargetManagedInstanceId",
    "EnableLedger", "ResourceGroupName", "ManagedInstanceName", "Name", "CreationDate",
    "EarliestRestorePoint", "Id",
]  # fmt: skip
STR_KEYS = ["ResourceGroupName", "InstanceName", "DatabaseName", "DeletionDate", "RetentionDays"]
LTR_KEYS = [
    "ResourceGroupName", "ManagedInstanceName", "DatabaseName", "WeeklyRetention",
    "MonthlyRetention", "YearlyRetention", "WeekOfYear", "Location",
]  # fmt: skip

DB_ID = "/subscriptions/s1/resourceGroups/rg-mi/providers/Microsoft.Sql/managedInstances/mi1/databases/db1"
UTC = timezone.utc


def _db(name="db1", **overrides) -> NS:
    """A managed database the way the SDK returns it, with the fields flattened."""
    fields = dict(
        id=DB_ID.replace("db1", name),
        name=name,
        location="eastus",
        tags=None,
        collation="SQL_Latin1_General_CP1_CI_AS",
        status="Online",
        default_secondary_location="westus",
        creation_date=datetime(2026, 7, 29, 1, 6, 44, 123000, tzinfo=UTC),
        earliest_restore_point=datetime(2026, 10, 15, 4, 0, 0, tzinfo=UTC),
        is_ledger_on=False,
    )
    fields.update(overrides)
    return NS(**fields)


# ── dates ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (datetime(2026, 7, 29, 1, 6, 44, 123000, tzinfo=UTC), "2026-07-29T01:06:44.123Z"),
        (datetime(2026, 7, 29, 1, 6, 44, 120000, tzinfo=UTC), "2026-07-29T01:06:44.12Z"),
        (datetime(2026, 7, 29, 1, 6, 44, 100000, tzinfo=UTC), "2026-07-29T01:06:44.1Z"),
        (datetime(2026, 7, 29, 1, 6, 44, 123456, tzinfo=UTC), "2026-07-29T01:06:44.123456Z"),
        (datetime(2026, 10, 15, 4, 0, 0, tzinfo=UTC), "2026-10-15T04:00:00Z"),
        (datetime(2026, 7, 29, 1, 6, 44), "2026-07-29T01:06:44Z"),
    ],
)
def test_a_date_keeps_only_the_fraction_it_has(value, text):
    assert az_time(value) == text


def test_a_date_in_another_time_zone_is_written_in_utc():
    value = datetime(2026, 7, 29, 6, 36, 44, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert az_time(value) == "2026-07-29T01:06:44Z"


def test_a_text_date_is_kept_and_anything_else_is_nothing():
    assert az_time("2026-07-29T01:06:44Z") == "2026-07-29T01:06:44Z"
    assert az_time(None) is None and az_time(42) is None and az_time(MagicMock()) is None


# ── one database ──────────────────────────────────────────────────────────────


def test_a_database_has_the_az_keys_in_the_az_order():
    record = az_managed_database(_db(), "rg-mi", "mi1")
    assert list(record) == DATABASE_KEYS


def test_the_values_are_the_ones_azure_returned():
    record = az_managed_database(_db(), "rg-mi", "mi1")
    assert record["Location"] == "eastus" and record["Status"] == "Online"
    assert record["Collation"] == "SQL_Latin1_General_CP1_CI_AS"
    assert record["DefaultSecondaryLocation"] == "westus"
    assert (record["ResourceGroupName"], record["ManagedInstanceName"], record["Name"]) == (
        "rg-mi",
        "mi1",
        "db1",
    )
    assert record["Id"].endswith("/databases/db1")
    assert record["CreationDate"] == "2026-07-29T01:06:44.123Z"
    assert record["EarliestRestorePoint"] == "2026-10-15T04:00:00Z"
    assert record["EnableLedger"] is False


def test_fields_azure_does_not_send_are_null():
    record = az_managed_database(_db(), "rg-mi", "mi1")
    for key in (
        "RestorePointInTime", "CatalogCollation", "CreateMode", "StorageContainerUri",
        "StorageContainerSasToken", "SourceDatabaseId", "FailoverGroupId", "RecoverableDatabaseId",
        "RestorableDroppedDatabaseId", "LongTermRetentionBackupResourceId", "AutoCompleteRestore",
        "LastBackupName", "StorageContainerIdentity", "CrossSubscriptionSourceDatabaseId",
        "CrossSubscriptionRestorableDroppedDatabaseId", "CrossSubscriptionTargetManagedInstanceId",
    ):  # fmt: skip
        assert record[key] is None, key


def test_tags_keep_the_difference_between_none_empty_and_some():
    assert az_managed_database(_db(tags=None), "rg", "mi")["Tags"] is None
    assert az_managed_database(_db(tags={}), "rg", "mi")["Tags"] == {}
    assert az_managed_database(_db(tags={"long_running": "1"}), "rg", "mi")["Tags"] == {
        "long_running": "1"
    }


def test_the_ledger_flag_is_true_only_when_azure_says_true():
    assert az_managed_database(_db(is_ledger_on=True), "rg", "mi")["EnableLedger"] is True
    assert az_managed_database(_db(is_ledger_on=None), "rg", "mi")["EnableLedger"] is False
    assert az_managed_database(_db(is_ledger_on=MagicMock()), "rg", "mi")["EnableLedger"] is False
    assert az_managed_database(_db(is_ledger_on="yes"), "rg", "mi")["EnableLedger"] is False


def test_the_fields_are_read_from_properties_when_the_sdk_does_not_flatten_them():
    nested = NS(
        id=DB_ID,
        name="db1",
        location="eastus",
        tags=None,
        properties=NS(collation="C", status="Stopped", is_ledger_on=True),
    )
    record = az_managed_database(nested, "rg", "mi")
    assert (record["Collation"], record["Status"], record["EnableLedger"]) == ("C", "Stopped", True)


def test_an_enum_is_written_as_its_text_and_an_sdk_object_as_nothing():
    class State(str, Enum):
        INACCESSIBLE = "Inaccessible"

    record = az_managed_database(_db(status=State.INACCESSIBLE, collation=MagicMock()), "rg", "mi")
    assert record["Status"] == "Inaccessible" and record["Collation"] is None


def test_the_short_and_long_term_policies_follow_the_database_in_that_order_when_read():
    short = NS(retention_days=7)
    long = NS(
        weekly_retention="P4W", monthly_retention="P12M", yearly_retention="P5Y", week_of_year=1
    )
    record = az_managed_database(_db(), "rg-mi", "mi1", short, long)
    assert list(record) == [*DATABASE_KEYS, "STR", "LTR"]
    assert list(record["STR"]) == STR_KEYS and list(record["LTR"]) == LTR_KEYS
    assert record["STR"] == {
        "ResourceGroupName": "rg-mi",
        "InstanceName": "mi1",
        "DatabaseName": "db1",
        "DeletionDate": None,
        "RetentionDays": 7,
    }
    assert record["LTR"] == {
        "ResourceGroupName": "rg-mi",
        "ManagedInstanceName": "mi1",
        "DatabaseName": "db1",
        "WeeklyRetention": "P4W",
        "MonthlyRetention": "P12M",
        "YearlyRetention": "P5Y",
        "WeekOfYear": 1,
        "Location": None,
    }


def test_a_policy_that_was_not_read_is_not_in_the_record():
    only_short = az_managed_database(_db(), "rg", "mi", NS(retention_days=7), None)
    assert "STR" in only_short and "LTR" not in only_short
    neither = az_managed_database(_db(), "rg", "mi")
    assert "STR" not in neither and "LTR" not in neither


# ── reading them ──────────────────────────────────────────────────────────────


def _mi(name="mi1") -> NS:
    return NS(
        id=f"/subscriptions/s1/resourceGroups/rg-mi/providers/Microsoft.Sql/managedInstances/{name}",
        name=name,
        location="eastus",
        sku=NS(name="GP_Gen5", tier="GeneralPurpose"),
        storage_size_in_gb=64,
        v_cores=4,
        tags=None,
    )


def _collector(databases, short=None, long=None):
    collector = _make_collector(managed_instances=[_mi()])
    sql = collector._sql
    sql.managed_databases.list_by_instance.return_value = list(databases)
    sql.managed_backup_short_term_retention_policies.get.side_effect = (
        short if short is not None else lambda *a: NS(retention_days=7)
    )
    sql.managed_instance_long_term_retention_policies.get.side_effect = (
        long
        if long is not None
        else lambda *a: NS(
            weekly_retention="PT0S",
            monthly_retention="PT0S",
            yearly_retention="PT0S",
            week_of_year=0,
        )
    )
    return collector


def _records(collector) -> list[dict]:
    (instance,) = collector.collect().managed_instances
    return instance.databases_az


def test_each_database_is_listed_with_both_policies_asked_for_by_the_default_policy_name():
    collector = _collector([_db("a"), _db("b")])
    records = _records(collector)
    assert [r["Name"] for r in records] == ["a", "b"]
    assert all("STR" in r and "LTR" in r for r in records)
    sql = collector._sql
    sql.managed_backup_short_term_retention_policies.get.assert_any_call(
        "rg-mi", "mi1", "a", "default"
    )
    sql.managed_instance_long_term_retention_policies.get.assert_any_call(
        "rg-mi", "mi1", "b", "default"
    )


def test_a_long_term_policy_that_cannot_be_read_keeps_the_short_term_one():
    def refuse(*args):
        raise RuntimeError("database is not online")

    (record,) = _records(_collector([_db()], long=refuse))
    assert "STR" in record and "LTR" not in record


def test_a_short_term_policy_that_cannot_be_read_skips_both():
    def refuse(*args):
        raise RuntimeError("denied")

    collector = _collector([_db()], short=refuse)
    (record,) = _records(collector)
    assert "STR" not in record and "LTR" not in record
    collector._sql.managed_instance_long_term_retention_policies.get.assert_not_called()


def test_an_instance_whose_databases_cannot_be_listed_has_none():
    collector = _collector([])
    collector._sql.managed_databases.list_by_instance.side_effect = RuntimeError("denied")
    assert _records(collector) == []


# ── the file ──────────────────────────────────────────────────────────────────


def _result(managed_by_subscription, tenant="Contoso", **extra) -> dict:
    return {
        "tenant_name": tenant,
        "tenant_id": "tenant-id",
        "subscription_names": {"s1": "Sub One", "s2": "Sub Two"},
        "tag_names": {},
        "skipped": [],
        "database": [
            {"subscription_id": sub, "managed_instances": instances}
            for sub, instances in managed_by_subscription.items()
        ],
        **extra,
    }


def _file(result, anonymizer=None) -> dict | None:
    files = build_csv_files(result, "2026-10-22_1102", anonymizer)
    name = next((n for n in files if n.startswith("azure_mi_db_items")), None)
    return json.loads(files[name]) if name else None


def _records_of(count: int) -> list[dict]:
    return [az_managed_database(_db(f"db{i}"), "rg-mi", "mi1") for i in range(count)]


def test_the_file_is_nested_by_tenant_then_subscription_then_instance():
    result = _result({"s1": [{"name": "mi1", "databases_az": _records_of(3)}], "s2": []})
    data = _file(result)
    assert list(data) == ["Contoso"]
    assert list(data["Contoso"]) == ["Sub One", "Sub Two"]
    assert [d["Name"] for d in data["Contoso"]["Sub One"]["mi1"]] == ["db0", "db1", "db2"]
    assert data["Contoso"]["Sub Two"] == {}


def test_one_database_is_an_object_not_a_one_item_array_as_powershell_writes_it():
    data = _file(_result({"s1": [{"name": "mi1", "databases_az": _records_of(1)}]}))
    one = data["Contoso"]["Sub One"]["mi1"]
    assert isinstance(one, dict) and one["Name"] == "db0"


def test_an_instance_with_no_database_is_an_empty_list():
    data = _file(_result({"s1": [{"name": "mi1", "databases_az": []}]}))
    assert data["Contoso"]["Sub One"]["mi1"] == []


def test_the_tenant_key_is_the_tenant_id_when_the_tenant_has_no_name():
    data = _file(_result({"s1": []}, tenant=None))
    assert list(data) == ["tenant-id"]


def test_the_file_is_written_even_when_there_is_no_managed_instance():
    assert _file(_result({"s1": []})) == {"Contoso": {"Sub One": {}}}


def test_the_records_come_through_unchanged_in_key_order():
    data = _file(_result({"s1": [{"name": "mi1", "databases_az": _records_of(2)}]}))
    first = data["Contoso"]["Sub One"]["mi1"][0]
    assert list(first) == DATABASE_KEYS


def test_skipping_sql_and_mi_stops_the_file():
    result = _result({"s1": []})
    assert _file(result) is not None
    assert _file({**result, "skipped": ["sql_mi"]}) is None


def test_an_anonymized_run_leaves_the_file_out_because_it_cannot_be_made_safe():
    result = _result({"s1": [{"name": "mi1", "databases_az": _records_of(2)}]})
    assert _file(result, Anonymizer()) is None
    files = build_csv_files(result, "2026-10-22_1102", Anonymizer())
    assert not [name for name in files if "mi_db_items" in name]
    assert not any("mi1" in text or "db0" in text for text in files.values())

"""Tests for collectors/dynamodb.py."""

from unittest.mock import MagicMock

import pytest
from collectors.dynamodb import fetch_dynamodb

ACCT = "123456789012"
ALIAS = "test-account"
REGION = "us-east-1"

GIB = 1024**3
TIB = 1024**4


def _mock_session(client):
    s = MagicMock()
    s.client.return_value = client
    return s


def _make_client(table_names, describe_results=None):
    pag = MagicMock()
    pag.paginate.return_value = [{"TableNames": table_names}]
    client = MagicMock()
    client.get_paginator.return_value = pag
    if describe_results is not None:
        client.describe_table.side_effect = describe_results
    return client


def _describe(name, size_bytes=0, item_count=0, arn=None, rcu=5, wcu=5, lsi_bytes=None):
    tbl = {
        "TableName": name,
        "TableId": f"id-{name}",
        "TableArn": arn or f"arn:aws:dynamodb:{REGION}:{ACCT}:table/{name}",
        "TableSizeBytes": size_bytes,
        "ItemCount": item_count,
        "TableStatus": "ACTIVE",
        "DeletionProtectionEnabled": False,
        "ProvisionedThroughput": {"ReadCapacityUnits": rcu, "WriteCapacityUnits": wcu},
    }
    if lsi_bytes is not None:
        tbl["LocalSecondaryIndexes"] = [{"IndexSizeBytes": b} for b in lsi_bytes]
    return {"Table": tbl}


class TestFetchDynamoDB:
    def test_basic_table_returned(self):
        client = _make_client(
            ["users"],
            describe_results=[_describe("users", size_bytes=GIB, item_count=500)],
        )
        result = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(result) == 1
        t = result[0]
        assert t.table_name == "users"
        assert t.item_count == 500
        assert t.status == "ACTIVE"

    def test_lsi_size_summed_across_indexes(self):
        # Two LSIs of 1 GiB each → 2 GiB LSI footprint, captured separately from table data.
        client = _make_client(
            ["indexed"],
            describe_results=[_describe("indexed", size_bytes=GIB, lsi_bytes=[GIB, GIB])],
        )
        t = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())[0]
        assert t.lsi_size_bytes == 2 * GIB
        assert t.lsi_size_gib == pytest.approx(2.0, abs=0.001)
        assert t.lsi_size_tb == pytest.approx(2.0 / 1024, abs=1e-4)

    def test_lsi_defaults_zero_without_indexes(self):
        client = _make_client(["plain"], describe_results=[_describe("plain", size_bytes=GIB)])
        t = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())[0]
        assert t.lsi_size_bytes == 0
        assert t.lsi_size_gib == 0.0
        assert t.lsi_size_tb == 0.0

    def test_size_bytes_to_gib_conversion(self):
        size_bytes = 2 * GIB  # 2 GiB
        client = _make_client(
            ["big"],
            describe_results=[_describe("big", size_bytes=size_bytes)],
        )
        result = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].size_bytes == size_bytes
        assert result[0].size_gib == pytest.approx(2.0, abs=0.001)

    def test_size_gib_to_tb_conversion(self):
        size_bytes = TIB  # 1 TiB
        client = _make_client(
            ["huge"],
            describe_results=[_describe("huge", size_bytes=size_bytes)],
        )
        result = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].size_tb == pytest.approx(1.0, abs=0.001)

    def test_backup_protection_marked(self):
        table_arn = f"arn:aws:dynamodb:{REGION}:{ACCT}:table/orders"
        client = _make_client(
            ["orders"],
            describe_results=[_describe("orders", arn=table_arn)],
        )
        result = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, {table_arn})
        assert result[0].in_backup_plan is True
        assert result[0].backup_plans == ["AWS Backup"]

    def test_unprotected_table(self):
        client = _make_client(
            ["events"],
            describe_results=[_describe("events")],
        )
        result = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].in_backup_plan is False

    def test_list_tables_error_returns_empty(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("AccessDenied")
        result = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result == []

    def test_describe_table_error_skips_table(self):
        client = _make_client(
            ["good", "bad"],
            describe_results=[
                _describe("good"),
                Exception("ResourceNotFound"),
            ],
        )
        result = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(result) == 1
        assert result[0].table_name == "good"

    def test_zero_size_table(self):
        client = _make_client(
            ["empty"],
            describe_results=[_describe("empty", size_bytes=0)],
        )
        result = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].size_bytes == 0
        assert result[0].size_gib == 0.0
        assert result[0].size_tb == 0.0

    def test_provisioned_throughput(self):
        client = _make_client(
            ["t1"],
            describe_results=[_describe("t1", rcu=10, wcu=20)],
        )
        result = fetch_dynamodb(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].read_capacity_units == 10
        assert result[0].write_capacity_units == 20

"""The SQL ``InstanceType`` cell, worded as Az.Sql's ``SkuName`` gives it.

The pairs come from a real run: every database and pool that both tools listed (210 databases, one
pool) and the four managed instances.
"""

from __future__ import annotations

import csv
import io

import pytest

from csv_export import _ps_sku_name, build_csv_files


@pytest.mark.parametrize(
    ("rest_name", "powershell_name"),
    [
        ("GP_S_Gen5_1", "GP_S_Gen5"),
        ("GP_S_Gen5_4", "GP_S_Gen5"),
        ("GP_S_Gen5_32", "GP_S_Gen5"),
        ("GP_Gen5_2", "GP_Gen5"),
        ("S0", "Standard"),
        ("P1", "Premium"),
        ("Basic", "Basic"),
        ("StandardPool", "StandardPool"),
        ("BC_Gen5_8", "BC_Gen5"),
        ("HS_Gen5_2", "HS_Gen5"),
        ("GP_Fsv2_72", "GP_Fsv2"),
        ("S12", "Standard"),
        ("P15", "Premium"),
    ],
)
def test_the_rest_name_becomes_the_name_az_sql_reports(rest_name, powershell_name):
    assert _ps_sku_name(rest_name) == powershell_name


def test_a_name_without_a_capacity_or_a_tier_pattern_is_left_alone():
    for name in ("ElasticPool", "DW100c", "Unknown", "GP_Gen5", "System"):
        assert _ps_sku_name(name) == name


def test_nothing_stays_nothing():
    assert _ps_sku_name(None) is None
    assert _ps_sku_name("") == ""


def _result() -> dict:
    db = lambda name, sku: {  # noqa: E731
        "name": name,
        "server_name": "srv",
        "sku_name": sku,
        "location": "eastus",
        "resource_group": "rg",
        "max_size_bytes": 1073741824,
    }
    return {
        "tenant_name": "T",
        "tenant_id": "t",
        "subscription_names": {"s": "S"},
        "tag_names": {},
        "skipped": [],
        "database": [
            {
                "subscription_id": "s",
                "sql_servers": [
                    {
                        "name": "srv",
                        "databases": [
                            db("a", "GP_S_Gen5_4"),
                            db("b", "S0"),
                            db("c", "ElasticPool"),
                        ],
                        "elastic_pools": [
                            {
                                "name": "pool",
                                "sku_name": "GP_Gen5_4",
                                "location": "eastus",
                                "resource_group": "rg",
                                "max_size_bytes": 1073741824,
                            }
                        ],
                    }
                ],
                "managed_instances": [
                    {
                        "name": "mi",
                        "sku_name": "GP_Gen5",
                        "location": "eastus",
                        "storage_size_gb": 32,
                    }
                ],
            }
        ],
    }


def _types(prefix: str) -> list[str]:
    files = build_csv_files(_result(), "2026-10-22_1102")
    text = next(t for n, t in files.items() if n.startswith(prefix))
    return [r["InstanceType"] for r in csv.DictReader(io.StringIO(text))]


def test_databases_and_pools_of_the_sql_file_are_worded_like_powershell():
    assert _types("azure_sql_info") == ["GP_S_Gen5", "Standard", "GP_Gen5"]


def test_a_managed_instance_keeps_its_sku_name():
    assert _types("azure_mi_sql_info") == ["GP_Gen5"]

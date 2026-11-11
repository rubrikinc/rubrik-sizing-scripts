"""azure_sizing_summary.

Expected lines come from the real summary block of Get-AzureSizingInfo.ps1 run in pwsh 7.6.5 on the
same inputs. Two things PowerShell gets wrong are not copied and are tested by hand instead: the
VM per-region rows and the count of a one-VM HasMSSQL group.
"""

from __future__ import annotations

import csv
import io

import pytest

import csv_export
from csv_export import _group, _ps_sum, _summary, build_csv_files, render

_VMS = [
    {"Region": "westus2", "HasMSSQL": "Yes", "SizeTiB": 0.5, "SizeTB": 0.25},
    {"Region": "EastUS", "HasMSSQL": "No", "SizeTiB": 1.0, "SizeTB": 0.5},
    {"Region": "eastus", "HasMSSQL": "No", "SizeTiB": 0.25, "SizeTB": 0.125},
    {"Region": "westus2", "HasMSSQL": "No", "SizeTiB": 0.125, "SizeTB": 0.0625},
    {"Region": "northeurope", "HasMSSQL": "No", "SizeTiB": 2.0, "SizeTB": 1.0},
]
_STORAGE = [
    {
        "Region": "westus2",
        "BlobCount": 1000.0,
        "UsedBlobCapacityTiB": 0.1,
        "UsedBlobCapacityTB": 0.7,
    },
    {"Region": "eastus", "BlobCount": None, "UsedBlobCapacityTiB": 0.2, "UsedBlobCapacityTB": 0.3},
    {
        "Region": "westus2",
        "BlobCount": 2345.0,
        "UsedBlobCapacityTiB": 0.3,
        "UsedBlobCapacityTB": 0.1,
    },
    {"Region": "eastus2", "BlobCount": None, "UsedBlobCapacityTiB": 0.0, "UsedBlobCapacityTB": 0.0},
    {"Region": "Eastus", "BlobCount": 5.0, "UsedBlobCapacityTiB": 0.1, "UsedBlobCapacityTB": 0.2},
]
_SHARES = [
    {"Region": "westus2", "UsedCapacityTiB": 0.1, "UsedCapacityTB": 0.7},
    {"Region": "eastus", "UsedCapacityTiB": 0.7, "UsedCapacityTB": 0.1},
    {"Region": "northeurope", "UsedCapacityTiB": 0.3, "UsedCapacityTB": 0.3},
    {"Region": "Eastus", "UsedCapacityTiB": 0.2, "UsedCapacityTB": 0.2},
    {"Region": "westus2", "UsedCapacityTiB": 0.2, "UsedCapacityTB": 0.2},
]
_SQL = [
    {"Region": "westus2", "InstanceType": "GP_Gen5_2", "MaxSizeTiB": 0.03125, "MaxSizeTB": 0.0344},
    {"Region": "eastus", "InstanceType": "DataWarehouse", "MaxSizeTiB": 1.0, "MaxSizeTB": 1.0995},
    {"Region": "northeurope", "InstanceType": None, "MaxSizeTiB": 0.2, "MaxSizeTB": 0.1},
    {"Region": "eastus", "InstanceType": "datawarehouse", "MaxSizeTiB": 9.0, "MaxSizeTB": 9.0},
    {"Region": "Eastus", "InstanceType": "S0", "MaxSizeTiB": 0.1, "MaxSizeTB": 0.3},
    {"Region": "westus2", "InstanceType": "S1", "MaxSizeTiB": 0.3, "MaxSizeTB": 0.2},
]
_MI = [
    {"Region": "westus2", "MaxSizeTiB": 0.25, "MaxSizeTB": 0.2749},
    {"Region": "eastus", "MaxSizeTiB": 4.0, "MaxSizeTB": 4.398},
    {"Region": "northeurope", "MaxSizeTiB": 0.1, "MaxSizeTB": 0.1},
    {"Region": "westus2", "MaxSizeTiB": 0.1, "MaxSizeTB": 0.1},
]
_AKS = [
    {"Location": "westus2", "TotalNodes": 3},
    {"Location": "eastus", "TotalNodes": 5},
    {"Location": "eastus", "TotalNodes": 0},
    {"Location": "Westus2", "TotalNodes": 2},
]


def _text(*lists) -> list[str]:
    padded = [*lists, *([[]] * (6 - len(lists)))]
    rows = _summary(*padded)
    return render(csv_export._SUMMARY_COLUMNS, rows, csv_export._SUMMARY_QUOTED_EMPTY).splitlines()[
        1:
    ]


# ── sections PowerShell gets right ────────────────────────────────────────────


def test_storage_section_matches_powershell():
    assert _text([], _STORAGE) == [
        '"[ Azure Storage Accounts ]","",,,',
        '"","All Regions (Total Blob Count: 3350)","0.7000000000000001","1.3","5"',
        '"","eastus (Blob Count: 5)","0.30000000000000004","0.5","2"',
        '"","eastus2 (Blob Count: 0)","0","0","1"',
        '"","westus2 (Blob Count: 3345)","0.4","0.7999999999999999","2"',
    ]


def test_file_share_section_matches_powershell():
    assert _text([], [], _SHARES) == [
        '"[ Azure File Shares ]","",,,',
        '"","All Regions","1.4999999999999998","1.4999999999999998","5"',
        '"","eastus","0.8999999999999999","0.30000000000000004","2"',
        '"","northeurope","0.3","0.3","1"',
        '"","westus2","0.30000000000000004","0.8999999999999999","2"',
    ]


def test_sql_section_matches_powershell_and_leaves_out_data_warehouses():
    assert _text([], [], [], _SQL) == [
        '"[ Azure SQL Databases ]","",,,',
        '"","All Regions","0.6312500000000001","0.6344000000000001","4"',
        '"","Eastus","0.1","0.3","1"',
        '"","northeurope","0.2","0.1","1"',
        '"","westus2","0.33125","0.2344","2"',
    ]


def test_managed_instance_section_matches_powershell():
    assert _text([], [], [], [], _MI) == [
        '"[ Azure SQL Managed Instances ]","",,,',
        '"","All Regions","4.449999999999999","4.872899999999999","4"',
        '"","eastus","4","4.398","1"',
        '"","northeurope","0.1","0.1","1"',
        '"","westus2","0.35","0.3749","2"',
    ]


def test_aks_section_matches_powershell():
    assert _text([], [], [], [], [], _AKS) == [
        '"[ Azure Kubernetes Service (AKS) Clusters ]","",,,',
        '"","All Regions (Total Nodes: 10)",,,"4"',
        '"","eastus (Nodes: 5)",,,"2"',
        '"","westus2 (Nodes: 5)",,,"2"',
    ]


def test_sections_follow_the_scripts_order_and_empty_ones_are_left_out():
    lines = _text(_VMS, _STORAGE, _SHARES, _SQL, _MI, _AKS)
    headers = [line.split(",")[0] for line in lines if line.endswith('"",,,')]
    assert headers == [
        '"[ Azure VMs and Managed Disks ]"',
        '"HasMSSQL = Yes"',
        '"[ Azure VMs and Managed Disks ]"',
        '"HasMSSQL = No"',
        '"[ Azure Storage Accounts ]"',
        '"[ Azure File Shares ]"',
        '"[ Azure SQL Databases ]"',
        '"[ Azure SQL Managed Instances ]"',
        '"[ Azure Kubernetes Service (AKS) Clusters ]"',
    ]
    assert _text() == []


def test_only_data_warehouses_gives_no_sql_section():
    only_dw = [
        {"Region": "eastus", "InstanceType": "DataWarehouse", "MaxSizeTiB": 1.0, "MaxSizeTB": 1.0}
    ]
    assert _text([], [], [], only_dw) == []


# ── VM section (PowerShell's per-region rows are broken, so these are hand-computed) ──


def test_vm_groups_have_a_header_a_mssql_row_a_total_and_real_regions():
    assert _text(_VMS) == [
        '"[ Azure VMs and Managed Disks ]","",,,',
        '"HasMSSQL = Yes","",,,',
        '"","All Regions","0.5","0.25","1"',
        '"","westus2","0.5","0.25","1"',
        '"[ Azure VMs and Managed Disks ]","",,,',
        '"HasMSSQL = No","",,,',
        '"","All Regions","3.375","1.6875","4"',
        '"","EastUS","1.25","0.625","2"',
        '"","northeurope","2","1","1"',
        '"","westus2","0.125","0.0625","1"',
    ]


def test_a_one_vm_group_counts_vms_not_hashtable_keys():
    (total,) = [line for line in _text(_VMS[:1]) if line.startswith('"","All Regions"')]
    assert total.endswith(',"1"')


# ── helpers ───────────────────────────────────────────────────────────────────


def test_sums_are_a_plain_running_total_not_python_sum():
    # sum() is compensated from Python 3.12 and gives 0.6 here, so only a plain running total passes.
    assert _ps_sum([0.1, 0.2, 0.3]) == 0.6000000000000001


def test_sum_skips_nulls_and_is_zero_for_all_null_but_null_for_nothing():
    assert _ps_sum([None, 5.0, None]) == 5.0
    assert _ps_sum([None, None]) == 0.0
    assert _ps_sum([]) is None


def test_groups_ignore_case_keep_the_first_spelling_and_come_sorted():
    rows = [{"r": "westus2"}, {"r": "EastUS"}, {"r": "eastus"}, {"r": "northeurope"}]
    assert [(name, len(group)) for name, group in _group(rows, "r")] == [
        ("EastUS", 2),
        ("northeurope", 1),
        ("westus2", 1),
    ]


@pytest.mark.parametrize("value,text", [(None, ""), (0.0, "0"), (3350.0, "3350"), (7, "7")])
def test_count_text(value, text):
    assert csv_export._count_text(value) == text


# ── the file ──────────────────────────────────────────────────────────────────


def _result() -> dict:
    return {
        "tenant_name": "Contoso",
        "tenant_id": "t",
        "subscription_names": {"sub-1": "Sub One"},
        "tag_names": {},
        "compute": [
            {
                "subscription_id": "sub-1",
                "vms": [
                    {
                        "name": "a",
                        "location": "westus2",
                        "total_disk_gb": 1536,
                        "disks": [{}],
                        "sql_server": None,
                    },
                    {
                        "name": "b",
                        "location": "westus2",
                        "total_disk_gb": 512,
                        "disks": [{}],
                        "sql_server": {"edition": "x"},
                    },
                ],
            }
        ],
        "storage": [
            {
                "subscription_id": "sub-1",
                "accounts": [
                    {
                        "name": "sa",
                        "location": "westus2",
                        "blob_capacity_bytes": 1099511627776,
                        "blob_count": 10,
                        "kind": "StorageV2",
                        "sku": "Standard_LRS",
                    }
                ],
            }
        ],
    }


def test_file_name_has_an_underscore_before_the_stamp():
    files = build_csv_files(_result(), "2026-10-06_1200")
    assert "azure_sizing_summary_2026-10-06_1200.csv" in files
    assert "azure_sizing_summary-2026-10-06_1200.csv" not in files


def test_summary_is_built_from_the_values_written_in_the_other_files():
    files = build_csv_files(_result(), "S")
    rows = list(csv.reader(io.StringIO(files["azure_sizing_summary_S.csv"])))
    assert rows[0] == csv_export._SUMMARY_COLUMNS
    by_type = {}
    for row in rows[1:]:
        by_type.setdefault(row[0], []).append(row)
    assert "HasMSSQL = Yes" in by_type and "HasMSSQL = No" in by_type
    storage = [r for r in rows if r[1].startswith("All Regions (Total Blob Count")]
    assert storage == [["", "All Regions (Total Blob Count: 10)", "1", "1.0995", "1"]]
    vm_totals = [r for r in rows if r[1] == "All Regions"]
    assert [(r[2], r[4]) for r in vm_totals] == [("0.5", "1"), ("1.5", "1")]  # the SQL VM first


def test_summary_has_no_tag_columns_and_is_empty_without_resources():
    files = build_csv_files({**_result(), "tag_names": {"sub-1": ["Env"]}}, "S")
    assert "Tag: Env" not in files["azure_sizing_summary_S.csv"]
    assert build_csv_files({"tag_names": {}}, "S")["azure_sizing_summary_S.csv"] == ""

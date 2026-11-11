"""gce_bigquery_info: the PowerShell-style BigQuery file.

The expected lines are what master's ``Get-GCPBigQueryInventory`` wrote, run in pwsh with ``bq``
replaced by a function that returned the same API answers (then ``Add-TagsToAllObjectsInList`` and
``Export-Csv`` as the script does).
"""

from __future__ import annotations

import csv
import io

import pytest

import csv_export
from csv_export import build_csv_files


def _table(**kw):
    base = dict(
        dataset_id="analytics",
        location="US",
        table_id="t",
        table_type="TABLE",
        num_rows=0,
        number_of_columns=0,
        total_logical_bytes=0,
        long_term_logical_bytes=0,
        external_source_format="",
        external_source_uri="",
        creation_time="",
        last_modified_time="",
        dataset_labels={},
        labels={},
        details_available=True,
    )
    base.update(kw)
    return base


_DATASET_LABELS = {"team": "data", "a-b": "1"}


def _result():
    return {
        "projects_scanned": ["proj-a"],
        "bigquery": [
            {
                "project_id": "proj-a",
                "tables": [
                    _table(
                        table_id="events",
                        num_rows=1_200_000,
                        number_of_columns=14,
                        total_logical_bytes=5_000_000_000,
                        long_term_logical_bytes=2_000_000_000,
                        creation_time="2025-01-15T09:30:00Z",
                        last_modified_time="2025-10-01T04:00:00Z",
                        dataset_labels=_DATASET_LABELS,
                        labels={"team": "override", "dataset_team": "t"},
                    ),
                    _table(
                        table_id="ext_logs",
                        table_type="EXTERNAL",
                        number_of_columns=2,
                        external_source_format="PARQUET",
                        external_source_uri="gs://b/x/*.parquet; gs://b/y/*.parquet",
                        creation_time="2023-11-14T22:13:20Z",
                        last_modified_time="2023-11-14T22:13:20Z",
                        dataset_labels=_DATASET_LABELS,
                    ),
                    _table(
                        dataset_id="nodetails",
                        location="",
                        table_id="nd1",
                        num_rows=1,
                        number_of_columns=1,
                        total_logical_bytes=10,
                        creation_time="2023-11-14T22:13:20Z",
                        last_modified_time="2023-11-14T22:13:20Z",
                    ),
                ],
            }
        ],
    }


def test_the_file_matches_what_the_powershell_script_writes():
    lines = build_csv_files(_result(), "S")["gce_bigquery_info-S.csv"].splitlines()
    assert lines == [
        '"Project","DatasetId","Location","TableId","TableType","NumRows","NumberOfColumns","TotalLogicalSizeBytes","TotalLogicalSizeGb","TotalLogicalSizeTb","TotalLogicalSizeGiB","TotalLogicalSizeTiB","ActiveLogicalSizeBytes","ActiveLogicalSizeGb","ActiveLogicalSizeTb","ActiveLogicalSizeGiB","ActiveLogicalSizeTiB","LongTermLogicalSizeBytes","LongTermLogicalSizeGb","LongTermLogicalSizeTb","LongTermLogicalSizeGiB","LongTermLogicalSizeTiB","ExternalSourceFormat","ExternalSourceUri","CreationTime","LastModifiedTime","Label/Tag: dataset_a_b","Label/Tag: team","Label/Tag: dataset_team"',
        '"proj-a","analytics","US","events","TABLE","1200000","14","5000000000","5","0.005","4.6566","0.004547","3000000000","3","0.003","2.794","0.002728","2000000000","2","0.002","1.8626","0.001819","","","2025-01-15T09:30:00Z","2025-10-01T04:00:00Z","1","override","t"',
        '"proj-a","analytics","US","ext_logs","EXTERNAL","0","2","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","PARQUET","gs://b/x/*.parquet; gs://b/y/*.parquet","2023-11-14T22:13:20Z","2023-11-14T22:13:20Z","1",,"data"',
        '"proj-a","nodetails","","nd1","TABLE","1","1","10","0","0","0","0","10","0","0","0","0","0","0","0","0","0","","","2023-11-14T22:13:20Z","2023-11-14T22:13:20Z",,,',
    ]


# bytes -> (GB, TB, GiB, TiB) as ConvertTo-GCPSizeUnits -InputUnit Bytes writes them for these rows:
# four decimals for GB and GiB, six for TB and TiB, with .NET's half-to-even rounding.
_POWERSHELL_UNITS = [
    (0, 0, 0, 0, 0),
    (1, 0, 0, 0, 0),
    (777, 0, 0, 0, 0),
    (1024, 0, 0, 0, 0),
    (123456, 0.0001, 0, 0.0001, 0),
    (1073741824, 1.0737, 0.001074, 1, 0.000977),
    (1073741825, 1.0737, 0.001074, 1, 0.000977),
    (5000000000, 5, 0.005, 4.6566, 0.004547),
    (1099511627777, 1099.5116, 1.099512, 1024, 1),
    (549755813888, 549.7558, 0.549756, 512, 0.5),
    (123456789012345, 123456.789, 123.456789, 114978.0946, 112.283296),
]


@pytest.mark.parametrize("size,gb,tb,gib,tib", _POWERSHELL_UNITS)
def test_size_units_match_the_powershell_helper(size, gb, tb, gib, tib):
    assert csv_export._bytes_units(size, "X") == {
        "XGb": gb,
        "XTb": tb,
        "XGiB": gib,
        "XTiB": tib,
    }


def test_decimal_and_binary_units_are_not_mixed_up():
    units = csv_export._bytes_units(1_000_000_000, "X")
    assert units["XGb"] == 1.0 and units["XGiB"] == 0.9313


def test_active_size_is_the_total_less_the_long_term_part_and_never_negative():
    row = {
        "projects_scanned": ["p"],
        "bigquery": [
            {
                "project_id": "p",
                "tables": [_table(total_logical_bytes=100, long_term_logical_bytes=500)],
            }
        ],
    }
    cells = _parse(build_csv_files(row, "S")["gce_bigquery_info-S.csv"])
    assert (cells["ActiveLogicalSizeBytes"], cells["LongTermLogicalSizeBytes"]) == ("0", "500")


def _parse(text):
    header, *rows = list(csv.reader(io.StringIO(text)))
    return dict(zip(header, rows[0]))


def test_rows_follow_the_order_the_projects_were_scanned():
    result = {
        "projects_scanned": ["proj-b", "proj-a"],
        "bigquery": [
            {"project_id": "proj-a", "tables": [_table(table_id="a1")]},
            {"project_id": "proj-b", "tables": [_table(table_id="b1")]},
        ],
    }
    rows = list(csv.reader(io.StringIO(build_csv_files(result, "S")["gce_bigquery_info-S.csv"])))
    assert [r[0] for r in rows[1:]] == ["proj-b", "proj-a"]


def test_a_result_without_bigquery_gives_an_empty_file():
    assert build_csv_files({"projects_scanned": ["p"]}, "S")["gce_bigquery_info-S.csv"] == ""


def test_the_label_helper_still_works_for_one_dict_and_adds_to_an_existing_row():
    assert csv_export._label_cells({"a-b": "1", "a_b": "2"}) == {"Label/Tag: a_b": "2"}
    row = {"x": 1, "Label/Tag: dataset_team": "data", "Label/Tag: y": "keep"}
    csv_export._label_cells({"dataset_team": "t"}, "Label/Tag: ", row)
    assert list(row) == ["x", "Label/Tag: y", "Label/Tag: dataset_team"]
    assert row["Label/Tag: dataset_team"] == "t"

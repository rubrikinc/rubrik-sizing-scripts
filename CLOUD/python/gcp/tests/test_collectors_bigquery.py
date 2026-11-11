"""Tests for collectors/bigquery.py — the Google API client is replaced by a fake."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import pytest

from collectors.bigquery import BigQueryCollector, _iso_utc

PROJECT = "proj-a"


class _Request:
    def __init__(self, payload):
        self._payload = payload

    def execute(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _Pages:
    """A list call that answers in pages, like ``datasets().list`` and ``tables().list``."""

    def __init__(self, key, pages):
        self.key, self.pages = key, pages

    def list(self, **kwargs):
        return _PageRequest(self, 0)

    def list_next(self, request, response):
        following = request.index + 1
        return _PageRequest(self, following) if following < len(self.pages) else None


class _PageRequest(_Request):
    def __init__(self, owner, index):
        self.owner, self.index = owner, index
        page = owner.pages[index]
        super().__init__(page if isinstance(page, Exception) else {owner.key: page})


class _Datasets(_Pages):
    def __init__(self, pages, info):
        super().__init__("datasets", pages)
        self._info = info

    def get(self, projectId, datasetId):
        return _Request(self._info[datasetId])


class _Tables:
    """``tables()``: one paged listing per dataset, and the details of each table."""

    def __init__(self, table_pages, info):
        self._listings = {d: _Pages("tables", pages) for d, pages in table_pages.items()}
        self._info = info

    def list(self, projectId, datasetId, maxResults=None):
        return self._listings[datasetId].list()

    def list_next(self, request, response):
        return request.owner.list_next(request, response)

    def get(self, projectId, datasetId, tableId):
        return _Request(self._info[(datasetId, tableId)])


class FakeBigQuery:
    def __init__(self, dataset_pages, dataset_info, table_pages, table_info):
        self._datasets = _Datasets(dataset_pages, dataset_info)
        self._tables = _Tables(table_pages, table_info)

    def datasets(self):
        return self._datasets

    def tables(self):
        return self._tables


def _ref(table_id, kind="TABLE", dataset="analytics"):
    return {"tableReference": {"tableId": table_id, "datasetId": dataset}, "type": kind}


def _dataset(dataset_id):
    return {"datasetReference": {"datasetId": dataset_id}}


def _collect(service):
    with patch("googleapiclient.discovery.build", return_value=service):
        collector = BigQueryCollector(PROJECT, MagicMock())
        return collector.collect(), collector.errors


def _simple(**overrides):
    args = dict(
        dataset_pages=[[_dataset("analytics")]],
        dataset_info={"analytics": {"location": "US", "labels": {"team": "data"}}},
        table_pages={"analytics": [[_ref("events")]]},
        table_info={
            ("analytics", "events"): {
                "numBytes": "5000000000",
                "numLongTermBytes": "2000000000",
                "numRows": "1200000",
                "schema": {"fields": [{"name": "a"}, {"name": "b"}, {"name": "c"}]},
                "creationTime": "1736933400123",
                "lastModifiedTime": "1759291200999",
                "labels": {"env": "prod"},
            }
        },
    )
    args.update(overrides)
    return FakeBigQuery(**args)


# ── what is read from a table ─────────────────────────────────────────────────


def test_a_table_is_read_with_its_sizes_counts_dates_and_labels():
    inventory, errors = _collect(_simple())
    (table,) = inventory.tables
    assert errors == []
    assert (table.dataset_id, table.location, table.table_id, table.table_type) == (
        "analytics",
        "US",
        "events",
        "TABLE",
    )
    assert (table.num_rows, table.number_of_columns) == (1_200_000, 3)
    assert (table.total_logical_bytes, table.long_term_logical_bytes) == (
        5_000_000_000,
        2_000_000_000,
    )
    assert table.creation_time == "2025-01-15T09:30:00Z"  # milliseconds are dropped, not rounded
    assert table.last_modified_time == "2025-10-01T04:00:00Z"
    assert table.dataset_labels == {"team": "data"} and table.labels == {"env": "prod"}
    assert table.details_available is True


def test_an_external_table_gives_its_format_and_its_uris_joined_with_semicolons():
    info = {
        "externalDataConfiguration": {
            "sourceFormat": "PARQUET",
            "sourceUris": ["gs://b/x/*.parquet", "gs://b/y/*.parquet"],
        }
    }
    service = _simple(
        table_pages={"analytics": [[_ref("ext", "EXTERNAL")]]},
        table_info={("analytics", "ext"): info},
    )
    (table,) = _collect(service)[0].tables
    assert table.table_type == "EXTERNAL"
    assert table.external_source_format == "PARQUET"
    assert table.external_source_uri == "gs://b/x/*.parquet; gs://b/y/*.parquet"


def test_a_view_has_no_size_and_stays_at_zero_with_empty_dates():
    service = _simple(
        table_pages={"analytics": [[_ref("v", "VIEW")]]}, table_info={("analytics", "v"): {}}
    )
    (table,) = _collect(service)[0].tables
    assert (table.total_logical_bytes, table.num_rows, table.number_of_columns) == (0, 0, 0)
    assert table.creation_time == "" and table.external_source_format == ""


@pytest.mark.parametrize(
    "milliseconds,expected",
    [
        ("1736933400123", "2025-01-15T09:30:00Z"),
        ("1736933400999", "2025-01-15T09:30:00Z"),
        ("0", "1970-01-01T00:00:00Z"),
        (None, ""),
        ("", ""),
    ],
)
def test_dates_are_utc_to_the_second(milliseconds, expected):
    assert _iso_utc(milliseconds) == expected


# ── paging ────────────────────────────────────────────────────────────────────


def test_every_page_of_datasets_and_tables_is_read():
    service = _simple(
        dataset_pages=[[_dataset("analytics")], [_dataset("raw")]],
        dataset_info={"analytics": {"location": "US"}, "raw": {"location": "EU"}},
        table_pages={
            "analytics": [[_ref("t1")], [_ref("t2")]],
            "raw": [[_ref("t3", dataset="raw")]],
        },
        table_info={
            ("analytics", "t1"): {},
            ("analytics", "t2"): {},
            ("raw", "t3"): {},
        },
    )
    inventory, errors = _collect(service)
    assert inventory.dataset_count == 2
    assert [(t.dataset_id, t.table_id) for t in inventory.tables] == [
        ("analytics", "t1"),
        ("analytics", "t2"),
        ("raw", "t3"),
    ]
    assert errors == []


# ── roll-ups ──────────────────────────────────────────────────────────────────


def test_only_tables_and_materialized_views_count_as_protectable_data():
    kinds = ["TABLE", "MATERIALIZED_VIEW", "VIEW", "EXTERNAL", "SNAPSHOT"]
    service = _simple(
        table_pages={"analytics": [[_ref(f"t{i}", k) for i, k in enumerate(kinds)]]},
        table_info={("analytics", f"t{i}"): {"numBytes": "100"} for i in range(len(kinds))},
    )
    inventory, _ = _collect(service)
    assert inventory.table_counts == dict.fromkeys(kinds, 1)
    assert inventory.protectable_logical_bytes == 200


# ── failures ──────────────────────────────────────────────────────────────────

_DISABLED = (
    "403 BigQuery API has not been used in project proj-a before or it is disabled. Enable it by "
    "visiting https://console.developers.google.com/apis/api/bigquery.googleapis.com/overview"
)


def test_a_disabled_api_gives_an_empty_inventory_and_one_api_disabled_record():
    service = _simple(dataset_pages=[RuntimeError(_DISABLED)])
    inventory, errors = _collect(service)
    assert inventory.tables == [] and inventory.dataset_count == 0
    assert [(e["collector"], e["category"]) for e in errors] == [("bigquery", "API_DISABLED")]
    assert inventory.incomplete_calls == 1


def test_a_table_whose_details_fail_is_still_listed_with_a_zero_size():
    service = _simple(
        table_pages={"analytics": [[_ref("events"), _ref("broken")]]},
        table_info={
            ("analytics", "events"): {"numBytes": "10"},
            ("analytics", "broken"): RuntimeError("Not found"),
        },
    )
    inventory, errors = _collect(service)
    events, broken = inventory.tables
    assert events.total_logical_bytes == 10 and events.details_available is True
    assert broken.total_logical_bytes == 0 and broken.details_available is False
    assert [e["message"].endswith("(table details)") for e in errors] == [True]
    assert inventory.incomplete_calls == 1


def test_a_dataset_whose_details_fail_keeps_its_tables_with_an_empty_location():
    service = _simple(dataset_info={"analytics": RuntimeError("Access Denied")})
    inventory, errors = _collect(service)
    assert [t.location for t in inventory.tables] == [""]
    assert inventory.tables[0].dataset_labels == {}
    assert [e["message"].endswith("(dataset details)") for e in errors] == [True]


def test_a_dataset_whose_table_list_fails_gives_no_rows_and_a_record():
    service = _simple(table_pages={"analytics": [RuntimeError("Access Denied")]})
    inventory, errors = _collect(service)
    assert inventory.tables == [] and inventory.dataset_count == 1
    assert [e["message"].endswith("(tables)") for e in errors] == [True]


def test_many_failures_of_one_kind_are_one_record_that_says_how_many():
    many = 40
    service = _simple(
        table_pages={"analytics": [[_ref(f"t{i}") for i in range(many)]]},
        table_info={("analytics", f"t{i}"): RuntimeError("Not found") for i in range(many)},
    )
    inventory, errors = _collect(service)
    assert len(inventory.tables) == many
    assert len(errors) == 1 and "(40 table details calls failed)" in errors[0]["message"]
    assert inventory.incomplete_calls == many


def test_a_client_that_cannot_be_built_is_recorded_and_gives_an_empty_inventory():
    with patch("googleapiclient.discovery.build", side_effect=ImportError("No module named x")):
        collector = BigQueryCollector(PROJECT, MagicMock())
        inventory = collector.collect()
    assert inventory.tables == [] and inventory.incomplete_calls == 1
    assert [e["category"] for e in collector.errors] == ["SDK_MISSING"]

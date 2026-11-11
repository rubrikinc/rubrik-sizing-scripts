"""BigQuery collector for Rubrik Discovery — GCP Edition.

Lists every dataset of a project and every table, view, materialized view, external table and
snapshot in it, with the logical size of each (``numBytes``, ``numLongTermBytes``), the row and
column counts, the external source of an external table, the dates and the labels. This is what
``Get-GCPBigQueryInventory`` of Get-GCPSizingInfo.ps1 collects with the ``bq`` command; here the
BigQuery REST API is called directly, so nothing but the Google API client is needed.

Credential injection rule: always receive credentials from ``main.py``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from collectors.retry import retry_call
from collectors.utils import brief_error, collection_error
from models.inventory import BigQueryInventory, BigQueryTable

logger = logging.getLogger(__name__)

# The table types whose data lives in BigQuery. Views, external tables and snapshots are not counted.
PROTECTABLE_TYPES = ("TABLE", "MATERIALIZED_VIEW")

_PAGE_SIZE = 1000


def _iso_utc(milliseconds: Any) -> str:
    """``2026-10-08T04:34:39Z`` for a Unix time in milliseconds; empty when there is none."""
    if not milliseconds:
        return ""
    moment = datetime.fromtimestamp(int(milliseconds) // 1000, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class BigQueryCollector:
    """Collects BigQuery datasets and tables for one project.

    Credential injection rule: always receive credentials from ``main.py``.
    """

    def __init__(self, project_id: str, credentials) -> None:
        self._project_id = project_id
        self._credentials = credentials
        self.errors: list[dict] = []
        # One record per kind of failure, however many calls failed: a project can have thousands
        # of tables and one error each would bury everything else.
        self._failures: dict[str, list] = {}

    def collect(self) -> BigQueryInventory:
        """Collect the project's BigQuery inventory.

        Returns:
            BigQueryInventory. A call that fails (API disabled, no permission) is recorded in
            ``errors`` and the rest is still collected; the totals are then low.
        """
        try:
            import googleapiclient.discovery  # deferred import

            service = googleapiclient.discovery.build(
                "bigquery", "v2", credentials=self._credentials, cache_discovery=False
            )
        except Exception as exc:
            logger.warning(
                "BigQuery collection failed for project %s: %s", self._project_id, brief_error(exc)
            )
            self.errors.append(collection_error("bigquery", exc))
            return BigQueryInventory(project_id=self._project_id, incomplete_calls=1)

        tables: list[BigQueryTable] = []
        datasets = self._list(
            service.datasets(), "datasets", "datasets", projectId=self._project_id
        )
        for dataset in datasets or []:
            dataset_id = dataset["datasetReference"]["datasetId"]
            location, dataset_labels = self._dataset_details(service, dataset_id)
            tables.extend(self._collect_tables(service, dataset_id, location, dataset_labels))

        self._record_failures()
        counts: dict[str, int] = {}
        for t in tables:
            counts[t.table_type or ""] = counts.get(t.table_type or "", 0) + 1
        inventory = BigQueryInventory(
            project_id=self._project_id,
            dataset_count=len(datasets or []),
            tables=tables,
            table_counts=counts,
            protectable_logical_bytes=sum(
                t.total_logical_bytes for t in tables if t.table_type in PROTECTABLE_TYPES
            ),
            incomplete_calls=sum(len(v) for v in self._failures.values()),
        )
        logger.debug(
            "Project %s: %d BigQuery datasets, %d tables/views",
            self._project_id,
            len(datasets or []),
            len(tables),
        )
        return inventory

    # ── API calls ─────────────────────────────────────────────────────────────

    def _list(self, resource, items_key: str, what: str, **params) -> Optional[list[dict]]:
        """Every page of a list call, or None (recorded) if it fails."""
        try:
            items: list[dict] = []
            request = resource.list(maxResults=_PAGE_SIZE, **params)
            while request is not None:
                response = retry_call(
                    request.execute, description=f"bigquery.{what}.list({self._project_id})"
                )
                items.extend(response.get(items_key, []))
                request = resource.list_next(request, response)
            return items
        except Exception as exc:
            self._failed(what, exc)
            return None

    def _dataset_details(self, service, dataset_id: str) -> tuple[str, dict[str, str]]:
        try:
            info = retry_call(
                service.datasets().get(projectId=self._project_id, datasetId=dataset_id).execute,
                description=f"bigquery.datasets.get({self._project_id}:{dataset_id})",
            )
            return info.get("location") or "", info.get("labels") or {}
        except Exception as exc:
            self._failed("dataset details", exc)
            return "", {}

    def _collect_tables(
        self, service, dataset_id: str, location: str, dataset_labels: dict[str, str]
    ) -> list[BigQueryTable]:
        listed = self._list(
            service.tables(), "tables", "tables", projectId=self._project_id, datasetId=dataset_id
        )
        tables = []
        for item in listed or []:
            table_id = item["tableReference"]["tableId"]
            table = BigQueryTable(
                dataset_id=dataset_id,
                location=location,
                table_id=table_id,
                table_type=item.get("type"),
                dataset_labels=dict(dataset_labels),
            )
            try:
                info = retry_call(
                    service.tables()
                    .get(projectId=self._project_id, datasetId=dataset_id, tableId=table_id)
                    .execute,
                    description=f"bigquery.tables.get({self._project_id}:{dataset_id}.{table_id})",
                )
                self._fill(table, info)
            except Exception as exc:
                table.details_available = False
                self._failed("table details", exc)
            tables.append(table)
        return tables

    @staticmethod
    def _fill(table: BigQueryTable, info: dict[str, Any]) -> None:
        """Read a ``tables.get`` answer. Values missing from it stay at 0 or empty."""
        if info.get("numBytes"):
            table.total_logical_bytes = int(info["numBytes"])
        if info.get("numLongTermBytes"):
            table.long_term_logical_bytes = int(info["numLongTermBytes"])
        if info.get("numRows"):
            table.num_rows = int(info["numRows"])
        fields = (info.get("schema") or {}).get("fields")
        if fields:
            table.number_of_columns = len(fields)
        table.creation_time = _iso_utc(info.get("creationTime"))
        table.last_modified_time = _iso_utc(info.get("lastModifiedTime"))
        external = info.get("externalDataConfiguration")
        if external:
            table.external_source_format = external.get("sourceFormat") or ""
            table.external_source_uri = "; ".join(external.get("sourceUris") or [])
        table.labels = info.get("labels") or {}

    # ── Failures ──────────────────────────────────────────────────────────────

    def _failed(self, what: str, exc: Exception) -> None:
        logger.debug("BigQuery %s failed for project %s: %s", what, self._project_id, exc)
        self._failures.setdefault(what, []).append(exc)

    def _record_failures(self) -> None:
        """One record per kind of failure, saying how many calls failed."""
        for what, excs in self._failures.items():
            record = collection_error("bigquery", excs[0])
            if len(excs) > 1:
                record["message"] += f" ({len(excs)} {what} calls failed)"
            else:
                record["message"] += f" ({what})"
            logger.warning(
                "BigQuery %s failed for project %s: %s", what, self._project_id, record["message"]
            )
            self.errors.append(record)

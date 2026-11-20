"""BigQuery collector for Rubrik Discovery — GCP Edition.

Lists every dataset of a project and every table, view, materialized view, external table and
snapshot in it, with the logical size of each (``numBytes``, ``numLongTermBytes``), the row and
column counts, the external source of an external table, the dates and the labels. This is what
``Get-GCPBigQueryInventory`` of Get-GCPSizingInfo.ps1 collects with the ``bq`` command; here the
BigQuery REST API is called directly, so nothing but the Google API client is needed.

A project can hold tens of thousands of tables, and ``tables.get`` is one call per table. The calls
run in a thread pool (one client per thread, as httplib2 is not thread safe), each call has a
network timeout and is retried by the Google client, and a project that runs past its time budget
(or a run that is asked to stop) keeps the tables it has sized and reports the rest as not read.

Credential injection rule: always receive credentials from ``main.py``.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Optional

from collectors.retry import retry_call
from collectors.utils import ScanStopped, brief_error, collection_error, stop_requested
from models.inventory import BigQueryInventory, BigQueryTable

logger = logging.getLogger(__name__)

# The table types whose data lives in BigQuery. Views, external tables and snapshots are not counted.
PROTECTABLE_TYPES = ("TABLE", "MATERIALIZED_VIEW")

_PAGE_SIZE = 1000

# Parallel ``tables.get`` calls per project. Projects already run in parallel, so this is kept modest.
DETAIL_WORKERS = 16
# Seconds one call may wait on the network. Without it a stalled connection waits for ever.
_HTTP_TIMEOUT_S = 60
# Retries the Google client makes itself (429, 5xx, dropped connections), with backoff.
_NUM_RETRIES = 5
# Seconds one project's BigQuery scan may take before the tables not yet sized are left at zero and
# the project is reported as partial. 0 means no limit.
DEFAULT_TIME_BUDGET_S = 1800
_PROGRESS_EVERY = 2000


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

    def __init__(
        self,
        project_id: str,
        credentials,
        time_budget_s: float = DEFAULT_TIME_BUDGET_S,
        workers: int = DETAIL_WORKERS,
    ) -> None:
        self._project_id = project_id
        self._credentials = credentials
        self._time_budget_s = time_budget_s
        self._workers = max(1, workers)
        self._deadline: Optional[float] = None
        self._local = threading.local()
        self._lock = threading.Lock()
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
            service = self._service()
        except Exception as exc:
            logger.warning(
                "BigQuery collection failed for project %s: %s", self._project_id, brief_error(exc)
            )
            self.errors.append(collection_error("bigquery", exc))
            return BigQueryInventory(project_id=self._project_id, incomplete_calls=1)

        self._deadline = time.monotonic() + self._time_budget_s if self._time_budget_s > 0 else None
        datasets = self._list(
            service.datasets(), "datasets", "datasets", projectId=self._project_id
        )
        dataset_ids = [d["datasetReference"]["datasetId"] for d in datasets or []]

        tables: list[BigQueryTable] = []
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            # Each dataset's location, labels and table list, then every table's details.
            listings = list(pool.map(self._dataset_listing, dataset_ids))
            for dataset_id, (location, dataset_labels, listed) in zip(dataset_ids, listings):
                for item in listed:
                    tables.append(
                        BigQueryTable(
                            dataset_id=dataset_id,
                            location=location,
                            table_id=item["tableReference"]["tableId"],
                            table_type=item.get("type"),
                            dataset_labels=dict(dataset_labels),
                        )
                    )
            self._fill_all(pool, tables)

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

    def _service(self):
        """This thread's BigQuery client, with a network timeout (built once per thread)."""
        service = getattr(self._local, "service", None)
        if service is None:
            import googleapiclient.discovery  # deferred import

            kwargs: dict[str, Any] = {"credentials": self._credentials}
            try:
                import google_auth_httplib2
                import httplib2

                kwargs = {
                    "http": google_auth_httplib2.AuthorizedHttp(
                        self._credentials, http=httplib2.Http(timeout=_HTTP_TIMEOUT_S)
                    )
                }
            except ImportError:  # the client then has no timeout of its own
                pass
            service = googleapiclient.discovery.build(
                "bigquery", "v2", cache_discovery=False, **kwargs
            )
            self._local.service = service
        return service

    def _execute(self, request, description: str):
        return retry_call(
            lambda: request.execute(num_retries=_NUM_RETRIES),
            description=f"bigquery.{description}({self._project_id})",
        )

    def _out_of_time(self) -> bool:
        return stop_requested() or (
            self._deadline is not None and time.monotonic() > self._deadline
        )

    def _list(self, resource, items_key: str, what: str, **params) -> Optional[list[dict]]:
        """Every page of a list call, or None (recorded) if it fails."""
        try:
            items: list[dict] = []
            request = resource.list(maxResults=_PAGE_SIZE, **params)
            while request is not None:
                response = self._execute(request, f"{what}.list")
                items.extend(response.get(items_key, []))
                request = resource.list_next(request, response)
            return items
        except Exception as exc:
            self._failed(what, exc)
            return None

    def _dataset_listing(self, dataset_id: str) -> tuple[str, dict[str, str], list[dict]]:
        """A dataset's location, its labels and its tables as listed (no details yet)."""
        if self._out_of_time():
            self._failed(self._not_read("datasets"), ScanStopped(dataset_id))
            return "", {}, []
        service = self._service()
        location, labels = self._dataset_details(service, dataset_id)
        listed = self._list(
            service.tables(), "tables", "tables", projectId=self._project_id, datasetId=dataset_id
        )
        return location, labels, listed or []

    def _dataset_details(self, service, dataset_id: str) -> tuple[str, dict[str, str]]:
        try:
            info = self._execute(
                service.datasets().get(projectId=self._project_id, datasetId=dataset_id),
                f"datasets.get:{dataset_id}",
            )
            return info.get("location") or "", info.get("labels") or {}
        except Exception as exc:
            self._failed("dataset details", exc)
            return "", {}

    def _fill_all(self, pool: ThreadPoolExecutor, tables: list[BigQueryTable]) -> None:
        """Read ``tables.get`` for every table, in parallel. Tables not reached before the time
        budget runs out (or a stop request) stay at zero and are counted in one record."""
        total = len(tables)
        counts = {"done": 0, "skipped": 0}

        def one(table: BigQueryTable) -> None:
            if self._out_of_time():
                table.details_available = False
                with self._lock:
                    counts["skipped"] += 1
                return
            try:
                info = self._execute(
                    self._service()
                    .tables()
                    .get(
                        projectId=self._project_id,
                        datasetId=table.dataset_id,
                        tableId=table.table_id,
                    ),
                    f"tables.get:{table.dataset_id}.{table.table_id}",
                )
                self._fill(table, info)
            except Exception as exc:
                table.details_available = False
                self._failed("table details", exc)
            with self._lock:
                counts["done"] += 1
                if counts["done"] % _PROGRESS_EVERY == 0:
                    logger.info(
                        "BigQuery project %s: sized %d of %d tables",
                        self._project_id,
                        counts["done"],
                        total,
                    )

        list(pool.map(one, tables))
        if counts["skipped"]:
            self._failed(
                self._not_read(f"{counts['skipped']} of {total} tables, listed with size 0"),
                ScanStopped("not read"),
            )

    @staticmethod
    def _not_read(what: str) -> str:
        why = "the run was stopped" if stop_requested() else "the time limit was reached"
        return f"details not read, {why} ({what})"

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
            # A BigLake table reads its data through a connection; a plain external one has none.
            table.connection_id = external.get("connectionId") or ""
        # A BigQuery Iceberg table keeps its data in a bucket folder it names here, not in sourceUris.
        biglake = info.get("biglakeConfiguration")
        if biglake:
            table.biglake_storage_uri = biglake.get("storageUri") or ""
            table.connection_id = table.connection_id or biglake.get("connectionId") or ""
        table.labels = info.get("labels") or {}

    # ── Failures ──────────────────────────────────────────────────────────────

    def _failed(self, what: str, exc: Exception) -> None:
        logger.debug("BigQuery %s failed for project %s: %s", what, self._project_id, exc)
        with self._lock:
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

"""GCS bucket collector for Rubrik Discovery — GCP Edition.

Lists a project's buckets and reads each bucket's size and object count from Cloud Monitoring.
Monitoring measures a bucket once a day and leaves out an empty (or brand new) bucket, so a bucket
with no datapoint has a blank size, never a 0, and is told apart from a read that failed.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Optional

from models.discovery_dataclasses import (
    GROWTH_MEASURED,
    GROWTH_NOT_READ,
    GROWTH_TOO_FEW_READINGS,
    SIZE_MEASURED,
    SIZE_NO_DATAPOINT,
    SIZE_NOT_READ,
    STORAGE_CLASSES,
)
from models.inventory import GCSBucket, StorageInventory

from collectors.retry import retry_call
from collectors.utils import LabelSummary, brief_error, build_label_summary, collection_error

logger = logging.getLogger(__name__)

# Bytes by storage class and type of data (live, noncurrent, soft-deleted, multipart upload). The
# older ``storage/total_bytes`` has no type label, so the split needs this one.
BYTES_METRIC = "storage.googleapis.com/storage/v2/total_bytes"
# Objects by storage class. Soft-deleted objects are not counted.
OBJECT_COUNT_METRIC = "storage.googleapis.com/storage/object_count"

_LIVE = "live-object"
_NONCURRENT = "noncurrent-object"
_SOFT_DELETED = "soft-deleted-object"
_MULTIPART = "multipart-upload"

# A bucket is measured once a day and the point shows up to 690 seconds after it is sampled, so a
# window of a few days always holds the latest day's reading, however late it is.
_LOOKBACK = datetime.timedelta(days=3)
_PAGE_SIZE = 1000


def _bytes_to_gb_tb(size_bytes: Optional[int]) -> tuple[Optional[float], Optional[float]]:
    """Decimal GB/TB siblings of a native-bytes value; None propagates through."""
    if size_bytes is None:
        return None, None
    return round(size_bytes / 1e9, 2), round(size_bytes / 1e12, 4)


# Monitoring reports Standard data under these names, by the bucket's location type, so a bucket
# whose objects are all Standard shows no STANDARD series at all.
_STANDARD_LABELS = frozenset({"REGIONAL", "MULTI_REGIONAL"})


def _class_key(storage_class: str) -> str:
    """The ``STORAGE_CLASSES`` entry a Monitoring ``storage_class`` label belongs to."""
    name = (storage_class or "").upper()
    if name in _STANDARD_LABELS:
        return "STANDARD"
    return name if name in STORAGE_CLASSES else "OTHER"


def _flag(value: Any) -> Optional[bool]:
    """``True``/``False`` as reported, ``None`` for anything else (missing or not a bool)."""
    return value if isinstance(value, bool) else None


def _text(value: Any) -> Optional[str]:
    """A non-empty string as reported, else ``None``."""
    return value if isinstance(value, str) and value else None


def _property(bucket: Any, name: str) -> Any:
    """A bucket property, or ``None`` when the client library cannot read it."""
    try:
        return getattr(bucket, name, None)
    except Exception:
        return None


def _lifecycle(bucket: Any) -> dict[str, Any]:
    """What the bucket's lifecycle rules do to the data, as the fields a retention estimate needs.

    A rule is an action (Delete, SetStorageClass, AbortIncompleteMultipartUpload) and the
    conditions it applies under. Only age-based rules say how long data is kept, so a rule that
    also needs a label, a prefix or a number of newer versions is counted but not read as a
    retention, and a delete rule limited to one storage class is left out the same way. The
    smallest age wins when several rules delete. Rules the client cannot read give no fields.
    """
    rules = _property(bucket, "lifecycle_rules")
    if rules is None:
        return {}
    try:
        rules = list(rules)
    except Exception:
        return {}

    delete_days: list[int] = []
    noncurrent_days: list[int] = []
    transitions: list[tuple[int, str]] = []
    for rule in rules:
        action = rule.get("action") or {}
        condition = rule.get("condition") or {}
        kind = action.get("type")
        if set(condition) - {"age", "isLive", "daysSinceNoncurrentTime", "matchesStorageClass"}:
            continue  # labels, prefixes, version counts or dates: not a plain age
        if kind == "Delete":
            if "matchesStorageClass" in condition:
                continue  # removes data in one class only, so it is not the bucket's retention
            if condition.get("isLive") is False or "daysSinceNoncurrentTime" in condition:
                days = condition.get("daysSinceNoncurrentTime", condition.get("age"))
                if isinstance(days, int):
                    noncurrent_days.append(days)
            elif isinstance(condition.get("age"), int):
                delete_days.append(condition["age"])
        elif kind == "SetStorageClass" and isinstance(condition.get("age"), int):
            if _text(action.get("storageClass")):
                transitions.append((condition["age"], action["storageClass"]))

    return {
        "lifecycle_rule_count": len(rules),
        "lifecycle_delete_days": min(delete_days) if delete_days else None,
        "lifecycle_noncurrent_delete_days": min(noncurrent_days) if noncurrent_days else None,
        "lifecycle_transitions": (
            "; ".join(f"{cls}@{days}d" for days, cls in sorted(transitions)) or None
        ),
    }


def _growth_endpoints(series_iter) -> dict[str, tuple[float, int, float, int]]:
    """``{bucket: (first_time, first_bytes, last_time, last_bytes)}``: a bucket's oldest and newest
    point. Points are kept by time, so a bucket that comes back as several series is added up."""
    by_time: dict[str, dict[float, int]] = {}
    for series in series_iter:
        bucket = series.resource.labels.get("bucket_name")
        if not bucket:
            continue
        points = by_time.setdefault(bucket, {})
        for point in series.points:
            when = point.interval.end_time.timestamp()
            points[when] = points.get(when, 0) + _point_value(point)
    return {
        bucket: (min(points), points[min(points)], max(points), points[max(points)])
        for bucket, points in by_time.items()
        if points
    }


def _point_value(point) -> int:
    """A point's number: Monitoring gives bytes as a double and counts as an integer."""
    value = point.value
    return int(value.double_value or value.int64_value or 0)


def _latest_by_series(series_iter) -> dict[str, dict[tuple[str, str], tuple[Any, int]]]:
    """``{bucket: {(storage_class, type): (time, value)}}``: the newest point of every series.

    Every query asks for one aligned point per series, but a series may still come back with
    more than one, so the newest of them wins here rather than the first.
    """
    latest: dict[str, dict[tuple[str, str], tuple[Any, int]]] = {}
    for series in series_iter:
        bucket = series.resource.labels.get("bucket_name")
        if not bucket or not series.points:
            continue
        key = (series.metric.labels.get("storage_class", ""), series.metric.labels.get("type", ""))
        point = max(series.points, key=lambda p: p.interval.end_time.timestamp())
        when = point.interval.end_time.timestamp()
        known = latest.setdefault(bucket, {}).get(key)
        if known is None or when > known[0]:
            latest[bucket][key] = (when, _point_value(point))
    return latest


class StorageCollector:
    """Collect Google Cloud Storage bucket metadata and sizes for a GCP project.

    Uses the Cloud Storage client to list buckets and fetch per-bucket properties. A bucket's size
    and object count come from Cloud Monitoring, one query for the whole project each, not one call
    per bucket, so a project with thousands of buckets costs two requests. If Monitoring cannot be
    read the buckets are still listed, the failure is recorded, and the sizes stay blank.

    Credential injection rule: always receive credentials from ``main.py``.
    """

    def __init__(
        self,
        project_id: str,
        credentials,
        growth_days: Optional[int] = None,
    ) -> None:
        """
        Args:
            project_id: GCP project ID.
            credentials: Authenticated google.auth Credentials instance.
            growth_days: Look back this many days to measure each bucket's growth, with one more
                Monitoring query for the project. None (the default) leaves growth off.
        """
        self._project_id = project_id
        self._credentials = credentials
        self._growth_days = growth_days
        self.errors: list[dict] = []

    def collect(self) -> StorageInventory:
        """List all GCS buckets and their metadata.

        Returns:
            StorageInventory. On permission error, returns an empty inventory
            and logs a warning rather than raising.
        """
        from google.cloud import storage  # deferred import

        try:
            client = storage.Client(project=self._project_id, credentials=self._credentials)
            buckets = self._list_buckets(client)
        except Exception as exc:
            logger.warning(
                "Storage collection failed for project %s: %s "
                "(needs storage.buckets.list and storage.buckets.get on the project)",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("storage", exc))
            return StorageInventory(project_id=self._project_id)

        if buckets:
            sizes_read = self._fill_sizes(buckets)
            if self._growth_days and sizes_read:
                self._fill_growth(buckets, self._growth_days)
            elif self._growth_days:
                # Monitoring just failed for the sizes; the same call would fail again, slowly.
                for bucket in buckets:
                    bucket.growth_status = GROWTH_NOT_READ
        return self._build_inventory(buckets)

    def _list_buckets(self, client) -> list[GCSBucket]:
        buckets: list[GCSBucket] = []

        bucket_objs = retry_call(
            lambda: list(client.list_buckets()),
            description=f"list_buckets({self._project_id})",
        )
        for blob_bucket in bucket_objs:
            soft_delete_days = self._get_soft_delete_days(blob_bucket)
            location = (blob_bucket.location or "").upper()
            location_type = self._classify_location_type(blob_bucket)

            bucket = GCSBucket(
                name=blob_bucket.name,
                location=location,
                location_type=location_type,
                storage_class=blob_bucket.storage_class or "STANDARD",
                versioning_enabled=bool(blob_bucket.versioning_enabled),
                soft_delete_retention_days=soft_delete_days,
                labels=dict(blob_bucket.labels) if blob_bucket.labels else {},
                **self._settings(blob_bucket, soft_delete_days, location_type),
            )
            buckets.append(bucket)

        return buckets

    @staticmethod
    def _settings(bucket, soft_delete_days: Optional[int], location_type: str) -> dict[str, Any]:
        """The ``GCSBucket`` fields that are plain settings of the bucket object.

        Each one is read defensively: a property the client library cannot give is ``None`` (blank
        in the CSV), never a guess.
        """
        created = _property(bucket, "time_created")
        retention_seconds = _property(bucket, "retention_period")
        iam = _property(bucket, "iam_configuration")
        dual = location_type == "dual-region"
        locations = _property(bucket, "data_locations")
        terminal = _property(bucket, "autoclass_terminal_storage_class")
        autoclass = _flag(_property(bucket, "autoclass_enabled"))
        kms_key = _text(_property(bucket, "default_kms_key_name"))
        has_retention = isinstance(retention_seconds, int) and not isinstance(
            retention_seconds, bool
        )

        return {
            "creation_time": (
                created.isoformat() if isinstance(created, datetime.datetime) else None
            ),
            "dual_region_locations": (
                [str(item) for item in locations] if isinstance(locations, (list, tuple)) else []
            ),
            # Turbo replication is a dual-region setting, so any other bucket leaves it blank.
            "turbo_replication_enabled": (
                _property(bucket, "rpo") == "ASYNC_TURBO" if dual else None
            ),
            "autoclass_enabled": autoclass,
            "autoclass_terminal_storage_class": _text(terminal) if autoclass else None,
            # The API leaves the setting out of a bucket without HNS, so not reported means flat.
            "hns_enabled": _flag(_property(bucket, "hierarchical_namespace_enabled")) is True,
            "retention_policy_enabled": has_retention,
            "retention_period_days": retention_seconds // 86400 if has_retention else None,
            "bucket_lock_locked": _flag(_property(bucket, "retention_policy_locked")) is True,
            "soft_delete_enabled": soft_delete_days is not None,
            "default_kms_key_name": kms_key,
            "ubla_enabled": _flag(
                _property(iam, "uniform_bucket_level_access_enabled") if iam is not None else None
            ),
            "public_access_prevention": (
                _text(_property(iam, "public_access_prevention")) if iam is not None else None
            ),
            "requester_pays": _flag(_property(bucket, "requester_pays")),
            **_lifecycle(bucket),
        }

    # ── Cloud Monitoring ──────────────────────────────────────────────────────

    def _fill_sizes(self, buckets: list[GCSBucket]) -> bool:
        """Set every bucket's size and object count from two project-wide Monitoring queries.

        Only the buckets this project listed are filled: Monitoring reports on every bucket in the
        project's metrics scope, which can include other projects' buckets. Returns False when
        Monitoring could not be read.
        """
        try:
            sizes = self._query(BYTES_METRIC)
            counts = self._query(OBJECT_COUNT_METRIC)
        except Exception as exc:
            logger.warning(
                "Storage sizes could not be read for project %s: %s "
                "(needs roles/monitoring.viewer and the Cloud Monitoring API)",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("storage:monitoring", exc))
            for bucket in buckets:
                bucket.size_status = SIZE_NOT_READ
            return False

        for bucket in buckets:
            self._apply(bucket, sizes.get(bucket.name), counts.get(bucket.name))
        return True

    def _fill_growth(self, buckets: list[GCSBucket], days: int) -> None:
        """Set every bucket's growth from one more project-wide Monitoring query.

        This is a query of its own, not a wider window on the size query: the size query keeps the
        newest point of every storage-class series, and over weeks a class that was emptied would
        keep its old reading in today's size. Here the classes are added up on the server, so the
        response is one series per bucket whatever the number of classes.
        """
        try:
            readings = self._query_growth(days)
        except Exception as exc:
            logger.warning(
                "Storage growth could not be read for project %s: %s",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("storage:growth", exc))
            for bucket in buckets:
                bucket.growth_status = GROWTH_NOT_READ
            return

        for bucket in buckets:
            reading = readings.get(bucket.name)
            if reading is None or reading[0] == reading[2]:
                bucket.growth_status = GROWTH_TOO_FEW_READINGS
                continue
            first_time, first_value, last_time, last_value = reading
            bucket.growth_start_bytes = first_value
            bucket.growth_end_bytes = last_value
            bucket.growth_days = round((last_time - first_time) / 86400, 2)
            bucket.growth_status = GROWTH_MEASURED

    def _query_growth(self, days: int) -> dict[str, tuple[float, int, float, int]]:
        """``{bucket: (first_time, first_bytes, last_time, last_bytes)}`` over the last ``days``.

        Live plus noncurrent bytes, added over storage classes on the server, one daily point per
        bucket. The oldest and the newest point of each bucket are kept.
        """
        from google.cloud import monitoring_v3  # deferred import

        client = monitoring_v3.MetricServiceClient(credentials=self._credentials)
        end = datetime.datetime.now(datetime.timezone.utc)
        request = monitoring_v3.ListTimeSeriesRequest(
            name=f"projects/{self._project_id}",
            filter=(
                f'metric.type="{BYTES_METRIC}" AND resource.type="gcs_bucket" '
                f'AND metric.labels.type = one_of("{_LIVE}","{_NONCURRENT}")'
            ),
            interval=monitoring_v3.TimeInterval(
                end_time=end, start_time=end - datetime.timedelta(days=days)
            ),
            view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            aggregation=monitoring_v3.Aggregation(
                alignment_period=datetime.timedelta(days=1),
                per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_NEXT_OLDER,
                cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
                group_by_fields=["resource.label.bucket_name"],
            ),
            page_size=_PAGE_SIZE,
        )
        return retry_call(
            lambda: _growth_endpoints(client.list_time_series(request=request)),
            description=f"monitoring.list_time_series(growth, {self._project_id})",
        )

    def _query(self, metric: str) -> dict[str, dict[tuple[str, str], tuple[Any, int]]]:
        """The newest point of every series of ``metric``, by bucket (see ``_latest_by_series``)."""
        from google.cloud import monitoring_v3  # deferred import

        client = monitoring_v3.MetricServiceClient(credentials=self._credentials)
        end = datetime.datetime.now(datetime.timezone.utc)
        aligner = monitoring_v3.Aggregation.Aligner.ALIGN_NEXT_OLDER
        request = monitoring_v3.ListTimeSeriesRequest(
            name=f"projects/{self._project_id}",
            filter=f'metric.type="{metric}" AND resource.type="gcs_bucket"',
            interval=monitoring_v3.TimeInterval(end_time=end, start_time=end - _LOOKBACK),
            view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            # One point per series: the newest reading in a day-wide bucket, not every repeat of it.
            aggregation=monitoring_v3.Aggregation(
                alignment_period=datetime.timedelta(days=1), per_series_aligner=aligner
            ),
            page_size=_PAGE_SIZE,
        )
        return retry_call(
            lambda: _latest_by_series(client.list_time_series(request=request)),
            description=f"monitoring.list_time_series({metric}, {self._project_id})",
        )

    @staticmethod
    def _apply(bucket: GCSBucket, sizes, counts) -> None:
        """Fill one bucket from its series, or mark it as having no datapoint."""
        if counts:
            bucket.object_count = sum(value for _, value in counts.values())
            by_class = dict.fromkeys(STORAGE_CLASSES, 0)
            for (storage_class, _), (_, value) in counts.items():
                by_class[_class_key(storage_class)] += value
            bucket.class_object_counts = by_class
        if not sizes:
            bucket.size_status = SIZE_NO_DATAPOINT
            return

        def total(kind: str) -> int:
            return sum(value for (_, k), (_, value) in sizes.items() if k == kind)

        bucket.live_bytes = total(_LIVE)
        bucket.noncurrent_bytes = total(_NONCURRENT)
        bucket.soft_deleted_bytes = total(_SOFT_DELETED)
        bucket.multipart_bytes = total(_MULTIPART)
        # The data a backup would copy: current objects and the older versions kept with them.
        bucket.size_bytes = bucket.live_bytes + bucket.noncurrent_bytes
        by_class = dict.fromkeys(STORAGE_CLASSES, 0)
        live_by_class = dict.fromkeys(STORAGE_CLASSES, 0)
        noncurrent_by_class = dict.fromkeys(STORAGE_CLASSES, 0)
        for (storage_class, kind), (_, value) in sizes.items():
            if kind in (_LIVE, _NONCURRENT):
                key = _class_key(storage_class)
                by_class[key] += value
                (live_by_class if kind == _LIVE else noncurrent_by_class)[key] += value
        bucket.class_bytes = by_class
        bucket.live_class_bytes = live_by_class
        bucket.noncurrent_class_bytes = noncurrent_by_class
        bucket.size_gb, bucket.size_tb = _bytes_to_gb_tb(bucket.size_bytes)
        bucket.size_status = SIZE_MEASURED

    @staticmethod
    def _get_soft_delete_days(bucket) -> Optional[int]:
        """Extract soft-delete retention days from a bucket object."""
        try:
            policy = bucket.soft_delete_policy
            if policy and policy.retention_duration_seconds:
                return int(policy.retention_duration_seconds) // 86400
        except Exception:
            pass
        return None

    @staticmethod
    def _classify_location_type(bucket) -> str:
        """Classify bucket location type from bucket metadata."""
        try:
            lt = (bucket.location_type or "").lower()
            if lt in {"region", "dual-region", "multi-region"}:
                return lt
        except Exception:
            pass
        # Fall back by inspecting the location name heuristically.
        loc = (getattr(bucket, "location", "") or "").upper()
        if loc in {"US", "EU", "ASIA"}:
            return "multi-region"
        return "region"

    def _build_inventory(self, buckets: list[GCSBucket]) -> StorageInventory:
        class_breakdown: dict[str, int] = {}
        location_type_breakdown: dict[str, int] = {}
        total_size: int = 0
        has_size_data = False
        soft_delete_count = 0
        versioning_count = 0

        for b in buckets:
            class_breakdown[b.storage_class] = class_breakdown.get(b.storage_class, 0) + 1
            location_type_breakdown[b.location_type] = (
                location_type_breakdown.get(b.location_type, 0) + 1
            )
            if b.soft_delete_retention_days is not None:
                soft_delete_count += 1
            if b.versioning_enabled:
                versioning_count += 1
            if b.size_bytes is not None:
                total_size += b.size_bytes
                has_size_data = True

        total_count = len(buckets)
        soft_delete_pct = round(soft_delete_count / total_count * 100, 1) if total_count else 0.0
        versioning_pct = round(versioning_count / total_count * 100, 1) if total_count else 0.0

        label_summary: Optional[LabelSummary] = build_label_summary([b.labels for b in buckets])

        logger.debug(
            "Project %s: %d GCS buckets",
            self._project_id,
            total_count,
        )

        total_size_bytes = total_size if has_size_data else None
        total_size_gb, total_size_tb = _bytes_to_gb_tb(total_size_bytes)

        return StorageInventory(
            project_id=self._project_id,
            buckets=buckets,
            total_buckets=total_count,
            total_size_bytes=total_size_bytes,
            total_size_gb=total_size_gb,
            total_size_tb=total_size_tb,
            class_breakdown=class_breakdown,
            location_type_breakdown=location_type_breakdown,
            soft_delete_enabled_count=soft_delete_count,
            soft_delete_pct=soft_delete_pct,
            versioning_enabled_count=versioning_count,
            versioning_pct=versioning_pct,
            label_summary=label_summary,
        )

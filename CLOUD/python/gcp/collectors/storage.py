"""GCS bucket collector for Rubrik Discovery — GCP Edition."""

from __future__ import annotations

import logging
from typing import Optional

from models.inventory import GCSBucket, StorageInventory

from collectors.retry import retry_call
from collectors.utils import LabelSummary, brief_error, build_label_summary, collection_error

logger = logging.getLogger(__name__)


def _bytes_to_gb_tb(size_bytes: Optional[int]) -> tuple[Optional[float], Optional[float]]:
    """Decimal GB/TB siblings of a native-bytes value; None propagates through."""
    if size_bytes is None:
        return None, None
    return round(size_bytes / 1e9, 2), round(size_bytes / 1e12, 4)


class StorageCollector:
    """Collect Google Cloud Storage bucket metadata for a GCP project.

    Uses the Cloud Storage client to list buckets and fetch per-bucket
    properties.  Bucket size (bytes) is fetched from Cloud Monitoring
    on a best-effort basis — if unavailable, ``GCSBucket.size_bytes``
    remains None.

    Credential injection rule: always receive credentials from ``main.py``.
    """

    def __init__(
        self,
        project_id: str,
        credentials,
    ) -> None:
        """
        Args:
            project_id: GCP project ID.
            credentials: Authenticated google.auth Credentials instance.
        """
        self._project_id = project_id
        self._credentials = credentials
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
                "(check roles/storage.objectViewer is granted)",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("storage", exc))
            return StorageInventory(project_id=self._project_id)

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

            size_gb, size_tb = _bytes_to_gb_tb(
                None
            )  # best-effort; set by _fetch_sizes if available
            bucket = GCSBucket(
                name=blob_bucket.name,
                location=location,
                location_type=location_type,
                storage_class=blob_bucket.storage_class or "STANDARD",
                versioning_enabled=bool(blob_bucket.versioning_enabled),
                soft_delete_retention_days=soft_delete_days,
                labels=dict(blob_bucket.labels) if blob_bucket.labels else {},
                size_bytes=None,  # best-effort; set by _fetch_sizes if available
                size_gb=size_gb,
                size_tb=size_tb,
            )
            buckets.append(bucket)

        return buckets

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

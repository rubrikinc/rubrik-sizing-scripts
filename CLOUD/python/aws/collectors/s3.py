"""S3 bucket collector with CloudWatch storage metrics."""

from __future__ import annotations

import csv
import gzip
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from models.discovery import S3Bucket

from collectors import BOTO_ADAPTIVE_CFG, DenialTracker, is_scp_denial, record_metric_failures
from collectors.arns import partition
from collectors.context import skip_bucket_tags

# Buckets created with the legacy "EU" location constraint live in eu-west-1.
_LEGACY_LOCATIONS = {"EU": "eu-west-1"}


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    return response.get("Error", {}).get("Code", "") if isinstance(response, dict) else ""


def _list_bucket_locations(session, tracker: "DenialTracker | None") -> dict[str, str]:
    """Bucket name -> region for every bucket in the account.

    Buckets whose location cannot be determined are left out and recorded once.
    """
    s3 = session.client("s3", config=BOTO_ADAPTIVE_CFG)
    try:
        listing = s3.list_buckets()
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("s3")
            logging.debug("Could not list S3 buckets (SCP denied)")
        else:
            record_metric_failures(tracker, "global", "S3 bucket listing", [exc], service="s3")
        return {}

    locations: dict[str, str] = {}
    errors: list[Exception] = []
    for b in listing.get("Buckets", []):
        name = b.get("Name", "")
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        except Exception as exc:
            errors.append(exc)
            continue
        locations[name] = _LEGACY_LOCATIONS.get(loc, loc)
    record_metric_failures(
        tracker,
        "global",
        "S3 bucket location lookup (these buckets are skipped)",
        errors,
        service="s3",
    )
    return locations


class BucketLocator:
    """Lists the account's buckets and their regions once, shared by all region scans."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._locations: dict[str, str] | None = None

    def locations(self, session, tracker: "DenialTracker | None" = None) -> dict[str, str]:
        with self._lock:
            if self._locations is None:
                self._locations = _list_bucket_locations(session, tracker)
            return self._locations


_WINDOW = timedelta(days=7)
_STANDARD = "StandardStorage"
_ALL_TYPES = "AllStorageTypes"


@dataclass(frozen=True)
class StorageLensConfig:
    """A Storage Lens dashboard and which buckets it covers.

    A ``cloudwatch`` dashboard is read from CloudWatch. One that does not publish there but exports
    CSV or Parquet reports to an S3 bucket is read from that export instead (``export_bucket`` is
    set); which of the two it is comes from the export's manifest at run time.
    """

    config_id: str
    dashboard_region: str
    cloudwatch: bool = True
    export_bucket: str = ""
    export_prefix: str = ""
    include_buckets: tuple[str, ...] = ()
    exclude_buckets: tuple[str, ...] = ()
    include_regions: tuple[str, ...] = ()
    exclude_regions: tuple[str, ...] = ()

    def covers(self, bucket_arn: str, region: str) -> bool:
        if self.include_buckets and bucket_arn not in self.include_buckets:
            return False
        if self.include_regions and region not in self.include_regions:
            return False
        if self.exclude_buckets and bucket_arn in self.exclude_buckets:
            return False
        if self.exclude_regions and region in self.exclude_regions:
            return False
        return True


def _storage_lens_configs_in(
    session, region: str, account_id: str, errors: list[Exception]
) -> list[StorageLensConfig]:
    client = session.client("s3control", region_name=region, config=BOTO_ADAPTIVE_CFG)
    configs: list[StorageLensConfig] = []
    try:
        listed: list[dict] = []
        token = None
        while True:
            page = client.list_storage_lens_configurations(
                AccountId=account_id, **({"NextToken": token} if token else {})
            )
            listed.extend(page.get("StorageLensConfigurationList", []))
            token = page.get("NextToken")
            if not token:
                break
    except Exception as exc:
        # S3 answers AccessDenied in regions that cannot be a Storage Lens home region; that
        # only means there is no dashboard there, so it is not a scan error.
        if "not supported as home region" not in str(exc):
            errors.append(exc)
        return configs
    for item in listed:
        try:
            detail = client.get_storage_lens_configuration(
                ConfigId=item["Id"], AccountId=account_id
            )["StorageLensConfiguration"]
        except Exception as exc:
            errors.append(exc)
            continue
        cloudwatch = (detail.get("DataExport") or {}).get("CloudWatchMetrics") or {}
        destination = (detail.get("DataExport") or {}).get("S3BucketDestination") or {}
        export_format = str(destination.get("Format") or "")
        if not detail.get("IsEnabled"):
            logging.info("Storage Lens dashboard %s (%s) is disabled; skipped", item["Id"], region)
            continue
        if cloudwatch.get("IsEnabled"):
            logging.info(
                "Storage Lens dashboard %s (%s) publishes to CloudWatch", item["Id"], region
            )
        elif export_format.upper() in _EXPORT_FORMATS and destination.get("Arn"):
            logging.info(
                "Storage Lens dashboard %s (%s) does not publish to CloudWatch; its %s export "
                "to %s will be read instead",
                item["Id"],
                region,
                export_format,
                destination["Arn"],
            )
        else:
            reason = (
                f"its S3 export is {export_format}, and only CSV and Parquet are read"
                if export_format
                else "it has no S3 export either"
            )
            logging.info(
                "Storage Lens dashboard %s (%s) does not publish to CloudWatch and %s; skipped",
                item["Id"],
                region,
                reason,
            )
            continue
        include, exclude = detail.get("Include") or {}, detail.get("Exclude") or {}
        configs.append(
            StorageLensConfig(
                config_id=item["Id"],
                dashboard_region=region,
                cloudwatch=bool(cloudwatch.get("IsEnabled")),
                export_bucket=(
                    "" if cloudwatch.get("IsEnabled") else str(destination["Arn"]).split(":::")[-1]
                ),
                export_prefix=str(destination.get("Prefix") or ""),
                include_buckets=tuple(include.get("Buckets") or ()),
                exclude_buckets=tuple(exclude.get("Buckets") or ()),
                include_regions=tuple(include.get("Regions") or ()),
                exclude_regions=tuple(exclude.get("Regions") or ()),
            )
        )
    return configs


_EXPORT_LOOKBACK_DAYS = 4  # a day's export may not be delivered yet
_EXPORT_FORMATS = ("CSV", "PARQUET")
_EXPORT_MAX_FILE_BYTES = 1024**3
_EXPORT_MAX_PARQUET_BYTES = 256 * 1024**2  # a Parquet file is held in memory to be read
_EXPORT_METRICS = {
    "CurrentVersionStorageBytes": "bytes",
    "CurrentVersionObjectCount": "objects",
}
_EXPORT_COLUMNS = (
    "aws_region",
    "storage_class",
    "record_type",
    "bucket_name",
    "metric_name",
    "metric_value",
)


def _export_lines(client, bucket: str, key: str):
    body = client.get_object(Bucket=bucket, Key=key)["Body"]
    if key.endswith(".gz"):
        return (line.decode("utf-8") for line in gzip.GzipFile(fileobj=body))
    return (line.decode("utf-8") for line in body.iter_lines())


def _csv_records(client, bucket: str, key: str, columns: list[str]):
    """(region, storage_class, record_type, bucket, metric, value) of each row of a CSV report."""
    at = [columns.index(name) for name in _EXPORT_COLUMNS]
    for row in csv.reader(_export_lines(client, bucket, key)):
        if len(row) >= len(columns):
            yield tuple(row[i] for i in at)


def _parquet_records(client, bucket: str, key: str):
    """The same tuples from a Parquet report, which is read whole, a batch at a time."""
    import io

    import pyarrow.parquet as pq

    data = client.get_object(Bucket=bucket, Key=key)["Body"].read()
    parquet = pq.ParquetFile(io.BytesIO(data))
    missing = [n for n in _EXPORT_COLUMNS if n not in parquet.schema_arrow.names]
    if missing:
        raise ValueError(f"Storage Lens Parquet report lacks columns {', '.join(missing)}")
    for batch in parquet.iter_batches(columns=list(_EXPORT_COLUMNS)):
        yield from zip(*(batch.column(name).to_pylist() for name in _EXPORT_COLUMNS))


def _read_storage_lens_export(
    session, lens: StorageLensConfig, account_id: str, errors: list[Exception]
) -> dict[tuple[str, str], dict[str, dict[str, float]]]:
    """Current-version bytes and object counts per (bucket, region) from a dashboard's S3 export.

    Reads the newest daily report within the last few days, found through its manifest at
    <prefix>/StorageLens/<account>/<config>/V_1/manifests/dt=<date>/manifest.json. The result maps
    (bucket, region) to {"bytes": {storage_class: n}, "objects": {storage_class: n}}.
    """
    client = session.client("s3", region_name=lens.dashboard_region, config=BOTO_ADAPTIVE_CFG)
    try:
        located = client.get_bucket_location(Bucket=lens.export_bucket)
        constraint = located.get("LocationConstraint") or "us-east-1"
        bucket_region = _LEGACY_LOCATIONS.get(constraint, constraint)
    except Exception as exc:
        errors.append(exc)
        bucket_region = lens.dashboard_region
    if bucket_region != lens.dashboard_region:
        client = session.client("s3", region_name=bucket_region, config=BOTO_ADAPTIVE_CFG)

    base = "/".join(
        part
        for part in (lens.export_prefix.strip("/"), "StorageLens", account_id, lens.config_id, "V_1")
        if part
    )
    manifest = None
    today = datetime.now(timezone.utc).date()
    for back in range(_EXPORT_LOOKBACK_DAYS):
        day = (today - timedelta(days=back)).isoformat()
        key = f"{base}/manifests/dt={day}/manifest.json"
        try:
            body = client.get_object(Bucket=lens.export_bucket, Key=key)["Body"]
            manifest = json.loads(body.read())
            break
        except Exception as exc:
            if _error_code(exc) not in ("NoSuchKey", "404"):
                errors.append(exc)
                return {}
    if manifest is None:
        logging.warning(
            "Storage Lens dashboard %s: no export manifest under s3://%s/%s/manifests in the last "
            "%d days; CurrentVersion S3 columns are not collected for it",
            lens.config_id,
            lens.export_bucket,
            base,
            _EXPORT_LOOKBACK_DAYS,
        )
        return {}
    report_format = str(manifest.get("reportFormat", "")).upper()
    if report_format not in _EXPORT_FORMATS:
        logging.warning(
            "Storage Lens dashboard %s exports %s, which is not read",
            lens.config_id,
            manifest.get("reportFormat"),
        )
        return {}
    columns: list[str] = []
    if report_format == "CSV":
        columns = [c.strip() for c in str(manifest.get("reportSchema", "")).split(",")]
        if any(name not in columns for name in _EXPORT_COLUMNS):
            logging.warning(
                "Storage Lens dashboard %s: unexpected export schema; not read", lens.config_id
            )
            return {}
    else:
        try:
            import pyarrow  # noqa: F401
        except ImportError:
            logging.warning(
                "Storage Lens dashboard %s exports Parquet, and reading it needs the pyarrow "
                "package, which is not installed (pip install pyarrow); its CurrentVersion S3 "
                "columns are not collected",
                lens.config_id,
            )
            return {}

    found: dict[tuple[str, str], dict[str, dict[str, float]]] = {}
    limit = _EXPORT_MAX_FILE_BYTES if report_format == "CSV" else _EXPORT_MAX_PARQUET_BYTES
    for report in manifest.get("reportFiles") or []:
        key = report.get("key", "")
        if int(report.get("size") or 0) > limit:
            logging.warning("Skipping oversized Storage Lens export file %s", key)
            continue
        try:
            records = (
                _csv_records(client, lens.export_bucket, key, columns)
                if report_format == "CSV"
                else _parquet_records(client, lens.export_bucket, key)
            )
            for region, storage_class, record_type, bucket, metric, raw in records:
                kind = _EXPORT_METRICS.get(metric)
                if record_type != "BUCKET" or kind is None:
                    continue
                try:
                    value = float(raw)
                except (TypeError, ValueError):
                    continue
                entry = found.setdefault((bucket, region), {"bytes": {}, "objects": {}})
                entry[kind][storage_class] = value
        except Exception as exc:
            errors.append(exc)
    logging.info(
        "Storage Lens dashboard %s: read export of %s (%d buckets)",
        lens.config_id,
        manifest.get("reportDate"),
        len(found),
    )
    return found


class StorageLensLookup:
    """Finds the account's CloudWatch-publishing Storage Lens dashboards once, on first use."""

    def __init__(self, regions: list[str]) -> None:
        self._regions = list(regions)
        self._lock = threading.Lock()
        self._configs: list[StorageLensConfig] | None = None
        self._exports: dict[str, dict] = {}
        self._exports_lock = threading.Lock()

    def export_values(
        self,
        session,
        lens: StorageLensConfig,
        account_id: str,
        bucket: str,
        region: str,
        tracker: "DenialTracker | None" = None,
    ) -> tuple[dict[str, Optional[float]], dict[str, Optional[float]]]:
        """A bucket's current-version values from the dashboard's CSV export, which is read once."""
        with self._exports_lock:
            if lens.config_id not in self._exports:
                errors: list[Exception] = []
                self._exports[lens.config_id] = _read_storage_lens_export(
                    session, lens, account_id, errors
                )
                record_metric_failures(
                    tracker, "global", "S3 Storage Lens export", errors, service="s3"
                )
            entry = self._exports[lens.config_id].get((bucket, region)) or {}
        return dict(entry.get("bytes", {})), dict(entry.get("objects", {}))

    def configs(
        self, session, account_id: str, tracker: "DenialTracker | None" = None
    ) -> list[StorageLensConfig]:
        with self._lock:
            if self._configs is None:
                self._configs = self._load(session, account_id, tracker)
            return self._configs

    def _load(
        self, session, account_id: str, tracker: "DenialTracker | None"
    ) -> list[StorageLensConfig]:
        if not self._regions:
            return []
        errors_by_region: list[list[Exception]] = [[] for _ in self._regions]
        with ThreadPoolExecutor(max_workers=min(len(self._regions), 8)) as pool:
            found = list(
                pool.map(
                    lambda pair: _storage_lens_configs_in(session, pair[0], account_id, pair[1]),
                    zip(self._regions, errors_by_region),
                )
            )
        record_metric_failures(
            tracker,
            "global",
            "S3 Storage Lens configuration lookup",
            [e for errors in errors_by_region for e in errors],
            service="s3",
        )
        configs = [c for per_region in found for c in per_region]
        logging.info(
            "Storage Lens: checked %d regions (%s), %d usable dashboard(s)",
            len(self._regions),
            ", ".join(sorted(self._regions)),
            len(configs),
        )
        if not configs:
            logging.info(
                "No Storage Lens dashboard publishing to CloudWatch or exporting CSV in account %s; "
                "CurrentVersion S3 columns are not collected",
                account_id,
            )
        return configs


def _datapoint_value(datapoints: list[dict], latest: bool) -> Optional[float]:
    if not datapoints:
        return None
    if latest:
        return float(max(datapoints, key=lambda dp: dp["Timestamp"]).get("Maximum", 0))
    return max(float(dp.get("Maximum", 0)) for dp in datapoints)


def _maximum(
    cw_client,
    namespace: str,
    metric_name: str,
    dimensions: list[dict],
    errors: list[Exception],
    latest: bool = False,
) -> Optional[float]:
    """Largest daily Maximum over the last 7 days (or the latest day's), None if no datapoints.

    A failed call appends to ``errors`` and returns None, as does "no datapoints"; callers tell
    the two apart through ``errors``.
    """
    end = datetime.now(timezone.utc)
    try:
        resp = cw_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=end - _WINDOW,
            EndTime=end,
            Period=86400,
            Statistics=["Maximum"],
        )
    except Exception as exc:
        errors.append(exc)
        return None
    return _datapoint_value(resp.get("Datapoints", []), latest)


def _dimension_values(metrics: list[dict], name: str) -> list[str]:
    values: list[str] = []
    for metric in metrics:
        for dim in metric.get("Dimensions", []):
            if dim.get("Name") == name and dim.get("Value") not in values:
                values.append(dim["Value"])
    return values


def _list_metrics(cw_client, errors: list[Exception], **kwargs) -> Optional[list[dict]]:
    """All metrics matching the filter, or None if the listing failed (appended to errors)."""
    try:
        return [
            metric
            for page in cw_client.get_paginator("list_metrics").paginate(**kwargs)
            for metric in page.get("Metrics", [])
        ]
    except Exception as exc:
        errors.append(exc)
        return None


def _storage_types_by_bucket(
    cw_client, metric_name: str, errors: list[Exception]
) -> Optional[dict[str, list[str]]]:
    """Bucket name -> the StorageType values that have ``metric_name`` data, for the region."""
    metrics = _list_metrics(cw_client, errors, Namespace="AWS/S3", MetricName=metric_name)
    if metrics is None:
        return None
    by_bucket: dict[str, list[str]] = {}
    for metric in metrics:
        dims = {d.get("Name"): d.get("Value") for d in metric.get("Dimensions", [])}
        bucket, storage_type = dims.get("BucketName"), dims.get("StorageType")
        if bucket and storage_type and storage_type not in by_bucket.setdefault(bucket, []):
            by_bucket[bucket].append(storage_type)
    return by_bucket


def _with_default_first(classes: list[str], default: str) -> list[str]:
    """``default`` first (always present), then the others alphabetically."""
    return [default, *sorted(c for c in classes if c != default)]


def _class_maxima(
    cw_client,
    bucket_name: str,
    metric_name: str,
    classes: list[str],
    errors: list[Exception],
) -> dict[str, Optional[float]]:
    return {
        storage_type: _maximum(
            cw_client,
            "AWS/S3",
            metric_name,
            [
                {"Name": "BucketName", "Value": bucket_name},
                {"Name": "StorageType", "Value": storage_type},
            ],
            errors,
        )
        for storage_type in classes
    }


def _current_version_metrics(
    session,
    lens: StorageLensConfig,
    account_id: str,
    region: str,
    bucket_name: str,
    cw_clients: dict[str, Any],
    errors: list[Exception],
) -> tuple[dict[str, Optional[float]], dict[str, Optional[float]]]:
    """Storage Lens CurrentVersionStorageBytes and CurrentVersionObjectCount per storage class.

    Read from the dashboard's home region, using all seven dimensions CloudWatch requires.
    """
    cw = cw_clients.get(lens.dashboard_region)
    if cw is None:
        cw = cw_clients[lens.dashboard_region] = session.client(
            "cloudwatch", region_name=lens.dashboard_region, config=BOTO_ADAPTIVE_CFG
        )
    listed = _list_metrics(
        cw,
        errors,
        Namespace="AWS/S3/Storage-Lens",
        MetricName="CurrentVersionStorageBytes",
        Dimensions=[
            {"Name": "configuration_id", "Value": lens.config_id},
            {"Name": "bucket_name", "Value": bucket_name},
        ],
    )
    classes = _dimension_values(listed or [], "storage_class")
    base = [
        {"Name": "configuration_id", "Value": lens.config_id},
        {"Name": "aws_account_number", "Value": account_id},
        {"Name": "aws_region", "Value": region},
        {"Name": "bucket_name", "Value": bucket_name},
        {"Name": "metrics_version", "Value": "1.0"},
        {"Name": "record_type", "Value": "BUCKET"},
    ]
    namespace = "AWS/S3/Storage-Lens"
    sizes, counts = {}, {}
    for storage_class in classes:
        dims = [*base, {"Name": "storage_class", "Value": storage_class}]
        sizes[storage_class] = _maximum(
            cw, namespace, "CurrentVersionStorageBytes", dims, errors, latest=True
        )
    for storage_class in classes:
        dims = [*base, {"Name": "storage_class", "Value": storage_class}]
        counts[storage_class] = _maximum(
            cw, namespace, "CurrentVersionObjectCount", dims, errors, latest=True
        )
    return sizes, counts


def _fetch_s3_monthly_trend(
    cw_client, bucket_name: str, errors: list[Exception]
) -> tuple[list[float], Optional[float]]:
    """Fetch 6-month monthly BucketSizeBytes trend for a single S3 bucket.

    Returns (monthly_size_gb, annual_growth_pct).  Uses 30-day periods so we
    get one data point per month.  This is a free CloudWatch metric — no cost.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=180)
    period = 86400 * 30  # 30-day buckets → ~6 data points
    try:
        resp = cw_client.get_metric_statistics(
            Namespace="AWS/S3",
            MetricName="BucketSizeBytes",
            Dimensions=[
                {"Name": "BucketName", "Value": bucket_name},
                {"Name": "StorageType", "Value": "StandardStorage"},
            ],
            StartTime=start,
            EndTime=end,
            Period=period,
            Statistics=["Average"],
        )
        datapoints = sorted(resp.get("Datapoints", []), key=lambda dp: dp["Timestamp"])
        monthly_gb = [round(dp["Average"] / (1024**3), 4) for dp in datapoints]

        annual_growth: Optional[float] = None
        if len(monthly_gb) >= 2:
            first = monthly_gb[0]
            last = monthly_gb[-1]
            months = len(monthly_gb) - 1
            if first > 0 and months > 0:
                # Annualise: total growth / months * 12
                annual_growth = round((last - first) / first / months * 12 * 100, 1)

        return monthly_gb, annual_growth
    except Exception as exc:
        errors.append(exc)
        return [], None


def fetch_s3(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    protected_arns: set[str],
    tracker: "DenialTracker | None" = None,
    locator: "BucketLocator | None" = None,
    storage_lens: "StorageLensLookup | None" = None,
) -> list[S3Bucket]:
    """Fetch S3 buckets that reside in this region, with CloudWatch sizing metrics.

    Sizes are the largest daily value of the last 7 days for every storage class CloudWatch
    reports, and Storage Lens "current version" values are added when a dashboard that
    publishes to CloudWatch covers the bucket, as in the PowerShell script.

    Pass one shared ``locator`` (and ``storage_lens``) across the region scans so the account's
    buckets (and dashboards) are looked up once instead of once per region.
    """
    locations = (locator or BucketLocator()).locations(session, tracker)
    in_region = [name for name, bucket_region in locations.items() if bucket_region == region]
    buckets: list[S3Bucket] = []
    if not in_region:
        return buckets

    # Bucket-level calls must go to the bucket's own region, or S3 answers PermanentRedirect.
    s3_client = session.client("s3", region_name=region, config=BOTO_ADAPTIVE_CFG)
    cw_client = session.client("cloudwatch", region_name=region, config=BOTO_ADAPTIVE_CFG)
    cw_clients: dict[str, Any] = {region: cw_client}
    metric_errors: list[Exception] = []
    tag_errors: list[Exception] = []

    size_types = _storage_types_by_bucket(cw_client, "BucketSizeBytes", metric_errors)
    object_types = _storage_types_by_bucket(cw_client, "NumberOfObjects", metric_errors)
    lens_configs = storage_lens.configs(session, account_id, tracker) if storage_lens else []

    for bucket_name in in_region:
        bucket_region = region

        size_errors: list[Exception] = []
        sizes = _class_maxima(
            cw_client,
            bucket_name,
            "BucketSizeBytes",
            _with_default_first((size_types or {}).get(bucket_name, []), _STANDARD),
            size_errors,
        )
        count_errors: list[Exception] = []
        counts = _class_maxima(
            cw_client,
            bucket_name,
            "NumberOfObjects",
            _with_default_first((object_types or {}).get(bucket_name, []), _ALL_TYPES),
            count_errors,
        )
        metric_errors.extend(size_errors)
        metric_errors.extend(count_errors)
        size_bytes = int(sizes.get(_STANDARD) or 0)
        obj_count = int(counts.get(_ALL_TYPES) or 0)
        size_gb = round(size_bytes / (1024**3), 4)
        size_tb = round(size_bytes / (1024**4), 4)

        bucket_arn = f"arn:{partition(region)}:s3:::{bucket_name}"
        backup_plans = ["AWS Backup"] if bucket_arn in protected_arns else []

        covering = [c for c in lens_configs if c.covers(bucket_arn, region)]
        lens = next((c for c in covering if c.cloudwatch), None)  # CloudWatch first, then an export
        exported = next((c for c in covering if not c.cloudwatch), None)
        cv_bytes: dict[str, Optional[float]] = {}
        cv_objects: dict[str, Optional[float]] = {}
        if lens is not None:
            cv_bytes, cv_objects = _current_version_metrics(
                session, lens, account_id, region, bucket_name, cw_clients, metric_errors
            )
        elif exported is not None and storage_lens is not None:
            cv_bytes, cv_objects = storage_lens.export_values(
                session, exported, account_id, bucket_name, region, tracker
            )

        tags: dict[str, str] = {}
        tags_failed = False
        try:
            if not skip_bucket_tags():  # PowerShell's -SkipBucketTags
                tag_resp = s3_client.get_bucket_tagging(Bucket=bucket_name)
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagSet", [])}
        except Exception as exc:
            if _error_code(exc) != "NoSuchTagSet":  # NoSuchTagSet just means "no tags"
                tags_failed = True
                tag_errors.append(exc)

        monthly_size_gb, annual_growth_pct = _fetch_s3_monthly_trend(
            cw_client, bucket_name, metric_errors
        )

        buckets.append(
            S3Bucket(
                account_id=account_id,
                account_alias=account_alias,
                bucket_name=bucket_name,
                region=bucket_region,
                size_bytes=size_bytes,
                size_gb=size_gb,
                size_tb=size_tb,
                object_count=obj_count,
                in_backup_plan=bool(backup_plans),
                backup_plans=backup_plans,
                tags=tags,
                monthly_size_gb=monthly_size_gb,
                annual_growth_pct=annual_growth_pct,
                size_metric_failed=bool(size_errors),
                object_count_metric_failed=bool(count_errors),
                tags_lookup_failed=tags_failed,
                storage_class_bytes=sizes,
                storage_class_objects=counts,
                current_version_bytes=cv_bytes,
                current_version_objects=cv_objects,
            )
        )

    record_metric_failures(tracker, region, "S3 CloudWatch metrics", metric_errors)
    record_metric_failures(tracker, region, "S3 bucket tag lookup", tag_errors, service="s3")
    return buckets

"""Per-resource discovery dataclasses — the collector-internal shapes that
``gcp/models/inventory.py`` serializes into the top-level ``DiscoveryResult`` JSON.

Split out from ``inventory.py`` so this module has ZERO external dependencies (stdlib
dataclasses only, no pydantic) — the Explorer's ingest adapter (``explorer/ingest/gcp.py``,
a repo-root service governed by the shared root ``requirements.txt``) reconstructs these
dataclasses from raw discovery JSON to catch field-name drift at ingest time, and must not
pull in a hard dependency on `gcp/`'s own tool-specific dependency tree (pydantic, cloud
SDKs) to do it. See CLAUDE.md: the three cloud tools "run independently and have separate
dependency trees."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# ── Phase 2: Compute ──────────────────────────────────────────────────────────


@dataclass
class GCEDisk:
    """A single GCE persistent disk."""

    name: str
    zone: str
    region: str
    size_gb: int
    disk_type: str  # pd-standard, pd-ssd, pd-balanced, pd-extreme
    status: str  # READY, FAILED, CREATING, etc.
    is_boot: bool = False
    source_image: Optional[str] = None
    # Compute API only ever returns whole-GB disk sizes, and Compute Engine's GB is binary (1 GB =
    # 2**30 bytes), so the bytes below are derived as size_gb * 2**30, not read from a native-byte
    # source. size_tb keeps the legacy size_gb / 1000 that the PowerShell SizeTb column uses.
    size_bytes_derived: int = 0
    size_tb: float = 0.0
    excluded_from_sizing: bool = False
    sizing_exclusion_reason: str = ""
    # What PowerShell writes in gce_*_disk_info. ``disk_id`` is None for a disk the project's disk
    # listing did not return (PowerShell leaves such a disk out).
    disk_id: Optional[str] = None
    labels: dict[str, str] = field(default_factory=dict)
    encrypted: bool = False
    # The disk's encryption key as ``gcloud`` shows it (``kmsKeyName``, ``kmsKeyServiceAccount``,
    # ``sha256``, keys present only when set); None when the disk has none.
    encryption_key: Optional[dict[str, str]] = None


@dataclass
class GCEInstance:
    """A single GCE VM instance."""

    name: str
    zone: str
    region: str
    machine_type: str  # e.g. n2-standard-4
    machine_family: str  # e.g. n2, e2, c2, m1
    status: str  # RUNNING, TERMINATED, STOPPED, etc.
    labels: dict[str, str] = field(default_factory=dict)
    disks: list[GCEDisk] = field(default_factory=list)
    total_disk_gb: float = 0.0
    os_type: str = "unknown"  # linux, windows, unknown
    # Derived bytes equivalent of total_disk_gb (binary, * 2**30) — see GCEDisk note above.
    total_disk_bytes_derived: float = 0.0


@dataclass
class ComputeInventory:
    """Compute inventory for a single GCP project."""

    project_id: str
    instances: list[GCEInstance] = field(default_factory=list)
    unattached_disks: list[GCEDisk] = field(default_factory=list)

    # Roll-ups
    total_instances: int = 0
    total_unattached_disks: int = 0
    total_unattached_disk_tb: float = 0.0
    # Attached plus unattached disk capacity (decimal TB).
    total_disk_tb: float = 0.0
    os_breakdown: dict[str, int] = field(default_factory=dict)
    machine_family_breakdown: dict[str, int] = field(default_factory=dict)
    disk_type_breakdown: dict[str, int] = field(default_factory=dict)
    region_breakdown: dict[str, int] = field(default_factory=dict)
    status_breakdown: dict[str, int] = field(default_factory=dict)

    label_summary: Optional[Any] = None  # LabelSummary from collectors/utils.py


# ── Phase 2: Storage ──────────────────────────────────────────────────────────


@dataclass
class GCSBucket:
    """A single Google Cloud Storage bucket."""

    name: str
    location: str  # e.g. US-CENTRAL1, US, EU
    location_type: str  # region, dual-region, multi-region
    storage_class: str  # STANDARD, NEARLINE, COLDLINE, ARCHIVE
    versioning_enabled: bool
    soft_delete_retention_days: Optional[int]  # None = not enabled
    labels: dict[str, str] = field(default_factory=dict)
    size_bytes: Optional[int] = None  # from Cloud Monitoring; may be unavailable
    # Straight decimal unit conversions of size_bytes (native precision — no
    # false-precision concern, so no _derived suffix). None when size_bytes is None.
    size_gb: Optional[float] = None
    size_tb: Optional[float] = None


@dataclass
class StorageInventory:
    """Storage inventory for a single GCP project."""

    project_id: str
    buckets: list[GCSBucket] = field(default_factory=list)

    # Roll-ups
    total_buckets: int = 0
    total_size_bytes: Optional[int] = None  # None if Monitoring data unavailable
    total_size_gb: Optional[float] = None  # decimal conversion of total_size_bytes
    total_size_tb: Optional[float] = None  # decimal conversion of total_size_bytes
    class_breakdown: dict[str, int] = field(default_factory=dict)
    location_type_breakdown: dict[str, int] = field(default_factory=dict)
    soft_delete_enabled_count: int = 0
    soft_delete_pct: float = 0.0
    versioning_enabled_count: int = 0
    versioning_pct: float = 0.0

    label_summary: Optional[Any] = None


# ── Phase 2: Database ─────────────────────────────────────────────────────────


@dataclass
class CloudSQLInstance:
    """A single Cloud SQL instance."""

    name: str
    region: str
    database_version: str  # MYSQL_8_0, POSTGRES_15, SQLSERVER_2019_STANDARD, etc.
    tier: str  # db-n1-standard-2, db-perf-optimized-N-2, etc.
    storage_type: str  # PD_SSD, PD_HDD
    storage_size_gb: int
    high_availability: bool  # REGIONAL vs ZONAL
    automated_backup_enabled: bool
    labels: dict[str, str] = field(default_factory=dict)
    state: str = "RUNNABLE"
    # Cloud SQL Admin API only ever returns whole-GB disk sizes — bytes/TB below
    # are derived (decimal: 1 GB = 1e9 bytes), not read from a native-byte source.
    storage_size_bytes_derived: int = 0
    storage_size_tb: float = 0.0
    # What PowerShell writes in gce_cloudsql_info, as the API returns it.
    instance_type: str = ""  # CLOUD_SQL_INSTANCE, READ_REPLICA_INSTANCE, ...
    data_disk_size_gb: Optional[float] = None  # None when the API gives no size
    availability_type: Optional[str] = None  # REGIONAL or ZONAL, None when not reported
    backup_retention_count: Optional[int] = None
    backup_start_time: Optional[str] = None
    # User databases (system databases left out); None when the databases could not be listed.
    number_of_databases: Optional[int] = None


@dataclass
class SpannerInstance:
    """A single Cloud Spanner instance."""

    name: str
    config: str  # e.g. nam6, eur3, regional-us-central1
    display_name: str
    node_count: int
    processing_units: int  # as reported by the API; 0 when the instance does not report it
    state: str  # READY, CREATING
    labels: dict[str, str] = field(default_factory=dict)
    database_count: int = 0  # databases in the instance; 0 if the listing failed (see errors)


@dataclass
class AlloyDBCluster:
    """A single AlloyDB cluster."""

    name: str
    region: str
    database_version: str  # POSTGRES_15, etc.
    state: str  # READY, CREATING, etc.
    labels: dict[str, str] = field(default_factory=dict)
    instance_count: int = 0


@dataclass
class BigtableInstance:
    """A single Cloud Bigtable instance."""

    name: str
    display_name: str
    state: str  # READY, CREATING
    instance_type: str  # PRODUCTION, DEVELOPMENT
    labels: dict[str, str] = field(default_factory=dict)
    cluster_count: int = 0


@dataclass
class DatabaseInventory:
    """Database inventory for a single GCP project."""

    project_id: str
    cloud_sql_instances: list[CloudSQLInstance] = field(default_factory=list)
    spanner_instances: list[SpannerInstance] = field(default_factory=list)
    alloydb_clusters: list[AlloyDBCluster] = field(default_factory=list)
    bigtable_instances: list[BigtableInstance] = field(default_factory=list)

    # Roll-ups
    total_databases: int = 0
    engine_breakdown: dict[str, int] = field(default_factory=dict)

    label_summary: Optional[Any] = None


# ── Phase 2: BigQuery ─────────────────────────────────────────────────────────


@dataclass
class BigQueryTable:
    """One table, view, materialized view, external table or snapshot of a BigQuery dataset."""

    dataset_id: str
    location: str
    table_id: str
    table_type: Optional[str]
    """TABLE, VIEW, MATERIALIZED_VIEW, EXTERNAL or SNAPSHOT, as the tables list gives it."""

    num_rows: int = 0
    number_of_columns: int = 0
    total_logical_bytes: int = 0
    """numBytes of the table: its logical size in bytes."""

    long_term_logical_bytes: int = 0
    external_source_format: str = ""
    external_source_uri: str = ""
    creation_time: str = ""
    last_modified_time: str = ""
    dataset_labels: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    details_available: bool = True
    """False when the table's own details could not be read: its size is then reported as 0."""


@dataclass
class BigQueryInventory:
    """BigQuery inventory for a single GCP project."""

    project_id: str
    dataset_count: int = 0
    tables: list[BigQueryTable] = field(default_factory=list)

    # Roll-ups
    table_counts: dict[str, int] = field(default_factory=dict)
    """Number of tables per table_type."""

    protectable_logical_bytes: int = 0
    """Logical bytes of the TABLE and MATERIALIZED_VIEW entries, the data that lives in BigQuery."""

    incomplete_calls: int = 0
    """BigQuery calls that failed, so the totals may be low (also recorded in collection_errors)."""


# ── Phase 2: Backup ───────────────────────────────────────────────────────────


@dataclass
class BackupPlan:
    """A Backup and DR backup plan."""

    name: str
    resource_type: str  # compute.googleapis.com/Instance, etc.
    backup_vault: str
    rpo_hours: Optional[int]  # None if not extractable
    retention_days: Optional[int]


@dataclass
class BackupPlanAssociation:
    """A single resource's association with a Backup and DR plan."""

    name: str
    resource: str  # full resource name
    resource_type: str
    backup_plan: str
    state: str  # ACTIVE, CREATING, DELETING, etc.
    last_backup_time: Optional[str] = None  # ISO 8601 or None
    last_backup_error: Optional[str] = None


@dataclass
class BackupPostureInventory:
    """Backup and DR posture for a single GCP project."""

    project_id: str
    backup_plans: list[BackupPlan] = field(default_factory=list)
    associations: list[BackupPlanAssociation] = field(default_factory=list)

    # Roll-ups
    total_associations: int = 0
    protected_instance_count: int = 0
    unprotected_instance_count: int = 0
    unprotected_instances: list[str] = field(default_factory=list)
    protection_coverage_pct: float = 0.0
    # False when the protected workloads could not be listed (Backup and DR API disabled, no
    # permission, SDK missing). The roll-ups above then count every VM as unprotected, which is a
    # guess and not a measurement, so the summary shows the coverage as n/a.
    available: bool = True

"""AWS Sizing Tool — unified discovery result model.

All dataclasses in this module are serialisable via ``dataclasses.asdict()``
so the final ``DiscoveryResult`` can be written as a single JSON file and
loaded back by the SE portal for analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class BackupSummary:
    """What backups exist for one resource (the PowerShell backup columns).

    Dates are ISO 8601 in UTC. ``latest_backup_size_bytes`` is the size of the latest backup,
    never a sum.
    """

    has_backups: bool = False
    has_recovery_points: bool = False
    backup_count: int = 0
    backup_sources: str = ""
    latest_backup_date: str = ""
    latest_backup_size_bytes: int = 0
    backup_enumeration_truncated: bool = False


@dataclass
class EC2Instance:
    account_id: str
    account_alias: str
    instance_id: str
    name: str
    instance_type: str
    platform: str
    state: str
    vcpus: int
    memory_gib: float
    region: str
    volume_count: int
    size_gib: int
    size_tb: float
    # Native EC2/EBS API only ever reports GiB — no true byte precision exists upstream.
    # This is size_gib * 1024**3, arithmetic-derived (the "_derived" suffix flags that).
    size_bytes_derived: int
    in_backup_plan: bool
    backup_plans: list[str]
    tags: dict[str, str]
    backup: BackupSummary = field(default_factory=BackupSummary)


@dataclass
class EC2Volume:
    account_id: str
    account_alias: str
    volume_id: str
    instance_id: str
    instance_name: str
    name: str
    device_name: str
    size_gib: int
    size_tb: float
    # Native EBS API only ever reports GiB — no true byte precision exists upstream.
    # This is size_gib * 1024**3, arithmetic-derived (the "_derived" suffix flags that).
    size_bytes_derived: int
    region: str
    availability_zone: str
    volume_type: str
    state: str
    iops: int
    throughput: int
    encrypted: bool
    in_backup_plan: bool
    backup_plans: list[str]
    tags: dict[str, str]
    avg_daily_write_gib: float = 0.0
    change_rate_pct: float = 0.0
    excluded_from_sizing: bool = False
    sizing_exclusion_reason: str = ""
    # 90-day monthly write trend: list of 3 monthly avg-daily-write-GiB values
    # (oldest month first).  Empty if metrics unavailable.
    monthly_write_trend_gib: list[float] = field(default_factory=list)
    # Month-over-month growth rate for write activity (last two months, %).
    # Positive = writes are increasing; negative = decreasing.
    write_growth_pct: Optional[float] = None
    backup: BackupSummary = field(default_factory=BackupSummary)


@dataclass
class RDSInstance:
    account_id: str
    account_alias: str
    db_instance_identifier: str
    db_name: str
    size_gib: int
    size_tb: float
    # Native RDS API only ever reports GiB (AllocatedStorage / VolumeBytesUsed→GiB) — no true
    # byte precision exists upstream. This is size_gib * 1024**3, arithmetic-derived.
    size_bytes_derived: int
    region: str
    engine: str
    instance_class: str
    multi_az: bool
    storage_type: str
    native_backup_enabled: bool
    native_backup_retention_days: int
    in_backup_plan: bool
    backup_plans: list[str]
    tags: dict[str, str]
    engine_version: str = ""
    db_instance_status: str = ""
    preferred_backup_window: str = ""
    backup: BackupSummary = field(default_factory=BackupSummary)


@dataclass
class DynamoDBTable:
    account_id: str
    account_alias: str
    region: str
    table_name: str
    table_id: str
    table_arn: str
    size_bytes: int
    size_gib: float
    size_tb: float
    item_count: int
    status: str
    deletion_protection: bool
    read_capacity_units: int
    write_capacity_units: int
    pitr_enabled: bool
    in_backup_plan: bool
    backup_plans: list[str]
    # Local Secondary Index footprint — sized separately from table data because Rubrik's
    # DynamoDB export size (and egress) is "table data + LSI for full backups".
    lsi_size_bytes: int = 0
    lsi_size_gib: float = 0.0
    lsi_size_tb: float = 0.0
    tags: dict[str, str] = field(default_factory=dict)
    number_of_decreases_today: int = 0
    global_table_version: str = ""
    backup: BackupSummary = field(default_factory=BackupSummary)


@dataclass
class EFSFileSystem:
    account_id: str
    account_alias: str
    file_system_id: str
    name: str
    size_bytes: int
    size_gib: float
    size_tb: float
    mount_targets: int
    owner_id: str
    performance_mode: str
    throughput_mode: str
    provisioned_throughput_mibps: float
    region: str
    in_backup_plan: bool
    backup_plans: list[str]
    tags: dict[str, str]
    # ReplicationOverwriteProtection: ENABLED, DISABLED or REPLICATING.
    file_system_protection: str = ""
    backup: BackupSummary = field(default_factory=BackupSummary)


@dataclass
class S3Bucket:
    account_id: str
    account_alias: str
    bucket_name: str
    region: str
    size_bytes: int
    size_gb: float
    size_tb: float
    object_count: int
    in_backup_plan: bool
    backup_plans: list[str]
    tags: dict[str, str] = field(default_factory=dict)
    # 6-month monthly size trend (oldest → newest), each entry is GB.
    # Empty list means metrics unavailable.
    monthly_size_gb: list[float] = field(default_factory=list)
    # Annualized growth rate derived from the 6-month trend (% per year).
    # None if fewer than 2 data points are available.
    annual_growth_pct: Optional[float] = None
    # True when the BucketSizeBytes call failed (throttled or denied), so size_bytes of 0
    # means "unknown" rather than "empty bucket".
    size_metric_failed: bool = False
    # True when the NumberOfObjects call failed, so object_count of 0 means "unknown".
    object_count_metric_failed: bool = False
    # True when the GetBucketTagging call failed for a reason other than "no tags".
    tags_lookup_failed: bool = False
    # Largest daily value over the last 7 days per storage class (None: no datapoints).
    # "StandardStorage" and "AllStorageTypes" are always present.
    storage_class_bytes: dict[str, Optional[float]] = field(default_factory=dict)
    storage_class_objects: dict[str, Optional[float]] = field(default_factory=dict)
    # True when a Glue Iceberg table's data lives in this bucket (HasIcebergTable column).
    has_iceberg_table: bool = False
    # Storage classes whose bytes were reduced by Glue Iceberg data. PowerShell recomputes their
    # size columns with a different GiB/TiB formula, and the CSV does the same for these classes.
    iceberg_adjusted_classes: list[str] = field(default_factory=list)
    # Storage Lens "current version" values (latest day), per storage class; empty when no
    # Storage Lens dashboard publishing to CloudWatch covers the bucket.
    current_version_bytes: dict[str, Optional[float]] = field(default_factory=dict)
    current_version_objects: dict[str, Optional[float]] = field(default_factory=dict)
    backup: BackupSummary = field(default_factory=BackupSummary)


@dataclass
class FSxFileSystem:
    account_id: str
    account_alias: str
    file_system_id: str
    file_system_type: str
    name: str
    storage_capacity_gib: int
    storage_capacity_tb: float
    # Native FSx API only ever reports GiB (StorageCapacity) — no true byte precision exists
    # upstream. This is storage_capacity_gib * 1024**3, arithmetic-derived.
    storage_capacity_bytes_derived: int
    storage_type: str
    lifecycle: str
    region: str
    dns_name: str
    in_backup_plan: bool
    backup_plans: list[str]
    tags: dict[str, str] = field(default_factory=dict)
    file_system_type_version: str = ""
    owner_id: str = ""
    # Which configuration block the API returned: ontap, windows, lustre or openzfs (or "").
    config_type: str = ""
    # Largest value over the last 7 days of the metrics that apply to this type, keyed by
    # PowerShell's column prefix: StorageUsed, PhysicalDiskUsage, LogicalDiskUsage,
    # FreeDataStorageCapacity, UsedStorageCapacity (bytes) and StorageCapacityUtilizationPercentage.
    # None means CloudWatch had no datapoints (or the call failed).
    usage_metrics: dict[str, Optional[float]] = field(default_factory=dict)
    backup: BackupSummary = field(default_factory=BackupSummary)


@dataclass
class FSxVolume:
    account_id: str
    account_alias: str
    region: str
    file_system_id: str
    volume_id: str
    name: str
    volume_type: str
    lifecycle: str
    resource_arn: str
    storage_used_bytes: Optional[float]  # largest hourly maximum over 7 days
    storage_capacity_bytes: Optional[float]
    in_backup_plan: bool
    backup_plans: list[str]
    file_system_dns_name: str = ""
    file_system_type: str = ""
    file_system_type_version: str = ""
    file_system_owner_id: str = ""
    file_system_storage_type: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    backup: BackupSummary = field(default_factory=BackupSummary)


@dataclass
class KMSRegionCount:
    account_id: str
    account_alias: str
    region: str
    key_count: int


@dataclass
class SecretsRegionCount:
    account_id: str
    account_alias: str
    region: str
    secret_count: int


@dataclass
class SQSRegionCount:
    account_id: str
    account_alias: str
    region: str
    queue_count: int


@dataclass
class BackupRule:
    rule_name: str
    vault_name: str
    schedule: str
    start_window_minutes: int
    completion_window_minutes: int
    delete_after_days: int
    cold_storage_after_days: int


@dataclass
class BackupSelection:
    """One resource selection of a backup plan, kept apart from the plan's other selections.

    PowerShell evaluates each selection on its own (tags OR-ed, conditions AND-ed, negations
    disqualify), so the criteria of different selections must not be mixed.
    """

    selection_id: str
    resources: list[str]  # BackupSelection.Resources (ARNs, may end in ":*")
    not_resources: list[str]  # BackupSelection.NotResources
    list_of_tags: list[dict]  # ConditionType / ConditionKey / ConditionValue
    string_equals: list[dict]  # Conditions.*: ConditionKey / ConditionValue
    string_like: list[dict]
    string_not_equals: list[dict]
    string_not_like: list[dict]


@dataclass
class BackupPlan:
    account_id: str
    account_alias: str
    region: str
    plan_id: str
    plan_arn: str
    plan_name: str
    version_id: str
    creation_date: str
    last_execution_date: str
    rules: list[BackupRule]
    resources: list[str]
    # Selection criteria, so a resource can be attributed to the plan that protects it (SE-side).
    # `selection_tags` are AWS Backup `ListOfTags` rows (tag-equality assignment, the common
    # org-policy case); `selection_conditions` are the richer `Conditions` block (StringEquals /
    # StringLike / …). Both are stored as plain dicts. Empty for plans that select by explicit
    # ARN only, or for older scans collected before this field existed.
    selection_tags: list[dict] = field(default_factory=list)
    selection_conditions: list[dict] = field(default_factory=list)
    # The same selections one by one, for the CSV plan membership. Absent in discovery files
    # collected before this field existed, which makes readers fall back to the old signal.
    selections: list[BackupSelection] = field(default_factory=list)
    # False when the plan or any of its selections could not be read, so its absence from a
    # resource's plans must not be read as "not protected".
    selections_complete: bool = True
    # The plan as PowerShell writes it to aws-backup-plans-info-*.json, without "Resources".
    # Empty for a plan whose details could not be read.
    plan_export: dict = field(default_factory=dict)


@dataclass
class BackupVault:
    """An AWS Backup vault — its Vault Lock (WORM immutability) config, recovery-point count, and
    encryption key. The Explorer's Backup Vaults tab reads these; immutability is the key signal
    (a customer with locked vaults already has native WORM, which reframes the Rubrik pitch)."""

    account_id: str
    account_alias: str
    region: str
    vault_name: str
    vault_arn: str
    encryption_key_arn: str = ""
    recovery_point_count: int = 0
    locked: bool = False  # Vault Lock active → recovery points are immutable
    lock_state: str = ""  # best-effort mode label when known (e.g. "compliance"); else ""
    min_retention_days: Optional[int] = None
    max_retention_days: Optional[int] = None


@dataclass
class BackupCostEntry:
    account_id: str
    account_alias: str
    period_start: str
    period_end: str
    amortized_cost: float
    blended_cost: float
    unblended_cost: float
    service: str = "AWS Backup"
    usage_type: str = (
        ""  # raw Cost Explorer USAGE_TYPE e.g. "USE1-BackupUsage:RDS-ColdStorageUsage"
    )
    resource_type: str = ""  # parsed: "RDS", "EBS", "DynamoDB", "EFS", "S3", "EC2", "FSx", etc.
    storage_tier: str = ""  # "warm" or "cold"


@dataclass
class ServiceCostEntry:
    account_id: str
    account_alias: str
    period_start: str  # YYYY-MM-DD
    period_end: str  # YYYY-MM-DD
    service: str  # e.g. "Amazon EC2", "Amazon RDS"
    amortized_cost: float
    unblended_cost: float


@dataclass
class DiscoverySummary:
    total_ec2_instances: int = 0
    total_ec2_protected: int = 0  # any protection (vault OR snapshot)
    total_ec2_vault_protected: int = 0  # AWS Backup vault only (or both)
    total_ec2_snapshot_only: int = 0  # EBS Snapshot but no vault policy
    total_ec2_unprotected: int = 0  # neither
    ec2_protection_pct: float = 0.0

    total_attached_disk_tb: float = 0.0
    total_unattached_disk_tb: float = 0.0
    total_disk_tb: float = 0.0

    total_rds_instances: int = 0
    total_rds_protected: int = 0
    total_rds_tb: float = 0.0

    total_dynamodb_tables: int = 0
    total_dynamodb_protected: int = 0
    total_dynamodb_tb: float = 0.0

    total_efs_filesystems: int = 0
    total_efs_protected: int = 0
    total_efs_tb: float = 0.0

    total_fsx_filesystems: int = 0
    total_fsx_protected: int = 0
    total_fsx_tb: float = 0.0

    total_s3_buckets: int = 0
    total_s3_gb: float = 0.0
    total_s3_tb: float = 0.0

    total_kms_keys: int = 0
    total_secrets: int = 0
    total_sqs_queues: int = 0

    total_backup_plans: int = 0
    total_12mo_backup_spend_usd: float = 0.0
    total_12mo_aws_spend_usd: float = 0.0  # all services, from Cost Explorer

    # IaC / DevOps signals
    iac_has_iac: bool = False
    iac_tools_detected: list[str] = field(default_factory=list)
    iac_devops_opportunity: str = "None"  # "High" | "Medium" | "Low" | "None"
    iac_cloudformation_stacks: int = 0
    iac_cdk_stacks: int = 0


@dataclass
class BackupCostMonth:
    """One month of the "AWS Backup" service cost, every Cost Explorer metric (raw amounts)."""

    account_id: str
    account_alias: str
    period_start: str  # YYYY-MM-DD
    period_end: str
    amounts: dict[str, float] = field(default_factory=dict)  # metric name -> amount


@dataclass
class SnapshotStorageCost:
    """One month of one snapshot/backup USAGE_TYPE (raw amounts, ``usage_unit`` as CE reports)."""

    account_id: str
    account_alias: str
    period_start: str
    period_end: str
    service: str
    usage_type: str  # region prefix kept, e.g. "USW2-EBS:SnapshotUsage"
    usage_unit: str
    amounts: dict[str, float] = field(default_factory=dict)  # metric name -> amount


@dataclass
class IcebergStats:
    """What an Iceberg ``metadata.json`` (and its manifest list) says about a table.

    ``None`` is "unknown"; sizes and counts come from the current snapshot's summary.
    """

    format_version: Optional[int] = None
    total_file_size_bytes: Optional[int] = None
    data_file_count: Optional[int] = None
    total_delete_file_count: Optional[int] = None
    manifest_count: Optional[int] = None
    target_manifest_size_bytes: Optional[int] = 8388608
    manifest_bytes_estimate: Optional[int] = None
    # True when some snapshot is a "replace" (compaction or manifest rewrite ran at least once).
    compaction_enabled: bool = False
    metadata_file_storage_class: str = ""


@dataclass
class S3Table:
    account_id: str
    account_alias: str
    region: str
    namespace: str  # multi-level namespaces joined with "/"
    table_name: str
    table_bucket_name: str
    table_bucket_arn: str
    table_arn: str
    # None: the API returned nothing (a table with no metadata yet); "": the call failed.
    warehouse_location: Optional[str] = ""
    metadata_location: Optional[str] = None
    table_type: str = ""
    created_at: Optional[str] = None  # ISO 8601 UTC
    modified_at: Optional[str] = None
    storage_class: str = "STANDARD"
    iceberg: Optional[IcebergStats] = None  # None when there is no metadata location to read
    # CloudWatch (largest daily value over 7 days) when the metadata could not be read.
    cloudwatch_size_bytes: Optional[int] = None
    total_file_count: Optional[int] = None
    # True/False from the maintenance configuration; None when it could not be read.
    compaction_enabled: Optional[bool] = None
    snapshot_management_enabled: Optional[bool] = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class GlueIcebergTable:
    account_id: str
    account_alias: str
    region: str
    database_name: str
    table_name: str
    s3_bucket_name: str
    s3_location: str
    metadata_location: Optional[str]
    create_time: Optional[str] = None  # ISO 8601 UTC
    update_time: Optional[str] = None
    iceberg: IcebergStats = field(default_factory=IcebergStats)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class RecoveryPointRow:
    """One COMPLETED AWS Backup recovery point (a row of aws_backup_recovery_points)."""

    account_id: str
    account_alias: str
    region: str
    backup_vault_name: str
    backup_vault_arn: str
    recovery_point_arn: str
    resource_arn: str
    resource_id: str
    resource_name: str
    resource_type: str
    backup_size_bytes: int
    creation_date: Optional[str]  # ISO 8601 UTC
    backup_plan_id: str
    backup_plan_name: str
    status: str
    is_parent: bool
    parent_recovery_point_arn: Optional[str]
    source: str = "AWSBackup"


@dataclass
class RecoveryPointAggregate:
    """Recovery points of one resource: count, latest one's date and size (never a sum)."""

    account_id: str
    region: str
    resource_arn: str
    resource_type: str
    resource_name: str
    recovery_point_count: int = 0
    null_size_recovery_point_count: int = 0
    latest_recovery_point_arn: Optional[str] = None
    latest_recovery_point_date: Optional[str] = None
    latest_recovery_point_size_bytes: int = 0
    backup_plan_names: list[str] = field(default_factory=list)
    backup_vault_names: list[str] = field(default_factory=list)


@dataclass
class VPC:
    account_id: str
    account_alias: str
    region: str
    vpc_id: str
    owner_id: str
    cidr_block: str
    state: str
    is_default: bool
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class LoadBalancer:
    account_id: str
    account_alias: str
    region: str
    name: str
    type: str  # classic, application, network or gateway
    scheme: str
    vpc_id: str
    dns_name: str
    arn: str
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class EKSCluster:
    account_id: str
    account_alias: str
    name: str
    version: str
    platform_version: str
    status: str
    arn: str
    role_arn: str
    region: str
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class EKSNodeGroup:
    account_id: str
    account_alias: str
    nodegroup_name: str
    cluster_name: str
    disk_size: Optional[int]
    capacity_type: str
    ami_type: str
    nodegroup_arn: str
    node_role: str
    status: str
    release_version: str
    version: str
    region: str
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class KMSKey:
    account_id: str
    account_alias: str
    region: str
    alias: str  # aliases joined with "; "
    key_id: str
    arn: str
    key_manager: str  # AWS or CUSTOMER
    key_state: str
    creation_date: str  # ISO 8601 UTC


@dataclass
class Route53Zone:
    account_id: str
    account_alias: str
    hosted_zone_id: str
    name: str
    private_zone: bool
    resource_record_set_count: int


@dataclass
class IAMSummary:
    account_id: str
    account_alias: str
    users: int
    roles: int
    customer_managed_policies: int


@dataclass
class RedshiftCluster:
    account_id: str
    account_alias: str
    region: str
    cluster_identifier: str
    node_type: str
    number_of_nodes: int
    cluster_status: str
    master_username: str
    db_name: str
    cluster_create_time: Optional[str]  # ISO 8601 UTC
    automated_snapshot_retention_period: int
    manual_snapshot_retention_period: int
    backup: BackupSummary = field(default_factory=BackupSummary)


@dataclass
class DiscoveryResult:
    schema_version: str
    account_id: str
    account_alias: str
    generated_at: str
    regions_scanned: list[str]

    ec2_instances: list[EC2Instance]
    ec2_attached_volumes: list[EC2Volume]
    ec2_unattached_volumes: list[EC2Volume]
    rds_instances: list[RDSInstance]
    dynamodb_tables: list[DynamoDBTable]
    efs_filesystems: list[EFSFileSystem]
    fsx_filesystems: list[FSxFileSystem]
    s3_buckets: list[S3Bucket]
    kms_counts: list[KMSRegionCount]
    secrets_counts: list[SecretsRegionCount]
    sqs_counts: list[SQSRegionCount]
    backup_plans: list[BackupPlan]
    backup_costs: list[BackupCostEntry]
    service_costs: list[ServiceCostEntry] = field(default_factory=list)
    backup_vaults: list[BackupVault] = field(default_factory=list)
    # Per-snapshot detail behind the native-backup columns (aws_rds_snapshot_info and
    # aws_ebs_and_ami_info); dataclasses from collectors/snapshots.py.
    rds_snapshots: list[Any] = field(default_factory=list)
    ebs_and_ami: list[Any] = field(default_factory=list)
    backup_cost_months: list[BackupCostMonth] = field(default_factory=list)
    snapshot_storage_costs: list[SnapshotStorageCost] = field(default_factory=list)
    fsx_volumes: list[FSxVolume] = field(default_factory=list)
    s3_tables: list[S3Table] = field(default_factory=list)
    glue_iceberg_tables: list[GlueIcebergTable] = field(default_factory=list)
    backup_recovery_points: list[RecoveryPointRow] = field(default_factory=list)
    backup_resource_aggregates: list[RecoveryPointAggregate] = field(default_factory=list)
    truncated_backup_regions: list[str] = field(default_factory=list)
    vpcs: list[VPC] = field(default_factory=list)
    load_balancers: list[LoadBalancer] = field(default_factory=list)
    eks_clusters: list[EKSCluster] = field(default_factory=list)
    eks_nodegroups: list[EKSNodeGroup] = field(default_factory=list)
    kms_keys: list[KMSKey] = field(default_factory=list)
    route53_zones: list[Route53Zone] = field(default_factory=list)
    iam_summaries: list[IAMSummary] = field(default_factory=list)
    redshift_clusters: list[RedshiftCluster] = field(default_factory=list)

    summary: DiscoverySummary = field(default_factory=DiscoverySummary)
    iac_summary: Optional[dict[str, Any]] = None  # serialised IaCSummary
    # Set when every service returned zero resources — strong indicator that an
    # org-level SCP is blocking read access for RubrikDiscoveryRole in this account.
    scp_restrictions_suspected: bool = False
    # Non-SCP permission errors encountered during the scan (service + region + error message).
    # A non-empty list means some resources may be missing from this account's results.
    scan_errors: list[dict] = field(default_factory=list)
    # The pre-flight access check: one row per service and region, with what was readable and what
    # the scan will therefore miss. Empty when the check was skipped (--no-preflight).
    access_check: list[dict] = field(default_factory=list)

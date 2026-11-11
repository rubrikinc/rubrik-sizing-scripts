"""Azure Database collector for Rubrik Discovery.

Collects per-subscription database inventory:
- Azure SQL logical servers + user databases: edition, SKU, size, short-term
  and long-term retention, backup storage redundancy
- Azure SQL Managed Instances: SKU, v-cores, storage size, license type,
  backup redundancy, tags.  Storage is aggregated at the sizing-API layer.
- PostgreSQL Flexible Servers: tier, storage, backup retention, geo-redundancy
- MySQL Flexible Servers: same fields

User-database counts exclude well-known system databases (master, tempdb,
model, msdb for SQL; postgres / azure_maintenance for PG; mysql / sys / etc.
for MySQL).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.rdbms.mysql_flexibleservers import (
    MySQLManagementClient as MySQLFlexClient,
)
from azure.mgmt.rdbms.postgresql_flexibleservers import (
    PostgreSQLManagementClient as PostgreSQLFlexClient,
)
from azure.mgmt.sql import SqlManagementClient
import progress
from cloud import DEFAULT_CLOUD, CloudEnvironment

from collectors.utils import (
    TagSummary,
    build_tag_summary,
    decimal_gb,
    decimal_tb,
    enum_text,
    metric_timespan,
    parse_resource_group,
)

logger = logging.getLogger(__name__)

# Monitor metric that reports a database's ACTUAL consumed data size, by resource type.
# The ARM resource only exposes the *provisioned* ceiling (max_size_gb / storage_size_gb /
# storage_gb) — like AWS Aurora's placeholder AllocatedStorage — so for accurate backup
# sizing we prefer the consumed figure from these metrics. (metricname, namespace, →GB divisor)
_USED_STORAGE_METRIC = {
    # Azure SQL DB "storage" = data space used, in bytes.
    "sql_db": ("storage", "Microsoft.Sql/servers/databases", 1024**3),
    # SQL Managed Instance "storage_space_used_mb" — in MB.
    "sql_mi": ("storage_space_used_mb", "Microsoft.Sql/managedInstances", 1024),
    # Flexible servers "storage_used" — in bytes.
    "pg_flex": ("storage_used", "Microsoft.DBforPostgreSQL/flexibleServers", 1024**3),
    "mysql_flex": ("storage_used", "Microsoft.DBforMySQL/flexibleServers", 1024**3),
}


def az_time(value: object) -> Optional[str]:
    """A date as PowerShell's JSON writes it: ISO 8601 in UTC with a ``Z`` and the fraction of a second
    only as far as it is not zero (``2026-07-29T01:06:44.12Z``, ``2026-07-29T01:06:44Z``).
    """
    if isinstance(value, str):
        return value
    if not isinstance(value, datetime):
        return None
    moment = value.astimezone(timezone.utc) if value.tzinfo else value
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    fraction = f"{moment.microsecond:06d}".rstrip("0")
    return f"{text}.{fraction}Z" if fraction else f"{text}Z"


def _plain_value(value: object) -> object:
    """``value`` if it is plain JSON data, else None, so a mock or an SDK object never reaches a file."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _plain_value(v) for k, v in value.items()}
    return str(value.value) if isinstance(value, Enum) else None


def _model_attr(model: object, name: str) -> object:
    """An SDK model's attribute, whether the SDK flattens ``properties`` into the model or not."""
    found = getattr(model, name, None)
    if found is None:
        found = getattr(getattr(model, "properties", None), name, None)
    return found


def az_managed_database(
    database: object,
    resource_group: str,
    instance: str,
    short_term: object = None,
    long_term: object = None,
) -> dict[str, object]:
    """One managed-instance database as ``Get-AzSqlInstanceDatabase`` and its retention policies are
    written to ``azure_mi_db_items``: the Az property names in the model's own order, ``STR`` after
    them and ``LTR`` after that, each only when the policy could be read.
    """

    def attr(name: str) -> object:
        return _plain_value(_model_attr(database, name))

    tags = getattr(database, "tags", None)
    name = getattr(database, "name", None)
    record: dict[str, object] = {
        "Location": _plain_value(getattr(database, "location", None)),
        "Tags": dict(tags) if isinstance(tags, dict) else None,
        "Collation": attr("collation"),
        "Status": attr("status"),
        "RestorePointInTime": az_time(_model_attr(database, "restore_point_in_time")),
        "DefaultSecondaryLocation": attr("default_secondary_location"),
        "CatalogCollation": attr("catalog_collation"),
        "CreateMode": attr("create_mode"),
        "StorageContainerUri": attr("storage_container_uri"),
        "StorageContainerSasToken": attr("storage_container_sas_token"),
        "SourceDatabaseId": attr("source_database_id"),
        "FailoverGroupId": attr("failover_group_id"),
        "RecoverableDatabaseId": attr("recoverable_database_id"),
        "RestorableDroppedDatabaseId": attr("restorable_dropped_database_id"),
        "LongTermRetentionBackupResourceId": attr("long_term_retention_backup_resource_id"),
        "AutoCompleteRestore": attr("auto_complete_restore"),
        "LastBackupName": attr("last_backup_name"),
        "StorageContainerIdentity": attr("storage_container_identity"),
        "CrossSubscriptionSourceDatabaseId": attr("cross_subscription_source_database_id"),
        "CrossSubscriptionRestorableDroppedDatabaseId": attr(
            "cross_subscription_restorable_dropped_database_id"
        ),
        "CrossSubscriptionTargetManagedInstanceId": attr(
            "cross_subscription_target_managed_instance_id"
        ),
        "EnableLedger": bool(_model_attr(database, "is_ledger_on") is True),
        "ResourceGroupName": resource_group,
        "ManagedInstanceName": instance,
        "Name": _plain_value(name),
        "CreationDate": az_time(_model_attr(database, "creation_date")),
        "EarliestRestorePoint": az_time(_model_attr(database, "earliest_restore_point")),
        "Id": _plain_value(getattr(database, "id", None)),
    }
    if short_term is not None:
        record["STR"] = {
            "ResourceGroupName": resource_group,
            "InstanceName": instance,
            "DatabaseName": _plain_value(name),
            "DeletionDate": None,
            "RetentionDays": _plain_value(_model_attr(short_term, "retention_days")),
        }
    if long_term is not None:
        record["LTR"] = {
            "ResourceGroupName": resource_group,
            "ManagedInstanceName": instance,
            "DatabaseName": _plain_value(name),
            "WeeklyRetention": _plain_value(_model_attr(long_term, "weekly_retention")),
            "MonthlyRetention": _plain_value(_model_attr(long_term, "monthly_retention")),
            "YearlyRetention": _plain_value(_model_attr(long_term, "yearly_retention")),
            "WeekOfYear": _plain_value(_model_attr(long_term, "week_of_year")),
            "Location": None,
        }
    return record


#: (metric name, namespace) of the peak used-storage reading in azure_postgres_info.
_UTILIZED_METRIC = {"pg_flex": ("storage_used", "Microsoft.DBforPostgreSQL/flexibleServers")}

#: System databases excluded from user-database counts.
_SQL_SYSTEM_DBS: frozenset[str] = frozenset({"master", "tempdb", "model", "msdb"})
_PG_SYSTEM_DBS: frozenset[str] = frozenset(
    {
        "postgres",
        "azure_maintenance",
        "azure_sys",
        "template0",
        "template1",
    }
)
_MYSQL_SYSTEM_DBS: frozenset[str] = frozenset(
    {
        "mysql",
        "sys",
        "information_schema",
        "performance_schema",
    }
)

#: The one long-term retention policy a database has; the API needs its name.
_LTR_POLICY_NAME = "default"


def _no_policy_answer(exc: Exception) -> bool:
    """Whether an error only means the database has no long-term retention policy to read.

    That is an answer, not a failure: the service says "not found" or "not supported" for a
    database that cannot have one. Anything else (a wrong call, a denied one) is a failure.
    """
    if isinstance(exc, ResourceNotFoundError):
        return True
    return isinstance(exc, HttpResponseError) and getattr(exc, "status_code", None) in (400, 404)


#: LTR field values that indicate "not configured" (ISO 8601 zero-duration strings).
_LTR_EMPTY: frozenset[str | None] = frozenset({"PT0S", "P0W", "P0D", "P0Y", None, ""})


@dataclass
class SqlDatabaseInfo:
    """A single Azure SQL user database."""

    name: str
    server_name: str
    resource_id: str
    resource_group: str
    subscription_id: str
    location: str
    edition: str  # GeneralPurpose / BusinessCritical / Standard / Premium / Basic / Hyperscale
    sku_name: str  # S0 / P1 / GP_Gen5_4 / …
    max_size_gb: Optional[float]
    backup_storage_redundancy: Optional[str]  # Geo / Local / Zone / GeoZone
    zone_redundant: bool
    short_term_retention_days: Optional[int]
    long_term_retention_enabled: bool
    tags: dict[str, str]
    used_storage_gb: Optional[float] = (
        None  # ACTUAL data used (Monitor metric); None if unavailable
    )
    # max_size_bytes: recovered from the SDK's native max_size_bytes (bytes-native, was
    # converted to max_size_gb then discarded) — true byte precision, not derived.
    max_size_bytes: Optional[int] = None
    max_size_tb: Optional[float] = None  # straight /1024 conversion of max_size_gb
    # used_storage_bytes: recovered from the Monitor "storage" metric (bytes-native).
    used_storage_bytes: Optional[int] = None
    used_storage_tb: Optional[float] = None  # straight /1024 conversion of used_storage_gb
    # Decimal units (GB = 1e9 bytes, TB = 1e12) alongside the binary fields above.
    max_size_gb_decimal: Optional[float] = None
    max_size_tb_decimal: Optional[float] = None
    used_storage_gb_decimal: Optional[float] = None
    used_storage_tb_decimal: Optional[float] = None

    # Figures PowerShell writes in azure_sql_info. ``tags`` above is the server's; db_tags are
    # the database's own.
    database_id: Optional[str] = None
    status: Optional[str] = None
    db_tags: dict[str, str] = field(default_factory=dict)
    allocated_bytes: Optional[float] = None  # allocated_data_storage, latest Maximum
    utilized_bytes: Optional[float] = None  # storage, latest Maximum
    ltr_weekly: Optional[str] = None  # ISO 8601 durations as the API returns them
    ltr_monthly: Optional[str] = None
    ltr_yearly: Optional[str] = None
    ltr_week_of_year: Optional[int] = None
    diff_backup_interval_hours: Optional[int] = None


@dataclass
class ElasticPoolInfo:
    """An elastic pool of a SQL logical server. PowerShell writes the pool, not its databases."""

    name: str
    server_name: str
    resource_group: str
    location: str
    sku_name: Optional[str] = None
    max_size_bytes: Optional[int] = None


@dataclass
class SqlServerInfo:
    """Azure SQL logical server with its user databases."""

    name: str
    resource_id: str
    resource_group: str
    subscription_id: str
    location: str
    version: str
    tags: dict[str, str]
    databases: list[SqlDatabaseInfo] = field(default_factory=list)
    # Listed only for servers that have a database in a pool.
    elastic_pools: list[ElasticPoolInfo] = field(default_factory=list)

    @property
    def database_count(self) -> int:
        """Number of user databases on this server."""
        return len(self.databases)


@dataclass
class SqlManagedInstanceInfo:
    """A single Azure SQL Managed Instance (MI).

    MIs are priced per instance in the Rubrik sizing API, with
    ``storage_size_gb`` summed across all MIs in the subscription as the
    front-end TB value.
    """

    name: str
    resource_id: str
    resource_group: str
    subscription_id: str
    location: str
    sku_name: Optional[str]  # GP_Gen5 / BC_Gen5 / …
    sku_tier: Optional[str]  # GeneralPurpose / BusinessCritical
    v_cores: Optional[int]
    storage_size_gb: Optional[int]
    license_type: Optional[str]  # LicenseIncluded / BasePrice
    backup_storage_redundancy: Optional[str]  # Geo / Local / Zone / GeoZone
    zone_redundant: bool
    tags: dict[str, str]
    used_storage_gb: Optional[float] = (
        None  # ACTUAL data used (Monitor metric); None if unavailable
    )
    # storage_size_gb is whole-GB-native from the SDK (storage_size_in_gb) — no true bytes
    # ever possible, hence _derived.
    storage_size_bytes_derived: Optional[int] = None
    storage_size_tb: Optional[float] = None
    storage_size_gb_decimal: Optional[float] = None
    storage_size_tb_decimal: Optional[float] = None
    used_storage_gb_decimal: Optional[float] = None
    used_storage_tb_decimal: Optional[float] = None
    # used_storage_gb's source (storage_space_used_mb) is native MB, not bytes — _derived.
    used_storage_bytes_derived: Optional[int] = None
    used_storage_tb: Optional[float] = None
    # Databases on the instance (None when the list call failed) and the latest Maximum of
    # storage_space_used_mb, which PowerShell writes in azure_mi_sql_info.
    database_count: Optional[int] = None
    storage_space_used_mb: Optional[float] = None
    # The instance's databases with their retention policies, as azure_mi_db_items writes them.
    databases_az: list[dict] = field(default_factory=list)


@dataclass
class FlexibleServerInfo:
    """Azure Database Flexible Server (PostgreSQL or MySQL)."""

    name: str
    resource_id: str
    resource_group: str
    subscription_id: str
    location: str
    engine: str  # "PostgreSQL" | "MySQL"
    sku_name: Optional[str]
    tier: Optional[str]  # Burstable / GeneralPurpose / MemoryOptimized
    version: Optional[str]
    storage_gb: Optional[int]
    backup_retention_days: Optional[int]
    geo_redundant_backup: bool
    # None when the databases could not be listed, so it is not mistaken for a server with none.
    database_count: Optional[int]
    tags: dict[str, str]
    used_storage_gb: Optional[float] = (
        None  # ACTUAL data used (Monitor metric); None if unavailable
    )
    # storage_gb is whole-GB-native from the SDK (storage_size_gb) — no true bytes ever
    # possible, hence _derived.
    storage_bytes_derived: Optional[int] = None
    storage_tb: Optional[float] = None
    storage_gb_decimal: Optional[float] = None
    storage_tb_decimal: Optional[float] = None
    used_storage_gb_decimal: Optional[float] = None
    used_storage_tb_decimal: Optional[float] = None
    # used_storage_gb's source (Monitor "storage_used") IS bytes-native — recovered, not derived.
    used_storage_bytes: Optional[int] = None
    used_storage_tb: Optional[float] = None
    # What azure_postgres_info needs beyond the fields above, as the PowerShell script reads them.
    state: Optional[str] = None
    administrator_login: Optional[str] = None
    high_availability_mode: Optional[str] = None
    geo_redundant_backup_text: Optional[str] = None
    # Azure returns a flexible server's location as it was typed ("Canada Central"); the CSV keeps it.
    raw_location: Optional[str] = None
    # The highest non-null storage_used datapoint of the last 24 hours, in bytes (Postgres only).
    utilized_bytes: Optional[float] = None


@dataclass
class DatabaseInventory:
    """Database inventory for a single subscription."""

    subscription_id: str
    sql_servers: list[SqlServerInfo] = field(default_factory=list)
    managed_instances: list[SqlManagedInstanceInfo] = field(default_factory=list)
    flexible_servers: list[FlexibleServerInfo] = field(default_factory=list)

    # Roll-ups
    total_sql_servers: int = 0
    total_sql_databases: int = 0
    total_sql_mi_instances: int = 0
    total_sql_mi_storage_gb: int = 0
    total_flexible_servers: int = 0
    total_databases: int = 0  # SQL user dbs + flexible user dbs (for quick card)
    engine_breakdown: dict[str, int] = field(default_factory=dict)
    # {"Azure SQL": n_user_dbs, "SQL MI": n_instances, "PostgreSQL": …, "MySQL": …}
    edition_breakdown: dict[str, int] = field(default_factory=dict)  # SQL editions
    tier_breakdown: dict[str, int] = field(default_factory=dict)  # Flexible tiers
    avg_short_term_retention_days: Optional[float] = None  # SQL databases only
    tag_summary: Optional[TagSummary] = None


class DatabaseCollector:
    """Collects Azure Database inventory for a subscription.

    Credentials are always injected — never instantiated inside this class.
    """

    def __init__(
        self,
        subscription_id: str,
        credential: DefaultAzureCredential,
        regions: Optional[list[str]] = None,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
        collect_sql_mi: bool = True,
        collect_postgres: bool = True,
    ) -> None:
        """
        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Validated credential injected from ``auth.get_credential()``.
            regions: Normalised region names to include, or None for all.
            cloud: Target Azure cloud (public vs. sovereign); drives ARM endpoint + token scope.
            collect_sql_mi: When False, do not collect SQL logical servers and managed instances
                (PowerShell's ``-SkipAzureSQLandMI``); flexible servers are still collected.
            collect_postgres: When False, do not collect PostgreSQL flexible servers
                (PowerShell's ``-SkipAzurePostgreSQL``). MySQL flexible servers are unaffected.
        """
        self._sub_id = subscription_id
        self._collect_sql_mi = collect_sql_mi
        self._collect_postgres = collect_postgres
        self._regions: Optional[frozenset[str]] = frozenset(regions) if regions else None
        self._sql = SqlManagementClient(credential, subscription_id, **cloud.client_kwargs())
        self._pg = PostgreSQLFlexClient(credential, subscription_id, **cloud.client_kwargs())
        self._mysql = MySQLFlexClient(credential, subscription_id, **cloud.client_kwargs())
        self._monitor = MonitorManagementClient(
            credential, subscription_id, **cloud.client_kwargs()
        )
        self._ltr_failures: list[Exception] = []

    def _used_storage(self, resource_id: str, kind: str) -> tuple[Optional[float], Optional[float]]:
        """Actual consumed storage for a database resource via the Monitor metrics API.

        Returns ``(used_gb, raw_native_value)`` — ``raw_native_value`` is the metric's
        unconverted reading (bytes for sql_db/pg_flex/mysql_flex, MB for sql_mi; see
        ``_USED_STORAGE_METRIC``), kept so callers can recover/derive a bytes figure
        without re-deriving from the rounded GB value. ``(None, None)`` if unavailable.
        Best-effort — never raises (callers fall back to the provisioned size).
        """
        if not resource_id or kind not in _USED_STORAGE_METRIC:
            return None, None
        metric_name, namespace, divisor = _USED_STORAGE_METRIC[kind]
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=24)
        timespan = metric_timespan(start, end)
        try:
            result = self._monitor.metrics.list(
                resource_uri=resource_id,
                timespan=timespan,
                interval="PT1H",
                metricnames=metric_name,
                aggregation="Average",
                metricnamespace=namespace,
            )
            for m in result.value:
                for ts in m.timeseries:
                    for point in reversed(ts.data):
                        avg = getattr(point, "average", None)
                        if avg is not None:
                            return round(avg / divisor, 3), avg
        except HttpResponseError as exc:
            logger.debug(
                "[%s] %s metric unavailable for %s: %s",
                self._sub_id,
                metric_name,
                resource_id[:60],
                exc,
            )
        except Exception as exc:
            logger.debug(
                "[%s] error fetching %s for %s: %s",
                self._sub_id,
                metric_name,
                resource_id[:60],
                exc,
            )
        return None, None

    def _metric_peak(self, resource_id: str, metric_name: str, namespace: str) -> Optional[float]:
        """The highest non-null hourly Maximum of a metric over the last day, or None.

        PowerShell reads ``Get-AzMetric -AggregationType Maximum`` for the last day and keeps the
        highest datapoint that is not null, so a trailing empty sample (a stopped server, metric lag)
        is blank rather than 0 bytes. Best-effort: never raises.
        """
        if not resource_id:
            return None
        end = datetime.now(timezone.utc)
        timespan = metric_timespan(end - timedelta(days=1), end)
        try:
            result = self._monitor.metrics.list(
                resource_uri=resource_id,
                timespan=timespan,
                interval="PT1H",
                metricnames=metric_name,
                aggregation="Maximum",
                metricnamespace=namespace,
            )
            points = [
                getattr(point, "maximum", None)
                for m in result.value
                for ts in m.timeseries
                for point in ts.data
            ]
            points = [value for value in points if value is not None]
            return max(points) if points else None
        except Exception as exc:
            logger.debug(
                "[%s] %s peak unavailable for %s: %s",
                self._sub_id,
                metric_name,
                resource_id[:60],
                exc,
            )
            return None

    def _metric_maximum(
        self, resource_id: str, metric_name: str, namespace: str
    ) -> Optional[float]:
        """Latest non-null hourly Maximum of a metric over the last day, or None.

        PowerShell reads the last Maximum of ``Get-AzMetric -AggregationType Maximum`` for
        ``storage``, ``allocated_data_storage`` and ``storage_space_used_mb``. Best-effort:
        never raises.
        """
        if not resource_id:
            return None
        end = datetime.now(timezone.utc)
        timespan = metric_timespan(end - timedelta(days=1), end)
        try:
            result = self._monitor.metrics.list(
                resource_uri=resource_id,
                timespan=timespan,
                interval="PT1H",
                metricnames=metric_name,
                aggregation="Maximum",
                metricnamespace=namespace,
            )
            for m in result.value:
                for ts in m.timeseries:
                    for point in reversed(ts.data):
                        value = getattr(point, "maximum", None)
                        if value is not None:
                            return value
        except Exception as exc:
            logger.debug(
                "[%s] %s maximum unavailable for %s: %s",
                self._sub_id,
                metric_name,
                resource_id[:60],
                exc,
            )
        return None

    def collect(self) -> DatabaseInventory:
        """Run the full database collection pass for this subscription."""
        logger.debug("[%s] Starting database collection", self._sub_id)

        sql_servers = self._list_sql_servers() if self._collect_sql_mi else []
        managed_instances = self._list_managed_instances() if self._collect_sql_mi else []
        pg_servers = self._list_flexible_servers("PostgreSQL") if self._collect_postgres else []
        mysql_servers = self._list_flexible_servers("MySQL")

        inventory = DatabaseInventory(
            subscription_id=self._sub_id,
            sql_servers=sql_servers,
            managed_instances=managed_instances,
            flexible_servers=pg_servers + mysql_servers,
        )
        self._compute_rollups(inventory)
        if self._ltr_failures:
            logger.warning(
                "[%s] Long-term retention policy could not be read for %d database(s); their LTR "
                "columns are blank (first error: %s)",
                self._sub_id,
                len(self._ltr_failures),
                self._ltr_failures[0],
            )

        # Tag summary across server-level resources only (server tags carry the
        # governance signal; database-level tags are always inherited from the server).
        all_tags = (
            [srv.tags for srv in sql_servers]
            + [mi.tags for mi in managed_instances]
            + [srv.tags for srv in pg_servers + mysql_servers]
        )
        inventory.tag_summary = build_tag_summary(all_tags)

        logger.debug(
            "[%s] Database complete: %d SQL dbs, %d managed instances, %d flexible servers",
            self._sub_id,
            inventory.total_sql_databases,
            inventory.total_sql_mi_instances,
            inventory.total_flexible_servers,
        )
        return inventory

    def _list_sql_servers(self) -> list[SqlServerInfo]:
        """Enumerate all SQL logical servers in the subscription."""
        servers: list[SqlServerInfo] = []
        try:
            listed = list(self._sql.servers.list())
            for srv in progress.every(listed, self._sub_id, "SQL servers"):
                try:
                    location = (srv.location or "").lower()
                    if self._regions and location not in self._regions:
                        continue

                    rg = parse_resource_group(srv.id or "")
                    server_name = srv.name or ""
                    databases = self._list_sql_databases(rg, server_name, location, srv)
                    pools = (
                        self._list_elastic_pools(rg, server_name)
                        if any(d.sku_name == "ElasticPool" for d in databases)
                        else []
                    )

                    servers.append(
                        SqlServerInfo(
                            name=server_name,
                            resource_id=srv.id or "",
                            resource_group=rg,
                            subscription_id=self._sub_id,
                            location=location,
                            version=str(getattr(srv, "version", None) or "Unknown"),
                            tags=dict(srv.tags) if srv.tags else {},
                            databases=databases,
                            elastic_pools=pools,
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping SQL server %s: %s",
                        self._sub_id,
                        getattr(srv, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning("[%s] Failed to list SQL servers: %s", self._sub_id, exc)
        return servers

    def _list_sql_databases(
        self,
        resource_group: str,
        server_name: str,
        server_location: str,
        server: object,
    ) -> list[SqlDatabaseInfo]:
        """List user databases for a SQL logical server."""
        databases: list[SqlDatabaseInfo] = []
        try:
            for db in self._sql.databases.list_by_server(resource_group, server_name):
                try:
                    db_name = db.name or ""
                    if db_name.lower() in _SQL_SYSTEM_DBS:
                        continue

                    sku = getattr(db, "sku", None)
                    edition = enum_text(getattr(sku, "tier", None)) or "Unknown"
                    sku_name = enum_text(getattr(sku, "name", None)) or "Unknown"

                    max_bytes = getattr(db, "max_size_bytes", None)
                    max_size_gb = round(max_bytes / (1024**3), 3) if max_bytes else None
                    max_size_bytes_val = int(max_bytes) if max_bytes else None
                    max_size_tb = round(max_size_gb / 1024, 3) if max_size_gb else None

                    # Prefer current (active) redundancy; fall back to requested.
                    backup_redundancy = getattr(
                        db, "current_backup_storage_redundancy", None
                    ) or getattr(db, "requested_backup_storage_redundancy", None)

                    short_term_days, diff_backup_hours = self._get_sql_short_term_policy(
                        resource_group, server_name, db_name
                    )
                    ltr = self._get_sql_ltr_policy(resource_group, server_name, db_name)
                    ltr_enabled = any(
                        ltr.get(f) not in _LTR_EMPTY
                        for f in ("weekly_retention", "monthly_retention", "yearly_retention")
                    )
                    db_id = getattr(db, "id", "") or ""
                    used_gb, used_raw_bytes = self._used_storage(db_id, "sql_db")
                    allocated_bytes = self._metric_maximum(
                        db_id, "allocated_data_storage", "Microsoft.Sql/servers/databases"
                    )
                    utilized_bytes = self._metric_maximum(
                        db_id, "storage", "Microsoft.Sql/servers/databases"
                    )
                    guid = getattr(db, "database_id", None)
                    used_bytes_val = (
                        int(round(used_raw_bytes)) if used_raw_bytes is not None else None
                    )
                    used_storage_tb = round(used_gb / 1024, 3) if used_gb else None

                    databases.append(
                        SqlDatabaseInfo(
                            name=db_name,
                            server_name=server_name,
                            resource_id=db_id,
                            resource_group=resource_group,
                            subscription_id=self._sub_id,
                            location=server_location,
                            edition=edition,
                            sku_name=sku_name,
                            max_size_gb=max_size_gb,
                            max_size_bytes=max_size_bytes_val,
                            max_size_tb=max_size_tb,
                            max_size_gb_decimal=decimal_gb(max_size_bytes_val),
                            max_size_tb_decimal=decimal_tb(max_size_bytes_val),
                            used_storage_gb_decimal=decimal_gb(used_bytes_val),
                            used_storage_tb_decimal=decimal_tb(used_bytes_val),
                            used_storage_gb=used_gb,
                            used_storage_bytes=used_bytes_val,
                            used_storage_tb=used_storage_tb,
                            backup_storage_redundancy=(enum_text(backup_redundancy) or None),
                            zone_redundant=bool(getattr(db, "zone_redundant", False)),
                            short_term_retention_days=short_term_days,
                            long_term_retention_enabled=ltr_enabled,
                            tags=dict(server.tags) if getattr(server, "tags", None) else {},
                            database_id=str(guid) if guid else None,
                            status=enum_text(getattr(db, "status", None)),
                            db_tags=dict(db.tags) if getattr(db, "tags", None) else {},
                            allocated_bytes=allocated_bytes,
                            utilized_bytes=utilized_bytes,
                            ltr_weekly=ltr.get("weekly_retention"),
                            ltr_monthly=ltr.get("monthly_retention"),
                            ltr_yearly=ltr.get("yearly_retention"),
                            ltr_week_of_year=ltr.get("week_of_year"),
                            diff_backup_interval_hours=diff_backup_hours,
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping database %s/%s: %s",
                        self._sub_id,
                        server_name,
                        getattr(db, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning(
                "[%s] Failed to list databases for %s: %s",
                self._sub_id,
                server_name,
                exc,
            )
        return databases

    def _get_sql_short_term_policy(
        self, resource_group: str, server_name: str, db_name: str
    ) -> tuple[Optional[int], Optional[int]]:
        """Short-term backup retention: ``(retention_days, diff_backup_interval_hours)``."""
        try:
            policy = self._sql.backup_short_term_retention_policies.get(
                resource_group, server_name, db_name, "default"
            )
            days = getattr(policy, "retention_days", None)
            hours = getattr(policy, "diff_backup_interval_in_hours", None)
            return (
                int(days) if days is not None else None,
                int(hours) if hours is not None else None,
            )
        except Exception as exc:
            logger.debug(
                "[%s] Short-term retention unavailable for %s/%s: %s",
                self._sub_id,
                server_name,
                db_name,
                exc,
            )
            return None, None

    def _get_sql_ltr_policy(self, resource_group: str, server_name: str, db_name: str) -> dict:
        """Long-term retention policy fields as the API returns them; ``{}`` if unavailable."""
        try:
            policy = self._sql.long_term_retention_policies.get(
                resource_group, server_name, db_name, _LTR_POLICY_NAME
            )
            week = getattr(policy, "week_of_year", None)
            return {
                "weekly_retention": getattr(policy, "weekly_retention", None),
                "monthly_retention": getattr(policy, "monthly_retention", None),
                "yearly_retention": getattr(policy, "yearly_retention", None),
                "week_of_year": int(week) if week is not None else None,
            }
        except Exception as exc:
            logger.debug(
                "[%s] LTR policy unavailable for %s/%s: %s",
                self._sub_id,
                server_name,
                db_name,
                exc,
            )
            if not _no_policy_answer(exc):
                self._ltr_failures.append(exc)
            return {}

    def _list_elastic_pools(self, resource_group: str, server_name: str) -> list[ElasticPoolInfo]:
        """Elastic pools of a SQL logical server."""
        pools: list[ElasticPoolInfo] = []
        try:
            for pool in self._sql.elastic_pools.list_by_server(resource_group, server_name):
                max_bytes = getattr(pool, "max_size_bytes", None)
                pools.append(
                    ElasticPoolInfo(
                        name=getattr(pool, "name", "") or "",
                        server_name=server_name,
                        resource_group=resource_group,
                        location=(getattr(pool, "location", "") or "").lower(),
                        sku_name=enum_text(getattr(getattr(pool, "sku", None), "name", None)),
                        max_size_bytes=int(max_bytes) if max_bytes is not None else None,
                    )
                )
        except Exception as exc:
            logger.warning(
                "[%s] Failed to list elastic pools for %s: %s", self._sub_id, server_name, exc
            )
        return pools

    def _list_managed_instances(self) -> list[SqlManagedInstanceInfo]:
        """Enumerate Azure SQL Managed Instances in the subscription.

        MIs use a different resource provider from SQL logical servers, so
        this is a separate ``managed_instances.list()`` call.  Region
        filtering is applied identically to the SQL server path.
        """
        instances: list[SqlManagedInstanceInfo] = []
        try:
            iterator = self._sql.managed_instances.list()
        except AttributeError:
            # Older azure-mgmt-sql builds may not expose managed_instances.
            logger.debug(
                "[%s] SQL client has no managed_instances attribute; skipping MI collection.",
                self._sub_id,
            )
            return instances
        except HttpResponseError as exc:
            logger.warning(
                "[%s] Failed to list SQL managed instances: %s",
                self._sub_id,
                exc,
            )
            return instances

        try:
            for mi in progress.every(list(iterator), self._sub_id, "managed instances"):
                try:
                    location = (getattr(mi, "location", "") or "").lower()
                    if self._regions and location not in self._regions:
                        continue

                    rg = parse_resource_group(getattr(mi, "id", "") or "")
                    sku = getattr(mi, "sku", None)
                    sku_name = getattr(sku, "name", None)
                    sku_tier = getattr(sku, "tier", None)

                    storage_gb = getattr(mi, "storage_size_in_gb", None)
                    v_cores = getattr(mi, "v_cores", None)

                    backup_redundancy = (
                        getattr(mi, "current_backup_storage_redundancy", None)
                        or getattr(mi, "requested_backup_storage_redundancy", None)
                        or getattr(mi, "storage_account_type", None)
                    )
                    mi_id = getattr(mi, "id", "") or ""
                    used_gb, used_raw_mb = self._used_storage(mi_id, "sql_mi")
                    mi_name = getattr(mi, "name", "") or ""
                    database_count = self._count_managed_databases(rg, mi_name)
                    space_used_mb = self._metric_maximum(
                        mi_id, "storage_space_used_mb", "Microsoft.Sql/managedInstances"
                    )
                    used_bytes_derived = (
                        int(round(used_raw_mb * 1024**2)) if used_raw_mb is not None else None
                    )
                    used_storage_tb = round(used_gb / 1024, 3) if used_gb else None
                    storage_size_bytes_derived = (
                        int(storage_gb) * 1024**3 if storage_gb is not None else None
                    )
                    storage_size_tb = (
                        round(storage_gb / 1024, 3) if storage_gb is not None else None
                    )

                    instances.append(
                        SqlManagedInstanceInfo(
                            name=getattr(mi, "name", "") or "",
                            resource_id=mi_id,
                            used_storage_gb=used_gb,
                            used_storage_bytes_derived=used_bytes_derived,
                            used_storage_tb=used_storage_tb,
                            resource_group=rg,
                            subscription_id=self._sub_id,
                            location=location,
                            sku_name=enum_text(sku_name) or None,
                            sku_tier=enum_text(sku_tier) or None,
                            v_cores=int(v_cores) if v_cores is not None else None,
                            storage_size_gb=int(storage_gb) if storage_gb is not None else None,
                            storage_size_bytes_derived=storage_size_bytes_derived,
                            storage_size_tb=storage_size_tb,
                            storage_size_gb_decimal=decimal_gb(storage_size_bytes_derived),
                            storage_size_tb_decimal=decimal_tb(storage_size_bytes_derived),
                            used_storage_gb_decimal=decimal_gb(used_bytes_derived),
                            used_storage_tb_decimal=decimal_tb(used_bytes_derived),
                            license_type=enum_text(getattr(mi, "license_type", None)) or None,
                            backup_storage_redundancy=(enum_text(backup_redundancy) or None),
                            zone_redundant=bool(getattr(mi, "zone_redundant", False)),
                            tags=dict(getattr(mi, "tags", {}) or {}),
                            database_count=database_count,
                            storage_space_used_mb=space_used_mb,
                            databases_az=self._managed_database_records(rg, mi_name),
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping SQL managed instance %s: %s",
                        self._sub_id,
                        getattr(mi, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning(
                "[%s] SQL managed-instance listing failed mid-stream: %s",
                self._sub_id,
                exc,
            )
        return instances

    def _managed_database_records(self, resource_group: str, instance: str) -> list[dict]:
        """The instance's databases with their short-term and long-term retention policies.

        PowerShell reads both policies in one ``try``: when the first cannot be read neither is added, and
        when only the long-term one cannot (a stopped or inaccessible database cannot report it) the
        short-term policy stays. A policy that cannot be read is not an error, so it is logged only at
        debug level.
        """
        try:
            databases = list(self._sql.managed_databases.list_by_instance(resource_group, instance))
        except Exception as exc:
            logger.debug(
                "[%s] Could not list databases of managed instance %s: %s",
                self._sub_id,
                instance,
                exc,
            )
            return []
        records = []
        for database in databases:
            name = getattr(database, "name", "") or ""
            short_term = long_term = None
            try:
                short_term = self._sql.managed_backup_short_term_retention_policies.get(
                    resource_group, instance, name, "default"
                )
                long_term = self._sql.managed_instance_long_term_retention_policies.get(
                    resource_group, instance, name, "default"
                )
            except Exception as exc:
                logger.debug(
                    "[%s] Could not read the retention policies of %s in %s: %s",
                    self._sub_id,
                    name,
                    instance,
                    exc,
                )
            records.append(
                az_managed_database(database, resource_group, instance, short_term, long_term)
            )
        return records

    def _count_managed_databases(self, resource_group: str, instance_name: str) -> Optional[int]:
        """Databases on a managed instance, or None if they cannot be listed."""
        try:
            return sum(
                1
                for _ in self._sql.managed_databases.list_by_instance(resource_group, instance_name)
            )
        except Exception as exc:
            logger.debug(
                "[%s] Could not list databases of managed instance %s: %s",
                self._sub_id,
                instance_name,
                exc,
            )
            return None

    def _list_flexible_servers(self, engine: str) -> list[FlexibleServerInfo]:
        """List PostgreSQL or MySQL flexible servers across the subscription."""
        client = self._pg if engine == "PostgreSQL" else self._mysql
        system_dbs = _PG_SYSTEM_DBS if engine == "PostgreSQL" else _MYSQL_SYSTEM_DBS
        servers: list[FlexibleServerInfo] = []

        try:
            listed = list(client.servers.list())
            for srv in progress.every(listed, self._sub_id, f"{engine} servers"):
                try:
                    raw_location = srv.location or ""
                    location = raw_location.lower().replace(" ", "")
                    if self._regions and location not in self._regions:
                        continue

                    rg = parse_resource_group(srv.id or "")
                    server_name = srv.name or ""

                    sku = getattr(srv, "sku", None)
                    sku_name = enum_text(getattr(sku, "name", None)) or "Unknown"
                    tier = enum_text(getattr(sku, "tier", None)) or "Unknown"

                    storage = getattr(srv, "storage", None)
                    storage_gb = getattr(storage, "storage_size_gb", None)

                    backup = getattr(srv, "backup", None)
                    retention = getattr(backup, "backup_retention_days", None)
                    geo_raw = getattr(backup, "geo_redundant_backup", None)
                    geo_text = enum_text(geo_raw)
                    geo_redundant = (geo_text or "").lower() == "enabled"
                    high_availability = getattr(srv, "high_availability", None)

                    db_count = self._count_flexible_dbs(rg, server_name, engine, system_dbs)
                    srv_id = srv.id or ""
                    used_gb, used_raw_bytes = self._used_storage(
                        srv_id, "pg_flex" if engine == "PostgreSQL" else "mysql_flex"
                    )
                    used_bytes_val = (
                        int(round(used_raw_bytes)) if used_raw_bytes is not None else None
                    )
                    used_storage_tb = round(used_gb / 1024, 3) if used_gb else None
                    utilized_bytes = (
                        self._metric_peak(srv_id, *_UTILIZED_METRIC["pg_flex"])
                        if engine == "PostgreSQL"
                        else None
                    )
                    storage_bytes_derived = (
                        int(storage_gb) * 1024**3 if storage_gb is not None else None
                    )
                    storage_tb = round(storage_gb / 1024, 3) if storage_gb is not None else None

                    servers.append(
                        FlexibleServerInfo(
                            name=server_name,
                            resource_id=srv_id,
                            used_storage_gb=used_gb,
                            used_storage_bytes=used_bytes_val,
                            used_storage_tb=used_storage_tb,
                            resource_group=rg,
                            subscription_id=self._sub_id,
                            location=location,
                            engine=engine,
                            sku_name=sku_name,
                            tier=tier,
                            version=enum_text(getattr(srv, "version", None)) or "Unknown",
                            storage_gb=int(storage_gb) if storage_gb is not None else None,
                            storage_bytes_derived=storage_bytes_derived,
                            storage_tb=storage_tb,
                            storage_gb_decimal=decimal_gb(storage_bytes_derived),
                            storage_tb_decimal=decimal_tb(storage_bytes_derived),
                            used_storage_gb_decimal=decimal_gb(used_bytes_val),
                            used_storage_tb_decimal=decimal_tb(used_bytes_val),
                            backup_retention_days=(
                                int(retention) if retention is not None else None
                            ),
                            geo_redundant_backup=geo_redundant,
                            database_count=db_count,
                            tags=dict(srv.tags) if srv.tags else {},
                            state=enum_text(getattr(srv, "state", None)),
                            administrator_login=getattr(srv, "administrator_login", None),
                            high_availability_mode=enum_text(
                                getattr(high_availability, "mode", None)
                            ),
                            geo_redundant_backup_text=geo_text,
                            raw_location=raw_location,
                            utilized_bytes=utilized_bytes,
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping %s flexible server %s: %s",
                        self._sub_id,
                        engine,
                        getattr(srv, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning(
                "[%s] Failed to list %s flexible servers: %s",
                self._sub_id,
                engine,
                exc,
            )
        return servers

    def _count_flexible_dbs(
        self,
        resource_group: str,
        server_name: str,
        engine: str,
        system_dbs: frozenset[str],
    ) -> Optional[int]:
        """Count user databases on a flexible server; None when they could not be listed."""
        client = self._pg if engine == "PostgreSQL" else self._mysql
        try:
            return sum(
                1
                for db in client.databases.list_by_server(resource_group, server_name)
                if (db.name or "").lower() not in system_dbs
            )
        except Exception as exc:
            logger.debug(
                "[%s] Could not count databases for %s/%s: %s",
                self._sub_id,
                server_name,
                engine,
                exc,
            )
            return None

    def _compute_rollups(self, inventory: DatabaseInventory) -> None:
        """Compute aggregate fields on the inventory object in-place."""
        inventory.total_sql_servers = len(inventory.sql_servers)
        inventory.total_sql_databases = sum(s.database_count for s in inventory.sql_servers)
        inventory.total_flexible_servers = len(inventory.flexible_servers)

        inventory.total_sql_mi_instances = len(inventory.managed_instances)
        inventory.total_sql_mi_storage_gb = sum(
            (mi.storage_size_gb or 0) for mi in inventory.managed_instances
        )

        # total_databases: user SQL databases + user databases on flexible servers
        inventory.total_databases = inventory.total_sql_databases + sum(
            (s.database_count or 0) for s in inventory.flexible_servers
        )

        # Engine breakdown (counts user databases for SQL + flex engines;
        # SQL MI is counted by instance since we don't enumerate per-MI databases).
        if inventory.total_sql_databases:
            inventory.engine_breakdown["Azure SQL"] = inventory.total_sql_databases
        if inventory.total_sql_mi_instances:
            inventory.engine_breakdown["SQL MI"] = inventory.total_sql_mi_instances
        for srv in inventory.flexible_servers:
            k = srv.engine
            inventory.engine_breakdown[k] = inventory.engine_breakdown.get(k, 0) + (
                srv.database_count or 0
            )

        # SQL edition breakdown
        for srv in inventory.sql_servers:
            for db in srv.databases:
                e = db.edition
                inventory.edition_breakdown[e] = inventory.edition_breakdown.get(e, 0) + 1

        # Flexible server tier breakdown (one entry per server instance)
        for srv in inventory.flexible_servers:
            t = srv.tier
            inventory.tier_breakdown[t] = inventory.tier_breakdown.get(t, 0) + 1

        # Average short-term retention (SQL databases with known values)
        retention_values = [
            db.short_term_retention_days
            for srv in inventory.sql_servers
            for db in srv.databases
            if db.short_term_retention_days is not None
        ]
        if retention_values:
            inventory.avg_short_term_retention_days = round(
                sum(retention_values) / len(retention_values), 1
            )

"""Database collector for Rubrik Discovery — GCP Edition.

Covers: Cloud SQL, Cloud Spanner, AlloyDB, Cloud Bigtable.
All collectors degrade gracefully — a missing API enablement or IAM permission
skips that engine and logs a warning rather than failing the whole run.
"""

from __future__ import annotations

import logging
from typing import Optional

from models.inventory import (
    AlloyDBCluster,
    BigtableInstance,
    CloudSQLInstance,
    DatabaseInventory,
    SpannerInstance,
)

from collectors.retry import retry_call
from collectors.utils import LabelSummary, brief_error, build_label_summary, collection_error

logger = logging.getLogger(__name__)

# System databases PowerShell leaves out of a Cloud SQL instance's database count, by engine
# (the engine is the prefix of the database version). Names are compared without regard to case.
_SYSTEM_DATABASES = {
    "POSTGRES": ("information_schema", "postgres", "template0", "template1", "cloudsqladmin"),
    "MYSQL": ("information_schema", "mysql", "performance_schema", "sys"),
    "SQLSERVER": ("information_schema", "master", "tempdb", "model", "msdb"),
}


def _system_databases(database_version: str) -> frozenset[str]:
    for prefix, names in _SYSTEM_DATABASES.items():
        if (database_version or "").upper().startswith(prefix):
            return frozenset(n.casefold() for n in names)
    return frozenset()


class DatabaseCollector:
    """Collect managed database inventory for a GCP project.

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

    def collect(self) -> DatabaseInventory:
        """Collect all database instances across all supported engines.

        Returns:
            DatabaseInventory. Individual engines are skipped (with a warning)
            if their API is not enabled or the credential lacks access.
        """
        cloud_sql = self._collect_cloud_sql()
        spanner = self._collect_spanner()
        alloydb = self._collect_alloydb()
        bigtable = self._collect_bigtable()

        return self._build_inventory(cloud_sql, spanner, alloydb, bigtable)

    # ── Cloud SQL ─────────────────────────────────────────────────────────────

    def _collect_cloud_sql(self) -> list[CloudSQLInstance]:
        try:
            import googleapiclient.discovery  # deferred import

            service = googleapiclient.discovery.build(
                "sqladmin", "v1beta4", credentials=self._credentials
            )
            req = service.instances().list(project=self._project_id)
            instances: list[CloudSQLInstance] = []

            while req is not None:
                resp = retry_call(
                    req.execute,
                    description=f"cloudsql.instances.list({self._project_id})",
                )
                for item in resp.get("items", []):
                    instance = self._parse_cloud_sql(item)
                    instance.number_of_databases = self._cloud_sql_database_count(
                        service, instance.name, instance.database_version
                    )
                    instances.append(instance)
                req = service.instances().list_next(req, resp)

            logger.debug("Project %s: %d Cloud SQL instances", self._project_id, len(instances))
            return instances
        except Exception as exc:
            logger.warning(
                "Cloud SQL collection failed for project %s: %s",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("database:cloud_sql", exc))
            return []

    def _cloud_sql_database_count(
        self, service, instance_name: str, database_version: str
    ) -> Optional[int]:
        """User databases of a Cloud SQL instance, or None (recorded once per project) if the
        databases cannot be listed. PowerShell counts those not in the engine's system list.
        """
        try:
            resp = retry_call(
                service.databases().list(project=self._project_id, instance=instance_name).execute,
                description=f"cloudsql.databases.list({self._project_id}/{instance_name})",
            )
        except Exception as exc:
            logger.warning(
                "Could not list databases of Cloud SQL instance %s in project %s: %s",
                instance_name,
                self._project_id,
                brief_error(exc),
            )
            if not any(e.get("collector") == "database:cloud_sql_databases" for e in self.errors):
                self.errors.append(collection_error("database:cloud_sql_databases", exc))
            return None
        system = _system_databases(database_version)
        return sum(
            1 for db in resp.get("items", []) if (db.get("name") or "").casefold() not in system
        )

    @staticmethod
    def _parse_cloud_sql(item: dict) -> CloudSQLInstance:
        settings = item.get("settings", {})
        _ip_config = settings.get("ipConfiguration", {})
        ha_type = settings.get("availabilityType", "ZONAL")
        backup_config = settings.get("backupConfiguration", {})
        storage_config = settings.get("dataDiskSizeGb", "10")
        # The API keeps the labels in settings.userLabels.
        labels = settings.get("userLabels") or item.get("userLabels", {})
        storage_size_gb = int(storage_config)
        retention = backup_config.get("backupRetentionSettings", {}).get("retainedBackups")
        raw_size = settings.get("dataDiskSizeGb")

        return CloudSQLInstance(
            name=item.get("name", ""),
            region=item.get("region", ""),
            database_version=item.get("databaseVersion", ""),
            tier=settings.get("tier", ""),
            storage_type=settings.get("dataDiskType", "PD_SSD"),
            storage_size_gb=storage_size_gb,
            high_availability=ha_type == "REGIONAL",
            automated_backup_enabled=bool(backup_config.get("enabled", False)),
            labels=dict(labels) if labels else {},
            state=item.get("state", "RUNNABLE"),
            storage_size_bytes_derived=int(storage_size_gb * 1e9),
            storage_size_tb=round(storage_size_gb / 1000, 4),
            instance_type=item.get("instanceType", ""),
            data_disk_size_gb=float(raw_size) if raw_size else None,
            availability_type=settings.get("availabilityType"),
            backup_retention_count=int(retention) if retention is not None else None,
            backup_start_time=backup_config.get("startTime"),
        )

    # ── Cloud Spanner ─────────────────────────────────────────────────────────

    def _collect_spanner(self) -> list[SpannerInstance]:
        try:
            from google.cloud import spanner_admin_instance_v1  # deferred import

            client = spanner_admin_instance_v1.InstanceAdminClient(credentials=self._credentials)
            parent = f"projects/{self._project_id}"
            instances: list[SpannerInstance] = []

            spanner_objs = retry_call(
                lambda: list(client.list_instances(parent=parent)),
                description=f"spanner.list_instances({self._project_id})",
            )
            db_client = self._spanner_database_client()
            for inst in spanner_objs:
                labels = dict(inst.labels) if inst.labels else {}
                node_count = inst.node_count or 0
                processing_units = inst.processing_units or 0

                instances.append(
                    SpannerInstance(
                        name=inst.name.split("/")[-1],
                        config=inst.config.split("/")[-1] if inst.config else "",
                        display_name=inst.display_name or "",
                        node_count=node_count,
                        processing_units=processing_units,
                        state=inst.state.name if inst.state else "UNKNOWN",
                        labels=labels,
                        database_count=self._spanner_database_count(db_client, inst.name),
                    )
                )

            logger.debug("Project %s: %d Spanner instances", self._project_id, len(instances))
            return instances
        except Exception as exc:
            logger.warning(
                "Spanner collection failed for project %s: %s",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("database:spanner", exc))
            return []

    def _spanner_database_client(self):
        """Database admin client, or None (recorded in errors) if it cannot be created."""
        try:
            from google.cloud import spanner_admin_database_v1  # deferred import

            return spanner_admin_database_v1.DatabaseAdminClient(credentials=self._credentials)
        except Exception as exc:
            logger.warning(
                "Spanner database listing unavailable for project %s: %s",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("database:spanner_databases", exc))
            return None

    def _spanner_database_count(self, db_client, instance_name: str) -> int:
        """Number of databases in a Spanner instance; 0 when listing fails (recorded)."""
        if db_client is None:
            return 0
        try:
            databases = retry_call(
                lambda: list(db_client.list_databases(parent=instance_name)),
                description=f"spanner.list_databases({instance_name})",
            )
            return len(databases)
        except Exception as exc:
            logger.warning(
                "Could not list databases for Spanner instance %s: %s",
                instance_name,
                brief_error(exc),
            )
            self.errors.append(collection_error("database:spanner_databases", exc))
            return 0

    # ── AlloyDB ───────────────────────────────────────────────────────────────

    def _collect_alloydb(self) -> list[AlloyDBCluster]:
        try:
            from google.cloud import alloydb_v1  # deferred import

            client = alloydb_v1.AlloyDBAdminClient(credentials=self._credentials)
            parent = f"projects/{self._project_id}/locations/-"
            clusters: list[AlloyDBCluster] = []

            cluster_objs = retry_call(
                lambda: list(client.list_clusters(parent=parent)),
                description=f"alloydb.list_clusters({self._project_id})",
            )
            for cluster in cluster_objs:
                labels = dict(cluster.labels) if cluster.labels else {}
                name_parts = cluster.name.split("/")
                region = name_parts[3] if len(name_parts) > 3 else ""

                clusters.append(
                    AlloyDBCluster(
                        name=cluster.name.split("/")[-1],
                        region=region,
                        database_version=cluster.database_version.name
                        if cluster.database_version
                        else "",
                        state=cluster.state.name if cluster.state else "UNKNOWN",
                        labels=labels,
                    )
                )

            logger.debug("Project %s: %d AlloyDB clusters", self._project_id, len(clusters))
            return clusters
        except Exception as exc:
            logger.warning(
                "AlloyDB collection failed for project %s: %s",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("database:alloydb", exc))
            return []

    # ── Bigtable ──────────────────────────────────────────────────────────────

    def _collect_bigtable(self) -> list[BigtableInstance]:
        try:
            from google.cloud import bigtable  # deferred import

            client = bigtable.Client(
                project=self._project_id,
                credentials=self._credentials,
                admin=True,
            )
            instances_list: list[BigtableInstance] = []

            bigtable_objs = retry_call(
                lambda: client.list_instances()[0],
                description=f"bigtable.list_instances({self._project_id})",
            )
            for inst in bigtable_objs:
                labels = dict(inst.labels) if inst.labels else {}
                instance_type = "PRODUCTION"
                try:
                    instance_type = inst.type_.name
                except Exception:
                    pass

                cluster_count = 0
                try:
                    cluster_count = len(list(inst.list_clusters()))
                except Exception:
                    pass

                instances_list.append(
                    BigtableInstance(
                        name=inst.instance_id,
                        display_name=inst.display_name or "",
                        state=inst.state.name if inst.state else "UNKNOWN",
                        instance_type=instance_type,
                        labels=labels,
                        cluster_count=cluster_count,
                    )
                )

            logger.debug(
                "Project %s: %d Bigtable instances",
                self._project_id,
                len(instances_list),
            )
            return instances_list
        except Exception as exc:
            logger.warning(
                "Bigtable collection failed for project %s: %s",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("database:bigtable", exc))
            return []

    # ── Roll-up ───────────────────────────────────────────────────────────────

    def _build_inventory(
        self,
        cloud_sql: list[CloudSQLInstance],
        spanner: list[SpannerInstance],
        alloydb: list[AlloyDBCluster],
        bigtable: list[BigtableInstance],
    ) -> DatabaseInventory:
        engine_breakdown: dict[str, int] = {}

        for inst in cloud_sql:
            # Normalise: MYSQL_8_0 → MYSQL, POSTGRES_15 → POSTGRES, etc.
            family = inst.database_version.split("_")[0] if inst.database_version else "UNKNOWN"
            engine_breakdown[family] = engine_breakdown.get(family, 0) + 1

        if spanner:
            engine_breakdown["SPANNER"] = len(spanner)
        if alloydb:
            engine_breakdown["ALLOYDB"] = len(alloydb)
        if bigtable:
            engine_breakdown["BIGTABLE"] = len(bigtable)

        total = len(cloud_sql) + len(spanner) + len(alloydb) + len(bigtable)

        # Build label summary across Cloud SQL + Spanner (the labelled engines).
        all_labels = (
            [i.labels for i in cloud_sql]
            + [i.labels for i in spanner]
            + [i.labels for i in alloydb]
            + [i.labels for i in bigtable]
        )
        label_summary: Optional[LabelSummary] = build_label_summary(all_labels)

        return DatabaseInventory(
            project_id=self._project_id,
            cloud_sql_instances=cloud_sql,
            spanner_instances=spanner,
            alloydb_clusters=alloydb,
            bigtable_instances=bigtable,
            total_databases=total,
            engine_breakdown=engine_breakdown,
            label_summary=label_summary,
        )

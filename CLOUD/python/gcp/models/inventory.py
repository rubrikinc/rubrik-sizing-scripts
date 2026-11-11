"""Unified output model for Rubrik Discovery — GCP Edition.

``DiscoveryResult`` is a Pydantic model that aggregates all per-project
collector results into a single serialisable object.  Everything else in the
codebase uses plain dataclasses; this is the only Pydantic boundary — the
point at which data leaves the collectors and becomes JSON.

Fields are added incrementally as collectors land:
  Phase 1 — schema skeleton, project scope, asset counts
  Phase 2 — compute, storage, database, backup_posture
  Phase 3 — filestore, iac, cost, security

The per-resource dataclasses (GCEInstance, CloudSQLInstance, ...) live in
``discovery_dataclasses.py``, re-exported here for backward compatibility — that split
keeps them importable with zero external dependencies (no pydantic), since the Explorer's
ingest adapter (a repo-root service with its own, separate requirements.txt) reconstructs
them from raw discovery JSON to catch field-name drift, and must not inherit gcp/'s own
tool-specific dependency tree to do it.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from .discovery_dataclasses import (
    AlloyDBCluster,
    BackupPlan,
    BackupPlanAssociation,
    BackupPostureInventory,
    BigQueryInventory,
    BigQueryTable,
    BigtableInstance,
    CloudSQLInstance,
    ComputeInventory,
    DatabaseInventory,
    GCEDisk,
    GCEInstance,
    GCSBucket,
    SpannerInstance,
    StorageInventory,
)

__all__ = [
    "AlloyDBCluster",
    "BackupPlan",
    "BackupPlanAssociation",
    "BackupPostureInventory",
    "BigQueryInventory",
    "BigQueryTable",
    "BigtableInstance",
    "CloudSQLInstance",
    "ComputeInventory",
    "DatabaseInventory",
    "GCEDisk",
    "GCEInstance",
    "GCSBucket",
    "SpannerInstance",
    "StorageInventory",
    "CollectionError",
    "DiscoveryResult",
    "CURRENT_SCHEMA_VERSION",
]

CURRENT_SCHEMA_VERSION = "1.0"


def _asdict_safe(obj: Any) -> Any:
    """Recursively convert dataclasses to dicts, leaving other types unchanged."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _asdict_safe(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_asdict_safe(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _asdict_safe(v) for k, v in obj.items()}
    return obj


# ── Pydantic output model ─────────────────────────────────────────────────────


class CollectionError(BaseModel):
    """A collector that failed (or partially failed) for one project.

    Recorded so a partial scan is *visible* in the output instead of silently
    showing zeros: at org scale a project with an API disabled or a missing
    permission would otherwise be indistinguishable from a genuinely empty one,
    causing the sizing estimate to undercount with no signal.
    """

    project_id: str
    collector: str
    """Which collector/sub-collector: e.g. 'compute', 'database:spanner', 'backup'."""

    category: str
    """Reason class: API_DISABLED | PERMISSION_DENIED | SDK_MISSING | OTHER."""

    message: str
    """One-line human-readable cause."""


class DiscoveryResult(BaseModel):
    """Top-level output model serialised to JSON at the end of a discovery run."""

    model_config = ConfigDict(arbitrary_types_allowed=False)

    schema_version: str = CURRENT_SCHEMA_VERSION
    generated_at: str
    """ISO 8601 UTC timestamp of when the discovery ran."""

    organization_id: Optional[str] = None
    """GCP organization ID, if the credential has org-level visibility."""

    projects_scanned: list[str]
    """Project IDs that were successfully enumerated."""

    regions_in_scope: Optional[list[str]] = None
    """Regions the collectors filtered to; None means all regions."""

    # Phase 1 — asset spine summary (one entry per project)
    asset_counts: dict[str, Any] = Field(default_factory=dict)
    """Per-project asset counts: {project_id: {asset_type: count, total: N}}."""

    # Phase 2
    compute: list[dict[str, Any]] = Field(default_factory=list)
    """Per-project compute inventories (ComputeInventory serialised to dict)."""

    storage: list[dict[str, Any]] = Field(default_factory=list)
    """Per-project storage inventories."""

    databases: list[dict[str, Any]] = Field(default_factory=list)
    """Per-project database inventories."""

    backup_posture: list[dict[str, Any]] = Field(default_factory=list)
    """Per-project backup posture inventories."""

    bigquery: list[dict[str, Any]] = Field(default_factory=list)
    """Per-project BigQuery inventories (one entry per table, view or snapshot)."""

    collection_errors: list[CollectionError] = Field(default_factory=list)
    # The pre-flight access check: one row per service and project, with what was readable and what
    # the scan will therefore miss. Empty when the check was skipped (--no-preflight).
    access_check: list[dict[str, str]] = Field(default_factory=list)
    """Per-project collector failures (API disabled, missing permission, missing
    SDK, etc.). A non-empty list means some projects' data is incomplete and the
    affected metrics undercount; empty means full coverage across all scanned
    projects. The SE report should surface this so a partial scan isn't silent."""

    # Phase 3 fields (stubbed)
    # filestore: list[dict[str, Any]] = Field(default_factory=list)
    # iac: list[dict[str, Any]] = Field(default_factory=list)
    # cost: dict[str, Any] = Field(default_factory=dict)
    # security: dict[str, Any] = Field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return self.model_dump()

"""pytest configuration — stub out missing GCP Cloud library packages.

google-auth is installed but the individual google-cloud-* libraries
(google-cloud-asset, google-cloud-resource-manager, etc.) may not be.
Tests mock all SDK calls, so stubs are sufficient for test collection.

Only stubs packages that are genuinely not importable; installed packages
are left untouched.
"""

from __future__ import annotations

import importlib
import sys
import types
from unittest.mock import MagicMock


def _ensure_stub(module_name: str, **attrs) -> None:
    """Stub ``module_name`` only if it is not already importable.

    Preserves existing parent namespace packages (e.g. the ``google``
    namespace package provided by google-auth).
    """
    if importlib.util.find_spec(module_name) is not None:
        return  # real package exists — leave it alone

    # Walk down the dotted path, creating intermediate namespace packages
    # only where missing, to avoid clobbering google-auth's ``google`` ns.
    parts = module_name.split(".")
    for i in range(1, len(parts) + 1):
        name = ".".join(parts[:i])
        if name in sys.modules:
            continue
        parent_name = ".".join(parts[: i - 1]) if i > 1 else None
        mod = types.ModuleType(name)
        if parent_name and parent_name in sys.modules:
            setattr(sys.modules[parent_name], parts[i - 1], mod)
        sys.modules[name] = mod

    stub = sys.modules[module_name]
    for k, v in attrs.items():
        setattr(stub, k, v)


# google-cloud-resource-manager
_ensure_stub(
    "google.cloud.resourcemanager_v3",
    ProjectsClient=MagicMock,
    SearchProjectsRequest=MagicMock,
    GetProjectRequest=MagicMock,
)

# google-cloud-asset
_AssetContentType = MagicMock()
_AssetContentType.RESOURCE = "RESOURCE"
_ensure_stub(
    "google.cloud.asset_v1",
    AssetServiceClient=MagicMock,
    ListAssetsRequest=MagicMock,
    ContentType=_AssetContentType,
)

# google-cloud-compute (Phase 2)
_ensure_stub(
    "google.cloud.compute_v1",
    InstancesClient=MagicMock,
    DisksClient=MagicMock,
    AggregatedListInstancesRequest=MagicMock,
    AggregatedListDisksRequest=MagicMock,
)

# google-cloud-storage (Phase 2)
_ensure_stub("google.cloud.storage", Client=MagicMock)

# google-cloud-monitoring (Phase 2)
_ensure_stub("google.cloud.monitoring_v3", MetricServiceClient=MagicMock)

# google-cloud-spanner (Phase 2)
_ensure_stub("google.cloud.spanner_v1", InstanceAdminClient=MagicMock)

# google-cloud-alloydb (Phase 2)
_ensure_stub("google.cloud.alloydb_v1", AlloyDBAdminClient=MagicMock)

# google-cloud-bigtable (Phase 2)
_ensure_stub("google.cloud.bigtable", Client=MagicMock)

# google-cloud-backupdr (Phase 2)
_ensure_stub("google.cloud.backupdr_v1", BackupDRClient=MagicMock)

# google-api-python-client (Phase 2 — Cloud SQL)
_ensure_stub("googleapiclient", discovery=MagicMock())
_ensure_stub("googleapiclient.discovery", build=MagicMock())

# google-cloud-billing (Phase 3)
_ensure_stub("google.cloud.billing_v1", CloudBillingClient=MagicMock)

# google-cloud-filestore (Phase 3)
_ensure_stub("google.cloud.filestore_v1", CloudFilestoreManagerClient=MagicMock)

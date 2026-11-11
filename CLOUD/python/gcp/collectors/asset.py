"""Cloud Asset Inventory collector — resource enumeration spine for GCP."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from collectors.retry import RateLimiter
from collectors.utils import brief_error, classify_error, collection_error

logger = logging.getLogger(__name__)

# ListAssets is limited to 100 requests a minute, counted against the project the calls are
# charged to (the quota project), not the scanned project.  Every worker thread shares that one
# budget, so pace them together below it.  The maximum page size is 1000 (the default is 100),
# which cuts the number of calls a project needs tenfold.
_LIST_ASSETS_PAGE_SIZE = 1000
_LIST_ASSETS_PER_MINUTE = 80
# Budget for one page, retries included.  The CSV files do not use the asset counts, so a project
# whose listing stays throttled should give up quickly rather than hold up its other collectors.
_LIST_ASSETS_PAGE_TIMEOUT_S = 120.0

_list_assets_limiter = RateLimiter(_LIST_ASSETS_PER_MINUTE, 60.0)


@dataclass
class AssetInventory:
    """Result of Cloud Asset Inventory enumeration for one project."""

    project_id: str
    total_assets: int = 0
    assets_by_type: dict[str, int] = field(default_factory=dict)
    raw_assets: list[Any] = field(default_factory=list)
    """Raw asset objects — other collectors enrich these with per-service API calls."""
    failed: bool = False
    """The listing could not be read.  The counts are then unknown, not zero."""
    failure_category: str = ""
    """``classify_error`` category of the failure, e.g. ``RATE_LIMITED``; empty when it worked."""


class AssetCollector:
    """Enumerate all resources in a project via Cloud Asset Inventory.

    CAI returns a paginated list of all asset types in a single API call per
    project, making it significantly cheaper than per-service list calls for
    initial enumeration.  Other collectors use per-service APIs to enrich the
    asset list with metadata that CAI does not expose (e.g., actual disk usage,
    backup plan associations).

    Credential injection rule: always receive credentials from ``main.py`` via
    ``auth.get_credentials()``; never instantiate ADC inside a collector.
    """

    def __init__(
        self,
        project_id: str,
        credentials,
        asset_types: Optional[list[str]] = None,
    ) -> None:
        """
        Args:
            project_id: GCP project ID (not project number).
            credentials: Authenticated google.auth Credentials instance.
            asset_types: Optional list of CAI asset type filters, e.g.
                ``["compute.googleapis.com/Instance"]``.  Empty list = all types.
        """
        self._project_id = project_id
        self._credentials = credentials
        self._asset_types = asset_types or []
        self.errors: list[dict] = []

    def collect(self) -> AssetInventory:
        """List all assets in the project.

        Returns:
            AssetInventory with total count, per-type breakdown, and raw assets.
            When the listing cannot be read (CAI not enabled, missing IAM, still
            rate limited after the retries), returns an AssetInventory marked
            ``failed`` and logs a warning rather than raising.
        """
        from google.cloud import asset_v1  # deferred so the module is importable without the SDK

        try:
            client = asset_v1.AssetServiceClient(credentials=self._credentials)
            raw_assets = self._list_all_pages(client, asset_v1)
        except Exception as exc:
            category = classify_error(exc)
            if category == "RATE_LIMITED":
                hint = (
                    "Google kept rate limiting the Cloud Asset API for the project the calls are "
                    "charged to; the asset counts for this project are unknown, not zero"
                )
            else:
                hint = (
                    "check that Cloud Asset Inventory API is enabled and "
                    "roles/cloudasset.viewer is granted"
                )
            logger.warning(
                "Asset enumeration failed for project %s: %s (%s)",
                self._project_id,
                brief_error(exc),
                hint,
            )
            self.errors.append(collection_error("asset", exc))
            return AssetInventory(
                project_id=self._project_id, failed=True, failure_category=category
            )

        assets_by_type: dict[str, int] = {}
        for asset in raw_assets:
            assets_by_type[asset.asset_type] = assets_by_type.get(asset.asset_type, 0) + 1

        logger.debug(
            "Project %s: %d assets across %d types",
            self._project_id,
            len(raw_assets),
            len(assets_by_type),
        )

        return AssetInventory(
            project_id=self._project_id,
            total_assets=len(raw_assets),
            assets_by_type=assets_by_type,
            raw_assets=raw_assets,
        )

    def _list_all_pages(self, client, asset_v1) -> list[Any]:
        """Read the listing one page at a time, retrying a throttled page on its own.

        Retrying the whole listing would start again from page one on every 429, and a large
        project under a shared quota then never finishes.  Each page is one RPC, retried with
        backoff, and the next one resumes from its page token.
        """
        from collectors.retry import retry_call

        raw_assets: list[Any] = []
        page_token = ""
        while True:
            request = asset_v1.ListAssetsRequest(
                parent=f"projects/{self._project_id}",
                asset_types=self._asset_types,
                content_type=asset_v1.ContentType.RESOURCE,
                page_size=_LIST_ASSETS_PAGE_SIZE,
                page_token=page_token,
            )
            _list_assets_limiter.acquire()
            page = retry_call(
                lambda request=request: _first_page(client, request),
                description=f"list_assets({self._project_id})",
                timeout=_LIST_ASSETS_PAGE_TIMEOUT_S,
            )
            raw_assets.extend(page.assets)
            page_token = page.next_page_token
            if not page_token:
                return raw_assets


def _first_page(client, request):
    """The first page of ``list_assets`` for ``request``: exactly one RPC.

    The pager makes the first call itself and fetches later pages only when they are iterated, so
    taking the first page never reaches the next one.  ``retry=None`` turns off the client's own
    retry, so ``retry_call`` is the only one and its time budget holds.
    """
    pager = client.list_assets(request=request, retry=None)
    return next(iter(pager.pages))


class OrgAssetCollector:
    """Org/folder-wide asset spine — one paginated CAI sweep for *all* projects.

    At org scale, calling ``list_assets`` once per project is N API calls (and N
    chances to hit per-project quota).  ``search_all_resources`` enumerates every
    resource under an organization or folder in a single paginated stream, so the
    whole asset spine for 1000 projects costs a handful of calls instead of 1000.

    This only replaces the *enumeration/count* layer.  The per-service deep
    collectors (compute, storage, database, backup) still run per project — they
    fetch metadata CAI does not expose — but they parallelise and retry.

    CAI reports each resource's owning project as ``projects/<NUMBER>``; pass a
    ``project_number_to_id`` map (from ``auth.build_project_number_map``) to key
    the result by ``project_id``.  Unmapped projects are keyed by the raw
    ``projects/<NUMBER>`` so no counts are dropped.
    """

    def __init__(
        self,
        scope: str,
        credentials,
        project_number_to_id: Optional[dict[str, str]] = None,
    ) -> None:
        """
        Args:
            scope: CAI scope — ``organizations/<id>`` or ``folders/<id>``.
            credentials: Authenticated google.auth Credentials instance.
            project_number_to_id: Map of ``project_number -> project_id`` for
                translating CAI's project references back to project IDs.
        """
        self._scope = scope
        self._credentials = credentials
        self._number_to_id = project_number_to_id or {}

    def collect(self) -> dict[str, AssetInventory]:
        """Enumerate all resources under the scope, grouped per project.

        Returns:
            ``{project_id: AssetInventory}``.  On permission error (CAI not
            enabled at org level, missing ``roles/cloudasset.viewer``), returns
            an empty dict and logs a warning — the caller falls back to the
            per-project asset path.
        """
        from google.cloud import asset_v1

        from collectors.retry import retry_call

        try:
            client = asset_v1.AssetServiceClient(credentials=self._credentials)
            # Pass scope as a kwarg rather than building a SearchAllResourcesRequest
            # — the kwarg form is stable across google-cloud-asset versions.
            results = retry_call(
                lambda: list(client.search_all_resources(scope=self._scope)),
                description=f"search_all_resources({self._scope})",
            )
        except Exception as exc:
            logger.warning(
                "Org-wide asset enumeration failed for scope %s: %s "
                "(check Cloud Asset Inventory API is enabled and "
                "roles/cloudasset.viewer is granted at the org/folder level) — "
                "falling back to per-project asset collection",
                self._scope,
                exc,
            )
            return {}

        # Group counts by owning project.
        per_project_types: dict[str, dict[str, int]] = {}
        for res in results:
            project_ref = getattr(res, "project", "") or ""
            number = project_ref.split("/")[-1] if project_ref else ""
            key = self._number_to_id.get(number, project_ref or "unknown")
            asset_type = getattr(res, "asset_type", "") or "unknown"
            types = per_project_types.setdefault(key, {})
            types[asset_type] = types.get(asset_type, 0) + 1

        inventories: dict[str, AssetInventory] = {}
        for key, types in per_project_types.items():
            inventories[key] = AssetInventory(
                project_id=key,
                total_assets=sum(types.values()),
                assets_by_type=types,
                # raw_assets intentionally left empty: the org spine carries
                # counts only; deep metadata comes from per-service collectors.
            )

        logger.debug(
            "Org scope %s: enumerated assets for %d projects in one sweep",
            self._scope,
            len(inventories),
        )
        return inventories

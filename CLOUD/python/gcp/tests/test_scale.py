"""Tests for org-scale discovery: retry/backoff, org-wide asset spine,
parallel orchestration, and streamed output.

All Google SDK calls are mocked — no credentials or live APIs are needed.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from collectors.asset import AssetInventory, OrgAssetCollector
from collectors.retry import _is_retryable, retry_call

# ── Feature 2: retry / backoff ──────────────────────────────────────────────


def test_retry_call_passthrough_no_error():
    """A call that succeeds returns immediately, with no retry."""
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        return "ok"

    assert retry_call(fn, description="t") == "ok"
    assert calls["n"] == 1


def test_retry_predicate_classifies_transient_vs_permanent():
    from google.api_core import exceptions as gexc

    assert _is_retryable(gexc.ServiceUnavailable("503"))
    assert _is_retryable(gexc.ResourceExhausted("429 quota"))
    assert _is_retryable(gexc.TooManyRequests("429"))
    # Permanent errors are NOT retried — graceful degradation handles them.
    assert not _is_retryable(gexc.PermissionDenied("403"))
    assert not _is_retryable(gexc.NotFound("404"))
    assert not _is_retryable(ValueError("nope"))


def test_retry_call_retries_then_succeeds():
    """A transient error backs off and the next attempt succeeds."""
    from google.api_core import exceptions as gexc

    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] == 1:
            raise gexc.ServiceUnavailable("503 transient")
        return "recovered"

    # initial backoff is 1s; patch sleep so the test stays fast.
    with patch("time.sleep", return_value=None):
        assert retry_call(fn, description="t") == "recovered"
    assert calls["n"] == 2


# ── Feature 4: org-wide asset spine ─────────────────────────────────────────


def _search_result(project_number: str, asset_type: str):
    r = MagicMock()
    r.project = f"projects/{project_number}"
    r.asset_type = asset_type
    return r


def test_org_asset_collector_groups_and_maps_to_project_id(mock_credentials):
    results = [
        _search_result("111", "compute.googleapis.com/Instance"),
        _search_result("111", "compute.googleapis.com/Instance"),
        _search_result("111", "storage.googleapis.com/Bucket"),
        _search_result("222", "storage.googleapis.com/Bucket"),
    ]
    fake_client = MagicMock()
    fake_client.search_all_resources.return_value = results

    number_map = {"111": "prod-project", "222": "dev-project"}

    with patch("google.cloud.asset_v1.AssetServiceClient", return_value=fake_client):
        inventories = OrgAssetCollector("organizations/123", mock_credentials, number_map).collect()

    assert set(inventories) == {"prod-project", "dev-project"}
    prod = inventories["prod-project"]
    assert prod.total_assets == 3
    assert prod.assets_by_type["compute.googleapis.com/Instance"] == 2
    assert prod.assets_by_type["storage.googleapis.com/Bucket"] == 1
    assert inventories["dev-project"].total_assets == 1


def test_org_asset_collector_unmapped_number_falls_back_to_raw_ref(mock_credentials):
    fake_client = MagicMock()
    fake_client.search_all_resources.return_value = [
        _search_result("999", "compute.googleapis.com/Instance")
    ]
    with patch("google.cloud.asset_v1.AssetServiceClient", return_value=fake_client):
        inventories = OrgAssetCollector("organizations/123", mock_credentials, {}).collect()
    # Unmapped project number is preserved under its raw ref, nothing dropped.
    assert "projects/999" in inventories
    assert inventories["projects/999"].total_assets == 1


def test_org_asset_collector_returns_empty_on_failure(mock_credentials):
    """A failed org sweep returns {} so the caller falls back to per-project."""
    fake_client = MagicMock()
    fake_client.search_all_resources.side_effect = RuntimeError("CAI not enabled")
    with patch("google.cloud.asset_v1.AssetServiceClient", return_value=fake_client):
        inventories = OrgAssetCollector("organizations/123", mock_credentials, {}).collect()
    assert inventories == {}


# ── Feature 3: streamed output equals in-memory output ──────────────────────


def _sample_per_project() -> dict:
    from models.inventory import (
        BackupPostureInventory,
        ComputeInventory,
        DatabaseInventory,
        StorageInventory,
    )

    return {
        "alpha": {
            "asset": AssetInventory(
                project_id="alpha",
                total_assets=10,
                assets_by_type={"compute.googleapis.com/Instance": 10},
            ),
            "compute": ComputeInventory(project_id="alpha", total_instances=3, total_disk_tb=1.5),
            "storage": StorageInventory(project_id="alpha", total_buckets=4),
            "database": DatabaseInventory(project_id="alpha", total_databases=2),
            "backup": BackupPostureInventory(
                project_id="alpha", protected_instance_count=3, protection_coverage_pct=100.0
            ),
        },
        "beta": {
            "asset": AssetInventory(project_id="beta", total_assets=5, assets_by_type={}),
            "compute": ComputeInventory(project_id="beta", total_instances=1, total_disk_tb=0.5),
            "storage": StorageInventory(project_id="beta", total_buckets=0),
            "database": DatabaseInventory(project_id="beta", total_databases=0),
            "backup": BackupPostureInventory(project_id="beta", protection_coverage_pct=0.0),
        },
    }


def test_streaming_output_matches_in_memory(tmp_path):
    import main
    from streaming_writer import StreamingDiscoveryWriter, slice_from_result

    per_project = _sample_per_project()
    projects = ["alpha", "beta"]
    regions = ["us-central1"]

    # In-memory canonical result.
    in_memory = main._build_result(projects, regions, per_project).to_json_dict()

    # Streamed result.
    writer = StreamingDiscoveryWriter(tmp_path, "20260101-000000")
    for pid in projects:
        writer.add(pid, slice_from_result(pid, per_project[pid]))
    meta = {
        "schema_version": in_memory["schema_version"],
        "generated_at": in_memory["generated_at"],
        "organization_id": None,
        "projects_scanned": projects,
        "regions_in_scope": regions,
        "collection_errors": in_memory["collection_errors"],
        "access_check": in_memory["access_check"],
    }
    out_path = writer.finalize(meta=meta, filename="streamed.json")
    streamed = json.loads(out_path.read_text())

    assert streamed == in_memory
    # Shard cleaned up.
    assert not list(tmp_path.glob(".gcp-sizing-shard-*.ndjson"))


# ── Feature 1: parallel orchestration ───────────────────────────────────────


def test_collect_and_write_parallel_streams_above_threshold(tmp_path, mock_credentials):
    import main
    from models.inventory import ComputeInventory

    n = main._STREAMING_THRESHOLD + 5  # force the streaming path
    projects = [f"proj-{i}" for i in range(n)]

    def fake_collect(pid, credentials, regions, enable_security, precomputed_asset, selected=None):
        return {
            "asset": precomputed_asset
            or AssetInventory(project_id=pid, total_assets=1, assets_by_type={"x": 1}),
            "compute": ComputeInventory(project_id=pid, total_instances=2, total_disk_tb=1.0),
        }

    with patch.object(main, "_collect_project", side_effect=fake_collect):
        out_path = main._collect_and_write(
            projects=projects,
            regions=None,
            credentials=mock_credentials,
            enable_security=False,
            workers=8,
            org_assets={},
            output_dir=tmp_path,
        )

    data = json.loads(out_path.read_text())
    assert data["projects_scanned"] == projects  # scan order preserved
    assert len(data["compute"]) == n
    assert sum(c["total_instances"] for c in data["compute"]) == 2 * n


def test_collect_and_write_uses_org_spine_asset(tmp_path, mock_credentials):
    """When org_assets has an entry for a project, it is passed through as the spine."""
    import main
    from models.inventory import ComputeInventory

    projects = ["p1", "p2"]
    org_assets = {"p1": AssetInventory(project_id="p1", total_assets=42, assets_by_type={"t": 42})}
    seen = {}

    def fake_collect(pid, credentials, regions, enable_security, precomputed_asset, selected=None):
        seen[pid] = precomputed_asset
        return {"compute": ComputeInventory(project_id=pid, total_instances=1, total_disk_tb=0.1)}

    with patch.object(main, "_collect_project", side_effect=fake_collect):
        main._collect_and_write(
            projects=projects,
            regions=None,
            credentials=mock_credentials,
            enable_security=False,
            workers=2,
            org_assets=org_assets,
            output_dir=tmp_path,
        )

    assert seen["p1"] is org_assets["p1"]
    assert seen["p2"] is None  # not in org spine → per-project fallback


def test_collect_project_skips_asset_when_precomputed(mock_credentials):
    """precomputed_asset short-circuits the per-project AssetCollector."""
    import main

    sentinel = AssetInventory(project_id="x", total_assets=7, assets_by_type={"a": 7})

    with (
        patch("collectors.asset.AssetCollector") as AssetCls,
        patch("collectors.compute.ComputeCollector") as ComputeCls,
        patch("collectors.storage.StorageCollector"),
        patch("collectors.database.DatabaseCollector"),
        patch("collectors.bigquery.BigQueryCollector"),
        patch("collectors.backup.BackupCollector"),
    ):
        ComputeCls.return_value.collect.return_value = MagicMock(instances=[], total_instances=0)
        res = main._collect_project("x", mock_credentials, None, False, sentinel)

    assert res["asset"] is sentinel
    AssetCls.assert_not_called()


def test_a_stop_request_writes_the_finished_projects_and_marks_the_rest_not_scanned(
    tmp_path, mock_credentials
):
    import main
    from collectors import utils
    from models.inventory import ComputeInventory

    projects = [f"proj-{i}" for i in range(main._STREAMING_THRESHOLD + 5)]
    failed: list = []

    def fake_collect(pid, credentials, regions, enable_security, precomputed_asset, selected=None):
        if pid == "proj-3":
            utils.request_stop()  # Ctrl-C arrives while this one is running
        return {"compute": ComputeInventory(project_id=pid, total_instances=1, total_disk_tb=1.0)}

    try:
        with patch.object(main, "_collect_project", side_effect=fake_collect):
            out_path = main._collect_and_write(
                projects=projects,
                regions=None,
                credentials=mock_credentials,
                enable_security=False,
                workers=1,
                org_assets={},
                output_dir=tmp_path,
                failed=failed,
            )
    finally:
        utils.reset_stop()

    data = json.loads(out_path.read_text())
    assert len(data["compute"]) == 4  # proj-0..3 finished
    stopped = {pid for pid, exc in failed if isinstance(exc, utils.ScanStopped)}
    assert stopped == set(projects[4:])

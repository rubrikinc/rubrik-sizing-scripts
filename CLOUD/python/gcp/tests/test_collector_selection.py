"""Tests for the --collectors / --inventory-only scan-scope selection."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import main
import pytest


def _args(argv: list[str]):
    return main._build_parser().parse_args(argv)


# ── _resolve_collectors ─────────────────────────────────────────────────────


def test_default_runs_all_core_collectors():
    assert main._resolve_collectors(_args([])) == set(main._CORE_COLLECTORS)


def test_inventory_only_is_asset_spine_alone():
    assert main._resolve_collectors(_args(["--inventory-only"])) == {"asset"}


def test_collectors_subset_is_honoured():
    sel = main._resolve_collectors(_args(["--collectors", "asset,compute,storage"]))
    assert sel == {"asset", "compute", "storage"}


def test_collectors_is_case_insensitive_and_trims():
    sel = main._resolve_collectors(_args(["--collectors", " Asset , COMPUTE "]))
    assert sel == {"asset", "compute"}


def test_unknown_collector_fails_fast():
    with pytest.raises(SystemExit) as exc:
        main._resolve_collectors(_args(["--collectors", "asset,bogus"]))
    assert "bogus" in str(exc.value)


def test_collectors_and_inventory_only_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        _args(["--collectors", "asset", "--inventory-only"])


# ── _collect_project honours the selection ──────────────────────────────────


def test_collect_project_inventory_only_skips_per_service(mock_credentials):
    with (
        patch("collectors.asset.AssetCollector") as asset_cls,
        patch("collectors.compute.ComputeCollector") as compute_cls,
        patch("collectors.storage.StorageCollector") as storage_cls,
        patch("collectors.database.DatabaseCollector") as db_cls,
        patch("collectors.bigquery.BigQueryCollector") as bq_cls,
        patch("collectors.backup.BackupCollector") as backup_cls,
    ):
        asset_cls.return_value.collect.return_value = MagicMock(total_assets=3, assets_by_type={})
        result = main._collect_project("proj-1", mock_credentials, regions=None, selected={"asset"})

    assert "asset" in result
    asset_cls.assert_called_once()
    compute_cls.assert_not_called()
    storage_cls.assert_not_called()
    db_cls.assert_not_called()
    bq_cls.assert_not_called()
    backup_cls.assert_not_called()


def test_collect_project_subset_runs_only_selected(mock_credentials):
    with (
        patch("collectors.asset.AssetCollector") as asset_cls,
        patch("collectors.compute.ComputeCollector") as compute_cls,
        patch("collectors.storage.StorageCollector") as storage_cls,
        patch("collectors.database.DatabaseCollector") as db_cls,
        patch("collectors.bigquery.BigQueryCollector") as bq_cls,
        patch("collectors.backup.BackupCollector") as backup_cls,
    ):
        compute_cls.return_value.collect.return_value = MagicMock(total_instances=2, instances=[])
        main._collect_project("proj-1", mock_credentials, regions=None, selected={"compute"})

    compute_cls.assert_called_once()
    asset_cls.assert_not_called()
    storage_cls.assert_not_called()
    db_cls.assert_not_called()
    bq_cls.assert_not_called()
    backup_cls.assert_not_called()


def test_collect_project_default_none_runs_all(mock_credentials):
    with (
        patch("collectors.asset.AssetCollector") as asset_cls,
        patch("collectors.compute.ComputeCollector") as compute_cls,
        patch("collectors.storage.StorageCollector") as storage_cls,
        patch("collectors.database.DatabaseCollector") as db_cls,
        patch("collectors.bigquery.BigQueryCollector") as bq_cls,
        patch("collectors.backup.BackupCollector") as backup_cls,
    ):
        compute_cls.return_value.collect.return_value = MagicMock(total_instances=0, instances=[])
        main._collect_project("proj-1", mock_credentials, regions=None, selected=None)

    asset_cls.assert_called_once()
    compute_cls.assert_called_once()
    storage_cls.assert_called_once()
    db_cls.assert_called_once()
    bq_cls.assert_called_once()
    backup_cls.assert_called_once()

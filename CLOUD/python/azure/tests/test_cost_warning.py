"""An empty cost result is only a warning when there is something that should have a cost.

The cost scan covers backup-attributable services only (Recovery Services, Azure Backup, Site Recovery).
A subscription with no backup vault has none of those, so "no cost data" is the expected answer, and a
warning that reads like a failure (and lands in the run summary with a fix) sends the reader looking for
a missing role that is not missing. With backup vaults present an empty result is suspicious: the
reader role may be missing, so the warning stays.
"""

from __future__ import annotations

import logging
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import main
from cloud import DEFAULT_CLOUD
from collectors.backup_jobs import BackupJobsInventory
from collectors.backup_posture import BackupPostureInventory
from collectors.compute import ComputeInventory
from collectors.cost import CostSummary
from collectors.database import DatabaseInventory
from collectors.storage import StorageInventory

_SUB = "00000000-0000-0000-0000-000000000001"
_WARNING = "Cost data requested but none returned"


def _run(vault_count: int, cost: CostSummary, caplog):
    results = {
        "compute.ComputeCollector": ComputeInventory(subscription_id=_SUB),
        "backup_posture.BackupPostureCollector": BackupPostureInventory(
            subscription_id=_SUB, vault_count=vault_count
        ),
        "backup_jobs.BackupJobsCollector": BackupJobsInventory(subscription_id=_SUB),
        "storage.StorageCollector": StorageInventory(subscription_id=_SUB),
        "database.DatabaseCollector": DatabaseInventory(subscription_id=_SUB),
        "cost.CostCollector": cost,
    }
    out = MagicMock()
    with caplog.at_level(logging.DEBUG), ExitStack() as stack:
        for target, inventory in results.items():
            mock = MagicMock()
            mock.return_value.collect.return_value = inventory
            mock.return_value.collect_backup_months.return_value = []
            stack.enter_context(patch(f"collectors.{target}", mock))
        main._collect_subscription(_SUB, MagicMock(), None, DEFAULT_CLOUD, scans={}, out=out)
    lines = [str(call.args[0]) for call in out.print.call_args_list if call.args]
    cost_line = next((line for line in lines if "Cost  " in line and "Cost Management" not in line), "")
    return cost_line, [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_no_backup_vaults_and_no_cost_is_not_a_warning(caplog):
    cost_line, warnings = _run(0, CostSummary(subscription_id=_SUB), caplog)
    assert not [w for w in warnings if _WARNING in w.getMessage()]
    assert "no backup vaults" in cost_line.lower()


def test_backup_vaults_and_no_cost_is_still_a_warning(caplog):
    _, warnings = _run(2, CostSummary(subscription_id=_SUB), caplog)
    assert [w for w in warnings if _WARNING in w.getMessage()]


def test_the_cost_line_for_no_vaults_does_not_look_like_a_failure(caplog):
    cost_line, _ = _run(0, CostSummary(subscription_id=_SUB), caplog)
    assert cost_line, "the cost step printed no line"
    assert "⚠" not in cost_line and "yellow" not in cost_line


def test_the_cost_line_with_vaults_and_no_data_is_still_flagged(caplog):
    cost_line, _ = _run(2, CostSummary(subscription_id=_SUB), caplog)
    assert "⚠" in cost_line


def test_a_subscription_with_cost_data_prints_it_whatever_the_vault_count(caplog):
    cost = CostSummary(subscription_id=_SUB, total_6mo_spend=1234.0, months_collected=["2026-09"])
    cost_line, warnings = _run(0, cost, caplog)
    assert "$1,234" in cost_line
    assert not [w for w in warnings if _WARNING in w.getMessage()]

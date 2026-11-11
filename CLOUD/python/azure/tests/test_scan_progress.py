"""Progress of the long collection steps, so a 30-minute step does not look stuck."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main  # noqa: E402
import progress  # noqa: E402

from tests.fixtures import (  # noqa: E402
    MOCK_PG_SERVERS,
    MOCK_SQL_SERVERS,
    MOCK_STORAGE_ACCOUNTS,
    SUB_ID,
)
from tests.test_database import _make_collector as _database_collector  # noqa: E402
from tests.test_storage import _make_collector as _storage_collector  # noqa: E402

SUB = "00000000-0000-0000-0000-000000000000"
OTHER = "11111111-1111-1111-1111-111111111111"


@pytest.fixture(autouse=True)
def _clean():
    for sub in progress.running():
        progress.finish(sub)
    yield
    for sub in progress.running():
        progress.finish(sub)


@pytest.fixture
def counts(monkeypatch):
    """Every count a collector reports, as (subscription, done, total, unit)."""
    seen = []
    original = progress.count

    def record(sub_id, done, total, unit):
        seen.append((sub_id, done, total, unit))
        original(sub_id, done, total, unit)

    monkeypatch.setattr(progress, "count", record)
    return seen


def test_a_step_reads_as_its_name_then_with_its_count():
    progress.step(SUB, "storage")
    assert progress.describe(SUB) == "storage" and progress.counter(SUB) == ""
    progress.count(SUB, 120, 257, "accounts")
    assert progress.describe(SUB) == "storage 120/257 accounts"
    progress.finish(SUB)
    assert progress.describe(SUB) == "" and progress.running() == []


def test_every_counts_each_item_and_ends_at_the_total(counts):
    assert list(progress.every(["a", "b", "c"], SUB, "accounts")) == ["a", "b", "c"]
    assert [(done, total) for _, done, total, _ in counts] == [(0, 3), (1, 3), (2, 3), (3, 3)]


def test_storage_counts_its_accounts(counts):
    _storage_collector().collect()
    totals = {total for sub, _, total, unit in counts if unit == "accounts" and sub == SUB_ID}
    assert totals == {len(MOCK_STORAGE_ACCOUNTS)}
    assert counts[-1][1] == counts[-1][2]


def test_databases_count_their_sql_and_postgresql_servers(counts):
    _database_collector().collect()
    units = {unit: total for _, _, total, unit in counts}
    assert units["SQL servers"] == len(MOCK_SQL_SERVERS)
    assert units["PostgreSQL servers"] == len(MOCK_PG_SERVERS)


def test_one_subscription_shows_the_count_on_its_spinner():
    msg = "  [dim]Collecting storage…[/dim]"
    progress.step(SUB, "storage")
    assert main._step_text(msg, SUB) == msg
    progress.count(SUB, 120, 257, "accounts")
    assert main._step_text(msg, SUB) == "  [dim]Collecting storage… 120/257 accounts[/dim]"


def test_a_parallel_scan_says_where_each_running_subscription_is():
    progress.step(SUB, "storage")
    progress.count(SUB, 120, 257, "accounts")
    progress.step(OTHER, "databases")
    text = main._parallel_status(1, 3)
    assert text.startswith("[dim]Scanning subscriptions… 1/3 complete")
    assert "00000000…: storage 120/257 accounts" in text
    assert "11111111…: databases" in text
    progress.finish(SUB)
    progress.finish(OTHER)
    assert main._parallel_status(3, 3) == "[dim]Scanning subscriptions… 3/3 complete[/dim]"


def test_the_spinner_text_is_worked_out_again_on_every_refresh():
    state = {"n": 1}
    live = progress.Live(lambda: f"step {state['n']}")
    assert live.__rich__().plain == "step 1"
    state["n"] = 2
    assert live.__rich__().plain == "step 2"


def test_a_finished_subscription_leaves_the_progress():
    seen = []

    def collect(i, sub_id):
        progress.step(sub_id, "storage")
        return ("result", sub_id)

    main._scan_subscriptions([SUB, OTHER], collect, 1, lambda *args: seen.append(args[1]))
    assert seen == [SUB, OTHER] and progress.running() == []

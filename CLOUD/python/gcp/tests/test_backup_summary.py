"""The run summary when Backup and DR could not be read: n/a, not 0, and no coverage percentage."""

from __future__ import annotations

import main
from models.inventory import BackupPostureInventory, ComputeInventory


def _compute(n: int) -> ComputeInventory:
    return ComputeInventory(project_id="p", total_instances=n)


def _backup(protected: int, unprotected: int, *, available: bool) -> BackupPostureInventory:
    total = protected + unprotected
    return BackupPostureInventory(
        project_id="p",
        protected_instance_count=protected,
        unprotected_instance_count=unprotected,
        protection_coverage_pct=round(protected / total * 100, 1) if total else 0.0,
        available=available,
    )


def _render(summaries, errors=None) -> str:
    with main.console.capture() as captured:
        main._print_summary(summaries, errors)
    return captured.get()


def test_the_summary_of_an_unreadable_project_has_no_coverage_numbers():
    s = main._summarise_project(
        "p", {"compute": _compute(4), "backup": _backup(0, 4, available=False)}
    )
    assert s["coverage_pct"] is None and s["protected"] is None
    assert s["coverage_unavailable"] is True
    assert s["instances_for_coverage"] == 0


def test_the_summary_of_a_readable_project_is_unchanged():
    s = main._summarise_project(
        "p", {"compute": _compute(10), "backup": _backup(5, 5, available=True)}
    )
    assert (s["protected"], s["coverage_pct"], s["instances_for_coverage"]) == (5, 50.0, 10)
    assert s["coverage_unavailable"] is False


def test_a_project_without_the_backup_collector_is_still_dash_not_n_a():
    s = main._summarise_project("p", {"compute": _compute(3)})
    assert s["coverage_pct"] is None and s["coverage_unavailable"] is False


def test_the_table_shows_n_a_and_leaves_the_project_out_of_the_total():
    readable = main._summarise_project(
        "good", {"compute": _compute(10), "backup": _backup(5, 5, available=True)}
    )
    unreadable = main._summarise_project(
        "bad", {"compute": _compute(4), "backup": _backup(0, 4, available=False)}
    )
    text = _render([readable, unreadable], [{"project_id": "bad", "category": "API_DISABLED"}])
    bad_row = next(line for line in text.splitlines() if "bad" in line)
    assert "n/a" in bad_row and "%" not in bad_row
    total_row = next(line for line in text.splitlines() if "TOTAL" in line)
    assert total_row.split("\u2502")[-2].strip() == "5"  # Protected: the readable project's 5
    assert "Protected is n/a for 1 project(s)" in " ".join(text.split())


def test_the_table_has_no_coverage_column_or_percentage():
    readable = main._summarise_project(
        "good", {"compute": _compute(10), "backup": _backup(5, 5, available=True)}
    )
    text = _render([readable])
    assert "Coverage" not in text and "%" not in text
    assert "Protected" in text


def test_the_total_is_n_a_when_no_project_could_be_read():
    unreadable = main._summarise_project(
        "bad", {"compute": _compute(4), "backup": _backup(0, 4, available=False)}
    )
    text = _render([unreadable], [{"project_id": "bad", "category": "API_DISABLED"}])
    total_row = next(line for line in text.splitlines() if "TOTAL" in line)
    assert total_row.split("\u2502")[-2].strip() == "n/a" and "%" not in total_row


def test_the_flag_is_written_to_the_json():
    import dataclasses

    assert dataclasses.asdict(_backup(0, 1, available=False))["available"] is False
    assert dataclasses.asdict(_backup(1, 0, available=True))["available"] is True

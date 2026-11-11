"""Tests for parallel subscription scanning (--workers) in main.py."""

from __future__ import annotations

import io
import logging
import threading
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import MagicMock

import pytest
from rich.console import Console

import main
from main import (
    DEFAULT_WORKERS,
    _apply_config_defaults,
    _BufferedOutput,
    _build_parser,
    _collect_all,
    _collect_subscription,
    _drop_failed,
    _resolve_workers,
    _scan_subscriptions,
)

WAIT = 5  # seconds; only reached if ordering logic deadlocks


def _args(argv):
    return _build_parser().parse_args(argv)


def _fake_result(sub_id: str) -> tuple:
    return tuple(
        f"{kind}:{sub_id}" for kind in ("comp", "bp", "stor", "db", "jobs", "cost")
    )


@pytest.fixture
def captured_console(monkeypatch):
    buf = io.StringIO()
    con = Console(file=buf, width=120, force_terminal=False, color_system=None)
    monkeypatch.setattr(main, "console", con)
    return buf


class TestScanSubscriptions:
    def test_results_keep_input_order_despite_out_of_order_completion(self):
        subs = ["a", "b", "c"]
        c_done, b_done = threading.Event(), threading.Event()
        completion: list[str] = []
        lock = threading.Lock()

        def collect(i, sub_id):
            # c finishes first, then b, then a: the reverse of input order.
            if sub_id == "a":
                assert b_done.wait(WAIT)
            elif sub_id == "b":
                assert c_done.wait(WAIT)
            with lock:
                completion.append(sub_id)
            if sub_id == "c":
                c_done.set()
            elif sub_id == "b":
                b_done.set()
            return _fake_result(sub_id)

        results, errors = _scan_subscriptions(subs, collect, workers=3)

        assert completion == ["c", "b", "a"]
        assert errors == {}
        assert results == [_fake_result(s) for s in subs]

    def test_on_done_runs_in_the_calling_thread(self):
        seen: list[int] = []
        _scan_subscriptions(
            ["a", "b", "c"],
            lambda i, s: _fake_result(s),
            workers=3,
            on_done=lambda i, s, r, e: seen.append(threading.get_ident()),
        )
        assert seen == [threading.get_ident()] * 3

    @pytest.mark.parametrize("workers", [1, 3])
    def test_failing_subscription_is_isolated_and_reported(self, workers, caplog):
        subs = ["a", "boom", "c"]
        done: list[tuple] = []

        def collect(i, sub_id):
            if sub_id == "boom":
                raise RuntimeError("AuthorizationFailed")
            return _fake_result(sub_id)

        with caplog.at_level(logging.ERROR, logger="main"):
            results, errors = _scan_subscriptions(
                subs,
                collect,
                workers,
                on_done=lambda i, s, r, e: done.append((i, s, e)),
            )

        assert results == [_fake_result("a"), None, _fake_result("c")]
        assert list(errors) == [1]
        assert isinstance(errors[1], RuntimeError)
        assert any(
            "boom" in r.getMessage() and "AuthorizationFailed" in r.getMessage()
            for r in caplog.records
        )
        assert sorted(done, key=lambda d: d[0])[1][2] is errors[1]
        assert len(done) == 3

    def test_workers_one_is_serial_in_input_order_on_the_calling_thread(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            main,
            "ThreadPoolExecutor",
            MagicMock(side_effect=AssertionError("pool used")),
        )
        calls: list[tuple[int, str, int]] = []

        def collect(i, sub_id):
            calls.append((i, sub_id, threading.get_ident()))
            return _fake_result(sub_id)

        results, errors = _scan_subscriptions(["a", "b", "c"], collect, workers=1)

        assert calls == [(i, s, threading.get_ident()) for i, s in enumerate("abc")]
        assert results == [_fake_result(s) for s in "abc"]
        assert errors == {}

    def test_serial_and_parallel_results_are_identical(self):
        subs = [f"sub-{n}" for n in range(8)]
        serial = _scan_subscriptions(subs, lambda i, s: _fake_result(s), workers=1)
        parallel = _scan_subscriptions(subs, lambda i, s: _fake_result(s), workers=4)
        assert serial == parallel

    def test_empty_subscription_list(self):
        assert _scan_subscriptions([], lambda i, s: _fake_result(s), workers=4) == (
            [],
            {},
        )


class TestDropFailed:
    def test_lists_stay_aligned_with_subscriptions(self):
        subs = ["a", "b", "c"]
        scanned = [_fake_result("a"), None, _fake_result("c")]
        kept_subs, lists = _drop_failed(subs, scanned, {1: RuntimeError("x")})
        assert kept_subs == ["a", "c"]
        assert len(lists) == 6
        for kind, lst in zip(("comp", "bp", "stor", "db", "jobs", "cost"), lists):
            assert lst == [f"{kind}:a", f"{kind}:c"]

    def test_no_failures_is_a_no_op(self):
        subs = ["a", "b"]
        scanned = [_fake_result(s) for s in subs]
        kept_subs, lists = _drop_failed(subs, scanned, {})
        assert kept_subs == subs
        assert lists[0] == ["comp:a", "comp:b"]


class TestCollectAll:
    def _patch_collect(self, monkeypatch, *, fail=()):
        def fake(sub_id, credential, regions, cloud, scans=None, out=None, skips=frozenset()):
            sink = out if out is not None else main.console
            sink.print(f"  ok line 1 for {sub_id}")
            if sub_id in fail:
                raise RuntimeError(f"cannot read {sub_id}")
            sink.print(f"  ok line 2 for {sub_id}")
            return _fake_result(sub_id)

        monkeypatch.setattr(main, "_collect_subscription", fake)

    def test_parallel_blocks_are_atomic_and_prefixed(
        self, monkeypatch, captured_console
    ):
        self._patch_collect(monkeypatch)
        subs = ["sub-a", "sub-b", "sub-c"]

        results, errors = _collect_all(subs, object(), None, None, {}, workers=3)

        assert results == [_fake_result(s) for s in subs]
        assert errors == {}
        lines = captured_console.getvalue().splitlines()
        for n, sub in enumerate(subs, 1):
            at = lines.index(f"[{n}/3] {sub}")
            assert lines[at + 1] == f"  ok line 1 for {sub}"
            assert lines[at + 2] == f"  ok line 2 for {sub}"

    def test_parallel_failure_prints_partial_output_then_the_error(
        self, monkeypatch, captured_console
    ):
        self._patch_collect(monkeypatch, fail={"sub-b"})
        results, errors = _collect_all(
            ["sub-a", "sub-b", "sub-c"], object(), None, None, {}, workers=3
        )

        assert results[1] is None and results[0] and results[2]
        assert list(errors) == [1]
        out = captured_console.getvalue()
        assert "ok line 1 for sub-b" in out
        assert "ok line 2 for sub-b" not in out
        assert "sub-b failed and was skipped" in out
        assert "cannot read sub-b" in out

    def test_serial_keeps_the_original_header_and_inline_output(
        self, monkeypatch, captured_console
    ):
        self._patch_collect(monkeypatch)
        _collect_all(["sub-a", "sub-b"], object(), None, None, {}, workers=1)
        assert captured_console.getvalue().splitlines() == [
            "[1/2] sub-a",
            "  ok line 1 for sub-a",
            "  ok line 2 for sub-a",
            "",
            "[2/2] sub-b",
            "  ok line 1 for sub-b",
            "  ok line 2 for sub-b",
            "",
        ]

    def test_single_subscription_uses_the_serial_path_even_with_many_workers(
        self, monkeypatch, captured_console
    ):
        monkeypatch.setattr(
            main,
            "ThreadPoolExecutor",
            MagicMock(side_effect=AssertionError("pool used")),
        )
        self._patch_collect(monkeypatch)
        results, _ = _collect_all(["only"], object(), None, None, {}, workers=8)
        assert results == [_fake_result("only")]
        assert "Scanning 1 subscriptions" not in captured_console.getvalue()

    def test_workers_are_capped_at_the_subscription_count(
        self, monkeypatch, captured_console
    ):
        self._patch_collect(monkeypatch)
        _collect_all(["a", "b"], object(), None, None, {}, workers=16)
        assert "2 in parallel" in captured_console.getvalue()


class TestCollectSubscriptionOutput:
    @pytest.fixture
    def fake_collectors(self, monkeypatch):
        def fake_cls(result):
            return lambda *a, **k: SimpleNamespace(collect=lambda: result)

        comp = SimpleNamespace(total_sql_vms=0, total_vms=2, total_disk_tb=1.5, vms=[])
        bp = SimpleNamespace(
            protection_coverage_pct=90, vault_count=1, unprotected_vm_count=0
        )
        stor = SimpleNamespace(
            soft_delete_coverage_pct=90, total_capacity_gb=10.0, total_accounts=1
        )
        db = SimpleNamespace(total_sql_databases=1, total_flexible_servers=0)
        monkeypatch.setattr("collectors.compute.ComputeCollector", fake_cls(comp))
        monkeypatch.setattr(
            "collectors.backup_posture.BackupPostureCollector", fake_cls(bp)
        )
        monkeypatch.setattr("collectors.storage.StorageCollector", fake_cls(stor))
        monkeypatch.setattr("collectors.database.DatabaseCollector", fake_cls(db))

    SCANS: ClassVar[dict[str, bool]] = {"backup_jobs": False, "cost": False}

    def test_buffered_output_never_touches_the_console_or_starts_a_spinner(
        self, monkeypatch, fake_collectors
    ):
        con = MagicMock()
        monkeypatch.setattr(main, "console", con)
        out = _BufferedOutput()

        _collect_subscription("sub", object(), None, scans=self.SCANS, out=out)

        con.status.assert_not_called()
        con.print.assert_not_called()
        assert len(out._calls) == 6

    def test_default_output_uses_spinners_and_the_console(
        self, monkeypatch, fake_collectors
    ):
        con = MagicMock()
        monkeypatch.setattr(main, "console", con)

        _collect_subscription("sub", object(), None, scans=self.SCANS)

        assert con.status.call_count == 4
        assert con.print.call_count == 6

    def test_replay_matches_direct_output(self, monkeypatch, fake_collectors):
        direct, replayed = io.StringIO(), io.StringIO()
        mk = lambda f: Console(
            file=f, width=120, force_terminal=False, color_system=None
        )

        monkeypatch.setattr(main, "console", mk(direct))
        _collect_subscription("sub", object(), None, scans=self.SCANS)

        out = _BufferedOutput()
        _collect_subscription("sub", object(), None, scans=self.SCANS, out=out)
        out.replay(mk(replayed))

        assert replayed.getvalue() == direct.getvalue()

    def test_the_scan_lines_show_counts_not_percentages(self, monkeypatch, fake_collectors):
        buf = io.StringIO()
        monkeypatch.setattr(
            main, "console", Console(file=buf, width=120, force_terminal=False, color_system=None)
        )
        _collect_subscription("sub", object(), None, scans=self.SCANS)
        text = buf.getvalue()
        assert "1 vaults \u00b7 0 unprotected VMs" in text
        assert "1 accounts \u00b7 10.0 GB" in text
        assert "%" not in text and "coverage" not in text and "soft delete" not in text

    def test_the_summary_table_has_counts_and_no_coverage_column(self, monkeypatch):
        buf = io.StringIO()
        monkeypatch.setattr(
            main, "console", Console(file=buf, width=120, force_terminal=False, color_system=None)
        )
        comps = [SimpleNamespace(total_vms=n, total_disk_tb=1.0) for n in (4, 0)]
        bps = [
            SimpleNamespace(
                subscription_id=f"sub-{i}", total_vm_count=n, unprotected_vm_count=u, vault_count=1
            )
            for i, (n, u) in enumerate([(4, 1), (0, 0)])
        ]
        main._print_summary(comps, bps)
        text = buf.getvalue()
        assert "Protected" in text and "Unprotected" in text and "TOTAL" in text
        assert "Coverage" not in text and "%" not in text


class TestWorkersPrecedence:
    def test_default(self):
        assert DEFAULT_WORKERS == 4
        assert _resolve_workers(_args([])) == DEFAULT_WORKERS

    def test_flag(self):
        assert _resolve_workers(_args(["--workers", "7"])) == 7

    def test_config_applies_when_flag_absent(self, tmp_path):
        cfg = tmp_path / "rubrik.yaml"
        cfg.write_text("discovery:\n  workers: 6\n")
        args = _args(["--config", str(cfg)])
        _apply_config_defaults(args)
        assert _resolve_workers(args) == 6

    def test_flag_beats_config(self, tmp_path):
        cfg = tmp_path / "rubrik.yaml"
        cfg.write_text("discovery:\n  workers: 6\n")
        args = _args(["--config", str(cfg), "--workers", "2"])
        _apply_config_defaults(args)
        assert _resolve_workers(args) == 2

    def test_flag_of_one_beats_config(self, tmp_path):
        cfg = tmp_path / "rubrik.yaml"
        cfg.write_text("discovery:\n  workers: 6\n")
        args = _args(["--config", str(cfg), "--workers", "1"])
        _apply_config_defaults(args)
        assert _resolve_workers(args) == 1

    def test_config_without_workers_keeps_default(self, tmp_path):
        cfg = tmp_path / "rubrik.yaml"
        cfg.write_text("discovery:\n  verbose: true\n")
        args = _args(["--config", str(cfg)])
        _apply_config_defaults(args)
        assert _resolve_workers(args) == DEFAULT_WORKERS

    @pytest.mark.parametrize("bad", ["0", "-2", "many"])
    def test_invalid_flag_is_rejected(self, bad):
        with pytest.raises(SystemExit):
            _args(["--workers", bad])

    def test_invalid_config_value_is_rejected(self, tmp_path):
        cfg = tmp_path / "rubrik.yaml"
        cfg.write_text("discovery:\n  workers: 0\n")
        with pytest.raises(SystemExit):
            _apply_config_defaults(_args(["--config", str(cfg)]))

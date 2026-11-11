"""Mock mode must not try to reach real services."""

from __future__ import annotations

import sys


def test_mock_run_does_not_attempt_devops_discovery(tmp_path, monkeypatch, capsys):
    import main
    from collectors import devops

    constructed = []

    def fail_if_built(*args, **kwargs):
        constructed.append(1)
        raise RuntimeError("DevOps collector must not run in mock mode")

    monkeypatch.setattr(devops, "DevOpsCollector", fail_if_built)
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path)])

    main.main()

    assert constructed == []
    assert "DevOps discovery skipped" not in capsys.readouterr().out
    assert list(tmp_path.glob("azure_sizing_results_*.zip"))

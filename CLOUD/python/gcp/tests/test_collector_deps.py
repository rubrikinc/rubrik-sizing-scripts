"""Regression guard: every client library a collector imports must be installed.

Collectors import their Google client libraries lazily (deferred `import` inside
the collect method) so the package stays importable without the full SDK, and so
a missing/disabled API degrades gracefully at runtime. The downside is that a
*packaging* bug — a client library missing from pyproject/requirements — is
invisible to the mocked unit suite and only surfaces as a silent
``cannot import name 'backupdr_v1'`` warning on a live customer run (the
google-cloud-backupdr / google-cloud-alloydb omission that shipped in 0.1.0).

This test forces each deferred import to actually resolve, so an absent
dependency fails CI here instead of on a customer's console. Keep it in sync
with the `from google.cloud import ...` / `import googleapiclient` lines in
collectors/.
"""

from __future__ import annotations

import importlib

import pytest

# (import path, distribution that provides it) for every deferred import in
# collectors/. The distribution name is only for the failure hint.
DEFERRED_COLLECTOR_IMPORTS = [
    ("google.cloud.asset_v1", "google-cloud-asset"),
    ("google.cloud.compute_v1", "google-cloud-compute"),
    ("google.cloud.storage", "google-cloud-storage"),
    ("google.cloud.monitoring_v3", "google-cloud-monitoring"),
    ("google.cloud.backupdr_v1", "google-cloud-backupdr"),
    ("google.cloud.spanner_admin_instance_v1", "google-cloud-spanner"),
    ("google.cloud.spanner_admin_database_v1", "google-cloud-spanner"),
    ("google.cloud.bigtable", "google-cloud-bigtable"),
    ("google.cloud.alloydb_v1", "google-cloud-alloydb"),
    ("googleapiclient.discovery", "google-api-python-client"),
]


@pytest.mark.parametrize("module_path,distribution", DEFERRED_COLLECTOR_IMPORTS)
def test_deferred_collector_import_resolves(module_path: str, distribution: str) -> None:
    try:
        importlib.import_module(module_path)
    except ImportError as exc:  # pragma: no cover - the failure path is the point
        pytest.fail(
            f"Collector deferred import '{module_path}' failed: {exc}. "
            f"Add '{distribution}' to gcp/pyproject.toml (and requirements.txt). "
            "A missing client library degrades silently on a live run."
        )


# Core collectors (Cloud SQL via googleapiclient, Spanner) must install with the base
# package, not only with the `databases` extra: a plain wheel install has no extras.
CORE_DISTRIBUTIONS = ["google-cloud-spanner", "google-api-python-client"]


def _pyproject() -> dict:
    import pathlib

    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python 3.10
        tomllib = pytest.importorskip("tomli")
    path = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _names(requirements: list[str]) -> set[str]:
    import re

    return {re.split(r"[<>=!~\[ ;]", r, maxsplit=1)[0].lower() for r in requirements}


@pytest.mark.parametrize("distribution", CORE_DISTRIBUTIONS)
def test_core_database_clients_are_base_dependencies(distribution: str) -> None:
    deps = _pyproject()["project"]["dependencies"]
    assert distribution in _names(deps), (
        f"'{distribution}' must be a base dependency in gcp/pyproject.toml, "
        "not only in the 'databases' extra, or the Cloud SQL/Spanner collectors fail "
        "with SDK_MISSING on a plain install."
    )


def test_core_database_clients_are_in_requirements_txt() -> None:
    import pathlib

    text = (pathlib.Path(__file__).resolve().parent.parent / "requirements.txt").read_text()
    names = _names([ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")])
    assert set(CORE_DISTRIBUTIONS) <= names

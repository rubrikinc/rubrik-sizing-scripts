#!/usr/bin/env python3
"""Rubrik Discovery — GCP Edition

Lightweight GCP inventory + backup posture assessment for Rubrik SE
conversations.  Run it from Google Cloud Shell, a GCE VM with Workload
Identity, or any machine with ``gcloud auth application-default login`` active.

Usage examples:
    # All accessible projects (default)
    python main.py

    # Specific project IDs
    python main.py --projects my-project-1,my-project-2

    # Project IDs from a file, one per line
    python main.py --project-file projects.txt

    # Only the project from gcloud config / ADC default
    python main.py --current-project

    # Org-scale run: org-wide asset spine (one CAI sweep) + more parallelism
    python main.py --org 123456789012 --workers 24

    # All projects, filtered to specific regions
    python main.py --regions us-central1,us-east1

    # Offline demo with mock data (no GCP credentials needed)
    python main.py --mock

    # Preview scope without running collectors
    python main.py --dry-run

    # Debug logging
    python main.py --verbose
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import pathlib
import sys
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from models.inventory import DiscoveryResult

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

import checkpoint_core
import manifest_core
import preflight
import preflight_core
import resume
import runlog
import totals
from anonymize import KEY_FILE_PREFIX, Anonymizer, anonymized_log_note

console = runlog.LoggedConsole(width=max(120, Console().width))

logger = logging.getLogger(__name__)

# Above this many projects, stream the JSON output to disk one project at a time
# (bounded memory) instead of building one in-memory DiscoveryResult.
_STREAMING_THRESHOLD = 50

# Core collectors, in run order. Selectable via --collectors; default is all.
# "asset" is the Cloud Asset Inventory breadth spine; the rest add per-service
# sizing depth. Optional add-ons (cost/iac/filestore/security) are gated separately.
_CORE_COLLECTORS = ["asset", "compute", "storage", "database", "bigquery", "backup"]

# Days of Cloud Monitoring history a bucket's growth is measured over. Cloud Storage metrics are
# kept for 24 months; the cap keeps one project's response well inside Monitoring's 200 MB limit.
_DEFAULT_GROWTH_DAYS = 30
_MAX_GROWTH_DAYS = 365

_DRY_RUN_API_CALLS = [
    (
        "asset",
        "AssetServiceClient.list_assets()",
        "roles/cloudasset.viewer",
        "Enumerate all resources",
    ),
    ("compute", "InstancesClient.aggregated_list()", "roles/compute.viewer", "GCE instances"),
    ("compute", "DisksClient.aggregated_list()", "roles/compute.viewer", "GCE persistent disks"),
    (
        "storage",
        "storage.Client.list_buckets()",
        "roles/storage.viewer",
        "GCS bucket metadata",
    ),
    (
        "storage",
        "MetricServiceClient.list_time_series()",
        "roles/monitoring.viewer",
        "GCS bucket sizes and object counts",
    ),
    ("database", "sqladmin.instances.list()", "roles/cloudsql.viewer", "Cloud SQL instances"),
    (
        "database",
        "InstanceAdminClient.list_instances()",
        "roles/spanner.viewer",
        "Cloud Spanner instances",
    ),
    ("database", "AlloyDBAdminClient.list_clusters()", "roles/alloydb.viewer", "AlloyDB clusters"),
    ("database", "bigtable.Client.list_instances()", "roles/bigtable.viewer", "Bigtable instances"),
    (
        "bigquery",
        "bigquery.datasets.list() / datasets.get()",
        "roles/bigquery.metadataViewer",
        "BigQuery datasets",
    ),
    (
        "bigquery",
        "bigquery.tables.list() / tables.get()",
        "roles/bigquery.metadataViewer",
        "BigQuery tables, views and their sizes",
    ),
    (
        "backup",
        "BackupDRClient.list_backup_plans()",
        "roles/backupdr.viewer",
        "Backup and DR plans",
    ),
    (
        "backup",
        "BackupDRClient.list_backup_plan_associations()",
        "roles/backupdr.viewer",
        "Protected workloads",
    ),
]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rubrik-gcp-discovery",
        description="Rubrik Discovery — GCP Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--config",
        action="append",
        type=pathlib.Path,
        metavar="FILE",
        help="Path to rubrik.yaml (see docs/config_schema.md).  Pass twice "
        "for base + overlay.  Values from the config are overridden "
        "by explicit flags.",
    )
    scope = p.add_mutually_exclusive_group()
    scope.add_argument(
        "--projects",
        metavar="ID,...",
        help="Comma-separated project IDs to scan",
    )
    scope.add_argument(
        "--project-file",
        metavar="FILE",
        type=pathlib.Path,
        help="File with one project ID per line (blank lines and # comments ignored)",
    )
    scope.add_argument(
        "--current-project",
        action="store_true",
        help="Scan only the project from gcloud config / ADC default "
        "(default: all accessible projects)",
    )
    scope.add_argument(
        "--all",
        action="store_true",
        help="Scan all accessible projects (this is the default; kept for compatibility)",
    )
    p.add_argument(
        "--include-system-projects",
        action="store_true",
        help="Also scan Google's auto-created sys-<number> projects when discovering all "
        "projects (default: left out; they hold nothing to size). Has no effect with "
        "--projects or --project-file, which scan what they name.",
    )
    p.add_argument(
        "--regions",
        metavar="REGION,...",
        help="Comma-separated regions to include (default: all)",
    )
    p.add_argument(
        "--workers",
        type=int,
        metavar="N",
        help="Parallel project-collection threads (default: 8). Raise for "
        "org-scale runs with many projects.",
    )
    p.add_argument(
        "--org",
        dest="org_id",
        metavar="ORG_ID",
        help="Organization ID (e.g. 123456789012). Enables the org-wide Cloud "
        "Asset Inventory spine: one paginated sweep enumerates assets for all "
        "projects instead of one list_assets call per project.",
    )
    p.add_argument(
        "--folder",
        dest="folder_id",
        metavar="FOLDER_ID",
        help="Folder ID to scope the org-wide asset spine (alternative to --org).",
    )
    p.add_argument(
        "--output",
        metavar="DIR",
        help="Output directory for JSON discovery file (default: ~/ or ./output)",
    )
    p.add_argument(
        "--mock",
        action="store_true",
        help="Run with built-in mock data — no GCP credentials required",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Preview scope + GCP APIs that would be called, then exit.  "
        "No collection is performed.  Safe to show a security team before "
        "approving a real run.",
    )
    p.add_argument(
        "--security",
        action="store_true",
        help="Enable Security Command Center findings collection "
        "(requires roles/securitycenter.findingsViewer at org level).",
    )
    depth = p.add_mutually_exclusive_group()
    depth.add_argument(
        "--collectors",
        metavar="LIST",
        help="Comma-separated subset of core collectors to run "
        f"(choices: {','.join(_CORE_COLLECTORS)}; default: all). "
        "e.g. --collectors asset,compute,storage",
    )
    depth.add_argument(
        "--inventory-only",
        action="store_true",
        help="Breadth scan only: run just the Cloud Asset Inventory spine "
        "(equivalent to --collectors asset). Minimal API enablement; no per-service "
        "sizing depth.",
    )
    p.add_argument(
        "--anonymize",
        action="store_true",
        help="Anonymize names, ids and labels in the CSV files (PowerShell's -Anonymize). The ZIP "
        "then has no raw JSON; the file that maps the labels back to the real values and the real "
        "run log are written next to the ZIP, not into it.",
    )
    p.add_argument(
        "--anonymize-fields",
        default="",
        metavar="FIELDS",
        help="Comma-separated extra fields to anonymize (with --anonymize). "
        "Same as PowerShell -AnonymizeFields.",
    )
    p.add_argument(
        "--not-anonymize-fields",
        default="",
        metavar="FIELDS",
        help="Comma-separated fields to leave as they are (with --anonymize); 'Tags' leaves all "
        "label columns alone. Same as PowerShell -NotAnonymizeFields.",
    )
    p.add_argument(
        "--no-csv",
        action="store_true",
        help="Write only the JSON. By default the ZIP also holds the PowerShell-style CSV files "
        "that Get-GCPSizingInfo.ps1 writes.",
    )
    p.add_argument(
        "--growth-days",
        type=int,
        default=None,
        metavar="N",
        help="Days of Cloud Monitoring history to measure each Cloud Storage bucket's growth "
        f"over (default: {_DEFAULT_GROWTH_DAYS}, at most {_MAX_GROWTH_DAYS}). Costs one extra "
        "Monitoring query per project. A bucket younger than this is measured over its own age.",
    )
    p.add_argument(
        "--no-growth",
        action="store_true",
        help="Do not measure bucket growth: skip the extra Monitoring query and leave the growth "
        "columns of gce_storage_info blank.",
    )
    p.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip the pre-flight access check that runs before the scan. The check makes one "
        "read-only call per service in each project and writes "
        "gcp_preflight_check-<timestamp>.csv, which lists what will be captured and what "
        "will be dropped.",
    )
    p.add_argument(
        "--no-sdk-check",
        action="store_true",
        help="Do not stop at the start when a Google library the chosen collectors need is not "
        "installed. Those collectors then fail in every project and their data is missing.",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Do not ask before scanning when the access check shows the quota project cannot "
        "serve the calls (API or billing off, or denied). Runs without a terminal never ask.",
    )
    p.add_argument(
        "--preflight-only",
        action="store_true",
        help="Only run the access check: resolve the projects, check what the sign-in can read "
        "in each, write gcp_preflight_check-<timestamp>.csv into "
        "gcp_access_check_<timestamp>.zip and stop. Nothing is collected. A project named with "
        "--projects or --project-file that cannot be read gets a row of its own.",
    )
    resume_group = p.add_mutually_exclusive_group()
    resume_group.add_argument(
        "--resume",
        action="store_true",
        help="Carry on with the unfinished run in the output folder: projects it finished are not "
        "scanned again. Needs the same options as that run. Without --resume or --fresh, a "
        "terminal is asked what to do; a run with no terminal stops until one is given.",
    )
    resume_group.add_argument(
        "--fresh",
        action="store_true",
        help="Delete the unfinished run in the output folder and scan everything again.",
    )
    p.add_argument(
        "--keep-partial",
        action="store_true",
        help="With --resume, keep the projects the earlier run finished with errors (an API off, a "
        "permission missing, a time limit reached), instead of scanning them again (the default). "
        "The zip then holds them with their gaps.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Show SE-focused terminal output + debug logging from collectors.",
    )
    return p


def _resolve_growth_days(args: argparse.Namespace, selected: set[str]) -> Optional[int]:
    """The days to measure bucket growth over, or None when growth is off for this run.

    Growth rides on the storage collector, so it is off when that collector is not running.
    """
    if args.no_growth or "storage" not in selected:
        return None
    return args.growth_days or _DEFAULT_GROWTH_DAYS


def _parse_csv(value: Optional[str]) -> Optional[list[str]]:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def _read_project_file(path: pathlib.Path) -> list[str]:
    """Project IDs from a newline-separated file; blanks and ``#`` comments skipped."""
    try:
        lines = path.expanduser().read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SystemExit(f"Cannot read project file {path}: {exc}")
    ids: list[str] = []
    for line in lines:
        pid = line.strip()
        if pid and not pid.startswith("#") and pid not in ids:
            ids.append(pid)
    if not ids:
        raise SystemExit(f"Project file {path} contains no project IDs.")
    return ids


def _current_project_only(args, cfg) -> bool:
    """True to scan only the current project.

    CLI flags win. Otherwise an explicit ``scope.all`` / ``scope.all_projects`` in the config
    file decides, so a config that says ``all_projects: false`` keeps its meaning. With
    neither, the default is all accessible projects.
    """
    if args.current_project:
        return True
    if args.all or args.projects or args.project_file:
        return False
    scope = cfg.scope
    if scope.all is not None or "all_projects" in scope.model_fields_set:
        return not scope.effective_all_projects()
    return False


def _resolve_collectors(args) -> set[str]:
    """Resolve which core collectors to run from --collectors / --inventory-only.

    Default (neither flag) = all core collectors (full depth). ``--inventory-only``
    is sugar for the CAI breadth spine alone. Unknown names raise SystemExit.
    """
    if getattr(args, "inventory_only", False):
        return {"asset"}
    raw = _parse_csv(args.collectors)
    if not raw:
        return set(_CORE_COLLECTORS)
    selected = {name.lower() for name in raw}
    unknown = selected - set(_CORE_COLLECTORS)
    if unknown:
        raise SystemExit(
            f"Unknown collector(s): {','.join(sorted(unknown))}. "
            f"Valid choices: {','.join(_CORE_COLLECTORS)}."
        )
    return selected


def _resolve_output_dir(override: Optional[str]) -> pathlib.Path:
    """Return the output directory, creating it if necessary.

    Priority: explicit --output flag > ~/ (Cloud Shell home) > ./output.
    """
    if override:
        path = pathlib.Path(override).expanduser()
    else:
        path = pathlib.Path("./output")

    path.mkdir(parents=True, exist_ok=True)
    return path


def _configure_logging(verbose: bool) -> None:
    # Thin wrapper around the shared per-tool convention (see logging_setup.py).
    from logging_setup import setup_logging

    setup_logging(verbose=verbose)


def _start_run_log() -> tuple[logging.Handler, str]:
    """Begin the run log: a transcript of the screen, in a temp file.

    Independent of --verbose (which only gates the console); the file is bundled
    into the result ZIP so the SE can debug a failed or partial scan.
    """
    from logging_setup import add_log_file

    fd, tmp = tempfile.mkstemp(prefix="gcp-sizing-run-", suffix=".log")
    os.close(fd)
    return add_log_file(tmp), tmp


def _run_access_check(
    projects: list[str], credentials, selected: set[str], workers: int
) -> list[dict]:
    """Check what the sign-in can read in each project, print the result, return its rows.

    A blocked service is one line that lists the projects it affects, however many there are. A
    refusal by the quota project (the project every call is charged to) is reported once, not
    per project, and its rows say "could not be checked" rather than "not enabled".
    """
    import auth

    quota_project, quota_source = auth.effective_quota_project(credentials)
    console.print(f"[dim]{escape(runlog.quota_source_line(quota_project, quota_source))}[/dim]")
    with console.status("[bold]Checking access…[/bold]"):
        per_project = preflight.run_all(projects, credentials, selected, workers)
    checks = preflight.attribute(
        [check for project_checks in per_project for check in project_checks], quota_project
    )
    if not checks:
        return []
    label = f"{len(projects)} project(s)"
    headline = preflight.report_lines(checks, label)[0]
    console.print(f"[dim]{escape(headline)}[/dim]")
    for line in preflight.table_lines(checks):
        console.print(escape(line))
    quota = preflight.quota_problems(checks)
    if quota:
        console.print("  [yellow]⚠[/yellow] The quota project blocked the check:")
        for line in runlog.quota_block(quota, len(projects), quota_source):
            console.print(escape(line))
    blocked = preflight.project_groups(checks)
    if blocked:
        console.print("  [yellow]⚠[/yellow] Problems found by the pre-flight check:")
        for line in runlog.problem_block(blocked):
            console.print(escape(line))
    console.print()
    return [check.to_row() for check in checks]


def _scope_for_manifest(facts) -> Optional[dict]:
    """The scope record of ``manifest.json``: the mode and counts, never a project name.

    The manifest is safe in an anonymized run, so it holds no IDs and no account.  ``facts`` is
    ``auth.ScopeFacts``, or None for a mock run, which has no scope to report.
    """
    if facts is None:
        return None
    return {
        "mode": facts.mode,
        "scanned": facts.scanned,
        "named": facts.named,
        "left_out_system_projects": facts.left_out_system,
        # None means "not looked up or the lookup failed", which is not the same as 0.
        "other_visible_projects": facts.visible_not_scanned,
    }


def _require_sdks(selected: set[str], log_handler: logging.Handler, log_tmp: str) -> None:
    """Exit with the install command when a library the chosen collectors need is missing.

    The message is on the screen in full, so the run log is not kept (as for a bad option).
    """
    missing = preflight.missing_sdks(selected)
    if not missing:
        return
    console.print("[red]Cannot start:[/red] " + escape(preflight.sdk_problem_lines(missing)[0]))
    for line in preflight.sdk_problem_lines(missing)[1:]:
        console.print(escape(line))
    _discard_run_log(log_handler, log_tmp)
    sys.exit(2)


def _confirm_quota_project(access_rows: list[dict], assume_yes: bool = False) -> None:
    """Stop and ask before scanning when the quota project cannot serve the calls.

    Every call is charged to the quota project, so when it has an API or billing off (or refuses
    the sign-in) the same calls will fail in every project and the results will be mostly empty.
    At a terminal the user chooses; ``--yes`` and runs with no terminal carry on, as before, with
    the warning already printed by the access check.
    """
    blocked = preflight.quota_blocking_rows(access_rows)
    if not blocked or assume_yes:
        return
    services = sorted({row.get("Service", "") for row in blocked})
    projects = {row.get("Owner") for row in blocked}
    interactive = sys.stdin is not None and sys.stdin.isatty() and sys.stdout.isatty()
    logger.warning(
        "The quota project cannot serve %d service(s) in %d project(s): %s",
        len(services),
        len(projects),
        ", ".join(services),
    )
    if not interactive:
        console.print(
            "[yellow]No terminal to ask on: continuing. Those services will be missing from the "
            "results; pass --yes to silence this.[/yellow]"
        )
        return
    console.print(
        f"\n[yellow]The quota project cannot serve {escape(', '.join(services))} "
        f"({len(projects)} project(s) affected).[/yellow] Scanning now will leave those out of "
        "the results. The fix is above."
    )
    try:
        answer = input("Continue anyway? [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    if answer not in ("y", "yes"):
        logger.warning("Stopped by the user at the quota project question.")
        console.print("Stopped. Fix the quota project and run again.")
        runlog.core.end_run(
            "stopped by the user at the quota project question",
            ["Nothing was scanned and no results zip was written."],
        )
        sys.exit(1)


def _manifest_text(files: dict, scope: Optional[dict] = None) -> Optional[str]:
    """The manifest.json of a results zip, or None when it could not be built.

    ``files`` maps each file name in the zip to its text or bytes. Never raises: a problem with the
    manifest must not cost the zip, so it is only logged.
    """
    try:
        return manifest_core.build(
            files,
            tool="gcp",
            tool_version=manifest_core.installed_version("rubrik-discovery-gcp"),
            code_version=runlog.core.code_version(runlog.HERE),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            scope=scope,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not build %s: %s", manifest_core.FILE_NAME, exc)
        return None


# The end of a run names this many projects that were not scanned; the CSV has all of them.
_NOT_SCANNED_SHOWN = 20


def _print_not_scanned(not_scanned: list[dict], heading: str) -> None:
    """Each project that is not in the results and why, on the screen and in the log."""
    if not not_scanned:
        return
    console.print()
    console.print(f"[yellow]{escape(heading)}[/yellow]")
    ordered = sorted(not_scanned, key=lambda e: (e["why"], e["id"]))
    for entry in ordered[:_NOT_SCANNED_SHOWN]:
        console.print(f"   {escape(entry['id'])}  {escape(entry['why'])}")
    if len(not_scanned) > _NOT_SCANNED_SHOWN:
        console.print(
            f"   ... and {len(not_scanned) - _NOT_SCANNED_SHOWN} more; every one is in "
            f"{preflight.FILE_PREFIX}-<timestamp>.csv"
        )


def _finish_access_check(
    output_dir: pathlib.Path,
    log_handler: logging.Handler,
    log_tmp: str,
    started: datetime,
    access_rows: list[dict],
    not_scanned: list[dict],
    checked: int,
    anonymizer: Optional[Anonymizer] = None,
    scope: Optional[dict] = None,
) -> pathlib.Path:
    """End a --preflight-only run: the pre-flight CSV and the run log in
    ``gcp_access_check_<stamp>.zip``. Nothing was collected."""
    import csv_export

    _print_not_scanned(not_scanned, "Not checked:")
    console.print(
        f"\n[bold]Access check complete:[/bold] {checked} project(s) checked, "
        f"{len(not_scanned)} could not be read. Nothing was collected."
    )
    logger.info("Access check complete — bundling the report.")
    runlog.finish(console)
    logging.getLogger().removeHandler(log_handler)
    log_handler.close()

    stamp = started.strftime(csv_export.FILE_TIMESTAMP_FORMAT)
    zip_path = output_dir / f"gcp_access_check_{stamp}.zip"
    rows = [*access_rows, *(row for entry in not_scanned for row in entry["rows"])]
    in_zip: dict = {}
    if rows:
        in_zip[preflight_core.file_name(preflight.FILE_PREFIX, stamp)] = preflight.csv_for(
            rows, anonymizer
        )
    manifest_text = _manifest_text(dict(in_zip), scope)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in in_zip.items():
            zf.writestr(name, text)
        if manifest_text is not None:
            zf.writestr(manifest_core.FILE_NAME, manifest_text)
        if anonymizer is not None:
            zf.writestr(f"output_gcp_{stamp}.log", anonymized_log_note())
        elif os.path.exists(log_tmp):
            zf.write(log_tmp, f"output_gcp_{stamp}.log")
    if anonymizer is not None:
        key_path = output_dir / f"{KEY_FILE_PREFIX}-{stamp}.csv"
        key_path.write_text(anonymizer.key_file_text(), encoding="utf-8", newline="")
        kept_log = output_dir / f"output_gcp_not_anonymized_{stamp}.log"
        if os.path.exists(log_tmp):
            shutil.copyfile(log_tmp, kept_log)
        console.print(f"[green]Keys:[/green] {key_path}  [dim](not in the ZIP)[/dim]")
        console.print(f"[green]Log: [/green] {kept_log}  [dim](not in the ZIP)[/dim]")
    try:
        pathlib.Path(log_tmp).unlink()
    except OSError as exc:
        logger.debug("Could not remove %s after zipping: %s", log_tmp, exc)
    console.print()
    console.print(f"[green]Access check complete.[/green]  Report: [cyan]{zip_path}[/cyan]")
    return zip_path


def _finalise_zip(
    out_path: pathlib.Path,
    log_handler: logging.Handler,
    log_tmp: str,
    started: Optional[datetime] = None,
    write_csv: bool = True,
    anonymizer: Optional[Anonymizer] = None,
    access_rows: Optional[list[dict]] = None,
    scope: Optional[dict] = None,
    stopped_early: bool = False,
) -> pathlib.Path:
    """Bundle the discovery JSON, the PowerShell-style CSV files and the run log into one ZIP,
    leaving a single file.

    The ZIP and the log are named as the PowerShell script names them
    (``gcp_sizing_results_<yyyy-MM-dd_HHmmss>.zip``, ``output_gcp_<same>.log``), with the run's
    start time. Detaches + closes the log handler first so the file is complete, then removes the
    loose JSON / temp log so only the ZIP remains to share.

    An anonymized run's ZIP has the anonymized CSV files and a note under the log's name, and no
    raw JSON (it holds every real name). The file that maps the labels back to the real values
    and the real log are written beside the ZIP.
    """
    import csv_export

    logger.info("Discovery run complete — bundling artefacts.")
    _print_totals(out_path)
    runlog.finish(console, "scan stopped early (partial results)" if stopped_early else None)
    logging.getLogger().removeHandler(log_handler)
    log_handler.close()

    stamp = (started or datetime.now(timezone.utc)).strftime(csv_export.FILE_TIMESTAMP_FORMAT)
    zip_path = out_path.with_name(f"gcp_sizing_results_{stamp}.zip")
    in_zip: dict = {}  # every data file written below, for the manifest
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if anonymizer is None:
            in_zip[out_path.name] = out_path.read_bytes()
            zf.writestr(out_path.name, in_zip[out_path.name])
        if write_csv:
            with out_path.open(encoding="utf-8") as f:
                for name, text in csv_export.build_csv_files(
                    json.load(f), stamp, anonymizer
                ).items():
                    in_zip[name] = text
                    zf.writestr(name, text)
            if access_rows:
                access_name = preflight_core.file_name(preflight.FILE_PREFIX, stamp)
                in_zip[access_name] = preflight.csv_for(access_rows, anonymizer)
                zf.writestr(access_name, in_zip[access_name])
        manifest_text = _manifest_text(in_zip, scope)  # last, so it lists everything above
        if manifest_text is not None:
            zf.writestr(manifest_core.FILE_NAME, manifest_text)
        if anonymizer is not None:
            zf.writestr(f"output_gcp_{stamp}.log", anonymized_log_note())
        elif os.path.exists(log_tmp):
            zf.write(log_tmp, f"output_gcp_{stamp}.log")
    if anonymizer is not None:
        key_path = out_path.with_name(f"{KEY_FILE_PREFIX}-{stamp}.csv")
        key_path.write_text(anonymizer.key_file_text(), encoding="utf-8", newline="")
        kept_log = out_path.with_name(f"output_gcp_not_anonymized_{stamp}.log")
        if os.path.exists(log_tmp):
            shutil.copyfile(log_tmp, kept_log)
        console.print(f"[green]Keys:[/green] {key_path}  [dim](not in the ZIP)[/dim]")
        console.print(f"[green]Log: [/green] {kept_log}  [dim](not in the ZIP)[/dim]")
        console.print("[dim]Keep these two files; they hold the real names.[/dim]")

    for stale in (out_path, pathlib.Path(log_tmp)):
        try:
            stale.unlink()
        except OSError as exc:
            logger.debug("Could not remove %s after zipping: %s", stale, exc)
    return zip_path


def _print_totals(json_path: pathlib.Path) -> None:
    """The per-resource totals, as the PowerShell script prints them, on the screen and in the log.

    Worked out from the discovery JSON the CSV files are built from, so the two agree. It holds
    counts and sizes only, so it is safe in an anonymized run. A failure here is a warning.
    """
    import csv_export

    try:
        with json_path.open(encoding="utf-8") as f:
            result = json.load(f)
        bigquery = result.get("bigquery") or []
        lines = totals.summary_lines(
            csv_export.rows_by_file(result),
            sum(int(b.get("dataset_count") or 0) for b in bigquery),
            sum(
                1 for e in result.get("collection_errors") or [] if e.get("collector") == "bigquery"
            ),
            bool(bigquery),
        )
    except Exception as exc:  # noqa: BLE001 - the totals must never stop the run
        logger.warning("Could not work out the totals: %s", exc)
        return
    console.print()
    for line in lines:
        console.print(line, markup=False, highlight=False, style="green")


def _move_run_log(log_handler: logging.Handler, output_dir: pathlib.Path, started: datetime) -> str:
    """Continue the run log in the output folder, named as it is inside the zip.

    The log starts in a temp file because the output folder can come from the config file, which is
    read after the log opens. From here a run that stops, is killed or crashes leaves its log in the
    folder the results go to, written up to that moment. Returns the log's path.
    """
    import csv_export

    name = f"output_gcp_{started.strftime(csv_export.FILE_TIMESTAMP_FORMAT)}.log"
    return log_handler.move(str(output_dir / name))


def _discard_run_log(log_handler: logging.Handler, log_tmp: str) -> None:
    """Detach the run-log handler and drop its temp file — no artefact produced."""
    logging.getLogger().removeHandler(log_handler)
    log_handler.close()
    try:
        os.remove(log_tmp)
    except OSError:
        pass


def _print_banner(projects: list[str], regions: Optional[list[str]]) -> None:
    region_str = ", ".join(regions) if regions else "all regions"
    project_str = ", ".join(projects[:3]) + (
        f" … +{len(projects) - 3} more" if len(projects) > 3 else ""
    )
    console.print()
    console.print(
        Panel(
            f"[bold white]Rubrik Discovery — GCP Edition[/bold white]\n"
            f"[dim]Projects:[/dim] [cyan]{project_str}[/cyan]\n"
            f"[dim]Regions:[/dim]  [cyan]{region_str}[/cyan]",
            border_style="bold blue",
            padding=(0, 2),
        )
    )
    console.print()


def _print_who_and_scope(
    credentials,
    projects: list[str],
    *,
    named: int,
    current_only: bool,
    include_system_projects: bool,
) -> tuple:
    """Say who the scan runs as and how the project list was chosen; return ``(facts, account)``.

    Both lines go to the screen and so to the run log.  The account is not kept anywhere else:
    the manifest and the anonymized log leave it out.
    """
    import auth

    account = auth.identity_of(credentials)
    console.print(f"[dim]{escape(runlog.account_line(account))}[/dim]")
    mode = "named" if named else "current" if current_only else "all"
    facts = auth.describe_scope(
        credentials,
        mode=mode,
        scanned=projects,
        named=named,
        include_system_projects=include_system_projects,
    )
    for line in runlog.scope_lines(facts):
        style = "yellow" if "WARNING" in line else "dim"
        console.print(f"[{style}]{escape(line)}[/{style}]")
    return facts, account


def _print_dry_run(
    projects: list[str], regions: Optional[list[str]], selected: Optional[set[str]] = None
) -> None:
    console.print(Rule("[bold]Dry Run — No GCP APIs will be called[/bold]"))
    console.print()

    sel = selected if selected is not None else set(_CORE_COLLECTORS)

    t = Table(box=box.ROUNDED, show_lines=False, title="In-scope projects")
    t.add_column("Project ID", style="cyan")
    for pid in projects:
        t.add_row(pid)
    console.print(t)
    console.print()

    t2 = Table(box=box.ROUNDED, show_lines=False, title="GCP APIs that would be called")
    t2.add_column("Collector", style="cyan", min_width=14)
    t2.add_column("API call", min_width=40)
    t2.add_column("Required IAM role", style="dim", min_width=30)
    t2.add_column("Purpose")
    for collector, api_call, iam, purpose in _DRY_RUN_API_CALLS:
        if collector not in sel:
            continue
        t2.add_row(collector, api_call, iam, purpose)
    console.print(t2)
    if sel != set(_CORE_COLLECTORS):
        console.print(
            f"[dim]Collector selection: {','.join(c for c in _CORE_COLLECTORS if c in sel)} "
            f"(others skipped via --collectors/--inventory-only).[/dim]"
        )
    console.print()
    console.print("[dim]Re-run without --dry-run to perform the actual collection.[/dim]")


def _collect_project(
    project_id: str,
    credentials,
    regions: Optional[list[str]],
    enable_security: bool = False,
    precomputed_asset=None,
    selected: Optional[set[str]] = None,
    switched_off: Optional[set[str]] = None,
    growth_days: Optional[int] = None,
) -> dict:
    """Run all Phase 2 collectors for one project.

    Returns a dict keyed by collector name with the inventory result.  Safe to
    run concurrently across projects — it shares only the (thread-safe, already
    refreshed) credentials and prints nothing (progress is printed by the
    orchestrator as each future completes, keeping parallel output ordered).

    If ``precomputed_asset`` is supplied (from the org-wide CAI spine), the
    per-project ``AssetCollector`` call is skipped — that's the whole point of
    the org spine: one sweep instead of one list_assets per project.
    """
    from collectors.asset import AssetCollector
    from collectors.backup import BackupCollector
    from collectors.bigquery import BigQueryCollector
    from collectors.compute import ComputeCollector
    from collectors.database import DatabaseCollector
    from collectors.storage import StorageCollector
    from collectors.utils import collection_error

    sel = selected if selected is not None else set(_CORE_COLLECTORS)
    # Collectors the pre-flight found switched off here (API or billing off) are not run: every
    # call would fail the same way. Nothing is lost, because there is nothing to read.
    if switched_off:
        sel = sel - switched_off
    result: dict = {}
    # Per-project collector failures (API disabled, missing permission, etc.).
    # Captured so a partial scan is visible downstream instead of silent zeros.
    errors: list[dict] = []

    # Asset enumeration — the spine
    if "asset" in sel:
        if precomputed_asset is not None:
            result["asset"] = precomputed_asset
        else:
            collector = AssetCollector(project_id, credentials)
            try:
                result["asset"] = collector.collect()
            except Exception as exc:
                logger.error("Asset collector failed for %s: %s", project_id, exc)
                errors.append(collection_error("asset", exc))
            errors.extend(collector.errors)

    # Compute
    if "compute" in sel:
        collector = ComputeCollector(project_id, credentials, regions)
        try:
            compute_inv = collector.collect()
            result["compute"] = compute_inv
            logger.debug(
                "Project %s: compute done (%d instances)", project_id, compute_inv.total_instances
            )
        except Exception as exc:
            logger.error("Compute collector failed for %s: %s", project_id, exc)
            errors.append(collection_error("compute", exc))
        errors.extend(collector.errors)

    # Storage
    if "storage" in sel:
        collector = StorageCollector(project_id, credentials, growth_days=growth_days)
        try:
            storage_inv = collector.collect()
            result["storage"] = storage_inv
            logger.debug(
                "Project %s: storage done (%d buckets)", project_id, storage_inv.total_buckets
            )
        except Exception as exc:
            logger.error("Storage collector failed for %s: %s", project_id, exc)
            errors.append(collection_error("storage", exc))
        errors.extend(collector.errors)

    # Database
    if "database" in sel:
        collector = DatabaseCollector(project_id, credentials)
        try:
            db_inv = collector.collect()
            result["database"] = db_inv
            logger.debug("Project %s: database done (%d total)", project_id, db_inv.total_databases)
        except Exception as exc:
            logger.error("Database collector failed for %s: %s", project_id, exc)
            errors.append(collection_error("database", exc))
        errors.extend(collector.errors)

    # BigQuery
    if "bigquery" in sel:
        collector = BigQueryCollector(project_id, credentials)
        try:
            bq_inv = collector.collect()
            result["bigquery"] = bq_inv
            logger.debug(
                "Project %s: bigquery done (%d datasets, %d tables)",
                project_id,
                bq_inv.dataset_count,
                len(bq_inv.tables),
            )
        except Exception as exc:
            logger.error("BigQuery collector failed for %s: %s", project_id, exc)
            errors.append(collection_error("bigquery", exc))
        errors.extend(collector.errors)

    # Backup and DR — pass instance names for gap analysis
    if "backup" in sel:
        gce_names = (
            [inst.name for inst in result["compute"].instances] if "compute" in result else []
        )
        collector = BackupCollector(
            project_id, credentials, gce_instance_names=gce_names, regions=regions
        )
        try:
            backup_inv = collector.collect()
            result["backup"] = backup_inv
            logger.debug(
                "Project %s: backup done (%.1f%% coverage)",
                project_id,
                backup_inv.protection_coverage_pct,
            )
        except Exception as exc:
            logger.error("Backup collector failed for %s: %s", project_id, exc)
            errors.append(collection_error("backup", exc))
        errors.extend(collector.errors)

    # Stamp the project onto each error so the aggregated list is self-describing.
    for e in errors:
        e["project_id"] = project_id
    if errors:
        result["errors"] = errors

    return result


def _print_project_line(
    project_id: str, result: dict, idx: int, total: int, switched_off: Optional[set] = None
) -> None:
    """Print one project's completion line (called in the main thread, in order)."""
    counter = f"[dim]{idx}/{total}[/dim]"
    asset = result.get("asset")
    if not result and switched_off:
        console.print(
            f"  [dim]-[/dim] {counter} {project_id[:40]:<40}  "
            f"[dim]nothing enabled to read ({', '.join(sorted(switched_off))} off)[/dim]"
        )
        return
    if asset is not None and asset.failed:
        # Unknown, not zero: the listing could not be read, so say so instead of "0 assets".
        why = "rate limited" if asset.failure_category == "RATE_LIMITED" else "could not be read"
        console.print(
            f"  [yellow]⚠[/yellow] {counter} {project_id[:40]:<40}  "
            f"[yellow]asset listing {why}[/yellow]  [dim](other collectors ran)[/dim]"
        )
    elif asset is not None:
        console.print(
            f"  [green]✓[/green] {counter} {project_id[:40]:<40}  "
            f"[cyan]{asset.total_assets}[/cyan] assets  "
            f"[dim]({len(asset.assets_by_type)} types)[/dim]"
        )
    elif result:
        console.print(
            f"  [green]✓[/green] {counter} {project_id[:40]:<40}  [dim](no asset spine)[/dim]"
        )
    else:
        console.print(
            f"  [red]✗[/red] {counter} {project_id[:40]:<40}  [red]collection failed[/red]"
        )


def _print_saved_line(project_id: str, line: dict, idx: int, total: int) -> None:
    """The completion line of a project taken from the saved run, marked as resumed.

    ``line`` is what ``resume.project_checkpoint`` recorded (asset count and types, and which
    collectors were switched off), so the line reads as it did the first time.
    """
    counter = f"[dim]{idx}/{total}[/dim]"
    name = f"{project_id[:40]:<40}"
    if line.get("assets") is not None:
        detail = (
            f"[cyan]{line['assets']}[/cyan] assets  [dim]({line.get('asset_types') or 0} types)[/dim]"
        )
    elif line.get("switched_off"):
        detail = f"[dim]nothing enabled to read ({', '.join(line['switched_off'])} off)[/dim]"
    else:
        detail = "[dim](no asset spine)[/dim]"
    console.print(f"  [green]✓[/green] {counter} {name}  {detail}  [dim]· saved by the earlier run[/dim]")


def _summarise_project(project_id: str, result: dict) -> dict:
    """Reduce a full collector result to the slim numbers the summary table needs.

    Kept tiny so org-scale runs can hold one per project (1000 of these) without
    retaining the heavy inventories.
    """
    import csv_export

    compute = result.get("compute")
    storage = result.get("storage")
    database = result.get("database")
    bigquery = result.get("bigquery")
    backup = result.get("backup")
    backup_known = bool(backup) and backup.available
    return {
        "project_id": project_id,
        "instances": compute.total_instances if compute else None,
        "disk_tb": compute.total_disk_tb if compute else None,
        "buckets": storage.total_buckets if storage else None,
        "bq_datasets": bigquery.dataset_count if bigquery else None,
        "bq_counts": dict(bigquery.table_counts) if bigquery else None,
        "bq_protectable_bytes": bigquery.protectable_logical_bytes if bigquery else None,
        "bq_other_cloud": csv_export.count_other_cloud(bigquery.tables) if bigquery else {},
        "dbs": database.total_databases if database else None,
        "protected": backup.protected_instance_count if backup_known else None,
        "coverage_pct": backup.protection_coverage_pct if backup_known else None,
        "coverage_unavailable": bool(backup) and not backup.available,
        "instances_for_coverage": (
            (compute.total_instances if compute else 0) if backup_known else 0
        ),
        "incomplete": bool(result.get("errors")),
    }


def _run_mock() -> tuple[list[str], Optional[list[str]], dict]:
    """Return mock scope + per-project results for --mock mode.

    No GCP APIs are called; all data comes from inline fixture definitions.
    """
    mock_projects = ["mock-project-prod", "mock-project-dev"]
    mock_regions = None  # all regions

    from collectors.asset import AssetInventory
    from models.inventory import (
        BackupPostureInventory,
        BigQueryInventory,
        BigQueryTable,
        ComputeInventory,
        DatabaseInventory,
        StorageInventory,
    )

    mock_results: dict[str, dict] = {
        "mock-project-prod": {
            "asset": AssetInventory(
                project_id="mock-project-prod",
                total_assets=142,
                assets_by_type={
                    "compute.googleapis.com/Instance": 28,
                    "storage.googleapis.com/Bucket": 15,
                    "sqladmin.googleapis.com/Instance": 6,
                    "compute.googleapis.com/Disk": 56,
                    "compute.googleapis.com/Firewall": 12,
                    "iam.googleapis.com/ServiceAccount": 25,
                },
            ),
            "compute": ComputeInventory(
                project_id="mock-project-prod",
                total_instances=28,
                total_disk_tb=round(56 * 200 / 1024, 2),
                os_breakdown={"linux": 22, "windows": 6},
                machine_family_breakdown={"n2": 14, "e2": 10, "c2": 4},
                disk_type_breakdown={"pd-ssd": 30, "pd-balanced": 26},
                region_breakdown={"us-central1": 20, "us-east1": 8},
                status_breakdown={"RUNNING": 25, "TERMINATED": 3},
            ),
            "storage": StorageInventory(
                project_id="mock-project-prod",
                total_buckets=15,
                class_breakdown={"STANDARD": 10, "NEARLINE": 3, "COLDLINE": 2},
                location_type_breakdown={"region": 12, "multi-region": 3},
                soft_delete_enabled_count=8,
                soft_delete_pct=53.3,
                versioning_enabled_count=6,
                versioning_pct=40.0,
            ),
            "database": DatabaseInventory(
                project_id="mock-project-prod",
                total_databases=6,
                engine_breakdown={"MYSQL": 3, "POSTGRES": 2, "SQLSERVER": 1},
            ),
            "bigquery": BigQueryInventory(
                project_id="mock-project-prod",
                dataset_count=2,
                tables=[
                    BigQueryTable(
                        dataset_id="analytics",
                        location="US",
                        table_id="events",
                        table_type="TABLE",
                        num_rows=1_200_000,
                        number_of_columns=14,
                        total_logical_bytes=5_000_000_000,
                        long_term_logical_bytes=2_000_000_000,
                        creation_time="2026-01-15T09:30:00Z",
                        last_modified_time="2026-10-01T04:00:00Z",
                        dataset_labels={"team": "data"},
                    ),
                    BigQueryTable(
                        dataset_id="analytics",
                        location="US",
                        table_id="events_view",
                        table_type="VIEW",
                        number_of_columns=6,
                        creation_time="2026-01-16T09:30:00Z",
                        last_modified_time="2026-01-16T09:30:00Z",
                        dataset_labels={"team": "data"},
                    ),
                ],
                table_counts={"TABLE": 1, "VIEW": 1},
                protectable_logical_bytes=5_000_000_000,
            ),
            "backup": BackupPostureInventory(
                project_id="mock-project-prod",
                total_associations=22,
                protected_instance_count=22,
                unprotected_instance_count=6,
                unprotected_instances=[
                    "vm-legacy-1",
                    "vm-legacy-2",
                    "vm-dev-3",
                    "vm-dev-4",
                    "vm-test-5",
                    "vm-test-6",
                ],
                protection_coverage_pct=78.6,
            ),
        },
        "mock-project-dev": {
            "asset": AssetInventory(
                project_id="mock-project-dev",
                total_assets=37,
                assets_by_type={
                    "compute.googleapis.com/Instance": 8,
                    "storage.googleapis.com/Bucket": 7,
                    "compute.googleapis.com/Disk": 16,
                    "iam.googleapis.com/ServiceAccount": 6,
                },
            ),
            "compute": ComputeInventory(
                project_id="mock-project-dev",
                total_instances=8,
                total_disk_tb=round(16 * 100 / 1024, 2),
                os_breakdown={"linux": 8},
                machine_family_breakdown={"e2": 8},
                disk_type_breakdown={"pd-standard": 16},
                region_breakdown={"us-central1": 8},
                status_breakdown={"RUNNING": 6, "TERMINATED": 2},
            ),
            "storage": StorageInventory(
                project_id="mock-project-dev",
                total_buckets=7,
                class_breakdown={"STANDARD": 7},
                location_type_breakdown={"region": 7},
                soft_delete_enabled_count=0,
                soft_delete_pct=0.0,
                versioning_enabled_count=0,
                versioning_pct=0.0,
            ),
            "database": DatabaseInventory(
                project_id="mock-project-dev",
                total_databases=0,
                engine_breakdown={},
            ),
            "backup": BackupPostureInventory(
                project_id="mock-project-dev",
                total_associations=0,
                protected_instance_count=0,
                unprotected_instance_count=8,
                unprotected_instances=[f"vm-dev-{i}" for i in range(1, 9)],
                protection_coverage_pct=0.0,
            ),
        },
    }

    console.print()
    console.print(
        Panel(
            "[bold white]Rubrik Discovery — GCP Edition[/bold white]  "
            "[yellow](MOCK MODE — no GCP credentials required)[/yellow]",
            border_style="yellow",
            padding=(0, 2),
        )
    )
    console.print()
    console.print(Rule("[bold]Collecting assets[/bold]"))
    for pid, res in mock_results.items():
        asset_inv = res["asset"]
        console.print(
            f"  [green]✓[/green] {pid:<40}  "
            f"[cyan]{asset_inv.total_assets}[/cyan] assets  "
            f"[dim]({len(asset_inv.assets_by_type)} types)[/dim]"
        )

    return mock_projects, mock_regions, mock_results


def _build_result(
    projects: list[str],
    regions: Optional[list[str]],
    per_project: dict[str, dict],
    organization_id: Optional[str] = None,
    collection_errors: Optional[list[dict]] = None,
    access_check: Optional[list[dict]] = None,
) -> "DiscoveryResult":
    import dataclasses

    from models.inventory import DiscoveryResult

    def _to_dict(obj):
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        return obj

    asset_counts: dict = {}
    compute_list = []
    storage_list = []
    databases_list = []
    bigquery_list = []
    backup_list = []

    for pid, res in per_project.items():
        # A failed listing has no counts; leave the project out rather than record a zero.
        if "asset" in res and not res["asset"].failed:
            inv = res["asset"]
            asset_counts[pid] = {"total": inv.total_assets, **inv.assets_by_type}
        if "compute" in res:
            compute_list.append(_to_dict(res["compute"]))
        if "storage" in res:
            storage_list.append(_to_dict(res["storage"]))
        if "database" in res:
            databases_list.append(_to_dict(res["database"]))
        if "bigquery" in res:
            bigquery_list.append(_to_dict(res["bigquery"]))
        if "backup" in res:
            backup_list.append(_to_dict(res["backup"]))

    if collection_errors is None:
        collection_errors = []
        for res in per_project.values():
            collection_errors.extend(res.get("errors", []))

    return DiscoveryResult(
        generated_at=datetime.now(timezone.utc).isoformat(),
        organization_id=organization_id,
        projects_scanned=projects,
        regions_in_scope=regions,
        asset_counts=asset_counts,
        compute=compute_list,
        storage=storage_list,
        databases=databases_list,
        bigquery=bigquery_list,
        backup_posture=backup_list,
        collection_errors=collection_errors,
        access_check=access_check or [],
    )


def _build_result_from_slices(
    projects: list[str],
    regions: Optional[list[str]],
    slices: dict[str, dict],
    collection_errors: Optional[list[dict]] = None,
    access_check: Optional[list[dict]] = None,
) -> "DiscoveryResult":
    """``_build_result`` for projects held as slices (``slice_from_result``), in scan order.

    A slice is what ``_build_result`` takes from one project's inventories, already as plain
    dicts, so a project taken from a saved run needs no inventory objects. The two give the same
    JSON for the same projects (tests/test_scale.py pins that for the streaming writer, which
    uses the same slices).
    """
    from models.inventory import DiscoveryResult

    asset_counts: dict = {}
    lists: dict[str, list] = {key: [] for key in ("compute", "storage", "databases", "bigquery")}
    lists["backup_posture"] = []
    for pid in projects:
        piece = slices.get(pid)
        if piece is None:
            continue
        if piece.get("asset_counts") is not None:
            asset_counts[pid] = piece["asset_counts"]
        for key, items in lists.items():
            if piece.get(key) is not None:
                items.append(piece[key])

    return DiscoveryResult(
        generated_at=datetime.now(timezone.utc).isoformat(),
        organization_id=None,
        projects_scanned=projects,
        regions_in_scope=regions,
        asset_counts=asset_counts,
        compute=lists["compute"],
        storage=lists["storage"],
        databases=lists["databases"],
        bigquery=lists["bigquery"],
        backup_posture=lists["backup_posture"],
        collection_errors=collection_errors or [],
        access_check=access_check or [],
    )


def _write_output(result: "DiscoveryResult", output_dir: pathlib.Path) -> pathlib.Path:

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"gcp-sizing-discovery-{ts}.json"
    out_path = output_dir / filename

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(result.to_json_dict(), f, indent=2, default=str)

    return out_path


_SUMMARY_TABLE_CAP = 50
"""Above this many projects, show only the org totals — a 1000-row table is noise."""


def _print_summary(summaries: list[dict], collection_errors: Optional[list[dict]] = None) -> None:
    console.print()
    console.print(Rule("[bold]Discovery Summary[/bold]"))
    console.print()

    total_instances = 0
    total_disk_tb = 0.0
    total_buckets = 0
    total_dbs = 0
    total_protected = 0

    for s in summaries:
        total_instances += s["instances"] or 0
        total_disk_tb += s["disk_tb"] or 0.0
        total_buckets += s["buckets"] or 0
        total_dbs += s["dbs"] or 0
        total_protected += s["protected"] or 0

    show_rows = len(summaries) <= _SUMMARY_TABLE_CAP

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Project", style="cyan", min_width=30)
    t.add_column("Instances", justify="right", min_width=10)
    t.add_column("Disk TB", justify="right", min_width=8)
    t.add_column("Buckets", justify="right", min_width=9)
    t.add_column("Databases", justify="right", min_width=10)
    t.add_column("Protected", justify="right", min_width=10)

    if show_rows:
        for s in summaries:
            instances = str(s["instances"]) if s["instances"] is not None else "-"
            disk_tb = f"{s['disk_tb']:.2f}" if s["disk_tb"] is not None else "-"
            buckets = str(s["buckets"]) if s["buckets"] is not None else "-"
            dbs = str(s["dbs"]) if s["dbs"] is not None else "-"

            if s.get("coverage_unavailable"):
                protected = "[yellow]n/a[/yellow]"
            elif s["coverage_pct"] is not None:
                protected = str(s["protected"])
            else:
                protected = "-"

            name = (
                f"[yellow]⚠[/yellow] {s['project_id']}" if s.get("incomplete") else s["project_id"]
            )
            t.add_row(name, instances, disk_tb, buckets, dbs, protected)
        t.add_section()
    else:
        console.print(
            f"[dim]{len(summaries)} projects scanned — per-project rows omitted "
            f"(> {_SUMMARY_TABLE_CAP}); see the JSON output for detail.[/dim]"
        )
        console.print()

    unavailable = sum(1 for s in summaries if s.get("coverage_unavailable"))
    readable = any(s["coverage_pct"] is not None for s in summaries)
    total_protected_str = "n/a" if unavailable and not readable else str(total_protected)
    t.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{total_instances}[/bold]",
        f"[bold]{total_disk_tb:.2f}[/bold]",
        f"[bold]{total_buckets}[/bold]",
        f"[bold]{total_dbs}[/bold]",
        f"[bold]{total_protected_str}[/bold]",
    )

    console.print(t)

    bq = [s for s in summaries if s.get("bq_counts") is not None]
    if bq:
        kinds: dict[str, int] = {}
        for s in bq:
            for kind, n in s["bq_counts"].items():
                kinds[kind] = kinds.get(kind, 0) + n
        protectable_tb = round(sum(s["bq_protectable_bytes"] or 0 for s in bq) / 1e12, 4)
        console.print()
        console.print(
            f"[bold]BigQuery:[/bold] {sum(s['bq_datasets'] or 0 for s in bq)} datasets · "
            f"{kinds.get('TABLE', 0)} tables · {kinds.get('MATERIALIZED_VIEW', 0)} materialized "
            f"views · {kinds.get('VIEW', 0)} views · {kinds.get('EXTERNAL', 0)} external tables · "
            f"{kinds.get('SNAPSHOT', 0)} snapshots"
        )
        console.print(
            f"  [dim]Logical size of the data in BigQuery (tables and materialized views): "
            f"{protectable_tb} TB, decimal. Views, external tables and snapshots are not "
            f"counted.[/dim]"
        )
        other_cloud: dict[str, int] = {}
        for s in bq:
            for cloud, n in (s.get("bq_other_cloud") or {}).items():
                other_cloud[cloud] = other_cloud.get(cloud, 0) + n
        if other_cloud:
            console.print(
                f"[yellow]⚠ {sum(other_cloud.values())} BigQuery table(s) read data in "
                f"{' and '.join(sorted(other_cloud))}, not in Google Cloud Storage "
                f"({', '.join(f'{n} in {c}' for c, n in sorted(other_cloud.items()))}).[/yellow]"
            )
            console.print(
                "  [dim]BigQuery Omni tables like these are not sized by this scan: their data is "
                "not in gce_storage_info. Run the AWS or Azure sizing script against the storage "
                "they read. They are marked in the ExternalCloud column of "
                "gce_bigquery_info.[/dim]"
            )

    # Surface partial coverage loudly — a project we couldn't fully read shows as
    # zeros above and would otherwise silently undercount the sizing estimate.
    errs = collection_errors or []
    if errs:
        affected = {e.get("project_id") for e in errs}
        cats: dict[str, int] = {}
        for e in errs:
            cats[e.get("category", "OTHER")] = cats.get(e.get("category", "OTHER"), 0) + 1
        cat_str = " · ".join(f"{k}: {v}" for k, v in sorted(cats.items()))
        console.print()
        console.print(
            f"[yellow]⚠ {len(affected)} of {len(summaries)} projects had incomplete "
            f"collection[/yellow] [dim]— affected metrics undercount.[/dim]"
        )
        console.print(f"  [dim]{cat_str}[/dim]")
        if unavailable:
            console.print(
                f"  [dim]Protected is n/a for {unavailable} project(s): Backup and DR could not be "
                "read, so they are left out of the Protected total (the JSON lists their VMs as "
                "unprotected, with available=false).[/dim]"
            )
        console.print(
            "  [dim]See [bold]collection_errors[/bold] in the discovery JSON for "
            "per-project detail.[/dim]"
        )


def main() -> None:
    try:
        _main()
    except BaseException as exc:
        runlog.crashed(exc)
        raise


def _main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    if (args.anonymize_fields or args.not_anonymize_fields) and not args.anonymize:
        parser.error("--anonymize-fields and --not-anonymize-fields need --anonymize")
    if args.anonymize and args.no_csv:
        parser.error("--anonymize works on the CSV files, so it cannot be used with --no-csv")
    if args.preflight_only and args.no_preflight:
        parser.error("--preflight-only runs only the access check, so it cannot skip it")
    if args.preflight_only and args.no_csv:
        parser.error("--preflight-only writes only the access-check CSV, so it cannot use --no-csv")
    if args.preflight_only and args.dry_run:
        parser.error("--preflight-only already collects nothing; use it or --dry-run, not both")
    if args.preflight_only and args.mock:
        parser.error("--preflight-only checks real access, so it cannot be used with --mock")
    if args.keep_partial and not args.resume:
        parser.error(
            "--keep-partial keeps what an earlier run finished with gaps instead of scanning it "
            "again, so it needs --resume"
        )
    if (args.resume or args.fresh) and (args.mock or args.dry_run or args.preflight_only):
        parser.error(
            "--resume and --fresh apply to a scan, not to --mock, --dry-run or --preflight-only"
        )
    if args.no_growth and args.growth_days is not None:
        parser.error("--no-growth turns growth off, so it cannot be used with --growth-days")
    if args.growth_days is not None and not 1 <= args.growth_days <= _MAX_GROWTH_DAYS:
        parser.error(f"--growth-days must be between 1 and {_MAX_GROWTH_DAYS}")
    anonymizer = (
        Anonymizer.from_options(args.anonymize_fields, args.not_anonymize_fields)
        if args.anonymize
        else None
    )
    _configure_logging(args.verbose)

    # Capture a full DEBUG run log to disk; bundled into the result ZIP below.
    log_handler, log_tmp = _start_run_log()
    runlog.start(sys.argv[1:])
    runlog.install_stop_handlers()
    started = datetime.now(timezone.utc)
    logger.info("Discovery run started (mock=%s)", bool(args.mock))

    from config import load_config

    cfg = load_config(args.config)
    if not args.dry_run:
        log_tmp = _move_run_log(
            log_handler, _resolve_output_dir(args.output or cfg.discovery.output_dir), started
        )

    # Validate collector selection early — fail fast on a typo before we touch
    # credentials or call any GCP API.
    selected = _resolve_collectors(args)

    # ── Mock mode ──────────────────────────────────────────────────────────────
    if args.mock or cfg.discovery.mock:
        projects, regions, per_project = _run_mock()
        result = _build_result(projects, regions, per_project)
        output_dir = _resolve_output_dir(args.output or cfg.discovery.output_dir)
        out_path = _write_output(result, output_dir)
        _print_summary([_summarise_project(pid, per_project[pid]) for pid in projects])
        zip_path = _finalise_zip(
            out_path,
            log_handler,
            log_tmp,
            started=started,
            write_csv=not args.no_csv,
            anonymizer=anonymizer,
        )
        console.print()
        console.print(f"[green]Discovery complete.[/green]  Output: [cyan]{zip_path}[/cyan]")
        console.print(
            "[dim]Share this ZIP with your Rubrik SE, who will run "
            "generate_report.py to produce the HTML + Excel report.[/dim]"
        )
        return

    # ── Live run ───────────────────────────────────────────────────────────────
    # A missing Google library fails here, before sign-in and before any API call.
    if not args.no_sdk_check and not args.dry_run:
        _require_sdks(selected, log_handler, log_tmp)

    import auth

    if args.project_file:
        project_ids = _read_project_file(args.project_file)
    else:
        project_ids = _parse_csv(args.projects) if args.projects else None

    credentials = auth.get_credentials()
    regions_raw = _parse_csv(args.regions) if args.regions else None
    regions = auth.normalise_regions(regions_raw)

    if cfg.scope.projects and not project_ids:
        logger.warning(
            "scope.projects in the config file is not used for project selection; "
            "pass --projects or --project-file. Scanning: %s",
            "current project" if _current_project_only(args, cfg) else "all accessible projects",
        )
    skipped_projects: list = []
    projects = auth.resolve_projects(
        credentials,
        project_ids,
        all_projects=not _current_project_only(args, cfg),
        skipped=skipped_projects,
        include_system_projects=args.include_system_projects,
    )
    # Projects that are not in the results, and why: each keeps rows in the pre-flight CSV and is
    # named at the end.
    not_scanned: list[dict] = []
    for pid, exc in skipped_projects:
        check = preflight.unreadable_check(pid, exc)
        not_scanned.append(
            {"id": pid, "why": f"cannot read the project: {check.code}", "rows": [check.to_row()]}
        )

    _print_banner(projects, regions)
    scope_facts, account = _print_who_and_scope(
        credentials,
        projects,
        named=len(project_ids) if project_ids else 0,
        current_only=_current_project_only(args, cfg),
        include_system_projects=args.include_system_projects,
    )

    if args.dry_run:
        _discard_run_log(log_handler, log_tmp)
        _print_dry_run(projects, regions, selected)
        return

    workers = args.workers or cfg.discovery.workers
    scope = auth.normalise_scope(
        args.org_id or cfg.discovery.org_id,
        args.folder_id or cfg.discovery.folder_id,
    )
    enable_security = args.security or cfg.discovery.collectors.security
    growth_days = _resolve_growth_days(args, selected)
    if selected != set(_CORE_COLLECTORS):
        console.print(
            f"[dim]Collectors:[/dim] running [cyan]"
            f"{','.join(c for c in _CORE_COLLECTORS if c in selected)}[/cyan] "
            f"[dim](subset — other core collectors skipped)[/dim]"
        )

    output_dir = _resolve_output_dir(args.output or cfg.discovery.output_dir)
    store = None
    to_check = projects
    if not args.preflight_only:
        store, resumed = _open_progress(
            args,
            output_dir,
            resume.request_of(
                selected=selected,
                regions=regions,
                security=enable_security,
                scope=scope,
                project_scope=(
                    "current"
                    if _current_project_only(args, cfg)
                    else "named" if project_ids else "all"
                ),
            ),
        )
        if resumed:
            # Projects the earlier run finished keep the access rows it saved: check only the rest.
            to_check = resume.split(store, projects, not args.keep_partial)[0]

    access_rows: list[dict] = []
    if not args.no_preflight:
        access_rows = _run_access_check(to_check, credentials, selected, workers)

    if access_rows and not args.preflight_only:
        _confirm_quota_project(access_rows, assume_yes=args.yes)

    if args.preflight_only:
        _finish_access_check(
            _resolve_output_dir(args.output or cfg.discovery.output_dir),
            log_handler,
            log_tmp,
            started,
            access_rows,
            not_scanned,
            checked=len(projects),
            anonymizer=anonymizer,
            scope=_scope_for_manifest(scope_facts),
        )
        return

    # ── Org-wide asset spine (Feature: one CAI sweep instead of N list_assets) ──
    # Only worth a sweep when the asset collector is actually selected.
    org_assets = _maybe_org_asset_spine(scope, credentials, projects) if "asset" in selected else {}

    # ── Per-project collection, parallelised across `workers` threads ───────────
    console.print(Rule(f"[bold]Collecting assets[/bold]  [dim]({workers} workers)[/dim]"))
    console.print()

    failed_projects: list = []
    zip_access: list[dict] = []
    project_gaps: list = []
    with _graceful_stop():
        out_path = _collect_and_write(
            projects=projects,
            regions=regions,
            credentials=credentials,
            enable_security=enable_security,
            workers=workers,
            org_assets=org_assets,
            output_dir=output_dir,
            selected=selected,
            access_rows=access_rows,
            failed=failed_projects,
            store=store,
            retry_partial=not args.keep_partial,
            access_out=zip_access,
            gaps_out=project_gaps,
            growth_days=growth_days,
        )
    from collectors.utils import ScanStopped, stop_requested

    stopped_early = stop_requested()
    for pid, exc in failed_projects:
        check = preflight.scan_failed_check(pid, exc)
        why = (
            "not scanned: the run was stopped"
            if isinstance(exc, ScanStopped)
            else f"collection failed: {check.code}"
        )
        not_scanned.append({"id": pid, "why": why, "rows": [check.to_row()]})
    _print_not_scanned(not_scanned, "Not scanned:")
    if stopped_early:
        console.print(
            "\n[yellow]The run was stopped early: the results are PARTIAL.[/yellow] Projects "
            "listed above are missing, and BigQuery tables the run did not reach show a size "
            "of 0."
        )

    zip_path = _finalise_zip(
        out_path,
        log_handler,
        log_tmp,
        started=started,
        write_csv=not args.no_csv,
        anonymizer=anonymizer,
        access_rows=[*zip_access, *(row for entry in not_scanned for row in entry["rows"])],
        scope=_scope_for_manifest(scope_facts),
        stopped_early=stopped_early,
    )
    kept = resume.keep_progress(not_scanned, stopped_early, project_gaps)
    _close_progress(store, keep=kept)
    _print_gaps(project_gaps, len(projects), kept)

    console.print()
    console.print(f"[green]Discovery complete.[/green]  Output: [cyan]{zip_path}[/cyan]")
    console.print(
        "[dim]Share this ZIP with your Rubrik SE, who will run "
        "generate_report.py to produce the HTML + Excel report.[/dim]"
    )


def _print_gaps(gaps: list, total: int, kept: bool) -> None:
    """End the run by saying which projects finished with gaps, and what to do about them.

    A project that finished is complete as far as the scan got, not as far as the project goes: a
    collector that failed leaves something out, and the zip alone does not say so.
    """
    lines = checkpoint_core.gaps_summary("project", gaps, total, kept=kept)
    if not lines:
        return
    console.print()
    console.print(f"[yellow]{escape(lines[0])}[/yellow]")
    for line in lines[1:]:
        console.print(escape(line))


def _open_progress(args, output_dir: pathlib.Path, request: dict):
    """Open this run's progress folder, or resume the unfinished one in output_dir.

    Returns the checkpoint store, and whether it is a resumed run. A previous run that cannot be
    resumed (different options, or no terminal to ask on) ends the run with what to do, not a
    traceback; nothing is deleted unless --fresh or the person's answer says so.
    """
    try:
        store, resumed = checkpoint_core.prepare(
            str(output_dir),
            prefix=resume.PREFIX,
            tool="gcp",
            request=request,
            mode=resume.mode_of(args),
            code_version=runlog.core.code_version(runlog.HERE),
            say=lambda text: console.print(f"[dim]{escape(text)}[/dim]"),
        )
    except checkpoint_core.ResumeRefused as exc:
        console.print(f"[red]Cannot start:[/red] {escape(str(exc))}")
        runlog.core.end_run("not started: an unfinished run is in the way", [str(exc)])
        sys.exit(2)
    runlog.core.set_stop_hint(
        f"Projects that finished are saved in {store.root}; run the same command with --resume "
        "to carry on where this one stopped."
    )
    return store, resumed


def _close_progress(store, keep: bool) -> None:
    """The results are written: remove the progress folder, unless something is left to resume.

    keep is True when a project has no saved result (it died, or was not reached after a stop),
    so a later --resume can scan just those. The folder is then left marked as unfinished.
    """
    if store is None:
        return
    if keep:
        console.print(
            f"[dim]Progress kept in {escape(store.root)}: run again with --resume to scan the "
            "projects that were not finished.[/dim]"
        )
        return
    store.finish()


def _maybe_org_asset_spine(scope, credentials, projects: list[str]) -> dict:
    """Run the org-wide CAI spine when a scope is set; return {project_id: AssetInventory}.

    Returns an empty dict (per-project fallback) when no scope is given or the
    org sweep fails / yields nothing.
    """
    if not scope:
        return {}

    import auth
    from collectors.asset import OrgAssetCollector

    console.print(
        f"[dim]Org spine:[/dim] enumerating assets for [cyan]{len(projects)}[/cyan] "
        f"projects under [cyan]{scope}[/cyan] in one Cloud Asset Inventory sweep…"
    )
    number_map = auth.build_project_number_map(credentials, projects)
    org_assets = OrgAssetCollector(scope, credentials, number_map).collect()
    if org_assets:
        console.print(
            f"[green]✓[/green] Org spine covered [cyan]{len(org_assets)}[/cyan] projects "
            f"[dim](skipping per-project list_assets)[/dim]\n"
        )
    else:
        console.print(
            "[yellow]Org spine returned no data — falling back to per-project "
            "asset collection.[/yellow]\n"
        )
    return org_assets


def _collect_unless_stopped(pid: str, *args, **kwargs) -> dict:
    """``_collect_project``, unless the run was asked to stop before this project started."""
    from collectors.utils import ScanStopped, stop_requested

    if stop_requested():
        raise ScanStopped("the run was stopped before this project started")
    return _collect_project(pid, *args, **kwargs)


@contextlib.contextmanager
def _graceful_stop():
    """For the scan only: the first Ctrl-C, SIGTERM or SIGHUP asks the scan to wind down, so the
    results of the projects done so far are still written (marked partial). A second one is handed
    to the handler that was there before, which logs the stop and exits at once.

    Does nothing off the main thread. The previous handlers are put back on exit.
    """
    import signal
    import threading

    from collectors.utils import request_stop, reset_stop, stop_requested

    reset_stop()
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous: dict = {}

    def handle(signum, frame) -> None:
        if stop_requested():
            handler = previous.get(signum)
            if callable(handler):
                handler(signum, frame)
            os._exit(128 + int(signum))
        request_stop()
        console.print(
            "\n[yellow]Stop requested.[/yellow] Finishing the calls in flight, then writing the "
            "results gathered so far (projects not reached are listed as not scanned). "
            "Press Ctrl-C again to quit at once without results."
        )

    for name, _label in runlog.STOP_SIGNALS:
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            previous[number] = signal.signal(number, handle)
        except (ValueError, OSError):
            continue
    try:
        yield
    finally:
        for number, handler in previous.items():
            try:
                signal.signal(number, handler)
            except (ValueError, OSError):
                pass


def _collect_and_write(
    *,
    projects: list[str],
    regions: Optional[list[str]],
    credentials,
    enable_security: bool,
    workers: int,
    org_assets: dict,
    output_dir: pathlib.Path,
    selected: Optional[set[str]] = None,
    access_rows: Optional[list[dict]] = None,
    failed: Optional[list] = None,
    store=None,
    retry_partial: bool = True,
    access_out: Optional[list] = None,
    gaps_out: Optional[list] = None,
    growth_days: Optional[int] = None,
) -> pathlib.Path:
    """Collect all projects in parallel and write the discovery JSON.

    ``failed``, when given, gets ``(project_id, exception)`` for each project whose collection
    stopped on an error as a whole (one collector failing is recorded in the project's errors).

    ``gaps_out``, when given, is filled with ``(project, why)`` for every project in the output that
    has collector errors, scanned now or taken from the earlier run.

    ``access_out``, when given, is filled with the access-check rows of every project in the output:
    this run's, plus those saved with the projects taken from the earlier run (not checked again).

    ``store`` is the run's checkpoint store. Each project that finishes is saved to it as it
    finishes, and a project it already holds is taken from it instead of being scanned again (unless
    ``retry_partial`` and it finished with errors). Without a store nothing is saved.

    Above ``_STREAMING_THRESHOLD`` projects the output is streamed to disk one
    project at a time (bounded memory); below it the simple in-memory path is
    used so small runs keep producing byte-identical output.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from collectors.utils import collection_error, stop_requested
    from streaming_writer import StreamingDiscoveryWriter, slice_from_result

    total = len(projects)
    use_streaming = total > _STREAMING_THRESHOLD
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    summaries: list[dict] = []
    all_errors: list[dict] = []
    off_by_project = preflight.switched_off_collectors(access_rows or [])
    access_of = resume.access_by_project(access_rows or [])
    # What the output records as checked: this run's rows, plus those of the projects taken from
    # the saved run (they were not checked again).
    output_access: list[dict] = list(access_rows or [])

    reuse: list[str] = []
    todo = list(projects)
    if store is not None:
        todo, reuse, notes = resume.split(store, projects, retry_partial)
        for note in notes:
            console.print(f"[dim]{escape(note)}[/dim]")
        if reuse:
            console.print(
                f"[dim]Resuming: {len(reuse)} of {total} projects are already done and are not "
                f"scanned again.[/dim]\n"
            )

    writer = None
    slices: dict[str, dict] = {}  # the in-memory path: project -> slice
    if use_streaming:
        writer = StreamingDiscoveryWriter(output_dir, ts)
        console.print(
            f"[dim]Streaming output (> {_STREAMING_THRESHOLD} projects) — bounded memory.[/dim]\n"
        )

    def _emit(pid: str, slice_dict: dict) -> None:
        if writer is not None:
            writer.add(pid, slice_dict)
        else:
            slices[pid] = slice_dict

    counter = {"n": 0}

    # Projects taken from the saved run: what they recorded, read back as it was written.
    for pid in reuse:
        loaded = store.load(pid)
        data = loaded[0]
        counter["n"] += 1
        all_errors.extend(data["errors"])
        output_access.extend(row for row in data["access"] if row not in output_access)
        _print_saved_line(pid, data["line"], counter["n"], total)
        summaries.append(data["summary"])
        _emit(pid, data["slice"])

    def _finish(pid: str, res: dict, *, died: bool, stopped: bool) -> None:
        """One scanned project is done: save it, print its line, add it to the output."""
        counter["n"] += 1
        summary = _summarise_project(pid, res)
        slice_dict = slice_from_result(pid, res)
        if store is not None and resume.should_save(stopped=stopped, died=died):
            try:
                store.save(
                    pid,
                    resume.project_checkpoint(
                        pid, res, summary, slice_dict, off_by_project.get(pid), access_of.get(pid, [])
                    ),
                    partial=resume.is_partial(res),
                )
            except OSError as exc:  # a full disk must not end a scan that is otherwise working
                logger.warning("Could not save the checkpoint of %s: %s", pid, exc)
        all_errors.extend(res.get("errors", []))
        _print_project_line(pid, res, counter["n"], total, off_by_project.get(pid))
        summaries.append(summary)
        _emit(pid, slice_dict)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _collect_unless_stopped,
                pid,
                credentials,
                regions,
                enable_security,
                org_assets.get(pid),
                selected,
                **({"growth_days": growth_days} if growth_days else {}),
                **({"switched_off": off_by_project[pid]} if pid in off_by_project else {}),
            ): pid
            for pid in todo
        }
        for future in as_completed(futures):
            pid = futures[future]
            died = False
            try:
                res = future.result()
            except Exception as exc:  # a project that died entirely
                logger.error("Project %s collection failed: %s", pid, exc)
                if failed is not None:
                    failed.append((pid, exc))
                err = collection_error("*", exc)
                err["project_id"] = pid
                res = {"errors": [err]}
                died = True
            _finish(pid, res, died=died, stopped=stop_requested())

    # Keep the summary table in scan order regardless of completion order.
    order = {pid: i for i, pid in enumerate(projects)}
    summaries.sort(key=lambda s: order.get(s["project_id"], 0))
    # In scan order, as an uninterrupted run lists them (sorted() is stable: each project's own rows
    # keep their order). The rows of projects taken from the saved run were added after this run's.
    rank = {pid: i for i, pid in enumerate(projects)}
    output_access.sort(key=lambda row: rank.get(row.get("Owner"), len(rank)))
    if access_out is not None:
        access_out[:] = output_access
    if gaps_out is not None:
        gaps_out[:] = resume.gaps_of_errors(all_errors)

    if writer is not None:
        meta = {
            "schema_version": _schema_version(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "organization_id": None,
            "projects_scanned": projects,
            "regions_in_scope": regions,
            "collection_errors": all_errors,
            "access_check": output_access,
        }
        out_path = writer.finalize(
            meta=meta, filename=f"gcp-sizing-discovery-{ts}.json", order=projects
        )
    else:
        result = _build_result_from_slices(
            projects, regions, slices, collection_errors=all_errors, access_check=output_access
        )
        out_path = _write_output(result, output_dir)

    _print_summary(summaries, all_errors)
    if off_by_project:
        every = {c for api in preflight.APIS for c in (api.collector,)} & (
            selected if selected is not None else set(_CORE_COLLECTORS)
        )
        empty = [p for p, off in off_by_project.items() if every and every <= off]
        console.print()
        console.print(
            f"[dim]The pre-flight check found services switched off (API or billing) in "
            f"{len(off_by_project)} of {total} project(s); {len(empty)} had nothing enabled to "
            f"read. Those services were not queried and are not counted as incomplete. "
            f"See the pre-flight CSV in the zip for which.[/dim]"
        )
    return out_path


def _schema_version() -> str:
    from models.inventory import CURRENT_SCHEMA_VERSION

    return CURRENT_SCHEMA_VERSION


if __name__ == "__main__":
    main()

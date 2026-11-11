"""Authentication and project resolution for Rubrik Discovery — GCP Edition."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

import google.auth
import google.auth.exceptions
import google.auth.transport.requests
from google.auth import credentials as google_credentials

logger = logging.getLogger(__name__)

_GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def get_credentials() -> google_credentials.Credentials:
    """Build and eagerly validate Application Default Credentials.

    Exits with a layered, actionable error message if authentication fails,
    with guidance tailored to the detected runtime environment (Cloud Shell,
    GCE Workload Identity, or local workstation).

    Returns:
        A validated google.auth Credentials instance.
    """
    try:
        credentials, _ = google.auth.default(scopes=_GCP_SCOPES)
        request = google.auth.transport.requests.Request()
        credentials.refresh(request)
        return credentials
    except google.auth.exceptions.DefaultCredentialsError as exc:
        _print_auth_error(str(exc))
        sys.exit(1)
    except Exception as exc:
        _print_auth_error(f"Unexpected error: {exc}")
        sys.exit(1)


def resolve_projects(
    credentials: google_credentials.Credentials,
    project_ids: Optional[list[str]],
    all_projects: bool = True,
    skipped: Optional[list] = None,
    include_system_projects: bool = False,
) -> list[str]:
    """Resolve the list of project IDs to operate on.

    Priority order:
    1. Explicit ``project_ids`` (--projects or --project-file) — each is validated
       against the API.
    2. ``all_projects=True`` (the default) — enumerate every ACTIVE project, except
       Google's ``sys-<digits>`` system projects unless ``include_system_projects``.
    3. ``all_projects=False`` (--current-project) — auto-detect via ADC default
       project or gcloud config.

    Args:
        credentials: Authenticated GCP credentials.
        project_ids: Explicit project IDs, or None.
        all_projects: If True (default), enumerate all accessible projects when no
            explicit IDs are given; if False, use only the current project.
        skipped: When given, each explicit ID that could not be read is appended as
            ``(project_id, exception)``, so the caller can report it.
        include_system_projects: When True, enumeration keeps Google's ``sys-<digits>``
            projects (--include-system-projects).

    Returns:
        List of validated project IDs.

    Raises:
        SystemExit: If no projects can be resolved.
    """
    if project_ids:
        return _validate_explicit_projects(credentials, project_ids, skipped)
    if all_projects:
        return _enumerate_all_projects(credentials, include_system_projects)
    return _detect_current_project(credentials)


def normalise_scope(org_id: Optional[str], folder_id: Optional[str]) -> Optional[str]:
    """Build a Cloud Asset Inventory ``scope`` string from a raw org/folder ID.

    Accepts a bare numeric ID (``123456789012``) or an already-qualified
    resource name (``organizations/123...`` / ``folders/456...``) and returns the
    qualified form CAI's ``search_all_resources`` expects.  Org takes precedence
    over folder.  Returns None when neither is supplied (project-scoped run).
    """
    if org_id:
        return org_id if "/" in org_id else f"organizations/{org_id}"
    if folder_id:
        return folder_id if "/" in folder_id else f"folders/{folder_id}"
    return None


def build_project_number_map(
    credentials: google_credentials.Credentials,
    project_ids: list[str],
) -> dict[str, str]:
    """Return a ``project_number -> project_id`` map for the given projects.

    Cloud Asset Inventory's ``search_all_resources`` reports each resource's
    owning project as ``projects/<NUMBER>``, whereas every model in this tool is
    keyed by ``project_id``.  This map lets the org-wide asset spine translate
    back.  Best-effort: a project that can't be resolved is simply absent from
    the map (its assets fall back to a number-keyed entry, so nothing is lost).
    """
    from google.cloud import resourcemanager_v3

    client = resourcemanager_v3.ProjectsClient(credentials=credentials)
    number_to_id: dict[str, str] = {}
    for pid in project_ids:
        try:
            project = client.get_project(name=f"projects/{pid}")
            # v3 resource name is ``projects/<PROJECT_NUMBER>``.
            number = project.name.split("/")[-1] if project.name else ""
            if number:
                number_to_id[number] = project.project_id
        except Exception as exc:
            logger.debug("Could not resolve number for project %s: %s", pid, exc)
    return number_to_id


def normalise_regions(regions: Optional[list[str]]) -> Optional[list[str]]:
    """Normalise region names to lowercase with no surrounding spaces.

    Args:
        regions: List of region strings, or None / empty to collect all.

    Returns:
        Normalised list, or None to signal "collect all regions".
    """
    if not regions:
        return None
    normalised = [r.strip().lower() for r in regions if r.strip()]
    return normalised or None


def zone_to_region(zone: str) -> str:
    """Strip the zone suffix from a GCP zone string to derive the region.

    GCP zones are ``<region>-<letter>`` where letter is a single alpha character
    (e.g. ``us-central1-a`` → ``us-central1``).

    Args:
        zone: GCP zone identifier.

    Returns:
        The region portion, or the original string if not zone-shaped.
    """
    if not zone:
        return zone
    parts = zone.rsplit("-", 1)
    if len(parts) == 2 and len(parts[1]) == 1 and parts[1].isalpha():
        return parts[0]
    return zone


_QUOTA_PROJECT = re.compile(r"required permission to use project ([\w.:-]+?)\.?(?:\s|$)")


def quota_project_denied(exc: BaseException) -> Optional[str]:
    """The project a call was charged to, when Google refused it there (USER_PROJECT_DENIED).

    Google charges each call to the login's quota project (in Cloud Shell, the current project,
    through GOOGLE_CLOUD_QUOTA_PROJECT), not to the project being read; without
    serviceusage.services.use there, every call fails, whatever access the scanned projects give.
    """
    text = str(exc)
    if "USER_PROJECT_DENIED" not in text:
        return None
    match = _QUOTA_PROJECT.search(text)
    return match.group(1) if match else ""


QUOTA_FROM_ENV = "GOOGLE_CLOUD_QUOTA_PROJECT"
QUOTA_FROM_KEY_FILE = "the GOOGLE_APPLICATION_CREDENTIALS file"
QUOTA_FROM_ADC = "the application-default login"


def effective_quota_project(credentials) -> tuple:
    """``(project, source)``: the project Google charges this sign-in's calls to, and where that
    setting came from. ``("", "")`` when the credentials name none.

    The client libraries send the credentials' quota project with every call. google-auth takes it
    from GOOGLE_CLOUD_QUOTA_PROJECT when that is set (Cloud Shell sets it to the current project),
    else from the credentials file.
    """
    project = getattr(credentials, "quota_project_id", None) or ""
    if not isinstance(project, str) or not project:
        return "", ""
    if os.environ.get(QUOTA_FROM_ENV) == project:
        return project, QUOTA_FROM_ENV
    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return project, QUOTA_FROM_KEY_FILE
    return project, QUOTA_FROM_ADC


def _first_line(exc: BaseException, limit: int = 200) -> str:
    line = (str(exc).strip().splitlines() or [type(exc).__name__])[0]
    return line if len(line) <= limit else line[: limit - 3] + "..."


def _validate_explicit_projects(
    credentials: google_credentials.Credentials,
    project_ids: list[str],
    skipped: Optional[list] = None,
) -> list[str]:
    """Validate explicitly provided project IDs against the Resource Manager API."""
    from google.cloud import resourcemanager_v3  # deferred — not needed for --mock or --dry-run

    client = resourcemanager_v3.ProjectsClient(credentials=credentials)
    validated: list[str] = []
    denied_by: Optional[str] = None
    for raw_id in project_ids:
        project_id = raw_id.strip()
        if not project_id:
            continue
        try:
            project = client.get_project(name=f"projects/{project_id}")
            validated.append(project.project_id)
            logger.debug("Validated project: %s (%s)", project.project_id, project.display_name)
        except Exception as exc:
            logger.debug("Project %s: %s", project_id, exc)
            consumer = quota_project_denied(exc)
            if consumer is not None:
                denied_by = consumer
                logger.warning(
                    "Project %s not checked: API calls are charged to quota project %s, which "
                    "refuses them (USER_PROJECT_DENIED)",
                    project_id,
                    consumer or "(unknown)",
                )
            else:
                logger.warning(
                    "Project %s not accessible: %s — skipping", project_id, _first_line(exc)
                )
            if skipped is not None:
                skipped.append((project_id, exc))
    if not validated:
        if denied_by is not None:
            _exit_quota_project_denied(denied_by)
        _exit_no_projects()
    return validated


# Google creates ``sys-<digits>`` projects itself (Apps Script and Workspace features). They have
# no billing account and normally no API enabled, so there is nothing to size in them.
_GOOGLE_SYSTEM_PROJECT = re.compile(r"sys-\d+")


def is_google_system_project(project_id: str) -> bool:
    """Whether the ID is one of Google's auto-created ``sys-<digits>`` projects."""
    return _GOOGLE_SYSTEM_PROJECT.fullmatch(project_id) is not None


def _search_active_projects(credentials: google_credentials.Credentials) -> tuple[list[str], int]:
    """``(project_ids, google_system_project_count)`` for every ACTIVE project the login can see.

    Google lists only the projects the identity may read (``resourcemanager.projects.get``) and
    does not report the others, so a project missing here is invisible to this login, not absent.
    Google's ``sys-<digits>`` projects are counted, not returned.
    """
    from google.cloud import resourcemanager_v3

    client = resourcemanager_v3.ProjectsClient(credentials=credentials)
    projects: list[str] = []
    system_projects = 0
    for project in client.search_projects(query="state:ACTIVE"):
        if is_google_system_project(project.project_id):
            system_projects += 1
            logger.debug("Found Google system project: %s", project.project_id)
            continue
        projects.append(project.project_id)
        logger.debug("Found project: %s (%s)", project.project_id, project.display_name)
    return projects, system_projects


def _enumerate_all_projects(
    credentials: google_credentials.Credentials,
    include_system_projects: bool = False,
) -> list[str]:
    """Enumerate all ACTIVE projects accessible to the credential.

    Google's auto-created ``sys-<digits>`` projects are left out unless
    ``include_system_projects``; a project named with ``--projects`` or ``--project-file`` is
    never filtered.
    """
    from google.cloud import resourcemanager_v3

    client = resourcemanager_v3.ProjectsClient(credentials=credentials)
    projects: list[str] = []
    system_projects = 0
    try:
        for project in client.search_projects(query="state:ACTIVE"):
            if not include_system_projects and is_google_system_project(project.project_id):
                system_projects += 1
                logger.debug("Skipping Google system project: %s", project.project_id)
                continue
            projects.append(project.project_id)
            logger.debug("Found project: %s (%s)", project.project_id, project.display_name)
    except Exception as exc:
        logger.debug("Project search: %s", exc)
        consumer = quota_project_denied(exc)
        if consumer is not None:
            _exit_quota_project_denied(consumer)
        logger.error("Failed to enumerate projects: %s", _first_line(exc))
        _exit_no_projects()
    if system_projects:
        logger.info(
            "Left out %d Google system project(s) (sys-<number>); pass "
            "--include-system-projects to scan them",
            system_projects,
        )
    if not projects:
        _exit_no_projects()
    return projects


@dataclass
class ScopeFacts:
    """How the project list was chosen, and what else this login can see.

    ``mode`` is ``"named"`` (--projects / --project-file), ``"all"`` (default or --all) or
    ``"current"`` (--current-project).  ``visible`` is the number of other ACTIVE projects the
    login can see that are not being scanned, or ``None`` when that was not looked up or the lookup
    failed.  Google does not report projects the login cannot see, so ``visible`` is a floor on
    what exists, never a total.
    """

    mode: str
    scanned: int
    named: int = 0
    left_out_system: int = 0
    visible_not_scanned: Optional[int] = None
    visible_examples: list[str] = field(default_factory=list)
    lookup_error: str = ""


# How many of the unscanned-but-visible project IDs the console names; the count is complete.
_VISIBLE_EXAMPLES_SHOWN = 5


def describe_scope(
    credentials: google_credentials.Credentials,
    *,
    mode: str,
    scanned: list[str],
    named: int = 0,
    include_system_projects: bool = False,
) -> ScopeFacts:
    """What the scan covers and, for a named list, what else this login can see.

    Never raises: the scan must not stop because this extra look failed.  One project search
    answers it.  For ``mode="all"`` the scan already enumerated that list, so only the Google
    system projects left out are counted; for ``"named"`` and ``"current"`` it finds the other
    projects the login can read, which is the case where a short list hides most of an estate.
    """
    facts = ScopeFacts(mode=mode, scanned=len(scanned), named=named)
    try:
        visible, system = _search_active_projects(credentials)
    except Exception as exc:  # noqa: BLE001 - informational; a failure is logged, not fatal
        logger.warning("Could not list the other projects this login can see: %s", _first_line(exc))
        facts.lookup_error = _first_line(exc)
        return facts
    if mode == "all":
        facts.left_out_system = 0 if include_system_projects else system
        return facts
    others = sorted(set(visible) - set(scanned))
    facts.visible_not_scanned = len(others)
    facts.visible_examples = others[:_VISIBLE_EXAMPLES_SHOWN]
    return facts


_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"


def identity_of(credentials: google_credentials.Credentials) -> str:
    """The account the scan runs as, or ``""`` when it cannot be told.  Never raises.

    A service account or a GCE/Cloud Shell identity names itself on the credentials.  A user login
    does not, so ask Google who owns the access token (the ``email`` scope is not in this tool's
    token, so a user login can show up without one; that is reported as unknown, not guessed).
    """
    for attr in ("service_account_email", "signer_email"):
        value = getattr(credentials, attr, None)
        if isinstance(value, str) and value and value != "default":
            return value
    token = getattr(credentials, "token", None)
    if not isinstance(token, str) or not token:
        return ""
    try:
        import requests  # google-auth's transport already depends on it

        response = requests.get(_TOKENINFO_URL, params={"access_token": token}, timeout=5)
        email = response.json().get("email", "") if response.ok else ""
    except Exception as exc:  # noqa: BLE001 - informational only
        logger.debug("Could not look up the account behind the access token: %s", exc)
        return ""
    return email if isinstance(email, str) else ""


def _detect_current_project(
    credentials: google_credentials.Credentials,
) -> list[str]:
    """Detect the active project via ADC default project or gcloud config."""
    from google.cloud import resourcemanager_v3

    # Try ADC default project first (most reliable in Cloud Shell / GCE).
    try:
        _, project_id = google.auth.default()
        if project_id:
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            project = client.get_project(name=f"projects/{project_id}")
            logger.debug("Auto-detected project from ADC: %s", project.project_id)
            return [project.project_id]
    except Exception:
        pass

    # Fall back to gcloud config.
    try:
        result = subprocess.run(
            ["gcloud", "config", "get-value", "project"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            project_id = result.stdout.strip()
            client = resourcemanager_v3.ProjectsClient(
                credentials=credentials
            )  # noqa: F821 (imported above)
            project = client.get_project(name=f"projects/{project_id}")
            logger.debug("Auto-detected project from gcloud config: %s", project.project_id)
            return [project.project_id]
    except Exception as exc:
        logger.debug("gcloud config get-value project failed: %s", exc)

    _exit_no_projects()
    return []  # unreachable; satisfies type checker


def _print_auth_error(detail: str) -> None:
    """Print a context-aware authentication error message to stderr."""
    in_cloud_shell = bool(os.environ.get("CLOUD_SHELL"))
    in_gce = bool(os.environ.get("GOOGLE_CLOUD_PROJECT") and not in_cloud_shell)

    from rich.console import Console
    from rich.panel import Panel

    console = Console(stderr=True)
    lines = [f"[bold red]Authentication failed:[/bold red] {detail}", ""]

    if in_cloud_shell:
        lines += [
            "[bold]Running in Google Cloud Shell:[/bold]",
            "  Your session may have expired. Close and reopen Cloud Shell, then retry.",
        ]
    elif in_gce:
        lines += [
            "[bold]Running on GCE (Workload Identity):[/bold]",
            "  1. Ensure a service account with the required roles is attached to this VM.",
            "  2. Grant [cyan]roles/cloudasset.viewer[/cyan] and [cyan]roles/compute.viewer[/cyan]"
            " at the organization or project level.",
        ]
    else:
        lines += [
            "[bold]Running locally:[/bold]",
            "  Option 1 (recommended): Run [cyan]gcloud auth application-default login[/cyan]"
            " and retry.",
            "  Option 2: Set [cyan]GOOGLE_APPLICATION_CREDENTIALS[/cyan] to a service account"
            " key file path.",
        ]

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]Rubrik Discovery — Auth Error[/bold]",
            border_style="red",
        )
    )


def _exit_quota_project_denied(consumer: str) -> None:
    """Exit explaining that the quota project refuses the calls, with the fix."""
    from rich.console import Console

    project = consumer or "the quota project"
    from_env = os.environ.get("GOOGLE_CLOUD_QUOTA_PROJECT")
    source = (
        " (set by GOOGLE_CLOUD_QUOTA_PROJECT; Cloud Shell sets it to the current project)"
        if from_env and from_env == consumer
        else ""
    )
    logger.error(
        "No project could be read: API calls are charged to quota project %s, which refuses "
        "them (USER_PROJECT_DENIED)",
        project,
    )
    Console(stderr=True).print(
        f"[bold red]No project could be read.[/bold red] Google charges every API call to the "
        f"quota project [cyan]{project}[/cyan]{source}, and this sign-in may not use services "
        "there (it needs roles/serviceusage.serviceUsageConsumer). This is not about access to the "
        "projects being scanned.\n"
        "Fix: stop sending that quota project, or name one where you have Service Usage Consumer:\n"
        "  [cyan]unset GOOGLE_CLOUD_QUOTA_PROJECT[/cyan]\n"
        "  [cyan]export GOOGLE_CLOUD_QUOTA_PROJECT=<project>[/cyan]\n"
        "See docs/troubleshooting.md#gcp-quota-project-denied.",
        highlight=False,
    )
    sys.exit(1)


def _exit_no_projects() -> None:
    """Exit with a helpful message when no projects are found."""
    from rich.console import Console

    Console(stderr=True).print(
        "[bold red]No accessible projects found.[/bold red]\n"
        "Use [cyan]--projects id1,id2[/cyan] or [cyan]--project-file FILE[/cyan] "
        "to specify project IDs.",
        highlight=False,
    )
    sys.exit(1)

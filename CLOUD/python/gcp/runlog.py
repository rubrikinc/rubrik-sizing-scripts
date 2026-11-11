"""GCP side of the run log: what to do about each kind of error, and the console that logs itself.

The log itself (a transcript of the screen, the digest) is ``runlog_core``, shared by the three
tools. This module holds what is specific to GCP: the fixes, which names to treat as one problem,
the header, and a console whose output also goes to the log. Each fix has an id that is also a
section in ``docs/troubleshooting.md``.
"""

from __future__ import annotations

import io
import logging
import os
import re
import textwrap

import auth
import preflight
import runlog_core as core
from rich.console import Console
from rich.markup import escape
from runlog_core import Solution

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGES = (
    "google-auth",
    "google-cloud-asset",
    "google-cloud-compute",
    "google-cloud-storage",
    "google-cloud-spanner",
    "google-cloud-bigtable",
    "google-cloud-alloydb",
    "google-cloud-backupdr",
    "google-api-python-client",
    "rich",
)

_PROJECT = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"

SOLUTIONS = (
    # First: a retry is not a loss, whatever error it quotes.
    Solution(
        "gcp-transient-retry",
        re.compile(r"Transient GCP error"),
        "A call failed for a reason that usually passes and the tool is retrying it. Nothing is "
        "lost unless the same project then reports 'collection failed' for that service; look "
        "that message up instead. Spanner listings can retry for up to 10 minutes.",
    ),
    Solution(
        "gcp-quota-project-denied",
        re.compile(r"USER_PROJECT_DENIED"),
        "Google charges every API call to your quota project, and this sign-in may not use "
        "services there (it needs roles/serviceusage.serviceUsageConsumer), so the call was "
        "refused whatever access the scanned project gives. In Cloud Shell the quota project is "
        "the current project, through GOOGLE_CLOUD_QUOTA_PROJECT. Stop sending it, or name a "
        "project where you have Service Usage Consumer.\n"
        "Run: unset GOOGLE_CLOUD_QUOTA_PROJECT\n"
        "Run: export GOOGLE_CLOUD_QUOTA_PROJECT=<project>",
    ),
    # Before the disabled-API fixes: the access check files this one as ServiceDisabled too.
    Solution(
        "gcp-quota-project-warning",
        re.compile(r"requires a quota project|without a quota project"),
        "Your application-default login names no quota project, the project Google charges API "
        "calls to, and some APIs (Cloud Asset Inventory among them) refuse calls without one. Set "
        "one you can use, usually one of the scanned projects, with that API enabled.\n"
        "Run: gcloud auth application-default set-quota-project <project>",
    ),
    # Before the per-project billing fix: the access check marks billing that is off in the quota
    # project with this code, and both fixes match the word "BillingDisabled".
    Solution(
        "gcp-quota-project-billing-disabled",
        re.compile(r"QuotaProjectBillingDisabled"),
        "Billing is off in your quota project, the project Google charges every call to, so every "
        "call that needs billing is refused in every scanned project. Link a billing account to "
        "the quota project named in the error, or charge a project that has billing on.\n"
        "Run: gcloud billing projects link <quota-project> --billing-account=<BILLING_ACCOUNT_ID>\n"
        "Run: gcloud auth application-default set-quota-project <other-project>",
    ),
    Solution(
        "gcp-billing-disabled",
        re.compile(
            r"BillingDisabled|BILLING_DISABLED|billing must be enabled|requires billing to be "
            r"enabled|[Aa]bsent billing account|billing account for the project is not found"
        ),
        "Billing is off in the project the error names, so Google refuses the call. When that is "
        "the scanned project, it holds nothing that needs billing: link a billing account, or "
        "leave the project out. When every project's error names one other project, that is your "
        "quota project; see gcp-quota-project-billing-disabled.\n"
        "Run: gcloud billing projects link <project> --billing-account=<BILLING_ACCOUNT_ID>",
    ),
    Solution(
        "gcp-api-disabled-in-billing-project",
        re.compile(
            r"has not been used in project (?P<project>[\w-]+) before or it is disabled"
            r".*?/apis/api/(?P<service>[\w.]+)/overview",
            re.S,
        ),
        "Enable {service} in the project the error names ({project} here). That is the project "
        "Google charges the call to: the scanned project itself, or the quota project of your "
        "login when every project's error names the same other project.\n"
        "Run: gcloud services enable {service} --project {project}\n"
        "Or charge a project where it is on:\n"
        "Run: gcloud auth application-default set-quota-project <project>",
    ),
    Solution(
        "gcp-api-disabled",
        re.compile(
            r"API has not been used in project|it is disabled|SERVICE_DISABLED|accessNotConfigured"
        ),
        "The API is not enabled. Enable it in the project named in the error, or leave that "
        "collector out with --collectors.\n"
        "Run: gcloud services enable <service>.googleapis.com --project <project>",
    ),
    Solution(
        "gcp-org-policy",
        re.compile(
            r"Operation denied by(?!\s*\[IAM)|prohibited by organization|VPC_SERVICE_CONTROLS|"
            r"org ?policy",
            re.I,
        ),
        "An organization policy or a VPC Service Controls perimeter blocks this call. Ask your "
        "Google Cloud organization admin to allow this identity, or leave the project out.",
    ),
    Solution(
        "gcp-permission-denied",
        re.compile(
            r"(?:Required|Permission) '(?P<permission>[\w.]+)'|Request denied by Cloud IAM|"
            r"PERMISSION_DENIED|PermissionDenied|notAuthorized|not authorized to make this request|"
            r"does not have [\w.]+ access|Missing IAM permission",
        ),
        "The identity cannot read this project. Grant a role that includes the read permission "
        "named in the pre-flight table (for example Viewer on the project) to the identity you "
        "signed in with, or leave the project out.",
    ),
    Solution(
        "gcp-no-projects",
        re.compile(
            r"Project \S+ not accessible|No accessible projects found|Failed to enumerate projects|"
            r"scope\.projects in the config file"
        ),
        "A project could not be read, so it is not scanned: a typo, a deleted project, or no "
        "resourcemanager.projects.get on it. Compare with what the sign-in can see, and pass "
        "projects with --projects or --project-file (a config file's scope.projects is not used).\n"
        "Run: gcloud projects list",
    ),
    Solution(
        "gcp-no-credentials",
        re.compile(
            r"DefaultCredentialsError|Could not automatically determine credentials|default credentials were not found"
        ),
        "No Google credentials were found. Sign in, then run the scan again.\n"
        "Run: gcloud auth application-default login",
    ),
    Solution(
        "gcp-credentials-expired",
        re.compile(
            r"RefreshError|invalid_grant|Reauthentication is needed|expired or revoked", re.I
        ),
        "Your Google sign-in can no longer be refreshed: it expired, the password changed or "
        "access was revoked. Sign in again, then run the scan again. For a service account, use a "
        "key that still exists.\n"
        "Run: gcloud auth application-default login",
    ),
    Solution(
        "gcp-rate-limited",
        # 429 only as a number of its own, never inside a project ID, a number or a path.
        re.compile(
            r"RESOURCE_EXHAUSTED|Quota exceeded|rate limit|TooManyRequests|Too Many Requests|"
            r"(?<![\w/-])429(?![\w-])"
        ),
        "Google is rate limiting the requests. Run the scan again later, or lower --workers. "
        "Cloud Asset listings are already paced to stay under their per-minute quota, and the "
        "quota belongs to the project the calls are charged to, so every worker shares it.",
    ),
    Solution(
        "gcp-asset-inventory",
        re.compile(r"Asset enumeration failed|Org-wide asset enumeration failed"),
        "The Cloud Asset Inventory could not be read. Enable the Cloud Asset API in the project "
        "your calls are charged to and grant roles/cloudasset.viewer (on the organization or "
        "folder for --org or --folder), or leave it out with --collectors. Asset data is in the "
        "JSON only.",
    ),
    Solution(
        "gcp-project-not-found",
        re.compile(r"PROJECT_NOT_FOUND|Project '?[\w-]+'? not found"),
        "The project was not found or this identity cannot see it. Check the spelling in "
        "--projects and that the sign-in can list the project.\n"
        "Run: gcloud projects list",
    ),
    Solution(
        "gcp-client-library-missing",
        re.compile(r"SdkMissing|cannot import name|No module named"),
        "A Google client library is missing from this environment. Install the requirements:\n"
        "Run: pip install -r requirements.txt",
    ),
)

# The same failure on each project is one problem: mask project ids where they appear.
MASKS = (
    re.compile(rf"(?<=project ){_PROJECT}"),
    re.compile(rf"(?<=projects/){_PROJECT}"),
    re.compile(rf"(?<=project=){_PROJECT}"),
)

_SCANNED_PROJECT = re.compile(rf"for project (?P<project>{_PROJECT})")
_BILLING = re.compile(
    r"has not been used in project (?P<project>[\w-]+) before or it is disabled"
    r".*?/apis/api/(?P<service>[\w.]+)/overview",
    re.S,
)
# What a message is about, from its label: the access check names the service ("bigtable instances")
# and a collector names itself ("Bigtable collection failed for project ..."). The first match wins,
# so the more specific words come first.
_SUBSYSTEMS = (
    ("bigtable", re.compile(r"bigtable", re.I)),
    ("alloydb", re.compile(r"alloydb", re.I)),
    ("spanner", re.compile(r"spanner", re.I)),
    ("cloud sql", re.compile(r"cloud ?sql|sqladmin", re.I)),
    ("bigquery", re.compile(r"bigquery", re.I)),
    ("backup and dr", re.compile(r"backup", re.I)),
    ("cloud asset inventory", re.compile(r"asset", re.I)),
    ("cloud storage", re.compile(r"storage|bucket", re.I)),
    ("compute", re.compile(r"compute|disk|instances", re.I)),
)


def cause(message: str):
    """``(key, project)`` naming what a message is about, or None when it has no known fix.

    The access check and the collector word the same failure differently, and the same failure on
    each project is one problem, so the key is the fix, the service it is about and, for an API
    that is off, the project Google charges (enabling it elsewhere does not help).
    """
    found = core.solve(message)
    if found is None:
        return None
    solution_id = found[0]
    scanned = _SCANNED_PROJECT.search(message)
    scope = scanned.group("project") if scanned else ""
    billing = _BILLING.search(message)
    if billing:
        return f"{solution_id}|{billing.group('service')}|{billing.group('project')}", scope
    # Billing that is off: the access check and the collector word it differently, and only the
    # project the error names tells the quota project's problem from a scanned project's.
    if solution_id in ("gcp-billing-disabled", "gcp-quota-project-billing-disabled"):
        solution_id = f"gcp-billing|{preflight.named_project(message)}"
    label = _SCANNED_PROJECT.sub("", message.split(":", 1)[0])
    for name, pattern in _SUBSYSTEMS:
        if pattern.search(label):
            return f"{solution_id}|{name}", scope
    return None


core.configure(SOLUTIONS, MASKS, cause, noun="project")

log = logging.getLogger(__name__)

_PRINT_OPTIONS = (
    "sep",
    "end",
    "style",
    "justify",
    "overflow",
    "no_wrap",
    "emoji",
    "markup",
    "highlight",
    "width",
    "height",
    "crop",
    "soft_wrap",
)


class LoggedConsole(Console):
    """A rich console whose output also goes to the run log, as the plain text a person saw.

    Spinners and other redraws are not logged; a print that shows nothing is skipped.
    """

    def print(self, *objects, **kwargs) -> None:  # type: ignore[override]
        super().print(*objects, **kwargs)
        sink = core.current()
        if sink is None:
            return
        try:
            probe = Console(
                file=io.StringIO(),
                width=self.width,
                force_terminal=False,
                color_system=None,
                legacy_windows=False,
            )
            probe.print(*objects, **{k: v for k, v in kwargs.items() if k in _PRINT_OPTIONS})
            text = probe.file.getvalue().rstrip("\n")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - logging must never stop a run
            return
        if objects and not text.strip():
            return
        sink.write(text)


def start(argv: list) -> None:
    """Write the header: what ran, with what, so the log explains itself when read later."""
    core.write_header(
        "GCP sizing tool",
        [("Code", core.code_version(HERE)), ("Packages", core.package_versions(PACKAGES))],
        argv,
    )


def fix_lines(text: str, service: str = "", code: str = "") -> list:
    return core.fix_lines(text, service, code)


# A fix lists at most this many per-project commands; the pre-flight CSV names every project.
_FIX_COMMANDS_SHOWN = 10
_WIDTH = 96


def _fix(sentences: list, commands: list, anchor: str) -> list:
    """Fix lines as ``core.fix_lines`` lays them out: wrapped sentences, unwrapped commands."""
    lines: list = []
    for sentence in sentences:
        for wrapped in textwrap.wrap(sentence, width=_WIDTH - 5) or [""]:
            lines.append(("Fix: " if not lines else "     ") + wrapped)
    lines += [f"     Run: {command}" for command in commands]
    lines.append(f"     ({core.DOC}#{anchor})")
    return lines


def _per_project_commands(scopes: list, command: str) -> list:
    """``command`` (with ``{project}``) once per project, cut at ``_FIX_COMMANDS_SHOWN``."""
    commands = [command.format(project=p) for p in scopes[:_FIX_COMMANDS_SHOWN]]
    if len(scopes) > _FIX_COMMANDS_SHOWN:
        rest = len(scopes) - _FIX_COMMANDS_SHOWN
        commands.append(
            f"(and {rest} more projects; every one is in {preflight.FILE_PREFIX}-*.csv)"
        )
    return commands


def _group_fix(group: dict) -> list:
    """The fix for one blocked service in the scanned projects, naming each of them.

    Google's text names one project; the fix covers every project the service is blocked in.
    """
    scopes = [s for s in group.get("scopes") or [] if s]
    code, api = group.get("code", ""), group.get("api", "")
    if code == "ServiceDisabled" and api and scopes:
        return _fix(
            [
                f"Enable {api} in each project it is off in, or leave the collector out with --collectors."
            ],
            _per_project_commands(scopes, f"gcloud services enable {api} --project {{project}}"),
            "gcp-api-disabled",
        )
    if code == "BillingDisabled" and scopes:
        return _fix(
            [
                "Billing is off in these projects, so they hold nothing that needs billing. Link a "
                "billing account to each one you expect data from, or leave them out."
            ],
            _per_project_commands(
                scopes,
                "gcloud billing projects link {project} --billing-account=<BILLING_ACCOUNT_ID>",
            ),
            "gcp-billing-disabled",
        )
    if code == "PermissionDenied" and scopes and group.get("permission"):
        return _fix(
            [
                f"Grant the identity a role with {group['permission']} (Viewer covers the list "
                "permissions) in each of these projects, or leave them out."
            ],
            _per_project_commands(
                scopes,
                "gcloud projects add-iam-policy-binding {project} --member=<MEMBER> --role=roles/viewer",
            ),
            "gcp-permission-denied",
        )
    return core.fix_lines(group.get("message", ""), group["service"], code)


def problem_block(groups: list) -> list:
    """The blocked pre-flight groups as lines (the error, then the fix), and each one is counted in
    the digest at the end of the run."""
    for group in groups:
        text = (
            f"{group['service']}: {group.get('code') or group['status']} {group.get('message', '')}"
        )
        for scope in group.get("scopes") or [""]:
            core.ISSUES.add(logging.WARNING, "preflight", text, scope)
    return core.problem_lines(groups, _group_fix)


# Lists the user's projects with billing and how many of the tool's APIs each has on, to pick a
# quota project. Printed, not run: the tool has no billing or Service Usage client.
CANDIDATE_LOOP = (
    "for p in $(gcloud projects list --format='value(projectId)'); do "
    "b=$(gcloud billing projects describe $p --format='value(billingEnabled)'); "
    "n=$(gcloud services list --enabled --project $p --format='value(config.name)' | "
    "grep -cE '^(cloudresourcemanager|cloudasset|compute|spanner|bigtableadmin|alloydb|backupdr)"
    '[.]googleapis[.]com$\'); echo "$p billing=$b apis=$n/7"; done'
)


def quota_source_line(project: str, source: str) -> str:
    """The line that says which project the calls are charged to, and why."""
    if not project:
        return (
            "Quota project: none (the login names no project to charge calls to; some APIs "
            "refuse calls without one)"
        )
    return f"Quota project: {project} (from {source}); every API call is charged to it"


def account_line(email: str) -> str:
    """The line that says who the scan runs as."""
    if not email:
        return (
            "Signed in as: unknown (the login does not name itself; run "
            "'gcloud auth application-default print-access-token' to check which login this is)"
        )
    return f"Signed in as: {email}"


def scope_lines(facts) -> list:
    """How the project list was chosen and, for a named list, how much else this login can see.

    ``facts`` is ``auth.ScopeFacts``.  The wording says "can see", never "exists": Google lists
    only the projects the login may read and does not report the rest, so a count here is a floor.
    """
    if facts.mode == "named":
        lines = [
            f"Scope: the {facts.named} project(s) you named with --projects or --project-file; "
            f"{facts.scanned} readable and scanned."
        ]
    elif facts.mode == "current":
        lines = ["Scope: the current project only (--current-project)."]
    else:
        lines = [f"Scope: all {facts.scanned} active project(s) this login can see."]
        if facts.left_out_system:
            lines.append(
                f"       Left out {facts.left_out_system} Google system project(s) "
                "(sys-<number>); pass --include-system-projects to scan them."
            )
        lines.append(
            "       A project this login cannot read is not listed and not reported, so a "
            "missing project may be a missing grant."
        )
    if facts.lookup_error:
        lines.append("       Could not check what else this login can see (see the log).")
    elif facts.visible_not_scanned:
        shown = ", ".join(facts.visible_examples)
        more = facts.visible_not_scanned - len(facts.visible_examples)
        names = f" ({shown}{f' and {more} more' if more > 0 else ''})"
        lines.append(
            f"       WARNING: this login can also see {facts.visible_not_scanned} other active "
            f"project(s) not in the scan{names}. Pass --all to scan every project it can see."
        )
    elif facts.visible_not_scanned == 0 and facts.mode != "all":
        lines.append("       This login can see no other active projects.")
    return lines


def quota_block(problems: list, total: int, source: str = "") -> list:
    """The quota project's problems, each once, whatever the number of projects it blocks.

    ``problems`` come from ``preflight.quota_problems``; ``total`` is the number of projects
    checked. Each problem is counted once per service in the digest at the end of the run.
    """
    lines: list = []
    for problem in problems:
        project, code = problem["project"], problem["code"]
        scopes, services, apis = problem["scopes"], problem["services"], problem["apis"]
        reach = (
            f"all {total} projects"
            if len(scopes) >= total
            else f"{len(scopes)} of {total} projects"
        )
        what = ", ".join(services)
        for service in services:
            for scope in scopes:
                core.ISSUES.add(
                    logging.WARNING, "preflight", f"{service}: {code} {problem['message']}", scope
                )
        other = "gcloud auth application-default set-quota-project <other-project>"
        if source == auth.QUOTA_FROM_ENV:
            other = "export GOOGLE_CLOUD_QUOTA_PROJECT=<other-project>"
        if code == preflight.QUOTA_API_OFF:
            head = f"Quota project {project} has {', '.join(apis) or what} disabled; this affects {reach}."
            fix = _fix(
                [
                    f"These rows are NOT CHECKED, not missing: {what}. Enable the APIs once, in the "
                    "quota project, or charge a project where they are on. Nothing needs to change "
                    "in the scanned projects."
                ],
                [f"gcloud services enable {' '.join(apis)} --project {project}", other],
                "gcp-api-disabled-in-billing-project",
            )
        elif code == preflight.QUOTA_BILLING_OFF:
            head = f"Quota project {project} has billing disabled; this affects {reach} ({what})."
            fix = _fix(
                [
                    "These rows are NOT CHECKED, not missing. Link a billing account to the quota "
                    f"project (console: Billing > Linked account, for project {project}), or charge a "
                    "project that has billing on. To find one, list your projects with billing and "
                    "the APIs the tool needs:"
                ],
                [
                    f"gcloud billing projects link {project} --billing-account=<BILLING_ACCOUNT_ID>",
                    other,
                    CANDIDATE_LOOP,
                ],
                "gcp-quota-project-billing-disabled",
            )
        elif code == preflight.QUOTA_DENIED:
            head = (
                f"Quota project {project or '(unknown)'} refuses the calls (USER_PROJECT_DENIED); "
                f"this affects {reach} ({what})."
            )
            fix = _fix(
                [
                    "These rows are NOT CHECKED, not missing. The sign-in needs "
                    "roles/serviceusage.serviceUsageConsumer in the quota project, or name another "
                    "quota project."
                ],
                [other],
                "gcp-quota-project-denied",
            )
        else:
            head = f"The login names no quota project; this affects {reach} ({what})."
            fix = _fix(
                ["These rows are NOT CHECKED, not missing. Set a quota project you can use."],
                ["gcloud auth application-default set-quota-project <project>"],
                "gcp-quota-project-warning",
            )
        lines.append(f"  {head}")
        if problem.get("message"):
            lines.append(f"      Error: {core.one_line(problem['message'], 300)}")
        lines += [f"      {line}" for line in fix]
    return lines


def install_stop_handlers() -> None:
    """Ctrl-C, SIGTERM and a closing terminal write the last line of the log, then exit."""
    core.install_stop_handlers()


def crashed(exc: BaseException) -> None:
    """Write how a run that raised ended, so its log is not simply cut off."""
    core.crashed(exc)


def finish(console: Console) -> None:
    """The last lines of the run, on the screen and in the log: every distinct problem once, then
    the line that says the scan finished."""
    console.print()
    console.print("[bold]Run summary[/bold]")
    for line in core.digest_lines():
        console.print(escape(line))
    core.finished()

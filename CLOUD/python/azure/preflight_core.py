"""Pre-flight access check shared by the AWS, Azure and GCP tools.

Before a scan, each tool makes one cheap, read-only call per service and scope (an AWS region, an
Azure subscription, a GCP project) and records whether it worked. The report then says which
output files the scan will fill and which it will leave empty or partial.

The calls are the ones the collectors make, limited to one result, so a pass means the scan can
read that service with the sign-in in use. The check never writes anything, never raises, and
never stops the scan. Only an error *code* is kept, never the provider's message, because
messages can name accounts and resources.
"""

from __future__ import annotations

import csv
import io
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

OK = "ok"
DENIED = "denied"
NOT_ENABLED = "not_enabled"
ERROR = "error"
SKIPPED = "skipped"

CAPTURED = "captured"
DROPPED = "dropped"
UNKNOWN = "unknown"
NOT_REQUESTED = "not requested"

_OUTCOME = {
    OK: CAPTURED,
    DENIED: DROPPED,
    NOT_ENABLED: DROPPED,
    ERROR: UNKNOWN,
    SKIPPED: NOT_REQUESTED,
}

CSV_COLUMNS = (
    "Owner",
    "OwnerName",
    "Scope",
    "Service",
    "Permission",
    "Access",
    "Outcome",
    "ResourcesFound",
    "Detail",
    "OutputFilesAffected",
)

# What each status means, in the words the report and the terminal summary use.
STATUS_TEXT = {
    OK: "readable",
    DENIED: "access denied",
    NOT_ENABLED: "not enabled",
    ERROR: "could not be checked",
    SKIPPED: "not requested",
}

Classifier = Callable[[BaseException], "tuple[str, str]"]


@dataclass(frozen=True)
class Probe:
    """One read-only call. ``call`` returns whether it saw a resource, or None if it cannot tell."""

    service: str
    scope: str
    call: Callable[[], Optional[bool]]
    affects: tuple = ()
    hint: str = ""  # what to do if it is blocked; shown on the terminal, not written to the CSV
    permission: str = ""  # the permission the call needs, in the cloud's own words


@dataclass
class Check:
    owner: str
    owner_name: str
    scope: str
    service: str
    status: str
    found: Optional[bool] = None
    code: str = ""
    affects: tuple = ()
    hint: str = ""
    permission: str = ""
    # What the cloud said, on one line. Shown on the screen and in the log, never in the table or the
    # CSV: it can name accounts and resources, which the anonymizer cannot label inside text.
    message: str = ""

    @property
    def outcome(self) -> str:
        return _OUTCOME[self.status]

    def to_row(self) -> dict:
        """One CSV row. The files affected are named only when the service is not readable."""
        blocked = self.status != OK
        return {
            "Owner": self.owner,
            "OwnerName": self.owner_name,
            "Scope": self.scope,
            "Service": self.service,
            "Permission": self.permission,
            "Access": STATUS_TEXT[self.status],
            "Outcome": self.outcome,
            "ResourcesFound": "" if self.found is None else ("yes" if self.found else "no"),
            "Detail": self.code,
            "OutputFilesAffected": "; ".join(self.affects) if blocked else "",
        }


def brief_message(exc: BaseException, limit: int = 300) -> str:
    """The error's text on one line, cut at ``limit`` characters."""
    text = " ".join(str(exc).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def skipped(
    owner: str,
    owner_name: str,
    scope: str,
    service: str,
    affects: tuple = (),
    reason: str = "",
    permission: str = "",
) -> Check:
    """A service the run is not collecting (``--services``, ``--no-cost``, ``--skip-*``)."""
    return Check(owner, owner_name, scope, service, SKIPPED, None, reason, affects, "", permission)


def run_probes(
    owner: str,
    owner_name: str,
    probes: Iterable[Probe],
    classify: Classifier,
    max_workers: int = 8,
) -> list:
    """Run the probes a few at a time. Results come back in the order the probes were given.

    A probe that raises is classified, never propagated, so the check cannot stop a scan.
    """
    probe_list = list(probes)

    def one(probe: Probe) -> Check:
        try:
            found = probe.call()
        except Exception as exc:  # noqa: BLE001 - the check must never stop the scan
            try:
                status, code = classify(exc)
            except Exception:  # noqa: BLE001
                status, code = ERROR, type(exc).__name__
            return Check(
                owner,
                owner_name,
                probe.scope,
                probe.service,
                status,
                None,
                code,
                probe.affects,
                probe.hint,
                probe.permission,
                brief_message(exc),
            )
        return Check(
            owner,
            owner_name,
            probe.scope,
            probe.service,
            OK,
            found,
            "",
            probe.affects,
            "",
            probe.permission,
        )

    if not probe_list:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(probe_list)))) as pool:
        return list(pool.map(one, probe_list))


def counts(checks: Iterable[Check]) -> dict:
    """How many checks ended in each outcome."""
    result = {CAPTURED: 0, DROPPED: 0, UNKNOWN: 0, NOT_REQUESTED: 0}
    for check in checks:
        result[check.outcome] += 1
    return result


def blocked_groups(checks: Iterable[Check]) -> list:
    """Checks that did not pass, one entry per service, status and error code.

    Each entry lists the scopes (regions, subscriptions, projects) it happened in, so a service
    denied in 17 regions is one line, not 17.
    """
    groups: dict = {}
    for check in checks:
        if check.status in (OK, SKIPPED):
            continue
        key = (check.service, check.status, check.code)
        group = groups.setdefault(
            key,
            {
                "service": check.service,
                "status": check.status,
                "code": check.code,
                "scopes": [],
                "affects": check.affects,
                "hint": check.hint,
                "message": "",
            },
        )
        if check.scope not in group["scopes"]:
            group["scopes"].append(check.scope)
        if check.message and not group["message"]:
            group["message"] = check.message
    return list(groups.values())


def _scope_text(scopes: list, limit: int) -> str:
    shown = ", ".join(scopes[:limit])
    return f"{shown} +{len(scopes) - limit} more" if len(scopes) > limit else shown


def summary_lines(
    checks: list, label: str = "", max_scopes: int = 4, show_scope: bool = True
) -> list:
    """Short terminal summary: one headline, then one line per blocked service."""
    total = counts(checks)
    checked = total[CAPTURED] + total[DROPPED] + total[UNKNOWN]
    groups = blocked_groups(checks)
    prefix = f"Pre-flight access check{' for ' + label if label else ''}: "
    if checked == 0:
        head = prefix + "nothing to check"
    elif groups:
        head = prefix + f"{total[CAPTURED]} of {checked} checks readable"
    else:
        head = (
            prefix + f"all {checked} check{'' if checked == 1 else 's'} readable, nothing blocked"
        )
    lines = [head]
    for group in groups:
        text = f"  {STATUS_TEXT[group['status']]}: {group['service']}"
        if show_scope and group["scopes"] and group["scopes"] != [""]:
            text += f" ({_scope_text(group['scopes'], max_scopes)})"
        if group["status"] != ERROR and group["affects"]:
            text += f" -> {'; '.join(group['affects'])} will be empty or partial"
        lines.append(text)
        if group["hint"] and group["status"] in (DENIED, NOT_ENABLED):
            lines.append(f"    to fix: {group['hint']}")
    return lines


# ── the table ────────────────────────────────────────────────────────────────

TABLE_HEADER = ("SERVICE", "PERMISSION", "ACCESS", "WHERE", "FOUND", "IMPACT")
_ACCESS_WORD = {
    OK: "granted",
    DENIED: "MISSING",
    NOT_ENABLED: "API NOT ENABLED",
    ERROR: "NOT CHECKED",
    SKIPPED: "not requested",
}
_WORST_FIRST = (DENIED, NOT_ENABLED, ERROR, OK)
_COLUMN_CAPS = (30, 68, 16, 72, 18)


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(0, width - 3)] + "..."


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _real_scopes(checks: list) -> list:
    seen: list = []
    for check in checks:
        if check.scope not in ("", "global") and check.scope not in seen:
            seen.append(check.scope)
    return seen


def _table_row(group: dict, scope_label: str, max_scopes: int, impact_width: int) -> tuple:
    checks = group["checks"]
    live = [c for c in checks if c.status != SKIPPED]
    if not live:
        reason = next((c.code for c in checks if c.code), "")
        return 4, [
            group["service"],
            group["permission"],
            _ACCESS_WORD[SKIPPED],
            "-",
            "-",
            reason or "-",
        ]
    statuses = {c.status for c in live}
    worst = next(status for status in _WORST_FIRST if status in statuses)
    scopes = _real_scopes(live)
    where = "-"
    if scope_label and len(scopes) > 1:
        if worst == OK:
            where = f"all {_plural(len(scopes), scope_label)}"
        else:
            bad = _real_scopes([c for c in live if c.status == worst])
            where = (
                f"{len(bad)} of {_plural(len(scopes), scope_label)}: {_scope_text(bad, max_scopes)}"
            )
    readable = [c for c in live if c.status == OK]
    seen = sum(1 for c in readable if c.found)
    if seen:
        found = "yes" if len(readable) == 1 else f"yes ({seen} of {len(readable)})"
    elif readable and all(c.found is False for c in readable):
        found = "none"
    else:
        found = "-"
    if worst == OK:
        impact = "-"
    elif worst == ERROR:
        codes = sorted({c.code for c in live if c.status == ERROR and c.code})
        impact = "unknown" + (f" ({', '.join(codes)})" if codes else "")
    else:
        impact = "; ".join(next((c.affects for c in live if c.affects), ())) or "-"
    rank = _WORST_FIRST.index(worst)
    return rank, [
        group["service"],
        group["permission"],
        _ACCESS_WORD[worst],
        where,
        found,
        _clip(impact, impact_width),
    ]


def table_lines(
    checks: list, scope_label: str = "", max_scopes: int = 2, impact_width: int = 70
) -> list:
    """A table of what the sign-in can read, one row per permission, the missing ones first.

    ``scope_label`` names the scopes in the WHERE column ("region", "project"); leave it empty
    when there is only one scope. Blocked rows say which output files they leave empty or partial,
    and a ``to fix`` line follows the table for each blocked service that has advice.
    """
    groups: dict = {}
    for check in checks:
        group = groups.setdefault(
            (check.service, check.permission),
            {"service": check.service, "permission": check.permission or "-", "checks": []},
        )
        group["checks"].append(check)
    ranked = sorted(
        (_table_row(g, scope_label, max_scopes, impact_width) for g in groups.values()),
        key=lambda item: item[0],
    )
    rows = [list(TABLE_HEADER)] + [row for _, row in ranked]
    widths = [
        min(max(len(row[i]) for row in rows), _COLUMN_CAPS[i]) for i in range(len(_COLUMN_CAPS))
    ]
    lines = []
    for number, row in enumerate(rows):
        cells = [_clip(row[i], widths[i]).ljust(widths[i]) for i in range(len(widths))]
        lines.append("  " + "  ".join(cells + [row[-1]]).rstrip())
        if number == 0:
            lines.append("  " + "  ".join("-" * w for w in widths) + "  ------")
    for group in blocked_groups(checks):
        if group["hint"] and group["status"] in (DENIED, NOT_ENABLED):
            lines.append(f"  to fix {group['service']}: {group['hint']}")
    return lines


def csv_text(rows: Iterable[dict]) -> str:
    """The report as CSV, every cell quoted and CRLF line ends, like the other output files."""
    out = io.StringIO()
    writer = csv.DictWriter(
        out, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_ALL, lineterminator="\r\n"
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row.get(name, "") for name in CSV_COLUMNS})
    return out.getvalue()


def file_name(prefix: str, stamp: str) -> str:
    """Underscores inside the prefix, a hyphen before the timestamp, like the other CSV files."""
    clean = re.sub(r"[^A-Za-z0-9]+", "_", prefix).strip("_")
    return f"{clean}-{stamp}.csv"

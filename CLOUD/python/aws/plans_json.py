"""The ``aws-backup-plans-info-<stamp>.json`` file of ``Get-AWSSizingInfo.ps1``.

PowerShell writes every backup plan it read (``$backupPlanList | ConvertTo-Json -Depth 10``): the
plan as AWS.Tools returns it, plus a ``Resources`` list of the explicit ARNs its selections name.
The collector keeps each plan in that shape (``plan_export``, without the SDK transport fields
``ResponseMetadata``, ``ContentLength`` and ``HttpStatusCode``); this module adds ``Resources`` and
writes the list.

``Resources`` holds explicit ARNs only: resources a selection reaches by tag are not added, as in
PowerShell. A plan whose details could not be read has no ``plan_export`` and is left out.
"""

from __future__ import annotations

import json
from typing import Iterable, Mapping

FILE_PREFIX = "aws-backup-plans-info"


def file_name(stamp: str) -> str:
    return f"{FILE_PREFIX}-{stamp}.json"


def plans_of(discovery: Mapping) -> list[dict]:
    """The plans of one discovery result in PowerShell's order: regions in scan order, the API's
    order within a region. The collection itself is in the order the regions finished, which
    changes from run to run."""
    ranks: dict[str, int] = {}
    for region in discovery.get("regions_scanned") or []:
        ranks.setdefault(region, len(ranks))
    plans = list(discovery.get("backup_plans") or [])
    return sorted(plans, key=lambda plan: ranks.get(plan.get("region"), len(ranks)))


def build(plans: Iterable[Mapping]) -> str:
    """The file's text for the plan dicts of one or more discovery results, in the order given.

    No plans (or none that could be read) is an empty list, which PowerShell also writes.
    """
    elements = []
    for plan in plans:
        export = plan.get("plan_export")
        if export:
            elements.append({**export, "Resources": list(plan.get("resources") or [])})
    return json.dumps(elements, indent=2, ensure_ascii=False) + "\n"

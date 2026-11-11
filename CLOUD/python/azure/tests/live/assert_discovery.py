#!/usr/bin/env python3
"""Assert the live Azure discovery JSON is well-formed against a REAL tenant.

The mocked unit suite proves the collectors shape their data correctly, but it
can't prove the tool survives a live Azure SDK round-trip: real
``DefaultAzureCredential`` resolution, subscription enumeration, the
recoveryservices / storage / cost management paths, and the
``DiscoveryResult`` → JSON serialisation. This script runs after a read-only
scan of an existing CI/CD subscription and asserts the run produced a valid,
structurally-complete discovery document — the kind of regression a customer
would otherwise hit first in their own Azure Cloud Shell.

Because the scan is read-only against whatever already lives in the
subscription (we deploy NO fixture), exact resource counts are unknowable. So
this asserts *structure and a clean run*, and only WARNS on an empty inventory
rather than failing.

Usage: assert_discovery.py <discovery.json>
"""

from __future__ import annotations

import json
import pathlib
import sys

# Top-level keys every rubrik-discovery JSON must carry (see
# models/inventory.py::DiscoveryResult).
REQUIRED_KEYS = (
    "schema_version",
    "tenant_id",
    "generated_at",
    "subscriptions",
    "compute",
    "backup_posture",
    "storage",
    "database",
    "cost",
    "backup_jobs",
    "total_vms",
    "total_disk_tb",
    "total_protected_vms",
    "total_unprotected_vms",
    "protection_coverage_pct",
)

# Keys whose values must be lists (per-subscription collections).
LIST_KEYS = (
    "subscriptions",
    "compute",
    "backup_posture",
    "storage",
    "database",
    "cost",
    "backup_jobs",
)

# Inventory collections that contribute to the "did we see anything?" signal.
INVENTORY_KEYS = ("compute", "backup_posture", "storage", "database")


def fail(msg: str) -> None:
    print(f"::error::Azure live validation: {msg}")
    sys.exit(1)


def warn(msg: str) -> None:
    print(f"::warning::Azure live validation: {msg}")


def main() -> None:
    if len(sys.argv) < 2:
        fail("usage: assert_discovery.py <discovery.json>")

    path = pathlib.Path(sys.argv[1])
    if not path.exists():
        fail(f"discovery JSON not found at {path} — did the scan write output?")

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        fail(f"discovery JSON is not valid JSON: {exc}")

    # 1. Structure: every required top-level key is present.
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        fail(f"missing top-level keys: {missing}")

    # 2. Types: per-subscription collections are lists.
    for k in LIST_KEYS:
        if not isinstance(data[k], list):
            fail(f"{k} should be a list, got {type(data[k]).__name__}")

    # 3. The scan actually authenticated and resolved a tenant + subscription.
    if not data["tenant_id"]:
        fail("tenant_id is empty — DefaultAzureCredential resolution failed")
    if not data["subscriptions"]:
        fail("subscriptions is empty — subscription enumeration returned nothing")

    # 4. Coverage roll-up is internally consistent (the headline SE insight).
    protected = data["total_protected_vms"]
    unprotected = data["total_unprotected_vms"]
    total = data["total_vms"]
    if protected + unprotected != total:
        fail(
            f"VM roll-up inconsistent: protected({protected}) + "
            f"unprotected({unprotected}) != total_vms({total})"
        )

    # 5. Inventory presence — a WARNING, never a failure (see module docstring).
    total_resources = sum(len(data[k]) for k in INVENTORY_KEYS)
    if total_resources == 0:
        warn(
            "scan produced zero inventory across "
            f"{', '.join(INVENTORY_KEYS)} — valid, but the subscription may be "
            "empty or the identity may lack reader access to resources."
        )

    print("Azure live discovery validation PASSED:")
    print(f"  tenant_id               = {data['tenant_id']}")
    print(f"  subscriptions           = {len(data['subscriptions'])}")
    print(f"  total_vms               = {total}")
    print(f"  protection_coverage_pct = {data['protection_coverage_pct']}")
    print(f"  total_disk_tb           = {data['total_disk_tb']}")
    print(f"  inventory records       = {total_resources}")


if __name__ == "__main__":
    main()

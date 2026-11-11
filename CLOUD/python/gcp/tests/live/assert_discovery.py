#!/usr/bin/env python3
"""Assert the live discovery JSON reflects the seeded fixture.

This validates what the mocked unit tests cannot: that against the *real* Cloud
Asset Inventory API, the org-wide spine returns the field shapes
``OrgAssetCollector`` assumes (``result.project`` as ``projects/<number>``,
``result.asset_type``) and that project-number → project-id mapping works — so
``asset_counts`` ends up keyed by ``project_id``, not a raw number.

Usage: assert_discovery.py <discovery.json>
       (reads GCP_VALIDATION_PROJECT_ID from the environment)
"""

from __future__ import annotations

import json
import os
import pathlib
import sys


def fail(msg: str) -> None:
    print(f"::error::live validation: {msg}")
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        fail("usage: assert_discovery.py <discovery.json>")
    project = os.environ.get("GCP_VALIDATION_PROJECT_ID")
    if not project:
        fail("GCP_VALIDATION_PROJECT_ID not set")

    data = json.loads(pathlib.Path(sys.argv[1]).read_text())

    # 1. The fixture project was enumerated.
    scanned = data.get("projects_scanned", [])
    if project not in scanned:
        fail(f"{project} not in projects_scanned={scanned}")

    # 2. Asset spine keyed by project_id (NOT 'projects/<number>') — the core
    #    unknown the live run exists to prove.
    asset_counts = data.get("asset_counts", {})
    if project not in asset_counts:
        fail(
            f"asset_counts not keyed by project_id (number→id map failed?); "
            f"keys={list(asset_counts)}"
        )
    types = asset_counts[project]
    for expected in ("compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"):
        if expected not in types:
            fail(f"asset type {expected} missing from asset_counts[{project}]={types}")

    # 3. Compute collector saw the VM.
    comp = next((c for c in data.get("compute", []) if c.get("project_id") == project), None)
    if not comp or comp.get("total_instances", 0) < 1:
        fail(f"compute.total_instances < 1 for {project}: {comp}")

    # 4. Storage collector saw both buckets.
    stor = next((s for s in data.get("storage", []) if s.get("project_id") == project), None)
    if not stor or stor.get("total_buckets", 0) < 2:
        fail(f"storage.total_buckets < 2 for {project}: {stor}")

    print("Live discovery validation PASSED:")
    print(f"  asset_counts[{project}].total = {types.get('total')}")
    print(f"  asset types seen              = {sorted(k for k in types if k != 'total')}")
    print(f"  compute.total_instances       = {comp['total_instances']}")
    print(f"  storage.total_buckets         = {stor['total_buckets']}")


if __name__ == "__main__":
    main()

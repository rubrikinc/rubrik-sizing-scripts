"""Memory-bounded discovery output writer for large (org-scale) GCP runs.

The naive path builds one in-memory ``DiscoveryResult`` holding every project's
full inventory, then serialises it to a single JSON string — so peak memory is
roughly *twice* the inventory (objects + serialised payload).  For a handful of
projects that is fine and ``main._write_output`` still does exactly that.

For 1000 projects it is not.  This writer bounds peak memory to roughly one
project at a time:

  1. As each project finishes, its slice is appended to an on-disk NDJSON shard
     (one JSON object per line) and the in-memory object is dropped.
  2. ``finalize`` streams the canonical combined JSON from the shard — writing
     the category arrays (compute/storage/databases/backup_posture) by reading
     the shard back one line at a time, never holding them all at once. Projects
     finish in any order, so ``finalize(order=...)`` seeks to them in the scan
     order, using the byte offsets recorded as they were added.

The output file is byte-for-byte the same grouped schema ``main._write_output``
produces, so the (future) SE-side report reader is unaffected — this is purely a
memory optimisation, selected automatically above a project-count threshold.

Only ``asset_counts`` (small per-project count dicts) is held in memory, since
the summary needs it and it is cheap.  Raw assets are never serialised.
"""

from __future__ import annotations

import json
import logging
import pathlib
from typing import Any, Optional

logger = logging.getLogger(__name__)

# The heavy per-project categories, streamed from the shard rather than held.
_CATEGORIES = ("compute", "storage", "databases", "bigquery", "backup_posture")


class StreamingDiscoveryWriter:
    """Append per-project slices to a shard, then stream-assemble the final JSON."""

    def __init__(self, output_dir: pathlib.Path, timestamp: str) -> None:
        self._output_dir = output_dir
        self._timestamp = timestamp
        self._shard_path = output_dir / f".gcp-sizing-shard-{timestamp}.ndjson"
        # Binary, so each slice's byte offset is known and finalize can read them in any order.
        self._shard = self._shard_path.open("wb")
        self._pos = 0
        self._entries: list[tuple[str, int]] = []  # (project_id, byte offset), as added
        self._asset_counts: dict[str, Any] = {}
        self._project_count = 0

    def add(self, project_id: str, slice_dict: dict[str, Any]) -> None:
        """Append one project's serialised slice to the shard.

        ``slice_dict`` has the shape::

            {"project_id", "asset_counts", "compute", "storage",
             "databases", "bigquery", "backup_posture"}

        where each category value is the per-project dict (or None if absent).
        """
        if slice_dict.get("asset_counts") is not None:
            self._asset_counts[project_id] = slice_dict["asset_counts"]
        data = (json.dumps(slice_dict, default=str) + "\n").encode("utf-8")
        self._entries.append((project_id, self._pos))
        self._shard.write(data)
        self._pos += len(data)
        self._project_count += 1

    def finalize(
        self,
        *,
        meta: dict[str, Any],
        filename: str,
        keep_shard: bool = False,
        order: Optional[list[str]] = None,
    ) -> pathlib.Path:
        """Stream the combined grouped JSON to ``filename`` and remove the shard.

        Args:
            meta: Top-level scalar fields (schema_version, generated_at,
                organization_id, projects_scanned, regions_in_scope).
            filename: Output file name within the writer's output dir.
            keep_shard: If True, leave the NDJSON shard on disk (debugging).
            order: Project IDs in the order their entries should be written (the scan order).
                Slices arrive as projects finish, which is not the scan order; without this the
                file lists them as they arrived. A project not named here goes last.

        Returns:
            Path to the written combined JSON file.
        """
        self._shard.close()
        out_path = self._output_dir / filename
        entries = self._ordered(order)

        with out_path.open("w", encoding="utf-8") as f:
            f.write("{\n")
            # Scalar/meta fields + the small asset_counts dict.
            head = dict(meta)
            head["asset_counts"] = self._asset_counts
            for key, value in head.items():
                f.write(f"  {json.dumps(key)}: {json.dumps(value, default=str)},\n")

            # Heavy categories: one streaming pass over the shard each.
            for i, category in enumerate(_CATEGORIES):
                f.write(f"  {json.dumps(category)}: [")
                first = True
                for entry in self._iter_category(category, entries):
                    f.write("\n    " if first else ",\n    ")
                    f.write(json.dumps(entry, default=str))
                    first = False
                f.write("\n  ]" if not first else "]")
                f.write(",\n" if i < len(_CATEGORIES) - 1 else "\n")
            f.write("}\n")

        if not keep_shard:
            try:
                self._shard_path.unlink()
            except OSError as exc:
                logger.debug("Could not remove shard %s: %s", self._shard_path, exc)

        return out_path

    def _ordered(self, order: Optional[list[str]]) -> list[tuple[str, int]]:
        """The shard entries in output order: as added, or sorted by ``order`` (stable)."""
        if not order:
            return list(self._entries)
        rank = {project_id: i for i, project_id in enumerate(order)}
        return sorted(self._entries, key=lambda entry: rank.get(entry[0], len(rank)))

    def _iter_category(self, category: str, entries: list[tuple[str, int]]):
        """Yield each project's value for ``category`` from the shard, one at a time."""
        with self._shard_path.open("rb") as f:
            for _project_id, offset in entries:
                f.seek(offset)
                line = f.readline().strip()
                if not line:
                    continue
                slice_dict = json.loads(line)
                value = slice_dict.get(category)
                if value is not None:
                    yield value


def slice_from_result(project_id: str, result: dict) -> dict[str, Any]:
    """Build the per-project slice dict the writer expects from a collector result.

    ``result`` is the dict returned by ``main._collect_project`` (keyed by
    collector name with dataclass/Pydantic inventory objects).  Mirrors the
    aggregation in ``main._build_result`` but for a single project.
    """
    import dataclasses

    def _to_dict(obj):
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        return obj

    asset_counts: Optional[dict] = None
    if "asset" in result and not result["asset"].failed:
        inv = result["asset"]
        asset_counts = {"total": inv.total_assets, **inv.assets_by_type}

    return {
        "project_id": project_id,
        "asset_counts": asset_counts,
        "compute": _to_dict(result["compute"]) if "compute" in result else None,
        "storage": _to_dict(result["storage"]) if "storage" in result else None,
        "databases": _to_dict(result["database"]) if "database" in result else None,
        "bigquery": _to_dict(result["bigquery"]) if "bigquery" in result else None,
        "backup_posture": _to_dict(result["backup"]) if "backup" in result else None,
    }

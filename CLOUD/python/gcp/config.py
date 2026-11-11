"""Unified Rubrik Discovery configuration — GCP Edition.

One YAML file parameterises the whole pipeline — ``rubrik-gcp-discovery``,
``rubrik-gcp-report``, and ``rubrik-gcp-portal`` all accept ``--config rubrik.yaml``.

Layered precedence, Helm-style:

  1. built-in defaults (this module's Pydantic models)
  2. values from ``--config base.yaml``
  3. values from an optional ``--config overlay.yaml``  (one overlay max)
  4. CLI flags — always win, for one-off debugging

Schema is documented in ``docs/config_schema.md``.
"""

from __future__ import annotations

import pathlib
from typing import Iterable, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError


class ScopeConfig(BaseModel):
    """Which projects + regions to scan."""

    projects: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    all_projects: bool = Field(default=False)
    all_regions: bool = Field(default=False)

    # Convenience shorthand: ``scope.all: true`` sets both all_* flags.
    all: Optional[bool] = Field(default=None)

    model_config = {"populate_by_name": True, "extra": "forbid"}

    def effective_all_projects(self) -> bool:
        return bool(self.all or self.all_projects)

    def effective_all_regions(self) -> bool:
        return bool(self.all or self.all_regions)


class CollectorsConfig(BaseModel):
    """Toggle optional collectors.

    Core collectors (asset, compute, storage, database, backup) always run;
    these are best-effort add-ons.
    """

    cost: bool = True
    iac: bool = True
    filestore: bool = True
    security: bool = False  # requires roles/securitycenter.findingsViewer at org level

    model_config = {"extra": "forbid"}


class DiscoveryConfig(BaseModel):
    output_dir: Optional[str] = None
    collectors: CollectorsConfig = Field(default_factory=CollectorsConfig)
    mock: bool = False
    verbose: bool = False
    workers: int = 8
    """Parallel project-collection threads (org-scale runs). CLI --workers wins."""

    org_id: Optional[str] = None
    """Organization ID for the org-wide Cloud Asset Inventory spine. CLI --org wins."""

    folder_id: Optional[str] = None
    """Folder ID for a folder-scoped asset spine. CLI --folder wins."""

    model_config = {"extra": "forbid"}


class ReportConfig(BaseModel):
    customer_name: Optional[str] = None
    html: bool = True
    excel: bool = True
    summary: bool = True
    include_monte_carlo: bool = True
    monte_carlo_trials: int = 50_000
    hourly_downtime_cost_usd: Optional[float] = None
    output_dir: Optional[str] = None

    model_config = {"extra": "forbid"}


class SizingConfig(BaseModel):
    retention_multiplier: float = 1.0
    dedup_factor: float = 4.0
    compression_factor: float = 2.0
    dry_run: bool = False
    use_cache: bool = False
    no_cache: bool = False

    model_config = {"extra": "forbid"}


class PricingConfig(BaseModel):
    currency: str = "USD"
    override_file: Optional[str] = None

    model_config = {"extra": "forbid"}


class RubrikConfig(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    sizing: SizingConfig = Field(default_factory=SizingConfig)
    pricing: PricingConfig = Field(default_factory=PricingConfig)

    model_config = {"extra": "forbid"}


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge ``overlay`` into a copy of ``base``.

    Dicts are merged key-wise; non-dict values in overlay replace base.
    Lists are replaced wholesale (overlay wins).
    """
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(
    paths: str | pathlib.Path | Iterable[str | pathlib.Path] | None,
) -> RubrikConfig:
    """Load ``rubrik.yaml`` with at-most-one overlay.

    ``paths`` may be:
      - ``None`` → returns all-defaults RubrikConfig
      - a single path → load that file
      - a list/tuple of up to 2 paths → load base, merge overlay on top
    """
    if paths is None:
        return RubrikConfig()

    if isinstance(paths, (str, pathlib.Path)):
        paths = [paths]
    paths = list(paths)

    if not paths:
        return RubrikConfig()
    if len(paths) > 2:
        raise ValueError(f"load_config accepts at most 2 paths (base + overlay); got {len(paths)}")

    merged: dict = {}
    for p in paths:
        p = pathlib.Path(p)
        if not p.is_file():
            raise FileNotFoundError(f"Config file not found: {p}")
        with p.open() as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{p}: top-level YAML must be a mapping, got {type(data).__name__}")
        merged = _deep_merge(merged, data)

    try:
        return RubrikConfig(**merged)
    except ValidationError as exc:
        raise ValueError(f"Invalid config {paths}:\n{exc}") from exc

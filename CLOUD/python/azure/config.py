"""Unified Rubrik Discovery configuration.

One YAML file parameterises the whole pipeline — ``rubrik-discovery``,
``rubrik-report``, and ``rubrik-whatif`` all accept ``--config rubrik.yaml``.

Layered precedence, Helm-style:

  1. built-in defaults (this module's Pydantic models)
  2. values from ``--config base.yaml``
  3. values from an optional ``--config overlay.yaml``  (one overlay max)
  4. CLI flags — always win, for one-off debugging

Schema is documented in ``docs/config_schema.md`` (LLM-paste-ready).
"""

from __future__ import annotations

import pathlib
from typing import Any, Iterable

import yaml
from pydantic import BaseModel, Field, ValidationError

# ---------------------------------------------------------------------------
# Sub-sections — each maps to a CLI or collector area.
# ---------------------------------------------------------------------------


class ScopeConfig(BaseModel):
    """Which subscriptions + regions to scan.  Empty list + ``all: false``
    means "use whatever the az context is pointing at."
    """

    subscriptions: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    all_subscriptions: bool = Field(default=False, alias="all_subscriptions")
    all_regions: bool = Field(default=False, alias="all_regions")

    # Convenience shorthand: `scope.all: true` sets both all_* flags.
    all: bool | None = Field(default=None)

    model_config = {"populate_by_name": True, "extra": "forbid"}

    def effective_all_subs(self) -> bool:
        return bool(self.all or self.all_subscriptions)

    def effective_all_regions(self) -> bool:
        return bool(self.all or self.all_regions)


class CollectorsConfig(BaseModel):
    """Toggle optional collectors.  Core collectors (compute, storage,
    backup_posture, database) always run; these three are best-effort add-ons.
    """

    defender: bool = True
    purview: bool = False
    site_recovery: bool = False
    cost: bool = True

    model_config = {"extra": "forbid"}


class DiscoveryConfig(BaseModel):
    output_dir: str | None = None  # default: ~/clouddrive
    collectors: CollectorsConfig = Field(default_factory=CollectorsConfig)
    mock: bool = False
    verbose: bool = False
    cloud: str | None = None  # AzureCloud (default) or AzureUSGovernment
    workers: int | None = Field(default=None, ge=1)  # parallel subscriptions (default 4)

    model_config = {"extra": "forbid"}


class ReportConfig(BaseModel):
    customer_name: str | None = None
    html: bool = True
    excel: bool = True
    summary: bool = True
    include_monte_carlo: bool = True
    monte_carlo_trials: int = 50_000
    include_third_party_detection: bool = True
    hourly_downtime_cost_usd: float | None = None  # overrides risk model default
    output_dir: str | None = None  # default: same dir as discovery JSON

    model_config = {"extra": "forbid"}


class SizingConfig(BaseModel):
    """Rubrik sizing API + sizing math knobs.  Everything optional."""

    retention_multiplier: float = 1.0  # fudge factor on policy retention_days
    dedup_factor: float = 4.0
    compression_factor: float = 2.0
    dry_run: bool = False
    use_cache: bool = False
    no_cache: bool = False

    model_config = {"extra": "forbid"}


class PricingConfig(BaseModel):
    currency: str = "USD"
    override_file: str | None = None  # path to rubrik_pricing.yaml-like file

    model_config = {"extra": "forbid"}


class PoliciesConfig(BaseModel):
    """What-if policies — either a file reference OR an inline definition.

    kubectl-style: at most one of ``file`` or ``definitions`` may be set.
    If neither is set, the what-if engine simply has no policies to apply.
    """

    file: str | None = None
    definitions: dict[str, Any] | None = None

    model_config = {"extra": "forbid"}

    def validate_exclusive(self) -> None:
        if self.file and self.definitions:
            raise ValueError("policies: set 'file' OR 'definitions', not both")


class ComplianceConfig(BaseModel):
    """Compliance framework evaluation settings."""

    enabled: bool = True
    frameworks: list[str] = Field(default_factory=list)
    custom_policies_dir: str | None = None

    model_config = {"extra": "forbid"}


class AdvisorConfig(BaseModel):
    """Placeholder for a future --advisor mode hooked into an LLM."""

    model: str = "claude-sonnet-4-6"
    api_key_env: str = "ANTHROPIC_API_KEY"

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Top-level config.
# ---------------------------------------------------------------------------


class RubrikConfig(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    sizing: SizingConfig = Field(default_factory=SizingConfig)
    pricing: PricingConfig = Field(default_factory=PricingConfig)
    policies: PoliciesConfig = Field(default_factory=PoliciesConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    advisor: AdvisorConfig = Field(default_factory=AdvisorConfig)

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Loader with one-overlay merge.
# ---------------------------------------------------------------------------


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge ``overlay`` into a copy of ``base``.

    Dicts are merged key-wise; non-dict values in overlay replace base.
    Lists are replaced wholesale (overlay wins) — users rarely want list
    concatenation here, and replacement is more predictable.
    """
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(paths: str | pathlib.Path | Iterable[str | pathlib.Path] | None) -> RubrikConfig:
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
        config = RubrikConfig(**merged)
    except ValidationError as exc:
        raise ValueError(f"Invalid config {paths}:\n{exc}") from exc

    config.policies.validate_exclusive()
    return config


def resolve_policy_book(config: RubrikConfig, base_dir: pathlib.Path | None = None):
    """Load policies from ``config.policies`` into a PolicyBook.

    If ``policies.file`` is a relative path, resolve it relative to
    ``base_dir`` (typically the dir containing rubrik.yaml), not cwd.
    """
    # Local import — avoids a hard dep from config → analysis.
    from analysis.whatif import load_policy_book

    if config.policies.definitions:
        return load_policy_book(config.policies.definitions)

    if config.policies.file:
        p = pathlib.Path(config.policies.file)
        if not p.is_absolute() and base_dir is not None:
            p = (base_dir / p).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Policies file not found: {p}")
        with p.open() as f:
            data = yaml.safe_load(f) or {}
        return load_policy_book(data)

    return None

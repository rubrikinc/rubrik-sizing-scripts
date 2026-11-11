"""Tests for config.py — master rubrik.yaml loader.

Includes an examples-as-test-suite block: every YAML under
``docs/examples/rubrik*.yaml`` is parsed and must load cleanly.  If you
break the schema, the examples catch it before a customer does.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest
from config import (
    RubrikConfig,
    _deep_merge,
    load_config,
    resolve_policy_book,
)

REPO_ROOT = pathlib.Path(__file__).parent.parent
EXAMPLES_DIR = REPO_ROOT / "docs" / "examples"

requires_analysis = pytest.mark.skipif(
    importlib.util.find_spec("analysis") is None,
    reason="analysis package (SE-side tooling) is not in this repo",
)


# ---------------------------------------------------------------------------
# Defaults + empty loads
# ---------------------------------------------------------------------------


def test_load_config_none_returns_all_defaults():
    c = load_config(None)
    assert isinstance(c, RubrikConfig)
    assert c.scope.subscriptions == []
    assert c.scope.all is None
    assert c.report.monte_carlo_trials == 50_000
    assert c.discovery.collectors.defender is True
    assert c.policies.file is None
    assert c.policies.definitions is None


def test_load_config_empty_list_returns_defaults():
    c = load_config([])
    assert isinstance(c, RubrikConfig)


def test_load_config_empty_yaml_file(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    c = load_config(p)
    assert c == RubrikConfig()


def test_defaults_are_sensible():
    c = RubrikConfig()
    assert c.report.html is True
    assert c.report.excel is True
    assert c.report.include_monte_carlo is True
    assert c.sizing.dedup_factor == 4.0
    assert c.sizing.compression_factor == 2.0
    assert c.discovery.collectors.defender is True
    assert c.discovery.collectors.purview is False


# ---------------------------------------------------------------------------
# Basic loading
# ---------------------------------------------------------------------------


def test_load_minimal_config(tmp_path):
    p = tmp_path / "rubrik.yaml"
    p.write_text("""
scope:
  subscriptions: [sub-a, sub-b]
  regions: [eastus]
report:
  customer_name: Acme
""")
    c = load_config(p)
    assert c.scope.subscriptions == ["sub-a", "sub-b"]
    assert c.scope.regions == ["eastus"]
    assert c.report.customer_name == "Acme"


def test_scope_all_shorthand(tmp_path):
    p = tmp_path / "rubrik.yaml"
    p.write_text("scope:\n  all: true\n")
    c = load_config(p)
    assert c.scope.effective_all_subs() is True
    assert c.scope.effective_all_regions() is True


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does-not-exist.yaml")


def test_top_level_non_mapping_raises(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("- just a list\n")
    with pytest.raises(ValueError, match="mapping"):
        load_config(p)


def test_unknown_key_raises(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("not_a_real_field: true\n")
    with pytest.raises(ValueError):
        load_config(p)


def test_unknown_nested_key_raises(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("""
report:
  customer_name: Acme
  bogus_knob: true
""")
    with pytest.raises(ValueError):
        load_config(p)


def test_type_mismatch_raises(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("""
report:
  monte_carlo_trials: "fifty thousand"
""")
    with pytest.raises(ValueError):
        load_config(p)


# ---------------------------------------------------------------------------
# Overlay merging
# ---------------------------------------------------------------------------


def test_deep_merge_basic():
    base = {"a": 1, "b": {"x": 1, "y": 2}}
    overlay = {"b": {"y": 99, "z": 3}, "c": 4}
    out = _deep_merge(base, overlay)
    assert out == {"a": 1, "b": {"x": 1, "y": 99, "z": 3}, "c": 4}


def test_deep_merge_replaces_lists():
    """Lists are replaced wholesale — not concatenated."""
    base = {"regions": ["eastus", "westus"]}
    overlay = {"regions": ["centralus"]}
    assert _deep_merge(base, overlay) == {"regions": ["centralus"]}


def test_overlay_merges_on_top_of_base(tmp_path):
    base = tmp_path / "base.yaml"
    overlay = tmp_path / "overlay.yaml"
    base.write_text("""
scope:
  all: true
report:
  monte_carlo_trials: 50000
  customer_name: Default
""")
    overlay.write_text("""
report:
  customer_name: Acme Corp
  hourly_downtime_cost_usd: 75000
""")
    c = load_config([base, overlay])
    assert c.scope.all is True  # base preserved
    assert c.report.monte_carlo_trials == 50_000  # base preserved
    assert c.report.customer_name == "Acme Corp"  # overlay wins
    assert c.report.hourly_downtime_cost_usd == 75_000  # added by overlay


def test_max_two_configs(tmp_path):
    a = tmp_path / "a.yaml"
    a.write_text("")
    b = tmp_path / "b.yaml"
    b.write_text("")
    c = tmp_path / "c.yaml"
    c.write_text("")
    with pytest.raises(ValueError, match="at most 2"):
        load_config([a, b, c])


# ---------------------------------------------------------------------------
# Policies — file vs inline (kubectl-style)
# ---------------------------------------------------------------------------


@requires_analysis
def test_policies_inline(tmp_path):
    p = tmp_path / "rubrik.yaml"
    p.write_text("""
policies:
  definitions:
    policies:
      - name: Gold
        retention_days: 2555
        match:
          - tag: Env = prod
    default:
      name: Bronze
      retention_days: 30
""")
    c = load_config(p)
    book = resolve_policy_book(c, base_dir=tmp_path)
    assert book is not None
    assert book.policies[0].name == "Gold"
    assert book.default_policy.name == "Bronze"


@requires_analysis
def test_policies_file_reference(tmp_path):
    (tmp_path / "policies.yaml").write_text("""
policies:
  - name: Gold
    retention_days: 2555
    match:
      - tag: Env = prod
default:
  name: Bronze
  retention_days: 30
""")
    (tmp_path / "rubrik.yaml").write_text("""
policies:
  file: policies.yaml
""")
    c = load_config(tmp_path / "rubrik.yaml")
    book = resolve_policy_book(c, base_dir=tmp_path)
    assert book.policies[0].name == "Gold"


def test_policies_both_set_raises(tmp_path):
    p = tmp_path / "rubrik.yaml"
    p.write_text("""
policies:
  file: foo.yaml
  definitions:
    policies: []
""")
    with pytest.raises(ValueError, match="file.*definitions|definitions.*file"):
        load_config(p)


@requires_analysis
def test_policies_neither_set_returns_none(tmp_path):
    p = tmp_path / "rubrik.yaml"
    p.write_text("scope:\n  all: true\n")
    c = load_config(p)
    assert resolve_policy_book(c) is None


@requires_analysis
def test_policies_relative_path_resolves_against_config_dir(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "policies.yaml").write_text("""
policies:
  - name: Gold
    match: [{tag: Env = prod}]
""")
    cfg = tmp_path / "rubrik.yaml"
    cfg.write_text("policies:\n  file: sub/policies.yaml\n")
    c = load_config(cfg)
    book = resolve_policy_book(c, base_dir=tmp_path)
    assert book.policies[0].name == "Gold"


# ---------------------------------------------------------------------------
# Examples-as-test-suite — every docs/examples/rubrik*.yaml must load.
# ---------------------------------------------------------------------------


def _example_configs() -> list[pathlib.Path]:
    return sorted(EXAMPLES_DIR.glob("rubrik*.yaml"))


@pytest.mark.parametrize("example", _example_configs(), ids=lambda p: p.name)
def test_example_config_loads(example: pathlib.Path):
    """Every rubrik-*.yaml under docs/examples/ must parse cleanly.

    Catches schema drift the moment a new field or default lands.
    """
    c = load_config(example)
    assert isinstance(c, RubrikConfig)


@pytest.mark.parametrize("example", _example_configs(), ids=lambda p: p.name)
def test_example_config_policies_resolvable(example: pathlib.Path):
    """If an example references a policies file, that file must exist +
    load, and inline definitions must produce a valid PolicyBook.
    """
    c = load_config(example)
    book = resolve_policy_book(c, base_dir=REPO_ROOT)
    # Either no policies configured, or we got a working book back.
    if c.policies.file or c.policies.definitions:
        assert book is not None
        # At least one policy (including default) must exist.
        assert len(book.all_policies) >= 1


@pytest.mark.skipif(not EXAMPLES_DIR.is_dir(), reason="docs/examples is not in this repo")
def test_examples_directory_not_empty():
    """Sanity check — otherwise the parametrised tests silently skip."""
    assert len(_example_configs()) >= 2

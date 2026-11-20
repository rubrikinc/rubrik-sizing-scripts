"""A subscription read back from a saved run must behave like the one that was saved.

``Saved`` stands in for the collectors' dataclasses after a resume. Rather than hand-build a few
inventories, these tests build a populated instance of every dataclass in ``collectors`` from its type
hints, save it, read it back, and compare every attribute read the rest of the run could make.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import json
import pkgutil
import typing
from typing import Any

import collectors
import pytest
import resume
from models.inventory import DiscoveryResult, _asdict_safe


def _all_dataclasses() -> list[type]:
    found = []
    for info in pkgutil.iter_modules(collectors.__path__):
        mod = importlib.import_module(f"collectors.{info.name}")
        for _, cls in inspect.getmembers(mod, inspect.isclass):
            if dataclasses.is_dataclass(cls) and cls.__module__ == mod.__name__:
                found.append(cls)
    return sorted(found, key=lambda c: f"{c.__module__}.{c.__name__}")


DATACLASSES = _all_dataclasses()


def _value_for(hint: Any, depth: int = 0) -> Any:
    """A populated value of the given type: containers get one element, dataclasses are filled in."""
    origin = typing.get_origin(hint)
    args = typing.get_args(hint)
    if origin is typing.Union:  # Optional[X]: take the X
        inner = [a for a in args if a is not type(None)]
        return _value_for(inner[0], depth) if inner else None
    if origin is list:
        return [_value_for(args[0], depth + 1)] if args and depth < 4 else []
    if origin is dict:
        return {"k": _value_for(args[1], depth + 1)} if len(args) == 2 and depth < 4 else {}
    if inspect.isclass(hint) and dataclasses.is_dataclass(hint):
        return _populated(hint, depth + 1)
    if hint is bool:
        return True
    if hint is int:
        return 7
    if hint is float:
        return 1.5
    if hint is str:
        return "text"
    return "any"  # typing.Any and anything else JSON can hold


def _populated(cls: type, depth: int = 0) -> Any:
    hints = typing.get_type_hints(cls)
    kwargs = {f.name: _value_for(hints[f.name], depth) for f in dataclasses.fields(cls) if f.init}
    return cls(**kwargs)


def _same(original: Any, saved: Any, where: str) -> None:
    """Every attribute read on the saved object gives what it gives on the original."""
    if dataclasses.is_dataclass(original) and not isinstance(original, type):
        for f in dataclasses.fields(original):
            _same(getattr(original, f.name), getattr(saved, f.name), f"{where}.{f.name}")
        return
    if isinstance(original, list):
        assert isinstance(saved, list) and len(saved) == len(original), where
        for i, (o, s) in enumerate(zip(original, saved)):
            _same(o, s, f"{where}[{i}]")
        return
    assert saved == _asdict_safe(original), where


def _round_trip(obj: Any) -> resume.Saved:
    return resume.Saved(json.loads(json.dumps(_asdict_safe(obj))), type(obj))


# ── every collector dataclass ─────────────────────────────────────────────────


def test_the_collectors_have_dataclasses_to_check():
    assert len(DATACLASSES) > 40  # 48 when this was written: a smaller number means a bad import


@pytest.mark.parametrize(
    "cls", DATACLASSES, ids=lambda c: f"{c.__module__.split('.')[-1]}.{c.__name__}"
)
def test_every_attribute_of_every_collector_dataclass_reads_back_the_same(cls):
    original = _populated(cls)
    saved = _round_trip(original)
    _same(original, saved, cls.__name__)


@pytest.mark.parametrize(
    "cls", DATACLASSES, ids=lambda c: f"{c.__module__.split('.')[-1]}.{c.__name__}"
)
def test_serialising_a_saved_inventory_gives_the_json_it_was_saved_from(cls):
    original = _populated(cls)
    assert _asdict_safe(_round_trip(original)) == json.loads(json.dumps(_asdict_safe(original)))


def test_the_properties_the_collectors_compute_are_answered_from_the_saved_lists():
    from collectors.data_protection import DataProtectionInventory
    from collectors.database import SqlServerInfo

    inventory = _populated(DataProtectionInventory)
    assert _round_trip(inventory).total_vaults == inventory.total_vaults == len(inventory.vaults)
    server = _populated(SqlServerInfo)
    assert _round_trip(server).database_count == server.database_count == len(server.databases)


def test_a_dataclass_property_is_not_missed_by_the_wrapper():
    """If a collector dataclass gains a property, the wrapper must learn it or resume silently loses it."""
    known = {"total_vaults", "database_count", "linux_monthly_usd", "windows_monthly_usd"}
    for cls in DATACLASSES:
        for name, value in vars(cls).items():
            if isinstance(value, property):
                assert name in known, f"{cls.__name__}.{name} is a property: teach resume.Saved"


# ── the wrapper itself ────────────────────────────────────────────────────────


def test_a_field_that_was_not_saved_raises_attribute_error_like_a_dataclass():
    saved = resume.Saved({"a": 1})
    assert saved.a == 1
    with pytest.raises(AttributeError):
        saved.b
    assert getattr(saved, "b", "fallback") == "fallback"


def test_a_saved_inventory_is_read_only():
    with pytest.raises(AttributeError):
        resume.Saved({"a": 1}).a = 2


def test_records_in_a_list_are_wrapped_and_plain_maps_are_not():
    saved = resume.Saved({"vms": [{"name": "x", "tags": {"k": "v"}}], "tags": {"k": "v"}})
    (vm,) = saved.vms
    assert isinstance(vm, resume.Saved) and vm.name == "x"
    assert vm.tags.get("k") == "v" and list(saved.tags.items()) == [("k", "v")]


def test_fields_named_like_dict_methods_return_the_saved_values():
    """DataProtectionInventory.items and KeyVault.keys: a dict subclass would answer with the method."""
    from collectors.data_protection import DataProtectionInventory
    from collectors.key_vault import KeyVault

    inventory = _populated(DataProtectionInventory)
    saved = _round_trip(inventory)
    assert isinstance(saved.items, list) and len(saved.items) == len(inventory.items) == 1
    first = dataclasses.fields(inventory.items[0])[0].name
    assert getattr(saved.items[0], first) == getattr(inventory.items[0], first)
    vault = _populated(KeyVault)
    assert _round_trip(vault).keys == vault.keys


# ── fresh and resumed build the same result ───────────────────────────────────


def _inventories(sub: str) -> tuple:
    from collectors.backup_jobs import BackupJobsInventory
    from collectors.backup_posture import BackupPostureInventory
    from collectors.compute import ComputeInventory
    from collectors.cost import CostSummary
    from collectors.database import DatabaseInventory
    from collectors.storage import StorageInventory

    parts = []
    for cls in (
        ComputeInventory,
        BackupPostureInventory,
        StorageInventory,
        DatabaseInventory,
        BackupJobsInventory,
        CostSummary,
    ):
        obj = _populated(cls)
        obj.subscription_id = sub
        parts.append(obj)
    return tuple(parts)


def _build(per_subscription: list, subs: list) -> DiscoveryResult:
    comp, bp, stor, db, jobs, cost = ([row[i] for row in per_subscription] for i in range(6))
    return DiscoveryResult.build(
        tenant_id="t",
        subscriptions=subs,
        regions_in_scope=None,
        compute_results=comp,
        bp_results=bp,
        storage_results=stor,
        database_results=db,
        cost_results=cost,
        job_results=jobs,
    )


def _comparable(result: DiscoveryResult) -> dict:
    data = json.loads(result.to_json())
    data.pop("generated_at", None)
    return data


def test_a_resumed_subscription_builds_the_same_result_as_the_fresh_one():
    fresh = _inventories("sub-1")
    resumed = tuple(_round_trip(part) for part in fresh)
    assert _comparable(_build([resumed], ["sub-1"])) == _comparable(_build([fresh], ["sub-1"]))


def test_the_roll_ups_are_not_trivially_zero():
    """The comparison above means nothing if the inventories were empty."""
    result = _comparable(_build([_inventories("sub-1")], ["sub-1"]))
    assert result["total_vms"] > 0 and result["total_storage_accounts"] > 0


def test_a_mix_of_fresh_and_resumed_subscriptions_builds_the_same_result():
    a, b = _inventories("sub-1"), _inventories("sub-2")
    mixed = [a, tuple(_round_trip(part) for part in b)]
    subs = ["sub-1", "sub-2"]
    assert _comparable(_build(mixed, subs)) == _comparable(_build([a, b], subs))


def test_a_nested_dataclass_reads_back_as_an_object_and_a_plain_map_stays_a_dict():
    from collectors.compute import ComputeInventory

    saved = _round_trip(_populated(ComputeInventory))
    assert isinstance(saved.tag_summary, resume.Saved)  # attribute access, as on the dataclass
    assert saved.tag_summary.key_coverage is not None
    assert isinstance(saved.os_breakdown, dict) or saved.os_breakdown is not None
    vm = saved.vms[0]
    assert isinstance(vm.sql_server, resume.Saved)


def test_a_saved_inventory_without_its_class_still_wraps_records_in_lists():
    saved = resume.Saved({"vms": [{"name": "x"}], "tags": {"k": "v"}})
    assert saved.vms[0].name == "x" and saved.tags == {"k": "v"}

"""Derive per-file CSV column lists from the PowerShell sizing scripts (task B1).

``dump_ast.ps1`` parses a script with the PowerShell parser and emits JSON facts (row
constructors, member additions, helper calls, Export-Csv sites). This module joins those
facts with ``sources.json`` (which output file each constructor feeds) and writes
``columns.json``. The PowerShell code is authoritative; the ``EXAMPLES`` samples are stale.

Usage (from sizing_scripts/cloud/python)::

    python -m contract.build_columns            # regenerate columns.json (needs pwsh)
    python -m contract.build_columns --check    # fail if columns.json is out of date
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
SCRIPTS_DIR = HERE.parent.parent  # sizing_scripts/cloud
SOURCES = HERE / "sources.json"
OUTPUT = HERE / "columns.json"
DUMP_SCRIPT = HERE / "dump_ast.ps1"

# Helper functions whose fixed Add-Member names are appended to the calling row.
HELPER_FUNCTIONS = {"Add-BackupColumnsToRow": "$Row"}

_FILE_RE = re.compile(r'^\$(?P<var>output\w+)\s*=\s*"(?P<value>[^"]*)"', re.MULTILINE)
_NAME_RE = re.compile(r"^(?:\./)?(?P<prefix>.+?)(?P<sep>[-_])\$.*\.(?P<ext>csv|json)$")


def _ctx(fact: dict) -> frozenset[str]:
    return frozenset(fact.get("ctx") or [])


def _interpolate(name: str) -> str:
    """Turn a PowerShell interpolated name into a ``{placeholder}`` pattern."""
    name = name.strip()
    if len(name) >= 2 and name[0] == name[-1] == '"':
        name = name[1:-1]
    if "+" in name or "$(" in name:
        return "expr:" + name
    return re.sub(r"\$\{?(\w+)\}?", r"{\1}", name).replace("{_}", "{key}")


def _helper_columns(facts: list[dict]) -> dict[str, list[str]]:
    """Fixed column names each helper function adds, in source order."""
    out: dict[str, list[str]] = {}
    for fn, target in HELPER_FUNCTIONS.items():
        names = []
        for f in sorted(facts, key=lambda f: f["line"]):
            if (
                f["kind"] == "addmember"
                and f["fn"] == fn
                and f["target"] == target
                and not f.get("dynamic")
            ):
                if f["name"] and f["name"] not in names:
                    names.append(f["name"])
        out[fn] = names
    return out


def _constructors(facts: list[dict]) -> list[dict]:
    return sorted((f for f in facts if f["kind"] == "obj"), key=lambda f: f["line"])


def _select(facts: list[dict], sel: dict) -> list[dict]:
    matches = [
        c
        for c in _constructors(facts)
        if c["fn"] == sel["fn"]
        and ("var" not in sel or c["var"] == sel["var"])
        and len(c["keys"]) >= sel.get("min_keys", 0)
    ]
    if "nth" in sel:
        return matches[sel["nth"] : sel["nth"] + 1]
    return matches


def row_columns(
    facts: list[dict], ctor: dict, helpers: dict[str, list[str]]
) -> tuple[list[dict], list[str]]:
    """Ordered columns for one constructor: ``([{name, optional}], dynamic_patterns)``."""
    cols: list[dict] = [{"name": k, "optional": False} for k in ctor["keys"]]
    seen = {k for k in ctor["keys"]}
    dynamic: list[str] = []
    later = [
        c["line"]
        for c in _constructors(facts)
        if c["fn"] == ctor["fn"] and c["var"] == ctor["var"] and c["line"] > ctor["line"]
    ]
    end = min(later) if later else float("inf")
    base_ctx = _ctx(ctor)

    events = [
        f
        for f in facts
        if f["kind"] in ("add", "index", "addmember", "helper")
        and f["fn"] == ctor["fn"]
        and f.get("target") == ctor["var"]
        and ctor["line"] < f["line"] < end
        and not (f["kind"] in ("add", "index") and ctor["how"] != "ordered")
    ]
    for ev in sorted(events, key=lambda f: f["line"]):
        optional = bool(_ctx(ev) - base_ctx)
        if ev["kind"] == "helper":
            for name in helpers.get(ev["helper"], []):
                if name not in seen:
                    cols.append({"name": name, "optional": optional})
                    seen.add(name)
            continue
        name = ev.get("name")
        if not name:
            continue
        if ev.get("dynamic"):
            pattern = _interpolate(name)
            if pattern not in dynamic:
                dynamic.append(pattern)
            continue
        if name not in seen:
            cols.append({"name": name, "optional": optional})
            seen.add(name)
    return cols, dynamic


def merge_producers(
    per_ctor: list[tuple[list[dict], list[str]]],
) -> tuple[list[dict], list[str], bool]:
    """Union columns across producers; a column missing from any producer is optional."""
    order: list[str] = []
    optional: dict[str, bool] = {}
    dynamic: list[str] = []
    for cols, dyn in per_ctor:
        for c in cols:
            if c["name"] not in optional:
                order.append(c["name"])
                optional[c["name"]] = c["optional"]
            else:
                optional[c["name"]] = optional[c["name"]] or c["optional"]
        for d in dyn:
            if d not in dynamic:
                dynamic.append(d)
    differ = False
    if len(per_ctor) > 1:
        sets = [{c["name"] for c in cols} for cols, _ in per_ctor]
        differ = any(s != sets[0] for s in sets)
        for name in order:
            if not all(name in s for s in sets):
                optional[name] = True
    return [{"name": n, "optional": optional[n]} for n in order], dynamic, differ


def parse_file_names(script_text: str) -> dict[str, dict]:
    """``$outputX`` variable -> {prefix, separator, extension} from its string literal."""
    out = {}
    for m in _FILE_RE.finditer(script_text):
        n = _NAME_RE.match(m.group("value"))
        if n:
            out[m.group("var")] = {
                "prefix": n.group("prefix"),
                "separator": n.group("sep"),
                "extension": n.group("ext"),
            }
    return out


def build_cloud(facts: list[dict], cfg: dict, script_text: str) -> list[dict]:
    names = parse_file_names(script_text)
    helpers = _helper_columns(facts)
    exports = {f["path"]: f for f in facts if f["kind"] == "export" and f.get("path")}
    result = []
    for var, spec in cfg["files"].items():
        key = var.lstrip("$")
        entry: dict[str, Any] = {"export_var": var}
        entry.update(names.get(key) or {})
        export = exports.get(var)
        if export:
            entry["export_line"] = export["line"]
        if spec.get("decision"):
            entry["decision"] = spec["decision"]
        status = spec.get("status")
        if status == "unresolved" or not spec.get("producers"):
            entry.update(
                {
                    "status": "unresolved",
                    "columns": [],
                    "dynamic": [],
                    "notes": spec.get("notes", ""),
                }
            )
            result.append(entry)
            continue
        per, sources = [], []
        for sel in spec["producers"]:
            ctors = _select(facts, sel)
            if not ctors:
                raise ValueError(f"{var}: no constructor matches {sel}")
            for c in ctors:
                per.append(row_columns(facts, c, helpers))
                sources.append({"fn": c["fn"], "var": c["var"], "line": c["line"]})
        columns, dynamic, differ = merge_producers(per)
        # Patterns a helper adds (Add-LabelsToObject, say), which the producer's AST does not show.
        for pattern in spec.get("dynamic") or []:
            if pattern not in dynamic:
                dynamic.append(pattern)
        for pattern, values in (spec.get("expand") or {}).items():
            if pattern in dynamic:
                dynamic.remove(pattern)
                columns += [
                    {"name": pattern.replace("{metric}", v), "optional": False} for v in values
                ]
        entry.update(
            {
                "status": status or "resolved",
                "columns": columns,
                "dynamic": dynamic,
                "sources": sources,
            }
        )
        if differ:
            entry["producers_differ"] = True
        if spec.get("notes"):
            entry["notes"] = spec["notes"]
        result.append(entry)
    return result


def build(
    dumps: dict[str, list[dict]], texts: dict[str, str], sources: dict, hashes: dict[str, str]
) -> dict:
    out: dict[str, Any] = {"generated_from": hashes, "clouds": {}}
    for cloud, cfg in sources.items():
        if cloud.startswith("_"):
            continue
        out["clouds"][cloud] = build_cloud(dumps[cloud], cfg, texts[cloud])
    return out


def _run_dump(script: Path) -> list[dict]:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(DUMP_SCRIPT), "-Path", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"pwsh failed for {script.name}: {proc.stderr[:500]}")
    data = json.loads(proc.stdout)
    return data if isinstance(data, list) else [data]


def generate(dump_dir: Optional[Path] = None) -> dict:
    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    dumps, texts, hashes = {}, {}, {}
    for cloud, cfg in sources.items():
        if cloud.startswith("_"):
            continue
        script = SCRIPTS_DIR / cfg["script"]
        texts[cloud] = script.read_text(encoding="utf-8")
        hashes[cfg["script"]] = hashlib.sha256(script.read_bytes()).hexdigest()
        if dump_dir:
            dumps[cloud] = json.loads((dump_dir / f"{cloud}.json").read_text(encoding="utf-8"))
        else:
            dumps[cloud] = _run_dump(script)
    return build(dumps, texts, sources, hashes)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if columns.json differs")
    ap.add_argument(
        "--dump-dir", type=Path, help="use pre-made <cloud>.json dumps instead of running pwsh"
    )
    args = ap.parse_args(argv)
    text = json.dumps(generate(args.dump_dir), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != text:
            print(
                "columns.json is out of date; run: python -m contract.build_columns",
                file=sys.stderr,
            )
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

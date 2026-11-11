"""Tests for common/consolidate.py (port of consolidate.ps1)."""

import csv
import io
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from common.consolidate import consolidate, main

SCRIPT = Path(__file__).resolve().parents[3] / "consolidate.ps1"


def _write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def _read(path) -> str:
    return open(path, encoding="utf-8", newline="").read()


@pytest.fixture()
def tree(tmp_path):
    src = tmp_path / "in"
    _write(src, "x-2026-01.csv", '"A","B","C"\n"1","","3"\n"4",,"6"\n\n"7","8","9"\n')
    _write(src, "sub/x-2026-02.csv", '"A","D","C"\n"10","dd","30"\n')
    _write(src, "sub/deep/x-2026-03.csv", '"B","E"\n"b3","e3"\n')
    _write(src, "zz/x-2026-04.csv", '"A","B","C"\n')  # header only
    _write(src, "x-empty.csv", "")
    _write(src, "y-2026-01.csv", '"K"\n"v1"\n')
    _write(src, "nodash.csv", '"Q"\n"1"\n')
    _write(src, "sub/a-b-c-1.csv", '"M"\n"quote ""inner"""\n')
    _write(src, "sub/a-other.csv", '"M","N"\n"x","y"\n')
    return src, tmp_path / "out"


def test_groups_by_the_name_before_the_first_dash(tree):
    src, out = tree
    written = consolidate(str(src), str(out))
    assert [os.path.basename(p) for p in written] == [
        "a_combined.csv",
        "x_combined.csv",
        "y_combined.csv",
    ]


def test_one_header_with_every_column_and_added_columns_left_bare(tree):
    src, out = tree
    consolidate(str(src), str(out))
    assert _read(out / "x_combined.csv") == (
        '"A","B","C","D","E"\n'
        '"1","","3",,\n'
        '"4","","6",,\n'
        '"7","8","9",,\n'
        '"10",,"30","dd",\n'
        ',"b3",,,"e3"\n'
    )


def test_existing_empty_cells_become_quoted_empty_and_quotes_are_doubled(tree):
    src, out = tree
    consolidate(str(src), str(out))
    assert _read(out / "a_combined.csv") == '"M","N"\n"quote ""inner""",\n"x","y"\n'


def test_a_file_without_a_dash_empty_files_and_header_only_files_add_nothing(tree):
    src, out = tree
    consolidate(str(src), str(out))
    assert not (out / "nodash_combined.csv").exists()
    assert _read(out / "y_combined.csv") == '"K"\n"v1"\n'


def test_a_group_with_no_rows_writes_no_file(tmp_path):
    _write(tmp_path / "in", "z-1.csv", '"A","B"\n')
    _write(tmp_path / "in", "z-2.csv", "")
    assert consolidate(str(tmp_path / "in"), str(tmp_path / "out")) == []
    assert not (tmp_path / "out").exists()


def test_files_come_before_subfolders_and_both_are_ordered_by_name(tmp_path):
    src = tmp_path / "in"
    for name, value in [
        ("m-aroot.csv", "aroot"),
        ("m-Zroot.csv", "Zroot"),
        ("m-root.csv", "root"),
        ("b/m-b.csv", "b"),
        ("b/deep/m-bdeep.csv", "bdeep"),
        ("a/m-a.csv", "a"),
        ("C/m-C.csv", "C"),
    ]:
        _write(src, name, f'"V"\n"{value}"\n')
    consolidate(str(src), str(tmp_path / "out"))
    text = _read(tmp_path / "out" / "m_combined.csv")
    values = [r["V"] for r in csv.DictReader(io.StringIO(text))]
    assert values == ["aroot", "root", "Zroot", "a", "b", "bdeep", "C"]


def test_a_byte_order_mark_and_short_rows_are_handled(tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    (src / "w-1.csv").write_bytes(b'\xef\xbb\xbf"A","B"\n"1"\n')
    consolidate(str(src), str(tmp_path / "out"))
    assert _read(tmp_path / "out" / "w_combined.csv") == '"A","B"\n"1",\n'


def test_command_line_writes_files_and_reports_a_missing_directory(tree, capsys, tmp_path):
    src, out = tree
    assert main([str(src), "--output-dir", str(out)]) == 0
    assert "x_combined.csv" in capsys.readouterr().out
    assert main([str(tmp_path / "nope")]) == 2


def _normalised(path):
    rows = list(csv.DictReader(io.StringIO(_read(path))))
    return sorted(rows[0].keys()), [dict(sorted(r.items())) for r in rows]


def _script_with_protection(tmp_path: Path):
    """The consolidate.ps1 to compare with: the checked-out one when it has Protect-CsvValue
    (SPARK-957429), else master's copy, so the comparison is against the current script."""
    if SCRIPT.exists() and "Protect-CsvValue" in SCRIPT.read_text(encoding="utf-8"):
        return SCRIPT
    git = shutil.which("git")
    if not git:
        return None
    shown = subprocess.run(
        [git, "show", "origin/master:sizing_scripts/cloud/consolidate.ps1"],
        cwd=SCRIPT.parent,
        capture_output=True,
        text=True,
    )
    if shown.returncode != 0 or "Protect-CsvValue" not in shown.stdout:
        return None
    path = tmp_path / "consolidate_master.ps1"
    path.write_text(shown.stdout, encoding="utf-8")
    return path


@pytest.mark.skipif(not shutil.which("pwsh") or not SCRIPT.exists(), reason="needs pwsh")
def test_rows_and_columns_match_the_powershell_script(tree, tmp_path):
    src, out = tree
    consolidate(str(src), str(out))
    ps_out = tmp_path / "ps"
    ps_out.mkdir()
    script = _script_with_protection(tmp_path)
    if script is None:
        pytest.skip("no consolidate.ps1 with Protect-CsvValue is available (needs origin/master)")
    subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(script), "-directoryPath", str(src)],
        cwd=ps_out,
        check=True,
        capture_output=True,
    )
    assert sorted(p.name for p in ps_out.iterdir()) == sorted(p.name for p in out.iterdir())
    for path in out.iterdir():
        # PowerShell orders columns added by later files unpredictably, so compare as sets.
        assert _normalised(path) == _normalised(ps_out / path.name)


# ── formula injection (SPARK-957429): every text cell is protected when the files are merged ──


@pytest.fixture()
def hostile(tmp_path):
    src = tmp_path / "in"
    _write(
        src,
        "h-2026-01.csv",
        '"A","B","C","D"\n'
        '"=1+1","+2","-3","@4"\n'
        '"ok","a=b","\t=5","\n=6"\n'
        '"\'=quoted","","x","y"\n',
    )
    return src, tmp_path / "out"


def test_every_formula_leading_cell_gets_a_quote(hostile):
    src, out = hostile
    consolidate(str(src), str(out))
    rows = list(csv.reader(io.StringIO(_read(out / "h_combined.csv"))))
    assert rows[1] == ["'=1+1", "'+2", "'-3", "'@4"]
    assert rows[2] == ["ok", "a=b", "'\t=5", "'\n=6"]


def test_a_value_the_exporter_already_protected_is_not_protected_twice(hostile):
    src, out = hostile
    consolidate(str(src), str(out))
    rows = list(csv.reader(io.StringIO(_read(out / "h_combined.csv"))))
    assert rows[3][0] == "'=quoted", "a leading quote is not a formula character"


def test_the_header_is_not_changed(hostile):
    src, out = hostile
    _write(src, "h2-2026-01.csv", '"=A","B"\n"1","2"\n')
    consolidate(str(src), str(out))
    assert _read(out / "h2_combined.csv").splitlines()[0] == '"=A","B"'


def test_a_missing_cell_stays_bare_and_an_empty_one_stays_quoted(hostile):
    src, out = hostile
    _write(src, "h-2026-02.csv", '"A","E"\n"=1","e"\n')
    consolidate(str(src), str(out))
    last = _read(out / "h_combined.csv").splitlines()[-1]
    assert last == "\"'=1\",,,,\"e\""

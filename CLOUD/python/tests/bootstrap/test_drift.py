"""The fetch_source block is published verbatim in three scripts; keep them identical and clean."""

import ast
import re
import subprocess

import pytest
from bootstrap_support import BASHES, SCRIPTS, block_text, extract_py, set_line

PRIVATE_NAMES = re.compile(r"scaledata|Rubrik-PLS|sizing_apps|Cloud-Sizing|sizing\.rubrik\.com", re.I)
CREDENTIAL_CODE = re.compile(r"RUBRIK_DISCOVERY_TOKEN|Authorization")


def test_block_is_byte_identical_across_scripts():
    blocks = {cloud: block_text(path) for cloud, path in SCRIPTS.items()}
    reference = blocks["aws"]
    for cloud, text in blocks.items():
        assert text == reference, "fetch_source block in %s differs from aws/install.sh" % cloud


@pytest.mark.parametrize("cloud", sorted(SCRIPTS))
@pytest.mark.parametrize("bash", BASHES)
def test_script_parses(cloud, bash):
    proc = subprocess.run([bash, "-n", str(SCRIPTS[cloud])], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize("cloud", sorted(SCRIPTS))
def test_each_script_has_a_set_line(cloud):
    line = set_line(SCRIPTS[cloud])
    assert "pipefail" in line
    # documented difference: only aws/install.sh runs without -e
    assert ("-e" in line.split()[1]) == (cloud != "aws")


@pytest.mark.parametrize("cloud", sorted(SCRIPTS))
def test_no_credential_handling_in_shipped_scripts(cloud):
    text = SCRIPTS[cloud].read_text(encoding="utf-8")
    assert not CREDENTIAL_CODE.search(text), "no token / Authorization code may ship in a customer script"


def test_block_names_no_private_system():
    assert not PRIVATE_NAMES.search(block_text(SCRIPTS["aws"]))


def test_extractor_heredoc_uses_command_substitution_form():
    # `read -r -d '' x <<'PY'` returns 1 and kills the script under `set -e`
    block = block_text(SCRIPTS["aws"])
    assert "_EXTRACT_PY=\"$(cat <<'PY'" in block
    assert not re.search(r"read\s+-r?\s*-d\s*''", block)


def test_extractor_is_valid_stdlib_only_python():
    tree = ast.parse(extract_py(SCRIPTS["aws"]))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"os", "re", "sys", "tarfile", "zlib"}, imported


def test_extractor_has_no_stray_apostrophes_or_unbalanced_brackets():
    # bash 3.2 and <= 4.3 count quotes and parentheses inside $(...) even in comments
    src = extract_py(SCRIPTS["aws"])
    assert src.count("(") == src.count(")")
    assert src.count("'") % 2 == 0
    assert src.count('"') % 2 == 0

"""No bucket-distribution or internal-tooling strings in the files that will be published.

The canonical regex lives (from PR-B on) in the mirror's sync script; until then it is
copied here. Matching is on bucket-*distribution* strings only: a bare ``s3://`` is
legitimate (aws/main.py's optional customer-owned --bucket results upload).
"""

import re

import pytest
from bootstrap_support import PY_DIR

DENY = re.compile(
    r"YOUR-ARTIFACTS-BUCKET|aws s3 cp|--template-url|TEMPLATE_URL|\.s3\.amazonaws\.com|"
    r"blob\.core\.windows\.net|rubrikdiscovery(dev|prod)?|storage\.googleapis\.com/rubrik|"
    r"WHEEL_URL|gen_customer_link|make publish|aws/Makefile|admin-setup|build_and_deploy|"
    r"setup_blob_storage|scaledata/sizing_apps|Rubrik-PLS"
)

# The files the public mirror allowlist publishes (keep in step with cloud-python.rsync-filter).
PUBLISHED = {
    "aws": (
        ["install.sh", "main.py", "logging_setup.py", "preflight.py", "preflight_core.py", "runlog.py", "runlog_core.py", "pyproject.toml"]
        + ["collectors/*.py", "models/*.py"]
        + ["iac/2-sizing-tool-spokes.yaml"]
    ),
    "azure": (
        ["install.sh", "main.py", "auth.py", "cloud.py", "config.py", "audit_manifest.py", "logging_setup.py", "preflight.py", "preflight_core.py", "runlog.py", "runlog_core.py", "pyproject.toml"]
        + ["collectors/*.py", "models/*.py"]
    ),
    "gcp": (
        ["install.sh", "main.py", "auth.py", "config.py", "logging_setup.py", "streaming_writer.py", "preflight.py", "preflight_core.py", "runlog.py", "runlog_core.py", "pyproject.toml"]
        + ["collectors/*.py", "models/*.py"]
    ),
}


def published_files(cloud):
    files = []
    for pattern in PUBLISHED[cloud]:
        files += sorted((PY_DIR / cloud).glob(pattern))
    assert files, "allowlist for %s matched nothing" % cloud
    return files


@pytest.mark.parametrize("cloud", sorted(PUBLISHED))
def test_published_files_contain_no_denied_strings(cloud):
    hits = []
    for path in published_files(cloud):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if DENY.search(line):
                hits.append("%s:%d: %s" % (path.relative_to(PY_DIR), lineno, line.strip()[:100]))
    assert not hits, "\n".join(hits)


def test_the_regex_does_catch_the_strings_it_exists_for():
    for bad in ("s3://YOUR-ARTIFACTS-BUCKET/x", "aws s3 cp s3://b/install.sh -", "--template-url x",
                "rubrikdiscoveryprod.blob.core.windows.net", "WHEEL_URL=", "see make publish"):
        assert DENY.search(bad), bad
    assert not DENY.search("s3://customer-bucket/results.json"), "bare s3:// must stay legal"

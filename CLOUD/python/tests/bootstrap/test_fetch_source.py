"""fetch_source: run each real script's block under that script's own shell options."""

import os
import shutil
import uuid
from pathlib import Path

import pytest
from bootstrap_support import (
    BASHES,
    FAKE_COMMIT,
    TOP,
    Server,
    closed_port,
    git_archive,
    make_tar,
    run_fetch,
    standard_files,
    valid_members,
)

pytestmark = pytest.mark.skipif(
    shutil.which("curl") is None or shutil.which("git") is None,
    reason="fetch_source tests need curl and git",
)


@pytest.fixture(params=["aws", "azure", "gcp"])
def cloud(request):
    return request.param


@pytest.fixture(params=["or", "bare"])
def mode(request):
    return request.param


@pytest.fixture(params=BASHES)
def bash(request):
    return request.param


@pytest.fixture
def archive(tmp_path):
    path, commit = git_archive(tmp_path, standard_files())
    return path, commit


def fetch(tmp_path, cloud, mode, bash, url, **kw):
    return run_fetch(tmp_path, cloud, bash=bash, mode=mode, url=url, **kw)


def assert_failed(res, *needles):
    assert res.rc != 0, res.stdout + res.stderr
    for n in needles:
        assert n in res.stderr, "expected %r in stderr:\n%s" % (n, res.stderr)
    assert "Traceback" not in res.stderr, res.stderr
    assert res.leftovers in ([], None), "temp dir not cleaned up: %s" % res.leftovers


# --------------------------------------------------------------------------- success


def test_happy_path(tmp_path, cloud, mode, bash, archive):
    path, commit = archive
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri())
    assert res.rc == 0, res.stderr
    assert res.vars["SRC_DIR"].endswith("CLOUD/python/" + cloud)
    assert "./pyproject.toml" in res.vars["FILES"] and "./main.py" in res.vars["FILES"]
    assert res.vars["COMMIT"] == commit
    assert res.vars["VERSION"] == "9.9.9"
    assert res.vars["PINNED"] == ""
    assert res.vars["REF"] == "master"
    assert res.leftovers == [], "EXIT trap must remove the temp dir"


def test_subdir_override_with_private_layout(tmp_path, cloud, mode, bash):
    files = {"sizing_scripts/cloud/python/%s/pyproject.toml" % cloud: '[project]\nversion = "1.2.3"\n',
             "sizing_scripts/cloud/python/%s/main.py" % cloud: "x\n",
             "unrelated/big.bin": "zzz\n"}
    path, commit = git_archive(tmp_path, files, prefix="rubrik-sizing-scripts-test/", paths=["sizing_scripts/cloud/python"])
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri(), subdir="sizing_scripts/cloud/python/" + cloud)
    assert res.rc == 0, res.stderr
    assert res.vars["VERSION"] == "1.2.3"
    assert res.vars["COMMIT"] == commit
    assert "unrelated" not in res.vars["FILES"]


def test_nothing_outside_subdir_is_extracted(tmp_path, cloud, mode, bash):
    files = standard_files()
    files["CLOUD/python/other/pyproject.toml"] = "x\n"
    files["README.md"] = "x\n"
    path, _ = git_archive(tmp_path, files)
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri())
    assert res.rc == 0, res.stderr
    assert "other" not in res.vars["FILES"] and "README" not in res.vars["FILES"]


# --------------------------------------------------------------------------- hostile archives


@pytest.mark.parametrize(
    "bad_name",
    [
        TOP + "/CLOUD/python/{cloud}/../../../../evil",
        "repo/../evil",
        TOP + "//etc/evil",
    ],
    ids=["deep-traversal", "bare-traversal", "double-slash-absolute"],
)
def test_path_traversal_rejected(tmp_path, cloud, mode, bash, bad_name):
    members = valid_members(cloud) + [(bad_name.format(cloud=cloud), "file", "pwned")]
    path = make_tar(tmp_path, members)
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri())
    assert_failed(res, "unsafe path in archive")
    assert not (tmp_path / "evil").exists() and not (tmp_path / "tmp" / "evil").exists()


def test_literal_absolute_member_is_never_extracted(tmp_path, cloud, mode, bash):
    members = valid_members(cloud) + [("/x", "file", "nope")]
    path = make_tar(tmp_path, members)
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri())
    assert res.rc == 0, res.stderr
    assert "/x" not in res.vars["FILES"].replace("./", "")


def test_symlink_member_skipped_and_child_cannot_escape(tmp_path, cloud, mode, bash):
    # short absolute target: a USTAR linkname is limited to 100 bytes
    outside = Path("/tmp") / ("rbk_outside_" + uuid.uuid4().hex[:8])
    outside.mkdir()
    try:
        base = "%s/CLOUD/python/%s" % (TOP, cloud)
        members = valid_members(cloud) + [
            (base + "/link", "symlink", str(outside)),
            (base + "/link/pwned", "file", "pwned"),
        ]
        path = make_tar(tmp_path, members)
        res = fetch(tmp_path, cloud, mode, bash, path.as_uri())
        assert res.rc == 0, res.stderr
        assert not (outside / "pwned").exists(), "a child of a skipped symlink must not escape the extraction root"
    finally:
        shutil.rmtree(outside, ignore_errors=True)


def test_only_directory_entry(tmp_path, cloud, mode, bash):
    path = make_tar(tmp_path, [("%s/CLOUD/python/%s" % (TOP, cloud), "dir", None)])
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri())
    assert_failed(res, "pyproject.toml not found in archive")


def test_missing_subdir(tmp_path, cloud, mode, bash, archive):
    path, _ = archive
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri(), subdir="CLOUD/python/nope")
    assert_failed(res, "CLOUD/python/nope/pyproject.toml not found in archive")


# --------------------------------------------------------------------------- broken downloads


def test_truncated_archive(tmp_path, cloud, mode, bash, archive):
    path, _ = archive
    data = path.read_bytes()
    bad = tmp_path / "trunc.tgz"
    bad.write_bytes(data[: len(data) // 2])
    res = fetch(tmp_path, cloud, mode, bash, bad.as_uri())
    assert_failed(res, "archive unreadable or truncated")


def test_empty_body(tmp_path, cloud, mode, bash):
    empty = tmp_path / "empty.tgz"
    empty.write_bytes(b"")
    res = fetch(tmp_path, cloud, mode, bash, empty.as_uri())
    assert_failed(res, "archive unreadable or truncated")


def test_captive_portal_html_with_http_200(tmp_path, cloud, mode, bash):
    with Server({"/x.tgz": (200, b"<html><body>Sign in to Wi-Fi</body></html>", "text/html")}) as srv:
        res = fetch(tmp_path, cloud, mode, bash, srv.url("/x.tgz"))
    assert_failed(res, "archive unreadable or truncated")


def test_http_404_names_the_ref(tmp_path, cloud, mode, bash):
    with Server({}) as srv:
        res = fetch(tmp_path, cloud, mode, bash, srv.url("/missing.tgz"), ref="does-not-exist")
    assert_failed(res, "GitHub returned HTTP 404", "does ref 'does-not-exist' exist?")


def test_connection_refused(tmp_path, cloud, mode, bash):
    res = fetch(tmp_path, cloud, mode, bash, "http://127.0.0.1:%d/x.tgz" % closed_port())
    assert_failed(res, "could not reach GitHub")


def test_missing_file_url_reports_curl_exit(tmp_path, cloud, mode, bash):
    res = fetch(tmp_path, cloud, mode, bash, (tmp_path / "nope.tgz").as_uri())
    assert_failed(res, "download failed (curl exit")


def test_mktemp_failure_writes_nothing_to_cwd(tmp_path, cloud, mode, bash, archive):
    path, _ = archive
    res = run_fetch(tmp_path, cloud, bash=bash, mode=mode, url=path.as_uri(), tmpdir=tmp_path / "does" / "not" / "exist")
    assert res.rc != 0
    assert "cannot create a temp dir" in res.stderr
    assert "Traceback" not in res.stderr
    assert os.listdir(tmp_path / "cwd") == [], "nothing may be written to the working directory"


# --------------------------------------------------------------------------- URL scheme


@pytest.mark.parametrize("url", ["ftp://example.com/x.tgz", "http://example.com/x.tgz", "gopher://x/y", "/tmp/x.tgz"])
def test_unsupported_url_scheme_rejected_without_network(tmp_path, cloud, mode, bash, url):
    res = fetch(tmp_path, cloud, mode, bash, url)
    assert_failed(res, "unsupported RUBRIK_DISCOVERY_SOURCE_URL scheme")


# --------------------------------------------------------------------------- commit pinning


def test_pin_full_sha_matches(tmp_path, cloud, mode, bash, archive):
    path, commit = archive
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri(), ref=commit)
    assert res.rc == 0, res.stderr
    assert res.vars["PINNED"] == "1"


@pytest.mark.parametrize("variant", ["short7", "short12", "upper12"])
def test_pin_short_and_uppercase_prefix(tmp_path, cloud, mode, bash, archive, variant):
    path, commit = archive
    ref = {"short7": commit[:7], "short12": commit[:12], "upper12": commit[:12].upper()}[variant]
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri(), ref=ref)
    assert res.rc == 0, res.stderr
    assert res.vars["PINNED"] == "1"


@pytest.mark.parametrize("ref", ["0" * 40, "0" * 12, "deadbeef"])
def test_pin_mismatch_aborts(tmp_path, cloud, mode, bash, archive, ref):
    path, _ = archive
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri(), ref=ref)
    assert_failed(res, "requested commit")


def test_pin_fails_closed_when_archive_has_no_commit_id(tmp_path, cloud, mode, bash):
    path = make_tar(tmp_path, valid_members(cloud), comment=None)
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri(), ref=FAKE_COMMIT)
    assert_failed(res, "cannot verify pinned commit")


def test_pin_fails_closed_when_commit_id_is_not_hex(tmp_path, cloud, mode, bash):
    path = make_tar(tmp_path, valid_members(cloud), comment="not-a-commit; rm -rf /")
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri(), ref=FAKE_COMMIT)
    assert_failed(res, "cannot verify pinned commit")


@pytest.mark.parametrize("ref", ["master", "main", "v1.2.3", "feature/x", "abcdef"])
def test_non_commit_refs_are_unpinned(tmp_path, cloud, mode, bash, archive, ref):
    path, _ = archive
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri(), ref=ref)
    assert res.rc == 0, res.stderr
    assert res.vars["PINNED"] == ""
    assert res.vars["REF"] == ref


def test_unpinned_run_tolerates_archive_without_commit_id(tmp_path, cloud, mode, bash):
    path = make_tar(tmp_path, valid_members(cloud), comment=None)
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri())
    assert res.rc == 0, res.stderr
    assert res.vars["COMMIT"] == ""


def test_version_is_empty_but_call_succeeds_without_version_line(tmp_path, cloud, mode, bash):
    base = "%s/CLOUD/python/%s" % (TOP, cloud)
    path = make_tar(tmp_path, [(base, "dir", None), (base + "/pyproject.toml", "file", "[project]\nname = 'x'\n")])
    res = fetch(tmp_path, cloud, mode, bash, path.as_uri())
    assert res.rc == 0, res.stderr
    assert res.vars["VERSION"] == ""


def test_temp_dir_with_spaces(tmp_path, cloud, mode, bash, archive):
    path, _ = archive
    spaced = tmp_path / "tmp with spaces"
    spaced.mkdir()
    res = run_fetch(tmp_path, cloud, bash=bash, mode=mode, url=path.as_uri(), tmpdir=spaced)
    assert res.rc == 0, res.stderr
    assert Path(res.vars["SRC_DIR"]).parts[-3:] == ("CLOUD", "python", cloud)

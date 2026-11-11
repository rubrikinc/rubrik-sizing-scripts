"""Shared helpers for the bootstrap (fetch_source) tests.

The harness runs each real script's own ``set ...`` line and its own
``# BEGIN fetch_source`` block, so shell-option differences between the three
scripts (``set -e`` vs none, ``pipefail``) are exercised exactly as shipped.
"""

import http.server
import io
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
from pathlib import Path

PY_DIR = Path(__file__).resolve().parents[2]  # sizing_scripts/cloud/python
SCRIPTS = {
    "aws": PY_DIR / "aws" / "install.sh",
    "azure": PY_DIR / "azure" / "install.sh",
    "gcp": PY_DIR / "gcp" / "install.sh",
}
BEGIN = "# BEGIN fetch_source"
END = "# END fetch_source"
TOP = "rubrik-sizing-scripts-master"
FAKE_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _bashes():
    found = []
    for cand in ("/bin/bash", shutil.which("bash"), "/opt/homebrew/bin/bash", "/usr/local/bin/bash"):
        if cand and os.path.exists(cand) and os.path.realpath(cand) not in [os.path.realpath(f) for f in found]:
            found.append(cand)
    return found


BASHES = _bashes()


def block_text(script):
    text = Path(script).read_text(encoding="utf-8")
    start = text.index(BEGIN + "\n")
    stop = text.index(END, start) + len(END)
    return text[start:stop] + "\n"


def set_line(script):
    for line in Path(script).read_text(encoding="utf-8").splitlines():
        if re.match(r"^set -[A-Za-z]+( .*)?$", line):
            return line
    raise AssertionError("no top-level set line in %s" % script)


def extract_py(script):
    m = re.search(r"_EXTRACT_PY=\"\$\(cat <<'PY'\n(.*?)\nPY\n\)\"", block_text(script), re.S)
    assert m, "extractor heredoc not found in %s" % script
    return m.group(1)


# --------------------------------------------------------------------------- archives


def git_archive(tmp_path, files, prefix=TOP + "/", paths=None, name="src.tgz"):
    """Build a tarball with `git archive` (real pax commit id). Returns (path, commit)."""
    repo = Path(tmp_path) / ("repo_" + name)
    repo.mkdir()
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }

    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True).stdout

    git("init", "-q")
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    git("add", "-A")
    git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
    commit = git("rev-parse", "HEAD").strip()
    out = Path(tmp_path) / name
    git("archive", "--prefix=" + prefix, "-o", str(out), "HEAD", *(paths or []))
    return out, commit


def standard_files(version="9.9.9"):
    files = {}
    for cloud in ("aws", "azure", "gcp"):
        files["CLOUD/python/%s/pyproject.toml" % cloud] = '[project]\nname = "x-%s"\nversion = "%s"\n' % (cloud, version)
        files["CLOUD/python/%s/main.py" % cloud] = "print('hi')\n"
    return files


def make_tar(tmp_path, members, comment=None, name="custom.tgz"):
    """members: list of (name, kind, payload); kind in file|dir|symlink. comment -> pax global header."""
    out = Path(tmp_path) / name
    kwargs = {"format": tarfile.PAX_FORMAT, "pax_headers": {"comment": comment}} if comment is not None else {"format": tarfile.USTAR_FORMAT}
    with tarfile.open(out, "w:gz", **kwargs) as tf:
        for mname, kind, payload in members:
            ti = tarfile.TarInfo(mname)
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tf.addfile(ti)
            else:
                data = payload.encode() if isinstance(payload, str) else payload
                ti.size = len(data)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(data))
    return out


def valid_members(cloud, version="9.9.9"):
    base = "%s/CLOUD/python/%s" % (TOP, cloud)
    return [
        (base, "dir", None),
        (base + "/pyproject.toml", "file", '[project]\nversion = "%s"\n' % version),
        (base + "/main.py", "file", "print('hi')\n"),
    ]


# --------------------------------------------------------------------------- http


class _Handler(http.server.BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        status, body, ctype = self.routes.get(self.path, (404, b"not found", "text/plain"))
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server:
    def __init__(self, routes):
        handler = type("H", (_Handler,), {"routes": routes})
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def url(self, path):
        return "http://127.0.0.1:%d%s" % (self.port, path)


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- end-to-end shims
# Real bootstrap scripts run against PATH shims: no cloud, no PyPI.

_AWS_SHIM = r"""#!/bin/sh
echo "aws $*" >> "$SHIM_LOG"
case "$*" in
  "sts get-caller-identity"*) echo "111122223333"; exit 0 ;;
  "organizations enable-aws-service-access"*) exit 0 ;;
  "cloudformation activate-organizations-access"*) exit 0 ;;
  "organizations list-roots"*) echo "r-abcd"; exit 0 ;;
  "cloudformation describe-stack-set "*)
      [ "$SHIM_STACKSET_EXISTS" = 1 ] && exit 0
      echo "StackSetNotFoundException" >&2; exit 254 ;;
  "cloudformation create-stack-set "*|"cloudformation update-stack-set "*)
      prev=""
      for a in "$@"; do
        if [ "$prev" = "--template-body" ]; then
          f="${a#file://}"
          if [ "$f" != "$a" ] && [ -f "$f" ]; then
            echo "TEMPLATE_BODY_EXISTS=yes BYTES=$(wc -c < "$f" | tr -d ' ') PATH=$f" >> "$SHIM_LOG"
          else
            echo "TEMPLATE_BODY_EXISTS=no VALUE=$a" >> "$SHIM_LOG"
          fi
        fi
        prev="$a"
      done
      exit 0 ;;
  "cloudformation create-stack-instances"*) echo "OP-1"; exit 0 ;;
  "cloudformation describe-stack-set-operation"*) echo "SUCCEEDED"; exit 0 ;;
  "cloudformation delete-stack-instances"*) echo "OP-2"; exit 0 ;;
  "cloudformation delete-stack-set"*) exit 0 ;;
esac
echo "UNEXPECTED aws $*" >> "$SHIM_LOG"
exit 0
"""

_PYTHON3_SHIM = r"""#!/bin/sh
case "$1" in
  -c) first=$(printf '%s' "$2" | head -n 1 | cut -c1-90); echo "python3 -c $first" >> "$SHIM_LOG" ;;
  *)  echo "python3 $*" >> "$SHIM_LOG" ;;
esac
case "$*" in
  "-m pip install "*)
      for last; do :; done
      if [ -f "$last/pyproject.toml" ]; then echo "PIP_SRC_HAS_PYPROJECT $last" >> "$SHIM_LOG"
      else echo "PIP_SRC_MISSING $last" >> "$SHIM_LOG"; fi
      exit "${SHIM_PIP_EXIT:-0}" ;;
  "-c import boto3") exit 0 ;;
  "-c import sys; print(sys.prefix)") echo "$SHIM_DIR/prefix"; exit 0 ;;
  "-c import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)") [ "${SHIM_IN_VENV:-1}" = 1 ]; exit $? ;;
  "-m site --user-base") echo "$SHIM_DIR/userbase"; exit 0 ;;
  "--version"|"-m pip --version") echo "Python 0.0.0-shim"; exit 0 ;;
esac
exec "$REAL_PYTHON" "$@"
"""

_PIP3_SHIM = r"""#!/bin/sh
echo "pip3 $*" >> "$SHIM_LOG"
case "$1" in
  uninstall) exit 0 ;;
  install)
      for last; do :; done
      if [ -f "$last/pyproject.toml" ]; then echo "PIP_SRC_HAS_PYPROJECT $last" >> "$SHIM_LOG"
      else echo "PIP_SRC_MISSING $last" >> "$SHIM_LOG"; fi
      [ "${SHIM_PIP_EXIT:-0}" != 0 ] && echo "shim: pip failure" >&2
      exit "${SHIM_PIP_EXIT:-0}" ;;
esac
exit 0
"""

_AZ_SHIM = r"""#!/bin/sh
echo "az $*" >> "$SHIM_LOG"
case "$*" in
  "account show --query"*) printf 'Shim Subscription\tsub-1111\n'; exit 0 ;;
  "account show"*) [ "${SHIM_AZ_LOGGED_IN:-1}" = 1 ] && exit 0; exit 1 ;;
esac
exit 0
"""

_GCLOUD_SHIM = r"""#!/bin/sh
echo "gcloud $*" >> "$SHIM_LOG"
case "$*" in
  "auth application-default print-access-token"*) [ "${SHIM_ADC_OK:-1}" = 1 ] && { echo "shim-token"; exit 0; }; exit 1 ;;
  "config get-value account"*) echo "tester@example.com"; exit 0 ;;
esac
exit 0
"""


def make_cloud_shims(entry_point, extra=None):
    """Create a shim dir. `entry_point` is the installed console script name (e.g. aws-sizing)."""
    import tempfile

    shim = Path(tempfile.mkdtemp(prefix="sh", dir="/tmp"))

    def put(name, body):
        p = shim / name
        p.write_text(body)
        p.chmod(0o755)

    put("aws", _AWS_SHIM)
    put("az", _AZ_SHIM)
    put("gcloud", _GCLOUD_SHIM)
    put("pip3", _PIP3_SHIM)
    put("python3", _PYTHON3_SHIM)
    # The entry point uses an env-python3 shebang, which resolves to the python3 shim via PATH
    # (macOS cannot run a script whose shebang interpreter is itself a script).
    put(entry_point, "#!/usr/bin/env python3\nimport os, sys\nopen(os.environ['SHIM_LOG'], 'a').write('%s ' + ' '.join(sys.argv[1:]) + '\\n')\n" % entry_point)
    for name, body in (extra or {}).items():
        put(name, body)
    return shim


def run_script(tmp_path, cloud, args, *, shim, bash="bash", url=None, ref=None, subdir=None,
               stackset_exists=False, pip_exit=0, in_venv=True, extra_env=None,
               az_logged_in=True, adc_ok=True, cloud_shell=False, virtual_env=None, make_clouddrive=False):
    """Run the REAL bootstrap script end to end with shims. Returns (Result, log_lines)."""
    tmp_path = Path(tmp_path)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    tdir = tmp_path / "tmp"
    tdir.mkdir(exist_ok=True)
    work = tmp_path / "cwd"
    work.mkdir(exist_ok=True)
    log = tmp_path / "shim.log"
    log.write_text("")
    env = {k: v for k, v in os.environ.items() if not k.startswith("RUBRIK_DISCOVERY_")}
    env.update(
        PATH="%s:/usr/bin:/bin" % shim,
        HOME=str(home),
        TMPDIR=str(tdir),
        SHIM_LOG=str(log),
        SHIM_DIR=str(shim),
        REAL_PYTHON=sys.executable,
        SHIM_STACKSET_EXISTS="1" if stackset_exists else "0",
        SHIM_PIP_EXIT=str(pip_exit),
        SHIM_IN_VENV="1" if in_venv else "0",
        SHIM_AZ_LOGGED_IN="1" if az_logged_in else "0",
        SHIM_ADC_OK="1" if adc_ok else "0",
        PYTHONDONTWRITEBYTECODE="1",
        TERM="dumb",
    )
    env.pop("VIRTUAL_ENV", None)
    env.pop("CLOUD_SHELL", None)
    if virtual_env:
        env["VIRTUAL_ENV"] = str(virtual_env)
    if cloud_shell:
        env["CLOUD_SHELL"] = "true"
    if make_clouddrive:
        (home / "clouddrive").mkdir(exist_ok=True)
    if url is not None:
        env["RUBRIK_DISCOVERY_SOURCE_URL"] = str(url)
    if ref is not None:
        env["RUBRIK_DISCOVERY_REF"] = ref
    if subdir is not None:
        env["RUBRIK_DISCOVERY_SOURCE_SUBDIR"] = subdir
    env.update(extra_env or {})
    proc = subprocess.run([bash, str(SCRIPTS[cloud])] + list(args), cwd=work, env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=180)
    return Result(proc, tdir), log.read_text().splitlines()


# --------------------------------------------------------------------------- harness

HARNESS = r"""
{set_line}
{block}
mode="$1"
if [ "$mode" = or ]; then
    fetch_source "$CLOUD" || {{ rc=$?; echo "HANDLER rc=$rc"; exit 7; }}
else
    fetch_source "$CLOUD"
fi
echo "SRC_DIR=$SRC_DIR"
echo "COMMIT=$_SRC_COMMIT"
echo "VERSION=$_SRC_VERSION"
echo "PINNED=$_SRC_PINNED"
echo "REF=$_SRC_REF"
[ -n "$SRC_DIR" ] || exit 9
echo "FILES=$(cd "$SRC_DIR" && find . -type f | sort | tr '\n' ' ')"
"""


class Result:
    def __init__(self, proc, tmpdir):
        self.proc = proc
        self.rc = proc.returncode
        self.stdout = proc.stdout
        self.stderr = proc.stderr
        self.vars = dict(re.findall(r"^([A-Z_]+)=(.*)$", proc.stdout, re.M))
        self.tmpdir = tmpdir

    @property
    def leftovers(self):
        return sorted(os.listdir(self.tmpdir)) if os.path.isdir(self.tmpdir) else None


def run_fetch(tmp_path, cloud, *, bash="bash", mode="or", url=None, ref=None, subdir=None, tmpdir=None, extra_env=None):
    tmp_path = Path(tmp_path)
    script = SCRIPTS[cloud]
    harness = tmp_path / ("harness_%s_%s.sh" % (cloud, mode))
    harness.write_text(HARNESS.format(set_line=set_line(script), block=block_text(script)))
    work = tmp_path / "cwd"
    work.mkdir(exist_ok=True)
    tdir = Path(tmpdir) if tmpdir is not None else tmp_path / "tmp"
    if tmpdir is None:
        tdir.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("RUBRIK_DISCOVERY_")}
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    env["TMPDIR"] = str(tdir)
    env["CLOUD"] = cloud
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if url is not None:
        env["RUBRIK_DISCOVERY_SOURCE_URL"] = str(url)
    if ref is not None:
        env["RUBRIK_DISCOVERY_REF"] = ref
    if subdir is not None:
        env["RUBRIK_DISCOVERY_SOURCE_SUBDIR"] = subdir
    env.update(extra_env or {})
    proc = subprocess.run([bash, str(harness), mode], cwd=work, env=env, capture_output=True, text=True, timeout=120)
    return Result(proc, tdir)

#!/usr/bin/env bash
# Rubrik Discovery — Azure Edition
# Customer bootstrap script (paste into Azure Cloud Shell):
#   bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/azure/install.sh)
#
# With options:
#   bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/azure/install.sh) --all
#   bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/azure/install.sh) --subs <id1>,<id2>
#
# The discovery source is downloaded from the public GitHub repository
# rubrikinc/rubrik-sizing-scripts (branch master unless a ref is given) and
# installed with pip. To run an exact, immutable version, pin a commit in BOTH
# places (the script URL and RUBRIK_DISCOVERY_REF); the run aborts if the
# downloaded source is not that commit:
#   S=<40-hex commit>
#   RUBRIK_DISCOVERY_REF=$S bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/$S/CLOUD/python/azure/install.sh) --all
#
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BOLD='\033[1m'; RESET='\033[0m'

banner() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║   Rubrik Discovery — Azure Edition               ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
    echo ""
}

die() { echo -e "${RED}Error: $*${RESET}" >&2; exit 1; }
info() { echo -e "  ${GREEN}✓${RESET}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $*"; }

# BEGIN fetch_source
# Download the discovery source for a git ref and extract one cloud's project dir.
# fetch_source <aws|azure|gcp> runs in the caller's shell and sets:
#   _SRC_ROOT    temp dir holding everything (removed by the EXIT trap below)
#   SRC_DIR      project dir containing pyproject.toml
#   _SRC_REF     the ref that was fetched
#   _SRC_COMMIT  commit id from the archive header, or empty
#   _SRC_VERSION package version read from pyproject.toml
#   _SRC_PINNED  1 when the ref was a commit id and it was verified
# On failure it prints one line to stderr and returns non-zero. Call it as
# "fetch_source x || handler": bash ignores set -e inside such a call, so every
# step below returns explicitly instead of relying on it.
# Optional environment: RUBRIK_DISCOVERY_REF (default master),
# RUBRIK_DISCOVERY_SOURCE_URL (https, file, or loopback http), and
# RUBRIK_DISCOVERY_SOURCE_SUBDIR (default CLOUD/python/<cloud>).
_SRC_ROOT=""; SRC_DIR=""; _SRC_REF=""; _SRC_COMMIT=""; _SRC_VERSION=""; _SRC_PINNED=""
_EXTRACT_PY="$(cat <<'PY'
import os, re, sys, tarfile, zlib
archive, subdir, dest, ref = sys.argv[1:5]
def die(msg):
    sys.exit("fetch_source: " + msg)
root = os.path.realpath(dest)
commit = ""
try:
    with tarfile.open(archive, "r:gz") as tf:
        for m in tf:
            _top, _, rel = m.name.partition("/")
            if ".." in rel.split("/") or rel.startswith("/"):
                die("unsafe path in archive: " + m.name)
            if not (rel == subdir or rel.startswith(subdir + "/")):
                continue
            if not (m.isfile() or m.isdir()):
                continue
            target = os.path.realpath(os.path.join(root, rel))
            if target != root and not target.startswith(root + os.sep):
                die("unsafe path in archive: " + m.name)
            m.name = rel
            try:
                tf.extract(m, root, filter="data")
            except TypeError:
                tf.extract(m, root)
        commit = (tf.pax_headers or {}).get("comment", "")
except (tarfile.TarError, EOFError, OSError, zlib.error) as e:
    die("archive unreadable or truncated (%s: %s)" % (e.__class__.__name__, e))
if not os.path.isfile(os.path.join(root, subdir, "pyproject.toml")):
    die("%s/pyproject.toml not found in archive - wrong ref or layout?" % subdir)
if commit and not re.fullmatch(r"[0-9a-f]{40,64}", commit):
    commit = ""
if re.fullmatch(r"[0-9a-fA-F]{7,40}", ref):
    ref = ref.lower()
    if not commit:
        die("cannot verify pinned commit %s: the archive carries no commit id" % ref)
    if not commit.startswith(ref):
        die("requested commit %s but the archive is commit %s" % (ref, commit))
with open(os.path.join(root, ".source-commit"), "w") as f:
    f.write(commit)
PY
)"
fetch_source() {
    local cloud="$1" url subdir rc http
    _SRC_REF="${RUBRIK_DISCOVERY_REF:-master}"
    url="${RUBRIK_DISCOVERY_SOURCE_URL:-https://github.com/rubrikinc/rubrik-sizing-scripts/archive/${_SRC_REF}.tar.gz}"
    subdir="${RUBRIK_DISCOVERY_SOURCE_SUBDIR:-CLOUD/python/${cloud}}"
    case "$url" in
        https://*|file://*|http://127.0.0.1:*|http://localhost:*) ;;
        *) echo "unsupported RUBRIK_DISCOVERY_SOURCE_URL scheme (https:// or file:// only)" >&2; return 1 ;;
    esac
    _SRC_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rubrik-discovery.XXXXXX")" || { echo "cannot create a temp dir under ${TMPDIR:-/tmp}" >&2; return 1; }
    local proto=()
    case "$url" in https://*) proto=(--proto '=https' --proto-redir '=https') ;; esac
    rc=0
    http="$(curl -fsSL --retry 3 --connect-timeout 20 --max-time 300 ${proto[@]+"${proto[@]}"} -w '%{http_code}' -o "${_SRC_ROOT}/src.tgz" "$url")" || rc=$?
    if [ "$rc" -ne 0 ]; then
        case "$rc" in
            22)                 echo "GitHub returned HTTP ${http} for ${url} — does ref '${_SRC_REF}' exist? (429/5xx: retry shortly)" >&2 ;;
            6|7|28|35|52|55|56) echo "could not reach GitHub — check that github.com and codeload.github.com are reachable from this shell" >&2 ;;
            *)                  echo "download failed (curl exit ${rc})" >&2 ;;
        esac
        return 1
    fi
    python3 -c "$_EXTRACT_PY" "${_SRC_ROOT}/src.tgz" "$subdir" "$_SRC_ROOT" "$_SRC_REF" || return 1
    SRC_DIR="${_SRC_ROOT}/${subdir}"
    _SRC_COMMIT="$(cat "${_SRC_ROOT}/.source-commit" 2>/dev/null || true)"
    _SRC_VERSION="$(sed -n '/^version *=/{s/^version *= *"\(.*\)"/\1/p;q;}' "${SRC_DIR}/pyproject.toml" 2>/dev/null || true)"
    _SRC_PINNED=""
    case "$_SRC_REF" in
        *[!0-9a-fA-F]*|"") ;;
        *) if [ "${#_SRC_REF}" -ge 7 ] && [ "${#_SRC_REF}" -le 40 ]; then _SRC_PINNED=1; fi ;;
    esac
    return 0
}
_src_cleanup() { [ -z "${_SRC_ROOT:-}" ] || rm -rf "${_SRC_ROOT}"; }
trap _src_cleanup EXIT
# END fetch_source

# ── Preflight checks ──────────────────────────────────────────────────────────
check_prereqs() {
    command -v python3 >/dev/null 2>&1 || die "python3 not found. Run from Azure Cloud Shell."
    command -v pip3    >/dev/null 2>&1 || die "pip3 not found. Run from Azure Cloud Shell."
    command -v curl    >/dev/null 2>&1 || die "curl not found. Run from Azure Cloud Shell."
    command -v az      >/dev/null 2>&1 || die "Azure CLI not found. Run from Azure Cloud Shell."

    local py_version
    py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    # Require 3.10+
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
        || die "Python 3.10+ required (found ${py_version}). Upgrade Python or use a newer Cloud Shell image."
}

# ── Verify az login ───────────────────────────────────────────────────────────
check_az_login() {
    if ! az account show >/dev/null 2>&1; then
        warn "Not logged in to Azure CLI."
        echo "  Run 'az login' first, then re-run this script."
        exit 1
    fi
    local account
    account=$(az account show --query "{name:name, id:id}" -o tsv 2>/dev/null | tr '\t' ' ')
    info "Azure context: ${account}"
}

# ── Install the tool ──────────────────────────────────────────────────────────
install_tool() {
    echo ""
    echo "  Installing Rubrik Discovery tool…"

    # Use --user if not in a venv and not root, to avoid needing sudo.
    local pip_flags="--quiet --disable-pip-version-check"
    if [[ "${VIRTUAL_ENV:-}" == "" ]] && [[ "$(id -u)" != "0" ]]; then
        pip_flags="$pip_flags --user"
    fi

    # Fetch BEFORE uninstalling: a failed download must never remove a working install.
    fetch_source azure || die "Could not fetch the discovery tool from GitHub. Check that github.com and codeload.github.com are reachable from this shell, or pin an exact commit with RUBRIK_DISCOVERY_REF (see the top of this script)."
    info "Rubrik Discovery Azure ${_SRC_VERSION:-unknown} — ${_SRC_REF} @ ${_SRC_COMMIT:-unknown}${_SRC_PINNED:+ (pinned, verified)}"

    # Uninstall previous version silently before upgrading.
    pip3 uninstall --yes rubrik-discovery-azure >/dev/null 2>&1 || true

    # Capture all pip output — we only want the customer to see it if
    # the install actually fails.  Azure Cloud Shell comes with
    # pre-installed packages (ansible-core, etc.) whose own broken
    # dependencies trigger noisy "ERROR: pip's dependency resolver…"
    # lines that are unrelated to our install.  pip still exits 0 in
    # those cases; hiding the resolver noise on success keeps the
    # customer's terminal clean while preserving full diagnostics for
    # real failures.
    local install_log
    install_log=$(mktemp)
    if ! pip3 install $pip_flags "${SRC_DIR}" >"$install_log" 2>&1; then
        echo ""
        cat "$install_log" >&2
        rm -f "$install_log"
        die "Installation failed. Check your network connection and try again."
    fi
    rm -f "$install_log"

    # Ensure ~/.local/bin is on PATH (needed for --user installs in some envs).
    if [[ ":${PATH}:" != *":${HOME}/.local/bin:"* ]]; then
        export PATH="${HOME}/.local/bin:${PATH}"
    fi

    info "Tool installed successfully."
}

# ── Output directory ──────────────────────────────────────────────────────────
resolve_output() {
    if [[ -d "${HOME}/clouddrive" ]]; then
        echo "${HOME}/clouddrive"
    else
        mkdir -p "${HOME}/rubrik-output"
        echo "${HOME}/rubrik-output"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
banner
check_prereqs
check_az_login
install_tool

OUTPUT_DIR=$(resolve_output)
info "Output will be saved to: ${OUTPUT_DIR}"
echo ""

# Run the tool — forward all arguments from this script to rubrik-discovery.
rubrik-discovery --output "${OUTPUT_DIR}" "$@"

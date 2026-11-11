#!/usr/bin/env bash
# Full customer bootstrap for the AWS Sizing Tool (Rubrik Discovery).
# Default mode: SSO (IAM Identity Center) — no StackSet deployment needed.
# Run 'aws sso login' in CloudShell before executing this script.
# All output is packaged into a zip for download from CloudShell.
#
# The discovery source is downloaded from the public GitHub repository
# rubrikinc/rubrik-sizing-scripts (branch master unless a ref is given) and
# installed with pip. To run an exact, immutable version, pin a commit in BOTH
# places (the script URL and RUBRIK_DISCOVERY_REF); the run aborts if the
# downloaded source is not that commit:
#   S=<40-hex commit>
#   RUBRIK_DISCOVERY_REF=$S bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/$S/CLOUD/python/aws/install.sh) --sso --role-name ReadOnlyAccess
#
# Default (SSO scan — recommended; asks for the permission set unless --role-name gives it):
#   bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --role-name ReadOnlyAccess
#
# Single-account scan (current account only, uses ambient credentials — no SSO or StackSet needed):
#   bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --single-account
#
# SSO scan with a pre-deployed runner role (customer provides role ARN in advance):
#   bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --assume-role arn:aws:iam::123456789012:role/SizingToolRunnerRole --role-name ReadOnlyAccess
#
# SSO scan with explicit start URL (auto-detected from ~/.aws/config if omitted):
#   bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --sso-start-url https://myorg.awsapps.com/start --role-name AdministratorAccess
#
# Scan only specific accounts (skips account discovery):
#   bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --accounts 123456789012,234567890123 --role-name ReadOnlyAccess
#
# Org scan mode (requires StackSet role deployed in each account):
#   First run (deploys StackSet + scans):
#     bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --org
#   Deploy IAM role only — customer can review it first, then run the scan:
#     bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --org --deploy-role-only
#   Subsequent runs (StackSet already deployed, just scan):
#     bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --org --skip-stackset
#   If organizations:ListRoots is denied, pass the root OU ID directly:
#     bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --org --root-ou-id r-xxxx
#   Use an existing cross-account role instead of deploying the StackSet:
#     bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --org --skip-stackset --role-name OrganizationAccountAccessRole
#
# Troubleshooting (verbose pip output, Python path info, debug messages):
#   bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --org --debug

# -u: treat unset vars as errors; -o pipefail: propagate pipe failures
# Intentionally no -e: we handle errors per-step and keep going where possible
set -uo pipefail

# Where this script comes from, for the commands printed in hints below. A pinned run
# (RUBRIK_DISCOVERY_REF set) keeps its pin in any command printed.
BOOTSTRAP_URL="https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/${RUBRIK_DISCOVERY_REF:-master}/CLOUD/python/aws/install.sh"
BOOTSTRAP_CMD="bash <(curl -fsSL ${BOOTSTRAP_URL})"
[ -n "${RUBRIK_DISCOVERY_REF:-}" ] && BOOTSTRAP_CMD="RUBRIK_DISCOVERY_REF=${RUBRIK_DISCOVERY_REF} ${BOOTSTRAP_CMD}"
STACKSET_NAME="aws-sizing-spoke-roles"
ROLE_NAME="RubrikDiscoveryRole"
REGION="us-east-1"
SKIP_STACKSET=false
DEPLOY_ROLE_ONLY=false
SSO_MODE=true          # SSO is the default mode; use --org to switch
SINGLE_ACCOUNT_MODE=false
SSO_START_URL=""
ASSUME_ROLE_ARN=""
ACCOUNTS=""
REGIONS=""
EXCLUDE_REGIONS=""
SERVICES=""
ROOT_OU_ID=""
ROOT_ID=""
ROLE_NAME_OVERRIDE=""
EXTRA_ARGS=()
STACKSET_WARNINGS=()
_stackset_deployed=false
DEBUG_MODE=false

# ── Parse flags ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --org)               SSO_MODE=false; shift ;;
        --single-account)    SINGLE_ACCOUNT_MODE=true; SSO_MODE=false; shift ;;
        --skip-stackset)     SKIP_STACKSET=true; SSO_MODE=false; shift ;;
        --deploy-role-only)  DEPLOY_ROLE_ONLY=true; SSO_MODE=false; shift ;;
        --sso)               SSO_MODE=true; shift ;;
        --sso-start-url)     SSO_START_URL="$2"; shift 2 ;;
        --sso-start-url=*)   SSO_START_URL="${1#*=}"; shift ;;
        --assume-role)       ASSUME_ROLE_ARN="$2"; shift 2 ;;
        --assume-role=*)     ASSUME_ROLE_ARN="${1#*=}"; shift ;;
        --accounts)          ACCOUNTS="$2"; shift 2 ;;
        --accounts=*)        ACCOUNTS="${1#*=}"; shift ;;
        --regions)           REGIONS="$2"; shift 2 ;;
        --regions=*)         REGIONS="${1#*=}"; shift ;;
        --exclude-regions)   EXCLUDE_REGIONS="$2"; shift 2 ;;
        --exclude-regions=*) EXCLUDE_REGIONS="${1#*=}"; shift ;;
        --services)          SERVICES="$2"; shift 2 ;;
        --services=*)        SERVICES="${1#*=}"; shift ;;
        --root-ou-id)        ROOT_OU_ID="$2"; shift 2 ;;
        --root-ou-id=*)      ROOT_OU_ID="${1#*=}"; shift ;;
        --role-name)         ROLE_NAME_OVERRIDE="$2"; shift 2 ;;
        --role-name=*)       ROLE_NAME_OVERRIDE="${1#*=}"; shift ;;
        --debug)             DEBUG_MODE=true; shift ;;
        *)                   EXTRA_ARGS+=("$1"); shift ;;
    esac
done

# ── Auto-detect SSO start URL from ~/.aws/config if not provided ──────────────
if [ "$SSO_MODE" = true ] && [ -z "$SSO_START_URL" ]; then
    _detected=$(awk -F'[= ]+' '/^\[sso-session /{in_s=1} in_s && /^sso_start_url/{print $2; exit}' \
        ~/.aws/config 2>/dev/null || true)
    if [ -n "$_detected" ]; then
        SSO_START_URL="$_detected"
    fi
fi

# ── Region picker ─────────────────────────────────────────────────────────────
# Called after install, before scan. Populates REGIONS unless already set.
_ALL_REGIONS=(
    "us-east-1:US East - N. Virginia"
    "us-east-2:US East - Ohio"
    "us-west-1:US West - N. California"
    "us-west-2:US West - Oregon"
    "ca-central-1:Canada - Central"
    "eu-west-1:Europe - Ireland"
    "eu-west-2:Europe - London"
    "eu-west-3:Europe - Paris"
    "eu-central-1:Europe - Frankfurt"
    "eu-north-1:Europe - Stockholm"
    "ap-southeast-1:Asia Pacific - Singapore"
    "ap-southeast-2:Asia Pacific - Sydney"
    "ap-northeast-1:Asia Pacific - Tokyo"
    "ap-northeast-2:Asia Pacific - Seoul"
    "ap-northeast-3:Asia Pacific - Osaka"
    "ap-south-1:Asia Pacific - Mumbai"
    "sa-east-1:South America - Sao Paulo"
)

_pick_regions() {
    # Already set via --regions flag — skip prompt
    [ -n "$REGIONS" ] && { info "Regions (from flag): ${REGIONS}"; return; }
    # Non-interactive (piped input) — scan all
    [ -t 0 ] || { info "Non-interactive mode — scanning all regions"; return; }

    if command -v whiptail &>/dev/null; then
        # Build checklist args: tag  description  ON
        local ITEMS=()
        for entry in "${_ALL_REGIONS[@]}"; do
            ITEMS+=("${entry%%:*}" "${entry##*:}" "ON")
        done
        local selected
        selected=$(whiptail \
            --title "AWS Sizing Tool — Region Selection" \
            --checklist $'Space = toggle   Tab = buttons   Enter = confirm\nLeave all checked to scan every region.' \
            22 66 17 \
            "${ITEMS[@]}" \
            3>&1 1>&2 2>&3) || return   # Cancelled → scan all
        # Strip quotes; convert spaces to commas
        selected=$(printf '%s' "$selected" | tr -d '"' | tr ' ' ',')
        [ -n "$selected" ] && REGIONS="$selected"
    else
        # Fallback: numbered list, type comma-separated numbers or Enter for all
        printf "\n"
        printf "${CYAN}${BOLD}  Select regions to scan:${RESET}\n"
        printf "${DIM}  Enter numbers separated by commas, or press Enter to scan all.${RESET}\n\n"
        local i=1
        for entry in "${_ALL_REGIONS[@]}"; do
            printf "  ${DIM}%2d)${RESET}  %-18s %s\n" "$i" "${entry%%:*}" "${entry##*:}"
            ((i++))
        done
        printf "\n"
        local selection
        read -rp "  Regions [all]: " selection
        if [ -n "$selection" ]; then
            local picked=()
            IFS=',' read -ra nums <<< "$selection"
            for n in "${nums[@]}"; do
                n="${n// /}"
                if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "${#_ALL_REGIONS[@]}" ]; then
                    picked+=("${_ALL_REGIONS[$((n-1))]%%:*}")
                fi
            done
            [ "${#picked[@]}" -gt 0 ] && REGIONS=$(IFS=','; echo "${picked[*]}")
        fi
    fi

    if [ -n "$REGIONS" ]; then
        info "Scanning regions: ${REGIONS}"
    else
        info "Scanning all regions"
    fi
}

# ── StackSet cleanup ─────────────────────────────────────────────────────────
_cleanup_stackset() {
    local _cleanup_ok=true

    if [ -n "$ROOT_ID" ]; then
        info "Removing stack instances (this may take a few minutes)..."
        local CLEANUP_OP
        CLEANUP_OP=$(aws cloudformation delete-stack-instances \
            --stack-set-name "$STACKSET_NAME" \
            --deployment-targets OrganizationalUnitIds="$ROOT_ID" \
            --regions "$REGION" \
            --no-retain-stacks \
            --region "$REGION" \
            --query 'OperationId' --output text 2>/tmp/dsi_err || echo "")

        if [ -z "$CLEANUP_OP" ]; then
            _err=$(cat /tmp/dsi_err 2>/dev/null || true)
            if ! echo "$_err" | grep -qi "no.*instance\|does not exist"; then
                warn "Could not remove stack instances: ${_err}"
                _cleanup_ok=false
            fi
        else
            printf "      Waiting"
            while true; do
                STATUS=$(aws cloudformation describe-stack-set-operation \
                    --stack-set-name "$STACKSET_NAME" \
                    --operation-id "$CLEANUP_OP" \
                    --region "$REGION" \
                    --query 'StackSetOperation.Status' --output text 2>/dev/null || echo "UNKNOWN")
                case $STATUS in
                    SUCCEEDED) printf "\n"; break ;;
                    FAILED|STOPPED)
                        printf "\n"
                        warn "Stack instance deletion ended with status: ${STATUS}"
                        _cleanup_ok=false; break ;;
                    UNKNOWN)
                        printf "\n"
                        warn "Could not poll deletion status — check CloudFormation console"
                        _cleanup_ok=false; break ;;
                    *) printf "."; sleep 10 ;;
                esac
            done
        fi
    fi

    if [ "$_cleanup_ok" = true ]; then
        info "Deleting StackSet..."
        if ! aws cloudformation delete-stack-set \
                --stack-set-name "$STACKSET_NAME" \
                --region "$REGION" 2>/tmp/dss_err; then
            _err=$(cat /tmp/dss_err 2>/dev/null || true)
            warn "Could not delete StackSet: ${_err}"
            _cleanup_ok=false
        fi
    fi

    if [ "$_cleanup_ok" = true ]; then
        printf "${GREEN}${BOLD}  ✓ CloudFormation StackSet cleaned up successfully.${RESET}\n\n"
    else
        printf "\n${YELLOW}${BOLD}  ⚠  Couldn't automatically clean up the CloudFormation StackSet.${RESET}\n"
        printf "${DIM}     Please delete it manually in the CloudFormation console:${RESET}\n"
        printf "${DIM}     CloudFormation → StackSets → ${STACKSET_NAME} → Actions → Delete${RESET}\n\n"
    fi
}

# ── Colors ────────────────────────────────────────────────────────────────────
BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
WHITE='\033[97m'
RESET='\033[0m'

step()    { printf "\n${CYAN}${BOLD}[%s/%s]${RESET} ${WHITE}%s${RESET}\n" "$1" "$2" "$3"; }
ok()      { printf "${GREEN}${BOLD}      ✓ Done${RESET}\n"; }
info()    { printf "${DIM}      %s${RESET}\n" "$1"; }
warn()    { printf "${YELLOW}      ⚠  %s${RESET}\n" "$1"; }
err()     { printf "${RED}${BOLD}      ✗  %s${RESET}\n" "$1" >&2; }
hint()    { printf "${DIM}         → %s${RESET}\n" "$1" >&2; }
debug()   { [ "$DEBUG_MODE" = true ] && printf "${DIM}      [debug] %s${RESET}\n" "$1"; }
divider() { printf "${DIM}      ────────────────────────────────────${RESET}\n"; }

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

TOTAL_STEPS=4  # SSO default: identify, download, install, scan
[ "$SSO_MODE" = false ] && [ "$SKIP_STACKSET" = false ] && [ "$SINGLE_ACCOUNT_MODE" = false ] && TOTAL_STEPS=6  # org+StackSet adds deploy + cleanup steps
[ "$SINGLE_ACCOUNT_MODE" = true ] && TOTAL_STEPS=3  # single-account: download, install, scan (no identity check needed)

# ── Header ────────────────────────────────────────────────────────────────────
printf "\n${CYAN}${BOLD}"
printf "┌─────────────────────────────────────────┐\n"
printf "│%s│\n" "         AWS Sizing Tool                 "
printf "│         Rubrik Discovery Engine          │\n"
printf "└─────────────────────────────────────────┘\n"
printf "${RESET}\n"

# ── SSO permission set: IAM Identity Center has no default one ────────────────
if [ "$SSO_MODE" = true ] && [ -z "$ROLE_NAME_OVERRIDE" ]; then
    if [ -t 0 ]; then
        info "An SSO scan signs in to each account with an IAM Identity Center permission set."
        read -rp "      Permission set name (as assigned to you, e.g. ReadOnlyAccess): " ROLE_NAME_OVERRIDE || true
    fi
    if [ -z "$ROLE_NAME_OVERRIDE" ]; then
        err "An SSO scan needs the permission set to sign in with."
        hint "Run again with --role-name <permission set>, for example: ${BOOTSTRAP_CMD} --role-name ReadOnlyAccess"
        exit 1
    fi
fi

# ── Step 1: Get account identity (skipped in single-account mode) ─────────────
if [ "$SINGLE_ACCOUNT_MODE" = false ]; then
    step 1 "$TOTAL_STEPS" "Identifying management account..."
    if ! ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>&1); then
        err "Cannot identify AWS account: ${ACCOUNT_ID}"
        hint "Make sure your AWS credentials are valid and try again."
        exit 1
    fi
    info "Account: ${ACCOUNT_ID}"
    ok
fi

# ── Step 1/2: Download source ─────────────────────────────────────────────────
_download_step=$([ "$SINGLE_ACCOUNT_MODE" = true ] && echo 1 || echo 2)
step "$_download_step" "$TOTAL_STEPS" "Downloading aws-sizing..."
for _req in python3 curl; do
    if ! command -v "$_req" >/dev/null 2>&1; then
        err "${_req} is required but was not found in PATH"
        hint "Run this from AWS CloudShell, or install ${_req} and re-run."
        exit 1
    fi
done
if ! fetch_source aws; then
    err "Could not fetch the discovery tool from GitHub"
    hint "Check that github.com and codeload.github.com are reachable from this shell,"
    hint "or pin an exact commit with RUBRIK_DISCOVERY_REF (see the top of this script)."
    exit 1
fi
info "aws-sizing ${_SRC_VERSION:-unknown} — ${_SRC_REF} @ ${_SRC_COMMIT:-unknown}${_SRC_PINNED:+ (pinned, verified)}"
debug "Source dir: ${SRC_DIR}"
ok

# ── Step 2/3: Install ─────────────────────────────────────────────────────────
_install_step=$([ "$SINGLE_ACCOUNT_MODE" = true ] && echo 2 || echo 3)
step "$_install_step" "$TOTAL_STEPS" "Installing..."
_PIP_QUIET=(-q)
[ "$DEBUG_MODE" = true ] && _PIP_QUIET=()
_PIP_USER=()
# CloudShell runs inside a virtualenv where --user installs are blocked.
# Capture sys.prefix so we can add the venv's bin/ to PATH after install —
# without this, a stale aws-sizing entry point from a previous run (with a
# different Python version) would be found first and fail to import boto3.
_INSTALL_PREFIX=$(python3 -c "import sys; print(sys.prefix)" 2>/dev/null)
if python3 -c "import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)" 2>/dev/null; then
    debug "Running inside a virtualenv — no --user flag"
    debug "Venv prefix: $_INSTALL_PREFIX"
else
    _PIP_USER=(--user)
fi
debug "Python: $(python3 --version 2>&1)"
debug "pip:    $(python3 -m pip --version 2>&1)"
debug "User:   ${_PIP_USER[*]:-<venv>}"

# Expand possibly-empty arrays with the ${arr[@]+"${arr[@]}"} idiom so an empty
# array yields zero args (not an "unbound variable" error under `set -u` on
# bash <= 4.3, e.g. Amazon Linux 2's bash 4.2 and macOS bash 3.2).
if ! python3 -m pip install --ignore-installed ${_PIP_QUIET[@]+"${_PIP_QUIET[@]}"} ${_PIP_USER[@]+"${_PIP_USER[@]}"} "${SRC_DIR}" 2>/tmp/pip_err; then
    err "pip install failed"
    hint "Python: $(python3 --version 2>&1)"
    hint "pip:    $(python3 -m pip --version 2>&1)"
    hint "Re-run with --debug for verbose pip output"
    cat /tmp/pip_err >&2
    exit 1
fi

# Prepend the install-prefix bin so the freshly installed aws-sizing entry
# point (with the correct Python shebang) is found before any stale copy
# left in ~/.local/bin from a previous run with a different Python version.
export PATH="${_INSTALL_PREFIX}/bin:$(python3 -m site --user-base)/bin:$HOME/.local/bin:$PATH"

# Verify importability using the exact Python from the entry point's shebang
_SIZING_BIN=$(command -v aws-sizing 2>/dev/null || true)
if [ -z "$_SIZING_BIN" ]; then
    err "aws-sizing not found in PATH after install"
    hint "Searched: ${_INSTALL_PREFIX}/bin  $(python3 -m site --user-base)/bin  $HOME/.local/bin"
    exit 1
fi
# Extract shebang Python — handles both "#!/path/python3" and "#!/usr/bin/env python3"
_SHEBANG=$(head -n1 "$_SIZING_BIN" | sed 's/^#!//')
if echo "$_SHEBANG" | grep -q "env "; then
    _ENTRY_PYTHON=$(command -v "$(echo "$_SHEBANG" | awk '{print $NF}')" 2>/dev/null || echo "python3")
else
    _ENTRY_PYTHON=$(echo "$_SHEBANG" | awk '{print $1}')
fi
debug "Entry point:  $_SIZING_BIN"
debug "Entry python: $_ENTRY_PYTHON ($(${_ENTRY_PYTHON} --version 2>&1))"

if ! "${_ENTRY_PYTHON}" -c "import boto3" 2>/tmp/dep_check_err; then
    _missing=$(grep "No module named" /tmp/dep_check_err \
               | sed "s/.*No module named '//;s/'.*//" | sort -u | tr '\n' ' ')
    err "Python dependencies not importable: ${_missing:-unknown}"
    hint "Entry Python: ${_ENTRY_PYTHON} ($("${_ENTRY_PYTHON}" --version 2>&1))"
    hint "Install prefix: ${_INSTALL_PREFIX}"
    hint "pip show boto3: $(python3 -m pip show boto3 2>/dev/null | grep -E 'Location:|Version:' | tr '\n' ' ')"
    hint "sys.path: $("${_ENTRY_PYTHON}" -c 'import sys; print(sys.path)' 2>/dev/null)"
    hint "Re-run with --debug for verbose pip output"
    exit 1
fi
ok

if [ "$SKIP_STACKSET" = false ] && [ "$SSO_MODE" = false ] && [ "$SINGLE_ACCOUNT_MODE" = false ]; then

    # ── Step 4: Deploy StackSet ───────────────────────────────────────────────
    step 4 "$TOTAL_STEPS" "Deploying IAM role StackSet across org..."
    _stackset_ok=true

    # Show where customers can review the IAM role template before deploying. The template
    # is read from the extracted source tree: CloudFormation only accepts S3 locations for a
    # template URL, so the StackSet is created from the local file with --template-body.
    TEMPLATE_FILE="${SRC_DIR}/iac/2-sizing-tool-spokes.yaml"
    REVIEW_URL="https://github.com/rubrikinc/rubrik-sizing-scripts/blob/${_SRC_REF}/CLOUD/python/aws/iac/2-sizing-tool-spokes.yaml"
    printf "\n"
    printf "${DIM}      IAM role template (read-only permissions only):${RESET}\n"
    printf "${DIM}      ${REVIEW_URL}${RESET}\n"
    printf "${DIM}      Permissions granted: ec2:Describe*, rds:Describe*, dynamodb:Describe*,${RESET}\n"
    printf "${DIM}      s3:List*, kms:List*, secretsmanager:List*, sqs:List*,${RESET}\n"
    printf "${DIM}      backup:List*/Get*, ce:GetCostAndUsage, cloudwatch:GetMetricStatistics${RESET}\n"
    printf "\n"

    if [ ! -f "$TEMPLATE_FILE" ]; then
        err "IAM role template not found in the downloaded source: iac/2-sizing-tool-spokes.yaml"
        _stackset_ok=false
        STACKSET_WARNINGS+=("StackSet not deployed: the IAM role template was missing from the downloaded source")
    fi

    # Enable trusted access — try both mechanisms; surface any real failures
    info "Enabling CloudFormation StackSets trusted access..."
    _trusted_access_ok=false
    _enable_svc_warn=""  # deferred — only print if both methods fail
    if aws organizations enable-aws-service-access \
            --service-principal stacksets.cloudformation.amazonaws.com 2>/tmp/sts_err; then
        _trusted_access_ok=true
    else
        _msg=$(cat /tmp/sts_err)
        if echo "$_msg" | grep -qi "AlreadyExistsException\|already.*enabled"; then
            _trusted_access_ok=true  # already on, that's fine
        else
            _enable_svc_warn="enable-aws-service-access: ${_msg}"
        fi
    fi
    # Newer orgs use activate-organizations-access instead — try it regardless
    if aws cloudformation activate-organizations-access 2>/tmp/cfn_org_err; then
        _trusted_access_ok=true
    else
        _msg=$(cat /tmp/cfn_org_err)
        if echo "$_msg" | grep -qi "already.*active\|AlreadyExistsException"; then
            _trusted_access_ok=true
        else
            warn "activate-organizations-access: ${_msg}"
        fi
    fi
    # Only surface the first warning if both methods failed
    [ -n "$_enable_svc_warn" ] && [ "$_trusted_access_ok" = false ] && warn "$_enable_svc_warn"
    if [ "$_trusted_access_ok" = false ]; then
        err "Could not enable StackSets trusted access with Organizations."
        hint "In the CloudFormation console → StackSets → Activate Organizations access"
        hint "then re-run this script."
        _stackset_ok=false
        STACKSET_WARNINGS+=("StackSets trusted access could not be enabled — stack instances may not deploy")
    else
        info "Trusted access confirmed."
    fi

    # Get the org root ID
    if [ -n "$ROOT_OU_ID" ]; then
        ROOT_ID="$ROOT_OU_ID"
        info "Using provided org root: ${ROOT_ID}"
    else
        info "Looking up org root ID..."
        if ! ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text 2>/tmp/roots_err); then
            _msg=$(cat /tmp/roots_err)
            err "Cannot list org roots: ${_msg}"
            if echo "$_msg" | grep -q "AccessDeniedException"; then
                hint "Missing permission: organizations:ListRoots"
                hint "Fix: attach the Organizations read policy to your role, OR"
                hint "     re-run with --root-ou-id r-xxxx"
                hint "     (find your Root ID: AWS Console → Organizations → AWS accounts → Root)"
            fi
            warn "Skipping StackSet deployment — will scan with existing roles."
            _stackset_ok=false
            STACKSET_WARNINGS+=("StackSet not deployed: organizations:ListRoots denied. Re-run with --root-ou-id r-xxxx or grant the permission.")
        else
            info "Org root: ${ROOT_ID}"
        fi
    fi

    if [ "$_stackset_ok" = true ]; then
        PARAMS="ParameterKey=ManagementAccountId,ParameterValue=${ACCOUNT_ID} \
                ParameterKey=RoleName,ParameterValue=${ROLE_NAME}"

        # Create or update the StackSet
        if aws cloudformation describe-stack-set \
                --stack-set-name "$STACKSET_NAME" \
                --region "$REGION" &>/dev/null; then
            warn "StackSet already exists — updating template..."
            aws cloudformation update-stack-set \
                --stack-set-name "$STACKSET_NAME" \
                --template-body "file://${TEMPLATE_FILE}" \
                --parameters $PARAMS \
                --capabilities CAPABILITY_NAMED_IAM \
                --region "$REGION" \
                --output text --query 'OperationId' > /dev/null 2>&1 || true
        else
            info "Creating StackSet..."
            if ! aws cloudformation create-stack-set \
                    --stack-set-name "$STACKSET_NAME" \
                    --template-body "file://${TEMPLATE_FILE}" \
                    --parameters $PARAMS \
                    --capabilities CAPABILITY_NAMED_IAM \
                    --permission-model SERVICE_MANAGED \
                    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
                    --region "$REGION" > /dev/null 2>/tmp/ss_err; then
                err "Failed to create StackSet: $(cat /tmp/ss_err)"
                _stackset_ok=false
                STACKSET_WARNINGS+=("StackSet creation failed — check CloudFormation permissions")
            fi
        fi
    fi

    if [ "$_stackset_ok" = true ]; then
        _stackset_deployed=true
        # Deploy instances to the entire org
        info "Deploying stack instances to org (this may take a few minutes)..."
        OPERATION_ID=$(aws cloudformation create-stack-instances \
            --stack-set-name "$STACKSET_NAME" \
            --deployment-targets OrganizationalUnitIds="${ROOT_ID}" \
            --regions "$REGION" \
            --operation-preferences \
                FailureTolerancePercentage=100,MaxConcurrentPercentage=100 \
            --region "$REGION" \
            --query 'OperationId' --output text 2>/tmp/csi_err || echo "")
        if [ -z "$OPERATION_ID" ]; then
            _csi_err=$(cat /tmp/csi_err 2>/dev/null || true)
            if [ -n "$_csi_err" ] && ! echo "$_csi_err" | grep -qi "already.*exist\|no.*new.*instance\|OperationInProgressException"; then
                warn "create-stack-instances: ${_csi_err}"
                STACKSET_WARNINGS+=("Stack instance deployment may have failed: ${_csi_err}")
            fi
        fi

        if [ -n "$OPERATION_ID" ]; then
            info "Operation ID: ${OPERATION_ID}"
            printf "      Waiting"
            while true; do
                STATUS=$(aws cloudformation describe-stack-set-operation \
                    --stack-set-name "$STACKSET_NAME" \
                    --operation-id "$OPERATION_ID" \
                    --region "$REGION" \
                    --query 'StackSetOperation.Status' --output text 2>/dev/null || echo "UNKNOWN")
                case $STATUS in
                    SUCCEEDED) printf "\n"; ok; break ;;
                    FAILED|STOPPED)
                        printf "\n"
                        warn "StackSet operation ${STATUS} — some accounts may be skipped"
                        STACKSET_WARNINGS+=("StackSet operation ended with status: ${STATUS} — check CloudFormation StackSets console for per-account details")
                        break ;;
                    UNKNOWN)
                        printf "\n"
                        warn "Could not poll operation status — check CloudFormation console"
                        break ;;
                    *) printf "."; sleep 10 ;;
                esac
            done
        else
            warn "Stack instances already deployed — skipping."
        fi
    fi

    divider

    if [ "$DEPLOY_ROLE_ONLY" = true ]; then
        if [ "$_stackset_ok" = true ]; then
            printf "\n${GREEN}${BOLD}  ✓ IAM role StackSet deployed successfully.${RESET}\n"
            printf "${DIM}    Run without --deploy-role-only to start the scan:${RESET}\n"
            printf "${DIM}    %s --skip-stackset${RESET}\n\n" "${BOOTSTRAP_CMD}"
        else
            printf "\n${YELLOW}${BOLD}  ⚠  StackSet deployment was skipped due to errors above.${RESET}\n"
            printf "${DIM}    The IAM role has NOT been deployed. See warnings above for details.${RESET}\n"
            printf "${DIM}    If organizations:ListRoots is denied, re-run with --root-ou-id r-xxxx${RESET}\n\n"
            exit 1
        fi
        exit 0
    fi

    # ── Step 5: Run scan ──────────────────────────────────────────────────────
    step 5 "$TOTAL_STEPS" "Starting org-wide scan..."
else
    if [ "$SINGLE_ACCOUNT_MODE" = true ]; then
        # ── Step 3 (single-account): Run scan ────────────────────────────────
        step 3 "$TOTAL_STEPS" "Starting single-account scan..."
    elif [ "$SSO_MODE" = true ]; then
        # ── Step 4 (sso): Run scan ────────────────────────────────────────────
        step 4 "$TOTAL_STEPS" "Starting SSO scan..."
    else
        # ── Step 4 (skip-stackset): Run scan ─────────────────────────────────
        step 4 "$TOTAL_STEPS" "Starting org-wide scan..."
    fi
fi

# Print any accumulated warnings before handing off to the scanner
if [ ${#STACKSET_WARNINGS[@]} -gt 0 ]; then
    printf "\n"
    for w in "${STACKSET_WARNINGS[@]}"; do
        warn "$w"
    done
    printf "\n"
fi

printf "\n"
if [ "$SINGLE_ACCOUNT_MODE" = true ]; then
    SCAN_CMD=(aws-sizing --output ./output)
    [ -n "$ASSUME_ROLE_ARN" ]    && SCAN_CMD+=(--assume-role "$ASSUME_ROLE_ARN")
    [ -n "$REGIONS" ]            && SCAN_CMD+=(--regions "$REGIONS")
    [ -n "$EXCLUDE_REGIONS" ]    && SCAN_CMD+=(--exclude-regions "$EXCLUDE_REGIONS")
    [ -n "$SERVICES" ]           && SCAN_CMD+=(--services "$SERVICES")
    [ "${#EXTRA_ARGS[@]}" -gt 0 ] && SCAN_CMD+=("${EXTRA_ARGS[@]}")
else
    _pick_regions

    if [ "$SSO_MODE" = true ]; then
        SCAN_CMD=(aws-sizing --sso)
        [ -n "$SSO_START_URL" ] && SCAN_CMD+=(--sso-start-url "$SSO_START_URL")
    else
        SCAN_CMD=(aws-sizing --org)
    fi
    [ -n "$ASSUME_ROLE_ARN" ]    && SCAN_CMD+=(--assume-role "$ASSUME_ROLE_ARN")
    [ -n "$ROLE_NAME_OVERRIDE" ] && SCAN_CMD+=(--role-name "$ROLE_NAME_OVERRIDE")
    [ -n "$ACCOUNTS" ]           && SCAN_CMD+=(--accounts "$ACCOUNTS")
    [ -n "$REGIONS" ]            && SCAN_CMD+=(--regions "$REGIONS")
    [ -n "$EXCLUDE_REGIONS" ]    && SCAN_CMD+=(--exclude-regions "$EXCLUDE_REGIONS")
    [ -n "$SERVICES" ]           && SCAN_CMD+=(--services "$SERVICES")
    [ "${#EXTRA_ARGS[@]}" -gt 0 ] && SCAN_CMD+=("${EXTRA_ARGS[@]}")
fi

_scan_exit=0
"${SCAN_CMD[@]}" || _scan_exit=$?

if [ "$_scan_exit" -ne 0 ]; then
    printf "\n"
    err "Scan exited with code ${_scan_exit}"
    hint "Re-run with --debug for verbose output"
    hint "Check /tmp/pip_err for install issues"
fi

if [ "$_stackset_deployed" = true ]; then
    step 6 "$TOTAL_STEPS" "Cleaning up StackSet..."
    _cleanup_stackset
fi

exit "$_scan_exit"

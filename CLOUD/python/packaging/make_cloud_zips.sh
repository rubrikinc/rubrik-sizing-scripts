#!/usr/bin/env bash
# Builds one shareable zip per cloud (AWS, Azure, GCP) of the Python cloud sizing tools.
#
# Usage:
#   bash make_cloud_zips.sh [REPO] [REF] [OUT]
#     REPO  path to a sizing_apps clone        (default: the clone this script is in)
#     REF   branch, tag or commit to package    (default: origin/master)
#     OUT   folder the zips are written to      (default: ./cloud-sizing-zips)
#
# Each zip holds the tool's committed code only (no tests, caches or local output), a docs/
# folder (user guide, permissions, troubleshooting, run log, PowerShell mapping, vs PowerShell)
# and a QUICKSTART.md. Re-run it to package newer code; the commit is in each zip's name.
# Needs git, tar and python3 (the zips are made with Python's zipfile module).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO="${1:-$(git -C "$HERE" rev-parse --show-toplevel)}"
REF="${2:-origin/master}"
OUT="${3:-./cloud-sizing-zips}"
BASE="$(git -C "$HERE" rev-parse --show-prefix)"
BASE="${BASE%/}"
BASE="${BASE%/*}"
DOCS="user-guide.md permissions.md troubleshooting.md logging.md powershell-parameter-mapping.md"

# A remote branch is fetched first, so the zips hold what is on GitHub, not a stale local copy.
case "$REF" in
  origin/*) git -C "$REPO" fetch -q origin || echo "warning: could not fetch; packaging the local copy of $REF" ;;
esac
COMMIT="$(git -C "$REPO" rev-parse --short "$REF")"
DATE="$(git -C "$REPO" log -1 --format=%cs "$REF")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git -C "$REPO" archive --format=tar "$REF" "$BASE" | tar -x -C "$WORK"

quickstart() {
  local cloud="$1" python sign_in run more title cli
  case "$cloud" in
    aws)
      title="AWS"; cli="AWS CLI (\`aws\`)"; python="3.9"
      sign_in='   aws sso login --profile <your-profile>
   export AWS_PROFILE=<your-profile>'
      run='.venv/bin/python main.py --output ./output'
      more='- Several accounts: `--sso`, `--org` or `--profiles` (see docs/user-guide.md).
- Cost Explorer is billed per request; add `--no-cost` to skip it.'
      ;;
    azure)
      title="Azure"; cli="Azure CLI (\`az\`)"; python="3.10"
      sign_in='   az login'
      run='.venv/bin/python main.py --subs <subscription-id>,<subscription-id> --output ./output'
      more='- All subscriptions you can see: `--all` instead of `--subs`.
- Optional: `--get-container-details` (needs Storage Blob Data Reader) and
  `--get-key-vault-amounts` (needs Key Vault Reader).'
      ;;
    gcp)
      title="GCP"; cli="Google Cloud CLI (\`gcloud\`)"; python="3.10"
      sign_in='   gcloud auth login
   gcloud auth application-default login'
      run='.venv/bin/python main.py --projects <project-id>,<project-id> --output ./output'
      more='- All projects you can see: `--all` instead of `--projects`.
- Google Cloud Shell charges API calls to its current project. If you get `USER_PROJECT_DENIED`, run
  `unset GOOGLE_CLOUD_QUOTA_PROJECT` (or set it to a project where you have Service Usage Consumer) and run again.'
      ;;
  esac
  cat <<EOF
# Rubrik cloud sizing: ${title} (Python)

Version: \`${COMMIT}\` (${DATE}). Read-only: the tool only reads your cloud's inventory.

## Requirements
- Python ${python} or newer, on macOS, Linux, WSL or the cloud provider's shell.
- The ${cli}, signed in with read access (see docs/permissions.md).

## Steps
1. Unzip and open a terminal in this folder.
2. Install (once):
   \`\`\`bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   \`\`\`
3. Sign in:
   \`\`\`bash
${sign_in}
   \`\`\`
4. Run:
   \`\`\`bash
   ${run}
   \`\`\`
5. Send back the zip printed at the end of the run (in \`./output\`).

## Good to know
- Check access first, without collecting anything: add \`--preflight-only\`.
- The run summary at the end lists each problem with its fix; details in docs/troubleshooting.md.
- Every option: \`.venv/bin/python main.py --help\` and docs/user-guide.md.
- These commands work in bash and in PowerShell (for example, Azure Cloud Shell in either mode). On native
  Windows, use \`.venv\\Scripts\\\` instead of \`.venv/bin/\`.
- In a cloud shell (AWS CloudShell, Azure Cloud Shell, Google Cloud Shell) you are already signed in: skip step 3.
${more}
EOF
}

for cloud in aws azure gcp; do
  name="rubrik-cloud-sizing-${cloud}"
  dir="$WORK/pkg/$name"
  mkdir -p "$dir/docs"
  cp -R "$WORK/$BASE/$cloud/." "$dir/"
  rm -rf "$dir/tests"
  for doc in $DOCS "${cloud}-vs-powershell.md"; do
    cp "$WORK/$BASE/docs/$doc" "$dir/docs/"
  done
  quickstart "$cloud" > "$dir/QUICKSTART.md"
  rm -f "$OUT/$name-$COMMIT.zip"
  (cd "$WORK/pkg" && python3 -m zipfile -c "$OUT/$name-$COMMIT.zip" "$name")
  echo "built $OUT/$name-$COMMIT.zip"
done

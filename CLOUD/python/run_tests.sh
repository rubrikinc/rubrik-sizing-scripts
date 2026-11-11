#!/usr/bin/env bash
# Runs every Python test suite of the cloud sizing tools and fails if any suite fails.
# Used by sizing_scripts/run_sizing_scripts_tests (Docker, SAIL) and runnable by hand:
#   pip install -r requirements-test.txt && ./run_tests.sh [suite ...]
# Suites: common contract aws azure gcp bootstrap (default: all of them). The live tests under
# tests/live need cloud credentials and are never run here.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${HERE}"

export PYTHONDONTWRITEBYTECODE=1

run_suite() {
  local name="$1" dir="$2" pythonpath="$3" target="$4"
  shift 4
  echo
  echo "=== ${name} ==="
  (cd "${dir}" && PYTHONPATH="${pythonpath}" python3 -m pytest "${target}" "$@" -q -p no:cacheprovider)
}

if [ "$#" -gt 0 ]; then
  SUITES=("$@")
else
  SUITES=(common contract aws azure gcp bootstrap)
fi

FAILED=()
for suite in "${SUITES[@]}"; do
  case "${suite}" in
    common)    run_suite common    .      "${HERE}"                   common ;;
    contract)  run_suite contract  .      "${HERE}"                   contract ;;
    aws)       run_suite aws       aws    "${HERE}:${HERE}/aws"       tests --ignore=tests/live ;;
    azure)     run_suite azure     azure  "${HERE}:${HERE}/azure"     tests --ignore=tests/live ;;
    gcp)       run_suite gcp       gcp    "${HERE}:${HERE}/gcp"       tests --ignore=tests/live ;;
    bootstrap) run_suite bootstrap .      "${HERE}/tests/bootstrap"   tests/bootstrap ;;
    *) echo "Unknown suite '${suite}'. Use: common contract aws azure gcp bootstrap" >&2; exit 2 ;;
  esac
  [ "$?" -eq 0 ] || FAILED+=("${suite}")
done

echo
if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "FAILED suites: ${FAILED[*]}"
  exit 1
fi
echo "All suites passed: ${SUITES[*]}"

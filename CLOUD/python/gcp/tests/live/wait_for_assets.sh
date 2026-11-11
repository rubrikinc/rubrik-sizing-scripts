#!/usr/bin/env bash
# Poll Cloud Asset Inventory until the seeded fixture is indexed.
#
# CAI is eventually consistent: search_all_resources / list_assets do not see
# newly-created resources immediately (indexing lag is typically tens of seconds
# to a few minutes). This is the single biggest source of flakiness in a
# create-then-scan test, so we wait for the spine to actually see the fixture
# before running the discovery tool. On timeout we scan anyway (and warn) rather
# than fail — a slow index is not a tool bug.
set -uo pipefail

ORG_ID="${1:?usage: wait_for_assets.sh <org-id> [min-expected] [timeout-s]}"
MIN_EXPECTED="${2:-3}"   # 1 VM + 2 buckets
TIMEOUT="${3:-600}"

deadline=$(( $(date +%s) + TIMEOUT ))
while :; do
  count=$(gcloud asset search-all-resources \
    --scope="organizations/${ORG_ID}" \
    --asset-types="compute.googleapis.com/Instance,storage.googleapis.com/Bucket" \
    --format="value(name)" 2>/dev/null | wc -l | tr -d ' ')
  echo "CAI sees ${count} fixture-relevant resources (need >= ${MIN_EXPECTED})"
  if [ "${count}" -ge "${MIN_EXPECTED}" ]; then
    echo "Assets indexed — proceeding to scan."
    exit 0
  fi
  if [ "$(date +%s)" -ge "${deadline}" ]; then
    echo "::warning::CAI did not index ${MIN_EXPECTED} resources within ${TIMEOUT}s; scanning anyway."
    exit 0
  fi
  sleep 20
done

#!/usr/bin/env bash
# Seed a minimal, cheap fixture in the lab project so the live validation run has
# something real to discover: one e2-micro VM (exercises compute aggregatedList +
# the CAI asset spine) and two GCS buckets (storage collector + spine).
#
# Everything is labelled / name-prefixed so teardown_fixture.sh can sweep it even
# if a run is killed mid-flight. Safe to re-run (idempotent network creation).
set -euo pipefail

PROJECT_ID="${1:?usage: seed_fixture.sh <project-id> [zone]}"
ZONE="${2:-us-central1-a}"
RUN="${GITHUB_RUN_ID:-local$(date +%s)}"

echo "Seeding fixture in ${PROJECT_ID} (run ${RUN}, zone ${ZONE})"

# A fresh project may lack a default network if an org policy stripped it.
if ! gcloud compute networks describe default --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "Creating default network…"
  gcloud compute networks create default --project="${PROJECT_ID}" --subnet-mode=auto
fi

# 1 tiny VM — boot disk auto-created. --no-address: no external IP, no firewall
# needed (we never connect to it, we just discover it).
gcloud compute instances create "rubrik-fix-vm-${RUN}" \
  --project="${PROJECT_ID}" --zone="${ZONE}" \
  --machine-type=e2-micro \
  --image-family=debian-12 --image-project=debian-cloud \
  --no-address \
  --labels=rubrik-fixture=true

# 2 buckets (names are globally unique via project + run id).
for i in 1 2; do
  gcloud storage buckets create "gs://${PROJECT_ID}-rubrik-fix-${RUN}-${i}" \
    --project="${PROJECT_ID}" --location=US
done

echo "Seed complete."

#!/usr/bin/env bash
# Best-effort teardown. MUST NEVER fail the job (it runs in an always() step), so
# `set +e` and a final `exit 0`. Deletes by label / name-prefix rather than by the
# current run id, so orphans from a killed earlier run get swept too — the safety
# net against accumulating lab cost.
set +e

PROJECT_ID="${1:?usage: teardown_fixture.sh <project-id> [zone]}"

echo "Tearing down rubrik fixture in ${PROJECT_ID} (best-effort)…"

# VMs labelled rubrik-fixture=true (this run + any orphans).
gcloud compute instances list --project="${PROJECT_ID}" \
  --filter="labels.rubrik-fixture=true" \
  --format="value(name,zone.basename())" | while read -r name zone; do
  [ -z "${name}" ] && continue
  echo "  deleting VM ${name} (${zone})"
  gcloud compute instances delete "${name}" \
    --project="${PROJECT_ID}" --zone="${zone}" --quiet
done

# Buckets by name prefix.
gcloud storage buckets list --project="${PROJECT_ID}" --format="value(name)" \
  | grep -- "-rubrik-fix-" | while read -r bucket; do
  echo "  deleting bucket ${bucket}"
  gcloud storage rm -r "gs://${bucket}" --quiet
done

echo "Teardown done (best-effort)."
exit 0

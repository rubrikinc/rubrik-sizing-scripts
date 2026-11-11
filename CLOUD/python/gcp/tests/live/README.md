# Live GCP validation (nightly, ephemeral)

The mocked unit suite (`gcp/tests/`) proves the tool's logic. It cannot prove
the tool works against the **real** Cloud Asset Inventory API — specifically the
field shapes `OrgAssetCollector` depends on and project-number → project-id
mapping. This nightly job closes that gap end-to-end:

```
seed tiny fixture → wait for CAI to index → run packaged tool org-wide
                  → assert output matches fixture → ALWAYS tear down
```

Workflow: [`.github/workflows/validate-gcp-live.yml`](../../../.github/workflows/validate-gcp-live.yml).
It self-skips until the secrets below are set, so merging it is harmless.

## What it costs

One `e2-micro` VM + two empty buckets, created and destroyed within a ~10-minute
run, once a night. Effectively cents/month. Teardown runs in an `always()` step
and sweeps by label/name-prefix, so a killed run can't leak resources into the
next night (the next run's teardown sweeps them too).

---

## One-time setup (you run these — needs GCP org admin + repo admin)

Fill in the four values, then paste the blocks. Uses Workload Identity
Federation — **no service-account keys** are ever created or stored.

```bash
# ── Fill these in ────────────────────────────────────────────────────────────
export ORG_ID="123456789012"                 # numeric org ID: gcloud organizations list
export PROJECT_ID="rubrik-discovery-lab"      # dedicated lab project for the fixture
export BILLING_ACCT="XXXXXX-XXXXXX-XXXXXX"     # gcloud billing accounts list
export REPO="Rubrik-PLS-SE/Cloud-Sizing"
# Fixed names (no need to change):
export POOL_ID="github-pool"
export PROVIDER_ID="github-provider"
export SA="discovery-validator"
```

```bash
# ── 1. Create the lab project + link billing (skip if it already exists) ──────
gcloud projects create "$PROJECT_ID" --organization="$ORG_ID"
gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCT"
export PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"

# ── 2. Enable the APIs the run needs ──────────────────────────────────────────
gcloud services enable \
  cloudasset.googleapis.com compute.googleapis.com storage.googleapis.com \
  iamcredentials.googleapis.com sts.googleapis.com \
  --project="$PROJECT_ID"
```

```bash
# ── 3. Workload Identity Federation pool + GitHub OIDC provider ───────────────
gcloud iam workload-identity-pools create "$POOL_ID" \
  --project="$PROJECT_ID" --location=global --display-name="GitHub Actions"

gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
  --project="$PROJECT_ID" --location=global --workload-identity-pool="$POOL_ID" \
  --display-name="GitHub OIDC" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='${REPO}'"
```

```bash
# ── 4. Validator service account ──────────────────────────────────────────────
gcloud iam service-accounts create "$SA" \
  --project="$PROJECT_ID" --display-name="Rubrik discovery live validator"
export SA_EMAIL="${SA}@${PROJECT_ID}.iam.gserviceaccount.com"

# Org-level READ — the asset spine + project enumeration:
gcloud organizations add-iam-policy-binding "$ORG_ID" \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudasset.viewer"
gcloud organizations add-iam-policy-binding "$ORG_ID" \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/browser"   # projects.list/get

# Project-level CREATE/DESTROY — only on the lab project (blast radius contained):
for ROLE in roles/compute.admin roles/storage.admin roles/iam.serviceAccountUser; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" --role="$ROLE"
done
```

```bash
# ── 5. Let the GitHub repo impersonate the SA (scoped to this repo) ───────────
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --project="$PROJECT_ID" --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.repository/${REPO}"
```

```bash
# ── 6. Repo secrets (gh CLI) ──────────────────────────────────────────────────
gh secret set GCP_WORKLOAD_IDENTITY_PROVIDER --repo "$REPO" \
  --body "projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}"
gh secret set GCP_VALIDATION_SERVICE_ACCOUNT --repo "$REPO" --body "$SA_EMAIL"
gh secret set GCP_VALIDATION_ORG_ID          --repo "$REPO" --body "$ORG_ID"
gh secret set GCP_VALIDATION_PROJECT_ID      --repo "$REPO" --body "$PROJECT_ID"
```

Then trigger it: **Actions → Validate GCP (live) → Run workflow** (or wait for
06:00 UTC). The discovery JSON + log upload as a run artifact.

> The deploy workflow reuses `GCP_WORKLOAD_IDENTITY_PROVIDER` with a *separate*
> `GCP_DEV_SERVICE_ACCOUNT`/`GCP_PROD_SERVICE_ACCOUNT`. Keeping the validator on
> its own `discovery-validator` SA means the create/destroy permissions never
> touch the deploy identity.

---

## Run it by hand (no CI)

With your own ADC (`gcloud auth application-default login`) against the lab org:

```bash
cd gcp
export PROJECT_ID="rubrik-discovery-lab" ORG_ID="123456789012"
export GCP_VALIDATION_PROJECT_ID="$PROJECT_ID"

bash tests/live/seed_fixture.sh "$PROJECT_ID"
bash tests/live/wait_for_assets.sh "$ORG_ID" 3 600
python main.py --all --org "$ORG_ID" --output ./out --verbose
python tests/live/assert_discovery.py ./out/gcp-sizing-discovery-*.json
bash tests/live/teardown_fixture.sh "$PROJECT_ID"   # ALWAYS run this
```

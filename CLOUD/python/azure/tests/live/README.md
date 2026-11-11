# Azure live discovery validation

Nightly end-to-end check that the **Azure discovery tool still runs against a
real subscription** — the kind of regression a customer would otherwise hit
first in their own Azure Cloud Shell. The mocked unit suite (`azure/tests/`)
proves the collectors shape their data correctly; this proves the tool survives
a live Azure SDK round-trip: `DefaultAzureCredential` resolution, subscription
enumeration, the recoveryservices / storage / cost management paths, and
`DiscoveryResult` → JSON serialisation.

Workflow: [`.github/workflows/validate-azure-live.yml`](../../../.github/workflows/validate-azure-live.yml)

## What it does

1. Authenticates GitHub → Azure via **OIDC / workload-identity federation**
   (no client secrets or keys) using an app registration with the **Reader**
   role.
2. `pip install .` then runs the packaged `rubrik-discovery` console entry
   point — exercising the same path the customer runs (catches packaging /
   `py-modules` regressions too).
3. Runs a **read-only scan** of an existing CI/CD subscription — **it deploys
   nothing**. (The tool is read-only by design.)
4. Asserts the output JSON is structurally complete
   ([`assert_discovery.py`](assert_discovery.py)). Because counts are unknowable
   against a live subscription, an empty inventory **warns** rather than fails.

The job **self-skips** until the secrets below are set, so it's safe to merge
before setup is done.

## One-time setup

### 1. Create the app registration + federated credential

```bash
SUB_ID="<your CI/CD subscription id>"
REPO="Rubrik-PLS-SE/Cloud-Sizing"

# App registration + service principal
APP_ID=$(az ad app create --display-name "cloud-sizing-live-validation" \
  --query appId -o tsv)
az ad sp create --id "$APP_ID"

# Federated credential — trusts GitHub Actions tokens from the main branch only
az ad app federated-credential create --id "$APP_ID" --parameters "{
  \"name\": \"github-main\",
  \"issuer\": \"https://token.actions.githubusercontent.com\",
  \"subject\": \"repo:${REPO}:ref:refs/heads/main\",
  \"audiences\": [\"api://AzureADTokenExchange\"]
}"

# Grant READ-ONLY access — Reader role, scoped to the subscription
az role assignment create --assignee "$APP_ID" \
  --role "Reader" --scope "/subscriptions/${SUB_ID}"

# Tenant ID (for the secret below)
az account show --query tenantId -o tsv
```

> **Cost data note:** the `Reader` role covers inventory, backup posture,
> storage, and database. Cost Management queries may additionally require the
> **Cost Management Reader** role on the subscription — add it if the run logs a
> cost-collection permission warning:
> `az role assignment create --assignee "$APP_ID" --role "Cost Management Reader" --scope "/subscriptions/${SUB_ID}"`

### 2. Configure GitHub Actions secrets / variables

| Name | Kind | Required | Description |
|---|---|---|---|
| `AZURE_VALIDATION_CLIENT_ID` | secret | **yes** | `appId` from step 1. Absent ⇒ the job self-skips. |
| `AZURE_VALIDATION_TENANT_ID` | secret | **yes** | Tenant ID from step 1. |
| `AZURE_VALIDATION_SUBSCRIPTION_ID` | secret | **yes** | The CI/CD subscription to scan. |
| `AZURE_VALIDATION_REGIONS` | variable | no | Comma-separated regions to bound runtime/cost (default: all). |

```bash
gh secret set AZURE_VALIDATION_CLIENT_ID --body "$APP_ID"
gh secret set AZURE_VALIDATION_TENANT_ID --body "<tenant-id>"
gh secret set AZURE_VALIDATION_SUBSCRIPTION_ID --body "$SUB_ID"
gh variable set AZURE_VALIDATION_REGIONS --body "eastus,westus2"   # optional
```

## Running it

- **Nightly:** 06:00 UTC cron.
- **On demand:** Actions → *Validate Azure (live)* → *Run workflow*.

The discovery JSON and the full DEBUG run log are uploaded as the
`azure-live-discovery` artifact (7-day retention) for debugging a failed run.

## Safety

- **Read-only.** The app registration holds only the `Reader` role (plus
  optional `Cost Management Reader`) — it cannot create, modify, or delete
  anything, even though other workflows deploy to the same subscription.
- **No secrets stored.** Auth is OIDC federation — there is no client secret to
  leak or rotate.
- **Branch-scoped.** The federated credential only accepts tokens from
  `refs/heads/main`.

# M365 Recovery Criticality Assessment — Preview

A redacted version of the full assessment, safe to run live against a real tenant without exposing individual identities or the scale of lower-priority data on screen or in a takeaway file. Built for demos and workshops, or for sharing results broadly within an organization.

**Script file:** `Invoke-RecoveryAssessment-M365-Preview.ps1`

Looking for the complete, unredacted build for a real engagement? See [`../full_script/README.md`](../full_script/README.md).

## Permissions & Prerequisites

| | Base (default) | Add `-Full` | Add `-Full -Groups` |
|---|---|---|---|
| **PowerShell** | Windows PowerShell 5.1, or PowerShell 7+ | same | same |
| **PowerShell modules** | `Microsoft.Graph.Reports`, `Microsoft.Graph.Authentication` | + `Microsoft.Graph.Users`, `Microsoft.Graph.Sites` | same as `-Full` |
| **Directory role** | Reports Reader | same | same |
| **Graph scopes** | `Reports.Read.All` | + `User.Read.All`, `Sites.Read.All` | + `Group.Read.All` |
| **Unlocks** | Everything described below | Deeper scoring inputs (job title, department) — still only shown for real on the top-priority tier | A read-only Entra ID group column, shown only on the top-priority tier |

**Required tenant setting, either way:** in the M365 admin center, go to Settings → Org settings → Reports, and turn on **"Displayed concealed user, group, and site names in all reports."** Without this, usage reports return anonymized identifiers instead of real names, and the redaction contrast won't render meaningfully.

This build does not support `-DetailedSizing` — use the full script if you need Archive Mailbox or Recoverable Items sizing detail.

## What Gets Shown vs. Redacted

This script runs the same data collection, scoring, and tiering as the full script, then redacts the report before anyone sees it:

- **The top-priority tier (Critical Group 1)** is shown completely real — identity and timing, unredacted.
- **Everything else** — object counts, per-tier totals, and individual identities — is locked behind a placeholder; nothing recoverable via page source or dev tools.
- **The whole-tenant recovery baseline** is shown real, as a single aggregate figure (not a per-tier breakdown), so the overall before/after comparison still comes through.
- **Editing controls are disabled.** Scoring weights and keyword tables are visible but read-only; per-row tier changes and bulk actions are removed.
- **Inputs you'd adjust live** — downtime cost, RTO targets, recovery window — stay fully interactive and recompute in real time.
- **PDF exports match what's on screen** — nothing is revealed on export that wasn't already visible live.

## Quick Start

```powershell
# Base permissions (most common for a live demo)
.\Invoke-RecoveryAssessment-M365-Preview.ps1

# With deeper scoring inputs
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -Full

# With a downtime cost input
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -DowntimeCostPerHour 25000
```

Defaults: 90-day usage window, 7-day recovery window, Auto-selected RTO preset, output to a timestamped folder (`.\M365CriticalityAssessmentPreview_yyyyMMdd_HHmmss\`) in the current directory.

## What You Get

Same file set as the full script, with the same redaction applied to both the CSVs and the HTML report:

- `Mailboxes.csv`, `OneDrive.csv`, `SharePointSites.csv`, `Teams.csv` — top-priority-tier rows carry real identity; everything else carries a placeholder identifier instead.
- `_MasterSummary.csv`, `_ReportData.json`, `_RunManifest.txt`, `raw\`
- `CriticalityAssessment_Report.html` — the interactive, redacted report.
- `EnterpriseApp-Setup-Guide.md`

## How Tiering Works

Identical to the full script — see [`../full_script/README.md`](../full_script/README.md)'s "How Tiering Works" section for the scoring and RTO-preset mechanics. Only what's *shown* differs between the two builds.

## Known Limitations

Same underlying model as the full script — see [`../full_script/README.md`](../full_script/README.md)'s "Known Limitations."

# M365 Recovery Criticality Assessment — Preview

A redacted version of the full assessment, safe to run live against a real tenant without exposing individual identities or the scale of lower-priority data on screen or in a takeaway file. Built for demos and workshops, or for sharing results broadly within an organization.

**Script file:** `Invoke-RecoveryAssessment-M365-Preview.ps1`

A separate, complete, unredacted build of this assessment exists for real customer engagements (no locked figures, live scoring/override controls, `-DetailedSizing` support). It's distributed separately — contact your Rubrik team for it.

## Permissions & Prerequisites

| | Always required | Add `-Groups` |
|---|---|---|
| **PowerShell** | Windows PowerShell 5.1, or PowerShell 7+ | same |
| **PowerShell modules** | `Microsoft.Graph.Reports`, `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Sites` — **all four must be the same version as each other** (2.38.0 or later; see [Updating PowerShell Modules](#updating-powershell-modules)) | same |
| **Directory role** | Reports Reader | same |
| **Graph scopes** | `Reports.Read.All`, `User.Read.All`, `Sites.Read.All` | + `Group.Read.All` |
| **Unlocks** | Everything described below, including deeper scoring inputs (job title, department) — shown for real only on the top-priority tier | A read-only Entra ID group column, shown only on the top-priority tier |

Getting an assembly-load error like `Could not load file or assembly 'Microsoft.Graph.Authentication, Version=...'`, or another module-related failure? → [Updating PowerShell Modules](#updating-powershell-modules) has copy-paste commands to fix it.

**Required tenant setting:** in the M365 admin center, go to Settings → Org settings → Reports, and turn on **"Displayed concealed user, group, and site names in all reports."** Without this, usage reports return anonymized identifiers instead of real names, and the redaction contrast won't render meaningfully.

This build does not support `-DetailedSizing` — use the full script if you need Archive Mailbox or Recoverable Items sizing detail.

## What Gets Shown vs. Redacted

This script runs the same data collection, scoring, and tiering as the full script, then redacts the report before anyone sees it:

- **The top-priority tier (Critical Group 1)** is shown completely real — identity and timing, unredacted.
- **Everything else** — object counts, per-tier totals, and individual identities — is locked behind a placeholder; nothing recoverable via page source or dev tools.
- **The whole-tenant recovery baseline** is shown real, as a single aggregate figure (not a per-tier breakdown), so the overall before/after comparison still comes through.
- **Editing controls are disabled.** Scoring weights and keyword tables are visible but read-only; per-row tier changes and bulk actions are removed.
- **Inputs you'd adjust live** — downtime cost, RTO targets, recovery window — stay fully interactive and recompute in real time.
- **PDF exports match what's on screen** — nothing is revealed on export that wasn't already visible live.
- **Large tenants:** the Criticality Groups tab's tables render only the top 500 rows per section by score, not every object, with a "Show all N rows" button when a table is capped — same reasoning and mechanism as the full script, unrelated to redaction (which row count renders doesn't change which rows are locked).

## Quick Start

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1
```

Defaults: 90-day usage window, 7-day recovery window, Auto-selected RTO preset, $10,000/hour downtime cost (pass `-DowntimeCostPerHour` to override), output to a timestamped folder (`.\M365CriticalityAssessmentPreview_yyyyMMdd_HHmmss\`) in the current directory. That single command already covers everything described in this README — everything below is optional.

## Command-Line Switches

Every switch below can be combined with any other. All of them are optional — the plain `.\Invoke-RecoveryAssessment-M365-Preview.ps1` command above already runs the full demo.

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -Groups
```
Adds a read-only Entra ID group column, shown only on the top-priority tier (Group 1). Requests one additional Graph scope (`Group.Read.All`) on top of the base permissions — no separate sign-in, no separate module.

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -DowntimeCostPerHour 25000
```
Sets the $/hour used for every downtime-cost figure in the report. Defaults to $10,000/hour; always override with the customer's real number when known.

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -OverridesFile .\overrides.json
```
Seeds manual tier overrides from a JSON file exported by a prior run — has no visible effect in this build since override controls are frozen/read-only here, but the value still passes through to the underlying tiering so Group 1's figures stay consistent with a full-assessment run using the same file.

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -CompareTo .\M365CriticalityAssessmentPreview_20260615_090000
```
Diffs this run against a prior run's output folder and adds a "Changes Since Last Run" tab to the report.

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -SkipHtmlReport
```
Writes the CSVs and manifest but skips generating the HTML report.

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -ShowEnterpriseAppGuide
```
Prints unattended/Enterprise App setup instructions and exits without running the assessment.

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -TenantId <tenant-id> -ClientId <client-id> -CertificateThumbprint <thumbprint>
```
Connects via an Enterprise App (application permissions, certificate auth) instead of an interactive delegated sign-in, for scheduled/unattended runs. All three parameters are required together.

## What You Get

Same file set as the full script, with the same redaction applied to both the CSVs and the HTML report:

- `Mailboxes.csv`, `OneDrive.csv`, `SharePointSites.csv`, `Teams.csv` — top-priority-tier rows carry real identity; everything else carries a placeholder identifier instead.
- `_MasterSummary.csv`, `_ReportData.json`, `_RunManifest.txt`, `raw\`
- `CriticalityAssessment_Report.html` — the interactive, redacted report.
- `EnterpriseApp-Setup-Guide.md`

## How Tiering Works

Every object gets a composite score from weighted, normalized metrics, so a mailbox's item count can't be swamped by a OneDrive account's byte count. Mailboxes, OneDrive, and SharePoint are walked into Critical Group 1 (highest priority) until adding the next object would exceed Group 1's recovery-time budget, then into Group 2 against its own remaining budget, then Group 3. Teams has no independent recovery-time model, so it's split into even thirds by score instead.

| Tier | Meaning |
|---|---|
| Critical Group 1 | Recovers first — highest priority within its time budget |
| Critical Group 2 | Recovers next, within its own remaining budget |
| Critical Group 3 | Recovers last among still-active objects |
| Group 4 | Minimal activity in the period; recovered via bulk Mass Recovery, not on the critical path |

**RTO presets:**

| Preset | Group 1 | Group 2 | Group 3 |
|---|---|---|---|
| Standard | 4h | 24h | 72h |
| Enterprise | 24h | 5 days | 10 days |
| Auto (default) | Automatically picks Standard or Enterprise from an early tenant-wide recovery-time estimate |
| Custom | Any values you pass explicitly via `-Group1/2/3TargetHours` — always wins over a preset |

Scoring weights are visible (read-only) in the report's Methodology & Glossary tab. `-TierSplit` reshapes Teams' thirds.

## Known Limitations

- SharePoint "broad access across the org" is an activity proxy (page views + active files), not a true unique-accessor count.
- The mailbox-type classifier and hub-site detection use heuristics, not authoritative directory reads.
- Recovery-time modeling assumes flat throughput caps regardless of slice size, matching the underlying recovery-time calculator's own formulas.

## Updating PowerShell Modules

**Minimum versions:** `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Reports`, and `Microsoft.Graph.Sites` all ship together as one family and must be **the same version as each other** — 2.38.0 or later.

By far the most common real-world failure isn't a module being too old — it's the four Graph modules being **mismatched versions of each other** (e.g. `Microsoft.Graph.Users` updated but `Microsoft.Graph.Authentication` didn't), which throws an assembly-load error that names a specific version it can't find, like:

```
Could not load file or assembly 'Microsoft.Graph.Authentication, Version=2.39.0.0, Culture=neutral,
PublicKeyToken=31bf3856ad364e35' or one of its dependencies. The system cannot find the file specified.
```

That happens when a partial `Update-Module`, multiple side-by-side installs, or a manually-copied module left the four Graph submodules out of sync. The fix is a clean uninstall of every installed version of every `Microsoft.Graph.*` module, followed by a fresh install of just the four this script needs — **run this in a brand-new PowerShell window**, not the one that hit the error (a session that already loaded a mismatched assembly can't unload it mid-run):

```powershell
# 1. See what's currently installed (useful to save/screenshot if the issue persists after this)
Get-InstalledModule -Name Microsoft.Graph* | Select-Object Name, Version | Sort-Object Name, Version

# 2. Uninstall every installed version of every Microsoft.Graph* module
Get-InstalledModule -Name Microsoft.Graph* | ForEach-Object {
    Write-Host "Removing $($_.Name) $($_.Version)..." -ForegroundColor Yellow
    Uninstall-Module -Name $_.Name -AllVersions -Force -ErrorAction SilentlyContinue
}

# 3. Filesystem sweep - catches leftover module folders PowerShellGet's own uninstall
#    sometimes can't clean up (partial installs, or a module that was manually copied
#    in rather than installed via Install-Module). Reads $env:PSModulePath directly
#    instead of guessing paths, so this works on Windows PowerShell or PowerShell 7,
#    on Windows or macOS, regardless of how PowerShell itself was installed.
($env:PSModulePath -split [IO.Path]::PathSeparator) | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem -Path $_ -Directory -Filter 'Microsoft.Graph*' -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Host "Deleting leftover folder: $($_.FullName)" -ForegroundColor Yellow
                Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
    }
}

# 4. Reinstall only what this script needs - CurrentUser scope, no admin/sudo required
'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Reports', 'Microsoft.Graph.Sites' | ForEach-Object {
    Write-Host "Installing $_..." -ForegroundColor Cyan
    Install-Module -Name $_ -Scope CurrentUser -Force -AllowClobber
}

# 5. Verify - should show exactly these 4 modules, one version each, no duplicates
Get-InstalledModule -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Reports, Microsoft.Graph.Sites |
    Select-Object Name, Version
```

Open a brand-new PowerShell window before running the assessment again. (This build doesn't use `ExchangeOnlineManagement` - that's only needed for `-DetailedSizing` in the full script.)

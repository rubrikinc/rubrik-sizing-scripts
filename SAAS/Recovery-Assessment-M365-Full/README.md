# M365 Recovery Criticality Assessment

Identifies which mailboxes, OneDrive accounts, SharePoint sites, and Teams matter most to your business, groups them into recovery-priority tiers (Critical Group 1 recovers first, then 2, then 3), and estimates how long each tier takes to recover and what downtime would cost. A data-driven starting point for a recovery-sequencing conversation — not a replacement for what you already know about your own environment.

**Script file:** `Invoke-RecoveryAssessment-M365-Full.ps1`

Looking for the redacted trade-show/demo build instead? It's distributed as a separate script/repo — contact your Rubrik team for it.

## Permissions & Prerequisites

| | Always required | Add `-DetailedSizing` |
|---|---|---|
| **PowerShell** | Windows PowerShell 5.1, or PowerShell 7+ | same |
| **PowerShell modules** | `Microsoft.Graph.Reports`, `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Sites` — **all four must be the same version as each other** (2.38.0 or later; see [Updating PowerShell Modules](#updating-powershell-modules)) | + `ExchangeOnlineManagement` 3.0.0 or later |
| **Directory role** | Reports Reader | same, plus a read-only Exchange Online role (e.g. View-Only Recipients) |
| **Graph/API scopes** | `Reports.Read.All`, `User.Read.All`, `Sites.Read.All`, `Group.Read.All` | same as base, plus a separate, second interactive sign-in to Exchange Online (not a Graph scope) |
| **Unlocks** | Full tiering, recovery time, and cost modeling for every workload, plus manager/job title/department enrichment, mailbox-type detection, exact Team-site matching, and a "Filter to Entra ID group" bulk-selection tool | Archive Mailbox and Recoverable Items sizing detail on the Sizing tab |

**As of v3.14.0, `Group.Read.All` is requested by default** (was opt-in via `-Groups` through v3.13.0) — pass `-NoGroups` if you need to skip it, e.g. a customer's security team hasn't approved that scope yet. See [Command-Line Switches](#command-line-switches) below.

Getting an assembly-load error like `Could not load file or assembly 'Microsoft.Graph.Authentication, Version=...'`, or another module-related failure? → [Updating PowerShell Modules](#updating-powershell-modules) has copy-paste commands to fix it.

**Required tenant setting:** in the M365 admin center, go to Settings → Org settings → Reports, and turn on **"Displayed concealed user, group, and site names in all reports."** Without this, usage reports return anonymized identifiers instead of real names, and the assessment won't be usable.

## Quick Start

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1
```

Defaults: 90-day usage window, 7-day recovery window, Auto-selected RTO preset, $10,000/hour downtime cost (pass `-DowntimeCostPerHour` to override), output to a timestamped folder (`.\M365CriticalityAssessment_yyyyMMdd_HHmmss\`) in the current directory. That single command already covers full tiering, recovery time, cost modeling, enrichment, and Entra ID group data for every workload — everything below is optional.

## Command-Line Switches

Every switch below can be combined with any other. All of them are optional — the plain `.\Invoke-RecoveryAssessment-M365-Full.ps1` command above already runs the full assessment.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -NoGroups
```
Opts out of Entra ID group data collection. By default (as of v3.14.0), every run resolves each user's group membership — rides the same directory pull the base assessment already does, no separate call — and surfaces a "Filter to Entra ID group" bulk-selection tool on the Criticality Groups tab, so you can filter to a specific department/team and mass-reassign everyone in it to a tier in one motion. This requests one additional Graph scope, `Group.Read.All`, on every run. Use `-NoGroups` if that's not acceptable yet (e.g. a customer's security team hasn't approved the scope) — it drops the extra scope request and the group filter/column disappear for that run.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -DetailedSizing
```
Adds Archive Mailbox storage/item counts and Recoverable Items folder storage/items to the Sizing tab. This is **not** a Graph permission — it needs the `ExchangeOnlineManagement` PowerShell module and a **second, separate interactive sign-in to Exchange Online** (a second MFA prompt, distinct from the Graph sign-in the base assessment uses). The account you sign in with needs a read-only Exchange Online RBAC role — **View-Only Recipients** is enough; nothing broader is required. It runs last, after every other export has already succeeded, and it loops over every active mailbox one at a time, so it's the slowest part of the run on a large tenant — a failure here never affects the rest of the report. Without this switch, the Sizing tab still shows Exchange/OneDrive/SharePoint totals and Archive Mailbox **count** (free, from data already collected) — just not Archive storage or Recoverable Items detail.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -DowntimeCostPerHour 25000
```
Sets the $/hour used for every downtime-cost figure in the report. Defaults to $10,000/hour; always override with the customer's real number when known.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -OverridesFile .\overrides.json
```
Seeds manual tier overrides from a JSON file exported by a prior run's "Export overrides" button in the report, so corrections persist across re-runs.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -CompareTo .\M365CriticalityAssessment_20260615_090000
```
Diffs this run against a prior run's output folder and adds a "Changes Since Last Run" tab to the report.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -SkipHtmlReport
```
Writes the CSVs and manifest but skips generating the HTML report.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -ShowEnterpriseAppGuide
```
Prints unattended/Enterprise App setup instructions and exits without running the assessment.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -TenantId <tenant-id> -ClientId <client-id> -CertificateThumbprint <thumbprint>
```
Connects via an Enterprise App (application permissions, certificate auth) instead of an interactive delegated sign-in, for scheduled/unattended runs. All three parameters are required together — see "Running as an Enterprise App" below.

## What You Get

- `Mailboxes.csv`, `OneDrive.csv`, `SharePointSites.csv`, `Teams.csv` — full metric detail and tier assignment per object.
- `_MasterSummary.csv` — every object across all four workloads in one file.
- `Interactive_CriticalityAssessment_Report.html` — the interactive report (see below). `-SkipHtmlReport` to turn both HTML reports off.
- `Summary_CriticalityAssessment_Report.html` — a small, static, aggregate-only companion report (see below).
- `EnterpriseApp-Setup-Guide.md` — setup steps for unattended/scheduled use, written every run.
- `_RunManifest.txt`, `_ReportData.json`, `raw\` — run metadata and untouched source data, useful for auditing or for a later run's `-CompareTo`.

## The Interactive Report

A single, self-contained HTML file — no server or installation needed to view it. Scoring weights, RTO targets, recovery window, and downtime cost all recompute live in your browser, so you can explore "what if" scenarios without re-running the script.

**Tabs:** Executive Summary, Report (detailed breakdown), Criticality Groups (live scoring controls and manual tier overrides), Recovery (RTO modeling), Methodology & Glossary, Sizing, and Changes Since Last Run (when `-CompareTo` is used).

Two PDF export options — **One Page Summary** and **Full Report** — both computed fresh from whatever's on screen at export time.

Manual overrides: every row's tier is a dropdown; changing it always wins over the computed tier. `Export overrides` downloads a JSON file — pass it back in via `-OverridesFile` on a later run so overrides persist.

`Export Criticality Groups (CSV)` downloads one CSV listing every object across all four workloads with its final tier — reading the live, on-screen state at the moment you click it, so any manual overrides or mass-reassignments you've made are included, not just what the script originally computed. Meant as a hand-off file for downstream automation (e.g. a script that calls RSC to create or update criticality groups from this list).

**Large tenants:** the Criticality Groups tab's tables render only the top 500 rows per section by score (highest-priority objects first), not every object — a tenant with tens of thousands of objects per workload would otherwise hang the browser building that many table rows at once. A "Show all N rows" button appears whenever a table is capped, for anyone who needs the full list on screen. Search and filters still run against every object regardless of the cap, so searching for one specific person or site always finds it.

## The Summary Report

A second, much smaller HTML file, generated alongside the interactive report on every run. It embeds no per-object data at all — no names, no identifiers, no row-level table — only pre-computed totals: recovery times and downtime cost avoided per group, object counts per tier per workload, and tenant-wide sizing. Nothing recomputes live in the browser; it's meant to be the file you can email, forward, or open on a phone without a multi-hundred-MB attachment, and to walk through with a customer before diving into the interactive report for row-level detail and live customization. Has its own "Print / Save as PDF" button.

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

Every scoring weight can be adjusted at the command line or live in the report; the Methodology & Glossary tab shows the full current list. `-TierSplit` reshapes Teams' thirds.

## Running as an Enterprise App (Unattended Use)

For scheduled or recurring runs without an interactive sign-in. Run `-ShowEnterpriseAppGuide` for exact, copy-paste setup steps — this script never creates the app registration or handles a secret/certificate itself; that should go through your own security/identity team's sign-off. Once set up, run with `-TenantId`, `-ClientId`, and `-CertificateThumbprint` instead of interactive sign-in.

## Known Limitations

- SharePoint "broad access across the org" is an activity proxy (page views + active files), not a true unique-accessor count.
- The mailbox-type classifier and hub-site detection use heuristics, not authoritative directory reads.
- Recovery-time modeling assumes flat throughput caps regardless of slice size, matching the underlying recovery-time calculator's own formulas.

## Updating PowerShell Modules

**Minimum versions:** `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Reports`, and `Microsoft.Graph.Sites` all ship together as one family and must be **the same version as each other** — 2.38.0 or later. `ExchangeOnlineManagement` (only needed for `-DetailedSizing`) needs 3.0.0 or later; if you're on PowerShell 7, versions 3.10.0+ additionally require PowerShell 7.6 or later (Windows PowerShell 5.1 is unaffected either way).

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

If you're also using `-DetailedSizing`, do the same for `ExchangeOnlineManagement` (a separate module family, not touched by the steps above):

```powershell
Uninstall-Module ExchangeOnlineManagement -AllVersions -Force -ErrorAction SilentlyContinue
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
```

Open a brand-new PowerShell window before running the assessment again.

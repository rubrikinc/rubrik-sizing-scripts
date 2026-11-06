# M365 Recovery Criticality Assessment - Preview (v2.0)

Runs against a real tenant and shows **Group 1 only**: who matters most to recover first, how fast Rubrik Autonomous Business Recovery (ABR) brings them back, and the hours saved versus a mass restore. Nothing about Groups 2-4 is in the report file or its data, so it cannot be derived from the HTML, page source, or by pasting the file into an AI tool.

To see Groups 2-4, the full recovery model, outlier insights and every adjustable control, re-run the Full script (the Preview controls are shown greyed out, with a contact-sales link: https://www.rubrik.com/contact-sales?v2).

**Script file:** `Invoke-RecoveryAssessment-M365-Preview.ps1`

## Permissions & Prerequisites

| | Required |
|---|---|
| **PowerShell** | Windows PowerShell 5.1, or PowerShell 7+ |
| **PowerShell modules** | `Microsoft.Graph.Reports`, `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Sites` — **all four must be the same version as each other** (2.38.0 or later; see [Updating PowerShell Modules](#updating-powershell-modules)) |
| **Directory role** | Reports Reader |
| **Graph scopes** | `Reports.Read.All`, `User.Read.All`, `Sites.Read.All`, `Group.Read.All` |
| **Unlocks** | Everything described below, including deeper scoring inputs (job title, department) and a read-only Entra ID group column — shown for real only on the top-priority tier |

**As of v3.14.0, `Group.Read.All` is requested by default** (was opt-in via `-Groups` through v3.13.0) — pass `-NoGroups` if you need to skip it, e.g. a customer's security team hasn't approved that scope yet, or you're running this live at a trade show/webinar and want the leanest possible consent prompt on screen. See [Command-Line Switches](#command-line-switches) below.

**Very large tenants (100,000+ mailboxes/OneDrive accounts/SharePoint sites/Teams combined):** run this from **64-bit PowerShell** (Windows PowerShell's default `powershell.exe`, or PowerShell 7's `pwsh.exe` — both are 64-bit; a 32-bit host caps the process at roughly 2-4 GB of memory regardless of the machine's actual RAM) with several GB of free memory available. This script collects all four workloads' full data into memory before scoring begins, so a tenant this large held alongside its user-enrichment index is a real memory ceiling — the script warns at startup and again mid-run if it detects this scale, but a run at the very largest end can still end in a `System.OutOfMemoryException` with no output files written. If that happens, re-run from 64-bit PowerShell on a machine with more available RAM. `-NoGroups` also helps here: group-membership enrichment is a second, separate bulk `Get-MgUser -All` pull on top of the one already made for base enrichment (Graph only allows one property expanded per query), so skipping it removes an entire extra full-tenant enumeration.

**Extremely large tenants (~900,000+ mailbox/OneDrive/SharePoint/Teams objects combined) and the Interactive report:** the Interactive report embeds each workload's row data as its own block inside the HTML file, and every browser (Chrome, Edge, and every other Chromium/V8-based browser) has a hard-coded ~512 MiB limit on how long a single piece of that data can be — a limit no amount of RAM works around. As of v3.15.14, each workload is embedded separately, comfortably covering every tenant seen to date (largest so far: ~327MB for one workload). A tenant with a single workload significantly larger than that (very roughly, 1,000,000+ objects in one workload alone) could still hit this ceiling and show a blank/broken Interactive report; if that happens, reach out — a further chunking fix would be needed. The Summary report never carries this risk (it has no per-object data at all).

**Tenants where a workload isn't used (e.g. no Teams, or a division with no SharePoint sites):** as of v3.15.16, the script handles a workload coming back with zero objects cleanly - it's tiered and reported as an empty workload (0 rows, real numbers everywhere else) rather than erroring out.

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

Defaults: 180-day usage window, 7-day recovery window, Auto-selected RTO preset, downtime cost not set (pass `-DowntimeCostPerHour` to override), output to a timestamped folder (`.\M365CriticalityAssessmentPreview_yyyyMMdd_HHmmss\`) in the current directory. That single command already covers everything described in this README — everything below is optional.

## Command-Line Switches

**No tenant access?** `-OfflinePath <folder>` runs from usage reports exported from the admin center - see [Running offline](#running-offline-no-tenant-access) at the bottom of this file.

Every switch below can be combined with any other. All of them are optional — the plain `.\Invoke-RecoveryAssessment-M365-Preview.ps1` command above already runs the full demo.

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -NoGroups
```
Opts out of Entra ID group data collection. By default (as of v3.14.0), every run resolves each user's group membership — no separate sign-in, no separate module, but via its own separate bulk directory pull alongside the one the base assessment already does (Microsoft Graph only allows one property expanded per user query, so the two can't be combined) — and shows a read-only Entra ID group column, shown only on the top-priority tier (Group 1). This requests one additional Graph scope, `Group.Read.All`, on every run, plus that extra directory pull. Use `-NoGroups` if that's not acceptable yet (e.g. a customer's security team hasn't approved the scope), or to cut collection time/memory on a very large tenant — it drops the extra scope request, the extra pull, and the group column disappears for that run.

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -DowntimeCostPerHour 25000
```
Sets the $/hour used for every downtime-cost figure in the report. Defaults to 0 (hours saved only; the report prompts for a rate); override with the customer's real number when known.

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

```powershell
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -GraphTimeoutSeconds 1800
```
Raises the Microsoft Graph client timeout beyond the default of 900 seconds (15 minutes). On a very large tenant, the profile-enrichment step (`Get-MgUser -All`) can take long enough that the Graph SDK's own default timeout cancels the request mid-run — this shows up as `WARNING: User profile enrichment failed (...HttpClient.Timeout... elapsing.)` and silently drops JobTitle/Department/Manager/Groups enrichment for every row. 900 seconds comfortably covers every tenant size seen so far; raise it further only if you see that warning.

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

## Licensed users, shared mailboxes, and unlicensed mailboxes

Microsoft's mailbox usage report no longer returns a usable `Recipient Type`, so the assessment classifies mailboxes from **assigned licenses** (`assignedLicenses`, covered by `User.Read.All` - no extra permission):

| Mailbox | Treated as | In the report |
|---|---|---|
| Has at least one license (enabled or disabled) | Licensed user | Counts toward the Rubrik license quote; sized |
| No license and either the account is disabled, or the mailbox has the 50 GB limit Exchange gives shared/resource mailboxes; or no matching user account (group mailbox) | Shared / group / other | Protected and sized, **no Rubrik license needed** |
| No license, account enabled | Unlicensed user | **Excluded** from every figure (Rubrik does not protect these); shown as a single excluded count on the Sizing tab |

The Sizing tab shows **Licensed users** (license basis), **Total protected mailboxes** (count, storage, items for onboarding estimates), and **Licensed users by plan** (E1/E3/E5/E7, F1/F3, A1/A3/A5, Business Basic/Standard/Premium, GCC G1/G3/G5, Exchange-only plans, including the no-Teams and EEA variants, plus the standalone Exchange Online Archiving add-on count). Each user is counted once, under their highest plan. The plan map is built from Microsoft's licensing reference; any SKU not in it is listed under "Other (unrecognized)" with its SKU id so it can be added. Free and add-on SKUs (Power BI/Fabric free, Power Automate free, Copilot, Microsoft 365 Apps) don't count as a mailbox license.

Without Exchange Online, shared mailboxes are an **estimate**: a shared mailbox that is enabled, unlicensed, and has a non-default mailbox limit looks like an unlicensed user and is excluded. The full script run with `-DetailedSizing` can confirm shared mailboxes via Exchange Online. If license data can't be collected (or almost no mailbox matches a user, e.g. when Microsoft 365 report names are concealed), nothing is excluded, mailboxes are shown as unclassified, and the report says so.


---

## Running offline (no tenant access)

Use this when your security team will not approve running the script against your tenant. You export usage reports from the Microsoft 365 admin center into a folder, then run the script against that folder. **No sign-in, no Graph or Exchange connection, no app consent.** The script only reads the CSV files you give it.

Offline runs are **reduced confidence** (see [What offline mode cannot show](#what-offline-mode-cannot-show)).

### Step 1 - Export the reports

**Who:** anyone with the **Reports Reader** role (or Global Reader / Global Admin).
**Where:** [admin.microsoft.com](https://admin.microsoft.com) -> **Reports -> Usage**. Pick the report, set the period (top right), click **Export** (top right of the table).

> **Important - concealed names must be turned off first.** Many tenants hide real user, group and site names in usage reports (exports show 32-character hashes such as `B8CD4590FAA61BD1EA95298F11203093` instead of names, and the admin center shows *"Information is concealed for privacy"*). With hashed names the offline assessment cannot match mailboxes to licenses, cannot show real names in the report, and Teams rows lose their IDs. **Turn the setting off before exporting, then turn it back on afterward.**
>
> 1. Sign in to [admin.microsoft.com](https://admin.microsoft.com) as a **Global Administrator** (Reports Reader cannot change this setting).
> 2. Go to **Settings -> Org settings**, open the **Services** tab, and select **Reports**.
> 3. **Clear** the checkbox *"Display concealed user, group, and site names in all reports"* and click **Save**.
> 4. Export all the reports below. Open one file and confirm it shows real names (for example `user@company.com`), not hashes. If it still shows hashes, wait a few minutes and re-export.
> 5. When all exports are done, return to the same page, **re-check** the box and **Save** to restore your privacy setting.
>
> The change is recorded in the audit log and your privacy or security team may need to approve it. If it cannot be turned off, the offline assessment still runs, but mailbox license classification is unavailable, names in the report are hashes, and results are lower confidence still.

Create one empty folder, for example `C:\RubrikAssessment\input\`, and save each export into it **with exactly the file name shown**:

| # | Where to find it (Reports -> Usage ->) | Period | Save as |
|---|---|---|---|
| 1 | **Email activity** | 180 days | `email_activity.csv` |
| 2 | **Email activity** | 7 days | `email_activity_7d.csv` |
| 3 | **Mailbox usage** | 180 days | `mailbox_usage.csv` |
| 4 | **OneDrive** -> *Activity* tab | 180 days | `onedrive_activity.csv` |
| 5 | **OneDrive** -> *Activity* tab | 7 days | `onedrive_activity_7d.csv` |
| 6 | **OneDrive** -> *Usage* tab | 180 days | `onedrive_usage.csv` |
| 7 | **SharePoint** -> *Site usage* tab | 180 days | `sharepoint_usage.csv` |
| 8 | **SharePoint** -> *Site usage* tab | 7 days | `sharepoint_usage_7d.csv` |
| 9 | **Microsoft Teams** -> *Team usage* tab (optional) | 180 days | `teams_team_activity.csv` |

Notes:

- Files 1-8 are required. File 9 is optional; without it Teams is reported as not modeled.
- Use the same long period for every non-7-day file. If you pick a period other than 180 days, pass the matching `-Period` (`D30`, `D90`) when you run the script. The script checks each file's *Report Period* column and warns on a mismatch. It also rejects any file missing its key column (a wrong export).
- The **7-day files drive the recent-data (ABR) recovery estimate** and cannot be skipped or substituted.
- For Teams, open the **Team usage** tab (not *User activity*) and use the **Export** link at the **bottom-left of the team table** (it shows an item count, e.g. "13 items"). Do not use the Export links above the charts; they export daily totals (for example `TeamsTeamCounts...csv`, columns `PublicTeams, PrivateTeams, ...`), not one row per team. The script rejects a file without a `Team Id` column and runs without Teams.
- Do not open and re-save the CSVs in Excel (it can change encoding and dates). Save them straight from the browser download.

**Sending to Rubrik:** zip the folder. The files contain user principal names and object sizes/activity counts, no content. Use your normal secure transfer.

### Step 2 - Run the script offline

On any Windows machine with PowerShell 5.1 or later. The Microsoft Graph and Exchange modules are **not** needed.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -OfflinePath C:\RubrikAssessment\input -Period D180
```

(For the Preview script, use `Invoke-RecoveryAssessment-M365-Preview.ps1` with the same switch.)

What happens:

1. The script lists each expected file as found / missing, with its size.
2. If a required file is missing, it stops and names it. Missing optional files are noted and the run continues.
3. It builds the same HTML reports and CSVs as a live run. Open `Interactive_CriticalityAssessment_Report.html` as usual.

### What offline mode cannot show

The report carries an **"Offline run - reduced confidence"** banner and a row in *Data quality & coverage* listing what was skipped:

- **User profile enrichment** (job title, department, manager, Entra groups): title-weight scoring and group/department filters are empty.
- **License-based mailbox classification:** unlicensed and shared mailboxes cannot be told apart from licensed ones, so mailbox counts may be overstated.
- **Team-to-site mapping:** Team sites are matched by heuristic only, so Teams/SharePoint overlap is approximate.
- **Archive mailbox and Recoverable Items sizes** (`-DetailedSizing` is ignored offline): Exchange sizing is understated by the Recoverable Items amount.

Do not compare an offline report directly with a live run on the same tenant. When the customer's security team later approves a live run, re-run without `-OfflinePath`.

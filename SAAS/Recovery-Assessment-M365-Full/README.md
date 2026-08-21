# M365 Recovery Criticality Assessment

Identifies which mailboxes, OneDrive accounts, SharePoint sites, and Teams matter most to your business, groups them into recovery-priority tiers (Critical Group 1 recovers first, then 2, then 3), and estimates how long each tier takes to recover and what downtime would cost. A data-driven starting point for a recovery-sequencing conversation — not a replacement for what you already know about your own environment.

**Script file:** `Invoke-RecoveryAssessment-M365-Full.ps1`

Looking for the redacted trade-show/demo build instead? It's distributed as a separate script/repo — contact your Rubrik team for it.

## Permissions & Prerequisites

| | Always required | Add `-Groups` | Add `-DetailedSizing` |
|---|---|---|---|
| **PowerShell** | Windows PowerShell 5.1, or PowerShell 7+ | same | same |
| **PowerShell modules** | `Microsoft.Graph.Reports`, `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Sites` | same | + `ExchangeOnlineManagement` |
| **Directory role** | Reports Reader | same | same, plus a read-only Exchange Online role (e.g. View-Only Recipients) |
| **Graph/API scopes** | `Reports.Read.All`, `User.Read.All`, `Sites.Read.All` | + `Group.Read.All` | same as base, plus a separate, second interactive sign-in to Exchange Online (not a Graph scope) |
| **Unlocks** | Full tiering, recovery time, and cost modeling for every workload, plus manager/job title/department enrichment, mailbox-type detection, and exact Team-site matching | A "Filter to Entra ID group" bulk-selection tool | Archive Mailbox and Recoverable Items sizing detail on the Sizing tab |

**Required tenant setting:** in the M365 admin center, go to Settings → Org settings → Reports, and turn on **"Displayed concealed user, group, and site names in all reports."** Without this, usage reports return anonymized identifiers instead of real names, and the assessment won't be usable.

## Quick Start

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1
```

Defaults: 90-day usage window, 7-day recovery window, Auto-selected RTO preset, $10,000/hour downtime cost (pass `-DowntimeCostPerHour` to override), output to a timestamped folder (`.\M365CriticalityAssessment_yyyyMMdd_HHmmss\`) in the current directory. That single command already covers full tiering, recovery time, cost modeling, and enrichment for every workload — everything below is optional.

## Command-Line Switches

Every switch below can be combined with any other. All of them are optional — the plain `.\Invoke-RecoveryAssessment-M365-Full.ps1` command above already runs the full assessment.

```powershell
.\Invoke-RecoveryAssessment-M365-Full.ps1 -Groups
```
Adds a "Filter to Entra ID group" bulk-selection tool to the Criticality Groups tab. Requests one additional Graph scope (`Group.Read.All`) on top of the base permissions — no separate sign-in, no separate module. Group membership rides the same directory pull the base assessment already does.

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

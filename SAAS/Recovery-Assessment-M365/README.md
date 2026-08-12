# M365 Recovery Criticality Assessment — Preview Script

**Script file:** `Invoke-RecoveryAssessment-M365-Preview.ps1`

This is a separate, independent script — **not a switch on the Full script** — built to run live against a real prospect's tenant at a webinar or trade show as a proof point, without exposing that prospect's actual people/site/mailbox identities, or the specific scale of their Group 2/3/4 data, on a screen or in a takeaway file.

**Looking for an actual customer engagement instead?** This build is for live public demos only — every Group 2/3/4 figure and every identity outside Group 1 is redacted. A separate, full, unredacted build of this tool exists for real customer engagements; ask your Rubrik contact for it. Run this script only for a live trade-show/webinar demo.

## What this script redacts, exactly

It runs the **exact same collection, scoring, and tiering** as the Full script, then applies these rules to the report before anyone sees it:

- **Group 1 is shown completely real** — identity, full ABR timing, everything. This is the "here's what you'd actually see" proof point.
- **Groups 2/3's own figures stay locked**: object counts, per-workload totals, and the cumulative "Groups 1-2"/"Groups 1-3" milestones. A locked value is never a real number hidden behind CSS — it's a fixed, blurred placeholder with a small "Full assessment" tag, so it can't be recovered via page source or dev tools either.
- **Group 4 detail stays locked** — the per-workload dormant-object breakdown is not shown; only a "see the full assessment" note appears.
- **The whole-tenant Mass Recovery baseline is shown real.** This is the one number outside Group 1 that isn't locked — it's a single aggregate figure for the entire tenant (not a Groups-2/3/4 breakdown), used as the "before" side of the Group 1 comparison ("your critical data is usable in X instead of Y").
- **Per-object identity** (name, identifier/UPN/site URL, job title, department, manager, criteria tags) for anything outside Group 1 is replaced with a placeholder like `Group 3 Mailbox #7`, server-side, before any CSV is written or the HTML's data blob is assembled. The browser independently re-checks this too, so an object that lands right on a tier boundary can't slip through with real identity under the "wrong" badge.
- **Every tiering-affecting control is frozen.** Scoring weight sliders, the title-weight keyword table, and the hub-site keyword editor render read-only (visible for transparency, not editable); the per-row tier dropdown, override badge, and mass-reassign bar are removed entirely; Export/Import overrides buttons are removed from the toolbar. A locked Group 2/3/4 object can never be re-tiered into the fully-real Group 1 view mid-demo.
- **Value-illustrating controls stay fully live.** Downtime cost/hour, RTO targets, recovery window, and SP/OD throughput tier are all still adjustable and recompute instantly — you can show "what if this tenant needed a 4-hour RTO instead of 24" live, and the Group 1 and whole-tenant figures update in real time (per-group Group 2/3/4 figures stay locked regardless).
- **PDF export matches the on-screen lock exactly.** Both `Export PDF: One Page Summary` and `Export PDF: Full Report` independently recompute their own figures rather than scraping the live DOM, so exporting a PDF can't reopen a leak the live report closed.

### Two graphics on the Executive Summary tab, two different treatments — know this before you present

- **The Recovery Ladder** (the horizontal to-scale timeline with Group 1/2/3 milestone pins) follows the lock rule above: only Group 1 and the Mass Recovery baseline are real; Groups 2/3 show a blurred time value, and their pins are spread evenly across a single hatched "locked" region rather than at their true position, so neither the number nor the geometry reveals their real timing.
- **The "Mass Recovery vs. ABR: Same Timescale, Different Order" timeline graphic**, directly above the Recovery Ladder on the same tab, is **not** locked — Groups 1/2/3's real chip-cluster segments and their real durations (via hover tooltip) are shown, alongside the real whole-tenant Mass Recovery bar. This was a deliberate earlier design decision to treat that specific graphic as one aggregate "big picture" comparison rather than an isolated Group 2/3 leak.
- **These two are currently inconsistent with each other**, and that hasn't been resolved yet. If you're demoing this tenant live, be aware a technical prospect could read approximate Group 2/3 timing off the upper graphic even though the lower one hides it. Flag to your team if you'd like this reconciled one way or the other.

## Prerequisites at a glance

Same underlying data collection as the Full script (this is a presentation-layer difference, not a data-collection difference) — but this script file does **not** support `-DetailedSizing` at all; there is no Preview equivalent of that feature.

| | Base (no switch) | `-Full` | `-Full -Groups` |
|---|---|---|---|
| **PowerShell** | Windows PowerShell 5.1, or PowerShell 7+ — whatever the Microsoft Graph PowerShell SDK itself requires | same | same |
| **PowerShell modules** | `Microsoft.Graph.Reports`, `Microsoft.Graph.Authentication` | + `Microsoft.Graph.Users`, `Microsoft.Graph.Sites` | same as `-Full` (no extra module) |
| **Directory role** | Reports Reader | Reports Reader (same — no extra role) | Reports Reader (same) |
| **Graph scopes requested** | `Reports.Read.All` | + `User.Read.All`, `Sites.Read.All` | + `Group.Read.All` |
| **What it unlocks** | Everything described above, including the hub-site heuristic (no extra scope needed) | + Job Title/Department/Employee Type/Manager enrichment feeding scoring on Mailboxes and OneDrive (still only visible for real on Group 1 rows); mailbox-type heuristic; exact (non-heuristic) Team-site dedupe | + each Group 1 user's Entra ID group membership, shown as a **read-only column on Group 1 rows only** |

**`-Groups` behaves differently here than in the Full script.** In Preview, it only adds a read-only group-membership column, visible on Group 1's real rows. The bulk "Filter to Entra ID group" selection tool is Full-script only — there is nothing to bulk-select against once Groups 2/3/4 are locked. `-Groups` requires `-Full` and is ignored, with a console warning, if passed alone.

**No `-DetailedSizing` switch exists in this script file at all.** If you need Archive Mailbox storage or Recoverable Items sizing detail, use the Full script.

**One tenant setting, required either way:** M365 admin center → Settings → Org settings → Reports → turn ON "Displayed concealed user, group, and site names in all reports." Without this, Graph's usage reports return pseudonymized identifiers instead of real names/UPNs, and Group 1's redaction contrast (the whole point of this build) won't render meaningfully.

## Running it

```powershell
# Base permissions (most common for a live demo)
.\Invoke-RecoveryAssessment-M365-Preview.ps1

# -Full - enrichment feeding scoring, mailbox-type heuristic, exact dedupe (still only Group 1 is shown real)
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -Full

# -Full plus a read-only Entra ID group column on Group 1 rows (requires -Full; requests Group.Read.All)
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -Full -Groups

# With recovery/cost modeling and a downtime cost input
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -Full -RecoveryWindowDays 3 -DowntimeCostPerHour 25000

# Force the Enterprise RTO preset (24/120/240h) instead of Auto's suggestion
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -RTOPreset Enterprise

# Print the Enterprise App setup guide without running anything
.\Invoke-RecoveryAssessment-M365-Preview.ps1 -ShowEnterpriseAppGuide
```

Defaults: 90-day usage window (`-Period D90`), 7-day recovery window, `Auto`-selected SP/OD throughput tier, $0/hour downtime cost, `Auto`-selected RTO preset (Standard 4/24/72h unless the tenant's estimated recovery time is large enough to suggest Enterprise), output to a timestamped folder (`.\M365CriticalityAssessmentPreview_yyyyMMdd_HHmmss\`).

## What comes out

Same shape as the Full script's output, with the same redaction applied to CSVs as to the HTML report:

- `Mailboxes.csv`, `OneDrive.csv`, `SharePointSites.csv`, `Teams.csv` — Group 1 rows carry real identity/detail; Group 2/3/4 rows carry placeholder identifiers (e.g. `Group 3 Mailbox #7`) instead of real names/UPNs/site URLs. Metric columns (item counts, storage, tier, rank) are present for every row — only identity is masked outside Group 1.
- `SharePointSites_Excluded.csv`, `_MasterSummary.csv`, `_ReportData.json`, `_RunManifest.txt`, `raw\` — same purpose as the Full script, with the same redaction rule applied.
- `CriticalityAssessment_Report.html` — the interactive, redacted report (see above). `-SkipHtmlReport` to turn it off.
- `EnterpriseApp-Setup-Guide.md` — written every run, no side effects.

## How the tiering works

Every object gets a composite score built from weighted, percentile-ranked metrics (0-1 normalized, so a mailbox's item count can't be swamped by a OneDrive account's byte count).

**Mailboxes/OneDrive/SharePoint (budget-constrained walk):** objects are sorted by composite score, descending, then walked into Group 1 until adding the next object would push Group 1's own ABR (hot-data) recovery time past its RTO target (`-Group1TargetHours`) — the remainder walks into Group 2 against its own remaining budget, then Group 3 against what's left. Change the RTO target and the tier boundaries move with it.

**Teams (criticality-ranked, equal-thirds):** sorted by composite score, split by `-TierSplit` (default even thirds). Teams has no independent recovery-time model to walk against (its content lives in SharePoint/Exchange), so it keeps the fixed split.

**Recovery time** is a separate calculation: ABR recovers each object's recent/active data first (real telemetry — Active File Count, Viewed/Edited File Count, Send+Receive volume, always pulled at a real 7-day window regardless of `-Period`), Mass Recovery catches up on the rest afterward.

| Tier | Meaning |
|---|---|
| Critical Group 1 | Highest-scoring objects that fit within Group 1's RTO budget (Mailboxes/OneDrive/SharePoint); top third by composite score (Teams) — recover first |
| Critical Group 2 | Next-highest-scoring objects that fit within Group 2's remaining RTO budget; middle third (Teams) |
| Critical Group 3 | Everything else still active; bottom third but still active (Teams) |
| Group 4 | Limited activity in the period. Gets no ABR timing at all and is recovered entirely by Mass Recovery. Still protected; just not on the critical path |

**RTO presets:**

| Preset | Group 1 | Group 2 (cumulative) | Group 3 (cumulative) |
|---|---|---|---|
| Standard | 4h | 24h | 72h |
| Enterprise | 24h | 120h (5 days) | 240h (10 days) |
| Auto (default) | Picks Standard or Enterprise based on an early full-tenant recovery-time estimate (≥ 5 days picks Enterprise) — then double-checks it isn't a degenerate all-in-Group-1 spread for any single workload, falling back to Standard if so. Always surfaced in console output, `_RunManifest.txt`, and the report | | |
| Custom | Whatever `-Group1/2/3TargetHours` you pass — always wins over a preset | | |

**Default weights:**

| Workload | Metric | Weight |
|---|---|---|
| Mailbox | Send + receive count | 0.45 |
| | Read count | 0.25 |
| | Item count (size) | 0.30 |
| | *(`-Full`) Job title match* | *0.15, additive* |
| OneDrive | File activity | 0.60 |
| | Storage used | 0.40 |
| | *(`-Full`) Job title match* | *0.15, additive* |
| SharePoint site | Page views | 0.35 |
| | Active file count | 0.35 |
| | Storage used | 0.30 |
| | *(hub-site bonus)* | *0.15, additive, capped at 1.0* |
| Team | Active users | 0.50 |
| | Channel messages | 0.35 |
| | Meetings organized | 0.15 |

Change any weight at the command line or live in the report. `-TierSplit @(0.2,0.3,0.5)` reshapes Teams' thirds. Note: in this Preview build, the scoring weight sliders and keyword tables render read-only (see above) — these values are shown for transparency but can't be changed live; use the Full build to adjust them interactively.


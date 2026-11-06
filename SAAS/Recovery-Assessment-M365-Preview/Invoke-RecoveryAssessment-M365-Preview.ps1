#Requires -Modules Microsoft.Graph.Reports, Microsoft.Graph.Authentication
<#
.SYNOPSIS
    M365 Recovery Criticality Assessment - PREVIEW BUILD (v2.0.0). Runs the
    same live-tenant collection, scoring and tiering as
    Invoke-RecoveryAssessment-M365-Full.ps1, but the report it writes contains
    Critical Group 1 ONLY: Group 1's real objects (identity, scores, recovery
    timing) plus whole-tenant totals and the whole-tenant Mass Recovery
    baseline. Objects in Groups 2, 3 and 4 are removed here, in PowerShell,
    before anything is written to a CSV or embedded in the HTML - they are not
    hidden by CSS/JS and cannot be recovered from the page source. Scoring
    weights and recovery targets are shown but locked. To see Groups 2-4,
    recovery sequencing and cost avoidance by group, contact a Rubrik
    representative (https://www.rubrik.com/contact-sales?v2) and re-run with
    the full assessment script, which is a separate deliverable and is not
    included alongside this one. Comments below that say "see Full script's
    matching comment" or "mirrored from the Full script" are provenance notes
    about where a piece of logic originated and always carry the full
    explanation inline, so this script reads standalone.

.DESCRIPTION
    v2.0.0 - PREVIEW BUILD. Same engine and recovery-model constants
    ("calibration v1") as the Full script, so Group 1 and whole-tenant figures
    match a Full run on the same tenant. Differences from the Full script:
      - Generation-time stripping: every object outside Critical Group 1 is
        removed from every output (HTML data, CSVs, _ReportData.json, console
        text). Whole-tenant totals (object, item, storage and activity sums per
        workload) and the sizing totals are computed first and embedded as
        aggregates; nothing is embedded per Group 2/3/4.
      - The report does not re-score or re-tier in the browser. Scoring
        weights, title keywords, RTO targets and the recovery window are
        displayed but locked.
      - No overrides export/import and no Criticality Groups CSV export.
      - A Preview banner links to https://www.rubrik.com/contact-sales?v2.
      - -Period defaults to D180.
    The vX.Y.Z numbers cited in the rest of this .DESCRIPTION and in inline
    comments (e.g. "v3.1.0", "v3.10.0") track the underlying recovery-model and
    tiering engine, which is shared with the Full script.

    v3.1.0 - corrects what "recovery time" means for ABR. v3.0.0 tiered
    Mailboxes/OneDrive/SharePoint by an efficiency-ranked walk-forward budget
    (rank by score-per-minute-of-FULL-object-recovery-time, then fill Groups
    1/2/3 until a cumulative RTO target was exceeded). Real tenant data
    showed this breaks down whenever one large object's FULL size dominates
    the walk: it can jump straight past an entire group's target in one step,
    leaving that group empty and stranding a genuinely critical (but large)
    object in "Beyond Target" - even though ABR does not actually need to
    recover that object's full size to make it useful again.

    All four workloads now use the SAME criticality-ranked grouping
    (composite score, split by -TierSplit, unchanged since v1.0) - this
    guarantees every group gets a population as long as there is enough
    active data, exactly like Teams always has.
    Recovery TIME is a separate, corrected calculation layered on top: ABR
    recovers each object's RECENT/ACTIVE data first (estimated from real
    telemetry already collected - SharePoint's Active File Count, OneDrive's
    Viewed/Edited File Count, Mailboxes' Send+Receive volume - proportionally
    applied to storage), and Mass Recovery continues afterward to fully
    restore the remaining (older) data. This replaces the old "Beyond
    Target" tier: instead of exiling slow objects to a 5th bucket, each of
    Group 1/2/3 now gets a simple pass/fail flag against its own RTO target
    hours, and the Executive Summary's Recovery Timeline shows the hot-data
    ABR phase followed by the Mass Recovery catch-up phase. See
    the Methodology tab for the full before/after rationale and
    real-tenant worked example. -Group1/2/3TargetHours and -RTOPreset
    (Auto/Standard/Enterprise/Custom) still control the targets and are
    still live-adjustable in the report's Recovery tab - they now drive a
    compliance check per group rather than the tiering walk itself. Also
    carried over from v3.0.0: the mailbox-type classifier uses the real
    Exchange "Recipient Type" field (from the mailbox usage report, no extra
    scope) instead of the old AccountEnabled proxy.

    On top of the v1.x activity-based tiering, v2.0.0 added:
      - A live, in-browser scoring/tiering engine in the HTML report. Weights,
        title-keyword scores, and hub-site keywords are adjustable directly in
        the report and everything (tiers, totals, recovery time, cost)
        recomputes instantly - PowerShell ships the raw metrics once, the
        browser owns the logic from there so it's a single, transparent,
        adjustable source of truth instead of a static snapshot.
      - Per-object manual tier overrides (dropdown per row + filter-driven
        mass reassignment), exportable to a JSON file that persists across
        re-runs via -OverridesFile.
      - Totals (objects / items / storage) per tier, per workload, and
        combined.
      - A dedicated Recovery tab modeling recovery TIME and downtime COST per
        group, using throughput-capped math reverse-engineered from the
        Rubrik's M365 recovery time model (see the Methodology tab).
      - Manager roll-up (who reports up through whom) for org-based filtering
        and mass-tiering ("everyone under this VP").
      - A heuristic mailbox-type classifier (User vs. likely Shared/Resource)
        and a heuristic "department hub site" flag for SharePoint.
      - A -CompareTo switch to diff this run against a prior run's output.
      - A guided (not automated) path to running this via an Enterprise
        App / application permissions instead of a delegated sign-in - see
        EnterpriseApp-Setup-Guide.md, written alongside every run.

    Later updates (v3.10.0 through v3.16.1) added, on top of the above:
      - A Sizing tab (Exchange/OneDrive/SharePoint totals and Archive
        Mailbox count for free - this build doesn't support the Archive
        storage/Recoverable Items detail from -DetailedSizing; use
        Invoke-RecoveryAssessment-M365-Full.ps1 for that) and a small,
        static Summary HTML report alongside the main interactive one.
      - A per-workload filter bar (department, manager roll-up, Entra ID
        group, mailbox type, hub site) for browsing Group 1's real data -
        filtering works the same as the Full script, but mass-reassignment
        stays frozen here (see PERMISSIONS above).
      - Entra ID group membership resolved and used BY DEFAULT (see
        -NoGroups above) rather than opt-in - shown as a read-only column
        for Group 1 rows only.
      - A guided, self-paced in-report tour ("Take the Tour" in the
        toolbar), adapted for this build's read-only tiering: it still
        demonstrates the live Group 1 recovery-time-target interaction, but
        narrates the mass-reassignment capability (an NBA-style analogy for
        how objects land in a tier) rather than pointing at a control that
        doesn't exist in this build.
      - Does NOT get the Full script's "Export Criticality Groups (CSV)"
        button - this build removes every non-Group-1 object at the source
        (see Select-PreviewGroup1Rows), so a complete object-list export
        isn't possible here. Use Invoke-RecoveryAssessment-M365-Full.ps1 for
        that.

    This is still directional, not exact. Treat tiers, recovery times, and
    costs as a data-driven starting point - the live override system exists
    specifically so the customer can correct anything the data can't see.

.NOTES
    LINEAGE: v2.0.0 is based on the 3.16.1 Preview script and the 3.17.1 Full
    script (same collection, tiering and recovery-model engine and constants).

    ============================================================================
    PERMISSIONS
    ============================================================================
    BASE (always requested): Entra role "Reports Reader". Delegated scopes
              Reports.Read.All, User.Read.All, Sites.Read.All. Also requests
              Group.Read.All BY DEFAULT (opt out via -NoGroups - see below;
              not a fixed base scope like the three above).
              Buys: user profile enrichment (Job Title, Department, Employee
              Type, Manager, manager roll-up chain, mailbox-type heuristic,
              title-weight scoring), exact Team<->SharePoint site resolution
              - all of which feed Group 1's real figures; objects outside
              Group 1 are removed before output (see Select-PreviewGroup1Rows)
              - AND (NEW v3.14.0, was opt-in via
              -Groups through v3.13.0) each user's Entra ID group membership
              (Mailboxes/OneDrive only - same UPN join as the rest of base
              enrichment, resolved via its own separate Get-MgUser -All pull -
              one extra bulk Graph call beyond the added scope, not per-user
              lookups). Shown as a
              read-only "Entra ID Groups" column for Group 1 rows only in
              this preview build (no other group is shipped); the bulk "filter/mass-tier everyone in
              this group" tool built on top of this data is Full-script only,
              same as the manager roll-up above. Requests the broader
              Group.Read.All rather than the strict-minimum
              GroupMember.Read.All so a future per-group detail lookup (type,
              owners, dynamic membership rule) does not require a second
              consent grant. This is a real widening of the default consent
              surface, not a free addition - pass -NoGroups to opt back out
              (e.g. a customer's security team hasn't approved Group.Read.All
              yet) and revert to the pre-v3.14.0 base scope set.

    NOTE ON NAMING: this file (Invoke-RecoveryAssessment-M365-Preview.ps1) is
    the separate, redacted webinar/trade-show build; Invoke-RecoveryAssessment-
    M365-Full.ps1 is the full customer-engagement script - a different file,
    not a different permission mode. Both scripts request the same base
    permissions above.

    Hub-site keyword detection needs no extra scope - it reuses
    already-collected page-view/active-file activity as a breadth proxy, NOT
    a true group-membership count - see README "Hub site detection".

    ============================================================================
    TENANT PREREQUISITE
    ============================================================================
    M365 admin center > Settings > Org settings > Reports > turn ON "Displayed
    concealed user, group, and site names in all reports."

    ============================================================================
    RUNNING VIA AN ENTERPRISE APP (application permissions)
    ============================================================================
    Pass -TenantId/-ClientId/-CertificateThumbprint to connect as an app
    registration instead of an interactive delegated sign-in. This script does
    NOT create or configure that app for you - run with -ShowEnterpriseAppGuide
    for exact, copy-paste setup steps (also written to
    EnterpriseApp-Setup-Guide.md on every run). Application permissions are
    tenant-wide and static - there is no per-user delegated-access ceiling
    like the default mode has - so this is a materially bigger, static grant.
    Treat it as something the customer's own security team signs off on.

.PARAMETER Period
    Usage report window: D7, D30, D90, or D180. Default D180.

.PARAMETER OfflinePath
    Run without any tenant connection from usage reports exported from the
    Microsoft 365 admin center into this folder (see the README, 'Running
    offline'). Reduced-confidence report; no directory/Exchange data.

.PARAMETER OutputPath
    Folder to write CSVs/HTML to. Defaults to a timestamped folder.

.EXAMPLE
    .\Invoke-RecoveryAssessment-M365-Preview.ps1

.EXAMPLE
    .\Invoke-RecoveryAssessment-M365-Preview.ps1 -RecoveryWindowDays 3 -DowntimeCostPerHour 25000

.EXAMPLE
    .\Invoke-RecoveryAssessment-M365-Preview.ps1 -CompareTo .\M365CriticalityAssessmentPreview_20260615_090000 -OverridesFile .\overrides.json

.EXAMPLE
    .\Invoke-RecoveryAssessment-M365-Preview.ps1 -NoGroups
    Opts out of the default Entra ID group data collection (drops the
    Group.Read.All scope request) - use when a customer's security team
    hasn't approved that scope yet, or to keep the live consent prompt as
    lean as possible during a trade-show/webinar demo.
#>

[CmdletBinding()]
param(
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D180',

    [string]$OutputPath = ".\M365CriticalityAssessmentPreview_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    # Per-workload metric weights - percentile-ranked, then weighted-summed into _Score.
    [hashtable]$MailboxWeights       = @{ SendRecvActivity = 0.45; ReadActivity = 0.25; Size = 0.30 },
    [hashtable]$OneDriveWeights      = @{ FileActivity     = 0.60; Storage      = 0.40 },
    [hashtable]$SharePointWeights    = @{ PageViews        = 0.35; ActiveFiles  = 0.35; Storage  = 0.30 },
    [hashtable]$TeamsWeights         = @{ ActiveUsers      = 0.50; ChannelMsgs  = 0.35; Meetings  = 0.15 },

    # NEW v2.0.0: title-keyword weights (0-1 scale). Needs JobTitle (from base enrichment).
    # First (longest/most specific) match wins by highest weight found, matched as a
    # case-insensitive substring against JobTitle. Fully customer-editable - and
    # editable LIVE in the HTML report without re-running the script.
    [hashtable]$TitleWeights = @{
        'Chief Executive' = 1.00; 'Chief Financial' = 1.00; 'Chief Information' = 1.00
        'Chief Security'  = 1.00; 'Chief Operating' = 1.00; 'CEO' = 1.00; 'CFO' = 1.00
        'CIO' = 1.00; 'CISO' = 1.00; 'COO' = 1.00; 'President' = 0.95
        'Executive Vice President' = 0.90; 'EVP' = 0.90
        'Senior Vice President'    = 0.85; 'SVP' = 0.85; 'General Counsel' = 0.85
        'Vice President'           = 0.80; 'VP' = 0.80
        'Payroll' = 0.60; 'Controller' = 0.60; 'Treasurer' = 0.60; 'Treasury' = 0.60
        'Director' = 0.55; 'Manager' = 0.30
    },
    # How much the title-weight component contributes into the composite score
    # (added as an extra percentile-ranked field alongside the workload's other
    # weights - does not need to make the total sum to 1.0).
    [double]$TitleWeightContribution = 0.15,

    # NEW v2.0.0: hub-site keywords for the SharePoint "department one-stop-shop"
    # heuristic. No extra Graph scope - see NOTES. Read-only in this preview
    # build (see the live report). Blank by default - deliberately no
    # built-in keyword list; which departments/site names actually matter is
    # not something this tool should guess at, and varies customer to
    # customer. Left blank, the hub-site heuristic flags nothing.
    [string[]]$HubSiteKeywords = @(),
    [double]$HubSiteBonus = 0.15,

    # Tier split as fractions of the ACTIVE (non-zero-activity) population.
    [double[]]$TierSplit = @(0.33, 0.33, 0.34),

    [string]$CustomerName = '',

    [switch]$SkipHtmlReport,

    # NEW v3.14.0: Entra ID group membership enrichment (Mailboxes/OneDrive
    # only) is now ON BY DEFAULT - was opt-in via -Groups through v3.13.0,
    # flipped per repeated customer feedback that "pin this specific
    # department/group into Group 1 regardless of what the activity score
    # says" is a common, real ask, and the bulk group-based selection this
    # enables (Full-script only) was going undiscovered behind an opt-in
    # flag. This DOES widen the default consent surface -
    # Group.Read.All is now requested on every run, not just when asked for.
    # Adds one extra bulk Get-MgUser -All pull alongside the one already made
    # for base enrichment (Graph only allows one property expanded per query,
    # so the two can't be combined) - still no per-user Graph calls, just the
    # one extra scope and one extra bulk call. Shown as a
    # read-only column for Group 1 rows only in this preview build; the bulk
    # group-based selection tool is Full-script only. Pass -NoGroups to opt
    # back out and revert to the pre-v3.14.0 behavior.
    [switch]$NoGroups,

    [switch]$IncludeGroupConnectedSites,

    # NEW v2.0.0: seed manual tier overrides from a previously-exported JSON file
    # (the HTML report's "Export overrides" button). Overrides always win over
    # the computed tier and are flagged in the report; re-running without this
    # file does NOT lose overrides as long as you pass the same file back in.
    [string]$OverridesFile = '',

    # NEW v2.0.0: point this run at a PRIOR run's output folder to get a
    # month-over-month tier-movement comparison embedded in the report.
    [string]$CompareTo = '',

    # NEW v2.0.0: recovery-time modeling inputs (see the Methodology tab).
    # 'Auto' picks the SP/OD throughput tier from actual object counts, same
    # bucket boundaries as the source calculator. All three are also
    # live-adjustable in the report's Recovery tab.
    [ValidateSet('Auto','0-1k','1k-5k','5k-15k','15k-50k','50k+')]
    [string]$RecoveryLicenseTier = 'Auto',
    # NEW: capped at 0-7, matching ABR's actual recovery capability - it can
    # only ever recover up to the last 7 days of activity, so anything
    # higher wouldn't mean anything. Live-adjustable 0-7 in the report's
    # Recovery tab; windows shorter than 7 days linearly scale down the real
    # D7 activity signal already collected (no separate report needed per
    # value). See the Methodology tab.
    [ValidateRange(0, 7)]
    [double]$RecoveryWindowDays = 7,
    # v2.0: default 0. The report shows hours saved always and prompts the customer to enter their own
    # downtime cost per hour to see potential cost avoidance (no invented dollar figure).
    [double]$DowntimeCostPerHour = 0,

    # NEW v3.0.0, meaning corrected in v3.1.0: customizable, CUMULATIVE
    # recovery-time-objective (RTO) targets in hours for Mailboxes/OneDrive/
    # SharePoint. As of v3.1.0 these do NOT decide which group an object
    # lands in (all workloads use the same criticality-ranked -TierSplit
    # grouping) - they are a compliance check against each group's ABR
    # (hot-data-scope) cumulative recovery time, surfaced as a per-group
    # "exceeds target" flag on the Recovery tab and Executive Summary.
    # Live-adjustable in the report's Recovery tab.
    [double]$Group1TargetHours = 4,
    [double]$Group2TargetHours = 24,
    [double]$Group3TargetHours = 72,

    # NEW v3.0.0: 'Standard' = 4/24/72h. 'Enterprise' = 24/120/240h (Day 1 /
    # 5 days / 10 days). 'Auto' picks Standard or Enterprise based on an early
    # full-tenant recovery-time estimate (>= 5 days / 7200 min picks
    # Enterprise) and always surfaces which it picked and why - never silent.
    # 'Custom' (or explicitly passing any -Group1/2/3TargetHours) always wins
    # over whatever a preset would have chosen.
    [ValidateSet('Auto','Standard','Enterprise','Custom')]
    [string]$RTOPreset = 'Auto',

    # NEW v2.0.0: print the Enterprise App (application-permission) setup guide
    # and exit - does not run the assessment. Guided, not automated: this
    # script never creates the app registration or handles secrets itself.
    [switch]$ShowEnterpriseAppGuide,

    # NEW v2.0.0: connect via an Enterprise App (application permissions,
    # certificate auth) instead of an interactive delegated sign-in. All three
    # required together. See EnterpriseApp-Setup-Guide.md.
    # NEW: run from admin-center report exports instead of a live Graph connection
    # (for tenants where security won't approve running the script). Folder must
    # contain the exported CSVs - see the README, 'Running offline'.
    [string]$OfflinePath = '',

    [string]$TenantId = '',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = '',

    # NEW 2026-09-17: see Full script's matching comment - a customer's
    # very large tenant made Get-UserEnrichmentIndex's Get-MgUser -All pull
    # exceed the Graph PowerShell SDK's default HttpClient timeout, silently
    # wiping ALL profile enrichment for the run. Set generously here rather
    # than relying on the customer running Set-MgRequestContext themselves.
    [int]$GraphTimeoutSeconds = 900
)

# Resolved once, here, so every downstream reference to $Groups (scope
# requests, enrichment, manifest text, meta.groupsRequested, JS gating via
# hasGroups) keeps working unchanged - $NoGroups is the only new surface,
# $Groups is still "should group data be collected/shown," just inverted
# and on-by-default per v3.14.0 (see -NoGroups param comment above).
$Groups = -not $NoGroups
if ($OfflinePath) {
    $Groups = $false
}

$ErrorActionPreference = 'Stop'

# Microsoft.Graph.Reports' -OutFile download cmdlets have a known progress-bar bug:
# they compute PercentComplete from a response header that isn't always populated,
# which throws "Cannot set percent... Actual value was 2147483647" mid-download.
# It's cosmetic (the file still downloads correctly) but noisy. $ProgressPreference
# alone does NOT suppress it - the module writes it to the error stream internally
# with its own ErrorAction. Left here as harmless belt-and-suspenders; the real fix
# is the Get-GraphReport wrapper below.
$ProgressPreference = 'SilentlyContinue'

#region ---------- Setup / connection ----------

function Assert-GraphModules {
    $required = @('Microsoft.Graph.Reports', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Sites')
    foreach ($m in $required) {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            throw "Required module '$m' is not installed. Run: Install-Module $m -Scope CurrentUser"
        }
        Import-Module $m -ErrorAction Stop
    }
    # NOTE: Entra ID group membership enrichment (-NoGroups to opt out) does
    # NOT require the separate Microsoft.Graph.Groups module today - group
    # membership is pulled via -ExpandProperty MemberOf
    # on its own separate Get-MgUser -All call in Get-UserEnrichmentIndex
    # (still part of Microsoft.Graph.Users, already required above; Graph
    # only allows one navigation property expanded per query, so this can't
    # be combined with the manager-enrichment call - see that function's
    # header).
}

function Connect-Assessment {
    param(
        [switch]$Groups,
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [int]$GraphTimeoutSeconds = 900
    )

    $scopes = @('Reports.Read.All', 'User.Read.All', 'Sites.Read.All')
    if ($Groups) { $scopes += @('Group.Read.All') }

    $useAppOnly = $TenantId -and $ClientId -and $CertificateThumbprint
    if ($useAppOnly) {
        Write-Host "Connecting via Enterprise App (application permissions) as $ClientId in tenant $TenantId..." -ForegroundColor Cyan
        Write-Host "Application permissions are tenant-wide and static - confirm only the exact permissions in EnterpriseApp-Setup-Guide.md were granted." -ForegroundColor Yellow
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    } else {
        Write-Host "Connecting to Microsoft Graph (delegated, interactive). Requesting scopes: $($scopes -join ', ')" -ForegroundColor Cyan
        Connect-MgGraph -Scopes $scopes -NoWelcome
    }

    $ctx = Get-MgContext
    if (-not $ctx) { throw "Graph connection failed - Connect-MgGraph returned no context." }
    Write-Host "Connected as $($ctx.Account)" -ForegroundColor Green
    Write-Host "Scopes granted:  $($ctx.Scopes -join ', ')" -ForegroundColor Green

    # NEW 2026-09-17: see Full script's matching comment - raise the Graph
    # client timeout right after connecting so a huge tenant's Get-MgUser
    # -All pull (and any other slow Graph call for the rest of the run)
    # doesn't silently wipe enrichment via an HttpClient.Timeout.
    try {
        # NEW 2026-09-22: see Full script's matching comment - suppress
        # Set-MgRequestContext's return value so it doesn't leak an unwanted
        # ClientTimeout/RetryDelay/MaxRetry/RetriesTimeLimit table to the
        # console.
        Set-MgRequestContext -ClientTimeout $GraphTimeoutSeconds -ErrorAction Stop | Out-Null
        Write-Host "Graph client timeout set to $GraphTimeoutSeconds seconds (large tenants can otherwise time out mid-enrichment)." -ForegroundColor Gray
    } catch {
        Write-Warning "Could not raise the Graph client timeout ($($_.Exception.Message)). Continuing with the SDK default - very large tenants may see enrichment fail with an HttpClient.Timeout warning; re-run with a newer Microsoft.Graph.Authentication module if so."
    }

    if (-not $useAppOnly) {
        foreach ($needed in $scopes) {
            if ($ctx.Scopes -notcontains $needed) {
                Write-Warning "Scope '$needed' was not granted. Related workload(s)/enrichment will fail or return empty."
            }
        }
    }
}

function Get-EnterpriseAppSetupGuideText {
    <#
        GUIDED, NOT AUTOMATED (per design decision): prints exact steps for a
        customer's own admin to create the app registration themselves. This
        script never creates the app, never requests admin consent, and never
        sees or stores a secret/certificate - it only documents the process
        and then, if the customer chooses to use it, connects with the
        credential THEY generated (via -TenantId/-ClientId/-CertificateThumbprint).
    #>
    @'
# Running via an Enterprise App (application permissions)

This is an alternative to the default interactive delegated sign-in. It trades
a per-user permission ceiling for a wider, STATIC, tenant-wide grant - treat
this as something your security/identity team signs off on, not a default choice.

This script does not create the app registration, grant consent, or generate a
secret for you. Follow these steps yourself (or hand them to whoever owns app
registrations in your tenant):

## 1. Register the app
Entra admin center > Applications > App registrations > New registration.
- Name: e.g. "Rubrik M365 Criticality Assessment"
- Supported account types: Single tenant
- Redirect URI: leave blank (this uses the client-credentials flow, no interactive sign-in)

## 2. Add API permissions (APPLICATION permissions, not delegated)
API permissions > Add a permission > Microsoft Graph > Application permissions:
- Reports.Read.All
- User.Read.All
- Sites.Read.All
- Group.Read.All (skip this one only if you'll always run with -NoGroups)

Click "Grant admin consent for <tenant>" - this step requires a Global
Administrator or Privileged Role Administrator. This is the step that makes
the grant tenant-wide: unlike delegated scopes, there is no per-user ceiling
once consent is granted.

## 3. Create a certificate (recommended over a client secret)
A cert-based credential is preferred because it does not need to be rotated
as often and cannot be read back out of Entra once uploaded (a client secret
value CAN be, by whoever has portal access, until it's revoked).

    $cert = New-SelfSignedCertificate -Subject "CN=RubrikM365Assessment" `
        -CertStoreLocation "Cert:\CurrentUser\My" -KeySpec KeyExchange
    Export-Certificate -Cert $cert -FilePath .\RubrikM365Assessment.cer

Upload the .cer (public key only - never the private key) under the app
registration's "Certificates & secrets" tab.

## 4. Note down three values
- Tenant ID (Entra admin center > Overview)
- Application (client) ID (the app registration's Overview page)
- Certificate thumbprint: $cert.Thumbprint from step 3, or from the
  certificate's Details tab in the portal.

## 5. Run the assessment
    .\Invoke-RecoveryAssessment-M365-Preview.ps1 -TenantId <tenant-id> -ClientId <client-id> -CertificateThumbprint <thumbprint> [-NoGroups] [other params]

## When you're done
Revoke or delete the app registration (or at minimum rotate/remove the
certificate) if this was a one-time engagement. A static, tenant-wide,
unattended credential left active longer than necessary is a real, ongoing
risk surface - it should not outlive the reason it was created.
'@
}

#endregion

#region ---------- Helpers: enrichment, scoring, tiering, overrides, recovery ----------

function Get-UserEnrichmentIndex {
    <#
        FULL MODE ONLY (needs User.Read.All). Bulk-pulls user profile
        attributes AND resolves each user's manager roll-up chain (a list of
        display names from immediate manager up to the top), entirely offline
        from a single Get-MgUser -All call - no per-user Graph calls.
        Joined onto Mailboxes/OneDrive by UPN in Add-UserEnrichment.

        -IncludeGroups (on by default as of v3.14.0 - pass -NoGroups at the
        top level to skip it, which needs Group.Read.All): expands 'MemberOf'
        via a SECOND, separate Get-MgUser -All call (see the NEW 2026-09-08
        note below for why this can't be combined with the call above) and
        keeps only entries that are actual Entra ID groups (filters out
        directory roles / administrative units, which also come back on
        memberOf). Without Group.Read.All granted, memberOf still resolves
        object IDs but displayName comes back null/limited - so this quietly
        produces an empty Groups list rather than an error if group data was
        requested but the scope wasn't actually consented.
        NOTE: this build additionally redacts Groups/GroupIds for every
        non-Group-1 row (stripped by Select-PreviewGroup1Rows before output).
    #>
    param([switch]$IncludeGroups)

    $indexByUpn = @{}
    $indexById  = @{}

    # NEW 2026-09-08: found in field use: live 403->new-warning
    # follow-up report. This USED to be one Get-MgUser -All call with
    # -ExpandProperty @('Manager','MemberOf') whenever -IncludeGroups was
    # on (the default since v3.14.0). Microsoft Graph's /users endpoint
    # only allows ONE navigation property to be expanded per query - asking
    # for both Manager AND MemberOf in the same request throws
    # "Request_BadRequest: Only one property can be expanded in a single
    # query," which the catch below used to treat as a total enrichment
    # failure, returning the EMPTY $indexByUpn and silently dropping
    # JobTitle/Department/EmployeeType/Manager/Groups for every single row
    # in the report - not just group data. Since -IncludeGroups is
    # default-on, this was breaking title-weight scoring and every
    # department/manager/group filter for every customer NOT passing
    # -NoGroups, without the run ever throwing a terminating error (this is
    # why "the old script doesn't give that warning" - the old script only
    # ever expanded Manager alone, a single property, which Graph allows).
    # Fixed by splitting into two separate Get-MgUser -All calls, one per
    # expand target, merged by Id below - so a failure in the group-
    # membership call degrades to "no groups" instead of nuking the entire
    # enrichment index, and the common (non-Groups) path can never trigger
    # this specific Graph restriction at all. Mirrored from the Full script.
    try {
        $users = Get-MgUser -All -Property 'Id,UserPrincipalName,DisplayName,JobTitle,Department,EmployeeType,OfficeLocation,Country,UsageLocation,AccountEnabled,AssignedLicenses' -ExpandProperty 'Manager' -ErrorAction Stop
    }
    catch {
        Write-Warning "User profile enrichment failed ($($_.Exception.Message)). Continuing without it."
        return $indexByUpn
    }

    $memberOfById = @{}
    if ($IncludeGroups) {
        try {
            $usersWithGroups = Get-MgUser -All -Property 'Id' -ExpandProperty 'MemberOf' -ErrorAction Stop
            foreach ($ug in $usersWithGroups) {
                if ($ug.Id) { $memberOfById[$ug.Id] = $ug.MemberOf }
            }
        }
        catch {
            Write-Warning "Entra ID group membership enrichment failed ($($_.Exception.Message)). Continuing WITH profile enrichment (title/department/manager) but WITHOUT group data - pass -NoGroups to suppress this warning if group data isn't needed."
        }
    }

    $groupResolvedCount = 0
    foreach ($u in $users) {
        $managerId   = $null
        $managerName = $null
        if ($u.Manager) {
            $managerId = $u.Manager.Id
            if ($u.Manager.AdditionalProperties -and $u.Manager.AdditionalProperties.ContainsKey('displayName')) {
                $managerName = $u.Manager.AdditionalProperties['displayName']
            }
        }
        $groupNames = @()
        $groupIds   = @()
        $userMemberOf = if ($u.Id -and $memberOfById.ContainsKey($u.Id)) { $memberOfById[$u.Id] } else { $null }
        if ($IncludeGroups -and $userMemberOf) {
            foreach ($m in $userMemberOf) {
                $odataType = $null
                if ($m.AdditionalProperties -and $m.AdditionalProperties.ContainsKey('@odata.type')) {
                    $odataType = $m.AdditionalProperties['@odata.type']
                }
                # Skip directory roles / administrative units - memberOf
                # returns those too; only keep actual groups.
                if ($odataType -ne '#microsoft.graph.group') { continue }
                $gName = if ($m.AdditionalProperties -and $m.AdditionalProperties.ContainsKey('displayName')) { $m.AdditionalProperties['displayName'] } else { $null }
                if ($gName) { $groupNames += $gName; $groupIds += $m.Id }
            }
            if ($groupNames.Count -gt 0) { $groupResolvedCount++ }
        }
        $rec = [PSCustomObject]@{
            Id                = $u.Id
            DisplayName       = $u.DisplayName
            UserPrincipalName = $u.UserPrincipalName
            JobTitle          = $u.JobTitle
            Department        = $u.Department
            EmployeeType      = $u.EmployeeType
            OfficeLocation    = $u.OfficeLocation
            Country           = $u.Country
            UsageLocation     = $u.UsageLocation
            AccountEnabled    = $u.AccountEnabled
            # NEW v3.17.0 (mirrors Full): effective license SKU ids from assignedLicenses (User.Read.All, no extra scope).
            LicenseSkuIds     = @($u.AssignedLicenses | ForEach-Object { [string]$_.SkuId } | Where-Object { $_ })
            Manager           = $managerName
            ManagerId         = $managerId
            ManagerChain      = @()
            Groups            = @($groupNames)
            GroupIds          = @($groupIds)
        }
        if ($u.Id) { $indexById[$u.Id] = $rec }
        if ($u.UserPrincipalName) { $indexByUpn[$u.UserPrincipalName] = $rec }
    }

    # Walk each user's manager chain offline - cap at 15 hops with a cycle guard.
    foreach ($rec in $indexByUpn.Values) {
        $chain = [System.Collections.Generic.List[string]]::new()
        $seen  = [System.Collections.Generic.HashSet[string]]::new()
        $currentId = $rec.ManagerId
        $hops = 0
        while ($currentId -and $indexById.ContainsKey($currentId) -and $hops -lt 15) {
            if (-not $seen.Add($currentId)) { break }
            $mgr = $indexById[$currentId]
            $label = if ($mgr.DisplayName) { $mgr.DisplayName } elseif ($mgr.UserPrincipalName) { $mgr.UserPrincipalName } else { $currentId }
            $chain.Add($label)
            $currentId = $mgr.ManagerId
            $hops++
        }
        $rec.ManagerChain = @($chain)
    }

    Write-Host "User profile enrichment: $($indexByUpn.Count) users indexed; manager chains resolved offline." -ForegroundColor Gray
    if ($IncludeGroups) {
        Write-Host "Group membership enrichment: $groupResolvedCount of $($indexByUpn.Count) users have >=1 Entra ID group resolved." -ForegroundColor Gray
    }
    return $indexByUpn
}

# NEW v3.17.0: built-in map of license SKU ids -> plan label, used for the
# "licensed users by plan" breakdown. Needs no extra Graph scope (the tenant's
# own /subscribedSkus would, via LicenseAssignment.Read.All). Any SKU not in
# this table is reported as "Other (unrecognized)" and its raw id is listed in
# the report so it can be added here. Rank = precedence when a user holds more
# than one plan: the HIGHEST rank wins so each user is counted once.
$script:LicensePlanMap = @{
    '9a18296a-025f-4e37-9ffa-30bf8d1ce775' = @{ Plan = 'E7'; Family = 'Enterprise'; Rank = 60 }   # Microsoft 365 E7 (MICROSOFT_365_E7)
    '06ebc4ee-1bb5-47dd-8120-11324bc54e06' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 (SPE_E5)
    'db684ac5-c0e7-4f92-8284-ef9ebde75d33' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 (500 seats min)_HUB (Microsoft_365_E5)
    '18a4bd3f-0b5b-4887-b04f-61dd0ee15f5e' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 (no Teams) (Microsoft_365_E5_(no_Teams))
    '3271cf8e-2be5-4a09-a549-70fd05baaa17' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 EEA (no Teams) (O365_w/o_Teams_Bundle_M5)
    '1e988bf3-8b7c-4731-bec0-4e2a2946600c' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 EEA (no Teams) (500 seats min)_HUB (O365_w/o_Teams_Bundle_M5_(500_seats_min)_HUB)
    '6ee4114a-9b2d-4577-9e7a-49fa43d222d3' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 EEA (no Teams) with Calling Minutes (Microsoft_365_E5_EEA_(no_Teams)_with_Calling_Minutes)
    '90277bc7-a6fe-4181-99d8-712b08b8d32b' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 EEA (no Teams) without Audio Conferencing (Microsoft_365_E5_EEA_(no_Teams)_without_Audio_Conferencing)
    'a640eead-25f6-4bec-97e3-23cfd382d7c2' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 EEA (no Teams) without Audio Conferencing (500 seats min)_HUB (Microsoft_365_E5_EEA_(no_Teams)without_Audio_Conferencing(500_seats_min)_HUB)
    'a91fc4e0-65e5-4266-aa76-4037509c1626' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 with Calling Minutes (SPE_E5_CALLINGMINUTES)
    'cd2925a3-5076-4233-8931-638a8c94f773' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 without Audio Conferencing (SPE_E5_NOPSTNCONF)
    '2113661c-6509-4034-98bb-9c47bd28d63c' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5 without Audio Conferencing (500 seats min)_HUB (Microsoft_365_E5_without_Audio_Conferencing)
    '4eb45c5b-0d19-4e33-b87c-adfc25268f20' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Microsoft 365 E5_USGOV_GCCHIGH (SPE_E5_USGOV_GCCHIGH)
    'c7df2760-2c81-4ef7-b578-5b5392b571df' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Office 365 E5 (ENTERPRISEPREMIUM)
    'cf50bae9-29e8-4775-b07c-56ee10e3776d' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Office 365 E5 EEA (no Teams) (Office_365_w/o_Teams_Bundle_E5)
    '71772aeb-4bb8-4f74-9dd4-36c7a9b5ca74' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Office 365 E5 EEA (no Teams) without Audio Conferencing (Office_365_E5_EEA_(no_Teams)_without_Audio_Conferencing)
    '26d45bd9-adf1-46cd-a9e1-51e9a5524128' = @{ Plan = 'E5'; Family = 'Enterprise'; Rank = 50 }   # Office 365 E5 without Audio Conferencing (ENTERPRISEPREMIUM_NOPSTNCONF)
    '8900a2c0-edba-4079-bdf3-b276e293b6a8' = @{ Plan = 'G5'; Family = 'Government'; Rank = 48 }   # Office 365 G5 GCC (ENTERPRISEPREMIUM_GOV)
    'e97c048c-37a4-45fb-ab50-922fbf07a370' = @{ Plan = 'A5'; Family = 'Education'; Rank = 45 }   # Microsoft 365 A5 for faculty (M365EDU_A5_FACULTY)
    '46c119d4-0379-4a9d-85e4-97c66d3f909e' = @{ Plan = 'A5'; Family = 'Education'; Rank = 45 }   # Microsoft 365 A5 for students (M365EDU_A5_STUDENT)
    'a4585165-0533-458a-97e3-c400570268c4' = @{ Plan = 'A5'; Family = 'Education'; Rank = 45 }   # Office 365 A5 for faculty (ENTERPRISEPREMIUM_FACULTY)
    'ee656612-49fa-43e5-b67e-cb1fdf7699df' = @{ Plan = 'A5'; Family = 'Education'; Rank = 45 }   # Office 365 A5 for students (ENTERPRISEPREMIUM_STUDENT)
    '05e9a617-0261-4cee-bb44-138d3ef5d965' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Microsoft 365 E3 (SPE_E3)
    '0c21030a-7e60-4ec7-9a0f-0042e0e0211a' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Microsoft 365 E3 (500 seats min)_HUB (Microsoft_365_E3)
    'dcf0408c-aaec-446c-afd4-43e3683943ea' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Microsoft 365 E3 (no Teams) (Microsoft_365_E3_(no_Teams))
    'c2fe850d-fbbb-4858-b67d-bd0c6e746da3' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Microsoft 365 E3 EEA (no Teams) (O365_w/o Teams Bundle_M3)
    '602e6573-55a3-46b1-a1a0-cc267991501a' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Microsoft 365 E3 EEA (no Teams) (500 seats min)_HUB (O365_w/o Teams Bundle_M3_(500_seats_min)_HUB)
    'd61d61cc-f992-433f-a577-5bd016037eeb' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Microsoft 365 E3_USGOV_DOD (SPE_E3_USGOV_DOD)
    'ca9d1dd9-dfe9-4fef-b97c-9bc1ea3c3658' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Microsoft 365 E3_USGOV_GCCHIGH (SPE_E3_USGOV_GCCHIGH)
    '6fd2c87f-b296-42f0-b197-1e91e994b900' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Office 365 E3 (ENTERPRISEPACK)
    '46c3a859-c90d-40b3-9551-6178a48d5c18' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Office 365 E3 (no Teams) (Office_365_E3_(no_Teams))
    'd711d25a-a21c-492f-bd19-aae1e8ebaf30' = @{ Plan = 'E3'; Family = 'Enterprise'; Rank = 40 }   # Office 365 E3 EEA (no Teams) (O365_w/o_Teams_Bundle_E3)
    'e823ca47-49c4-46b3-b38d-ca11d5abe3d2' = @{ Plan = 'G3'; Family = 'Government'; Rank = 38 }   # Microsoft 365 G3 GCC (M365_G3_GOV)
    '535a3a29-c5f0-42fe-8215-d3b9e1f38c4a' = @{ Plan = 'G3'; Family = 'Government'; Rank = 38 }   # Office 365 G3 GCC (ENTERPRISEPACK_GOV)
    '4b590615-0888-425a-a965-b3bf7789848d' = @{ Plan = 'A3'; Family = 'Education'; Rank = 35 }   # Microsoft 365 A3 for faculty (M365EDU_A3_FACULTY)
    '7cfd9a2b-e110-4c39-bf20-c6a3f36a3121' = @{ Plan = 'A3'; Family = 'Education'; Rank = 35 }   # Microsoft 365 A3 for students (M365EDU_A3_STUDENT)
    'e578b273-6db4-4691-bba0-8d691f4da603' = @{ Plan = 'A3'; Family = 'Education'; Rank = 35 }   # Office 365 A3 for Faculty (ENTERPRISEPACKPLUS_FACULTY)
    '98b6e773-24d4-4c0d-a968-6e787a1f8204' = @{ Plan = 'A3'; Family = 'Education'; Rank = 35 }   # Office 365 A3 for Students (ENTERPRISEPACKPLUS_STUDENT)
    '18181a46-0d4e-45cd-891e-60aabd171b4e' = @{ Plan = 'E1'; Family = 'Enterprise'; Rank = 30 }   # Office 365 E1 (STANDARDPACK)
    'f8ced641-8e17-4dc5-b014-f5a2d53f6ac8' = @{ Plan = 'E1'; Family = 'Enterprise'; Rank = 30 }   # Office 365 E1 (no Teams) (Office_365_E1_(no_Teams))
    'b57282e3-65bd-4252-9502-c0eae1e5ab7f' = @{ Plan = 'E1'; Family = 'Enterprise'; Rank = 30 }   # Office 365 E1 EEA (no Teams) (Office_365_w/o_Teams_Bundle_E1)
    '6634e0ce-1a9f-428c-a498-f84ec7b8aa2e' = @{ Plan = 'E1'; Family = 'Enterprise'; Rank = 30 }   # Office 365 E2 (STANDARDWOFFPACK)
    '3f4babde-90ec-47c6-995d-d223749065d1' = @{ Plan = 'G1'; Family = 'Government'; Rank = 28 }   # Office 365 G1 GCC (STANDARDPACK_GOV)
    'b17653a4-2443-4e8c-a550-18249dda78bb' = @{ Plan = 'A1'; Family = 'Education'; Rank = 25 }   # Microsoft 365 A1 (M365EDU_A1)
    '78e66a63-337a-4a9a-8959-41c6654dfb56' = @{ Plan = 'A1'; Family = 'Education'; Rank = 25 }   # Office 365 A1 Plus for Faculty (STANDARDWOFFPACK_IW_FACULTY)
    'e82ae690-a2d5-4d76-8d30-7c6e01e6022e' = @{ Plan = 'A1'; Family = 'Education'; Rank = 25 }   # Office 365 A1 Plus for Students (STANDARDWOFFPACK_IW_STUDENT)
    '94763226-9b3c-4e75-a931-5c89701abe66' = @{ Plan = 'A1'; Family = 'Education'; Rank = 25 }   # Office 365 A1 for faculty (STANDARDWOFFPACK_FACULTY)
    '314c4481-f395-4525-be8b-2ec4bb1e9d91' = @{ Plan = 'A1'; Family = 'Education'; Rank = 25 }   # Office 365 A1 for students (STANDARDWOFFPACK_STUDENT)
    '66b55226-6b4f-492c-910c-a3b7a3c9d993' = @{ Plan = 'F3'; Family = 'Frontline'; Rank = 20 }   # Microsoft 365 F3 (SPE_F1)
    'f7ee79a7-7aec-4ca4-9fb9-34d6b930ad87' = @{ Plan = 'F3'; Family = 'Frontline'; Rank = 20 }   # Microsoft 365 F3 EEA (no Teams) (Microsoft_365_F3_EEA_(no_Teams))
    '2a914830-d700-444a-b73c-e3f31980d833' = @{ Plan = 'F3'; Family = 'Frontline'; Rank = 20 }   # Microsoft 365 F3 GCC (M365_F1_GOV)
    '4b585984-651b-448a-9e53-3b10f069cf7f' = @{ Plan = 'F3'; Family = 'Frontline'; Rank = 20 }   # Office 365 F3 (DESKLESSPACK)
    'd1f0495b-cb7b-4e11-8b85-daee7e7e5664' = @{ Plan = 'F3'; Family = 'Frontline'; Rank = 20 }   # Office 365 F3 EEA (no Teams) (Office_365_F3_EEA_(no_Teams))
    '74039b88-bd62-4b5c-9d9c-7a92bbc0bfdf' = @{ Plan = 'F3'; Family = 'Frontline'; Rank = 20 }   # Office 365 F3_USGOV_GCCHIGH (DESKLESSPACK_USGOV_GCCHIGH)
    '44575883-256e-4a79-9da4-ebe9acabe2b2' = @{ Plan = 'F1'; Family = 'Frontline'; Rank = 18 }   # Microsoft 365 F1 (M365_F1)
    '50f60901-3181-4b75-8a2c-4c8e4c1d5a72' = @{ Plan = 'F1'; Family = 'Frontline'; Rank = 18 }   # Microsoft 365 F1 (M365_F1_COMM)
    '0666269f-b167-4c5b-a76f-fc574f2b1118' = @{ Plan = 'F1'; Family = 'Frontline'; Rank = 18 }   # Microsoft 365 F1 EEA (no Teams) (Microsoft_365_F1_EEA_(no_Teams))
    'cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46' = @{ Plan = 'Business Premium'; Family = 'Business'; Rank = 15 }   # Microsoft 365 Business Premium (SPB)
    '00e1ec7b-e4a3-40d1-9441-b69b597ab222' = @{ Plan = 'Business Premium'; Family = 'Business'; Rank = 15 }   # Microsoft 365 Business Premium (no Teams) (Microsoft_365_ Business_ Premium_(no Teams))
    '24c35284-d768-4e53-84d9-b7ae73dddf69' = @{ Plan = 'Business Premium'; Family = 'Business'; Rank = 15 }   # Microsoft 365 Business Premium Donation (Microsoft_365_Business_Premium_Donation_(Non_Profit_Pricing))
    'a3f586b6-8cce-4d9b-99d6-55238397f77a' = @{ Plan = 'Business Premium'; Family = 'Business'; Rank = 15 }   # Microsoft 365 Business Premium EEA (no Teams) (Office_365_w/o_Teams_Bundle_Business_Premium)
    'fc14ec4a-4169-49a4-a51e-2c852931814b' = @{ Plan = 'Business Premium'; Family = 'Business'; Rank = 15 }   # Office 365 Small Business Premium (LITEPACK_P2)
    'f245ecc8-75af-4f8e-b61f-27d8114de5f3' = @{ Plan = 'Business Standard'; Family = 'Business'; Rank = 14 }   # Microsoft 365 Business Standard (O365_BUSINESS_PREMIUM)
    '5a1c7b8d-0739-4ca8-bf69-ec87e69133ac' = @{ Plan = 'Business Standard'; Family = 'Business'; Rank = 14 }   # Microsoft 365 Business Standard (no Teams) (MICROSOFT_365_BUSINESS_STANDARD_NO_TEAMS)
    'ac5cef5d-921b-4f97-9ef3-c99076e5470f' = @{ Plan = 'Business Standard'; Family = 'Business'; Rank = 14 }   # Microsoft 365 Business Standard - Prepaid Legacy (SMB_BUSINESS_PREMIUM)
    'c1f79c29-5d7a-4bec-a2c1-1a76774864c0' = @{ Plan = 'Business Standard'; Family = 'Business'; Rank = 14 }   # Microsoft 365 Business Standard EEA (no Teams) (Office_365_w/o_Teams_Bundle_Business_Standard)
    'ffa3a2a0-3820-462a-aa81-8a4d741f0cba' = @{ Plan = 'Business Standard'; Family = 'Business'; Rank = 14 }   # Microsoft 365 Business Standard EEA (no Teams) (Microsoft_365_Business_Standard_EEA_(no_Teams))
    '3b555118-da6a-4418-894f-7df1e2096870' = @{ Plan = 'Business Basic'; Family = 'Business'; Rank = 13 }   # Microsoft 365 Business Basic (O365_BUSINESS_ESSENTIALS)
    'dab7782a-93b1-4074-8bb1-0e61318bea0b' = @{ Plan = 'Business Basic'; Family = 'Business'; Rank = 13 }   # Microsoft 365 Business Basic (SMB_BUSINESS_ESSENTIALS)
    '21502a13-c8dc-4744-be9c-177fd9d2eafc' = @{ Plan = 'Business Basic'; Family = 'Business'; Rank = 13 }   # Microsoft 365 Business Basic (no Teams) (Microsoft_365_Business_Basic_(no Teams))
    'b1f3042b-a390-4b56-ab61-b88e7e767a97' = @{ Plan = 'Business Basic'; Family = 'Business'; Rank = 13 }   # Microsoft 365 Business Basic EEA (no Teams) (Microsoft_365_Business_Basic_EEA_(no_Teams))
    '19ec0d23-8335-4cbd-94ac-6050e30712fa' = @{ Plan = 'Exchange Online (Plan 2)'; Family = 'Exchange'; Rank = 12 }   # Exchange Online (PLAN 2) (EXCHANGEENTERPRISE)
    '0b7b15a8-7fd2-4964-bb96-5a566d4e3c15' = @{ Plan = 'Exchange Online (Plan 2)'; Family = 'Exchange'; Rank = 12 }   # Exchange Online (Plan 2) for Faculty (EXCHANGEENTERPRISE_FACULTY)
    '7be8dc28-4da4-4e6d-b9b9-c60f2806df8a' = @{ Plan = 'Exchange Online (Plan 2)'; Family = 'Exchange'; Rank = 12 }   # Exchange Online (Plan 2) for GCC (EXCHANGEENTERPRISE_GOV)
    '4b9405b0-7788-4568-add1-99614e613b69' = @{ Plan = 'Exchange Online (Plan 1)'; Family = 'Exchange'; Rank = 11 }   # Exchange Online (Plan 1) (EXCHANGESTANDARD)
    'aa0f9eb7-eff2-4943-8424-226fb137fcad' = @{ Plan = 'Exchange Online (Plan 1)'; Family = 'Exchange'; Rank = 11 }   # Exchange Online (Plan 1) for Alumni with Yammer (EXCHANGESTANDARD_ALUMNI)
    'f37d5ebf-4bf1-4aa2-8fa3-50c51059e983' = @{ Plan = 'Exchange Online (Plan 1)'; Family = 'Exchange'; Rank = 11 }   # Exchange Online (Plan 1) for GCC (EXCHANGESTANDARD_GOV)
    'ad2fe44a-915d-4e2b-ade1-6766d50a9d9c' = @{ Plan = 'Exchange Online (Plan 1)'; Family = 'Exchange'; Rank = 11 }   # Exchange Online (Plan 1) for Students (EXCHANGESTANDARD_STUDENT)
    '80b2d799-d2ba-4d2a-8842-fb0d0f3a4b82' = @{ Plan = 'Exchange Online Kiosk'; Family = 'Exchange'; Rank = 10 }   # Exchange Online Kiosk (EXCHANGEDESKLESS)
    'e8f81a67-bd96-4074-b108-cf193eb9433b' = @{ Plan = 'Exchange Online Essentials'; Family = 'Exchange'; Rank = 9 }   # Exchange Online Essentials (EXCHANGE_S_ESSENTIALS)
    '7fc0182e-d107-4556-8329-7caaa511197b' = @{ Plan = 'Exchange Online Essentials'; Family = 'Exchange'; Rank = 9 }   # Exchange Online Essentials (ExO P1 Based) (EXCHANGEESSENTIALS)
}
# Standalone Exchange Online Archiving add-on SKUs (reported separately; not a base plan).
# Free / non-mailbox SKUs that do NOT make a mailbox a licensed user mailbox
# (Fabric/Power BI free, Power Automate free, Power Apps Developer, Copilot and M365 Apps add-ons). Ignored for classification and plan.
$script:LicenseNonMailboxSkus = @('a403ebcc-fae0-4ca2-8c8c-7a907fd6c235', 'f30db892-07e9-47e9-837c-80727f46fd3d', '5b631642-bd26-49fe-bd20-1daaa972ef80', '639dec6b-bb19-468b-871c-c5c441c4b0cb', 'c2273bd0-dff7-4215-9ef5-2c7bcfb06425')
# Counts of license SKU ids NOT in the map above (mailboxes only), surfaced in the report so they can be identified and added.
$script:UnmappedSkuCounts = @{}
$script:LicenseArchiveAddonSkus = @('ee02fd1b-340e-4a4b-b355-4a514e4c8943', '90b5e015-709a-4b8b-b08e-3200f994494c')

function Get-LicensePlan {
    <# Returns the highest-ranked recognized plan label for a user's SKU ids; 'Other (unrecognized)' when licensed but none match; '' when unlicensed. #>
    param([AllowEmptyCollection()] [string[]] $SkuIds)
    if (-not $SkuIds -or $SkuIds.Count -eq 0) { return '' }
    $best = $null
    foreach ($id in $SkuIds) {
        $hit = $script:LicensePlanMap[$id.ToLowerInvariant()]
        if ($hit -and (-not $best -or $hit.Rank -gt $best.Rank)) { $best = $hit }
    }
    if ($best) { return $best.Plan }
    return 'Other (unrecognized)'
}

function Add-UserEnrichment {
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]     $Data,
        [Parameter(Mandatory)] [hashtable] $EnrichmentIndex,
        [Parameter(Mandatory)] [string]    $UpnField
    )
    if (-not $EnrichmentIndex -or $EnrichmentIndex.Count -eq 0) { return $Data }

    foreach ($row in $Data) {
        $upn = $row.$UpnField
        $enrich = if ($upn) { $EnrichmentIndex[$upn] } else { $null }
        Add-Member -InputObject $row -NotePropertyName 'JobTitle'       -NotePropertyValue $(if ($enrich) { $enrich.JobTitle } else { '' })       -Force
        Add-Member -InputObject $row -NotePropertyName 'Department'     -NotePropertyValue $(if ($enrich) { $enrich.Department } else { '' })     -Force
        Add-Member -InputObject $row -NotePropertyName 'EmployeeType'   -NotePropertyValue $(if ($enrich) { $enrich.EmployeeType } else { '' })   -Force
        Add-Member -InputObject $row -NotePropertyName 'Manager'        -NotePropertyValue $(if ($enrich) { $enrich.Manager } else { '' })        -Force
        # NEW 2026-09-11: see Full script's matching comment - $(...) around
        # an if/else lets PowerShell auto-unroll a collection written to the
        # output stream, collapsing exactly-one-element arrays (a single
        # Entra ID group, a single manager-chain hop) into bare strings
        # instead of 1-element arrays. @(...) forces array-context
        # collection regardless of element count.
        Add-Member -InputObject $row -NotePropertyName 'ManagerChain'   -NotePropertyValue @(if ($enrich) { $enrich.ManagerChain } else { @() })  -Force
        Add-Member -InputObject $row -NotePropertyName 'Groups'         -NotePropertyValue @(if ($enrich) { $enrich.Groups } else { @() })        -Force
        Add-Member -InputObject $row -NotePropertyName 'GroupIds'       -NotePropertyValue @(if ($enrich) { $enrich.GroupIds } else { @() })      -Force
        Add-Member -InputObject $row -NotePropertyName 'OfficeLocation' -NotePropertyValue $(if ($enrich) { $enrich.OfficeLocation } else { '' }) -Force
        Add-Member -InputObject $row -NotePropertyName 'AccountEnabled' -NotePropertyValue $(if ($enrich) { $enrich.AccountEnabled } else { $null }) -Force
        # NEW v3.17.0: license join. EntraMatched distinguishes "no user
        # account at all" (group mailbox, orphan) from "user, unlicensed".
        $rawSkuIds = @(if ($enrich) { $enrich.LicenseSkuIds } else { @() })
        $skuIds = @($rawSkuIds | Where-Object { $script:LicenseNonMailboxSkus -notcontains ([string]$_).ToLowerInvariant() })
        Add-Member -InputObject $row -NotePropertyName 'EntraMatched' -NotePropertyValue ([bool]$enrich) -Force
        Add-Member -InputObject $row -NotePropertyName 'IsLicensed'   -NotePropertyValue ($skuIds.Count -gt 0) -Force
        Add-Member -InputObject $row -NotePropertyName 'LicensePlan'  -NotePropertyValue (Get-LicensePlan -SkuIds $skuIds) -Force
        if ($UpnField -eq 'Identifier') {
            foreach ($id in $skuIds) {
                $lid = $id.ToLowerInvariant()
                if (-not $script:LicensePlanMap.ContainsKey($lid) -and ($script:LicenseArchiveAddonSkus -notcontains $lid)) {
                    $script:UnmappedSkuCounts[$lid] = 1 + [int]$script:UnmappedSkuCounts[$lid]
                }
            }
        }
        Add-Member -InputObject $row -NotePropertyName 'HasArchiveAddon' -NotePropertyValue (@($skuIds | Where-Object { $script:LicenseArchiveAddonSkus -contains $_.ToLowerInvariant() }).Count -gt 0) -Force
    }
    return $Data
}

function Add-MailboxTypeHeuristic {
    <#
        v3.17.0: the Graph mailbox usage report NO LONGER returns a usable
        'Recipient Type' column (confirmed blank/absent on every customer
        export checked), so the old Recipient-Type-first classification
        counted every mailbox as a user and reported 0 shared mailboxes.
        Classification is now license-based (assignedLicenses, joined in
        Add-UserEnrichment; User.Read.All, no new scope):

          Shared    - confirmed Shared/Room/Equipment by Exchange Online
                      (-DetailedSizing, authoritative, wins over everything),
                      OR a Recipient Type that says so (older tenants), OR no
                      matching Entra user (group mailbox / orphan), OR
                      DISABLED and unlicensed (shared mailboxes are normally
                      created with sign-in blocked), OR unlicensed with the
                      50 GB mailbox limit (v3.17.1: shared mailboxes whose
                      sign-in was left enabled).
                      Protected and sized, but needs NO Rubrik license.
          Licensed  - at least one assigned license (enabled OR disabled).
                      Counts toward the Rubrik license quote.
          Unlicensed- ENABLED and unlicensed. Rubrik does not protect these;
                      the caller excludes them from the report entirely.
          Unknown   - license data wasn't collected (enrichment failed or
                      returned nothing), so nothing is excluded or guessed.

        MailboxClass drives the Sizing tab; MailboxTypeHeuristic is the
        human-readable label shown in the Mailbox Type column/filter.
    #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Data,
        [System.Collections.Generic.HashSet[string]] $SharedUpnSet = $null,
        [bool] $LicenseDataAvailable = $true
    )
    foreach ($row in $Data) {
        $recipientType = [string]$row.RecipientType
        $class = $null; $label = $null
        if ($null -ne $SharedUpnSet -and $SharedUpnSet.Contains([string]$row.Identifier)) {
            $class = 'Shared'; $label = 'Shared / resource mailbox (confirmed via Exchange Online)'
        }
        elseif ($recipientType -match 'Shared|Room|Equipment') {
            $class = 'Shared'; $label = "$recipientType (Recipient Type)"
        }
        elseif (-not $LicenseDataAvailable) {
            $class = 'Unknown'; $label = 'Unclassified (license data not collected)'
        }
        elseif ($row.PSObject.Properties.Name -contains 'EntraMatched' -and -not $row.EntraMatched) {
            $class = 'Shared'; $label = 'Shared / group / other (no matching user account)'
        }
        elseif ($row.IsLicensed) {
            $class = 'Licensed'; $label = 'Licensed user mailbox'
        }
        elseif ($row.AccountEnabled -eq $false) {
            $class = 'Shared'; $label = 'Shared / other (disabled, unlicensed)'
        }
        elseif ($row.SendReceiveQuotaBytes -gt 0 -and [math]::Abs($row.SendReceiveQuotaBytes - 53687091200) -lt 1073741824) {
            # Unlicensed but still sign-in enabled, with the 50 GB limit Exchange gives
            # unlicensed shared/room/equipment mailboxes (a real user mailbox that lost
            # its license keeps its old limit). Seen on a live tenant: both genuine
            # shared mailboxes were enabled+unlicensed and carried exactly this limit.
            $class = 'Shared'; $label = 'Shared / resource (unlicensed, standard shared-mailbox limit)'
        }
        else {
            $class = 'Unlicensed'; $label = 'Unlicensed user (enabled) - not protected'
        }
        Add-Member -InputObject $row -NotePropertyName 'MailboxClass' -NotePropertyValue $class -Force
        Add-Member -InputObject $row -NotePropertyName 'MailboxTypeHeuristic' -NotePropertyValue $label -Force
    }
    return $Data
}

function Add-TitleWeightScore {
    <# Needs JobTitle (from base enrichment). Highest-weight keyword match wins. #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]     $Data,
        [Parameter(Mandatory)] [hashtable] $TitleWeights
    )
    foreach ($row in $Data) {
        $title = [string]$row.JobTitle
        $best = 0.0
        $matchedKeyword = ''
        if ($title) {
            foreach ($kw in $TitleWeights.Keys) {
                if ($title -match [regex]::Escape($kw)) {
                    if ($TitleWeights[$kw] -gt $best) { $best = $TitleWeights[$kw]; $matchedKeyword = $kw }
                }
            }
        }
        Add-Member -InputObject $row -NotePropertyName 'TitleWeight'      -NotePropertyValue $best -Force
        Add-Member -InputObject $row -NotePropertyName 'TitleWeightMatch' -NotePropertyValue $matchedKeyword -Force
    }
    return $Data
}

function Add-HubSiteFlag {
    <#
        SharePoint "department one-stop-shop" heuristic - runs in BOTH Preview
        and Full, no extra Graph scope. Flags a site as a hub CANDIDATE
        when its name/URL matches a department keyword AND its activity
        (page views + active files) ranks in the top quartile of this
        dataset - a breadth-of-use PROXY, not a true unique-accessor or
        group-membership count (that would need Group.Read.All / a per-site
        permissions crawl - out of scope here, see README).
    #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]    $Data,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Keywords,
        [double] $Bonus = 0.15
    )
    if ($Data.Count -eq 0) { return $Data }

    $sorted = @($Data | Sort-Object -Property TotalActivity)
    $n = $sorted.Count
    for ($i = 0; $i -lt $n; $i++) {
        $rank = if ($n -gt 1) { $i / ($n - 1) } else { 1 }
        Add-Member -InputObject $sorted[$i] -NotePropertyName '_BreadthRank' -NotePropertyValue $rank -Force
    }

    foreach ($row in $Data) {
        $haystack = "$($row.ObjectName) $($row.Identifier)"
        $matched = $null
        foreach ($kw in $Keywords) {
            if ($haystack -match [regex]::Escape($kw)) { $matched = $kw; break }
        }
        $isHub = ($null -ne $matched) -and ($row._BreadthRank -ge 0.75)
        Add-Member -InputObject $row -NotePropertyName 'HubSiteCandidate'     -NotePropertyValue $isHub -Force
        Add-Member -InputObject $row -NotePropertyName 'HubSiteKeywordMatch' -NotePropertyValue $(if ($matched) { $matched } else { '' }) -Force
        Add-Member -InputObject $row -NotePropertyName 'HubSiteBonus'        -NotePropertyValue $(if ($isHub) { $Bonus } else { 0.0 }) -Force
    }
    return $Data
}

function Get-ExactTeamSiteUrls {
    <#
    FULL MODE ONLY. Needs Sites.Read.All - AND, despite the comment this
    replaced saying otherwise, Get-MgGroupSite also needs enough group-read
    access to resolve each Team's underlying Microsoft 365 Group before it
    can return that group's site (Group.Read.All in practice). Found
    2026-09-08 via a customer 403/accessDenied report:
    running with -NoGroups (which deliberately does NOT request
    Group.Read.All) made EVERY Get-MgGroupSite call fail, since the group
    itself can't be read. That was already non-fatal (caught below, one
    Write-Warning per Team) - but returning a non-null, mostly-empty $keys
    set in that all-fail scenario was a real correctness bug on top of the
    noise: Get-SharePointCriticality's $useExactMode goes true whenever
    $ExactTeamSiteKeys is non-null, so with -NoGroups every team-connected
    SharePoint site was silently NOT recognized as team-owned (empty set
    never contains anything) and got double-counted as a standalone site,
    instead of falling back to the free, no-extra-permission heuristic
    (RootWebTemplate -in 'Group'/'Team Channel', already used when
    $ExactTeamSiteKeys is $null). Skipping the whole loop and returning
    $null up front when -Groups wasn't requested fixes BOTH problems: no
    doomed per-team API calls/warning spam, and the heuristic fallback
    actually engages instead of quietly mis-scoping the SharePoint tab.
    Mirrored from the Full script. See v1.2.1/1.2.2 notes retained below.
    #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Teams,
        [switch] $Groups
    )

    if (-not $Groups) {
        Write-Host "Exact Team-site resolution skipped (-NoGroups was passed - Get-MgGroupSite needs Group.Read.All to resolve each Team's site, which -NoGroups deliberately doesn't request). Falling back to heuristic Team/Group-site matching for SharePoint dedup - no extra permission needed." -ForegroundColor Gray
        return $null
    }

    # Circuit breaker: found 2026-09-08 via a second report from the same
    # customer tenant - even with Group.Read.All AND
    # Sites.Read.All both actually granted (confirmed via their own
    # (Get-MgContext).Scopes dump), Get-MgGroupSite still 403'd for every
    # Team. Root cause is a separate, well-documented Graph limitation from
    # the missing-scope case above: under DELEGATED (interactive user)
    # auth, /groups/{id}/sites/root enforces that the signed-in user is
    # actually a MEMBER of that Microsoft 365 Group - broad admin-consented
    # scopes don't override that for this specific call. An admin running
    # this interactively is realistically not a member of most Teams in a
    # large tenant, so this fails almost every time regardless of scope
    # breadth. Rather than grinding through every remaining Team making a
    # doomed API call and printing a warning each time, bail out after the
    # first few failures (with zero successes so far - a real, occasional
    # per-team failure would typically be interspersed with successes, not
    # clustered from the very first attempt) and fall back cleanly to the
    # free heuristic for everyone, same as the -NoGroups case above.
    # Mirrored from the Full script.
    $maxProbeFailuresBeforeBail = 5
    $failureCount = 0

    $keys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $resolvedCount = 0
    foreach ($t in $Teams) {
        $groupId = $t.Identifier
        if (-not $groupId) { continue }
        try {
            $site = Get-MgGroupSite -GroupId $groupId -SiteId 'root' -ErrorAction Stop
            if ($site) {
                $matched = $false
                if ($site.WebUrl) { [void]$keys.Add($site.WebUrl.TrimEnd('/')); $matched = $true }
                if ($site.Id) {
                    $parts = $site.Id -split ','
                    if ($parts.Count -ge 2 -and $parts[1]) { [void]$keys.Add($parts[1]); $matched = $true }
                }
                if ($matched) { $resolvedCount++ }
            }
        }
        catch {
            $failureCount++
            if ($resolvedCount -eq 0 -and $failureCount -ge $maxProbeFailuresBeforeBail) {
                Write-Warning "Exact Team-site resolution: Get-MgGroupSite failed for the first $failureCount team(s) in a row (most recent error: $($_.Exception.Message)). This usually means either (a) the signed-in session doesn't actually have Sites.Read.All/Group.Read.All granted, or (b) you're connected via delegated/interactive auth and simply aren't a member of most of these Microsoft 365 Groups - Microsoft Graph enforces group membership for this specific call regardless of how broad the consented scopes are. Falling back to heuristic Team/Group-site matching for all $($Teams.Count) teams instead of continuing to retry one at a time."
                return $null
            }
            Write-Warning "Could not resolve SharePoint site for Team '$($t.ObjectName)' ($groupId): $($_.Exception.Message)"
        }
    }
    Write-Host "Exact Team-site resolution: $resolvedCount of $($Teams.Count) teams resolved." -ForegroundColor Gray
    return $keys
}

function Get-ColumnValue {
    param(
        [Parameter(Mandatory)] $Row,
        [Parameter(Mandatory)] [string[]] $CandidateNames,
        $Default = 0
    )
    $available = $Row.PSObject.Properties.Name
    foreach ($name in $CandidateNames) {
        if ($available -contains $name) {
            $val = $Row.$name
            if ($null -ne $val -and $val -ne '') { return $val }
        }
    }
    return $Default
}

function Get-FieldSum {
    <#
        NEW v3.0.0. Single shared "sum a numeric field across a row set"
        helper - used everywhere a dataset-wide total (avg item size inputs,
        the early full-tenant recovery estimate, Build-RecoveryModel's
        per-tier slices) is computed, so there is exactly one implementation
        instead of several copies that could quietly drift out of sync.
    #>
    param($Rows, [string]$Field)
    if (-not $Rows -or $Rows.Count -eq 0) { return 0.0 }
    return [double]((($Rows | Measure-Object -Property $Field -Sum).Sum))
}

function Add-CompositeScore {
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Data,
        [Parameter(Mandatory)] [hashtable] $MetricWeights
    )
    $count = $Data.Count
    if ($count -eq 0) { return $Data }

    foreach ($field in $MetricWeights.Keys) {
        $sorted = $Data | Sort-Object -Property { [double]$_.$field }
        for ($i = 0; $i -lt $sorted.Count; $i++) {
            $rank = if ($count -gt 1) { $i / ($count - 1) } else { 1 }
            Add-Member -InputObject $sorted[$i] -NotePropertyName "_${field}_Rank" -NotePropertyValue $rank -Force
        }
    }

    foreach ($row in $Data) {
        $score = 0.0
        foreach ($field in $MetricWeights.Keys) {
            $rankProp = "_${field}_Rank"
            $score += ([double]$row.$rankProp) * $MetricWeights[$field]
        }
        Add-Member -InputObject $row -NotePropertyName '_Score' -NotePropertyValue ([math]::Round($score, 4)) -Force
    }
    return $Data
}

function Add-CriteriaTags {
    <#
        NEW v2.0.0. Per-object "why is this here" summary: the top 1-2
        weighted metrics that drove the score, plus modifier flags (title
        match, hub-site candidate). Mirrored client-side in JS so tags stay
        accurate when weights are adjusted live in the report.
    #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]     $Data,
        [Parameter(Mandatory)] [hashtable] $MetricWeights
    )
    $friendly = @{
        SendRecvActivity = 'Send/receive volume'; ReadActivity = 'Read volume'; Size = 'Mailbox size'
        FileActivity     = 'File activity';       Storage      = 'Storage size'
        PageViews        = 'Page views';          ActiveFiles  = 'Recently used files'
        ActiveUsers      = 'Participating users';        ChannelMsgs  = 'Channel messages'; Meetings = 'Meetings organized'
        TitleWeight      = 'Job title'
    }
    foreach ($row in $Data) {
        $contributions = foreach ($field in $MetricWeights.Keys) {
            $rankProp = "_${field}_Rank"
            if ($row.PSObject.Properties.Name -contains $rankProp) {
                [PSCustomObject]@{ Field = $field; Contribution = ([double]$row.$rankProp) * $MetricWeights[$field] }
            }
        }
        $top = $contributions | Sort-Object -Property Contribution -Descending | Select-Object -First 2
        $tags = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $top) {
            if ($c.Contribution -gt 0) {
                $tags.Add($(if ($friendly.ContainsKey($c.Field)) { $friendly[$c.Field] } else { $c.Field }))
            }
        }
        if (($row.PSObject.Properties.Name -contains 'HubSiteCandidate') -and $row.HubSiteCandidate) { $tags.Add('Department hub site (heuristic)') }
        if (($row.PSObject.Properties.Name -contains 'TitleWeightMatch') -and $row.TitleWeightMatch)  { $tags.Add("Title match: $($row.TitleWeightMatch)") }
        Add-Member -InputObject $row -NotePropertyName 'CriteriaTags' -NotePropertyValue ($tags -join '; ') -Force
    }
    return $Data
}

function Add-Tier {
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Data,
        [double[]] $TierSplit = @(0.33, 0.33, 0.34),
        [string] $InactiveCheckField
    )
    $active = $Data
    $inactive = @()

    if ($InactiveCheckField) {
        $active   = @($Data | Where-Object { [double]$_.$InactiveCheckField -gt 0 })
        $inactive = @($Data | Where-Object { [double]$_.$InactiveCheckField -le 0 })
    }

    $ranked = @($active | Sort-Object -Property _Score -Descending)
    $n = $ranked.Count
    $t1Cut = [math]::Ceiling($n * $TierSplit[0])
    $t2Cut = [math]::Ceiling($n * ($TierSplit[0] + $TierSplit[1]))

    for ($i = 0; $i -lt $n; $i++) {
        $tier = if ($i -lt $t1Cut) { 'Critical Group 1' }
                elseif ($i -lt $t2Cut) { 'Critical Group 2' }
                else { 'Critical Group 3' }
        Add-Member -InputObject $ranked[$i] -NotePropertyName 'Tier' -NotePropertyValue $tier -Force
        Add-Member -InputObject $ranked[$i] -NotePropertyName 'ComputedTier' -NotePropertyValue $tier -Force
        Add-Member -InputObject $ranked[$i] -NotePropertyName 'RankWithinWorkload' -NotePropertyValue ($i + 1) -Force
    }
    foreach ($row in $inactive) {
        Add-Member -InputObject $row -NotePropertyName 'Tier' -NotePropertyValue 'Group 4' -Force
        Add-Member -InputObject $row -NotePropertyName 'ComputedTier' -NotePropertyValue 'Group 4' -Force
        Add-Member -InputObject $row -NotePropertyName 'RankWithinWorkload' -NotePropertyValue $null -Force
    }
    $all = @($ranked) + @($inactive)
    foreach ($row in $all) {
        Add-Member -InputObject $row -NotePropertyName 'IsOverride'     -NotePropertyValue $false -Force
        Add-Member -InputObject $row -NotePropertyName 'OverrideReason' -NotePropertyValue '' -Force
    }
    return $all
}

function Add-RecentDataEstimate {
    <#
        NEW v3.1.0. Estimates each object's "hot" (recently active) data
        slice - the portion ABR actually recovers first; Mass Recovery
        catches up on the rest afterward. Replaces v3.0.0's Efficiency/
        Get-IndividualRecoveryMinutes/Add-TimeBudgetTiers walk, which used
        each object's FULL size to rank AND tier it - real tenant data
        showed that conflates "how long would recovering EVERYTHING take"
        with "how long until ABR makes this object USABLE again," and a
        single large-but-not-necessarily-more-active object could jump the
        walk straight past an entire group (see chat 2026-07-16, "why is
        group 2 empty").

        Uses REAL telemetry already collected by each workload's usage/
        activity report - no invented numbers: SharePoint's native "Active
        File Count", OneDrive's "Viewed Or Edited File Count" (from the
        activity report), Mailboxes' Send+Receive count (new items
        originated in the report period). The recent item/file count is
        capped at the object's total (a report artifact could otherwise push
        it slightly over), then that fraction is applied proportionally to
        total storage - Graph does not expose a literal byte-level change
        log, so per-object proportional scaling is the closest available
        estimate. See the Methodology tab.

        Tiering itself no longer depends on this - see Add-Tier, now called
        uniformly for all four workloads. This function only feeds
        Build-RecoveryModel's ABR (hot-scope) recovery-time figures.
    #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $Data,
        [Parameter(Mandatory)] [string] $TotalItemField,
        [Parameter(Mandatory)] [string] $TotalStorageField,
        [Parameter(Mandatory)] [string] $RecentItemField
    )
    foreach ($row in $Data) {
        $totalItems   = [double]$row.$TotalItemField
        $totalStorage = [double]$row.$TotalStorageField
        $recentRaw    = [double]$row.$RecentItemField
        $recentItems  = [math]::Max(0.0, [math]::Min($recentRaw, $totalItems))
        $fraction     = if ($totalItems -gt 0) { $recentItems / $totalItems } else { 0.0 }
        $recentStorage = $totalStorage * $fraction
        Add-Member -InputObject $row -NotePropertyName 'RecentItemCount'    -NotePropertyValue $recentItems -Force
        Add-Member -InputObject $row -NotePropertyName 'RecentStorage'      -NotePropertyValue $recentStorage -Force
        Add-Member -InputObject $row -NotePropertyName 'RecentDataFraction' -NotePropertyValue ([math]::Round($fraction, 4)) -Force
    }
    return $Data
}

function Add-BudgetTier {
    <#
        NEW v3.8.0/Phase 2. PowerShell port of the JS engine's
        assignBudgetTiers(), used for Mailboxes/OneDrive/SharePoint instead
        of Add-Tier's fixed equal-thirds split. The two implementations MUST
        stay in lockstep - unlike most PS/JS math in this script (which the
        browser re-derives live from raw metrics regardless of what PS
        computed at generation time), THIS PS-side tier assignment feeds
        Select-PreviewGroup1Rows's strip decision here and the exported
        CSVs/manifest - both would silently drift from what the live report
        ends up showing on load if this algorithm ever diverges from
        assignBudgetTiers(). See the Methodology tab.

        Fills Group 1 with as many top-ranked (by _Score) objects as fit
        inside its own RTO budget (using windowed ABR hot-data figures),
        spills the remainder into Group 2 against its REMAINING (cumulative)
        budget, then Group 3 - advancing to the next tier only ONE STEP per
        object, never skipping a tier in a single step, so a single
        large-but-inactive object can no longer jump the walk past an entire
        group (the v3.0.0 empty-middle-tier failure mode). Group 3 always
        absorbs every remaining active object regardless of fit.

        Reuses Add-RecentDataEstimate's RecentItemCount/RecentStorage
        (already the capped-fraction-of-total hot-data estimate) rather than
        re-deriving it from raw fields - Add-RecentDataEstimate MUST already
        have run on $Data before this is called. WindowFactor applies the
        same 0-7 day scaling the JS Recovery tab/tiering walk uses.
    #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $Data,
        [Parameter(Mandatory)] [string] $InactiveCheckField,
        [Parameter(Mandatory)] [double] $AvgItemSize,
        [hashtable] $SPODTier,
        [Parameter(Mandatory)] [ValidateSet('SP','OD','EX')] [string] $WorkloadType,
        [Parameter(Mandatory)] [double[]] $TargetsMin,
        [Parameter(Mandatory)] [double] $WindowFactor
    )
    $active   = @($Data | Where-Object { [double]$_.$InactiveCheckField -gt 0 })
    $inactive = @($Data | Where-Object { [double]$_.$InactiveCheckField -le 0 })
    $ranked   = @($active | Sort-Object -Property _Score -Descending)

    $tierNames = @('Critical Group 1', 'Critical Group 2', 'Critical Group 3')
    $n = $ranked.Count
    $cursor = 0
    $priorTiersTime = 0.0

    for ($t = 0; $t -lt 3; $t++) {
        $budget = $TargetsMin[$t] - $priorTiersTime
        $cumObjs = 0; $cumItems = 0.0; $cumStorage = 0.0
        while ($cursor -lt $n) {
            $row = $ranked[$cursor]
            $ri = [double]$row.RecentItemCount
            $rs = [double]$row.RecentStorage
            $candObjs = $cumObjs + 1
            $candItems = $cumItems + ($ri * $WindowFactor)
            $candStorage = $cumStorage + ($rs * $WindowFactor)
            $candTime = Get-RecoveryTimeMinutes -WorkloadType $WorkloadType -ObjectCount $candObjs -ItemCount $candItems -StorageAmount $candStorage -AvgItemSize $AvgItemSize -SPODTier $SPODTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $true
            if ($t -lt 2 -and $budget -gt 0 -and $candTime -gt $budget -and $cumObjs -gt 0) {
                break # this tier is full relative to its budget - move to the next tier
            }
            Add-Member -InputObject $row -NotePropertyName 'Tier' -NotePropertyValue $tierNames[$t] -Force
            Add-Member -InputObject $row -NotePropertyName 'ComputedTier' -NotePropertyValue $tierNames[$t] -Force
            Add-Member -InputObject $row -NotePropertyName 'RankWithinWorkload' -NotePropertyValue ($cursor + 1) -Force
            $cumObjs = $candObjs; $cumItems = $candItems; $cumStorage = $candStorage
            $cursor++
            if ($t -lt 2 -and $budget -gt 0 -and $candTime -gt $budget) {
                break # just accepted the one object that alone overflows an empty tier - close it now
            }
        }
        $priorTiersTime += (Get-RecoveryTimeMinutes -WorkloadType $WorkloadType -ObjectCount $cumObjs -ItemCount $cumItems -StorageAmount $cumStorage -AvgItemSize $AvgItemSize -SPODTier $SPODTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $true)
    }

    foreach ($row in $inactive) {
        Add-Member -InputObject $row -NotePropertyName 'Tier' -NotePropertyValue 'Group 4' -Force
        Add-Member -InputObject $row -NotePropertyName 'ComputedTier' -NotePropertyValue 'Group 4' -Force
        Add-Member -InputObject $row -NotePropertyName 'RankWithinWorkload' -NotePropertyValue $null -Force
    }
    $all = @($ranked) + @($inactive)
    foreach ($row in $all) {
        Add-Member -InputObject $row -NotePropertyName 'IsOverride'     -NotePropertyValue $false -Force
        Add-Member -InputObject $row -NotePropertyName 'OverrideReason' -NotePropertyValue '' -Force
    }
    return $all
}

function Import-Overrides {
    <# NEW v2.0.0. Reads a prior export from the HTML report's "Export overrides" button. #>
    param([string]$Path)
    $index = @{}
    if (-not $Path) { return $index }
    if (-not (Test-Path $Path)) {
        Write-Warning "-OverridesFile '$Path' not found - continuing without overrides."
        return $index
    }
    try {
        $items = Get-Content -Path $Path -Raw | ConvertFrom-Json
    }
    catch {
        Write-Warning "-OverridesFile '$Path' could not be parsed as JSON ($($_.Exception.Message)) - continuing without overrides."
        return $index
    }
    foreach ($o in @($items)) {
        if (-not $o.Workload -or -not $o.Identifier) { continue }
        $key = "$($o.Workload)|$($o.Identifier)"
        $index[$key] = $o
    }
    Write-Host "Loaded $($index.Count) manual overrides from $Path" -ForegroundColor Gray
    return $index
}

function Add-Overrides {
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]     $Data,
        [Parameter(Mandatory)] [hashtable] $OverridesIndex,
        [Parameter(Mandatory)] [string]    $Workload
    )
    if (-not $OverridesIndex -or $OverridesIndex.Count -eq 0) { return $Data }
    foreach ($row in $Data) {
        $key = "$Workload|$($row.Identifier)"
        if ($OverridesIndex.ContainsKey($key)) {
            $o = $OverridesIndex[$key]
            $row.Tier = $o.Tier
            $row.IsOverride = $true
            $row.OverrideReason = [string]$o.Reason
        }
    }
    return $Data
}

function Get-TierTotals {
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $Data,
        [string] $ItemField = '',
        [string] $StorageField = ''
    )
    $tiers = @('Critical Group 1','Critical Group 2','Critical Group 3','Group 4')
    foreach ($t in $tiers) {
        $subset = @($Data | Where-Object { $_.Tier -eq $t })
        [PSCustomObject]@{
            Tier         = $t
            ObjectCount  = $subset.Count
            ItemTotal    = if ($ItemField -and $subset.Count -gt 0)    { [double]((($subset | Measure-Object -Property $ItemField -Sum).Sum)) } else { 0 }
            StorageTotal = if ($StorageField -and $subset.Count -gt 0) { [double]((($subset | Measure-Object -Property $StorageField -Sum).Sum)) } else { 0 }
        }
    }
}

#endregion

#region ---------- Recovery time modeling ----------
<#
    Derived from Rubrik's M365 recovery time model.
    Full derivation is in the Methodology tab - summary:

    The source tool computes, for SharePoint/OneDrive/Exchange, an "effective"
    items-per-minute and bytes(or MB)-per-minute throughput, capped by a
    size-tier lookup table (SP/OD) or fixed benchmark constants (EX), then
    Full-restore time = MAX(items / effective items-per-min, storage /
    effective bytes-per-min). We reuse that exact throughput-cap engine, but
    apply it to each CRITICALITY TIER's real object/item/storage totals
    instead of the source model's sampled percentage - because our tiers
    are actual observed criticality groups, not a statistical subset.

    Recovery is modeled as SEQUENTIAL per workload (Group 1 objects recovered
    first, then Group 2, etc.) - this is the entire point of tiering. The
    wall-clock milestone for "Groups 1..N are back" is the MAX across
    SP/OD/EX of each workload's own cumulative sequential time (the overall
    recovery isn't "done" for a milestone until every workload has reached
    it). Total time to recover EVERYTHING is roughly invariant to ordering
    (same total items/bytes over the same capped throughput) - prioritizing
    does not shrink total recovery time, it changes WHEN each tier comes
    back online. That's the entire value case for the cost-of-downtime
    comparison below, and it's called out explicitly in the report so it
    isn't a surprise.
#>

$script:SPODTierTable = @(
    @{ Bucket = '0-1k';    Max = 1000;                       Parallelism = 3  }
    @{ Bucket = '1k-5k';   Max = 5000;                       Parallelism = 6  }
    @{ Bucket = '5k-15k';  Max = 15000;                      Parallelism = 9  }
    @{ Bucket = '15k-50k'; Max = 50000;                      Parallelism = 12 }
    @{ Bucket = '50k+';    Max = $null;                       Parallelism = 15 }
)
# NEW v3.10.0 (Rubrik's M365 recovery time model, superseding the earlier formula). SharePoint and OneDrive now have DIFFERENT
# per-object-of-parallelism item rates (108/168 items/min/unit - 27/42
# files/sec at 15-way parallelism, divided out so lower tiers scale down),
# instead of sharing one ItemsPerMinCap/BytesPerMinCap table. There is no
# separate bytes/min cap anymore for SP/OD - an oversized average item is
# instead penalized via SizeFactor (inflates the EFFECTIVE item count,
# rather than throttling a second, independent byte-rate). See
# Get-RecoveryTimeMinutes and the Methodology tab.
$script:SP_ItemsPerMinPerUnit = 108
$script:OD_ItemsPerMinPerUnit = 168
# A file bigger than this (MiB, org-wide average) costs proportionally more
# than the ~1-API-call baseline; never speeds up below it (factor floors at
# 1x). Assumed, not measured - the pivot for the whole size-factor concept.
$script:SizeFactorBaselineMB = 3
# Job-launch/scheduling overhead: a FIXED per-object cost (every object
# touched by a restore - even one with a single changed item - needs its
# own restore job) modeling 1,000 restore jobs launched/settled in 6 hours.
# Applies to ABR (the source model) recovery time only - a full/
# undifferentiated Mass Recovery restore's scheduling cost is assumed
# absorbed into the throughput figures already, per the source tool.
$script:JobSchedulingRatePerMin = 1000.0 / 360.0
# Reported floor for ABR recovery time only - mirrors the floor RSC-UI
# applies to its own estimated recovery time; a real restore never
# completes in seconds once orchestration/validation are counted. Full/Mass
# Recovery is never small enough for this to bind, so it does not apply
# there. Zero stays zero (e.g. a genuinely empty tier, or
# -RecoveryWindowDays 0) - the floor only lifts a NONZERO time up to a
# minimum, it never manufactures time out of nothing.
$script:MinRecoveryMinutes = 5.0

$script:EXBenchmark = @{
    PerMailboxMBPerMin    = 25
    # NEW v3.10.0: 300 -> 1000 items/min/mailbox.
    PerMailboxItemsPerMin = 1000
    # NEW v3.10.0: unified to a single 700-mailbox parallelism cap for BOTH
    # the bytes and items bound (previously implied two slightly different
    # caps: 700 via MBPerMinCap/PerMailboxMBPerMin, ~766.7 via
    # ItemsPerMinCap/PerMailboxItemsPerMin). Exchange ignores the SP/OD
    # license tier entirely - this cap is tier-independent.
    MaxParallelMailboxes  = 700
    # NEW v3.10.0: +50% overhead/throttling buffer applied to Exchange's
    # transfer time only (not its job-scheduling overhead, for ABR calls).
    OverheadBuffer        = 1.5
}

function Resolve-RecoveryLicenseTier {
    param([string]$Requested, [double]$ObjectScale)
    if ($Requested -ne 'Auto') {
        return ($script:SPODTierTable | Where-Object { $_.Bucket -eq $Requested } | Select-Object -First 1)
    }
    foreach ($t in $script:SPODTierTable) {
        if ($ObjectScale -le $t.Max) { return $t }
    }
    return $script:SPODTierTable[-1]
}

function Get-RecoveryTimeMinutes {
    <#
        Time to recover ONE slice (a tier, a cumulative union of tiers, or an
        entire workload) in isolation.

        v3.10.0: reworked to match Rubrik's M365 recovery time model, superseding the earlier formula. Two structural changes from before:
          1. SharePoint/OneDrive no longer have an independent bytes/min cap
             - an oversized average item now inflates the EFFECTIVE item
             count instead (SizeFactor), and SP/OD each have their OWN
             per-unit-of-parallelism item rate (108 vs 168/min) rather than
             sharing one table. Exchange is unchanged in SHAPE (still a
             bytes-vs-items dual constraint, take the max) but its rates
             changed - see $script:EXBenchmark above.
          2. -IncludeOverhead adds a fixed per-object job-scheduling cost
             (every object touched needs its own restore job, regardless of
             how much of it changed) plus a 5-minute floor - this is what
             ABR (the source model) actually costs on top of raw
             transfer time. A full/undifferentiated Mass Recovery restore
             has neither - pass $false for those calls.

        AvgItemSize must be computed ONCE from the workload's FULL dataset
        (bytes/item for SP/OD; unused for EX, which no longer has a
        size-dependent rate) and reused for every slice, matching the source
        tool's own methodology.
    #>
    param(
        [Parameter(Mandatory)] [ValidateSet('SP','OD','EX')] [string] $WorkloadType,
        [Parameter(Mandatory)] [double] $ObjectCount,
        [Parameter(Mandatory)] [double] $ItemCount,
        [Parameter(Mandatory)] [double] $StorageAmount,
        [Parameter(Mandatory)] [double] $AvgItemSize,
        [hashtable] $SPODTier,
        [hashtable] $EXBenchmark,
        # NEW v3.10.0: true for ABR (adds job-scheduling overhead + the
        # 5-minute floor); false for Mass Recovery/Full (raw transfer time
        # only) - see header comment.
        [bool] $IncludeOverhead = $false
    )

    if ($WorkloadType -in @('SP', 'OD')) {
        if ($ObjectCount -le 0) { return 0.0 }
        $perUnitRate = if ($WorkloadType -eq 'SP') { $script:SP_ItemsPerMinPerUnit } else { $script:OD_ItemsPerMinPerUnit }
        $ipm = [math]::Min($ObjectCount, $SPODTier.Parallelism) * $perUnitRate
        $avgFileMb = $AvgItemSize / (1024 * 1024)
        $sizeFactor = if ($avgFileMb -gt 0) { [math]::Max(1.0, $avgFileMb / $script:SizeFactorBaselineMB) } else { 1.0 }
        $effItems = $ItemCount * $sizeFactor
        $transferMin = if ($effItems -gt 0 -and $ipm -gt 0) { $effItems / $ipm } else { 0.0 }
    }
    else {
        if ($ObjectCount -le 0) { return 0.0 }
        $mbRate = [math]::Min($ObjectCount, $EXBenchmark.MaxParallelMailboxes) * $EXBenchmark.PerMailboxMBPerMin
        $itemsRate = [math]::Min($ObjectCount, $EXBenchmark.MaxParallelMailboxes) * $EXBenchmark.PerMailboxItemsPerMin
        $timeByBytes = if ($StorageAmount -gt 0 -and $mbRate -gt 0) { $StorageAmount / $mbRate } else { 0.0 }
        $timeByItems = if ($ItemCount -gt 0 -and $itemsRate -gt 0) { $ItemCount / $itemsRate } else { 0.0 }
        $transferMin = [math]::Max($timeByBytes, $timeByItems) * $EXBenchmark.OverheadBuffer
    }

    if (-not $IncludeOverhead) { return $transferMin }
    $schedMin = $ObjectCount / $script:JobSchedulingRatePerMin
    $total = $transferMin + $schedMin
    if ($total -gt 0) { return [math]::Max($total, $script:MinRecoveryMinutes) }
    return 0.0
}

function Build-RecoveryModel {
    <#
        Builds the full per-tier / cumulative / full-restore recovery-time
        (minutes) and object/item/storage totals structure that gets embedded
        in the report for the JS Recovery tab to render and recompute live.
        Returns a hashtable keyed by workload type (SP/OD/EX) plus a
        'Cumulative' summary (MAX across workloads at each milestone).

        v3.1.0: "ABR" per-tier/cumulative time (TimeMin/CumulativeMin/
        WallClockCumulativeMin) is now computed from each tier's RECENT/hot
        data slice (RecentItemCount/RecentStorage, from Add-RecentDataEstimate)
        instead of its full data - this is what ABR actually restores first.
        "Mass Recovery" (MassTimeMin/MassRecoveryCumulativeMin) is UNCHANGED -
        still the full-data cumulative-batch figure, since Mass Recovery has
        no hot/cold distinction. There is no more "Beyond Target" tier;
        instead each of Group 1/2/3 gets an ExceedsTarget/TargetGapMin flag
        (see the loop after $tierOrder below) comparing its own ABR
        cumulative time against the corresponding entry in $TargetsMin.
    #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $SharePoint,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $OneDrive,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Mailboxes,
        [Parameter(Mandatory)] [string] $RecoveryLicenseTier,
        # NEW v3.1.0: Group 1/2/3 RTO targets in minutes, used to flag
        # ExceedsTarget/TargetGapMin per group (a compliance check, not a
        # tiering rule - see header comment above).
        [double[]] $TargetsMin = @(0.0, 0.0, 0.0),
        # NEW: 0-7, matching ABR's actual recovery capability. RecentItemCount/
        # RecentStorage (from Add-RecentDataEstimate) are always real D7
        # figures; this linearly scales them down for a shorter window - same
        # math as the live report's JS (computeRecoveryModel). This console
        # summary is a point-in-time snapshot at whatever value was passed at
        # generation time - the live report's own slider is what's actually
        # live-adjustable. See the Methodology tab.
        [double] $RecoveryWindowDays = 7
    )
    $windowFactor = [math]::Max(0, [math]::Min(7, $RecoveryWindowDays)) / 7

    $tierOrder = @('Critical Group 1','Critical Group 2','Critical Group 3','Group 4')

    $spTotalItems = Get-FieldSum $SharePoint 'FileCount'
    $spTotalBytes = Get-FieldSum $SharePoint 'StorageBytes'
    $spAvgItemSize = if ($spTotalItems -gt 0) { $spTotalBytes / $spTotalItems } else { 0 }

    $odTotalItems = Get-FieldSum $OneDrive 'FileCount'
    $odTotalBytes = Get-FieldSum $OneDrive 'StorageBytes'
    $odAvgItemSize = if ($odTotalItems -gt 0) { $odTotalBytes / $odTotalItems } else { 0 }

    $exTotalItems = Get-FieldSum $Mailboxes 'ItemCount'
    $exTotalMB    = Get-FieldSum $Mailboxes 'StorageUsedMB'
    $exAvgItemSize = if ($exTotalItems -gt 0) { $exTotalMB / $exTotalItems } else { 0 }

    $scale = [math]::Max($SharePoint.Count, $OneDrive.Count)
    $spodTier = Resolve-RecoveryLicenseTier -Requested $RecoveryLicenseTier -ObjectScale $scale

    # NEW v3.1.0: also sums each tier's RECENT (hot) item/storage totals -
    # RecentItemCount/RecentStorage, attached per-object by
    # Add-RecentDataEstimate - alongside the full totals.
    function local:TierSlice($rows, $itemField, $storageField, $tierName) {
        $subset = @($rows | Where-Object { $_.Tier -eq $tierName })
        [PSCustomObject]@{
            ObjectCount     = $subset.Count
            ItemCount       = (Get-FieldSum $subset $itemField)
            Storage         = (Get-FieldSum $subset $storageField)
            RecentItemCount = (Get-FieldSum $subset 'RecentItemCount') * $windowFactor
            RecentStorage   = (Get-FieldSum $subset 'RecentStorage') * $windowFactor
        }
    }

    $result = @{ SP = @{}; OD = @{}; EX = @{}; Meta = @{
        SPODTierBucket = $spodTier.Bucket
        SPAvgItemSizeBytes = $spAvgItemSize
        ODAvgItemSizeBytes = $odAvgItemSize
        EXAvgItemSizeMB    = $exAvgItemSize
    } }

    $cumSP = 0.0; $cumOD = 0.0; $cumEX = 0.0
    # NEW: running cumulative object/item/storage totals per workload, for
    # the Mass Recovery comparison. Mass Recovery "through tier N" = the
    # throughput formula applied ONCE to tiers 1..N's COMBINED FULL totals
    # (one undifferentiated batch of that same cumulative scope), NOT the
    # whole tenant - must scale with each group's size, converging with the
    # full-tenant figure only at the final (Dormant) milestone.
    $cumSPObjs = 0; $cumSPItems = 0.0; $cumSPStorage = 0.0
    $cumODObjs = 0; $cumODItems = 0.0; $cumODStorage = 0.0
    $cumEXObjs = 0; $cumEXItems = 0.0; $cumEXStorage = 0.0
    $milestones = [ordered]@{}
    $prevWall = 0.0
    foreach ($tierName in $tierOrder) {
        $spSlice = TierSlice $SharePoint 'FileCount' 'StorageBytes' $tierName
        $odSlice = TierSlice $OneDrive   'FileCount' 'StorageBytes' $tierName
        $exSlice = TierSlice $Mailboxes  'ItemCount'  'StorageUsedMB' $tierName

        # ABR time: this tier's own RECENT/hot slice, using the SAME
        # dataset-wide avg item size (a rate, not an absolute) as every other
        # figure - see Get-RecoveryTimeMinutes header.
        $spTime = Get-RecoveryTimeMinutes -WorkloadType SP -ObjectCount $spSlice.ObjectCount -ItemCount $spSlice.RecentItemCount -StorageAmount $spSlice.RecentStorage -AvgItemSize $spAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $true
        $odTime = Get-RecoveryTimeMinutes -WorkloadType OD -ObjectCount $odSlice.ObjectCount -ItemCount $odSlice.RecentItemCount -StorageAmount $odSlice.RecentStorage -AvgItemSize $odAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $true
        $exTime = Get-RecoveryTimeMinutes -WorkloadType EX -ObjectCount $exSlice.ObjectCount -ItemCount $exSlice.RecentItemCount -StorageAmount $exSlice.RecentStorage -AvgItemSize $exAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $true

        $cumSP += $spTime; $cumOD += $odTime; $cumEX += $exTime

        $cumSPObjs += $spSlice.ObjectCount; $cumSPItems += $spSlice.ItemCount; $cumSPStorage += $spSlice.Storage
        $cumODObjs += $odSlice.ObjectCount; $cumODItems += $odSlice.ItemCount; $cumODStorage += $odSlice.Storage
        $cumEXObjs += $exSlice.ObjectCount; $cumEXItems += $exSlice.ItemCount; $cumEXStorage += $exSlice.Storage

        # Mass Recovery: UNCHANGED - full-data cumulative-batch figure.
        $massSPTime = Get-RecoveryTimeMinutes -WorkloadType SP -ObjectCount $cumSPObjs -ItemCount $cumSPItems -StorageAmount $cumSPStorage -AvgItemSize $spAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $false
        $massODTime = Get-RecoveryTimeMinutes -WorkloadType OD -ObjectCount $cumODObjs -ItemCount $cumODItems -StorageAmount $cumODStorage -AvgItemSize $odAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $false
        $massEXTime = Get-RecoveryTimeMinutes -WorkloadType EX -ObjectCount $cumEXObjs -ItemCount $cumEXItems -StorageAmount $cumEXStorage -AvgItemSize $exAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $false
        $massCumMin = [math]::Max([math]::Max($massSPTime,$massODTime),$massEXTime)

        # v3.16.0: cap ABR at Mass for the SAME scope; keep monotonic.
        $abrRawCum    = [math]::Max([math]::Max($cumSP,$cumOD),$cumEX)
        $cappedByMass = ($abrRawCum -gt $massCumMin)
        $cappedWall   = [math]::Max($prevWall, [math]::Min($abrRawCum, $massCumMin))
        $prevWall     = $cappedWall

        $milestones[$tierName] = [ordered]@{
            SP = [ordered]@{ ObjectCount = $spSlice.ObjectCount; ItemCount = $spSlice.ItemCount; Storage = $spSlice.Storage; TimeMin = [math]::Round($spTime,2); CumulativeMin = [math]::Round($cumSP,2); MassTimeMin = [math]::Round($massSPTime,2) }
            OD = [ordered]@{ ObjectCount = $odSlice.ObjectCount; ItemCount = $odSlice.ItemCount; Storage = $odSlice.Storage; TimeMin = [math]::Round($odTime,2); CumulativeMin = [math]::Round($cumOD,2); MassTimeMin = [math]::Round($massODTime,2) }
            EX = [ordered]@{ ObjectCount = $exSlice.ObjectCount; ItemCount = $exSlice.ItemCount; Storage = $exSlice.Storage; TimeMin = [math]::Round($exTime,2); CumulativeMin = [math]::Round($cumEX,2); MassTimeMin = [math]::Round($massEXTime,2) }
            WallClockCumulativeMin = [math]::Round($cappedWall, 2)
            AbrRawCumulativeMin = [math]::Round($abrRawCum, 2)
            CappedByMass = $cappedByMass
            MassRecoveryCumulativeMin = [math]::Round($massCumMin, 2)
            ExceedsTarget = $false
            TargetGapMin  = 0.0
        }
    }

    # NEW v3.1.0: per-group RTO compliance flag, replacing the old "Beyond
    # Target" tier. Each of Group 1/2/3's own ABR (hot-scope) cumulative time
    # is checked against the corresponding target - if it runs over, flag it
    # in place rather than exiling the object(s) responsible to a 5th tier.
    $groupTierNames = @('Critical Group 1','Critical Group 2','Critical Group 3')
    for ($gi = 0; $gi -lt $groupTierNames.Count; $gi++) {
        $m = $milestones[$groupTierNames[$gi]]
        $target = $TargetsMin[$gi]
        if ($target -gt 0 -and $m.WallClockCumulativeMin -gt $target) {
            $m.ExceedsTarget = $true
            $m.TargetGapMin  = [math]::Round($m.WallClockCumulativeMin - $target, 2)
        }
    }

    $fullSPTime = Get-RecoveryTimeMinutes -WorkloadType SP -ObjectCount $SharePoint.Count -ItemCount $spTotalItems -StorageAmount $spTotalBytes -AvgItemSize $spAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $false
    $fullODTime = Get-RecoveryTimeMinutes -WorkloadType OD -ObjectCount $OneDrive.Count -ItemCount $odTotalItems -StorageAmount $odTotalBytes -AvgItemSize $odAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $false
    $fullEXTime = Get-RecoveryTimeMinutes -WorkloadType EX -ObjectCount $Mailboxes.Count -ItemCount $exTotalItems -StorageAmount $exTotalMB -AvgItemSize $exAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $false

    $result.Milestones = $milestones
    $result.FullRestoreUnprioritizedMin = [math]::Round([math]::Max([math]::Max($fullSPTime,$fullODTime),$fullEXTime), 2)
    # "Mass Recovery" (undifferentiated, no prioritization) has no concept of
    # a per-group subset - it always operates on the whole dataset. Aliased
    # explicitly here so callers don't have to know that reuse is deliberate.
    $result.MassRecoveryUnprioritizedMin = $result.FullRestoreUnprioritizedMin
    return $result
}

function Get-FullTenantRecoveryEstimate {
    <#
        NEW v3.0.0. Early, pre-scoring "how big is this tenant, recovery-wise"
        estimate - the max across SP/OD/EX of Get-RecoveryTimeMinutes applied
        to each workload's ENTIRE raw dataset. Reuses the exact same
        avg-item-size / SPOD-tier-bucket logic as Build-RecoveryModel (same
        formula, just invoked once, early, before any scoring/tiering has
        happened) - used to drive -RTOPreset Auto's Standard-vs-Enterprise
        suggestion. Deliberately factored out of Build-RecoveryModel so there
        is exactly one implementation of "full dataset as one batch," not two
        that could quietly diverge.
    #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $SharePoint,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $OneDrive,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $Mailboxes,
        [Parameter(Mandatory)] [string] $RecoveryLicenseTier
    )

    $spTotalItems = Get-FieldSum $SharePoint 'FileCount'
    $spTotalBytes = Get-FieldSum $SharePoint 'StorageBytes'
    $spAvgItemSize = if ($spTotalItems -gt 0) { $spTotalBytes / $spTotalItems } else { 0 }

    $odTotalItems = Get-FieldSum $OneDrive 'FileCount'
    $odTotalBytes = Get-FieldSum $OneDrive 'StorageBytes'
    $odAvgItemSize = if ($odTotalItems -gt 0) { $odTotalBytes / $odTotalItems } else { 0 }

    $exTotalItems = Get-FieldSum $Mailboxes 'ItemCount'
    $exTotalMB    = Get-FieldSum $Mailboxes 'StorageUsedMB'
    $exAvgItemSize = if ($exTotalItems -gt 0) { $exTotalMB / $exTotalItems } else { 0 }

    $scale = [math]::Max($SharePoint.Count, $OneDrive.Count)
    $spodTier = Resolve-RecoveryLicenseTier -Requested $RecoveryLicenseTier -ObjectScale $scale

    $fullSPTime = Get-RecoveryTimeMinutes -WorkloadType SP -ObjectCount $SharePoint.Count -ItemCount $spTotalItems -StorageAmount $spTotalBytes -AvgItemSize $spAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $false
    $fullODTime = Get-RecoveryTimeMinutes -WorkloadType OD -ObjectCount $OneDrive.Count   -ItemCount $odTotalItems -StorageAmount $odTotalBytes -AvgItemSize $odAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $false
    $fullEXTime = Get-RecoveryTimeMinutes -WorkloadType EX -ObjectCount $Mailboxes.Count  -ItemCount $exTotalItems -StorageAmount $exTotalMB    -AvgItemSize $exAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $false

    return [math]::Max([math]::Max($fullSPTime,$fullODTime),$fullEXTime)
}

function Get-WholeTenantABRMinutes {
    <#
        NEW v3.10.0. Early, pre-scoring "if literally EVERY active object of
        ONE workload were dumped into Group 1 together, how long would ABR
        take" estimate, taken as the MINIMUM across SharePoint/OneDrive/
        Mailboxes (ignoring any workload with zero active objects) - i.e.
        the workload whose entire active population is EASIEST to swallow
        whole. Used ONLY to detect a degenerate -RTOPreset Auto suggestion:
        a tenant can have a huge FULL-data recovery estimate (driving
        Get-FullTenantRecoveryEstimate toward Enterprise) while one or more
        of its workloads' ABR/hot-data footprints are tiny - in which case
        Enterprise's generous Group 1 budget swallows that workload's ENTIRE
        active population, leaving ITS Group 2/3 empty and defeating the
        whole point of showing a criticality-tiered recovery for that
        workload (see "Why the walk-forward approach was replaced" /
        "Budget-constrained tiering" in the Methodology tab for
        the underlying tiering mechanism this is protecting the USEFULNESS
        of, not its correctness).

        Deliberately MIN, not MAX: taking the max across workloads only
        flags a degenerate spread when EVERY workload collapses into Group 1
        at once, which under the v3.10.0 formula's per-object job-scheduling
        overhead is rare (mailbox counts alone can push EX past budget even
        with near-zero data - see Get-RecoveryTimeMinutes). SharePoint/
        OneDrive can still independently degenerate while EX does not; MIN
        catches that case (confirmed against real demo data: Enterprise's
        24h/1440min Group 1 budget comfortably contains SharePoint's and
        OneDrive's entire active populations - ~687 min and ~1378 min
        respectively - while Mailboxes' does not, at ~1855 min; MAX would
        have wrongly reported "not degenerate").

        Deliberately does NOT require per-object composite scores or tiers
        (neither exists yet this early in the pipeline) - aggregates each
        object's own capped recent-item/storage fraction directly, the same
        per-object math as Add-RecentDataEstimate, without mutating the raw
        rows or requiring the full processing pipeline to have run yet.
        Excludes dormant objects (TotalActivity <= 0), matching what the
        real budget walk excludes from its active population.
    #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $SharePoint,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $OneDrive,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $Mailboxes,
        [Parameter(Mandatory)] [string] $RecoveryLicenseTier,
        [Parameter(Mandatory)] [double] $WindowFactor
    )

    function local:AggregateRecent {
        param($Rows, [string]$TotalItemField, [string]$TotalStorageField, [string]$RecentItemField)
        $active = @($Rows | Where-Object { [double]$_.TotalActivity -gt 0 })
        $totalItems = 0.0; $totalStorage = 0.0; $recentItems = 0.0; $recentStorage = 0.0
        foreach ($row in $active) {
            $ti = [double]$row.$TotalItemField
            $ts = [double]$row.$TotalStorageField
            $rr = [double]$row.$RecentItemField
            $ri = [math]::Max(0.0, [math]::Min($rr, $ti))
            $frac = if ($ti -gt 0) { $ri / $ti } else { 0.0 }
            $totalItems += $ti; $totalStorage += $ts
            $recentItems += $ri; $recentStorage += ($ts * $frac)
        }
        [PSCustomObject]@{ ActiveCount = $active.Count; TotalItems = $totalItems; TotalStorage = $totalStorage; RecentItems = $recentItems; RecentStorage = $recentStorage }
    }

    $spAgg = AggregateRecent -Rows $SharePoint -TotalItemField 'FileCount' -TotalStorageField 'StorageBytes' -RecentItemField 'ActiveFiles7d'
    $odAgg = AggregateRecent -Rows $OneDrive   -TotalItemField 'FileCount' -TotalStorageField 'StorageBytes' -RecentItemField 'ViewedOrEditedCount7d'
    $exAgg = AggregateRecent -Rows $Mailboxes  -TotalItemField 'ItemCount' -TotalStorageField 'StorageUsedMB' -RecentItemField 'SendRecvActivity7d'

    $spAvgItemSize = if ($spAgg.TotalItems -gt 0) { $spAgg.TotalStorage / $spAgg.TotalItems } else { 0 }
    $odAvgItemSize = if ($odAgg.TotalItems -gt 0) { $odAgg.TotalStorage / $odAgg.TotalItems } else { 0 }
    $exAvgItemSize = if ($exAgg.TotalItems -gt 0) { $exAgg.TotalStorage / $exAgg.TotalItems } else { 0 }

    $scale = [math]::Max($SharePoint.Count, $OneDrive.Count)
    $spodTier = Resolve-RecoveryLicenseTier -Requested $RecoveryLicenseTier -ObjectScale $scale

    $spTime = Get-RecoveryTimeMinutes -WorkloadType SP -ObjectCount $spAgg.ActiveCount -ItemCount ($spAgg.RecentItems * $WindowFactor) -StorageAmount ($spAgg.RecentStorage * $WindowFactor) -AvgItemSize $spAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $true
    $odTime = Get-RecoveryTimeMinutes -WorkloadType OD -ObjectCount $odAgg.ActiveCount -ItemCount ($odAgg.RecentItems * $WindowFactor) -StorageAmount ($odAgg.RecentStorage * $WindowFactor) -AvgItemSize $odAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $true
    $exTime = Get-RecoveryTimeMinutes -WorkloadType EX -ObjectCount $exAgg.ActiveCount -ItemCount ($exAgg.RecentItems * $WindowFactor) -StorageAmount ($exAgg.RecentStorage * $WindowFactor) -AvgItemSize $exAvgItemSize -SPODTier $spodTier -EXBenchmark $script:EXBenchmark -IncludeOverhead $true

    # Only consider workloads that actually HAVE active objects - a workload
    # with zero active objects returns 0 from Get-RecoveryTimeMinutes and
    # must not be mistaken for a degenerate (trivially-fast) spread.
    $candidateTimes = [System.Collections.Generic.List[double]]::new()
    if ($spAgg.ActiveCount -gt 0) { $candidateTimes.Add($spTime) }
    if ($odAgg.ActiveCount -gt 0) { $candidateTimes.Add($odTime) }
    if ($exAgg.ActiveCount -gt 0) { $candidateTimes.Add($exTime) }
    if ($candidateTimes.Count -eq 0) { return [double]::PositiveInfinity }

    $minTime = $candidateTimes[0]
    foreach ($t in $candidateTimes) { if ($t -lt $minTime) { $minTime = $t } }
    return $minTime
}

#endregion

#region ---------- Helpers: download wrapper, export ----------

#region ---------- Offline mode (-OfflinePath) ----------
# Customers whose security team won't approve a live run export the usage
# reports from the Microsoft 365 admin center into one folder. With
# -OfflinePath the script never connects to Graph/Exchange: Get-GraphReport
# reads the exported CSV (same columns as the Graph report) instead of
# downloading it. Files are named like the raw_*.csv work files without the
# "raw_" prefix, e.g. mailbox_usage.csv, email_activity_7d.csv.
$script:Offline = [bool]$OfflinePath
$script:OfflinePath = $OfflinePath
$script:OfflineMissing = [System.Collections.Generic.List[string]]::new()
$script:OfflineBad = [System.Collections.Generic.List[string]]::new()

$script:OfflineInputs = @(
    @{ File = 'mailbox_usage.csv'; Key = 'User Principal Name';        Label = 'Mailbox usage (long period)';       Required = $true;  Days = 'Period' },
    @{ File = 'email_activity.csv'; Key = 'User Principal Name';       Label = 'Email activity (long period)';      Required = $true;  Days = 'Period' },
    @{ File = 'email_activity_7d.csv'; Key = 'User Principal Name';    Label = 'Email activity (7 days)';           Required = $true;  Days = 7 },
    @{ File = 'onedrive_usage.csv'; Key = 'Owner Principal Name';       Label = 'OneDrive usage (long period)';      Required = $true;  Days = 'Period' },
    @{ File = 'onedrive_activity.csv'; Key = 'User Principal Name';    Label = 'OneDrive activity (long period)';   Required = $true;  Days = 'Period' },
    @{ File = 'onedrive_activity_7d.csv'; Key = 'User Principal Name'; Label = 'OneDrive activity (7 days)';        Required = $true;  Days = 7 },
    @{ File = 'sharepoint_usage.csv'; Key = 'Site URL';     Label = 'SharePoint site usage (long period)'; Required = $true; Days = 'Period' },
    @{ File = 'sharepoint_usage_7d.csv'; Key = 'Site URL';  Label = 'SharePoint site usage (7 days)';    Required = $true;  Days = 7 },
    @{ File = 'teams_team_activity.csv'; Key = 'Team Id';  Label = 'Teams team activity (long period)'; Required = $false; Days = 'Period' }
)

function Test-OfflineInputs {
    param([string]$Path, [string]$Period)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "-OfflinePath '$Path' is not a folder that exists." }
    $expectedLong = [int]($Period -replace '[^0-9]', '')
    Write-Host "`n--- Offline mode: checking exported reports in $Path ---" -ForegroundColor Yellow
    $missingRequired = @()
    foreach ($in in $script:OfflineInputs) {
        $f = Join-Path $Path $in.File
        if (-not (Test-Path -LiteralPath $f) -or (Get-Item -LiteralPath $f).Length -eq 0) {
            $tag = if ($in.Required) { 'MISSING (required)' } else { 'missing (optional)' }
            Write-Host ("  {0,-38} {1}" -f $in.Label, $tag) -ForegroundColor $(if ($in.Required) { 'Red' } else { 'DarkYellow' })
            if ($in.Required) { $missingRequired += $in.File } else { $script:OfflineMissing.Add($in.File) }
            continue
        }
        # Wrong-export guard: every report must contain its key column (e.g. the Teams
        # chart export has only daily team counts, not one row per team).
        try {
            $h = (Get-Content -LiteralPath $f -TotalCount 1 -ErrorAction Stop) -replace '^\xEF\xBB\xBF|^\uFEFF', ''
            $cols = @($h -split ',') | ForEach-Object { $_.Trim().Trim('"') }
        } catch { $cols = @() }
        if ($cols -notcontains $in.Key) {
            $why = "wrong export - no '$($in.Key)' column (found: $((@($cols) | Select-Object -First 6) -join ', '))"
            Write-Host ("  {0,-38} NOT USABLE: {1}" -f $in.Label, $why) -ForegroundColor $(if ($in.Required) { 'Red' } else { 'DarkYellow' })
            if ($in.Required) { $missingRequired += "$($in.File) ($why)" } else { $script:OfflineMissing.Add($in.File); $script:OfflineBad.Add($in.File) }
            continue
        }
        $sizeKb = [math]::Round((Get-Item -LiteralPath $f).Length / 1KB)
        $note = ''
        try {
            $hdr = Get-Content -LiteralPath $f -TotalCount 2 -ErrorAction Stop
            if ($hdr.Count -ge 2) {
                $first = $hdr | ConvertFrom-Csv
                $rp = $first.'Report Period'
                $want = if ($in.Days -eq 'Period') { $expectedLong } else { [int]$in.Days }
                if ($rp -and ([int]$rp) -ne $want) {
                    $note = " WARNING: file is a $rp-day export, expected $want"
                    Write-Warning "$($in.File) looks like a $rp-day export but $want days is expected. Re-export it with the right period or results will be skewed."
                }
            }
        } catch { }
        Write-Host ("  {0,-38} found ({1:N0} KB){2}" -f $in.Label, $sizeKb, $note) -ForegroundColor Gray
    }
    if ($missingRequired.Count -gt 0) {
        throw ("Offline mode cannot continue - required export(s) missing from '{0}': {1}. See the 'Running offline' section of the README for where to find each report. (The 7-day files drive the recent-data/ABR recovery estimate and cannot be substituted.)" -f $Path, ($missingRequired -join ', '))
    }
    Write-Host "Offline mode: no sign-in, no Graph or Exchange connection will be made. Profile enrichment, Entra groups, Exact Team-site mapping and Detailed Sizing are not available." -ForegroundColor Magenta
}

function Import-OfflineReport {
    param([string]$Label, [string]$OutFile)
    $leaf = (Split-Path $OutFile -Leaf) -replace '^raw_', ''
    $src = Join-Path $script:OfflinePath $leaf
    if (($script:OfflineBad -notcontains $leaf) -and (Test-Path -LiteralPath $src) -and (Get-Item -LiteralPath $src).Length -gt 0) {
        Copy-Item -LiteralPath $src -Destination $OutFile -Force
        return
    }
    # Optional report not supplied: header-only file so the importer yields zero rows.
    Set-Content -Path $OutFile -Value 'Report Refresh Date,Report Period' -Encoding UTF8
}

function Get-SignedInAccount {
    if ($script:Offline) { return 'Offline (exported admin center reports)' }
    return (Get-MgContext).Account
}
#endregion

function Get-GraphReport {
    <#
        NEW v3.7.1: actually implements the fix the comment above
        $ProgressPreference always pointed at but never built - confirmed
        2026-07-31 against a live tenant that a failed SharePoint site usage
        pull (this exact wrapper threw "did not produce a file") was
        immediately reproducible-but-harmless when re-run manually: the
        known PercentComplete overflow bug fired (non-terminating, but
        $ErrorActionPreference = 'Stop' above turns it terminating), YET the
        file still landed on disk complete and valid (39,903 bytes). Blindly
        redirecting stderr (`2>$null`, the old approach) doesn't help here -
        a terminating exception isn't stream output, so it was never
        actually being caught by that redirect; this run's failure was
        something else. Two independent problems, one fix:
          1. Catch the download call. If a file still landed with real
             content, treat it as success regardless of what the exception
             said - the PercentComplete bug is real but purely cosmetic.
          2. If no valid file landed, retry a few times with a short delay -
             large tenants (thousands of SharePoint sites in particular)
             can hit transient "report still generating" gaps in the Graph
             Reports API that a bare retry clears on its own, as seen here.
        Only after retries are exhausted does this throw - and now with the
        actual last error attached, instead of a guess.
    #>
    param(
        [Parameter(Mandatory)] [scriptblock] $Download,
        [Parameter(Mandatory)] [string] $OutFile,
        [Parameter(Mandatory)] [string] $Label,
        [int] $MaxAttempts = 3,
        [int] $RetryDelaySeconds = 10
    )
    if ($script:Offline) { Import-OfflineReport -Label $Label -OutFile $OutFile; return }
    $lastError = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $lastError = $null
        try {
            & $Download
        } catch {
            $lastError = $_
        }
        if ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0) {
            if ($lastError) {
                Write-Host ("  (${Label}: file downloaded fine despite a cosmetic progress-bar error - continuing)") -ForegroundColor DarkGray
            }
            return
        }
        if ($attempt -lt $MaxAttempts) {
            $why = if ($lastError) { $lastError.Exception.Message } else { 'no error thrown, but no file (or an empty file) resulted' }
            Write-Warning "$Label - attempt $attempt of $MaxAttempts produced no usable file ($why). Retrying in $RetryDelaySeconds sec..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    $detail = if ($lastError) { " Last error: $($lastError.Exception.Message)" } else { ' No exception was thrown on the last attempt, but no usable file resulted.' }
    throw "$Label - report download did not produce a file at '$OutFile' after $MaxAttempts attempt(s).$detail Check the Reports Reader role, granted scopes, and licensing for this workload."
}

function Export-WorkloadResult {
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Data,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $OutDir
    )
    $path = Join-Path $OutDir "$Name.csv"
    if ($Data.Count -eq 0) {
        Write-Warning "$Name - no rows returned."
        return $null
    }
    $Data | Sort-Object -Property Tier, RankWithinWorkload | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Host ("{0,-24} {1,5} objects  ->  {2}" -f $Name, $Data.Count, $path) -ForegroundColor Gray
    return $path
}

# v2.0 PREVIEW build only: generation-time STRIPPING (replaces the 3.x redaction approach). Everything
# the Preview report, CSVs, _ReportData.json and manifest ship is limited to Critical Group 1 rows; Groups
# 2/3/4 rows are dropped from the data BEFORE anything is written, so nothing about them (identity, scores,
# storage, timing) can be recovered from page source or dev tools. The whole-tenant context the report
# needs (Mass Recovery baseline, sizing, tenant totals) is computed from the full row set first and shipped
# as aggregates only - see Get-ReportTenantTotals / Get-ReportSizingAgg.
function Select-PreviewGroup1Rows {
    param([AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Data)
    return @($Data | Where-Object { $_.Tier -eq 'Critical Group 1' })
}

#endregion

#region ---------- Workload collectors ----------

function Get-MailboxCriticality {
    param([string]$Period, [string]$WorkDir)

    $usageFile    = Join-Path $WorkDir 'raw_mailbox_usage.csv'
    $activityFile = Join-Path $WorkDir 'raw_email_activity.csv'
    # NEW: ABR (Autonomous Business Recovery) can only ever recover the last
    # 7 days of activity - that's a fixed product capability, not something
    # -Period should influence. So the "how much does ABR actually have to
    # recover" signal always pulls its OWN D7 activity report, completely
    # independent of whatever -Period the customer chose for scoring/
    # dormancy detection above. This is a second report pull (Graph reports
    # are tenant-wide per call, no way to scope by object), not a re-slice of
    # the $Period pull. See the Methodology tab.
    $activity7dFile = Join-Path $WorkDir 'raw_email_activity_7d.csv'

    Get-GraphReport -Label 'Mailbox usage' -OutFile $usageFile -Download { Get-MgReportMailboxUsageDetail -Period $Period -OutFile $usageFile -ErrorAction SilentlyContinue }
    Get-GraphReport -Label 'Email activity' -OutFile $activityFile -Download { Get-MgReportEmailActivityUserDetail -Period $Period -OutFile $activityFile -ErrorAction SilentlyContinue }
    Get-GraphReport -Label 'Email activity (7-day, ABR)' -OutFile $activity7dFile -Download { Get-MgReportEmailActivityUserDetail -Period 'D7' -OutFile $activity7dFile -ErrorAction SilentlyContinue }

    $usage = Import-Csv $usageFile
    $activityIndex = @{}
    foreach ($a in (Import-Csv $activityFile)) {
        $upn = Get-ColumnValue $a @('User Principal Name') ''
        if ($upn) { $activityIndex[$upn] = $a }
    }
    $activity7dIndex = @{}
    foreach ($a in (Import-Csv $activity7dFile)) {
        $upn = Get-ColumnValue $a @('User Principal Name') ''
        if ($upn) { $activity7dIndex[$upn] = $a }
    }

    $rows = foreach ($u in $usage) {
        $upn = Get-ColumnValue $u @('User Principal Name') ''
        if (-not $upn) { continue }
        $act = $activityIndex[$upn]
        $act7d = $activity7dIndex[$upn]

        $sendCount    = if ($act) { [double](Get-ColumnValue $act @('Send Count') 0) } else { 0 }
        $receiveCount = if ($act) { [double](Get-ColumnValue $act @('Receive Count') 0) } else { 0 }
        $readCount    = if ($act) { [double](Get-ColumnValue $act @('Read Count') 0) } else { 0 }
        $sendCount7d    = if ($act7d) { [double](Get-ColumnValue $act7d @('Send Count') 0) } else { 0 }
        $receiveCount7d = if ($act7d) { [double](Get-ColumnValue $act7d @('Receive Count') 0) } else { 0 }
        $itemCount    = [double](Get-ColumnValue $u @('Item Count') 0)
        $storageBytes = [double](Get-ColumnValue $u @('Storage Used (Byte)', 'Storage Used (Bytes)') 0)
        # NEW v3.0.0: real Exchange recipient type, straight from the mailbox
        # usage report - already pulled with no extra scope needed.
        # Authoritative signal for Add-MailboxTypeHeuristic (replaces the old
        # AccountEnabled proxy - see that function's header for why).
        $recipientType = Get-ColumnValue $u @('Recipient Type') ''
        # NEW: "Has Archive" - straight from the SAME mailbox usage report
        # (getMailboxUsageDetail), no extra scope/module. This is the free
        # half of the Sizing tab's Archive Mailbox line: a real count comes
        # from this flag alone. The archive's actual SIZE/item count needs a
        # separate Exchange Online connection and a per-mailbox loop - see
        # -DetailedSizing (Full-only) - and is intentionally NOT gathered here.
        $hasArchive = (Get-ColumnValue $u @('Has Archive') '') -eq 'TRUE'
        # NEW v3.17.1: mailbox limit from the same usage report. A mailbox with no
        # license and a 50 GB limit is a shared/resource mailbox (Exchange's
        # default for unlicensed mailboxes) - see Add-MailboxTypeHeuristic.
        $sendRecvQuota = [double](Get-ColumnValue $u @('Prohibit Send/Receive Quota (Byte)', 'Prohibit Send/Receive Quota (Bytes)') 0)

        [PSCustomObject]@{
            Workload          = 'Mailbox'
            ObjectName        = Get-ColumnValue $u @('Display Name') $upn
            Identifier        = $upn
            LastActivityDate  = Get-ColumnValue $u @('Last Activity Date') ''
            ItemCount         = $itemCount
            StorageBytes      = $storageBytes
            StorageUsedMB     = [math]::Round($storageBytes / 1MB, 2)
            RecipientType     = $recipientType
            HasArchive        = $hasArchive
            SendReceiveQuotaBytes = $sendRecvQuota
            SendCount         = $sendCount
            ReceiveCount      = $receiveCount
            ReadCount         = $readCount
            SendRecvActivity  = $sendCount + $receiveCount
            ReadActivity      = $readCount
            Size              = $itemCount
            TotalActivity     = $sendCount + $receiveCount + $readCount
            # NEW: ABR-only signal, always D7 - see header comment above.
            # Feeds Add-RecentDataEstimate's hot-data slice, NOT scoring or
            # the TotalActivity dormancy check (both stay on $Period above).
            SendRecvActivity7d = $sendCount7d + $receiveCount7d
        }
    }
    # NEW: see ConvertTo-ReportRows's matching comment - if $usage has zero
    # rows, or every row gets skipped by the `if (-not $upn) { continue }`
    # above, this foreach-as-expression produces ZERO output objects and
    # PowerShell collapses $rows to $null (not an empty array) - so @($rows)
    # would return a ONE-element array containing $null instead of a true
    # empty array. Guard against that explicitly.
    if ($null -eq $rows) { return @() }
    return @($rows)
}

function Get-OneDriveCriticality {
    param([string]$Period, [string]$WorkDir)

    $usageFile    = Join-Path $WorkDir 'raw_onedrive_usage.csv'
    $activityFile = Join-Path $WorkDir 'raw_onedrive_activity.csv'
    # NEW: see Get-MailboxCriticality's header comment - ABR's hot-data
    # signal always uses D7, independent of -Period.
    $activity7dFile = Join-Path $WorkDir 'raw_onedrive_activity_7d.csv'

    Get-GraphReport -Label 'OneDrive usage' -OutFile $usageFile -Download { Get-MgReportOneDriveUsageAccountDetail -Period $Period -OutFile $usageFile -ErrorAction SilentlyContinue }
    Get-GraphReport -Label 'OneDrive activity' -OutFile $activityFile -Download { Get-MgReportOneDriveActivityUserDetail -Period $Period -OutFile $activityFile -ErrorAction SilentlyContinue }
    Get-GraphReport -Label 'OneDrive activity (7-day, ABR)' -OutFile $activity7dFile -Download { Get-MgReportOneDriveActivityUserDetail -Period 'D7' -OutFile $activity7dFile -ErrorAction SilentlyContinue }

    $usage = Import-Csv $usageFile
    $activityIndex = @{}
    foreach ($a in (Import-Csv $activityFile)) {
        $upn = Get-ColumnValue $a @('User Principal Name') ''
        if ($upn) { $activityIndex[$upn] = $a }
    }
    $activity7dIndex = @{}
    foreach ($a in (Import-Csv $activity7dFile)) {
        $upn = Get-ColumnValue $a @('User Principal Name') ''
        if ($upn) { $activity7dIndex[$upn] = $a }
    }

    $rows = foreach ($u in $usage) {
        $upn = Get-ColumnValue $u @('Owner Principal Name') ''
        if (-not $upn) { continue }
        $act = $activityIndex[$upn]
        $act7d = $activity7dIndex[$upn]

        $viewedEdited = if ($act) { [double](Get-ColumnValue $act @('Viewed Or Edited File Count') 0) } else { 0 }
        $viewedEdited7d = if ($act7d) { [double](Get-ColumnValue $act7d @('Viewed Or Edited File Count') 0) } else { 0 }
        $synced       = if ($act) { [double](Get-ColumnValue $act @('Synced File Count') 0) } else { 0 }
        $sharedInt    = if ($act) { [double](Get-ColumnValue $act @('Shared Internally File Count') 0) } else { 0 }
        $sharedExt    = if ($act) { [double](Get-ColumnValue $act @('Shared Externally File Count') 0) } else { 0 }
        $storageBytes = [double](Get-ColumnValue $u @('Storage Used (Byte)', 'Storage Used (Bytes)') 0)
        $fileCount    = [double](Get-ColumnValue $u @('File Count') 0)

        [PSCustomObject]@{
            Workload               = 'OneDrive'
            ObjectName             = Get-ColumnValue $u @('Owner Display Name') $upn
            Identifier             = Get-ColumnValue $u @('Site URL') $upn
            OwnerUpn               = $upn
            LastActivityDate       = Get-ColumnValue $u @('Last Activity Date') ''
            FileCount              = $fileCount
            ViewedOrEditedCount    = $viewedEdited
            SyncedFileCount        = $synced
            SharedInternallyCount  = $sharedInt
            SharedExternallyCount  = $sharedExt
            StorageBytes           = $storageBytes
            StorageUsedGB          = [math]::Round($storageBytes / 1GB, 3)
            FileActivity           = $viewedEdited + $synced + $sharedInt + ($sharedExt * 1.5)
            Storage                = [math]::Round($storageBytes / 1GB, 3)
            TotalActivity          = $viewedEdited + $synced + $sharedInt + $sharedExt
            # NEW: ABR-only signal, always D7 - see Get-MailboxCriticality.
            ViewedOrEditedCount7d  = $viewedEdited7d
        }
    }
    # NEW: see ConvertTo-ReportRows's matching comment - guard against the
    # foreach-as-expression $null-collapse when $usage is empty or every row
    # gets skipped above, so @($rows) can't return a ONE-element [$null]
    # array instead of a true empty array.
    if ($null -eq $rows) { return @() }
    return @($rows)
}

function Get-SharePointCriticality {
    param(
        [string] $Period,
        [string] $WorkDir,
        [switch] $IncludeGroupConnectedSites,
        [System.Collections.Generic.HashSet[string]] $ExactTeamSiteKeys = $null
    )

    $usageFile = Join-Path $WorkDir 'raw_sharepoint_usage.csv'
    Get-GraphReport -Label 'SharePoint site usage' -OutFile $usageFile -Download { Get-MgReportSharePointSiteUsageDetail -Period $Period -OutFile $usageFile -ErrorAction SilentlyContinue }
    $usage = Import-Csv $usageFile

    # NEW: see Get-MailboxCriticality's header comment - ABR's hot-data
    # signal always uses D7, independent of -Period. SharePoint's "Active
    # File Count" lives in this SAME usage-detail report (unlike Mailboxes/
    # OneDrive, there's no separate activity report), so this is a second
    # call to the identical endpoint with Period=D7 instead of $Period.
    $usage7dFile = Join-Path $WorkDir 'raw_sharepoint_usage_7d.csv'
    Get-GraphReport -Label 'SharePoint site usage (7-day, ABR)' -OutFile $usage7dFile -Download { Get-MgReportSharePointSiteUsageDetail -Period 'D7' -OutFile $usage7dFile -ErrorAction SilentlyContinue }
    $usage7dIndex = @{}
    foreach ($s7 in (Import-Csv $usage7dFile)) {
        $key = Get-ColumnValue $s7 @('Site Id') ''
        if ($key) { $usage7dIndex[$key] = $s7 }
    }

    $kept = [System.Collections.Generic.List[object]]::new()
    $excluded = [System.Collections.Generic.List[object]]::new()
    $useExactMode = $null -ne $ExactTeamSiteKeys

    foreach ($s in $usage) {
        $url      = Get-ColumnValue $s @('Site URL') ''
        $siteId   = Get-ColumnValue $s @('Site Id') ''
        $template = Get-ColumnValue $s @('Root Web Template') ''
        $ownerUpn = Get-ColumnValue $s @('Owner Principal Name') ''

        $isOneDrive = ($url -match '-my\.sharepoint\.com') -or
                      ($template -eq 'My Site') -or
                      ($template -match 'OneDrive') -or
                      ($template -match 'Personal Site')

        $isTeamSite = if ($useExactMode) {
            ($siteId -and $ExactTeamSiteKeys.Contains($siteId)) -or ($url -and $ExactTeamSiteKeys.Contains($url.TrimEnd('/')))
        } else {
            ($template -in @('Group', 'Team Channel')) -and -not $IncludeGroupConnectedSites
        }

        $identifier = if ($url) { $url } elseif ($ownerUpn) { $ownerUpn } else { $siteId }

        $pageViews    = [double](Get-ColumnValue $s @('Page View Count') 0)
        $activeFiles  = [double](Get-ColumnValue $s @('Active File Count') 0)
        $storageBytes = [double](Get-ColumnValue $s @('Storage Used (Byte)', 'Storage Used (Bytes)') 0)
        $fileCount    = [double](Get-ColumnValue $s @('File Count') 0)
        # NEW: ABR-only signal, always D7 - see header comment above. Matched
        # by Site Id (falls back to 0 if a site is missing from the D7 pull -
        # e.g. created between the two report generations).
        $s7d = if ($siteId) { $usage7dIndex[$siteId] } else { $null }
        $activeFiles7d = if ($s7d) { [double](Get-ColumnValue $s7d @('Active File Count') 0) } else { 0 }

        $obj = [PSCustomObject]@{
            Workload         = 'SharePoint Site'
            ObjectName       = Get-ColumnValue $s @('Owner Display Name') $identifier
            Identifier       = $identifier
            SiteId           = $siteId
            RootWebTemplate  = $template
            LastActivityDate = Get-ColumnValue $s @('Last Activity Date') ''
            FileCount        = $fileCount
            ActiveFileCount  = $activeFiles
            PageViewCount    = $pageViews
            VisitedPageCount = [double](Get-ColumnValue $s @('Visited Page Count') 0)
            StorageBytes     = $storageBytes
            StorageUsedGB    = [math]::Round($storageBytes / 1GB, 3)
            PageViews        = $pageViews
            ActiveFiles      = $activeFiles
            ActiveFiles7d    = $activeFiles7d
            Storage          = [math]::Round($storageBytes / 1GB, 3)
            TotalActivity    = $pageViews + $activeFiles
            BreadthNote      = 'Traffic proxy only - not a unique-accessor count. See script header NOTES.'
        }

        if ($isOneDrive) {
            Add-Member -InputObject $obj -NotePropertyName 'ExclusionReason' -NotePropertyValue 'OneDrive personal site - already tiered under OneDrive' -Force
            $excluded.Add($obj)
        }
        elseif ($isTeamSite) {
            $reason = if ($useExactMode) {
                "Exact match to a Team's SharePoint site (resolved via Get-MgGroupSite) - already tiered under Teams."
            } else {
                "Group/Teams-connected site (RootWebTemplate=$template) - heuristic match, likely already tiered under Teams. Re-run with -IncludeGroupConnectedSites to keep sites like this."
            }
            Add-Member -InputObject $obj -NotePropertyName 'ExclusionReason' -NotePropertyValue $reason -Force
            $excluded.Add($obj)
        }
        else {
            $kept.Add($obj)
        }
    }

    return @{ Sites = @($kept); Excluded = @($excluded) }
}

function Get-TeamsCriticality {
    param([string]$Period, [string]$WorkDir)

    $teamFile = Join-Path $WorkDir 'raw_teams_team_activity.csv'
    Get-GraphReport -Label 'Team activity' -OutFile $teamFile -Download { Get-MgReportTeamActivityDetail -Period $Period -OutFile $teamFile -ErrorAction SilentlyContinue }
    $teams = Import-Csv $teamFile

    $rows = foreach ($t in $teams) {
        $activeUsers  = [double](Get-ColumnValue $t @('Active users', 'Active Users') 0)
        $channelMsgs  = [double](Get-ColumnValue $t @('Channel Messages') 0)
        $meetings     = [double](Get-ColumnValue $t @('Meetings Organized') 0)

        [PSCustomObject]@{
            Workload          = 'Team'
            ObjectName        = Get-ColumnValue $t @('Team Name') ''
            # Concealed-names tenants export an all-zero Team Id for every team; fall back to the (unique, hashed) Team Name so rows stay distinct.
            Identifier        = $(if ((Get-ColumnValue $t @('Team Id') '') -match '^[0\-]*$') { Get-ColumnValue $t @('Team Name') '' } else { Get-ColumnValue $t @('Team Id') '' })
            LastActivityDate  = Get-ColumnValue $t @('Last Activity Date') ''
            ActiveUsersCount  = $activeUsers
            ChannelMessages   = $channelMsgs
            MeetingsOrganized = $meetings
            Guests            = [double](Get-ColumnValue $t @('Guests') 0)
            ActiveUsers       = $activeUsers
            ChannelMsgs       = $channelMsgs
            Meetings          = $meetings
            TotalActivity     = $activeUsers + $channelMsgs + $meetings
        }
    }
    # NEW: see ConvertTo-ReportRows's matching comment - a tenant with no
    # Teams usage (or a Teams report that comes back with zero data rows)
    # makes this foreach-as-expression produce ZERO output objects, which
    # PowerShell collapses to $rows = $null rather than an empty array.
    # Without this guard, @($rows) would return a ONE-element array
    # containing $null instead of a true empty array - which is what caused
    # a customer's run to crash downstream with "Cannot bind argument
    # to parameter 'Teams' because it is an empty collection" when that
    # value was later passed into a [Parameter(Mandatory)] [array] $Teams
    # parameter (see Get-ExactTeamSiteUrls and [AllowEmptyCollection()]
    # additions throughout this file).
    if ($null -eq $rows) { return @() }
    return @($rows)
}

#endregion

#region ---------- HTML report (Rubrik-branded, live client-side engine) ----------
<#
    v2.0.0 architecture change: PowerShell ships RAW per-object metrics plus
    enrichment as a single embedded JSON blob. ALL scoring, tiering, override
    handling, filtering, totals, and recovery/cost math is computed in the
    browser by $script:ReportJs. This is what makes weights, title scoring,
    hub-site keywords, and manual tier overrides live-adjustable without
    re-running the script - there is exactly one place the "logic" lives
    (client-side), not two copies that can drift out of sync.

    The HTML/CSS/JS below use a placeholder + string .Replace() technique
    instead of a double-quoted here-string with inline PowerShell variable
    interpolation. Reason: the JSON data blob can contain arbitrary customer
    data (mailbox display names, SharePoint URLs, etc.) that may itself
    contain "$" or other characters PowerShell would try to interpolate
    inside a double-quoted here-string. .Replace() on a single-quoted
    template does a pure literal substitution - safe regardless of content.
#>

function ConvertTo-SafeHtml {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

<#
    PowerShell's ConvertTo-Json happily emits the bare words Infinity,
    -Infinity, and NaN for [double]::PositiveInfinity/NegativeInfinity/NaN
    values anywhere in the object graph - none of which are valid JSON
    (the spec has no numeric literal for them). The browser's JSON.parse()
    on the embedded report-data blob throws on the very first one, which
    kills DATA entirely and leaves every tab blank - with no error visible
    anywhere except the browser console, so it looks like a silently broken
    report rather than a crash. Found live 2026-08-26: the SPOD throughput
    tier table's uncapped "50k+" bucket was still [double]::PositiveInfinity
    (fixed to $null, which the JS side already expected), but nothing
    stopped the NEXT such value - added anywhere in $dataObject by a future
    change - from doing the exact same thing again, undetected by node
    --check or a JS-logic vm harness (both operate on an already-parsed JS
    object, never the raw JSON text a browser's JSON.parse() actually sees).
    Call this on the compressed JSON string immediately after every
    ConvertTo-Json call that builds an embedded/exported report-data blob,
    before it's written anywhere - fails loudly and immediately at
    generation time instead of shipping a report that only looks broken
    once a customer opens it.
#>
function Assert-ValidReportJson {
    param([Parameter(Mandatory)][string]$Json, [string]$Context = 'report data')
    if ($Json -match '(?<=[:,\[])(-?Infinity|NaN)(?=[,\]}])') {
        throw "Assert-ValidReportJson: found a bare '$($Matches[1])' token in $Context - not valid JSON, will crash JSON.parse() in the browser and leave the report blank. Root cause is almost always a [double]::PositiveInfinity/NegativeInfinity/NaN value somewhere in the object passed to ConvertTo-Json; replace it with `$null` (or a finite sentinel) before this point."
    }
}

$script:ReportCss = @'
/* ==========================================================================
   Recovery Assessment v2.0 - dark theme (Rubrik presentation template palette).
   ALL colors in this file and in ReportCss.d/*.css come from the tokens below.
   v1 was a light page with navy accents; v2 is dark navy with white text so the
   two versions are obvious at a glance. @media print switches back to a light
   scheme (see the end of this file) so PDF/print output stays readable.
   ASCII only: this file is embedded in a PowerShell script.
   ========================================================================== */
:root[data-theme="dark"] {
  /* ---- contract tokens ---- */
  --bg-deep:#011E3A;       /* page */
  --bg-navy:#0A2547;       /* panels, header, tab bar (softened v2.0: deeper than 122861) */
  --bg-card:#122861;       /* cards, table headers, accordion heads (Rubrik navy; was brighter 152C7C) */
  --bg-raise:#1D3A94;      /* hover state on cards / rows */
  --text:#FFFFFF;
  --text-muted:#D9D9D9;
  --text-dim:#BFBFBF;
  --border:#3A4A80;
  --border-soft:rgba(255,255,255,.12);
  --accent-teal:#04CAB9;   /* primary accent, Group 1 */
  --accent-cyan:#1BBCF3;
  --accent-blue:#0C67DD;
  --accent-mint:#BCFFFB;
  --accent-lilac:#F4C9F4;
  --accent-purple:#8242E8; /* Group 2 */
  --alert:#FB3A73;         /* exceeds RTO target, flagged outliers */
  --warn:#FF5A2E;
  --ok:#00B46E;

  /* ---- supporting tokens (derived; text variants are lighter so they pass contrast on dark panels) ---- */
  --ok-text:#3EE0A0;
  --amber:#FFBE49;
  --alert-text:#FF8FB0;
  --ok-bg:rgba(0,180,110,.16);   --ok-bd:rgba(0,180,110,.55);
  --alert-bg:rgba(251,58,115,.16); --alert-bd:rgba(251,58,115,.55);
  --warn-bg:rgba(255,190,73,.14);  --warn-bd:rgba(255,190,73,.50);
  --info-bg:rgba(27,188,243,.14);  --info-bd:rgba(27,188,243,.50);
  --shadow:0 1px 3px rgba(0,0,0,.35);
  --shadow-lg:0 4px 18px rgba(0,0,0,.40);
  --hatch-base:#2B3D7A;
  --hatch-stripe:rgba(255,255,255,.14);
  --inset:rgba(0,0,0,.28);       /* dark inset wells (tracks, bars) */
  --inset-cell:#0A2547; --massc:#FF4D5E; --g1c:#04CAB9; --g2c:#8242E8; --g3c:#F4C9F4; --g4c:#6F7FA3; --g2t:#B993F5; --qpill:#FFB3C6;

  /* surfaces: top-level cards use --surface, insets use --surface-2. Inside a panel that is already --bg-navy
     (accordion bodies) the roles are swapped so nested cards still separate from their parent. */
  --surface:var(--bg-navy);
  --surface-2:var(--bg-card);
  --zebra:rgba(255,255,255,.035);

  /* ---- legacy names (3.x code and inline styles in the JS) remapped for a dark background ----
     --navy / --dark-gray were TEXT colors on white (headings / muted text); here they are light.
     --blue was link/accent text and button fill; here it is the cyan accent so text stays legible.
     --white is only ever a literal white (it was never used as a card fill). */
  --teal:#04CAB9; --cyan:#1BBCF3; --green:#3EE0A0; --blue:#1BBCF3;
  --navy:#FFFFFF; --navy-dark:#011E3A; --yellow:#FFBE49;
  --mid-gray:#8FA0BF; --dark-gray:#BFBFBF; --white:#FFFFFF;
  /* The one deliberate exception to "never use red for mere priority ranking": exceeds-RTO-target callouts. */
  /* used as TEXT by inline styles in the JS, so it is the lighter alert tint (4.5:1+ on every panel); borders/fills in CSS use --alert */
  --red-target:#FF8FB0;
  color-scheme: dark;
}
/* Light theme (default): v1-style light page with Rubrik navy text; the header stays navy so the logo reads. */
:root, :root[data-theme="light"] {
  --bg-deep:#E8ECF1; --bg-navy:#EEF1F4; --bg-card:#FFFFFF; --bg-raise:#E7EBEF;
  --text:#1B2430; --text-muted:#4A5560; --text-dim:#6C7576; --border:#E2E6EA; --border-soft:#EDF0F3;
  --accent-teal:#0A6764; --accent-cyan:#1B8FC4; --accent-blue:#0E5BCF; --accent-mint:#0A6764; --accent-lilac:#5B2DA8; --accent-purple:#5B2DA8;
  --alert:#B5384F; --warn:#B9622E; --ok:#2F7D5B;
  --ok-text:#2B6B50; --amber:#8A6420; --alert-text:#9C3040;
  --ok-bg:rgba(10,122,79,.10); --ok-bd:rgba(10,122,79,.45);
  --alert-bg:rgba(192,33,63,.08); --alert-bd:rgba(192,33,63,.45);
  --warn-bg:rgba(194,74,27,.09); --warn-bd:rgba(194,74,27,.45);
  --info-bg:rgba(10,111,168,.08); --info-bd:rgba(10,111,168,.40);
  --shadow:0 1px 3px rgba(0,0,0,.08); --shadow-lg:0 6px 16px rgba(9,53,101,.14);
  --hatch-base:#D7DCE1; --hatch-stripe:rgba(255,255,255,.55);
  --inset:rgba(9,53,101,.07); --inset-cell:#E2E6EA; --massc:#B3122B; --g1c:#0F7F7C; --g2c:#5B2DA8; --g3c:#8A66C8; --g4c:#A4A9A8; --g2t:#5B2DA8; --qpill:#9C3040;
  --surface:var(--bg-navy); --surface-2:var(--bg-card); --zebra:rgba(9,53,101,.03);
  --teal:#0F8C89; --cyan:#2FCAFF; --green:#21DDAA; --blue:#0E5BCF; --navy:#093565; --navy-dark:#0A2E57; --yellow:#FFBE49;
  --mid-gray:#A4A9A8; --dark-gray:#6C7576; --white:#FFFFFF; --red-target:#E5484D;
  color-scheme: light;
}
/* v1-style cards: white with a soft shadow */
:root:not([data-theme="dark"]) .xs-tile, :root:not([data-theme="dark"]) .xs-pill, :root:not([data-theme="dark"]) .xs-ladder { box-shadow:0 1px 3px rgba(0,0,0,.08); }
/* The header is navy in both themes: keep its own copy of the dark tokens. */
.header { --text:#FFFFFF; --text-muted:#D9D9D9; --bg-card:#122861; --bg-navy:#0A2547; --bg-deep:#011E3A; --border:#3A4A80; --accent-teal:#04CAB9; --accent-cyan:#1BBCF3; --accent-mint:#BCFFFB; --inset:rgba(0,0,0,.28); }
/* Nested surfaces: panels whose own background is --bg-navy */
.acc-body, .exec-collapsible-body, .controls-panel, .rt-group-section {
  --surface:var(--bg-deep);
  --surface-2:var(--bg-card);
}
/* presenter/1920x1080 pass: root font-size scales with viewport width via clamp() - virtually every rule here is in rem. */
html { font-size: clamp(15px, 0.6vw + 9px, 18px); }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg-deep); color: var(--text); font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; overflow-x: hidden; }
a { color: var(--accent-teal); }
a:hover { color: var(--accent-mint); }
::selection { background: var(--accent-teal); color: var(--bg-deep); }
/* accent rule across the very top - the old multicolor bar, now teal to cyan to blue */
.rainbow-bar { height: 4px; position: fixed; top: 0; left: 0; right: 0; z-index: 1000; background: linear-gradient(90deg, var(--accent-teal), var(--accent-cyan), var(--accent-blue)); box-shadow: 0 0 10px rgba(4,202,185,.55); }
.header { position: relative; margin-top: 4px; color: var(--text); padding: .9rem 3rem .9rem; background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-navy) 55%, var(--bg-deep) 100%); border-bottom: 3px solid var(--accent-teal); }
.header .logo { position: absolute; right: calc(3rem - 34px); top: 50%; transform: translateY(-50%); pointer-events: none; }
.header .logo svg { height: 84px; width: auto; display: block; }
.header .eyebrow { font-size: .72rem; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; color: var(--accent-teal); margin: .35rem 0 .3rem; }
.header h1 { font-size: clamp(1.5rem, 2.6vw, 2.1rem); font-weight: 800; margin: 0 0 .4rem; line-height: 1.15; color: var(--text); }
.header .meta { font-size: .9rem; color: var(--text-muted); display: flex; gap: .5rem 1.75rem; flex-wrap: wrap; align-items: center; }
.header .meta b { color: var(--text); font-weight: 600; }
.tabbar { position: sticky; top: 4px; z-index: 999; background: var(--bg-navy); border-bottom: 1px solid var(--border); padding: 0 3rem; display: flex; gap: .25rem; flex-wrap: wrap; box-shadow: 0 2px 8px rgba(0,0,0,.45); }
.tab-btn { border: none; background: none; padding: .9rem 1rem; font-size: .85rem; font-weight: 700; color: var(--text-muted); cursor: pointer; border-bottom: 3px solid transparent; font-family: inherit; }
.tab-btn.active { color: var(--text); border-bottom-color: var(--accent-teal); background: rgba(255,255,255,.05); }
.tab-btn:hover { color: var(--text); background: rgba(255,255,255,.06); }
main { padding: 2rem 2.75rem 4rem; max-width: 1800px; margin: 0 auto; }
.tab-panel { display: none; }
.tab-panel.active { display: block; }
h2 { font-size: 1.3rem; font-weight: 800; color: var(--text); margin: 0 0 1.25rem; }
h3, h4, h5 { color: var(--text); }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.1rem; margin-bottom: 2rem; }
.summary-card { display: block; background: var(--surface); border: 1px solid var(--border-soft); border-radius: 12px; padding: 1.1rem 1.4rem; box-shadow: var(--shadow); border-left: 4px solid var(--accent, var(--accent-teal)); text-decoration: none; color: inherit; cursor: pointer; transition: box-shadow .15s ease, transform .15s ease; }
.summary-card:hover { box-shadow: 0 6px 16px rgba(0,0,0,.5); transform: translateY(-2px); background: var(--bg-raise); }
.summary-card h3 { margin: 0 0 .15rem; font-size: .82rem; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }
.summary-card .total { font-size: 2rem; font-weight: 800; color: var(--text); margin: .1rem 0 .65rem; }
.tier-bar { display: flex; height: 9px; border-radius: 6px; overflow: hidden; margin-bottom: .6rem; background: var(--inset); }
.tier-bar span { display: block; height: 100%; }
.tier-legend { font-size: .74rem; color: var(--text-muted); display: flex; flex-direction: column; gap: .2rem; }
.tier-legend > div { display: flex; align-items: center; gap: .4rem; }
.totals-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: .75rem; margin-bottom: 1.5rem; }
.totals-cell { background: var(--surface); border: 1px solid var(--border-soft); border-radius: 8px; padding: .8rem 1rem; box-shadow: var(--shadow); }
.totals-cell .label { font-size: .72rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: .5px; }
.totals-cell .value { font-size: 1.3rem; font-weight: 800; color: var(--text); }

/* Executive Summary hero sections (Financial Impact, Recovery Times): bigger/bolder than .totals-cell. */
.exec-hero-label { font-size: .95rem; font-weight: 800; color: var(--text); margin: 0 0 .7rem; text-transform: uppercase; letter-spacing: .5px; }
.exec-hero-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.6rem; }
.exec-hero-card { background: var(--surface); border: 1px solid var(--border-soft); border-radius: 12px; padding: 1.1rem 1.4rem; box-shadow: var(--shadow); border-left: 4px solid var(--accent-teal); }
.exec-hero-card.savings { border-left-color: var(--ok); }
.exec-hero-card.exposure { border-left-color: var(--alert); }
.exec-hero-card .exec-hero-tag { font-size: .72rem; text-transform: uppercase; letter-spacing: .5px; color: var(--text-muted); font-weight: 700; }
.exec-hero-card .exec-hero-value { font-size: 1.9rem; font-weight: 800; color: var(--text); margin: .2rem 0; }
.exec-hero-card .exec-hero-sub { font-size: .82rem; color: var(--text-muted); }
.exec-hero-note { font-size: .78rem; color: var(--text-muted); background: var(--surface-2); border-radius: 8px; padding: .55rem .85rem; margin: -.6rem 0 1.6rem; }
.exec-hero-caption { font-size: .78rem; color: var(--text-muted); margin: -.4rem 0 1rem; max-width: 70ch; }
.exec-hero-linkout { font-size: .78rem; color: var(--accent-teal); cursor: pointer; text-decoration: underline; }

/* Financial Impact as a before/after comparison with a savings punchline. */
.exec-fin-compare { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
.exec-fin-compare-card { flex: 1 1 240px; background: var(--surface); border: 1px solid var(--border-soft); border-radius: 12px; padding: 1.1rem 1.4rem; box-shadow: var(--shadow); border-left: 4px solid var(--alert); }
.exec-fin-compare-card.after { border-left-color: var(--accent-teal); }
.exec-fin-compare-label { font-size: .72rem; text-transform: uppercase; letter-spacing: .5px; color: var(--text-muted); font-weight: 700; }
.exec-fin-compare-time { font-size: 1.7rem; font-weight: 800; color: var(--text); margin: .2rem 0; }
.exec-fin-compare-cost { font-size: 1rem; font-weight: 700; color: var(--text-muted); }
.exec-fin-compare-arrow { font-size: 1.6rem; color: var(--mid-gray); flex: 0 0 auto; }
.exec-fin-punchline { background: var(--ok-bg); border: 1px solid var(--ok-bd); border-radius: 10px; padding: .9rem 1.3rem; font-size: 1rem; font-weight: 600; color: var(--ok-text); margin-bottom: 1.6rem; }
.exec-fin-punchline b { font-size: 1.35rem; }
/* time-first headline: leads with "critical data usable in X instead of Y" before any dollar figure */
.exec-fin-headline { font-size: 1.15rem; font-weight: 700; color: var(--text); margin: 0 0 1.2rem; max-width: 68ch; }
.exec-fin-headline b { color: var(--ok-text); font-size: 1.35rem; }
/* Recovery Timeline under Financial Impact: genuinely to-scale tracks. "Without ABR" is a full-width hatched bar; "With ABR"
   is the same timescale with Groups 1/2/3 as a small chip cluster followed by a de-emphasized background-restore fill. */
.fin-timeline { margin-top: 1.6rem; }
.fin-tl-title { font-size: 1rem; font-weight: 800; color: var(--text); margin: 0 0 .3rem; }
.fin-tl-desc { font-size: .85rem; color: var(--text-muted); margin: 0 0 1.3rem; max-width: 62ch; }
.fin-tl-track-block { margin-bottom: 1.3rem; }
.fin-tl-track-label { font-size: .95rem; font-weight: 800; color: var(--text); margin: 0 0 .1rem; }
.fin-tl-track-sublabel { font-size: .8rem; color: var(--text-muted); margin: 0 0 .5rem; }
.fin-tl-track-row { display: flex; align-items: center; gap: .7rem; }
.fin-tl-track-bar { flex: 1 1 auto; height: 52px; border-radius: 10px; overflow: hidden; display: flex; align-items: center; box-shadow: var(--shadow); }
/* both bars fade out on their trailing edge (mask-image) to show they run to the same real endpoint */
.fin-tl-track-bar.hatched { background-color: var(--hatch-base); background-image: repeating-linear-gradient(45deg, var(--hatch-stripe) 0, var(--hatch-stripe) 7px, transparent 7px, transparent 14px); padding: 0 1.2rem; mask-image: linear-gradient(to right, #000 0%, #000 65%, transparent 97%); -webkit-mask-image: linear-gradient(to right, #000 0%, #000 65%, transparent 97%); }
.fin-tl-track-bar-text { font-weight: 700; font-size: .92rem; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.fin-tl-track-endlabel { flex: 0 0 auto; font-size: 1.15rem; font-weight: 800; color: var(--text); white-space: nowrap; display: flex; align-items: center; gap: .3rem; }
.fin-tl-track-endlabel .arrow { color: var(--mid-gray); font-size: 1.1rem; }
.fin-tl-track-bar.with-abr { background: var(--surface-2); padding: 0; }
.fin-tl-chip-cluster { flex: 0 0 auto; display: flex; align-items: stretch; height: 100%; gap: 2px; padding: 6px; box-sizing: border-box; }
.fin-tl-chip { border-radius: 4px; min-width: 6px; }
.fin-tl-bg-fill { flex: 1 1 auto; height: 100%; display: flex; align-items: center; justify-content: center; color: var(--text-muted); font-size: .82rem; font-style: italic; white-space: nowrap; overflow: hidden; background-color: var(--hatch-base); background-image: repeating-linear-gradient(45deg, var(--hatch-stripe) 0, var(--hatch-stripe) 7px, transparent 7px, transparent 14px); mask-image: linear-gradient(to right, #000 0%, #000 40%, transparent 96%); -webkit-mask-image: linear-gradient(to right, #000 0%, #000 40%, transparent 96%); }
.fin-tl-gap-callout { font-size: .95rem; color: var(--text-muted); margin: 0 0 1.2rem; }
.fin-tl-gap-callout b { color: var(--ok-text); font-size: 1.05rem; }
.fin-tl-legend { display: flex; flex-wrap: wrap; gap: .45rem 1.5rem; margin: .6rem 0 .5rem; }
.fin-tl-legend-item { display: flex; align-items: center; gap: .45rem; font-size: .8rem; color: var(--text); }
.fin-tl-swatch { width: 12px; height: 12px; border-radius: 3px; flex: 0 0 auto; }
.fin-tl-legend-item b { font-weight: 800; }
.fin-tl-legend-item .fin-tl-sub { color: var(--text-muted); font-weight: 400; }
.fin-tl-track-note { font-size: .78rem; color: var(--text-muted); background: var(--surface-2); border-radius: 8px; padding: .55rem .85rem; margin-bottom: 1.6rem; }
/* Low-activity (Group 4) callout classes keep their historical exec-dormant-* names; wording is set by the JS. */
.exec-dormant-headline { font-size: 1rem; color: var(--text); margin: 0 0 1rem; max-width: 72ch; }
.exec-dormant-headline b { font-size: 1.3rem; color: var(--amber); }
.exec-dormant-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .8rem; margin-bottom: 1.6rem; }
.exec-dormant-cell { background: var(--surface); border: 1px solid var(--border-soft); border-radius: 10px; padding: .9rem 1.1rem; box-shadow: var(--shadow); border-left: 4px solid var(--amber); }
.exec-dormant-pct { font-size: 1.5rem; font-weight: 800; color: var(--text); }
.exec-dormant-label { font-size: .78rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: .5px; margin-top: .2rem; }
.exec-dormant-sub { font-size: .78rem; color: var(--text-muted); margin-top: .15rem; }
.exec-dormant-time { font-size: .78rem; color: var(--text); font-weight: 700; margin-top: .35rem; padding-top: .35rem; border-top: 1px dashed var(--border); }
.exec-dormant-time-na { font-size: .72rem; color: var(--text-muted); font-style: italic; margin-top: .35rem; padding-top: .35rem; border-top: 1px dashed var(--border); }
/* Generic collapsible (collapsed by default, one click to expand). */
.exec-collapsible { margin-top: 1.8rem; background: var(--surface-2); border: 1px solid var(--border-soft); border-radius: 12px; overflow: hidden; }
.exec-collapsible-toggle { display: flex; align-items: center; gap: .7rem; width: 100%; background: none; border: none; cursor: pointer; padding: 1rem 1.2rem; text-align: left; font-family: inherit; color: var(--text); }
.exec-collapsible-toggle:hover { background: rgba(255,255,255,.06); }
.exec-collapsible-chevron { display: inline-block; font-size: .75rem; color: var(--text-muted); transition: transform .15s ease; flex: 0 0 auto; }
.exec-collapsible-toggle[aria-expanded="true"] .exec-collapsible-chevron { transform: rotate(90deg); }
.exec-collapsible-title { font-weight: 800; color: var(--text); font-size: .95rem; flex: 1 1 auto; }
.exec-collapsible-summary { font-size: .85rem; color: var(--text-muted); flex: 0 0 auto; }
.exec-collapsible-body { padding: 0 1.2rem 1.4rem; }
.exec-collapsible-body[hidden] { display: none; }
/* Lean Executive Summary: big stat tiles, mechanism callout, link to the Report tab. */
.exec-lean-tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
.exec-lean-tile { background: var(--surface); border: 1px solid var(--border-soft); border-radius: 16px; padding: 2.2rem 2rem; box-shadow: var(--shadow-lg); border-top: 6px solid var(--accent-teal); }
.exec-lean-tile.money { border-top-color: var(--ok); }
.exec-lean-tile.dormant { border-top-color: var(--amber); }
.exec-lean-tile-label { font-size: .8rem; font-weight: 800; text-transform: uppercase; letter-spacing: .8px; color: var(--text-muted); margin-bottom: .6rem; }
.exec-lean-tile-value { font-size: 3.2rem; font-weight: 900; color: var(--text); line-height: 1; margin-bottom: .5rem; }
.exec-lean-tile.money .exec-lean-tile-value { color: var(--ok-text); }
.exec-lean-tile.dormant .exec-lean-tile-value { color: var(--amber); }
.exec-lean-tile-sub { font-size: .95rem; color: var(--text-muted); }
.exec-lean-tile-sub b { color: var(--text); }
.exec-lean-mechanism { background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-navy) 100%); border: 1px solid var(--border); color: var(--text); border-radius: 16px; padding: 1.8rem 2.2rem; font-size: 1.1rem; font-weight: 600; line-height: 1.5; margin-bottom: 1.6rem; }
.exec-lean-mechanism b { color: var(--accent-teal); }
.exec-lean-footer-link { font-size: .9rem; color: var(--text-muted); text-align: right; }
/* Recovery Ladder: single to-scale horizontal timeline. Time value renders ABOVE the track/pin, sub-label BELOW. */
.recovery-ladder { background: var(--surface); border: 1px solid var(--border-soft); border-radius: 16px; padding: 1.8rem 2rem 1.6rem; box-shadow: var(--shadow-lg); margin-bottom: 1.6rem; }
.rl-title { font-size: 1rem; font-weight: 800; color: var(--text); margin: 0 0 .2rem; }
.rl-sub { font-size: .82rem; color: var(--text-muted); margin: 0 0 2.6rem; }
.rl-track-wrap { position: relative; height: 112px; margin: 0 4px; }
.rl-track { position: absolute; top: 42px; left: 0; right: 0; height: 10px; border-radius: 6px; overflow: hidden; display: flex; background: var(--inset); box-shadow: inset 0 1px 2px rgba(0,0,0,.4); }
.rl-seg { height: 100%; }
.rl-seg.mass { background-color: var(--hatch-base); background-image: repeating-linear-gradient(45deg, var(--hatch-stripe) 0, var(--hatch-stripe) 6px, transparent 6px, transparent 12px); }
.rl-seg.locked { background-color: var(--hatch-base); background-image: repeating-linear-gradient(135deg, var(--hatch-base) 0, var(--hatch-base) 8px, var(--border) 8px, var(--border) 16px); }
.rl-flag { position: absolute; top: 0; width: 132px; transform: translateX(-50%); text-align: center; }
.rl-flag .rl-time { position: absolute; top: 0; left: 0; right: 0; font-weight: 800; font-size: 1.05rem; color: var(--text); white-space: nowrap; }
.rl-flag.mass .rl-time { color: var(--text-muted); }
.rl-pin { position: absolute; top: 36px; transform: translateX(-50%); width: 16px; height: 16px; border-radius: 50%; border: 3px solid var(--text); box-shadow: 0 0 0 1.5px rgba(0,0,0,.45); z-index: 2; }
.rl-pin.mass { background: var(--bg-deep); border-color: var(--mid-gray); box-shadow: none; width: 14px; height: 14px; top: 37px; }
.rl-pin.locked { background: var(--border); }
.rl-flag .rl-label { position: absolute; top: 62px; left: 0; right: 0; font-size: .76rem; color: var(--text-muted); line-height: 1.25; }
.rl-note { margin-top: .6rem; font-size: .8rem; color: var(--text-muted); line-height: 1.4; background: var(--surface-2); border-radius: 8px; padding: .55rem .8rem; }
/* Group tables used on the Report tab and Sizing tab. */
.exec-cost-table-wrap { overflow-x: auto; margin-bottom: 1.6rem; }
.exec-cost-table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 10px; overflow: hidden; box-shadow: var(--shadow); }
.exec-cost-table th { text-align: left; padding: .55rem .85rem; font-size: .7rem; text-transform: uppercase; letter-spacing: .5px; color: var(--text-muted); background: var(--surface-2); }
.exec-cost-table td { padding: .55rem .85rem; font-size: .85rem; border-top: 1px solid var(--border-soft); color: var(--text); }
.exec-cost-table tr.total-row td { font-weight: 700; color: var(--text); border-top: 2px solid var(--border); }
.sizing-section { margin-bottom: 2rem; }
.sizing-section h3 { font-size: .95rem; font-weight: 800; color: var(--text); margin: 0 0 .6rem; }
.sizing-discovery-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1.2rem; background: var(--surface); border: 1px solid var(--border-soft); border-radius: 10px; padding: 1.3rem 1.5rem; box-shadow: var(--shadow); margin-bottom: .6rem; }
.sizing-discovery-cell .label { font-size: .72rem; text-transform: uppercase; letter-spacing: .5px; color: var(--text-muted); margin-bottom: .3rem; }
.sizing-discovery-cell .value { font-size: 1.6rem; font-weight: 800; color: var(--text); }
.sizing-footnote { font-size: .78rem; color: var(--text-muted); font-style: italic; margin: .6rem 0 1.2rem; }
/* Controls (scoring weights, recovery inputs). */
.controls-panel { background: var(--surface); border: 1px solid var(--border-soft); border-radius: 10px; padding: 1.1rem 1.3rem; margin-bottom: 1.5rem; box-shadow: var(--shadow); }
.controls-panel h4 { margin: 0 0 .6rem; font-size: .85rem; color: var(--text); }
.control-row { display: flex; align-items: center; gap: .6rem; margin-bottom: .5rem; flex-wrap: wrap; }
.control-row label { font-size: .78rem; color: var(--text-muted); min-width: 150px; }
.control-row input[type=range] { flex: 1; max-width: 220px; }
.control-row .valdisp { font-size: .78rem; font-weight: 700; color: var(--text); min-width: 40px; }
/* All text-like inputs, selects and textareas share one dark style. */
input[type=number], input[type=text], input[type=search], select, textarea, .control-row input[type=number], .control-row input[type=text], .control-row select {
  background: var(--bg-deep); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: .3rem .5rem; font-size: .8rem; font-family: inherit; }
input::placeholder, textarea::placeholder { color: var(--text-dim); opacity: 1; }
select option { background: var(--bg-deep); color: var(--text); }
input[type=range] { accent-color: var(--accent-teal); }
input[type=checkbox], input[type=radio] { accent-color: var(--accent-teal); }
input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible, a:focus-visible, [tabindex]:focus-visible, summary:focus-visible { outline: 2px solid var(--accent-cyan); outline-offset: 2px; }
/* Locked / disabled controls (Preview keeps sliders visible but not changeable): visibly greyed. */
input:disabled, select:disabled, textarea:disabled, button:disabled, .is-locked, [aria-disabled="true"] { opacity: .5; cursor: not-allowed; filter: grayscale(.6); }
input[type=range]:disabled { accent-color: var(--mid-gray); }
.locked-note { font-size: .74rem; color: var(--text-muted); font-style: italic; margin: .3rem 0 .8rem; }

/* scoring-controls: percentage weights with a per-workload 100% cap, next to the Live Impact Preview */
.controls-panel-grid { display: grid; grid-template-columns: minmax(360px, 480px) 1fr; gap: 1.6rem; align-items: start; margin-bottom: 1.5rem; }
@media (max-width: 900px) { .controls-panel-grid { grid-template-columns: 1fr; } }
.panel-title { margin: 0 0 .2rem; font-size: .95rem; color: var(--text); font-weight: 800; }
.panel-sub { margin: 0 0 1.1rem; font-size: .78rem; color: var(--text-muted); max-width: 60ch; line-height: 1.4; }
.panel-sub b { color: var(--text); }
.wd-block { margin-bottom: 1rem; border: 1px solid var(--border); border-radius: 8px; padding: .75rem .85rem .6rem; }
.wd-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: .5rem; }
.wd-head b { font-size: .8rem; color: var(--text); }
.wd-total { font-size: .7rem; font-weight: 800; padding: .18rem .5rem; border-radius: 20px; letter-spacing: .3px; }
.wd-total.ok { background: var(--ok-bg); color: var(--ok-text); border: 1px solid var(--ok-bd); }
.wd-total.warn { background: var(--warn-bg); color: var(--amber); border: 1px solid var(--warn-bd); }
.remaining-hint { font-size: .68rem; color: var(--text-muted); margin-top: .2rem; }
.remaining-hint.has-room { color: var(--ok-text); font-weight: 600; }
.bonus-section { margin-top: 1.2rem; padding-top: .9rem; border-top: 1px dashed var(--border); }
.bonus-label-row { display: flex; align-items: center; gap: .5rem; margin-bottom: .5rem; }
.bonus-tag { font-size: .62rem; font-weight: 800; letter-spacing: .5px; text-transform: uppercase; color: var(--bg-deep); background: var(--accent-teal); padding: .15rem .45rem; border-radius: 4px; }
.bonus-hint { font-size: .72rem; color: var(--text-muted); margin: -.2rem 0 .7rem; }
/* Editable title-weight keyword table. */
.tw-table { margin: .5rem 0 .9rem; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.tw-head, .tw-row { display: grid; grid-template-columns: 1fr 74px 28px; gap: .5rem; align-items: center; padding: .35rem .6rem; }
.tw-head { background: var(--surface-2); font-size: .66rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: .02em; }
.tw-row { border-top: 1px solid var(--border); }
.tw-row input[type=text] { width: 100%; box-sizing: border-box; padding: .28rem .5rem; font-size: .78rem; }
.tw-row input[type=number] { width: 100%; box-sizing: border-box; padding: .28rem .3rem; font-size: .78rem; text-align: center; }
.tw-rm { background: none; border: none; color: var(--alert-text); font-size: 1rem; cursor: pointer; line-height: 1; padding: 0; }
.tw-add-row { padding: .4rem .6rem; border-top: 1px solid var(--border); }
.tw-add-row button { background: none; border: 1px dashed var(--accent-cyan); color: var(--accent-cyan); font-size: .72rem; font-weight: 700; border-radius: 6px; padding: .3rem .7rem; cursor: pointer; }
.tw-add-row button:hover { background: var(--info-bg); }
.tw-note { font-size: .68rem; color: var(--text-muted); margin: -.3rem 0 .8rem; }
.preview-card { background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; padding: 1.1rem 1.3rem 1.3rem; }
.preview-head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: .15rem; }
.preview-head h5 { margin: 0; font-size: .85rem; color: var(--text); font-weight: 800; }
.preview-live-dot { display: inline-flex; align-items: center; gap: .35rem; font-size: .68rem; font-weight: 700; color: var(--ok-text); text-transform: uppercase; letter-spacing: .4px; }
.preview-live-dot span.dot { width: 6px; height: 6px; border-radius: 50%; background: var(--ok-text); display: inline-block; animation: pv-pulse 1.6s infinite; }
@keyframes pv-pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
.preview-sub { font-size: .74rem; color: var(--text-muted); margin: 0 0 1rem; }
.headline-delta { background: var(--bg-deep); border-radius: 8px; padding: .7rem .9rem; margin-bottom: 1.1rem; border-left: 4px solid var(--accent-teal); }
.headline-delta .n { font-size: 1.5rem; font-weight: 900; color: var(--text); }
.headline-delta .t { font-size: .74rem; color: var(--text-muted); margin-top: .1rem; }
.group-section { margin-bottom: 1.1rem; padding-bottom: .8rem; border-bottom: 1px solid var(--border-soft); }
.group-section:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
.group-head { display: flex; align-items: center; gap: .45rem; margin-bottom: .4rem; }
.group-head .tier-dot { width: 10px; height: 10px; border-radius: 50%; flex: 0 0 auto; }
.group-head .group-name { font-size: .8rem; font-weight: 800; color: var(--text); flex: 1; }
.group-head .group-total { font-size: .7rem; color: var(--text-muted); font-weight: 700; }
.group-wd-row { display: flex; align-items: center; gap: .5rem; padding: .22rem 0; }
.group-wd-row .wd-name { font-size: .74rem; color: var(--text-muted); min-width: 108px; flex: 0 0 auto; }
.group-wd-row .wd-bar-track { flex: 1; height: 6px; background: var(--inset); border-radius: 3px; overflow: hidden; }
.group-wd-row .wd-bar-fill { height: 100%; border-radius: 3px; transition: width .3s ease; }
.group-wd-row .wd-count { font-size: .76rem; font-weight: 800; color: var(--text); min-width: 26px; text-align: right; flex: 0 0 auto; }
.group-wd-row .wd-delta { font-size: .68rem; font-weight: 800; min-width: 44px; text-align: right; flex: 0 0 auto; }
.group-wd-row .wd-delta.up { color: var(--ok-text); margin-right: .3rem; }
.group-wd-row .wd-delta.down { color: var(--alert-text); }
.reset-link { display: block; text-align: right; font-size: .7rem; color: var(--accent-cyan); cursor: pointer; margin-top: .5rem; text-decoration: underline; }
/* Deferred recompute: Recalculate button and the greyed "is-stale" treatment. */
.recalc-btn { font-size: .72rem; font-weight: 800; padding: .3rem .8rem; border-radius: 20px; border: 1px solid var(--accent-cyan); background: transparent; color: var(--accent-cyan); cursor: pointer; transition: background .15s ease, color .15s ease, opacity .15s ease; font-family: inherit; }
.recalc-btn:disabled { border-color: var(--border); color: var(--text-muted); cursor: default; opacity: .55; }
.recalc-btn.pending { background: var(--accent-blue); border-color: var(--accent-blue); color: var(--text); animation: recalc-pulse 1.4s infinite; }
@keyframes recalc-pulse { 0%,100% { box-shadow: 0 0 0 0 rgba(27,188,243,.45); } 50% { box-shadow: 0 0 0 6px rgba(27,188,243,0); } }
.stale-note { font-size: .72rem; color: var(--amber); font-weight: 700; margin: -.4rem 0 .8rem; }
.is-stale { opacity: .4; filter: saturate(.5); transition: opacity .2s ease; pointer-events: none; }
.mass-edit-bar { background: var(--surface-2); border: 1px solid var(--border-soft); border-radius: 8px; padding: .7rem 1rem; display: flex; gap: .6rem; align-items: center; flex-wrap: wrap; margin-bottom: .8rem; }
.mass-edit-bar select, .mass-edit-bar input, .mass-edit-bar button { border: 1px solid var(--border); border-radius: 6px; padding: .35rem .6rem; font-size: .78rem; }
button, .btn { font-family: inherit; }
.mass-edit-bar button, .btn { background: var(--accent-blue); color: var(--text); border: none; border-radius: 6px; padding: .4rem .9rem; font-size: .78rem; font-weight: 700; cursor: pointer; }
.mass-edit-bar button:hover, .btn:hover { background: var(--accent-cyan); color: var(--bg-deep); }
section.workload { margin-bottom: 3rem; scroll-margin-top: 90px; }
section.workload h3 { font-size: 1.15rem; font-weight: 800; color: var(--text); margin: 0; }
.filter-chips { display: flex; gap: .5rem; flex-wrap: wrap; margin: .9rem 0 1rem; }
/* per-workload free-text search: deliberately bigger than the attribute-filter dropdowns */
.search-box-row { margin: .5rem 0 0; }
.search-box { width: 100%; max-width: 480px; background: var(--bg-deep); color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: .55rem .8rem; font-size: .85rem; box-shadow: 0 1px 2px rgba(0,0,0,.3); font-family: inherit; }
.search-box:focus { outline: none; border-color: var(--accent-cyan); box-shadow: 0 0 0 3px rgba(27,188,243,.30); }
.totals-heading { font-size: .78rem; font-weight: 700; color: var(--text); text-transform: uppercase; letter-spacing: .5px; margin: 1.1rem 0 .4rem; }
.chip { border: 1px solid var(--border); background: var(--surface-2); border-radius: 999px; padding: .32rem .85rem; font-size: .78rem; font-weight: 600; cursor: pointer; color: var(--text-muted); font-family: inherit; }
.chip:hover { color: var(--text); background: var(--bg-raise); }
.chip.active { background: var(--accent-teal); color: var(--bg-deep); border-color: var(--accent-teal); }
/* .table-wrap is the one shared scroll container for every data table: thick always-visible scrollbar, capped height,
   sticky header, sticky identity column. Wide tables scroll INSIDE it, never the page. */
.table-wrap { position: relative; overflow: auto; max-height: 62vh; max-width: 100%; border-radius: 10px; border: 1px solid var(--border-soft); box-shadow: var(--shadow); scrollbar-width: auto; scrollbar-color: var(--accent-teal) var(--bg-deep); }
.table-wrap::-webkit-scrollbar { width: 14px; height: 14px; }
.table-wrap::-webkit-scrollbar-track { background: var(--bg-deep); border-radius: 0 0 10px 10px; }
.table-wrap::-webkit-scrollbar-thumb { background-color: var(--accent-teal); border-radius: 8px; border: 3px solid var(--bg-deep); }
.table-wrap::-webkit-scrollbar-thumb:hover { background-color: var(--accent-cyan); }
table { width: 100%; border-collapse: collapse; background: var(--surface); color: var(--text); }
thead th { position: sticky; top: 0; z-index: 3; background: var(--surface-2); text-align: left; padding: .6rem .85rem; font-size: .7rem; text-transform: uppercase; letter-spacing: .5px; color: var(--text-muted); cursor: pointer; user-select: none; white-space: nowrap; border-bottom: 1px solid var(--border); }
thead th:hover { color: var(--text); }
tbody td { padding: .55rem .85rem; font-size: .82rem; border-top: 1px solid var(--border-soft); color: var(--text); white-space: nowrap; }
tbody tr:nth-child(even) td { background-image: linear-gradient(var(--zebra), var(--zebra)); }
tbody tr:hover td { background-color: var(--bg-raise); background-image: none; }
/* Sticky leftmost identity column (Object/name): never lose track of which row you are on while scrolled right. */
table thead th:first-child, table tbody td:first-child { position: sticky; left: 0; z-index: 2; background-color: var(--surface); box-shadow: 3px 0 6px -3px rgba(0,0,0,.6); }
table thead th:first-child { z-index: 4; background-color: var(--surface-2); }
tbody tr:hover td:first-child { background-color: var(--bg-raise); }
/* Column-visibility toggle: hide the noisy enrichment columns for a clean no-scroll "essentials" view. */
.table-wrap.essentials-only .col-detail { display: none; }
.table-toolbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: .5rem; margin-bottom: .5rem; }
.col-toggle { font-size: .78rem; color: var(--text-muted); display: flex; align-items: center; gap: .4rem; cursor: pointer; user-select: none; }
.col-toggle input { transform: scale(1.05); }
.col-toggle-hint { color: var(--text-muted); font-weight: 400; }
.table-scroll-shell { position: relative; max-width: 100%; }
.scroll-fade-right { position: absolute; top: 0; right: 0; bottom: 0; width: 34px; border-radius: 0 10px 10px 0; background: linear-gradient(to right, rgba(1,30,58,0), rgba(1,30,58,.95) 65%); pointer-events: none; opacity: 0; transition: opacity .2s ease; z-index: 5; }
.table-scroll-shell.has-more-right .scroll-fade-right { opacity: 1; }
.scroll-hint { font-size: .74rem; font-weight: 700; color: var(--accent-teal); white-space: nowrap; opacity: 1; transition: opacity .25s ease; }
.scroll-hint.scrolled { opacity: 0; visibility: hidden; }
.table-cap-notice { font-size: .78rem; color: var(--text-muted); padding: .5rem 0 0; }
.table-cap-notice button { border: 1px solid var(--border); border-radius: 6px; background: var(--surface-2); padding: .15rem .5rem; font-size: .76rem; cursor: pointer; color: var(--accent-teal); }
.table-cap-notice button:hover { background: var(--bg-raise); }
.badge { display: inline-block; padding: .18rem .6rem; border-radius: 999px; font-size: .7rem; font-weight: 700; white-space: nowrap; }
.badge.override { background: var(--accent-blue); color: var(--text); margin-left: .35rem; }
.tier-select { border: 1px solid var(--border); border-radius: 6px; padding: .2rem .4rem; font-size: .76rem; }
.criteria-tags { font-size: .74rem; color: var(--text-muted); white-space: normal; max-width: 240px; }
.score-bar-wrap { display: flex; align-items: center; gap: .5rem; }
.score-bar { width: 60px; height: 6px; background: var(--inset); border-radius: 4px; overflow: hidden; }
.score-bar span { display: block; height: 100%; background: var(--accent-teal); }
.row-check { transform: scale(1.1); }
.glossary dt { font-weight: 700; color: var(--text); margin-top: .8rem; }
.glossary dd { margin: .2rem 0 0; color: var(--text-muted); font-size: .88rem; }
.weights-table td, .weights-table th { padding: .4rem .7rem; font-size: .8rem; }
footer { padding: 1.75rem 3rem 3rem; font-size: .78rem; color: var(--text-muted); border-top: 1px solid var(--border); }
footer p { max-width: 900px; }
.export-bar { display: flex; gap: .6rem; margin-bottom: 1rem; }
.tabbar-actions { margin-left: auto; display: flex; align-items: center; gap: .4rem; padding: .4rem 0; flex: 0 0 auto; }
.icon-btn { background: var(--bg-card); color: var(--text); border: 1px solid var(--border); border-radius: 7px; width: 34px; height: 34px; padding: 0; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; flex: 0 0 auto; }
.icon-btn:hover { background: var(--accent-teal); color: var(--bg-deep); border-color: var(--accent-teal); }
.icon-btn svg { width: 17px; height: 17px; }
.pill-note { font-size: .78rem; color: var(--text-muted); background: var(--surface-2); border-radius: 8px; padding: .5rem .8rem; margin-bottom: 1rem; max-width: 900px; }

/* guided tour: welcome modal, spotlight overlay, positioned tooltip. Zero-dependency. */
.tour-welcome-backdrop { position: fixed; inset: 0; background: rgba(1,30,58,.80); z-index: 9500; display: flex; align-items: center; justify-content: center; padding: 1rem; }
.tour-welcome-card { background: var(--bg-navy); color: var(--text); border: 1px solid var(--accent-teal); border-radius: 14px; max-width: 480px; width: 100%; padding: 2rem; box-shadow: 0 20px 60px rgba(0,0,0,.6); }
.tour-welcome-title { font-size: 1.3rem; font-weight: 800; color: var(--text); margin-bottom: .6rem; }
.tour-welcome-body { font-size: .92rem; color: var(--text-muted); line-height: 1.55; margin-bottom: 1.3rem; }
.tour-welcome-actions { display: flex; gap: .7rem; margin-bottom: 1rem; flex-wrap: wrap; }
.tour-welcome-dontshow { font-size: .78rem; color: var(--text-muted); display: flex; align-items: center; gap: .45rem; cursor: pointer; }
.tour-overlay-backdrop { position: fixed; inset: 0; background: transparent; z-index: 9000; pointer-events: none; transition: background .15s ease; }
/* steps with no specific target dim and blur the whole page behind the centered tooltip */
.tour-overlay-backdrop.dimmed { background: rgba(1,30,58,.75); backdrop-filter: blur(3px); -webkit-backdrop-filter: blur(3px); }
.tour-spotlight { position: fixed; border-radius: 10px; box-shadow: 0 0 0 9999px rgba(1,30,58,.75); z-index: 9001; pointer-events: none; border: 2px solid var(--accent-cyan); }
.tour-tooltip { position: fixed; z-index: 9002; background: var(--bg-navy); color: var(--text); border: 1px solid var(--accent-teal); border-radius: 12px; box-shadow: 0 12px 40px rgba(0,0,0,.6); padding: 1.1rem 1.3rem; max-width: 340px; }
.tour-tooltip.centered { position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%); max-width: 460px; width: calc(100% - 2rem); }
.tour-tooltip-step { font-size: .72rem; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; color: var(--accent-teal); margin-bottom: .3rem; }
.tour-tooltip-title { font-size: 1.05rem; font-weight: 700; color: var(--text); margin-bottom: .5rem; }
.tour-tooltip-body { font-size: .88rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 1rem; }
.tour-tooltip-actions { display: flex; justify-content: space-between; align-items: center; gap: .6rem; flex-wrap: wrap; }
.tour-btn { border: none; border-radius: 7px; padding: .5rem 1rem; font-size: .82rem; font-weight: 600; cursor: pointer; font-family: inherit; }
.tour-btn-primary { background: var(--accent-teal); color: var(--bg-deep); }
.tour-btn-primary:hover { background: var(--accent-mint); }
.tour-btn-secondary { background: transparent; color: var(--text-muted); padding: .5rem .4rem; }
.tour-btn-secondary:hover { text-decoration: underline; color: var(--text); }
.tour-skip { font-size: .76rem; color: var(--text-muted); background: none; border: none; cursor: pointer; text-decoration: underline; padding: 0; }

/* RTO controls, per-group ABR vs Mass Recovery sections, exceeds-target callout, auto-suggest banner. */
.rt-preset-row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; margin-bottom: .8rem; }
.rt-preset-btn { border: 1px solid var(--border); background: var(--surface-2); border-radius: 999px; padding: .32rem .95rem; font-size: .78rem; font-weight: 700; cursor: pointer; color: var(--text-muted); font-family: inherit; }
.rt-preset-btn.active { background: var(--accent-teal); color: var(--bg-deep); border-color: var(--accent-teal); }
.rt-auto-banner { display: flex; justify-content: space-between; align-items: center; gap: 1rem; background: var(--warn-bg); border: 1px solid var(--warn-bd); border-radius: 8px; padding: .7rem 1rem; margin-bottom: 1rem; font-size: .82rem; color: var(--amber); }
.rt-auto-banner button { background: none; border: 1px solid var(--amber); color: var(--amber); border-radius: 6px; padding: .25rem .7rem; font-size: .74rem; font-weight: 700; cursor: pointer; white-space: nowrap; }
.rt-group-section { background: var(--surface); border: 1px solid var(--border-soft); border-radius: 12px; padding: 1.4rem 1.6rem; margin-bottom: 1.5rem; box-shadow: var(--shadow); }
.rt-group-section.total { border: 2px solid var(--border); }
.rt-group-section.exceeds-target { border-left: 4px solid var(--alert); }
.rt-group-section h3 { margin: 0 0 .2rem; font-size: 1.15rem; color: var(--text); font-weight: 800; }
.rt-group-section .rt-subtitle { font-size: .8rem; color: var(--text-muted); margin-bottom: 1.1rem; }
.rt-compare-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: .9rem; }
@media (max-width: 700px) { .rt-compare-grid { grid-template-columns: 1fr; } }
.rt-compare-card { border-radius: 10px; padding: 1rem 1.2rem; }
.rt-compare-card.abr { background: var(--info-bg); border: 1px solid var(--info-bd); }
.rt-compare-card.mass { background: var(--alert-bg); border: 1px solid var(--alert-bd); }
.rt-compare-card .rt-label { font-size: .72rem; text-transform: uppercase; letter-spacing: .5px; color: var(--text-muted); font-weight: 700; }
.rt-compare-card .rt-time { font-size: 1.7rem; font-weight: 800; color: var(--text); margin: .25rem 0; }
.rt-compare-card .rt-cost { font-size: .95rem; font-weight: 700; color: var(--text-muted); }
.rt-savings-bar { display: flex; justify-content: space-between; align-items: center; background: var(--ok-bg); border: 1px solid var(--ok-bd); border-radius: 8px; padding: .6rem 1rem; font-size: .85rem; color: var(--ok-text); font-weight: 600; }
.rt-shortfall-bar { display: flex; justify-content: space-between; align-items: center; background: var(--alert-bg); border: 1px solid var(--alert-bd); border-radius: 8px; padding: .6rem 1rem; font-size: .85rem; color: var(--alert-text); font-weight: 600; }
.rt-toggle { margin-top: .7rem; font-size: .78rem; color: var(--accent-cyan); cursor: pointer; user-select: none; }
.rt-detail { display: none; margin-top: .8rem; border-top: 1px solid var(--border-soft); padding-top: .8rem; font-size: .8rem; }
.rt-detail.open { display: block; }
.rt-total-note { font-size: .78rem; color: var(--text-muted); background: var(--surface-2); border-radius: 8px; padding: .6rem .9rem; margin-top: .9rem; }
.badge.exceeds-target { background: var(--alert); color: var(--bg-deep); }
/* a group with 0 objects: neutral, not alarming */
.badge.empty-tier { background: var(--mid-gray); color: var(--bg-deep); }
.rt-empty-note, .exec-hero-card .exec-empty-note { font-size: .78rem; color: var(--text-muted); background: var(--surface-2); border-radius: 8px; padding: .5rem .8rem; margin: .5rem 0 .8rem; }

/* Preview-only: locked / redacted display for anything beyond Group 1 or the whole-tenant baseline. The placeholder text is
   blurred (never the real value), plus a small tag. pv-locked-panel replaces a whole section with a static frosted pattern. */
.pv-locked-value { display: inline-block; filter: blur(4px); user-select: none; -webkit-user-select: none; }
.pv-locked-tag { display: inline-block; font-size: .6rem; font-weight: 700; letter-spacing: .3px; text-transform: uppercase; color: var(--accent-teal); margin-left: .4rem; white-space: nowrap; vertical-align: middle; }
.pv-locked-tag::before { content: "\1F512"; margin-right: .2rem; }
.pv-locked-panel { border-radius: 12px; padding: 1.8rem 1.4rem; text-align: center; background: repeating-linear-gradient(135deg, var(--bg-navy) 0, var(--bg-navy) 12px, var(--bg-card) 12px, var(--bg-card) 24px); border: 1px dashed var(--accent-teal); }
.pv-locked-panel-icon { font-size: 1.5rem; margin-bottom: .3rem; opacity: .85; }
.pv-locked-panel-title { font-weight: 800; color: var(--text); font-size: .92rem; }
.pv-locked-panel-note { font-size: .78rem; color: var(--text-muted); margin-top: .35rem; max-width: 460px; margin-left: auto; margin-right: auto; }
.pv-locked-mini { display: inline-block; padding: .1rem .4rem; border-radius: 4px; background: var(--surface-2); }

/* ---- generic building blocks the v2 tabs share (callouts, stat tiles, section headings, dividers) ---- */
.callout { background: var(--info-bg); border: 1px solid var(--info-bd); border-radius: 8px; padding: .7rem 1rem; font-size: .85rem; color: var(--text); margin: .8rem 0; }
.callout.ok { background: var(--ok-bg); border-color: var(--ok-bd); color: var(--ok-text); }
.callout.warn { background: var(--warn-bg); border-color: var(--warn-bd); color: var(--amber); }
.callout.alert { background: var(--alert-bg); border-color: var(--alert-bd); color: var(--alert-text); }
.section-divider { border: 0; border-top: 2px solid var(--accent-teal); margin: 2.2rem 0 1.2rem; opacity: .8; }
.divider-heading { display: flex; align-items: center; gap: 1rem; margin: 2.4rem 0 1rem; font-size: 1.05rem; font-weight: 800; color: var(--text); text-transform: uppercase; letter-spacing: .06em; }
.divider-heading::before, .divider-heading::after { content: ""; flex: 1 1 auto; height: 2px; background: var(--accent-teal); opacity: .7; }
.stat-tile { background: var(--surface); border: 1px solid var(--border-soft); border-radius: 12px; padding: 1rem 1.2rem; box-shadow: var(--shadow); }
.stat-tile .stat-label { font-size: .72rem; text-transform: uppercase; letter-spacing: .5px; color: var(--text-muted); font-weight: 700; }
.stat-tile .stat-value { font-size: 1.9rem; font-weight: 800; color: var(--text); line-height: 1.1; margin: .2rem 0; }
.stat-tile .stat-sub { font-size: .82rem; color: var(--text-muted); }
.text-ok { color: var(--ok-text); } .text-alert { color: var(--alert-text); } .text-warn { color: var(--amber); } .text-muted { color: var(--text-muted); }
.flag-chip { display: inline-block; font-size: .66rem; font-weight: 800; letter-spacing: .3px; text-transform: uppercase; padding: .12rem .5rem; border-radius: 999px; background: var(--alert-bg); border: 1px solid var(--alert-bd); color: var(--alert-text); white-space: nowrap; }

/* ---- PDF / print export. #print-root is hidden on screen; the print block below is the ONLY thing that shows it. ----
   The print scheme is LIGHT (white paper, dark ink) so PDFs read well and are cheap to print. The --pr-* tokens are scoped to
   #print-root so the dark screen theme never leaks into the export. */
#print-root { display: none; font-family: 'Inter', -apple-system, Arial, sans-serif;
  --pr-ink:#093565; --pr-ink-2:#2B3542; --pr-muted:#5A6672; --pr-line:#C9D2DC; --pr-soft:#F0F3F6; --pr-softer:#F7F9FB; --pr-accent:#0B8F86; --pr-alert:#C0213F;
  color: var(--pr-ink); }
.pr-page-break { page-break-before: always; }
.pr-avoid-break { page-break-inside: avoid; }
.pr-header { border-bottom: 3px solid var(--pr-ink); padding-bottom: .4rem; margin-bottom: .8rem; }
.pr-eyebrow { font-size: .68rem; font-weight: 800; letter-spacing: 1px; color: var(--pr-muted); text-transform: uppercase; }
.pr-title { font-size: 1.2rem; font-weight: 900; color: var(--pr-ink); margin: .15rem 0; }
.pr-meta { font-size: .72rem; color: var(--pr-muted); }
.pr-meta span { margin-right: 1.1rem; }
.pr-meta b { color: var(--pr-ink); }
.pr-section-title { font-size: .92rem; font-weight: 800; color: var(--pr-ink); margin: .9rem 0 .4rem; border-left: 4px solid var(--pr-accent); padding-left: .5rem; }
.pr-section-title:first-of-type { margin-top: 0; }
.pr-subnote { font-size: .7rem; color: var(--pr-muted); margin: -.25rem 0 .5rem; max-width: 90ch; }
.pr-tiles { display: grid; grid-template-columns: repeat(3, 1fr); gap: .6rem; margin-bottom: .7rem; }
.pr-tile { border: 1px solid var(--pr-line); border-radius: 8px; padding: .5rem .7rem; }
.pr-tile-label { font-size: .64rem; font-weight: 800; text-transform: uppercase; color: var(--pr-muted); letter-spacing: .4px; }
.pr-tile-value { font-size: 1.25rem; font-weight: 900; color: var(--pr-ink); margin: .1rem 0; }
.pr-tile-sub { font-size: .68rem; color: var(--pr-ink-2); }
.pr-mechanism { font-size: .78rem; background: var(--pr-soft); border-radius: 8px; padding: .5rem .8rem; margin-bottom: .8rem; }
.pr-table { width: 100%; border-collapse: collapse; font-size: .72rem; margin-bottom: .8rem; background: transparent; color: var(--pr-ink-2); }
.pr-table th, .pr-table td { border: 1px solid var(--pr-line); padding: .3rem .45rem; text-align: left; background-image: none; position: static; box-shadow: none; color: var(--pr-ink-2); background-color: transparent; white-space: normal; font-size: .72rem; }
.pr-table th { background-color: var(--pr-soft); font-weight: 800; color: var(--pr-ink); text-transform: none; letter-spacing: 0; cursor: default; }
.pr-table td.num, .pr-table th.num { text-align: right; }
.pr-table tr.total-row td { font-weight: 800; background-color: var(--pr-softer); }
.pr-note { font-size: .68rem; color: var(--pr-muted); margin-bottom: .7rem; }
.pr-footer { font-size: .64rem; color: var(--pr-muted); margin-top: .8rem; border-top: 1px solid var(--pr-line); padding-top: .35rem; }
.pr-glossary dt { font-weight: 800; color: var(--pr-ink); font-size: .78rem; margin-top: .5rem; }
.pr-glossary dd { font-size: .72rem; color: var(--pr-ink-2); margin: .1rem 0 0; }
.pr-badge { display: inline-block; font-size: .62rem; font-weight: 800; padding: .1rem .4rem; border-radius: 4px; color: #fff; margin-left: .4rem; }
.pr-badge.exceeds { background: var(--pr-alert); }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; animation-iteration-count: 1 !important; transition-duration: .001ms !important; scroll-behavior: auto !important; }
}
@media (max-width: 700px) {
  .header { padding: .8rem 1rem .8rem; }
  .header .logo { position: static; transform: none; height: 40px; }
  .header .logo svg { height: 56px; margin: -8px 0 0 -18px; }
  .tabbar { padding: 0 .5rem; }
  .tab-btn { padding: .7rem .7rem; font-size: .8rem; }
  main { padding: 1.2rem 1rem 3rem; }
  footer { padding: 1.2rem 1rem 2rem; }
  .exec-lean-tile { padding: 1.4rem 1.2rem; }
  .exec-lean-tile-value { font-size: 2.4rem; }
  .exec-lean-mechanism { padding: 1.2rem 1.2rem; }
  .recovery-ladder { padding: 1.2rem 1rem; }
  .tabbar-actions { margin-left: 0; width: 100%; padding-bottom: .5rem; }
  .pr-tiles { grid-template-columns: 1fr; }
}
/* Print: switch every token to a LIGHT scheme (also remaps the legacy names, so inline var(--navy) / var(--dark-gray) styles in
   the JS-built print HTML come out as dark ink on white). Only #print-root is shown while body.printing-* is set. */
@media print {
  html:root[data-theme], :root {
    --bg-deep:#FFFFFF; --bg-navy:#FFFFFF; --bg-card:#F0F3F6; --bg-raise:#F0F3F6;
    --text:#093565; --text-muted:#2B3542; --text-dim:#5A6672; --border:#C9D2DC; --border-soft:#DCE3EA;
    --accent-teal:#0B8F86; --accent-cyan:#0A6FA8; --accent-blue:#0C67DD; --accent-mint:#0B8F86; --accent-lilac:#7A4A9A; --accent-purple:#5B2DB5;
    --alert:#C0213F; --warn:#C24A1B; --ok:#0A7A4F; --ok-text:#0A6B4E; --amber:#8A5A00; --alert-text:#A5222B;
    --shadow:none; --shadow-lg:none; --hatch-base:#D7DCE1; --hatch-stripe:rgba(255,255,255,.55); --inset:#E7EBEE; --zebra:transparent;
    --surface:#FFFFFF; --surface-2:#F0F3F6;
    --teal:#0B8F86; --cyan:#0A6FA8; --green:#0A6B4E; --blue:#0C67DD; --navy:#093565; --navy-dark:#0A2E57; --yellow:#8A5A00;
    --mid-gray:#8A97A6; --dark-gray:#5A6672; --white:#FFFFFF; --red-target:#C0213F;
    color-scheme: light;
  }
  html { font-size: 10pt; }
  @page { size: letter; margin: 0.55in; }
  body { background: #fff; color: #093565; }
  body.printing-summary > *:not(#print-root),
  body.printing-full > *:not(#print-root) { display: none !important; }
  body.printing-summary #print-root,
  body.printing-full #print-root { display: block !important; }
  * { box-shadow: none !important; text-shadow: none !important; }
}

/* ===== v2.0 shared components (accordion, info bubble, sortable headers, unit toggle, banners) =====
   Colors come from the theme tokens defined in ReportCss.css (:root). Do not hard-code hex here. */
.v2-badge { display:inline-block; margin-left:.5rem; padding:.05rem .5rem; border-radius:999px; background:var(--accent-teal, #04CAB9); color:var(--bg-deep, #011E3A); font-weight:800; font-size:.7rem; letter-spacing:.5px; vertical-align:middle; }
.unit-toggle { display:inline-flex; border:1px solid var(--border, #3a4a80); border-radius:6px; overflow:hidden; vertical-align:middle; margin-left:.35rem; }
.unit-btn { background:transparent; color:inherit; border:0; padding:.12rem .6rem; font:inherit; font-weight:700; cursor:pointer; }
.unit-btn.active { background:var(--accent-teal, #04CAB9); color:var(--bg-deep, #011E3A); }
.unit-btn:focus-visible, .info-btn:focus-visible, .acc-head:focus-visible, .sortable-th:focus-visible { outline:2px solid var(--accent-cyan, #1BBCF3); outline-offset:2px; }

/* sortable headers */
th.sortable-th { cursor:pointer; user-select:none; white-space:nowrap; }
th.sortable-th::after { content:"\2195"; opacity:.35; margin-left:.35rem; font-size:.8em; }
th.sortable-th.sort-asc::after { content:"\25B2"; opacity:1; }
th.sortable-th.sort-desc::after { content:"\25BC"; opacity:1; }

/* accordions */
.acc { border:1px solid var(--border, #3a4a80); border-radius:10px; margin:.6rem 0; overflow:hidden; }
.acc-head { width:100%; display:flex; align-items:center; gap:.75rem; padding:.85rem 1rem; background:var(--bg-card, #122861); color:var(--text, #fff); border:0; cursor:pointer; text-align:left; font:inherit; }
.acc-head:hover { filter:brightness(1.12); }
.acc-chev { transition:transform .15s ease; display:inline-block; flex:0 0 auto; }
.acc.open > .acc-head .acc-chev { transform:rotate(90deg); }
.acc-title { font-weight:700; flex:0 0 auto; }
.acc-summary { margin-left:auto; display:flex; flex-wrap:wrap; gap:.4rem 1.1rem; justify-content:flex-end; color:var(--text-muted, #D9D9D9); font-size:.9rem; }
.acc-body { padding:1rem; background:var(--bg-navy, #0A2547); }
.acc-body[hidden] { display:none; }

/* info bubble */
.info-btn { display:inline-flex; align-items:center; justify-content:center; width:1.15rem; height:1.15rem; border-radius:50%; border:1px solid var(--accent-cyan, #1BBCF3); background:transparent; color:var(--accent-cyan, #1BBCF3); font:700 .72rem/1 Georgia, serif; font-style:italic; cursor:pointer; margin-left:.35rem; padding:0; vertical-align:middle; }
.info-btn:hover { background:var(--accent-cyan, #1BBCF3); color:var(--bg-deep, #011E3A); }
.info-pop { position:absolute; z-index:1000; background:var(--bg-deep, #011E3A); color:var(--text, #fff); border:1px solid var(--accent-cyan, #1BBCF3); border-radius:10px; box-shadow:0 8px 30px rgba(0,0,0,.5); padding:.9rem 1rem; font-size:.9rem; line-height:1.45; }
.info-pop-title { font-weight:800; margin-bottom:.4rem; padding-right:1.5rem; position:relative; }
.info-pop-close { position:absolute; right:-.25rem; top:-.35rem; background:transparent; border:0; color:var(--text-muted, #D9D9D9); font-size:1.3rem; cursor:pointer; }
.info-pop-body p { margin:.4rem 0; }

/* linked summaries */
[data-link] { cursor:pointer; }
[data-link]:hover { filter:brightness(1.1); }
.link-flash { animation:linkflash 1.6s ease; }
@keyframes linkflash { 0%,60% { box-shadow:0 0 0 3px var(--accent-teal, #04CAB9); } 100% { box-shadow:0 0 0 0 transparent; } }
.linkout { color:var(--accent-teal, #04CAB9); text-decoration:underline; cursor:pointer; font-weight:600; }

/* cost avoided prompt */
.cost-prompt { color:var(--text-muted, #D9D9D9); font-style:italic; }

/* preview chrome */
.pv-banner { background:var(--bg-card, #122861); border:1px solid var(--accent-teal, #04CAB9); border-left:5px solid var(--accent-teal, #04CAB9); border-radius:8px; padding:.7rem 1rem; margin:0 0 1rem; font-size:.9rem; line-height:1.45; }
.pv-banner a, .pv-locked-panel a { color:var(--accent-teal, #04CAB9); font-weight:700; }

/* ===== v2.0 Executive Summary + Report tab (WP-B). Colors via theme tokens only. ===== */
.report-intro { color:var(--text-muted, #D9D9D9); font-size:.9rem; max-width:70ch; margin:-1rem 0 1.5rem; }
.ex2-grid { display:grid; grid-template-columns:repeat(12, minmax(0, 1fr)); gap:1.1rem; margin:0 0 1.4rem; }
.ex2-block { grid-column:span 6; background:var(--bg-navy, #0A2547); border:1px solid var(--border, #3a4a80); border-radius:14px; padding:1.2rem 1.4rem; min-width:0; }
.ex2-hero { grid-column:span 12; border-left:6px solid var(--accent-teal, #04CAB9); background:var(--bg-card, #122861); }
.ex2-tile { grid-column:span 6; }
.ex2-wide { grid-column:span 12; }
@media (max-width:900px) { .ex2-block, .ex2-tile { grid-column:span 12; } }
.ex2-eyebrow { display:flex; align-items:center; flex-wrap:wrap; gap:.4rem .7rem; font-size:.74rem; font-weight:800; letter-spacing:.7px; text-transform:uppercase; color:var(--accent-teal, #04CAB9); margin:0 0 .7rem; }
.ex2-details { margin-left:auto; font-size:.78rem; text-transform:none; letter-spacing:0; }
.ex2-headline { font-size:1.55rem; line-height:1.35; font-weight:600; color:var(--text, #fff); max-width:60ch; }
.ex2-headline b { color:var(--accent-mint, #BCFFFB); font-weight:800; }
.ex2-sub, .ex2-note { font-size:.88rem; color:var(--text-muted, #D9D9D9); margin-top:.7rem; line-height:1.45; }
.ex2-lead { font-size:.98rem; color:var(--text, #fff); margin:0 0 .9rem; max-width:80ch; line-height:1.5; }
.ex2-big { font-size:3rem; font-weight:900; line-height:1.05; color:var(--text, #fff); margin:.1rem 0 .4rem; }
.ex2-tile-sub { color:var(--text-muted, #D9D9D9); font-size:.95rem; }
.ex2-tile-sub b { color:var(--text, #fff); }
.ex2-dollars { font-size:1.05rem; margin:0 0 .7rem; color:var(--text, #fff); }
.ex2-money { font-size:1.6rem; font-weight:800; color:var(--accent-mint, #BCFFFB); }
.ex2-smalls { border-top:1px solid var(--border, #3a4a80); padding-top:.6rem; margin-top:.4rem; }
.ex2-small-row { display:flex; justify-content:space-between; gap:1rem; font-size:.88rem; color:var(--text-muted, #D9D9D9); padding:.15rem 0; }
.ex2-small-row b { color:var(--text, #fff); }
.ex2-rate { display:flex; align-items:center; flex-wrap:wrap; gap:.5rem; margin-top:.8rem; font-size:.82rem; color:var(--text-muted, #D9D9D9); }
.ex2-rate input { width:7.5rem; background:var(--bg-deep, #011E3A); color:var(--text, #fff); border:1px solid var(--border, #3a4a80); border-radius:6px; padding:.3rem .5rem; font:inherit; }
.ex2-rate input:focus-visible { outline:2px solid var(--accent-cyan, #1BBCF3); outline-offset:1px; }
.ex2-locked { display:inline-block; }
/* concentration bars */
.ex2-conc { display:grid; gap:.55rem; margin-bottom:.8rem; }
.ex2-conc-row { display:grid; grid-template-columns:7.5rem 1fr 3rem; grid-template-areas:"label track val" ". detail detail"; gap:.15rem .7rem; align-items:center; }
.ex2-conc-label { grid-area:label; font-size:.85rem; font-weight:700; }
.ex2-conc-track { grid-area:track; height:14px; background:var(--bg-deep, #011E3A); border-radius:7px; overflow:hidden; }
.ex2-conc-track span { display:block; height:100%; background:var(--accent-teal, #04CAB9); border-radius:7px; }
.ex2-conc-val { grid-area:val; font-weight:800; text-align:right; }
.ex2-conc-detail { grid-area:detail; font-size:.74rem; color:var(--text-muted, #D9D9D9); }
/* tables, lists */
.ex2-table { width:100%; border-collapse:collapse; font-size:.88rem; }
.ex2-table th { text-align:left; padding:.45rem .7rem; background:var(--bg-card, #122861); color:var(--text, #fff); border-bottom:1px solid var(--border, #3a4a80); font-size:.74rem; text-transform:uppercase; letter-spacing:.4px; }
.ex2-table td { padding:.45rem .7rem; border-bottom:1px solid var(--border, #3a4a80); color:var(--text, #fff); vertical-align:top; }
.ex2-two { display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:1.2rem; }
.ex2-mini-title { font-weight:800; font-size:.85rem; margin:0 0 .4rem; color:var(--text, #fff); }
.ex2-btn { margin-top:1rem; background:var(--accent-teal, #04CAB9); color:var(--bg-deep, #011E3A); border:0; border-radius:8px; padding:.55rem 1.1rem; font:inherit; font-weight:800; cursor:pointer; }
.ex2-btn:hover { filter:brightness(1.1); }
.ex2-btn:focus-visible { outline:2px solid var(--accent-cyan, #1BBCF3); outline-offset:2px; }
.ex2-badge { display:inline-block; padding:.12rem .6rem; border-radius:999px; font-size:.74rem; font-weight:800; white-space:nowrap; }
.ex2-badge.ok { background:var(--ok, #00B46E); color:var(--bg-deep, #011E3A); }
.ex2-badge.bad { background:var(--alert, #FB3A73); color:var(--text, #fff); }
.ex2-badge.neutral { background:var(--bg-card, #122861); color:var(--text, #fff); border:1px solid var(--border, #3a4a80); }
.ex2-gap { margin-top:1rem; border-left:4px solid var(--alert, #FB3A73); padding:.3rem 0 .3rem 1rem; }
.ex2-gap ul { margin:.4rem 0 0 1.1rem; padding:0; font-size:.9rem; line-height:1.5; }
.ex2-risks, .ex2-next { margin:0; padding-left:1.2rem; font-size:.92rem; line-height:1.55; }
.ex2-risk-title { font-weight:800; color:var(--accent-teal, #04CAB9); text-decoration:underline; cursor:pointer; }
.ex2-risk-detail { color:var(--text-muted, #D9D9D9); font-size:.84rem; margin:.1rem 0 .5rem; }
.ex2-wait-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(130px, 1fr)); gap:.8rem; margin-bottom:.6rem; }
.ex2-wait-label { font-size:.74rem; text-transform:uppercase; letter-spacing:.4px; color:var(--text-muted, #D9D9D9); }
.ex2-wait-val { font-size:1.6rem; font-weight:800; }
.ex2-wait-val.ok { color:var(--accent-teal, #04CAB9); }
.ex2-mechanism { background:var(--bg-card, #122861); border-radius:14px; padding:1.1rem 1.4rem; font-size:.92rem; line-height:1.55; color:var(--text, #fff); }
.ex2-mechanism b { color:var(--accent-mint, #BCFFFB); }
.ex2-dot { width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:.35rem; }
.ex2-card-sub, .ex2-cell-sub { font-size:.8rem; color:var(--text-muted, #D9D9D9); margin-top:.2rem; }
/* Report-tab accordions sit directly under the page background */
#report-low-activity, #report-data-quality { margin-top:1.4rem; }

/* v2.0 Report tab */
#report-verdict, #report-case, #report-by-group, #report-drivers, #report-sensitivity, #report-concentration, #report-group-overview, #report-decisions { margin-bottom:1.8rem; }
#panel-report h2 { margin:1.4rem 0 .7rem; }
#panel-report > h2:first-child { margin-top:0; }
.rep-verdict { background:var(--bg-navy, #0A2547); border:1px solid var(--border, rgba(255,255,255,.18)); border-left:4px solid var(--accent-teal, #04CAB9); border-radius:14px; padding:1.2rem 1.5rem; }
.rep-verdict-text { font-size:1.15rem; line-height:1.5; }
.rep-verdict-text b { color:var(--accent-mint, #BCFFFB); }
.rep-confidence { margin-top:.8rem; font-size:.85rem; color:var(--text-muted, #D9D9D9); display:flex; flex-wrap:wrap; gap:.5rem; align-items:center; cursor:pointer; }
.rep-conf-badge { font-weight:700; border-radius:999px; padding:.15rem .7rem; background:var(--bg-card, #122861); }
.rep-conf-badge.high { color:var(--ok, #00B46E); }
.rep-conf-badge.moderate { color:var(--warn, #FF5A2E); }
.rep-conf-badge.limited { color:var(--alert, #FB3A73); }
.rep-case { display:grid; grid-template-columns:repeat(auto-fit, minmax(230px, 1fr)); gap:.9rem; }
.rep-step { display:flex; gap:.8rem; background:var(--bg-card, #122861); border-radius:14px; padding:1rem 1.1rem; cursor:pointer; }
.rep-step:hover { outline:1px solid var(--accent-teal, #04CAB9); }
.rep-step-n { flex:0 0 auto; width:1.9rem; height:1.9rem; border-radius:50%; background:var(--accent-teal, #04CAB9); color:var(--bg-deep, #011E3A); font-weight:800; display:flex; align-items:center; justify-content:center; }
.rep-step-title { font-size:.75rem; letter-spacing:.06em; text-transform:uppercase; color:var(--accent-teal, #04CAB9); font-weight:700; margin-bottom:.25rem; }
.rep-step-text { font-size:.92rem; line-height:1.45; }
.rep-table td, .rep-table th { white-space:nowrap; }
.rep-lock-note { color:var(--text-muted, #D9D9D9); font-size:.8rem; }
.rep-drivers { display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:.9rem; }
.rep-driver { background:var(--bg-card, #122861); border-radius:14px; padding:.9rem 1.1rem; }
.rep-driver[data-link] { cursor:pointer; }
.rep-driver-label { font-size:.75rem; letter-spacing:.05em; text-transform:uppercase; color:var(--text-muted, #D9D9D9); }
.rep-driver-val { font-size:1.35rem; font-weight:800; margin:.2rem 0; }
.rep-driver-note { font-size:.8rem; color:var(--text-muted, #D9D9D9); }
.rep-live { margin-top:.9rem; display:flex; flex-wrap:wrap; gap:1.5rem; align-items:center; }
.rep-current td { background:rgba(4,202,185,.12); }
.rep-decisions { list-style:none; padding:0; margin:0; display:grid; gap:.6rem; }
.rep-decisions li { display:flex; gap:.7rem; align-items:flex-start; background:var(--bg-card, #122861); border-radius:12px; padding:.8rem 1rem; }
.rep-check { flex:0 0 auto; width:1.05rem; height:1.05rem; border:2px solid var(--accent-teal, #04CAB9); border-radius:4px; margin-top:.15rem; }

/* v2.0 simplified Executive Summary */
.xs-hero { display:grid; grid-template-columns:repeat(3, 1fr); gap:16px; }
.xs-tile { background:var(--bg-card, #122861); border-radius:18px; padding:26px 24px; cursor:default; }
.xs-tile[data-link] { cursor:pointer; }
.xs-big { font-size:clamp(2.4rem, 5vw, 3.6rem); font-weight:800; line-height:1; letter-spacing:-.02em; }
.xs-teal .xs-big { color:var(--accent-teal, #04CAB9); }
.xs-mint .xs-big { color:var(--accent-mint, #BCFFFB); }
.xs-cap { margin-top:10px; font-size:.95rem; color:var(--text-muted, #D9D9D9); line-height:1.4; }
.xs-cap b { color:var(--text, #fff); }
.xs-money { margin-top:8px; font-size:1.2rem; font-weight:800; color:var(--accent-mint, #BCFFFB); }
.xs-rate { display:block; margin-top:10px; font-size:.85rem; color:var(--text-muted, #D9D9D9); }
.xs-rate input { background:var(--bg-navy, #0A2547); border:1px solid var(--border, #3A4A80); border-radius:8px; color:var(--text, #fff); padding:.35rem .6rem; width:120px; margin-left:.3rem; }
.xs-ladder { background:var(--bg-card, #122861); border-radius:18px; padding:24px 24px 20px; margin-top:16px; }
.xs-ladder-h { font-size:.8rem; letter-spacing:.08em; text-transform:uppercase; color:var(--accent-teal, #04CAB9); font-weight:700; display:flex; flex-wrap:wrap; gap:.8rem; align-items:baseline; }
.xs-ladder-sub { text-transform:none; letter-spacing:0; color:var(--text-muted, #D9D9D9); font-weight:400; }
.xs-steps { display:grid; grid-template-columns:1fr auto 1fr auto 1fr; gap:10px; align-items:stretch; margin-top:16px; }
.xs-step { background:var(--bg-navy, #0A2547); border-radius:14px; padding:16px 18px; border-top:5px solid var(--grey-tier, #8FA0BF); }
.xs-step.s1 { border-top-color:var(--accent-teal, #04CAB9); }
.xs-step.s2 { border-top-color:var(--accent-purple, #8242E8); }
.xs-step.s3 { border-top-color:#8FA0BF; background-image:repeating-linear-gradient(135deg, rgba(143,160,191,.10) 0 6px, transparent 6px 12px); }
.xs-step-n { display:inline-flex; width:1.6rem; height:1.6rem; border-radius:50%; background:var(--text-muted, #D9D9D9); color:var(--bg-deep, #011E3A); font-weight:800; font-size:.85rem; align-items:center; justify-content:center; margin-right:.5rem; }
.xs-step-t { display:inline; font-size:.85rem; font-weight:700; text-transform:uppercase; letter-spacing:.05em; }
.xs-step-big { font-size:2.3rem; font-weight:800; margin-top:8px; line-height:1.1; }
.xs-step.s1 .xs-step-big { color:var(--accent-teal, #04CAB9); }
.xs-step-sub { font-size:.85rem; color:var(--text-muted, #D9D9D9); margin-top:4px; }
.xs-step-sub span { color:var(--text, #fff); font-weight:600; }
.xs-arrow { align-self:center; font-size:1.6rem; color:var(--text-muted, #D9D9D9); }
.xs-ladder-line { margin-top:14px; font-size:.95rem; color:var(--text-muted, #D9D9D9); }
.xs-ladder-line b { color:var(--text, #fff); }
.xs-pills { display:grid; grid-template-columns:repeat(2, 1fr); gap:16px; margin-top:16px; }
.xs-pill { background:var(--bg-card, #122861); border-radius:18px; padding:18px 22px; cursor:pointer; }
.xs-pill.warn { border-left:5px solid var(--warn, #FF5A2E); }
.xs-pill-big { font-size:1.7rem; font-weight:800; }
.xs-pill-sub { font-size:.88rem; color:var(--text-muted, #D9D9D9); margin-top:3px; }
.xs-foot { margin-top:18px; display:flex; justify-content:space-between; flex-wrap:wrap; gap:10px; font-size:.85rem; color:var(--text-muted, #D9D9D9); }
@media (max-width:860px) { .xs-hero, .xs-pills { grid-template-columns:1fr; } .xs-steps { grid-template-columns:1fr; } .xs-arrow { transform:rotate(90deg); justify-self:center; } }

/* Recovery calendar (Report tab) */
.cal { display:grid; grid-template-columns:repeat(auto-fit, minmax(250px, 1fr)); gap:16px; }
.cal-mon { background:var(--bg-card, #122861); border-radius:14px; padding:12px; }
.cal-mon h4 { margin:0 0 8px; font-size:.9rem; }
.cal-g { display:grid; grid-template-columns:repeat(7, 1fr); gap:3px; }
.cal-h { font-size:.62rem; color:var(--text-muted, #D9D9D9); text-align:center; }
.cal-cell { position:relative; min-height:var(--ch, 30px); border-radius:6px; background:var(--bg-navy, #0A2547); font-size:.68rem; padding:2px 4px; color:var(--text-muted, #D9D9D9); overflow:hidden; }
.cal-cell.in { color:#fff; font-weight:600; text-shadow:0 1px 2px rgba(0,0,0,.5); }
.cal-cell.blank { background:transparent; }
.cal-cell.today { outline:2px solid #fff; outline-offset:1px; }
.cal-cell.done { outline:2px solid var(--accent-mint, #BCFFFB); outline-offset:1px; }
.cal-tag { position:absolute; bottom:2px; left:4px; right:2px; font-size:.58rem; font-weight:800; letter-spacing:.04em; }
.cal-tag.dtag { color:var(--accent-mint, #BCFFFB); }
.cal-mon.fadeout { -webkit-mask-image:linear-gradient(to bottom, #000 30%, transparent 100%); mask-image:linear-gradient(to bottom, #000 30%, transparent 100%); }
.cal-mon.fadein { -webkit-mask-image:linear-gradient(to bottom, transparent 0%, #000 70%); mask-image:linear-gradient(to bottom, transparent 0%, #000 70%); }
.cal-gap { grid-column:1/-1; text-align:center; padding:6px 10px 2px; color:var(--text-muted, #D9D9D9); font-size:.9rem; }
.cal-gap-n { font-size:1.5rem; font-weight:800; color:#fff; }
.cal-dots { letter-spacing:.5em; color:var(--accent-teal, #04CAB9); font-size:1.2rem; }
.cal-legend { display:flex; flex-wrap:wrap; gap:14px; font-size:.8rem; color:var(--text-muted, #D9D9D9); margin-top:10px; }
.cal-legend i { display:inline-block; width:11px; height:11px; border-radius:3px; margin-right:5px; vertical-align:-1px; }
.cal-ends { display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; margin-top:10px; font-size:.85rem; color:var(--text-muted, #D9D9D9); }
.cal-ends b { color:#fff; }
#report-calendar, #report-g1list, #report-rto, #report-risks { margin-bottom:1.8rem; }

/* Recovery Playbook tab */
.pb-note { background:var(--bg-card, #122861); border-left:4px solid var(--accent-teal, #04CAB9); border-radius:10px; padding:.8rem 1.1rem; margin:0 0 1.2rem; font-size:.92rem; }
.pb-steps { display:grid; gap:12px; margin-bottom:1.6rem; }
.pb-step { display:flex; gap:14px; background:var(--bg-card, #122861); border-radius:14px; padding:16px 18px; }
.pb-n { flex:0 0 auto; width:2.2rem; height:2.2rem; border-radius:50%; background:var(--accent-teal, #04CAB9); color:var(--bg-deep, #011E3A); font-weight:800; display:flex; align-items:center; justify-content:center; }
.pb-title { font-size:1.05rem; font-weight:700; margin-bottom:.3rem; }
.pb-tag { font-size:.7rem; text-transform:uppercase; letter-spacing:.06em; background:var(--bg-navy, #0A2547); border-radius:999px; padding:.15rem .6rem; color:var(--accent-mint, #BCFFFB); margin-left:.4rem; vertical-align:middle; }
.pb-body p { margin:.35rem 0; font-size:.92rem; line-height:1.5; }
.pb-sub { margin:.3rem 0 .3rem 1.2rem; padding:0; font-size:.92rem; line-height:1.5; }
.pb-meta { margin-top:.6rem; padding-top:.5rem; border-top:1px solid var(--border, #3A4A80); font-size:.88rem; color:var(--text-muted, #D9D9D9); }
.pb-meta b { color:#fff; }
.pb-cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:14px; margin-bottom:1.4rem; }
.pb-card { background:var(--bg-card, #122861); border-radius:14px; padding:16px 18px; }
.pb-card-t { font-weight:700; margin-bottom:.4rem; color:var(--accent-mint, #BCFFFB); }
.pb-card p { margin:.4rem 0; font-size:.9rem; line-height:1.5; }
.pb-small { font-size:.8rem !important; color:var(--text-muted, #D9D9D9); }
.pb-locknote { font-size:.8rem; color:var(--text-muted, #D9D9D9); }

/* v2.0 exec recovery timeline: two bars on one scale */
.xt-row { margin-top:16px; }
.xt-head { display:flex; align-items:center; gap:18px; margin-bottom:8px; flex-wrap:wrap; }
.xt-big { font-size:clamp(2rem, 4vw, 2.8rem); font-weight:800; line-height:1; min-width:9.5rem; }
.xt-big.g1 { color:var(--accent-teal, #04CAB9); }
.xt-big.g2 { color:var(--g2t, #B993F5); }
.xt-big.g3 { color:var(--accent-lilac, #F4C9F4); }
.xt-lab { font-size:.9rem; color:var(--text-muted, #D9D9D9); line-height:1.4; }
.xt-lab b { color:var(--text, #fff); font-size:1rem; }
.xt-bar { height:34px; border-radius:10px; background:var(--bg-navy, #0A2547); overflow:hidden; }
.xt-fill { height:100%; min-width:8px; background:var(--accent-teal, #04CAB9); border-radius:10px; }
.xt-fill.grey { width:100%; background:repeating-linear-gradient(135deg, #6F7FA3 0 4px, #5B6B90 4px 8px); }

/* Light theme: navy headings/numbers like the 3.x report; darker bar tracks give the timeline a visible boundary */
:root:not([data-theme="dark"]) h2, :root:not([data-theme="dark"]) .xs-big { color:#093565; }
:root:not([data-theme="dark"]) .xs-mint .xs-big, :root:not([data-theme="dark"]) .xs-money { color:#0F6B4F; }
:root:not([data-theme="dark"]) .xs-teal { border-top:5px solid #0E5BCF; }
:root:not([data-theme="dark"]) .xs-mint { border-top:5px solid #0F6B4F; }
:root:not([data-theme="dark"]) .xt-bar { background:#C3CCD7; }
:root:not([data-theme="dark"]) .xs-ladder-h { color:#093565; }

/* v1-style recovery ladder on the Executive tab */
.xs-ladder-h2 { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:baseline; gap:.8rem; margin-bottom:.2rem; }
section.recovery-ladder#exec-ladder { margin-top:16px; }

/* Spread ladder: vertical lines instead of dots, tail into mass recovery */
.rl-line { position:absolute; top:33px; width:4px; height:28px; border-radius:2px; transform:translateX(-50%); z-index:2; box-shadow:0 0 0 2px var(--surface, #fff); }
.rl-break { position:absolute; top:38px; transform:translateX(-50%); font-size:1.1rem; font-weight:800; color:var(--text-dim, #6C7576); background:var(--surface, #fff); padding:0 4px; z-index:3; line-height:1; }
.rl-seg.tail { background-color:var(--hatch-base, #D7DCE1); background-image:repeating-linear-gradient(45deg, var(--hatch-stripe, rgba(255,255,255,.55)) 0, var(--hatch-stripe, rgba(255,255,255,.55)) 6px, transparent 6px, transparent 12px); }
.rl-seg.tail.g13 { background-color:#8793A6; }
.rl-seg.tail.g4 { background-color:#F5A524; }
.rl-seg.tail.g4, .rl-seg.tail.g13 { background-image:repeating-linear-gradient(45deg, rgba(255,255,255,.35) 0, rgba(255,255,255,.35) 6px, transparent 6px, transparent 12px); }
:root[data-theme="dark"] { --g4-text:#FFC25A; }

.rl-seglabel { position:absolute; top:58px; width:150px; transform:translateX(-50%); text-align:center; }
.rl-seglabel-t { display:inline-block; border-top:2px solid #8793A6; padding-top:6px; font-size:.76rem; font-weight:700; color:var(--text-muted, #D9D9D9); line-height:1.25; }

/* Long recoveries: one row - month 1, month 2 fading out, a gap, then the completion month fading back in */
.cal.long { display:flex; flex-wrap:wrap; align-items:stretch; gap:12px; }
.cal.long .cal-mon { flex:1 1 230px; max-width:340px; }
.cal.long .cal-gap { flex:0 1 190px; align-self:center; padding:6px 4px; }
.cal.long .cal-mon.fadeout { -webkit-mask-image:linear-gradient(to right, #000 15%, transparent 100%); mask-image:linear-gradient(to right, #000 15%, transparent 100%); }
.cal.long .cal-mon.fadein { -webkit-mask-image:linear-gradient(to right, transparent 0%, #000 85%); mask-image:linear-gradient(to right, transparent 0%, #000 85%); }
/* Light theme: these were hard-coded white */
:root:not([data-theme="dark"]) .cal-gap-n { color:#093565; }
:root:not([data-theme="dark"]) .cal-ends b { color:#093565; }
:root:not([data-theme="dark"]) .pb-meta b { color:#093565; }

/* Editable fields: tinted "fill me in" cells (pale amber well, amber border) so they stand out from the panel */
:root:not([data-theme="dark"]) input[type=number], :root:not([data-theme="dark"]) input[type=text], :root:not([data-theme="dark"]) input[type=search], :root:not([data-theme="dark"]) select, :root:not([data-theme="dark"]) textarea {
  background:#FFF3C4; border:2px solid #B7791F; box-shadow: inset 0 1px 2px rgba(120,70,0,.18); color:#093565; font-weight:700; }
:root:not([data-theme="dark"]) input[type=number]:hover, :root:not([data-theme="dark"]) input[type=text]:hover, :root:not([data-theme="dark"]) select:hover { border-color:#8A5A10; background:#FFEFAE; }
:root:not([data-theme="dark"]) input[type=number]:focus, :root:not([data-theme="dark"]) input[type=text]:focus, :root:not([data-theme="dark"]) select:focus, :root:not([data-theme="dark"]) textarea:focus { background:#FFFFFF; border-color:#0A6764; box-shadow:0 0 0 3px rgba(10,103,100,.28); outline:none; }
:root[data-theme="dark"] input[type=number], :root[data-theme="dark"] input[type=text], :root[data-theme="dark"] select { border:2px solid #F2B84B; background:#3A2F10; color:#FFF3C4; font-weight:700; }
:root[data-theme="dark"] input[type=number]:focus, :root[data-theme="dark"] input[type=text]:focus, :root[data-theme="dark"] select:focus { border-color:#04CAB9; box-shadow:0 0 0 3px rgba(4,202,185,.3); outline:none; }
.control-row input[type=number] { text-align:center; }
@media print { input[type=number], input[type=text], select { border:1px solid #999 !important; box-shadow:none !important; background:#fff !important; } }

/* Ladder: a label held back by the right edge is anchored to its own line and reads leftward from it */
.rl-flag.end { transform:translateX(-100%); text-align:right; }
.rl-flag.end .rl-time, .rl-flag.end .rl-label { text-align:right; }

/* Compact ladder (5+ groups): numbered ticks for intermediate groups, tighter flags */
.rl-tickn { position:absolute; top:64px; transform:translateX(-50%); font-size:.68rem; font-weight:800; color:var(--text-muted, #4A5560); }
.rl-flag.compact .rl-time { font-size:.9rem; }
.rl-flag.compact .rl-label { font-size:.7rem; }

.rto-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); column-gap:1.5rem; }
.rl-flag.start { transform:none; text-align:left; }
.rl-flag.start .rl-time, .rl-flag.start .rl-label { text-align:left; }

/* ===== v2.0 Groups & Recovery Model tab (WP-A). Colors come from theme tokens only. ===== */
.tab-lead { color:var(--text-muted, #D9D9D9); max-width:80ch; margin:-.6rem 0 1.2rem; }
.grp-section-title { margin:1.6rem 0 .4rem; }
.grp-section { margin-top:.5rem; }
.tier-dot { display:inline-block; width:.7rem; height:.7rem; border-radius:50%; margin-right:.45rem; vertical-align:middle; }
.acc-sub { font-weight:400; color:var(--text-muted, #D9D9D9); font-size:.82rem; margin-left:.35rem; }

/* headline */
.grp-headline { margin-top:1rem; }
.hl-grid { display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin:.6rem 0 1rem; }
@media (max-width:760px) { .hl-grid { grid-template-columns:1fr; } }
.hl-card { background:var(--bg-card, #122861); border:1px solid var(--border, #3a4a80); border-radius:12px; padding:1.1rem 1.3rem; }
.hl-time { border-left:5px solid var(--accent-teal, #04CAB9); }
.hl-money { border-left:5px solid var(--accent-cyan, #1BBCF3); }
.hl-label { font-size:.82rem; letter-spacing:.4px; text-transform:uppercase; color:var(--text-muted, #D9D9D9); font-weight:700; }
.hl-big { font-size:2.6rem; line-height:1.15; font-weight:800; color:var(--text, #fff); margin:.25rem 0; }
.hl-sub { color:var(--text-muted, #D9D9D9); font-size:.92rem; }
.hl-smalls { margin-top:.8rem; border-top:1px solid var(--border, #3a4a80); padding-top:.6rem; }
.hl-small { display:flex; justify-content:space-between; gap:1rem; font-size:.95rem; padding:.15rem 0; }
.hl-small-label { color:var(--text-muted, #D9D9D9); }
.hl-wl-table tr[data-link]:hover td { background:var(--bg-card, #122861); }
.hl-wl-table .total-row td { border-top:2px solid var(--border, #3a4a80); }
.grp-exclusion-note { display:flex; justify-content:space-between; align-items:center; gap:1rem; flex-wrap:wrap; background:var(--bg-card, #122861); border:1px solid var(--warn, #FF5A2E); border-radius:8px; padding:.6rem .9rem; margin:0 0 1rem; font-size:.9rem; }
.grp-exclusion-note button { background:transparent; color:var(--text, #fff); border:1px solid var(--accent-teal, #04CAB9); border-radius:6px; padding:.25rem .8rem; cursor:pointer; font:inherit; font-weight:700; }
.grp-exclusion-note button:hover { background:var(--accent-teal, #04CAB9); color:var(--bg-deep, #011E3A); }

/* divider between "by group" and "by workload" */
.grp-divider { display:flex; align-items:center; gap:1rem; margin:2.4rem 0 1rem; color:var(--accent-teal, #04CAB9); font-weight:800; font-size:1.05rem; letter-spacing:.3px; }
.grp-divider::before, .grp-divider::after { content:""; flex:1; border-top:2px solid var(--accent-teal, #04CAB9); opacity:.7; }

/* locked (Preview/Summary) controls */
.locked-note { background:var(--bg-card, #122861); border:1px solid var(--accent-teal, #04CAB9); border-radius:8px; padding:.6rem .9rem; margin-bottom:.9rem; font-size:.9rem; }
.locked-note a, .remaining-card a { color:var(--accent-teal, #04CAB9); font-weight:700; }
fieldset.locked-controls { border:0; margin:0; padding:0; min-width:0; opacity:.55; filter:grayscale(.6); }
fieldset.locked-controls input, fieldset.locked-controls select, fieldset.locked-controls button { cursor:not-allowed; }
.lock-tag { display:inline-block; font-size:.62rem; font-weight:800; letter-spacing:.4px; text-transform:uppercase; color:var(--accent-teal, #04CAB9); border:1px solid var(--accent-teal, #04CAB9); border-radius:999px; padding:.05rem .45rem; margin-left:.4rem; vertical-align:middle; }
.remaining-card { border:1px dashed var(--accent-teal, #04CAB9); border-radius:10px; padding:1rem; margin:.8rem 0; background:var(--bg-navy, #0A2547); }
.remaining-card h4 { margin:0 0 .4rem; }

/* group / workload bodies */
.grp-breakdown td, .grp-breakdown th { white-space:nowrap; }
.g4-note { color:var(--text-muted, #D9D9D9); margin:.2rem 0 1rem; }
.grp-wl-chips { margin:1rem 0 .4rem; }
.g1all { margin:1.2rem 0; }
.g1all-title, .obj-count { margin:.6rem 0 .3rem; font-weight:700; }
.obj-count-n { font-weight:400; color:var(--text-muted, #D9D9D9); font-size:.88rem; }
.obj-table { margin-top:.8rem; }
.empty-cell { text-align:center; color:var(--text-muted, #D9D9D9); padding:2rem; white-space:normal; }
.totals-sub { font-size:.72rem; color:var(--text-muted, #D9D9D9); }
.mass-edit-label { font-size:.78rem; color:var(--text-muted, #D9D9D9); }
.attr-input { background:var(--bg-deep, #011E3A); color:var(--text, #fff); border:1px solid var(--border, #3a4a80); border-radius:6px; padding:.3rem .5rem; font-size:.78rem; }
.rt-current { font-size:.78rem; color:var(--text-muted, #D9D9D9); margin-left:.6rem; }
.bonus-title { font-size:.8rem; color:var(--text, #fff); }
.rt-empty-note.exceeds { border-left:4px solid var(--alert, #FB3A73); }
.flag-chip { display:inline-block; font-size:.62rem; font-weight:800; letter-spacing:.3px; text-transform:uppercase; border-radius:999px; padding:.05rem .45rem; margin-left:.35rem; vertical-align:middle; background:var(--warn, #FF5A2E); color:var(--bg-deep, #011E3A); cursor:pointer; }
.flag-chip.excluded { background:transparent; color:var(--warn, #FF5A2E); border:1px solid var(--warn, #FF5A2E); }

/* ===== v2.0 Recovery Insights tab. Colors come from the theme tokens (see ReportCss.css :root). ===== */
.ins-sub { color:var(--text-muted, #D9D9D9); max-width:80ch; margin:-.5rem 0 1.2rem; font-size:.95rem; }
.ins-banner { background:var(--bg-card, #122861); border:1px solid var(--border, #3a4a80); border-left:5px solid var(--accent-teal, #04CAB9); border-radius:10px; padding:1rem 1.2rem; margin:0 0 1.2rem; display:flex; flex-wrap:wrap; align-items:center; gap:1rem 1.5rem; }
.ins-banner-text { flex:1 1 320px; line-height:1.45; }
.ins-compare { display:flex; gap:.75rem; flex-wrap:wrap; }
.ins-compare-card { background:var(--bg-navy, #0A2547); border:1px solid var(--border, #3a4a80); border-radius:8px; padding:.55rem .9rem; min-width:170px; opacity:.8; }
.ins-compare-card.current { border-color:var(--accent-teal, #04CAB9); opacity:1; }
.ins-compare-label { font-size:.72rem; text-transform:uppercase; letter-spacing:.5px; color:var(--text-muted, #D9D9D9); }
.ins-compare-val { font-weight:800; font-size:1.05rem; }
.ins-compare-sub { font-size:.82rem; color:var(--text-muted, #D9D9D9); }
.ins-toggle { display:inline-flex; border:1px solid var(--border, #3a4a80); border-radius:8px; overflow:hidden; align-items:center; }
.ins-toggle-btn { background:transparent; color:var(--text, #fff); border:0; padding:.45rem 1rem; font:inherit; font-weight:700; cursor:pointer; }
.ins-toggle-btn.active { background:var(--accent-teal, #04CAB9); color:var(--bg-deep, #011E3A); }
.ins-toggle-btn:disabled { opacity:.5; cursor:not-allowed; }
.ins-toggle-btn:focus-visible, .ins-tile:focus-visible, .ins-clear:focus-visible { outline:2px solid var(--accent-cyan, #1BBCF3); outline-offset:2px; }
.ins-toggle-note { padding:0 .8rem; font-size:.8rem; color:var(--text-muted, #D9D9D9); }
.ins-tiles { display:grid; grid-template-columns:repeat(auto-fill, minmax(210px, 1fr)); gap:.75rem; margin:0 0 1.5rem; }
.ins-tile { text-align:left; background:var(--bg-card, #122861); color:var(--text, #fff); border:1px solid var(--border, #3a4a80); border-radius:10px; padding:.8rem 1rem; cursor:pointer; font:inherit; display:flex; flex-direction:column; gap:.2rem; }
.ins-tile:hover:not(:disabled) { border-color:var(--accent-teal, #04CAB9); }
.ins-tile.active { border-color:var(--accent-teal, #04CAB9); box-shadow:0 0 0 2px var(--accent-teal, #04CAB9); }
.ins-tile.zero { opacity:.5; cursor:default; }
.ins-tile-count { font-size:1.7rem; font-weight:800; color:var(--accent-teal, #04CAB9); line-height:1.1; }
.ins-tile-label { font-weight:700; }
.ins-tile-impact { font-size:.8rem; color:var(--text-muted, #D9D9D9); line-height:1.35; }
.ins-table-head { display:flex; align-items:center; gap:.8rem; flex-wrap:wrap; }
.ins-table-head h3, #insights-baseline h3 { margin:1rem 0 .5rem; }
.ins-filter { font-size:.9rem; color:var(--text-muted, #D9D9D9); }
.ins-clear { background:transparent; color:var(--accent-teal, #04CAB9); border:0; text-decoration:underline; cursor:pointer; font:inherit; }
.ins-table td.ins-why { min-width:280px; max-width:520px; font-size:.85rem; line-height:1.4; }
.ins-table td.ins-flags { min-width:160px; }
.ins-table tr.ins-excluded td { background:rgba(251, 58, 115, .08); }
.ins-chip { display:inline-block; font-size:.72rem; font-weight:700; padding:.1rem .5rem; border-radius:999px; border:1px solid var(--accent-cyan, #1BBCF3); color:var(--accent-cyan, #1BBCF3); margin:.1rem .15rem .1rem 0; white-space:nowrap; }
.ins-chip.excl { border-color:var(--alert, #FB3A73); color:var(--alert, #FB3A73); }
.ins-empty { color:var(--text-muted, #D9D9D9); font-style:italic; margin:.5rem 0 1rem; }

'@

#endregion

#region ---------- HTML report JS: engine (data, scoring, tiering, overrides) ----------

$script:ReportJsEngine = @'
// ===== v2.0: build mode. "full" = everything; "preview" = Group 1 only (Groups 2-4 are stripped
// from the data at generation time, see Select-PreviewGroup1Rows); "summary" = aggregate-only (no
// per-object rows at all). The mode is data-driven (meta.buildMode, set by PowerShell) so the
// SAME JS ships in every build and the three can never drift apart.
var DATA = JSON.parse(document.getElementById("report-data-meta").textContent);
var BUILD_MODE = (DATA.meta && DATA.meta.buildMode) || "full";
var IS_PREVIEW = BUILD_MODE === "preview";
var IS_SUMMARY = BUILD_MODE === "summary";
// NEW 2026-09-24: large-tenant fix - the embedded payload is split across 5
// separate <script> tags (meta/weights/etc, then one per workload) instead
// of one combined blob, because a customer's
// very large tenant produced a single JSON string of more than 536 million characters - OVER V8's hard-coded maximum JS string length
// (536,870,888 characters; this is a fixed engine constant in every
// Chromium/Node build, not something more RAM works around). JSON.parse()
// on a string past that ceiling throws immediately, before ANY of this
// engine runs, leaving the whole report blank. Splitting per-workload
// keeps each individual JSON.parse() call's input comfortably under the
// limit for every tenant seen to date (the largest single workload seen,
// SharePoint, was several hundred MB - with headroom left). This does NOT
// eliminate the ceiling - an extreme enough SINGLE workload could still
// someday exceed it on its own; there is no dynamic chunking within a
// workload yet.
function readWorkloadJson(id) {
  var el = document.getElementById(id);
  if (!el) { return []; }
  var t = el.textContent;
  if (!t || !t.trim()) { return []; }
  return JSON.parse(t);
}
DATA.workloads = {
  mailboxes:  readWorkloadJson("report-data-mailboxes"),
  onedrive:   readWorkloadJson("report-data-onedrive"),
  sharepoint: readWorkloadJson("report-data-sharepoint"),
  teams:      readWorkloadJson("report-data-teams")
};
// NEW 2026-09-11: defensive normalization for a field-found bug
// (an Interactive report that was blank/broken). The PS-side fix
// (see Get-UserEnrichmentIndex / Add-UserEnrichment @(...) vs $(...)) stops
// this at the source for NEW runs, but any report ALREADY generated before
// that fix still has the bad shape baked into its embedded JSON - a row in
// exactly one Entra ID group (or with exactly one manager-chain hop) has
// Groups/GroupIds/ManagerChain as a bare STRING instead of a 1-element
// array. Several JS helpers call .forEach/.join on those fields, which
// throws on a string and was aborting the entire script (breaking every
// tab, not just the group/manager filters). Normalizing every row's shape
// once, right after parsing, means this file works whether it was
// generated before or after the PS fix, and guards against any other
// field with the same collapse risk we haven't found yet.
(function normalizeRowArrayFields() {
  function toArr(v) {
    if (Array.isArray(v)) { return v; }
    if (v === null || v === undefined || v === "") { return []; }
    return [v];
  }
  var arrayFields = ["Groups", "GroupIds", "ManagerChain"];
  if (!DATA || !DATA.workloads) { return; }
  Object.keys(DATA.workloads).forEach(function (wKey) {
    var rows = DATA.workloads[wKey];
    if (!Array.isArray(rows)) { return; }
    rows.forEach(function (r) {
      arrayFields.forEach(function (f) {
        if (f in r) { r[f] = toArr(r[f]); }
      });
    });
  });
})();
// v3.1.0: 4-tier order. All five workloads are tiered the same way
// (criticality-ranked, see computeScoresAndTiers) - there is no more
// separate "Beyond Target" bucket. Group 1/2/3's RTO compliance is now a
// per-group flag on the recovery model instead (see computeRecoveryModel).
// NEW v3.7.0: renamed the 4th tier from "Dormant - No Recent Activity" to
// plain "Group 4", per feedback - folds zero-activity data into
// the same Group 1/2/3 naming convention instead of calling it out as its
// own "dormant" category, and swaps its badge from amber (which read as an
// alert) to a neutral gray (--mid-gray) so it doesn't draw the eye.
// NEW v3.10.3: large-tenant render cap. Every workload table (and the Group 1
// cross-workload overview) used to render one <tr> per object with no limit -
// fine at demo scale, but a live tenant with tens of thousands of objects per
// workload turned "click Criticality Groups" into tens of thousands of DOM
// rows built and laid out synchronously on every recompute (including the
// very first page load, since recomputeAll() renders every tab up front) -
// long enough for the browser to flag the page as unresponsive. Tables now
// render only the top MAX_TABLE_ROWS (by score, so the highest-priority
// objects are always what you see first) and show a "Show all" toggle per
// table/section for when someone genuinely needs the full list on screen
// (e.g. to eyeball everything before an Export overrides pass). Search and
// filters still run over the FULL underlying dataset first - the cap only
// limits how many of the matching rows get rendered, so a search for one
// specific object always finds it even if it's outside the default top slice.
var MAX_TABLE_ROWS = 500;
var TIER_ORDER = ["Critical Group 1","Critical Group 2","Critical Group 3","Group 4"];
// v2.0 dark theme tier colors (same values as the --accent-* tokens; fg chosen for >= 4.5:1 contrast).
var TIER_META = {
  "Critical Group 1": {bg:"#04CAB9", fg:"#011E3A", short:"Group 1", role:"Critical users", named:"Critical users (Group 1)"},
  "Critical Group 2": {bg:"#8242E8", fg:"#FFFFFF", short:"Group 2", role:"Important users", named:"Important users (Group 2)"},
  "Critical Group 3": {bg:"#F4C9F4", fg:"#011E3A", short:"Group 3", role:"Standard users", named:"Standard users (Group 3)"},
  "Group 4": {bg:"#8FA0BF", fg:"#011E3A", short:"Group 4", role:"Low-activity objects", named:"Low-activity objects (Group 4)"}
};
// ---- Variable group count (v2.0) -------------------------------------------------------------------------------------
// N criticality groups ("Critical Group 1".."Critical Group N", every one sequenced by ABR) plus ONE low-activity group
// (internal key LOW_KEY, labelled "Group N+1"). N defaults to 3 (the original layout) and is 3-12 in the Full report.
// TIER_ORDER / TIER_META are rebuilt in place by rebuildTiers() whenever N changes, so code that loops over them adapts.
var LOW_KEY = "Group 4";
var MIN_GROUPS = 3, MAX_GROUPS = 12;
var TIER_DARK_ANCHORS = ["#04CAB9", "#8242E8", "#F4C9F4"];
function groupN() { return (typeof state !== "undefined" && state.recovery && state.recovery.groupCount) || 3; }
function critKey(k) { return "Critical Group " + k; }
function critKeys() { var a = []; for (var k = 1; k <= groupN(); k++) { a.push(critKey(k)); } return a; }
function lastCritKey() { return critKey(groupN()); }
function tierNum(key) { var m = /^Critical Group (\d+)$/.exec(key || ""); return m ? parseInt(m[1], 10) : 0; }
function lowName() { return "Group " + (groupN() + 1); }
function scopeName(k) { return k <= 1 ? "Group 1" : "Groups 1-" + k; }
function groupHoursOf(k) { return state.recovery.groupHours[k - 1]; }
function hexToRgb(h) { h = h.replace("#", ""); return [parseInt(h.substr(0, 2), 16), parseInt(h.substr(2, 2), 16), parseInt(h.substr(4, 2), 16)]; }
function rgbToHex(c) { return "#" + c.map(function (v) { v = Math.max(0, Math.min(255, Math.round(v))); return (v < 16 ? "0" : "") + v.toString(16); }).join(""); }
function cssAnchor(i) {
  var fb = TIER_DARK_ANCHORS[i];
  try { var v = getComputedStyle(document.documentElement).getPropertyValue("--g" + (i + 1) + "c").trim(); return /^#[0-9a-f]{6}$/i.test(v) ? v : fb; } catch (e) { return fb; }
}
// Colour of criticality group k of n: the three theme anchors (teal, purple, lilac) with intermediate groups interpolated.
function groupColor(k, n, anchors) {
  n = n || groupN(); anchors = anchors || [cssAnchor(0), cssAnchor(1), cssAnchor(2)];
  if (n <= 3) { return anchors[Math.min(2, k - 1)]; }
  var t = (k - 1) / (n - 1) * 2, i = Math.min(1, Math.floor(t)), f = t - i;
  var a = hexToRgb(anchors[i]), b = hexToRgb(anchors[i + 1]);
  return rgbToHex([0, 1, 2].map(function (j) { return a[j] + (b[j] - a[j]) * f; }));
}
function lowGroupColor() { return "#8FA0BF"; }
function readableFg(hex) { var c = hexToRgb(hex), l = (0.299 * c[0] + 0.587 * c[1] + 0.114 * c[2]) / 255; return l > 0.6 ? "#011E3A" : "#FFFFFF"; }
function tierTitle(k) {
  if (k === 1) { return "Critical users (Group 1)"; }
  if (groupN() === 3 && k <= 3) { return (k === 2 ? "Important users" : "Standard users") + " (Group " + k + ")"; }
  return "Group " + k;
}
function rebuildTiers() {
  var n = groupN();
  TIER_ORDER.length = 0;
  Object.keys(TIER_META).forEach(function (k) { delete TIER_META[k]; });
  for (var k = 1; k <= n; k++) {
    var bg = groupColor(k, n, TIER_DARK_ANCHORS);
    TIER_META[critKey(k)] = { bg: bg, fg: readableFg(bg), short: "Group " + k, role: k === 1 ? "Critical users" : (n === 3 ? (k === 2 ? "Important users" : "Standard users") : "Group " + k), named: tierTitle(k) };
    TIER_ORDER.push(critKey(k));
  }
  TIER_META[LOW_KEY] = { bg: lowGroupColor(), fg: "#011E3A", short: "Group " + (n + 1), role: "Low-activity objects", named: "Low-activity objects (Group " + (n + 1) + ")" };
  TIER_ORDER.push(LOW_KEY);
}
// Whole-tenant ABR (hot-data) time if every active object were one group - sizes the "Enterprise Plus" targets.
function wholeTenantAbrMin() {
  var wf = getWindowFactor(), total = 0, scale = Math.max((DATA.workloads.sharepoint || []).length, (DATA.workloads.onedrive || []).length);
  var tier = resolveLicenseTier(state.recovery.licenseTier, scale);
  Object.keys(RECOVERY_FIELD_MAP).forEach(function (wl) {
    var f = RECOVERY_FIELD_MAP[wl], rows = DATA.workloads[wl] || [], items = 0, stor = 0, ri = 0, rs = 0, objs = 0;
    rows.forEach(function (r) {
      var it = parseFloat(r.metrics[f.itemField]) || 0, st = parseFloat(r.metrics[f.storageField]) || 0;
      var rec = Math.max(0, Math.min(parseFloat(r.metrics[RECENT_FIELD[wl]]) || 0, it));
      if ((parseFloat(r.metrics.TotalActivity) || 0) > 0) { objs++; ri += rec; rs += it > 0 ? st * rec / it : 0; }
      items += it; stor += st;
    });
    var avg = items > 0 ? stor / items : 0;
    total = Math.max(total, recoveryTimeMinutes(f.type, objs, ri * wf, rs * wf, avg, tier, true));
  });
  return total;
}
// Enterprise Plus: sized to the tenant. The last group's target is the whole-tenant ABR time (rounded up), Group 1 is
// Day 1 (24 hr, or less on a small tenant), and the groups in between are spaced geometrically so each group is a bit
// larger than the one before. Cumulative hours, rounded to 12 hr (1 hr on small tenants), always editable.
function enterprisePlusHours(n) {
  var A = wholeTenantAbrMin() / 60, big = A >= 240, step = big ? 12 : 1;
  var endH = Math.max(step * 2, Math.ceil(A / step) * step);
  var g1 = Math.max(step, Math.min(24, Math.round(endH / n / step) * step));
  var out = [], prev = 0;
  for (var k = 1; k <= n; k++) {
    var h = k === 1 ? g1 : (k === n ? endH : g1 * Math.pow(endH / g1, (k - 1) / (n - 1)));
    h = Math.max(prev + step, Math.round(h / step) * step);
    out.push(h); prev = h;
  }
  return out;
}
var FRIENDLY = { SendRecvActivity:"Send/receive volume", ReadActivity:"Read volume", Size:"Mailbox size",
  FileActivity:"File activity", Storage:"Storage size", PageViews:"Page views", ActiveFiles:"Recently used files",
  ActiveUsers:"Participating users", ChannelMsgs:"Channel messages", Meetings:"Meetings organized",
  TitleWeight:"Job title" };
// spExOd (non-null for Mailboxes/OneDrive/SharePoint) flags the three
// workloads with an independent, throughput-based recovery-time model - used
// by computeRecoveryModel/buildControlsPanel. Tiering itself (below) is now
// identical for all four workloads.
// NEW v3.7.4: Enterprise Applications removed entirely, per feedback
// 2026-07-31 - not needed for the recovery-sequencing use case this tool
// targets, and dropping it also let PREVIEW mode's Graph footprint shrink to
// Reports.Read.All only (AuditLog.Read.All existed solely to pull sign-in
// logs for this workload).
var WORKLOAD_DEFS = [
  {key:"mailboxes", label:"Mailboxes", idLabel:"UPN", itemField:"ItemCount", itemLabel:"Items", storageField:"StorageUsedMB", storageLabel:"Storage", spExOd:"EX"},
  {key:"onedrive", label:"OneDrive Accounts", idLabel:"Site URL / Owner UPN", itemField:"FileCount", itemLabel:"Files", storageField:"StorageUsedGB", storageLabel:"Storage", spExOd:"OD"},
  {key:"sharepoint", label:"SharePoint Sites", idLabel:"Site URL / Owner UPN", itemField:"FileCount", itemLabel:"Files", storageField:"StorageUsedGB", storageLabel:"Storage", spExOd:"SP"},
  {key:"teams", label:"Teams", idLabel:"Team Id", itemField:"ActiveUsersCount", itemLabel:"Participating Users", storageField:null, storageLabel:"", spExOd:null}
];
// NEW v3.1.0: real "recent/active data" telemetry field per workload
// (already collected, no invented numbers) - the recent item/file count
// used by computeRecoveryModel to estimate each tier's ABR (hot-scope)
// recovery time. Byte-equivalent storage field alongside it (SP/OD use
// bytes, EX uses MB), distinct from wd.storageField (the display/GB field).
// NEW: ABR can only ever recover the last 7 days of activity - a fixed
// product capability, not a -Period choice - so these point at the *7d
// fields (always collected at Period=D7, independent of whatever -Period
// drove scoring/dormancy) rather than the scoring-signal fields of the same
// name without the suffix. See the Methodology tab.
var RECENT_FIELD = { mailboxes:"SendRecvActivity7d", onedrive:"ViewedOrEditedCount7d", sharepoint:"ActiveFiles7d" };

// NEW v3.8.0/Phase 2: item/storage field names + recoveryTimeMinutes()
// workload-type code for the three workloads with an independent,
// throughput-based recovery-time model - used by assignBudgetTiers() below.
// Matches computeRecoveryModel's own field choices exactly (StorageBytes for
// SP/OD, StorageUsedMB for EX) - NOT WORKLOAD_DEFS.storageField, which is the
// display/GB-scaled field. Teams has no entry - it has no recovery-time
// model to walk against, so it keeps the original equal-thirds split.
var RECOVERY_FIELD_MAP = {
  mailboxes:  { itemField: "ItemCount", storageField: "StorageUsedMB", type: "EX" },
  onedrive:   { itemField: "FileCount", storageField: "StorageBytes",  type: "OD" },
  sharepoint: { itemField: "FileCount", storageField: "StorageBytes",  type: "SP" }
};

// NEW v3.8.0: shared with computeRecoveryModel (Recovery heredoc) so the
// tiering walk and the rendered ABR figures can never drift out of sync -
// both call this same function rather than each computing windowFactor
// inline. See the Methodology tab.
function getWindowFactor() {
  return Math.max(0, Math.min(7, state.recovery.windowDays || 0)) / 7;
}

function assignBudgetTiers(active, itemField, storageField, recentField, avgItemSize, spodTier, workloadType, targetsMin, windowFactor) {
  // v3.8.0/Phase 2: replaces the fixed equal-thirds split for Mailboxes/
  // OneDrive/SharePoint. `active` must already be sorted by _Score
  // descending (criticality rank is unchanged - only which tier an object
  // lands in is now budget-aware). Fills Group 1 with as many top-ranked
  // objects as fit inside its own RTO budget (using the SAME windowed ABR
  // hot-data figures the Recovery tab shows), spills the remainder into
  // Group 2 against its REMAINING (cumulative) budget, then Group 3.
  //
  // Advances to the next tier only ONE STEP per object, never skipping a
  // tier in a single step - the specific fix for v3.0.0's empty-middle-tier
  // bug (a single large object could jump the walk straight past an entire
  // group). If even one object alone exceeds a tier's ENTIRE remaining
  // budget, it still gets placed there (can't leave an active object
  // homeless, and can't skip a tier to find it a "better fit") - that tier
  // just closes immediately after taking it, flagged ExceedsTarget by
  // computeRecoveryModel same as before. Group 3 (the last real tier)
  // always absorbs every remaining active object regardless of fit - there
  // is no active-overflow tier, matching the v3.1.0 "every active object is
  // in Group 1/2/3" invariant. See the Methodology tab.
  var tierNames = critKeys(), G = tierNames.length;
  var n = active.length;
  var cursor = 0;
  var priorTiersTime = 0;
  for (var t = 0; t < G; t++) {
    var budget = targetsMin[t] - priorTiersTime;
    var cumObjs = 0, cumItems = 0, cumStorage = 0;
    while (cursor < n) {
      var row = active[cursor];
      var ti = parseFloat(row.metrics[itemField]) || 0;
      var ts = parseFloat(row.metrics[storageField]) || 0;
      var recentRaw = parseFloat(row.metrics[recentField]) || 0;
      var ri = Math.max(0, Math.min(recentRaw, ti));
      var frac = ti > 0 ? (ri / ti) : 0;
      var candObjs = cumObjs + 1;
      var candItems = cumItems + (ri * windowFactor);
      var candStorage = cumStorage + (ts * frac * windowFactor);
      var candTime = recoveryTimeMinutes(workloadType, candObjs, candItems, candStorage, avgItemSize, spodTier, true);
      if (t < G - 1 && budget > 0 && candTime > budget && cumObjs > 0) {
        break; // this tier is full relative to its budget - move to the next tier
      }
      row.ComputedTier = tierNames[t];
      cumObjs = candObjs; cumItems = candItems; cumStorage = candStorage;
      cursor++;
      if (t < G - 1 && budget > 0 && candTime > budget) {
        break; // just accepted the one object that alone overflows an empty tier - close it now
      }
    }
    priorTiersTime += recoveryTimeMinutes(workloadType, cumObjs, cumItems, cumStorage, avgItemSize, spodTier, true);
  }
}

var state = {
  weights: JSON.parse(JSON.stringify(DATA.weights)),
  tierSplit: DATA.tierSplit.slice(),
  titleWeights: JSON.parse(JSON.stringify(DATA.titleWeights)),
  // Ordered [{keyword, weight}] view of titleWeights, used only to drive the
  // editable table in the report (add/rename/reweight/remove rows) - plain
  // JS objects can't have a key "renamed" in place, so edits happen on this
  // array and titleWeights itself is rebuilt from it via syncTitleWeights().
  titleWeightRows: Object.keys(DATA.titleWeights).map(function (k) { return { keyword: k, weight: DATA.titleWeights[k] }; }),
  // Collapsed by default (see buildTitleWeightTableHtml/toggleTitleWeightTable) -
  // persists across full recomputes so editing a row doesn't re-collapse it.
  titleWeightTableExpanded: false,
  titleWeightContribution: DATA.titleWeightContribution,
  hubSiteKeywords: DATA.hubSiteKeywords.slice(),
  hubSiteBonus: DATA.hubSiteBonus,
  overrides: {},
  // NEW: presenter pass - per-workload "show detail columns" toggle state
  // (true/undefined = show everything, unchanged default behavior; false =
  // essentials-only view). Persisted the same way overrides are, below.
  columnPrefs: {},
  // NEW v3.10.3: per-workload/section "render every row, not just the top
  // MAX_TABLE_ROWS" opt-in. Deliberately NOT persisted to localStorage (unlike
  // overrides/columnPrefs) - defaults back to the fast, capped view on every
  // fresh page load rather than silently re-triggering the slow render.
  showAllRows: {},
  group1ShowAll: false,
  recovery: {
    windowDays: DATA.meta.recoveryWindowDays, licenseTier: DATA.meta.recoveryLicenseTierRequested, costPerHour: DATA.meta.downtimeCostPerHour,
    // NEW v3.0.0: RTO targets (hours), seeded from the resolved server-side
    // defaults. Live-adjustable in the Recovery tab; changing these triggers
    // a FULL retiering recompute (recomputeAll), not just a recovery-time
    // recompute, since tiering itself now depends on these targets.
    groupCount: (IS_PREVIEW || IS_SUMMARY) ? 3 : Math.max(3, Math.min(12, parseInt(DATA.meta.groupCount, 10) || 3)),
    groupHours: [DATA.meta.group1TargetHours, DATA.meta.group2TargetHours, DATA.meta.group3TargetHours],
    rtoPreset: DATA.meta.rtoPresetResolved || "Standard", rtoPresetReason: DATA.meta.rtoPresetReason || "",
    autoBannerDismissed: false
  },
  activeFilters: {},
  // v2.0 Recovery Insights. exclude: peer-outlier / concentration objects are left out of the HEADLINE recovery
  // estimates (ABR and Mass alike, so the comparison stays like-for-like) and called out; the customer can toggle them
  // back in. Preview/Summary builds never exclude (the baseline cannot be recomputed without Groups 2-4).
  // floorInHeadline: long-pole floor is shown as an insight only until the single-object restore rates are confirmed.
  insights: { exclude: !(IS_PREVIEW || IS_SUMMARY), floorInHeadline: false }
};

// Groups 1-3 targets stay readable/writable as state.recovery.group1Hours..group3Hours (older code paths); both views are one array.
[0, 1, 2].forEach(function (i) {
  Object.defineProperty(state.recovery, "group" + (i + 1) + "Hours", { enumerable: false, configurable: true,
    get: function () { return state.recovery.groupHours[i]; }, set: function (v) { state.recovery.groupHours[i] = v; } });
});
rebuildTiers();
// Called once at start-up (Recovery constants are defined later in the file): a report opened with more than 3 groups
// starts on the sized Enterprise Plus targets.
function initGroupCount() {
  var n = state.recovery.groupCount;
  if (n > 3) {
    state.recovery.groupHours = enterprisePlusHours(n);
    state.recovery.rtoPreset = "Enterprise Plus";
    state.recovery.rtoPresetReason = "Enterprise Plus targets sized to this tenant for " + n + " criticality groups.";
  }
  rebuildTiers();
}
// Live change of N from the Recovery modeling inputs (Full report only).
function setGroupCount(v) {
  if (!canEditTiers()) { return; }
  var n = Math.max(MIN_GROUPS, Math.min(MAX_GROUPS, Math.round(parseFloat(v)) || 3)), old = groupN();
  if (n === old) { renderGroupsTab(); return; }
  var preset = state.recovery.rtoPreset, hrs = state.recovery.groupHours.slice();
  state.recovery.groupCount = n;
  if (preset === "Custom") {
    while (hrs.length < n) { hrs.push(Math.ceil((hrs[hrs.length - 1] || 24) * 1.5 / 12) * 12); }
    state.recovery.groupHours = hrs.slice(0, n);
  } else if (n > 3 || preset === "Enterprise Plus") {
    state.recovery.rtoPreset = "Enterprise Plus";
    state.recovery.groupHours = enterprisePlusHours(n);
  } else {
    state.recovery.groupHours = hrs.slice(0, 3);
  }
  rebuildTiers();
  Object.keys(uiState.acc).forEach(function (k) { if (/^grp-/.test(k) && k !== "grp-controls-acc") { delete uiState.acc[k]; } });
  recomputeAll();
}

WORKLOAD_DEFS.forEach(function (wd) {
  (DATA.workloads[wd.key] || []).forEach(function (row) {
    if (row.IsOverride) {
      state.overrides[wd.key + "|" + row.Identifier] = { tier: row.Tier, reason: row.OverrideReason || "", setBy: "prior run / seeded", timestamp: "" };
    }
  });
});
try {
  var savedRaw = localStorage.getItem("m365crit_overrides_" + DATA.meta.runId);
  if (savedRaw) {
    var savedParsed = JSON.parse(savedRaw);
    Object.keys(savedParsed).forEach(function (k) { state.overrides[k] = savedParsed[k]; });
  }
} catch (e) {}

function saveOverridesToStorage() {
  try { localStorage.setItem("m365crit_overrides_" + DATA.meta.runId, JSON.stringify(state.overrides)); } catch (e) {}
}

// NEW: presenter pass - column-visibility prefs, same localStorage pattern
// as overrides above (keyed by runId so it doesn't bleed across reports).
try {
  var savedColPrefsRaw = localStorage.getItem("m365crit_colprefs_" + DATA.meta.runId);
  if (savedColPrefsRaw) { state.columnPrefs = JSON.parse(savedColPrefsRaw) || {}; }
} catch (e) {}

function saveColumnPrefsToStorage() {
  try { localStorage.setItem("m365crit_colprefs_" + DATA.meta.runId, JSON.stringify(state.columnPrefs)); } catch (e) {}
}

function percentileRank(rows, field) {
  var idx = rows.map(function (r, i) { return { r: r, v: parseFloat(r.metrics[field]) || 0, i: i }; });
  idx.sort(function (a, b) { return a.v - b.v; });
  var n = idx.length;
  idx.forEach(function (o, rank) {
    o.r._ranks = o.r._ranks || {};
    o.r._ranks[field] = n > 1 ? rank / (n - 1) : 1;
  });
}

function computeTitleWeight(row) {
  var title = (row.JobTitle || "");
  var best = 0, matched = "";
  if (title) {
    Object.keys(state.titleWeights).forEach(function (kw) {
      if (title.toLowerCase().indexOf(kw.toLowerCase()) !== -1 && state.titleWeights[kw] > best) {
        best = state.titleWeights[kw]; matched = kw;
      }
    });
  }
  row.TitleWeight = best; row.TitleWeightMatch = matched;
}

function computeHubSite(rows) {
  var idx = rows.map(function (r) { return { r: r, v: parseFloat(r.metrics.TotalActivity) || 0 }; });
  idx.sort(function (a, b) { return a.v - b.v; });
  var n = idx.length;
  idx.forEach(function (o, rank) { o.r._breadthRank = n > 1 ? rank / (n - 1) : 1; });
  rows.forEach(function (row) {
    var hay = (row.ObjectName + " " + row.Identifier).toLowerCase();
    var matched = null;
    for (var i = 0; i < state.hubSiteKeywords.length; i++) {
      if (hay.indexOf(state.hubSiteKeywords[i].toLowerCase()) !== -1) { matched = state.hubSiteKeywords[i]; break; }
    }
    row.HubSiteCandidate = !!matched && row._breadthRank >= 0.75;
    row.HubSiteKeywordMatch = matched || "";
  });
}

function computeScoresAndTiers(workloadKey) {
  var rows = DATA.workloads[workloadKey] || [];
  if (rows.length === 0) { return; }
  if (IS_PREVIEW || IS_SUMMARY) {
    // v2.0: Preview/Summary builds never re-score. The scoring population (every object in the
    // tenant) is not in the page - Groups 2-4 were stripped at generation time - so a client-side
    // percentile-rank would give different numbers. Use what PowerShell computed and shipped.
    rows.forEach(function (row) {
      row._Score = (typeof row.Score === "number") ? row.Score : (row._Score || 0);
      row.Tier = row.ComputedTier || row.Tier;
      row.IsOverride = false;
      row.OverrideReason = "";
    });
    return;
  }
  var weights = Object.assign({}, state.weights[workloadKey] || {});

  if (workloadKey === "mailboxes" || workloadKey === "onedrive") {
    var anyTitles = rows.some(function (r) { return !!r.JobTitle; });
    if (anyTitles) {
      rows.forEach(computeTitleWeight);
      rows.forEach(function (r) { r.metrics.TitleWeight = r.TitleWeight; });
      weights.TitleWeight = state.titleWeightContribution;
    }
  }
  if (workloadKey === "sharepoint") { computeHubSite(rows); }

  Object.keys(weights).forEach(function (field) { percentileRank(rows, field); });

  rows.forEach(function (row) {
    var score = 0;
    Object.keys(weights).forEach(function (field) {
      score += ((row._ranks && row._ranks[field]) || 0) * weights[field];
    });
    if (workloadKey === "sharepoint" && row.HubSiteCandidate) { score += state.hubSiteBonus; }
    row._Score = Math.min(1, Math.round(score * 10000) / 10000);
  });

  // v3.1.0: ALL FIVE workloads use the SAME criticality-ranked split -
  // guarantees every group gets a population as long as there's enough
  // active data. See computeRecoveryModel for the separate ABR (hot-scope)
  // vs Mass Recovery (full-scope) recovery-TIME calculation, which no
  // longer influences which tier an object lands in.
  var inactiveField = "TotalActivity";
  var active = rows.filter(function (r) { return (parseFloat(r.metrics[inactiveField]) || 0) > 0; });
  var inactive = rows.filter(function (r) { return (parseFloat(r.metrics[inactiveField]) || 0) <= 0; });

  active.sort(function (a, b) { return b._Score - a._Score; });

  // v3.8.0/Phase 2: Mailboxes/OneDrive/SharePoint (RECOVERY_FIELD_MAP has an
  // entry) are now tiered by a budget-constrained walk against their own RTO
  // targets, using the SAME windowed ABR hot-data figures the Recovery tab
  // shows - see assignBudgetTiers(). Teams (no entry - no independent
  // recovery-time model to walk against) keeps the original fixed-thirds
  // split it and every other workload used through v3.1.0.
  var recoveryFieldInfo = RECOVERY_FIELD_MAP[workloadKey];
  if (recoveryFieldInfo) {
    var wlTotalItems = sumField(rows, recoveryFieldInfo.itemField);
    var wlTotalStorage = sumField(rows, recoveryFieldInfo.storageField);
    var avgItemSize = wlTotalItems > 0 ? wlTotalStorage / wlTotalItems : 0;
    var scale = Math.max((DATA.workloads.sharepoint || []).length, (DATA.workloads.onedrive || []).length);
    var spodTier = resolveLicenseTier(state.recovery.licenseTier, scale);
    var targetsMin = state.recovery.groupHours.slice(0, groupN()).map(function (h) { return h * 60; });
    assignBudgetTiers(active, recoveryFieldInfo.itemField, recoveryFieldInfo.storageField, RECENT_FIELD[workloadKey], avgItemSize, spodTier, recoveryFieldInfo.type, targetsMin, getWindowFactor());
  } else {
    var n = active.length;
    var G = groupN(), cuts = [];
    for (var c = 1; c < G; c++) { cuts.push(Math.ceil(n * (G === 3 ? (c === 1 ? state.tierSplit[0] : state.tierSplit[0] + state.tierSplit[1]) : c / G))); }
    active.forEach(function (row, i) {
      var g = 0; while (g < cuts.length && i >= cuts[g]) { g++; }
      row.ComputedTier = critKey(g + 1);
    });
  }
  inactive.forEach(function (row) {
    row.ComputedTier = "Group 4";
  });

  rows.forEach(function (row) {
    var key = workloadKey + "|" + row.Identifier;
    if (state.overrides[key]) {
      row.Tier = (TIER_ORDER.indexOf(state.overrides[key].tier) >= 0) ? state.overrides[key].tier : lastCritKey();
      row.IsOverride = true;
      row.OverrideReason = state.overrides[key].reason || "";
    } else {
      row.Tier = row.ComputedTier;
      row.IsOverride = false;
      row.OverrideReason = "";
    }
  });

  rows.forEach(function (row) {
    var contribs = Object.keys(weights).map(function (f) { return { f: f, c: ((row._ranks && row._ranks[f]) || 0) * weights[f] }; });
    contribs.sort(function (a, b) { return b.c - a.c; });
    var tags = [];
    contribs.slice(0, 2).forEach(function (c) { if (c.c > 0) { tags.push(FRIENDLY[c.f] || c.f); } });
    if (row.HubSiteCandidate) { tags.push("Department hub site (heuristic)"); }
    if (row.TitleWeightMatch) { tags.push("Title match: " + row.TitleWeightMatch); }
    row.CriteriaTags = tags.join("; ");
  });
}

function setOverride(workloadKey, identifier, tier, reason) {
  var key = workloadKey + "|" + identifier;
  if (tier === "__CLEAR__") {
    delete state.overrides[key];
  } else {
    state.overrides[key] = { tier: tier, reason: reason || "Manual (live edit)", setBy: "this session", timestamp: new Date().toISOString() };
  }
}

function getTierTotals(workloadKey, rowsOverride) {
  // rowsOverride (optional): pass a pre-filtered row set to get tier totals
  // for just that subset (e.g. "how many of the currently-filtered rows are
  // in each tier") instead of the whole workload. See buildWorkloadSection's
  // filtered-totals block.
  var rows = rowsOverride || DATA.workloads[workloadKey] || [];
  var wd = WORKLOAD_DEFS.filter(function (w) { return w.key === workloadKey; })[0];
  var out = {};
  TIER_ORDER.forEach(function (t) {
    var subset = rows.filter(function (r) { return r.Tier === t; });
    var itemTotal = 0, storageTotal = 0;
    subset.forEach(function (r) {
      itemTotal += parseFloat(r.metrics[wd.itemField]) || 0;
      if (wd.storageField) { storageTotal += parseFloat(r.metrics[wd.storageField]) || 0; }
    });
    out[t] = { objectCount: subset.length, itemTotal: itemTotal, storageTotal: storageTotal };
  });
  return out;
}
'@

#endregion

#region ---------- HTML report JS: recovery/cost engine + formatters ----------

$script:ReportJsRecovery = @'
var SPOD_TIER_TABLE = DATA.meta.spodTierTable;
var EX_BENCHMARK = DATA.meta.exBenchmark;
// NEW v3.10.0 (Rubrik's M365 recovery time model): read back out of
// meta (PowerShell is the single source of truth) rather than hardcoded
// here a second time, so the two can never drift. See
// the Methodology tab and Get-RecoveryTimeMinutes.
var SP_ITEMS_PER_MIN_PER_UNIT = DATA.meta.spItemsPerMinPerUnit;
var OD_ITEMS_PER_MIN_PER_UNIT = DATA.meta.odItemsPerMinPerUnit;
var SIZE_FACTOR_BASELINE_MB = DATA.meta.sizeFactorBaselineMB;
var JOB_SCHEDULING_RATE_PER_MIN = DATA.meta.jobSchedulingRatePerMin;
var MIN_RECOVERY_MINUTES = DATA.meta.minRecoveryMinutes;

function resolveLicenseTier(requested, objectScale) {
  if (requested !== "Auto") {
    for (var i = 0; i < SPOD_TIER_TABLE.length; i++) { if (SPOD_TIER_TABLE[i].Bucket === requested) { return SPOD_TIER_TABLE[i]; } }
  }
  for (var j = 0; j < SPOD_TIER_TABLE.length; j++) { if (objectScale <= SPOD_TIER_TABLE[j].Max) { return SPOD_TIER_TABLE[j]; } }
  return SPOD_TIER_TABLE[SPOD_TIER_TABLE.length - 1];
}

// v3.10.0: reworked to match Rubrik's M365 recovery time model, replacing
// the earlier export this formula was originally reverse-engineered from.
// Two structural changes from before: (1) SharePoint/OneDrive no longer have
// an independent bytes/min cap - an oversized average item now inflates the
// EFFECTIVE item count instead (sizeFactor), and SP/OD each have their OWN
// per-unit-of-parallelism item rate rather than sharing one table; Exchange
// keeps its bytes-vs-items dual constraint (take the max) but with new
// rates. (2) includeOverhead adds a fixed per-object job-scheduling cost
// (every object touched needs its own restore job, regardless of how much
// of it changed) plus a 5-minute floor - what ABR actually costs on top of
// raw transfer time. A full/undifferentiated Mass Recovery restore has
// neither - pass false for those calls. See the Methodology tab.
function recoveryTimeMinutes(workloadType, objectCount, itemCount, storageAmount, avgItemSize, spodTier, includeOverhead) {
  var transferMin;
  if (workloadType === "SP" || workloadType === "OD") {
    if (objectCount <= 0) { return 0; }
    var perUnitRate = workloadType === "SP" ? SP_ITEMS_PER_MIN_PER_UNIT : OD_ITEMS_PER_MIN_PER_UNIT;
    var ipm = Math.min(objectCount, spodTier.Parallelism) * perUnitRate;
    var avgFileMb = avgItemSize / (1024 * 1024);
    var sizeFactor = avgFileMb > 0 ? Math.max(1, avgFileMb / SIZE_FACTOR_BASELINE_MB) : 1;
    var effItems = itemCount * sizeFactor;
    transferMin = (effItems > 0 && ipm > 0) ? effItems / ipm : 0;
  } else {
    if (objectCount <= 0) { return 0; }
    var mbRate = Math.min(objectCount, EX_BENCHMARK.MaxParallelMailboxes) * EX_BENCHMARK.PerMailboxMBPerMin;
    var itemsRate = Math.min(objectCount, EX_BENCHMARK.MaxParallelMailboxes) * EX_BENCHMARK.PerMailboxItemsPerMin;
    var timeByBytes = (storageAmount > 0 && mbRate > 0) ? storageAmount / mbRate : 0;
    var timeByItems = (itemCount > 0 && itemsRate > 0) ? itemCount / itemsRate : 0;
    transferMin = Math.max(timeByBytes, timeByItems) * EX_BENCHMARK.OverheadBuffer;
  }
  if (!includeOverhead) { return transferMin; }
  var schedMin = objectCount / JOB_SCHEDULING_RATE_PER_MIN;
  var total = transferMin + schedMin;
  return total > 0 ? Math.max(total, MIN_RECOVERY_MINUTES) : 0;
}

function sliceTotals(rows, itemField, storageField, recentField, tierName) {
  // v3.1.0: also sums each tier's RECENT (hot) item/storage totals, per
  // object - recentRaw is capped at that object's own total (a report
  // artifact could otherwise push it slightly over), then that fraction is
  // applied to storage, mirroring PowerShell's Add-RecentDataEstimate
  // exactly so server-side and client-side figures never diverge.
  var subset = rows.filter(function (r) { return r.Tier === tierName && !isExcludedRow(r); });
  var items = 0, storage = 0, recentItems = 0, recentStorage = 0;
  subset.forEach(function (r) {
    var ti = parseFloat(r.metrics[itemField]) || 0;
    var ts = parseFloat((storageField ? r.metrics[storageField] : 0)) || 0;
    items += ti; storage += ts;
    var recentRaw = parseFloat(r.metrics[recentField]) || 0;
    var ri = Math.max(0, Math.min(recentRaw, ti));
    var frac = ti > 0 ? (ri / ti) : 0;
    recentItems += ri;
    recentStorage += ts * frac;
  });
  return { objectCount: subset.length, itemCount: items, storage: storage, recentItemCount: recentItems, recentStorage: recentStorage };
}

function sumField(rows, field) {
  var s = 0;
  rows.forEach(function (r) { s += parseFloat(r.metrics[field]) || 0; });
  return s;
}

// v2.0: the recovery model no longer reads per-object rows directly. It asks these two helpers,
// which use the rows when they are present (Full) and the generation-time aggregates when they
// are not (Preview: Group 1 rows + whole-tenant totals; Summary: tier aggregates only). In Full
// the numbers are identical to 3.x because the same row arithmetic runs.
var RECOVERY_FIELDS = {
  mailboxes:  { item: "ItemCount", storage: "StorageUsedMB", recent: "SendRecvActivity7d" },
  onedrive:   { item: "FileCount", storage: "StorageBytes",  recent: "ViewedOrEditedCount7d" },
  sharepoint: { item: "FileCount", storage: "StorageBytes",  recent: "ActiveFiles7d" }
};
// v2.0: an object flagged by Recovery Insights as a peer outlier / concentration object (row._excl, set in
// computeInsights) is left out of the headline recovery model while state.insights.exclude is on.
function isExcludedRow(r) { return !!(r && r._excl) && !!(state.insights && state.insights.exclude); }
function tenantTotalsFor(wlKey, includeExcluded) {
  var rows = DATA.workloads[wlKey] || [];
  var f = RECOVERY_FIELDS[wlKey];
  if (DATA.tenantTotals && DATA.tenantTotals[wlKey]) {
    var t = DATA.tenantTotals[wlKey];
    return { objectCount: t.objectCount || 0, itemCount: t.itemCount || 0, storage: t.storage || 0 };
  }
  if (!f) { return { objectCount: rows.length, itemCount: 0, storage: 0 }; }
  var kept = includeExcluded ? rows : rows.filter(function (r) { return !isExcludedRow(r); });
  return { objectCount: kept.length, itemCount: sumField(kept, f.item), storage: sumField(kept, f.storage) };
}
function tierSliceFor(wlKey, tierName) {
  var f = RECOVERY_FIELDS[wlKey];
  var rows = DATA.workloads[wlKey] || [];
  if (!IS_SUMMARY && rows.length > 0) {
    var anyTier = rows.some(function (r) { return r.Tier === tierName; });
    if (anyTier || !IS_PREVIEW || tierName === "Critical Group 1") {
      return sliceTotals(rows, f.item, f.storage, f.recent, tierName);
    }
    return null; // Preview: Groups 2-4 are not in the page
  }
  if (DATA.tierAgg && DATA.tierAgg[wlKey] && DATA.tierAgg[wlKey][tierName]) {
    var a = DATA.tierAgg[wlKey][tierName];
    return { objectCount: a.objectCount || 0, itemCount: a.itemCount || 0, storage: a.storage || 0, recentItemCount: a.recentItemCount || 0, recentStorage: a.recentStorage || 0 };
  }
  return null;
}

function computeRecoveryModel() {
  var spT = tenantTotalsFor("sharepoint"), odT = tenantTotalsFor("onedrive"), exT = tenantTotalsFor("mailboxes");
  var spTotalItems = spT.itemCount, spTotalBytes = spT.storage;
  var odTotalItems = odT.itemCount, odTotalBytes = odT.storage;
  var exTotalItems = exT.itemCount, exTotalMB = exT.storage;

  // v2.0: the average item size (size factor / per-item rates) is a property of the WHOLE tenant, so it is taken from the
  // totals that include any outlier-excluded objects. Excluding an object then changes only the work to be done, never
  // the per-item cost, which keeps "excluded" vs "included" like-for-like. Identical to 3.x when nothing is excluded.
  var spAll = tenantTotalsFor("sharepoint", true), odAll = tenantTotalsFor("onedrive", true), exAll = tenantTotalsFor("mailboxes", true);
  var spAvg = spAll.itemCount > 0 ? spAll.storage / spAll.itemCount : 0;
  var odAvg = odAll.itemCount > 0 ? odAll.storage / odAll.itemCount : 0;
  var exAvg = exAll.itemCount > 0 ? exAll.storage / exAll.itemCount : 0;

  var scale = Math.max(spT.objectCount, odT.objectCount);
  var spodTier = resolveLicenseTier(state.recovery.licenseTier, scale);

  // v3.1.0: ABR time (cumSP/cumOD/cumEX) is now the RECENT/hot-scope
  // cumulative recovery time - what ABR actually restores first - instead
  // of each tier's full data. Mass Recovery (cumSPObjs/... below) is
  // UNCHANGED: full-data cumulative-batch figure, since Mass Recovery has no
  // hot/cold distinction. See the Methodology tab.
  // NEW: ABR's recent-data fields (RECENT_FIELD) are always real D7 counts,
  // regardless of -Period. The live "Recovery window (days)" control (0-7)
  // linearly scales that D7 baseline down for a shorter window - e.g. a
  // 1-day window assumes 1/7 of the D7 activity happened in-scope. This is a
  // proportional estimate (Graph has no finer-than-day telemetry, and no
  // per-item change log at all), not a literal day-level figure - disclosed
  // in the Recovery tab copy. See the Methodology tab.
  var windowFactor = Math.max(0, Math.min(7, state.recovery.windowDays || 0)) / 7;

  var cumSP = 0, cumOD = 0, cumEX = 0;
  var cumSPObjs = 0, cumSPItems = 0, cumSPStorage = 0;
  var cumODObjs = 0, cumODItems = 0, cumODStorage = 0;
  var cumEXObjs = 0, cumEXItems = 0, cumEXStorage = 0;
  var milestones = {};
  var prevWall = 0;
  var lockedBeyond = false;
  TIER_ORDER.forEach(function (tierName) {
    if (lockedBeyond) { milestones[tierName] = { locked: true }; return; }
    var spSlice = tierSliceFor("sharepoint", tierName);
    var odSlice = tierSliceFor("onedrive", tierName);
    var exSlice = tierSliceFor("mailboxes", tierName);
    if (!spSlice || !odSlice || !exSlice) {
      // v2.0 Preview: this group's data is not in the page, so there is nothing to calculate.
      milestones[tierName] = { locked: true };
      lockedBeyond = true;
      return;
    }

    var spRecentItems = spSlice.recentItemCount * windowFactor, spRecentStorage = spSlice.recentStorage * windowFactor;
    var odRecentItems = odSlice.recentItemCount * windowFactor, odRecentStorage = odSlice.recentStorage * windowFactor;
    var exRecentItems = exSlice.recentItemCount * windowFactor, exRecentStorage = exSlice.recentStorage * windowFactor;

    var spTime = recoveryTimeMinutes("SP", spSlice.objectCount, spRecentItems, spRecentStorage, spAvg, spodTier, true);
    var odTime = recoveryTimeMinutes("OD", odSlice.objectCount, odRecentItems, odRecentStorage, odAvg, spodTier, true);
    var exTime = recoveryTimeMinutes("EX", exSlice.objectCount, exRecentItems, exRecentStorage, exAvg, spodTier, true);

    cumSP += spTime; cumOD += odTime; cumEX += exTime;

    cumSPObjs += spSlice.objectCount; cumSPItems += spSlice.itemCount; cumSPStorage += spSlice.storage;
    cumODObjs += odSlice.objectCount; cumODItems += odSlice.itemCount; cumODStorage += odSlice.storage;
    cumEXObjs += exSlice.objectCount; cumEXItems += exSlice.itemCount; cumEXStorage += exSlice.storage;

    var massSPTime = recoveryTimeMinutes("SP", cumSPObjs, cumSPItems, cumSPStorage, spAvg, spodTier, false);
    var massODTime = recoveryTimeMinutes("OD", cumODObjs, cumODItems, cumODStorage, odAvg, spodTier, false);
    var massEXTime = recoveryTimeMinutes("EX", cumEXObjs, cumEXItems, cumEXStorage, exAvg, spodTier, false);
    var massCumMin = Math.max(massSPTime, massODTime, massEXTime);

    // v3.17.0: ABR for a scope can never be slower than mass-restoring that
    // SAME scope (ABR restores only the hot slice of those groups). The raw
    // ABR figure carries per-object job-scheduling overhead that Mass does not
    // model, so on object-heavy tenants it can overshoot. Cap at Mass for the
    // same scope and keep milestones monotonic.
    var abrRawCum = Math.max(cumSP, cumOD, cumEX);
    var cappedByMass = abrRawCum > massCumMin;
    var cappedWall = Math.max(prevWall, Math.min(abrRawCum, massCumMin));
    prevWall = cappedWall;

    milestones[tierName] = {
      sp: { objectCount: spSlice.objectCount, itemCount: spSlice.itemCount, storage: spSlice.storage, timeMin: spTime, cumMin: cumSP, massTimeMin: massSPTime },
      od: { objectCount: odSlice.objectCount, itemCount: odSlice.itemCount, storage: odSlice.storage, timeMin: odTime, cumMin: cumOD, massTimeMin: massODTime },
      ex: { objectCount: exSlice.objectCount, itemCount: exSlice.itemCount, storage: exSlice.storage, timeMin: exTime, cumMin: cumEX, massTimeMin: massEXTime },
      wallClockCumMin: cappedWall,
      abrRawCumMin: abrRawCum,
      cappedByMass: cappedByMass,
      massRecoveryCumMin: massCumMin,
      exceedsTarget: false,
      targetGapMin: 0
    };
  });

  // NEW v3.1.0: per-group RTO compliance flag, replacing the old "Beyond
  // Target" tier - each of Group 1/2/3's own ABR (hot-scope) cumulative time
  // is checked against its target; if it runs over, flag it in place rather
  // than exiling the responsible object(s) to a 5th tier.
  var targetsMin = state.recovery.groupHours.map(function (h) { return h * 60; });
  critKeys().forEach(function (tierName, idx) {
    var m = milestones[tierName];
    if (m.locked) { return; }
    var target = targetsMin[idx];
    if (target > 0 && m.wallClockCumMin > target) {
      m.exceedsTarget = true;
      m.targetGapMin = m.wallClockCumMin - target;
    }
  });

  var fullSP = recoveryTimeMinutes("SP", spT.objectCount, spTotalItems, spTotalBytes, spAvg, spodTier, false);
  var fullOD = recoveryTimeMinutes("OD", odT.objectCount, odTotalItems, odTotalBytes, odAvg, spodTier, false);
  var fullEX = recoveryTimeMinutes("EX", exT.objectCount, exTotalItems, exTotalMB, exAvg, spodTier, false);
  var fullRestoreMin = Math.max(fullSP, fullOD, fullEX);

  // Whole-tenant Mass Recovery figure - used ONLY by the Total section now
  // (where it should equal the last milestone's massRecoveryCumMin, since
  // the cumulative scope through Dormant IS the whole tenant). Every other
  // group uses that milestone's own massRecoveryCumMin above instead.
  var massRecoveryMin = fullRestoreMin;

  return {
    milestones: milestones, fullRestoreMin: fullRestoreMin, massRecoveryMin: massRecoveryMin, spodTierBucket: spodTier.Bucket,
    // Per-workload full-dataset ("Mass Recovery" for THAT workload alone) times - used in the per-group workload breakdown table.
    perWorkloadMassRecoveryMin: { sp: fullSP, od: fullOD, ex: fullEX }
  };
}

function fmtMin(min) {
  if (!isFinite(min) || min <= 0) { return "0 min"; }
  if (min < 60) { return Math.round(min) + " min"; }
  if (min < 1440) { return (min / 60).toFixed(1) + " hr"; }
  return (min / 1440).toFixed(1) + " days";
}
function fmtHours(min) { return (min / 60); }
function fmtNum(n) { if (n === undefined || n === null || isNaN(n)) { return "0"; } return Math.round(n).toLocaleString(); }
function fmtMoney(n) { if (n === undefined || n === null || isNaN(n)) { return "$0"; } return "$" + Math.round(n).toLocaleString(); }
// NEW: Sizing tab - bytes to GB, matching the report's existing StorageUsedGB
// convention (PowerShell's binary 1GB = 1073741824), not decimal.
function fmtGB(bytes) { if (!bytes || isNaN(bytes)) { return "0.00"; } return (bytes / 1073741824).toFixed(2); }
function esc(s) { var d = document.createElement("div"); d.textContent = (s === null || s === undefined) ? "" : String(s); return d.innerHTML; }
'@

#endregion

#region ---------- HTML report JS: v2 shared UI toolkit (units, sorting, accordions, info bubbles, links) ----------

$script:ReportJsUi = @'
// ===================================================================================
// v2.0 shared UI toolkit. Loaded after the recovery engine, before every renderer.
// Everything a renderer needs that is NOT specific to one tab lives here:
//   - storage units (one unit for the whole report: GB, or TB when the tenant is large)
//   - sortable tables (DOM sort for static tables, data sort helpers for object tables)
//   - accordions (collapsed by default, lazy body render, state survives re-render)
//   - info bubbles (click popovers)
//   - linked summaries (data-link navigation: tab -> section -> expanded accordion)
//   - cost-avoided calculation (single place, used by Exec / Report / Summary)
//   - Preview lock helpers
// ASCII only (the .ps1 that embeds this must stay ASCII for Windows PowerShell 5.1).
// ===================================================================================

var uiState = { acc: { "grp-controls-acc": true }, sort: {}, unit: null, openInfo: null };

// ---------- period / language helpers ----------
function periodDays() {
  var m = /D(\d+)/i.exec((DATA.meta && DATA.meta.period) || "");
  return m ? parseInt(m[1], 10) : 180;
}
// Group 4 wording. Never says active/inactive/dormant; always states the real lookback period.
function group4Disclaimer() {
  return lowName() + " holds objects with little to no activity in the past " + periodDays() + " days.";
}

// ---------- storage units ----------
var BYTES_PER_GB = 1073741824;
var BYTES_PER_TB = 1099511627776;
var TB_THRESHOLD_BYTES = 5 * BYTES_PER_TB; // above this the whole report switches to TB

function rowStorageBytes(wlKey, row) {
  var m = (row && row.metrics) || {};
  if (wlKey === "mailboxes") { return (parseFloat(m.StorageUsedMB) || 0) * 1048576; }
  var b = parseFloat(m.StorageBytes);
  if (!isNaN(b) && b > 0) { return b; }
  return (parseFloat(m.StorageUsedGB) || parseFloat(m.Storage) || 0) * BYTES_PER_GB;
}
function tenantStorageBytes() {
  var sp = tenantTotalsFor("sharepoint"), od = tenantTotalsFor("onedrive"), ex = tenantTotalsFor("mailboxes");
  return sp.storage + od.storage + ex.storage * 1048576;
}
function autoStorageUnit() { return tenantStorageBytes() > TB_THRESHOLD_BYTES ? "TB" : "GB"; }
function storageUnit() {
  if (!uiState.unit) { uiState.unit = autoStorageUnit(); }
  return uiState.unit;
}
function setStorageUnit(u) {
  if (u !== "GB" && u !== "TB") { return; }
  uiState.unit = u;
  recomputeAll();
}
function bytesToUnit(bytes) { return (bytes || 0) / (storageUnit() === "TB" ? BYTES_PER_TB : BYTES_PER_GB); }
// Number only (no unit label) - for table cells under a header that already says the unit.
function fmtStorageNum(bytes) {
  var v = bytesToUnit(bytes);
  if (!isFinite(v) || v <= 0) { return "0"; }
  var digits = storageUnit() === "TB" ? 3 : 2;
  var min = Math.pow(10, -digits);
  if (v < min) { return "<" + min.toFixed(digits); }
  return v.toLocaleString(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits });
}
function fmtStorage(bytes) { return fmtStorageNum(bytes) + " " + storageUnit(); }
function fmtStorageMB(mb) { return fmtStorage((mb || 0) * 1048576); }
function fmtStorageGBVal(gb) { return fmtStorage((gb || 0) * BYTES_PER_GB); }
function storageHeader(label) { return (label || "Storage") + " (" + storageUnit() + ")"; }

function setTheme(name) {
  document.documentElement.setAttribute("data-theme", name === "dark" ? "dark" : "light");
  try { window.localStorage.setItem("m365Theme", name === "dark" ? "dark" : "light"); } catch (e) {}
  renderHeaderExtras();
}
function renderHeaderExtras() {
  var cal = document.getElementById("hdr-calib");
  if (cal) {
    cal.innerHTML = 'Recovery model: <b>calibration ' + esc((DATA.meta && DATA.meta.calibrationVersion) || "v1") + '</b> ' + infoBtn("calibration", "About the recovery model calibration");
  }
  var th = document.getElementById("hdr-theme");
  if (th) {
    var cur = document.documentElement.getAttribute("data-theme") || "light";
    th.innerHTML = 'Theme: <span class="unit-toggle" role="group" aria-label="Color theme">' +
      '<button type="button" class="unit-btn' + (cur === "light" ? " active" : "") + '" onclick="setTheme(\'light\')" aria-pressed="' + (cur === "light") + '">Light</button>' +
      '<button type="button" class="unit-btn' + (cur === "dark" ? " active" : "") + '" onclick="setTheme(\'dark\')" aria-pressed="' + (cur === "dark") + '">Dark</button></span>';
  }
  var el = document.getElementById("hdr-unit");
  if (!el) { return; }
  var u = storageUnit();
  el.innerHTML = 'Units: <span class="unit-toggle" role="group" aria-label="Storage units">' +
    '<button type="button" class="unit-btn' + (u === "GB" ? " active" : "") + '" onclick="setStorageUnit(\'GB\')" aria-pressed="' + (u === "GB") + '">GB</button>' +
    '<button type="button" class="unit-btn' + (u === "TB" ? " active" : "") + '" onclick="setStorageUnit(\'TB\')" aria-pressed="' + (u === "TB") + '">TB</button></span>';
}

// ---------- sortable tables ----------
// Static tables: every <table> that has a <thead> and is not class="no-sort" is made sortable by
// enhanceTables(root). Cells may carry data-sort="<number or text>"; otherwise the text is parsed.
// Object tables (capped to the top N rows) sort the FULL filtered data set before the cap - those use
// sortThHtml()/getSort()/applySort() below instead, so the cap never hides the real top/bottom rows.
function parseCellValue(cell) {
  if (cell.hasAttribute("data-sort")) {
    var d = cell.getAttribute("data-sort");
    var n0 = parseFloat(d);
    return (isNaN(n0) || String(n0) !== String(d).trim()) ? { t: d.toLowerCase() } : { n: n0 };
  }
  var txt = (cell.textContent || "").replace(/\s+/g, " ").trim();
  var m = /^[~<>]?\s*\$?\s*(-?[\d,]*\.?\d+)\s*(min|hr|days|day|%|gb|tb|mb|x)?\b/i.exec(txt);
  if (m) {
    var v = parseFloat(m[1].replace(/,/g, ""));
    var u = (m[2] || "").toLowerCase();
    if (u === "hr") { v *= 60; } else if (u === "day" || u === "days") { v *= 1440; }
    else if (u === "tb") { v *= 1024; } else if (u === "mb") { v /= 1024; }
    return { n: v };
  }
  return { t: txt.toLowerCase() };
}
function sortDomTable(table, colIdx, dir) {
  var tbody = table.tBodies[0];
  if (!tbody) { return; }
  var rows = Array.prototype.slice.call(tbody.rows).filter(function (r) { return !r.classList.contains("no-sort-row") && r.cells.length > colIdx; });
  var keyed = rows.map(function (r, i) { return { r: r, i: i, v: parseCellValue(r.cells[colIdx]) }; });
  var numeric = keyed.filter(function (k) { return k.v.n !== undefined; }).length >= keyed.length / 2;
  keyed.sort(function (a, b) {
    var c;
    if (numeric) {
      var av = a.v.n === undefined ? -Infinity : a.v.n, bv = b.v.n === undefined ? -Infinity : b.v.n;
      c = av - bv; if (isNaN(c)) { c = 0; }
    } else {
      var at = a.v.t !== undefined ? a.v.t : String(a.v.n), bt = b.v.t !== undefined ? b.v.t : String(b.v.n);
      c = at.localeCompare(bt);
    }
    if (c === 0) { return a.i - b.i; }
    return dir === "asc" ? c : -c;
  });
  keyed.forEach(function (k) { tbody.appendChild(k.r); });
  Array.prototype.forEach.call(table.tHead.rows[table.tHead.rows.length - 1].cells, function (th, i) {
    th.classList.remove("sort-asc", "sort-desc");
    th.removeAttribute("aria-sort");
    if (i === colIdx) { th.classList.add(dir === "asc" ? "sort-asc" : "sort-desc"); th.setAttribute("aria-sort", dir === "asc" ? "ascending" : "descending"); }
  });
}
function tableSortId(table) {
  if (!table.__sortId) {
    var host = table.closest("[id]");
    var all = host ? host.querySelectorAll("table") : [];
    table.__sortId = (host ? host.id : "doc") + "#" + Array.prototype.indexOf.call(all, table);
  }
  return table.__sortId;
}
function enhanceTables(root) {
  var scope = root || document;
  Array.prototype.forEach.call(scope.querySelectorAll("table"), function (table) {
    if (table.classList.contains("no-sort") || table.hasAttribute("data-datasort") || !table.tHead || !table.tBodies.length) { return; }
    var hr = table.tHead.rows[table.tHead.rows.length - 1];
    Array.prototype.forEach.call(hr.cells, function (th) { th.classList.add("sortable-th"); th.setAttribute("tabindex", "0"); });
    var saved = uiState.sort[tableSortId(table)];
    if (saved && saved.col < hr.cells.length) { sortDomTable(table, saved.col, saved.dir); }
  });
}
function onSortActivate(th) {
  var table = th.closest("table");
  if (!table || table.classList.contains("no-sort") || table.hasAttribute("data-datasort") || !th.classList.contains("sortable-th")) { return; }
  var idx = Array.prototype.indexOf.call(th.parentNode.cells, th);
  var id = tableSortId(table);
  var cur = uiState.sort[id];
  // first click: numeric columns high to low, text columns A to Z
  var sample = table.tBodies[0] && table.tBodies[0].rows[0] && table.tBodies[0].rows[0].cells[idx];
  var numericFirst = sample ? (parseCellValue(sample).n !== undefined) : false;
  var dir = (cur && cur.col === idx) ? (cur.dir === "asc" ? "desc" : "asc") : (numericFirst ? "desc" : "asc");
  uiState.sort[id] = { col: idx, dir: dir };
  sortDomTable(table, idx, dir);
}
document.addEventListener("click", function (e) {
  var th = e.target.closest ? e.target.closest("th.sortable-th") : null;
  if (th) { onSortActivate(th); }
});
document.addEventListener("keydown", function (e) {
  if ((e.key === "Enter" || e.key === " ") && e.target.classList && e.target.classList.contains("sortable-th")) { e.preventDefault(); onSortActivate(e.target); }
});

// Data-driven sorting for capped object tables. tableKey identifies the table (e.g. "obj-mailboxes").
// cols: [{key, label, type: "num"|"text", get: function(row) -> value, cls}] ; rerender: function() called after a click.
var SORT_RERENDER = {};
function getSort(tableKey, defaultCol, defaultDir) {
  return uiState.sort["data:" + tableKey] || { col: defaultCol, dir: defaultDir || "desc" };
}
function setTableSort(tableKey, colKey, type) {
  var cur = uiState.sort["data:" + tableKey];
  var dir = (cur && cur.col === colKey) ? (cur.dir === "asc" ? "desc" : "asc") : (type === "text" ? "asc" : "desc");
  uiState.sort["data:" + tableKey] = { col: colKey, dir: dir };
  if (SORT_RERENDER[tableKey]) { SORT_RERENDER[tableKey](); }
}
function sortThHtml(tableKey, col, defaultCol, defaultDir) {
  var s = getSort(tableKey, defaultCol, defaultDir);
  var active = s.col === col.key;
  var cls = "sortable-th" + (col.cls ? " " + col.cls : "") + (active ? (s.dir === "asc" ? " sort-asc" : " sort-desc") : "");
  return '<th class="' + cls + '" tabindex="0" ' + (active ? 'aria-sort="' + (s.dir === "asc" ? "ascending" : "descending") + '" ' : "") +
    'onclick="setTableSort(\'' + tableKey + '\',\'' + col.key + '\',\'' + (col.type || "num") + '\')" ' +
    'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();setTableSort(\'' + tableKey + '\',\'' + col.key + '\',\'' + (col.type || "num") + '\');}">' + col.label + '</th>';
}
function applySort(rows, tableKey, cols, defaultCol, defaultDir) {
  var s = getSort(tableKey, defaultCol, defaultDir);
  var col = cols.filter(function (c) { return c.key === s.col; })[0] || cols[0];
  var sign = s.dir === "asc" ? 1 : -1;
  var keyed = rows.map(function (r, i) { return { r: r, i: i, v: col.get(r) }; });
  keyed.sort(function (a, b) {
    var c;
    if (col.type === "text") { c = String(a.v == null ? "" : a.v).toLowerCase().localeCompare(String(b.v == null ? "" : b.v).toLowerCase()); }
    else { c = (parseFloat(a.v) || 0) - (parseFloat(b.v) || 0); }
    return c === 0 ? a.i - b.i : c * sign;
  });
  return keyed.map(function (k) { return k.r; });
}

// ---------- accordions ----------
var ACC_BODY = {};   // id -> function returning the body html (rendered lazily on first open)
// opts: {id, title, summary (html, always visible), body (html string or function), level, cls}
function accHtml(opts) {
  var id = opts.id;
  ACC_BODY[id] = (typeof opts.body === "function") ? opts.body : function () { return opts.body || ""; };
  var open = !!uiState.acc[id];
  var inner = open ? ACC_BODY[id]() : "";
  return '<div class="acc ' + (opts.cls || "") + (open ? " open" : "") + '" id="acc-' + id + '" data-acc="' + id + '">' +
    '<button type="button" class="acc-head" aria-expanded="' + (open ? "true" : "false") + '" aria-controls="accb-' + id + '" onclick="toggleAcc(\'' + id + '\')">' +
      '<span class="acc-chev" aria-hidden="true">&#9656;</span>' +
      '<span class="acc-title">' + opts.title + '</span>' +
      '<span class="acc-summary">' + (opts.summary || "") + '</span>' +
    '</button>' +
    '<div class="acc-body" id="accb-' + id + '"' + (open ? "" : " hidden") + (open ? ' data-rendered="1"' : "") + '>' + inner + '</div>' +
  '</div>';
}
function toggleAcc(id, forceOpen) {
  var host = document.getElementById("acc-" + id);
  if (!host) { return; }
  var body = document.getElementById("accb-" + id);
  var open = (forceOpen === undefined) ? !uiState.acc[id] : !!forceOpen;
  uiState.acc[id] = open;
  host.classList.toggle("open", open);
  host.querySelector(".acc-head").setAttribute("aria-expanded", open ? "true" : "false");
  if (open) {
    if (!body.getAttribute("data-rendered") && ACC_BODY[id]) { body.innerHTML = ACC_BODY[id](); body.setAttribute("data-rendered", "1"); enhanceTables(body); }
    body.removeAttribute("hidden");
  } else { body.setAttribute("hidden", ""); }
}
function openAcc(id) { toggleAcc(id, true); }

// ---------- info bubbles ----------
var INFO = {}; // key -> {title, html}
function registerInfo(key, title, html) { INFO[key] = { title: title, html: html }; }
function infoBtn(key, label) {
  return '<button type="button" class="info-btn" aria-label="' + (label || "More information") + '" aria-haspopup="dialog" onclick="showInfo(event,\'' + key + '\')">i</button>';
}
function closeInfo() {
  var p = document.getElementById("info-pop");
  if (p) { p.parentNode.removeChild(p); }
  if (uiState.openInfo && uiState.openInfo.btn) { uiState.openInfo.btn.setAttribute("aria-expanded", "false"); }
  uiState.openInfo = null;
}
function showInfo(ev, key) {
  ev.stopPropagation();
  var btn = ev.currentTarget || ev.target;
  var wasOpen = uiState.openInfo && uiState.openInfo.key === key && uiState.openInfo.btn === btn;
  closeInfo();
  if (wasOpen) { return; }
  var info = INFO[key];
  if (!info) { return; }
  var pop = document.createElement("div");
  pop.id = "info-pop"; pop.className = "info-pop"; pop.setAttribute("role", "dialog"); pop.setAttribute("aria-label", info.title);
  pop.innerHTML = '<div class="info-pop-title">' + info.title + '<button type="button" class="info-pop-close" aria-label="Close" onclick="closeInfo()">&times;</button></div><div class="info-pop-body">' + info.html + '</div>';
  document.body.appendChild(pop);
  var r = btn.getBoundingClientRect();
  var w = Math.min(420, window.innerWidth - 24);
  pop.style.width = w + "px";
  var left = Math.max(12, Math.min(r.left + window.pageXOffset - 16, window.pageXOffset + window.innerWidth - w - 12));
  pop.style.left = left + "px";
  pop.style.top = (r.bottom + window.pageYOffset + 8) + "px";
  btn.setAttribute("aria-expanded", "true");
  uiState.openInfo = { key: key, btn: btn };
}
document.addEventListener("click", function (e) {
  if (!uiState.openInfo) { return; }
  var pop = document.getElementById("info-pop");
  if (pop && pop.contains(e.target)) { return; }
  closeInfo();
});
document.addEventListener("keydown", function (e) { if (e.key === "Escape") { closeInfo(); } });

// ---------- linked summaries ----------
// A summary element carries data-link="tab[:sectionId[:accId,accId,...]]". Clicking it switches to the tab,
// opens the listed accordions, scrolls the section into view and flashes it. navAttr() builds the attributes.
function navAttr(target) { return 'data-link="' + target + '" role="link" tabindex="0"'; }
function navigateTo(target) {
  var parts = String(target).split(":");
  var tab = parts[0], section = parts[1] || "", acc = parts[2] ? parts[2].split(",") : [];
  switchTab(tab);
  acc.forEach(function (id) { if (document.getElementById("acc-" + id)) { openAcc(id); } });
  var el = section ? (document.getElementById(section) || document.getElementById("acc-" + section)) : null;
  if (!el && acc.length) { el = document.getElementById("acc-" + acc[acc.length - 1]); }
  if (el) {
    if (el.scrollIntoView) { el.scrollIntoView({ behavior: "smooth", block: "start" }); }
    el.classList.add("link-flash");
    setTimeout(function () { el.classList.remove("link-flash"); }, 1600);
  } else if (window.scrollTo) { window.scrollTo(0, 0); }
}
document.addEventListener("click", function (e) {
  var el = e.target.closest ? e.target.closest("[data-link]") : null;
  if (el && !(e.target.closest && e.target.closest(".info-btn"))) { e.preventDefault(); navigateTo(el.getAttribute("data-link")); }
});
document.addEventListener("keydown", function (e) {
  if (e.key !== "Enter") { return; }
  var el = e.target.closest ? e.target.closest("[data-link]") : null;
  if (el) { e.preventDefault(); navigateTo(el.getAttribute("data-link")); }
});

// ---------- cost avoided (single source for Exec / Report / Summary) ----------
// Baseline: restoring the whole tenant as one undifferentiated job (Mass Recovery) - data is usable when that job finishes.
// ABR: the milestone at which Groups 1..N are back. Hours saved never goes negative (ABR is capped at Mass for the same scope,
// and per-object scheduling can make later milestones exceed the whole-tenant baseline on small tenants - shown as 0, not negative).
function computeCostAvoided(model) {
  var perHour = parseFloat(state.recovery.costPerHour) || 0;
  var baseline = model.fullRestoreMin;
  var rows = [];
  critKeys().map(function (key, i) { return [key, scopeName(i + 1) + " online", "Group " + (i + 1)]; }).forEach(function (d) {
    var m = model.milestones[d[0]];
    if (!m || m.locked) { rows.push({ tier: d[0], label: d[1], short: d[2], locked: true }); return; }
    var saved = Math.max(0, baseline - m.wallClockCumMin);
    rows.push({ tier: d[0], label: d[1], short: d[2], locked: false, abrMin: m.wallClockCumMin, baselineMin: baseline, savedMin: saved, savedHours: saved / 60, cost: (saved / 60) * perHour });
  });
  return { perHour: perHour, baselineMin: baseline, rows: rows, hasRate: perHour > 0 };
}
function costPromptHtml() {
  return '<span class="cost-prompt">Enter your estimated downtime cost per hour to see potential cost avoidance.</span>';
}

// ---------- Preview lock helpers ----------
function pvLocked(placeholder) {
  return '<span class="pv-locked-value">' + (placeholder || "&bull;&bull;&bull;&bull;") + '</span><span class="pv-locked-tag">Full assessment</span>';
}
var CONTACT_SALES_URL = "https://www.rubrik.com/contact-sales?v2";
function pvLockedPanel(title, note) {
  return '<div class="pv-locked-panel"><div class="pv-locked-panel-icon">&#128274;</div>' +
    '<div class="pv-locked-panel-title">' + esc(title) + '</div>' +
    '<div class="pv-locked-panel-note">' + esc(note || "Available in the full assessment.") + ' <a href="' + CONTACT_SALES_URL + '" target="_blank" rel="noopener">Contact your Rubrik representative</a>.</div></div>';
}
function offlineBannerHtml() {
  var m = (typeof DATA !== "undefined" && DATA.meta) || {};
  if (!m.offlineMode) { return ""; }
  var miss = (m.offlineMissing && m.offlineMissing.length) ? " Not supplied: " + m.offlineMissing.map(esc).join(", ") + "." : "";
  return '<div class="pv-banner"><b>Offline run - reduced confidence.</b> Built from exported admin center usage reports, with no tenant connection. ' +
    'Not collected: user profile enrichment (title, department, manager, groups), license-based mailbox classification, Team-to-site mapping, archive mailbox and Recoverable Items sizes. ' +
    'Mailbox counts may include unlicensed or shared mailboxes, and sizes exclude Recoverable Items.' + miss + ' Do not compare directly with a live run.</div>';
}
function previewBannerHtml() {
  return '<div class="pv-banner"><b>Preview.</b> This report shows Critical Group 1 only. Group 2-4 detail, recovery sequencing, and cost avoidance by group are available in the full assessment. ' +
    '<a href="' + CONTACT_SALES_URL + '" target="_blank" rel="noopener">Contact your Rubrik representative</a> to run the full assessment (it requires re-running the script against your tenant).</div>';
}

registerInfo("calibration", "Recovery model calibration",
  "<p>Recovery times use the throughput constants from the Rubrik M365 recovery time estimator (SharePoint/OneDrive items per minute per parallel unit, Exchange per-mailbox rates, job scheduling cost, size factor). " +
  "These constants are the same as the previous version of this assessment, so a repeat run on the same data produces the same recovery times.</p>" +
  "<p>If Rubrik updates the benchmarks, the calibration version shown here changes so any difference between two runs can be explained.</p>");

'@

#endregion

#region ---------- HTML report JS: v2 Recovery Insights (abnormal-object detection) ----------

$script:ReportJsInsights = @'
// ===================================================================================
// v2.0 Recovery Insights - abnormal-object detection.
//
//   computeInsights()        - runs after tiering on every recomputeAll(). Sets row._excl (true = peer outlier or
//                              concentration object, excluded from the headline model while state.insights.exclude)
//                              and row._flags (array of flag ids, or null) on every object row. Result in INSIGHTS.
//   getInsights()            - the full result object (shape below)
//   getInsightsSummary()     - small shape used by the Executive Summary and the Groups & Recovery Model tab
//   modelWithExclusion(flag) - computeRecoveryModel() with exclusion forced on/off, then restored
//   setExcludeOutliers(bool) - toggles state.insights.exclude and re-renders everything
//   setInsightFilter(flagId) - filters the Insights table to one flag (null = all)
//   renderInsightsTab()      - renders #panel-insights
//
// How "abnormal" is decided (no fixed size thresholds - each tenant is compared with ITS OWN distribution):
//   peer-size / peer-items : value > 5x the workload's own 99th percentile AND >= 0.1% of the workload total
//   concentration          : one object holds >= 2% of the workload's total storage or items
//   long-pole-abr          : the object's own hot-data (last 7 days) restore time exceeds its group's pooled ABR time
//   long-pole-mass         : the object's own full restore time exceeds the pooled whole-workload Mass time
//   high-recent-change     : peer-outlier test on the 7-day change field
//   critical-lower-group   : score in the top decile of its workload but the object sits in Critical Group 3 / Group 4
//   near-mailbox-limit     : mailbox storage >= 95% of its mailbox limit (MailboxLimitBytes, when known)
// Only peer-size, peer-items and concentration set row._excl. Long-pole times for SharePoint/OneDrive are shown as a
// RANGE (full tier rate .. one parallel unit) because single-object parallelism is unconfirmed, and are never part of
// any headline number (state.insights.floorInHeadline stays false).
//
// INSIGHTS shape:
//   { flagged: [ { wl, row, flags:[ids], excluded:bool (peer/concentration), reason:"plain-language sentence(s)",
//                  storageBytes, items, recent, singleObjectMin (number: mailbox full time; SP/OD low end),
//                  singleObjectMinHigh (SP/OD one-unit time, else same as singleObjectMin),
//                  hotObjectMin, hotObjectMinHigh } ],
//     byFlag: { "peer-size": 3, ... }, excludedCount: 3,
//     baselines: { sharepoint: { n, scope:"tenant"|"group1", storageP50, storageP95, storageP99, itemsP50, itemsP95, itemsP99,
//                                recentP50, recentP95, recentP99, totalStorage, totalItems } } }
// getInsightsSummary() shape:
//   { total, excludedCount, byFlag, topRisks:[{id,title,detail,link}], headline:{excludedG1Min,includedG1Min,deltaG1Min,excludedMassMin,includedMassMin}|null }
// ASCII only.
// ===================================================================================
var INSIGHT_PEER_MULT = 5;          // x the workload's own 99th percentile
var INSIGHT_PEER_MIN_SHARE = 0.001; // and at least 0.1% of the workload total
var INSIGHT_CONC_SHARE = 0.02;      // 2% of the workload total
var INSIGHT_PEER_MIN_N = 20;        // below this many objects a percentile baseline is not meaningful
var INSIGHT_CONC_MIN_N = 100;       // below this many objects every object would "hold 2%"
var INSIGHT_LIMIT_FRAC = 0.95;      // mailbox at 95% of its limit
var INSIGHT_TOP_DECILE = 0.9;
var INSIGHT_MIN_POLE_MIN = 60;      // a long pole only matters if the object alone takes at least an hour
var INSIGHT_TABLE_CAP = 500;
var INSIGHT_WL = ["mailboxes", "onedrive", "sharepoint"];
var INSIGHT_WL_META = {
  mailboxes:  { one: "mailbox", plural: "mailboxes", yours: "your mailboxes", label: "Mailboxes", key: "ex", noun: "mailboxes" },
  onedrive:   { one: "OneDrive account", plural: "OneDrive accounts", yours: "your OneDrive accounts", label: "OneDrive", key: "od", noun: "OneDrive accounts" },
  sharepoint: { one: "site", plural: "SharePoint sites", yours: "your SharePoint sites", label: "SharePoint", key: "sp", noun: "SharePoint sites" }
};
var INSIGHT_FLAGS = {
  "peer-size":            { label: "Much larger than peers",       tile: "Unusually large",           impact: "A single very large object cannot be split up, so it can stretch recovery well past the rest.", excl: true },
  "peer-items":           { label: "Far more items than peers",    tile: "Unusually many items",      impact: "Restore speed is limited by items per minute, so an object with a huge item count takes far longer.", excl: true },
  "concentration":        { label: "Large share of workload",      tile: "Large share of a workload", impact: "One object that holds a big share of a workload can move that workload's totals by itself.", excl: true },
  "long-pole-abr":        { label: "Slow to restore (ABR)",        tile: "Sets the pace for ABR",     impact: "Its group is only fully back when this object finishes." , excl: false },
  "long-pole-mass":       { label: "Slow to restore (Mass)",       tile: "Sets the pace for Mass",    impact: "A whole-tenant restore is only finished when this object finishes.", excl: false },
  "high-recent-change":   { label: "Heavy recent change",          tile: "Heavy recent change",       impact: "The more that changed in the last 7 days, the longer ABR takes for this object.", excl: false },
  "critical-lower-group": { label: "Looks critical, lower group",  tile: "Looks critical, lower group", impact: "Its score is in the top 10% of its workload but it is not in Group 1 or 2. Worth a manual check.", excl: false },
  "near-mailbox-limit":   { label: "Near mailbox limit",           tile: "Near mailbox limit",        impact: "A full mailbox is the slowest kind to restore and a growth risk.", excl: false }
};
var INSIGHT_FLAG_ORDER = ["peer-size", "peer-items", "concentration", "long-pole-abr", "long-pole-mass", "high-recent-change", "critical-lower-group", "near-mailbox-limit"];

var INSIGHTS = { flagged: [], byFlag: {}, baselines: {}, excludedCount: 0 };
var insightFilter = null;
var insightSummaryCache = null;
var NO_INSIGHT_FLAGS = null;

// ---------- small helpers ----------
function insightPct(sorted, p) {
  var n = sorted.length;
  if (n === 0) { return 0; }
  var idx = Math.ceil(p * n) - 1;
  if (idx < 0) { idx = 0; }
  if (idx >= n) { idx = n - 1; }
  return sorted[idx];
}
function insightCount(n) {
  if (n >= 1000000) { return (n / 1000000).toFixed(1) + " million"; }
  return fmtNum(n);
}
function insightAddFlag(row, id) {
  if (!row._flags) { row._flags = []; }
  if (row._flags.indexOf(id) === -1) { row._flags.push(id); }
  if (INSIGHT_FLAGS[id].excl) { row._excl = true; }
}
function insightTierShort(row) { var m = TIER_META[row.Tier]; return m ? m.short : (row.Tier || ""); }
function insightIdentity(row) { return row.ObjectName || row.Identifier || "(unnamed)"; }

// Single-object restore minutes. Mailboxes use the per-mailbox rates (one mailbox = one parallel restore).
// SharePoint/OneDrive: [time at the full tier rate, time at one parallel unit] because how many parallel units one site/
// OneDrive can use is not yet confirmed.
function insightMailboxMin(mb, items) {
  var byBytes = mb > 0 ? mb / EX_BENCHMARK.PerMailboxMBPerMin : 0;
  var byItems = items > 0 ? items / EX_BENCHMARK.PerMailboxItemsPerMin : 0;
  return Math.max(byBytes, byItems) * EX_BENCHMARK.OverheadBuffer;
}

// ---------- compute ----------
function computeInsights() {
  insightSummaryCache = null;
  var res = { flagged: [], byFlag: {}, baselines: {}, excludedCount: 0 };
  INSIGHT_FLAG_ORDER.forEach(function (id) { res.byFlag[id] = 0; });
  var ctxs = {};

  // reset every row every run
  WORKLOAD_DEFS.forEach(function (wd) {
    var rows = DATA.workloads[wd.key] || [];
    for (var i = 0; i < rows.length; i++) { rows[i]._excl = false; rows[i]._flags = NO_INSIGHT_FLAGS; }
  });
  INSIGHTS = res;
  if (IS_SUMMARY) { return; }

  // ---- pass 1: baselines, peer outliers, concentration, high recent change, near-limit, critical-lower-group ----
  INSIGHT_WL.forEach(function (wl) {
    var rows = DATA.workloads[wl] || [];
    var n = rows.length;
    if (n === 0) { return; }
    var f = RECOVERY_FIELDS[wl];
    var stor = new Float64Array(n), items = new Float64Array(n), recent = new Float64Array(n), score = new Float64Array(n);
    var totS = 0, totI = 0, totR = 0, i;
    for (i = 0; i < n; i++) {
      var r = rows[i], m = r.metrics || {};
      var s = rowStorageBytes(wl, r);
      var it = parseFloat(m[f.item]) || 0;
      var rc = Math.max(0, Math.min(parseFloat(m[f.recent]) || 0, it));
      stor[i] = s; items[i] = it; recent[i] = rc; score[i] = r._Score || 0;
      totS += s; totI += it; totR += rc;
    }
    var sS = Float64Array.from(stor).sort(), sI = Float64Array.from(items).sort(), sR = Float64Array.from(recent).sort(), sSc = Float64Array.from(score).sort();
    var base = {
      n: n, scope: IS_PREVIEW ? "group1" : "tenant", totalStorage: totS, totalItems: totI, totalRecent: totR,
      storageP50: insightPct(sS, 0.5), storageP95: insightPct(sS, 0.95), storageP99: insightPct(sS, 0.99),
      itemsP50: insightPct(sI, 0.5), itemsP95: insightPct(sI, 0.95), itemsP99: insightPct(sI, 0.99),
      recentP50: insightPct(sR, 0.5), recentP95: insightPct(sR, 0.95), recentP99: insightPct(sR, 0.99)
    };
    res.baselines[wl] = base;
    var scoreCut = insightPct(sSc, INSIGHT_TOP_DECILE);
    var peerOk = n >= INSIGHT_PEER_MIN_N, concOk = n >= INSIGHT_CONC_MIN_N;
    var thS = base.storageP99 * INSIGHT_PEER_MULT, thI = base.itemsP99 * INSIGHT_PEER_MULT, thR = base.recentP99 * INSIGHT_PEER_MULT;
    var minS = totS * INSIGHT_PEER_MIN_SHARE, minI = totI * INSIGHT_PEER_MIN_SHARE, minR = totR * INSIGHT_PEER_MIN_SHARE;
    var concS = totS * INSIGHT_CONC_SHARE, concI = totI * INSIGHT_CONC_SHARE;
    for (i = 0; i < n; i++) {
      var row = rows[i];
      if (peerOk) {
        if (base.storageP99 > 0 && stor[i] > thS && stor[i] >= minS) { insightAddFlag(row, "peer-size"); }
        if (base.itemsP99 > 0 && items[i] > thI && items[i] >= minI) { insightAddFlag(row, "peer-items"); }
        if (base.recentP99 > 0 && recent[i] > thR && recent[i] >= minR) { insightAddFlag(row, "high-recent-change"); }
      }
      if (concOk && ((totS > 0 && stor[i] >= concS) || (totI > 0 && items[i] >= concI))) { insightAddFlag(row, "concentration"); }
      if (wl === "mailboxes") {
        var lim = parseFloat(row.MailboxLimitBytes) || 0;
        if (lim > 0 && stor[i] >= INSIGHT_LIMIT_FRAC * lim) { insightAddFlag(row, "near-mailbox-limit"); }
      }
      if (!IS_PREVIEW && score[i] > 0 && score[i] >= scoreCut && (tierNum(row.Tier) >= Math.max(3, groupN()) || row.Tier === LOW_KEY)) { insightAddFlag(row, "critical-lower-group"); }
    }
    ctxs[wl] = { rows: rows, stor: stor, items: items, recent: recent, base: base, tot: { s: totS, i: totI } };
  });

  // ---- pass 2: long poles, against the pooled times of the (exclusion-aware) headline model ----
  var model = computeRecoveryModel();
  var spodTier = resolveLicenseTier(state.recovery.licenseTier, Math.max(tenantTotalsFor("sharepoint").objectCount, tenantTotalsFor("onedrive").objectCount));
  var wf = getWindowFactor();
  INSIGHT_WL.forEach(function (wl) {
    var c = ctxs[wl];
    if (!c) { return; }
    var meta = INSIGHT_WL_META[wl];
    var n = c.rows.length, i;
    var massPooled = model.perWorkloadMassRecoveryMin ? model.perWorkloadMassRecoveryMin[meta.key] : 0;
    var rate = 0, sf = 1, par = 1;
    if (wl !== "mailboxes") {
      rate = wl === "sharepoint" ? SP_ITEMS_PER_MIN_PER_UNIT : OD_ITEMS_PER_MIN_PER_UNIT;
      par = Math.max(1, spodTier.Parallelism);
      var avgMb = c.tot.i > 0 ? c.tot.s / c.tot.i / 1048576 : 0;
      sf = avgMb > 0 ? Math.max(1, avgMb / SIZE_FACTOR_BASELINE_MB) : 1;
    }
    for (i = 0; i < n; i++) {
      var row = c.rows[i];
      var it = c.items[i];
      if (it <= 0 && c.stor[i] <= 0) { continue; }
      var rc = c.recent[i] * wf;
      var fullHigh, fullLow, hotHigh, hotLow;
      if (wl === "mailboxes") {
        var mb = c.stor[i] / 1048576;
        fullHigh = fullLow = insightMailboxMin(mb, it);
        var frac = it > 0 ? c.recent[i] / it : 0;
        hotHigh = hotLow = insightMailboxMin(mb * frac * wf, rc);
      } else {
        fullHigh = it * sf / rate; fullLow = fullHigh / par;
        hotHigh = rc * sf / rate; hotLow = hotHigh / par;
      }
      var tierKey = row.Tier;
      // ABR applies to Groups 1-3 only; compare with that group's own pooled ABR time for the workload
      if (tierKey !== "Group 4" && hotHigh >= INSIGHT_MIN_POLE_MIN && model.milestones[tierKey] && !model.milestones[tierKey].locked) {
        var pooledAbr = model.milestones[tierKey][meta.key].timeMin;
        if (hotHigh > pooledAbr) { insightAddFlag(row, "long-pole-abr"); }
      }
      if (fullHigh >= INSIGHT_MIN_POLE_MIN && massPooled > 0 && fullHigh > massPooled) { insightAddFlag(row, "long-pole-mass"); }
      if (row._flags) {
        row._insTimes = [fullLow, fullHigh, hotLow, hotHigh];
      }
    }
  });

  // ---- collect ----
  INSIGHT_WL.forEach(function (wl) {
    var c = ctxs[wl];
    if (!c) { return; }
    var meta = INSIGHT_WL_META[wl];
    for (var i = 0; i < c.rows.length; i++) {
      var row = c.rows[i];
      if (!row._flags) { continue; }
      var t = row._insTimes || [0, 0, 0, 0];
      var entry = {
        wl: wl, row: row, flags: row._flags.slice(), excluded: !!row._excl,
        storageBytes: c.stor[i], items: c.items[i], recent: c.recent[i],
        singleObjectMin: t[0], singleObjectMinHigh: t[1], hotObjectMin: t[2], hotObjectMinHigh: t[3]
      };
      entry.reason = insightReason(wl, entry, c.base, meta, model);
      res.flagged.push(entry);
      entry.flags.forEach(function (id) { res.byFlag[id]++; });
      if (entry.excluded) { res.excludedCount++; }
    }
  });
}

function insightTimeRange(entry, wl, hot) {
  var lo = hot ? entry.hotObjectMin : entry.singleObjectMin, hi = hot ? entry.hotObjectMinHigh : entry.singleObjectMinHigh;
  if (wl === "mailboxes" || Math.abs(hi - lo) < 0.5) { return fmtMin(hi); }
  return fmtMin(lo) + " to " + fmtMin(hi);
}

function insightReason(wl, e, base, meta, model) {
  var parts = [];
  var row = e.row;
  var has = function (id) { return e.flags.indexOf(id) !== -1; };
  var sentenceCase = meta.one.charAt(0).toUpperCase() + meta.one.slice(1);
  var scopeWord = base.scope === "group1" ? "Group 1 " : "";
  var cmp = base.scope === "group1" ? "other Group 1 " + meta.plural : meta.yours;
  if (has("peer-size")) {
    parts.push("This " + meta.one + " holds " + fmtStorage(e.storageBytes) + "; 99% of " + cmp + " hold less than " + fmtStorage(base.storageP99) + " (typical: " + fmtStorage(base.storageP50) + ").");
  }
  if (has("peer-items")) {
    parts.push("This " + meta.one + " holds " + insightCount(e.items) + " items; 99% of " + cmp + " hold fewer than " + fmtNum(base.itemsP99) + " (typical: " + fmtNum(base.itemsP50) + ").");
  }
  if (has("concentration")) {
    var shS = base.totalStorage > 0 ? e.storageBytes / base.totalStorage : 0, shI = base.totalItems > 0 ? e.items / base.totalItems : 0;
    var bits = [];
    if (shS >= INSIGHT_CONC_SHARE) { bits.push((shS * 100).toFixed(1) + "% of all " + scopeWord + meta.noun + " storage"); }
    if (shI >= INSIGHT_CONC_SHARE) { bits.push((shI * 100).toFixed(1) + "% of all " + scopeWord + meta.noun + " items"); }
    parts.push("This " + meta.one + " alone holds " + bits.join(" and ") + ".");
  }
  if (has("long-pole-abr")) {
    var pooledAbr = model.milestones[row.Tier] && !model.milestones[row.Tier].locked ? model.milestones[row.Tier][meta.key].timeMin : 0;
    var txt = "Restoring just its last 7 days of changes takes roughly " + insightTimeRange(e, wl, true) + ", longer than the " + fmtMin(pooledAbr) + " estimated for its whole group, so it sets the pace for ABR.";
    if (wl !== "mailboxes") { txt += " How many parallel restores one " + meta.one + " can use is still being confirmed, hence the range."; }
    parts.push(txt);
  }
  if (has("long-pole-mass")) {
    var pooledMass = model.perWorkloadMassRecoveryMin ? model.perWorkloadMassRecoveryMin[meta.key] : 0;
    var txt2 = "Restored on its own, all of its data takes roughly " + insightTimeRange(e, wl, false) + ", longer than the " + fmtMin(pooledMass) + " estimated for all of " + meta.yours + " together.";
    if (wl !== "mailboxes") { txt2 += " The range reflects restoring on the full tier rate versus a single parallel unit."; }
    parts.push(txt2);
  }
  if (has("high-recent-change")) {
    parts.push(insightCount(e.recent) + " items changed in the last 7 days; 99% of " + cmp + " saw fewer than " + fmtNum(base.recentP99) + ". The more that changed recently, the longer ABR takes for this " + meta.one + ".");
  }
  if (has("critical-lower-group")) {
    parts.push("Its criticality score is in the top 10% of " + meta.yours + " but it sits in " + insightTierShort(row) + ". Consider whether it belongs in a higher group.");
  }
  if (has("near-mailbox-limit")) {
    var lim = parseFloat(row.MailboxLimitBytes) || 0;
    parts.push("This mailbox is at " + (lim > 0 ? Math.round(e.storageBytes / lim * 100) : 0) + "% of its " + fmtStorage(lim) + " limit. A full mailbox is the slowest kind to restore.");
  }
  if (e.excluded) { parts.push("It is excluded from the headline recovery estimates by default; include it to see the impact."); }
  return parts.join(" ");
}

function getInsights() { return INSIGHTS; }

// ---------- model with exclusion forced on/off ----------
function modelWithExclusion(flag) {
  var prev = state.insights.exclude;
  state.insights.exclude = !!flag;
  try { return computeRecoveryModel(); }
  finally { state.insights.exclude = prev; }
}
function setExcludeOutliers(on) {
  if (IS_PREVIEW || IS_SUMMARY) { return; }
  state.insights.exclude = !!on;
  recomputeAll();
}
function setInsightFilter(id) {
  insightFilter = (id && INSIGHT_FLAGS[id]) ? id : null;
  renderInsightsTab();
}

function insightHeadline() {
  if (IS_PREVIEW || IS_SUMMARY || INSIGHTS.excludedCount === 0) { return null; }
  var sig = [state.recovery.windowDays, state.recovery.licenseTier, state.recovery.groupCount, state.recovery.groupHours.join(','), INSIGHTS.excludedCount, DATA.workloads.mailboxes.length, DATA.workloads.sharepoint.length].join("|");
  if (insightSummaryCache && insightSummaryCache.sig === sig) { return insightSummaryCache.headline; }
  var ex = modelWithExclusion(true), inc = modelWithExclusion(false);
  var g = "Critical Group 1";
  var h = null;
  if (ex.milestones[g] && !ex.milestones[g].locked && inc.milestones[g] && !inc.milestones[g].locked) {
    h = {
      excludedG1Min: ex.milestones[g].wallClockCumMin, includedG1Min: inc.milestones[g].wallClockCumMin,
      deltaG1Min: inc.milestones[g].wallClockCumMin - ex.milestones[g].wallClockCumMin,
      excludedMassMin: ex.fullRestoreMin, includedMassMin: inc.fullRestoreMin
    };
  }
  insightSummaryCache = { sig: sig, headline: h };
  return h;
}

function getInsightsSummary() {
  var topRisks = [];
  var groups = {}; // flagId|wl -> {count, g1, flagId, wl, example}
  INSIGHTS.flagged.forEach(function (e) {
    e.flags.forEach(function (id) {
      var k = id + "|" + e.wl;
      if (!groups[k]) { groups[k] = { id: id, wl: e.wl, count: 0, g1: 0, bytes: 0, maxMin: 0 }; }
      var g = groups[k];
      g.count++;
      if (e.row.Tier === "Critical Group 1") { g.g1++; }
      g.bytes += e.storageBytes;
      if (e.singleObjectMinHigh > g.maxMin) { g.maxMin = e.singleObjectMinHigh; }
    });
  });
  var weight = { "long-pole-abr": 6, "peer-size": 5, "peer-items": 5, "long-pole-mass": 4, "concentration": 3, "high-recent-change": 3, "critical-lower-group": 2, "near-mailbox-limit": 1 };
  var list = Object.keys(groups).map(function (k) { return groups[k]; });
  list.sort(function (a, b) {
    var sa = (a.g1 > 0 ? 100 : 0) + (weight[a.id] || 0) * 10 + Math.min(9, a.count);
    var sb = (b.g1 > 0 ? 100 : 0) + (weight[b.id] || 0) * 10 + Math.min(9, b.count);
    return sb - sa;
  });
  list.slice(0, 5).forEach(function (g) {
    var m = INSIGHT_WL_META[g.wl];
    var noun = g.count === 1 ? m.one : m.plural;
    var title, detail;
    switch (g.id) {
      case "peer-size": title = g.count + " " + noun + (g.count === 1 ? " holds" : " hold") + " far more data than the rest of " + m.yours; detail = "Together " + fmtStorage(g.bytes) + ". Large single objects cannot be split up and can stretch recovery."; break;
      case "peer-items": title = g.count + " " + noun + (g.count === 1 ? " holds" : " hold") + " far more items than the rest of " + m.yours; detail = "Recovery speed is limited by items per minute, so these take much longer than their size suggests."; break;
      case "concentration": title = g.count + " " + noun + (g.count === 1 ? " holds" : " hold") + " a large share of all " + m.plural; detail = "One object can move the whole workload's recovery estimate."; break;
      case "long-pole-abr": title = g.count + " " + noun + (g.count === 1 ? " sets" : " set") + " the pace for ABR in its group"; detail = "Its group is only fully back when the slowest object finishes."; break;
      case "long-pole-mass": title = g.count + " " + noun + (g.count === 1 ? " sets" : " set") + " the pace for a whole-tenant restore"; detail = "A full restore is only finished when the slowest object finishes."; break;
      case "high-recent-change": title = g.count + " " + noun + " changed far more than usual in the last 7 days"; detail = "More recent change means more for ABR to restore first."; break;
      case "critical-lower-group": title = g.count + " " + noun + (g.count === 1 ? " looks" : " look") + " critical but " + (g.count === 1 ? "sits" : "sit") + " in a lower group"; detail = "Worth a manual check on the Groups & Recovery Model tab."; break;
      default: title = g.count + " " + noun + (g.count === 1 ? " is" : " are") + " near the mailbox limit"; detail = "A full mailbox is the slowest kind to restore and a growth risk.";
    }
    topRisks.push({ id: g.id, wl: g.wl, title: title, detail: detail, link: "insights:insights-table" });
  });
  return { total: INSIGHTS.flagged.length, excludedCount: INSIGHTS.excludedCount, byFlag: INSIGHTS.byFlag, topRisks: topRisks, headline: insightHeadline() };
}

// ---------- render ----------
registerInfo("insights-method", "How abnormal objects are found",
  "<p>Each workload is compared with <b>its own</b> distribution, not a fixed size. An object is flagged when it holds more than 5 times the 99th percentile of your own objects (and at least 0.1% of the workload), or holds 2% or more of the workload by itself.</p>" +
  "<p>Objects that are unusually large, hold unusually many items, or hold a large share of a workload are <b>left out of the headline recovery estimates by default</b> (for both ABR and Mass, so the comparison stays like-for-like) because one object can stretch the whole window. You can include them again at any time.</p>" +
  "<p>The other flags are for awareness only and never change a number.</p>");
registerInfo("insights-single-object", "Single-object restore time",
  "<p>Mailboxes restore at the per-mailbox rate. For SharePoint sites and OneDrive accounts it is not yet confirmed how many restores can run in parallel inside one site, so the table shows a range: the full restore rate for your size tier, up to a single parallel unit. SharePoint and OneDrive times are never part of the headline numbers.</p>");

function insightsSummaryTilesHtml() {
  var h = '<div class="ins-tiles" id="insights-tiles">';
  INSIGHT_FLAG_ORDER.forEach(function (id) {
    var n = INSIGHTS.byFlag[id] || 0;
    if (id === "critical-lower-group" && IS_PREVIEW) { return; }
    var meta = INSIGHT_FLAGS[id];
    h += '<button type="button" class="ins-tile' + (n === 0 ? " zero" : "") + (insightFilter === id ? " active" : "") + '" ' + navAttr("insights:insights-table") + ' onclick="setInsightFilter(\'' + id + '\')" ' + (n === 0 ? "disabled" : "") + '>' +
      '<span class="ins-tile-count">' + fmtNum(n) + '</span><span class="ins-tile-label">' + meta.tile + '</span><span class="ins-tile-impact">' + meta.impact + '</span></button>';
  });
  return h + "</div>";
}

function insightsBannerHtml() {
  var h = '<div class="ins-banner">';
  var n = INSIGHTS.excludedCount;
  if (n === 0) {
    return h + '<b>Nothing stands out.</b> No object is unusually large, item-heavy, or dominant compared with ' + (IS_PREVIEW ? "the other Group 1 objects" : "the rest of your environment") + ', so no object is excluded from the recovery estimates.</div>';
  }
  var on = state.insights.exclude;
  h += '<div class="ins-banner-text">';
  if (IS_PREVIEW) {
    h += '<b>' + fmtNum(n) + ' Group 1 object' + (n === 1 ? "" : "s") + ' stand out</b> compared with the other Group 1 objects. In the Preview they are shown for awareness and are not removed from any estimate.';
  } else if (on) {
    h += '<b>' + fmtNum(n) + ' object' + (n === 1 ? " is" : "s are") + ' excluded from the recovery estimates.</b> They are abnormally large, item-heavy, or dominant compared with your other objects and would stretch recovery. They may be worth investigating.';
  } else {
    h += '<b>' + fmtNum(n) + ' abnormal object' + (n === 1 ? " is" : "s are") + ' included in the recovery estimates.</b> By default they are excluded because they would stretch recovery.';
  }
  h += ' ' + infoBtn("insights-method", "How abnormal objects are found") + '</div>';
  var hl = insightHeadline();
  if (hl) {
    h += '<div class="ins-compare"><div class="ins-compare-card' + (on ? " current" : "") + '"><div class="ins-compare-label">Excluded (default)</div><div class="ins-compare-val">Group 1: ' + fmtMin(hl.excludedG1Min) + '</div><div class="ins-compare-sub">Whole tenant: ' + fmtMin(hl.excludedMassMin) + '</div></div>' +
      '<div class="ins-compare-card' + (on ? "" : " current") + '"><div class="ins-compare-label">Included</div><div class="ins-compare-val">Group 1: ' + fmtMin(hl.includedG1Min) + '</div><div class="ins-compare-sub">Whole tenant: ' + fmtMin(hl.includedMassMin) + '</div></div></div>';
  }
  if (IS_PREVIEW) {
    h += '<div class="ins-toggle" aria-disabled="true"><button type="button" class="ins-toggle-btn" disabled>Exclude</button><button type="button" class="ins-toggle-btn" disabled>Include</button><span class="ins-toggle-note">Locked in the Preview</span></div>';
  } else {
    h += '<div class="ins-toggle" role="group" aria-label="Abnormal objects in recovery estimates"><button type="button" class="ins-toggle-btn' + (on ? " active" : "") + '" aria-pressed="' + on + '" onclick="setExcludeOutliers(true)">Exclude</button>' +
      '<button type="button" class="ins-toggle-btn' + (on ? "" : " active") + '" aria-pressed="' + (!on) + '" onclick="setExcludeOutliers(false)">Include</button></div>';
  }
  return h + "</div>";
}

var INSIGHT_COLS = [
  { key: "wl", label: "Workload", type: "text", get: function (e) { return INSIGHT_WL_META[e.wl].label; } },
  { key: "obj", label: "Object", type: "text", get: function (e) { return insightIdentity(e.row); } },
  { key: "flags", label: "Flags", type: "text", get: function (e) { return e.flags.map(function (f) { return INSIGHT_FLAGS[f].label; }).join(", "); } },
  { key: "why", label: "Why it is flagged", type: "text", get: function (e) { return e.reason; } },
  { key: "storage", label: "Storage", type: "num", cls: "num", get: function (e) { return e.storageBytes; } },
  { key: "items", label: "Items", type: "num", cls: "num", get: function (e) { return e.items; } },
  { key: "recent", label: "Changed in last 7 days", type: "num", cls: "num", get: function (e) { return e.recent; } },
  { key: "group", label: "Group", type: "text", get: function (e) { return insightTierShort(e.row); } },
  { key: "time", label: "Est. time to restore on its own", type: "num", cls: "num", get: function (e) { return e.singleObjectMinHigh; } },
  { key: "excl", label: "In headline estimates?", type: "text", get: function (e) { return e.excluded ? (state.insights.exclude ? "Excluded" : "Included") : "Included"; } }
];

function insightsTableHtml() {
  var all = INSIGHTS.flagged;
  var list = insightFilter ? all.filter(function (e) { return e.flags.indexOf(insightFilter) !== -1; }) : all;
  var sorted = applySort(list, "insights", INSIGHT_COLS, "time", "desc");
  var shown = sorted.length > INSIGHT_TABLE_CAP ? sorted.slice(0, INSIGHT_TABLE_CAP) : sorted;
  SORT_RERENDER["insights"] = renderInsightsTab;
  var h = '<div class="ins-table-head"><h3>Flagged objects</h3>';
  if (insightFilter) { h += '<span class="ins-filter">Showing: <b>' + INSIGHT_FLAGS[insightFilter].label + '</b> <button type="button" class="ins-clear" onclick="setInsightFilter(null)">Show all</button></span>'; }
  h += ' ' + infoBtn("insights-single-object", "About single-object restore time") + '</div>';
  h += '<div class="table-wrap"><table class="ins-table sort-data" data-datasort="1"><thead><tr>';
  INSIGHT_COLS.forEach(function (c) { h += sortThHtml("insights", c, "time", "desc"); });
  h += "</tr></thead><tbody>";
  shown.forEach(function (e) {
    var meta = INSIGHT_WL_META[e.wl];
    var excl = e.excluded ? (state.insights.exclude ? "Excluded" : "Included") : "Included";
    h += "<tr" + (e.excluded && state.insights.exclude ? ' class="ins-excluded"' : "") + ">" +
      "<td>" + meta.label + "</td>" +
      '<td><span class="linkout" ' + navAttr("groups:grp-by-workload:wl-" + e.wl) + ">" + esc(insightIdentity(e.row)) + "</span></td>" +
      '<td class="ins-flags">' + e.flags.map(function (f) { return '<span class="ins-chip' + (INSIGHT_FLAGS[f].excl ? " excl" : "") + '">' + INSIGHT_FLAGS[f].label + "</span>"; }).join(" ") + "</td>" +
      '<td class="ins-why">' + esc(e.reason) + "</td>" +
      '<td class="num" data-sort="' + Math.round(e.storageBytes) + '">' + fmtStorageNum(e.storageBytes) + "</td>" +
      '<td class="num" data-sort="' + Math.round(e.items) + '">' + fmtNum(e.items) + "</td>" +
      '<td class="num" data-sort="' + Math.round(e.recent) + '">' + fmtNum(e.recent) + "</td>" +
      "<td>" + esc(insightTierShort(e.row)) + "</td>" +
      '<td class="num" data-sort="' + Math.round(e.singleObjectMinHigh) + '">' + insightTimeRange(e, e.wl, false) + "</td>" +
      "<td>" + excl + "</td></tr>";
  });
  h += "</tbody></table></div>";
  // storage header carries the unit; swap the plain label for the unit-aware one
  h = h.replace(">Storage</th>", ">" + storageHeader("Storage") + "</th>");
  if (sorted.length > INSIGHT_TABLE_CAP) {
    h += '<div class="table-cap-notice">Showing the first ' + fmtNum(INSIGHT_TABLE_CAP) + ' of ' + fmtNum(sorted.length) + ' flagged objects in the current sort order. Click a column heading to change the order, or use the tiles above to narrow the list.</div>';
  }
  if (sorted.length === 0) { h += '<p class="ins-empty">No objects match this filter.</p>'; }
  return h;
}

function insightsBaselineHtml() {
  var h = '<h3>Your baseline</h3><p class="ins-sub">' + (IS_PREVIEW ? "Medians and percentiles compared with other Group 1 objects." : "Each workload is compared with its own objects. These are the numbers &quot;abnormal&quot; is measured against.") + "</p>";
  h += '<div class="table-wrap"><table class="ins-base-table"><thead><tr><th>Workload</th><th class="num">Objects</th><th class="num">' + storageHeader("Median") + '</th><th class="num">' + storageHeader("95th pct.") + '</th><th class="num">' + storageHeader("99th pct.") + '</th>' +
    '<th class="num">Median items</th><th class="num">95th pct. items</th><th class="num">99th pct. items</th><th class="num">99th pct. 7-day change</th></tr></thead><tbody>';
  INSIGHT_WL.forEach(function (wl) {
    var b = INSIGHTS.baselines[wl];
    if (!b) { return; }
    h += "<tr><td>" + INSIGHT_WL_META[wl].label + '</td><td class="num">' + fmtNum(b.n) + '</td><td class="num" data-sort="' + Math.round(b.storageP50) + '">' + fmtStorageNum(b.storageP50) + '</td><td class="num" data-sort="' + Math.round(b.storageP95) + '">' + fmtStorageNum(b.storageP95) +
      '</td><td class="num" data-sort="' + Math.round(b.storageP99) + '">' + fmtStorageNum(b.storageP99) + '</td><td class="num">' + fmtNum(b.itemsP50) + '</td><td class="num">' + fmtNum(b.itemsP95) + '</td><td class="num">' + fmtNum(b.itemsP99) + '</td><td class="num">' + fmtNum(b.recentP99) + "</td></tr>";
  });
  return h + "</tbody></table></div>";
}

function renderInsightsTab() {
  var p = document.getElementById("panel-insights");
  if (!p) { return; }
  var h = "<h2>Recovery Insights</h2>";
  if (IS_SUMMARY) {
    p.innerHTML = h + '<p class="ins-sub">Object-level insights (unusually large or item-heavy objects, objects that set the pace for recovery) are part of the interactive assessment.</p>';
    return;
  }
  h += '<p class="ins-sub">Objects that look abnormal compared with the rest of your environment and can pull the recovery window out. Surfacing them early helps you decide what to review before an outage.</p>';
  h += '<div id="insights-summary">' + insightsBannerHtml() + insightsSummaryTilesHtml() + "</div>";
  if (INSIGHTS.flagged.length > 0) {
    h += '<div id="insights-table">' + insightsTableHtml() + "</div>";
  } else {
    h += '<div id="insights-table"><p class="ins-empty">No objects were flagged.</p></div>';
  }
  h += '<div id="insights-baseline">' + insightsBaselineHtml() + "</div>";
  if (IS_PREVIEW) {
    h += pvLockedPanel("Insights for the remaining groups", "Insights for the remaining groups are part of the full assessment.");
  }
  p.innerHTML = h;
  enhanceTables(p);
}

'@

#endregion

#region ---------- HTML report JS: rendering (exec summary, tables) ----------

$script:ReportJsRenderA = @'
// ===================================================================================
// v2.0 Executive Summary (panel "exec") and Report tab (panel "report").
//
// Executive Summary = one-screen story, 10 blocks (section ids are fixed by the v2 layout):
//   1 headline (exec-who + exec-fast)   2 hours saved / cost avoided (exec-worth)
//   3 concentration proof (exec-concentration)   4 recovery ladder (exec-ladder)
//   5 why speed is limited (exec-constraint)     6 who is in Group 1 (exec-g1list)
//   7 RTO scorecard + gap analysis (exec-rto)    8 top risks (exec-risks)
//   9 next steps (exec-next)  (the "expected wait" block was removed in v2.0)
// Works in three modes (DATA.meta.buildMode): full (rows), preview (Group 1 rows + tenantTotals),
// summary (tierAgg + tenantTotals + group1Profile, no rows). Nothing beyond Group 1 is ever
// calculated in Preview: model.milestones[...].locked is honoured everywhere.
// ASCII only. Colors via CSS variables only.
// ===================================================================================

// ---------------------------------------------------------------------------
// Info bubble: how cost avoided is estimated (registered at load, used by Exec and Report)
// ---------------------------------------------------------------------------
registerInfo("cost-avoided", "How we estimate cost avoided",
  "<p><b>Baseline.</b> Restoring your whole tenant as one undifferentiated Mass Recovery job. Data is only guaranteed usable when that job finishes.</p>" +
  "<p><b>With ABR.</b> Autonomous Business Recovery restores in priority order. The milestone is the point where Group 1 (or Groups 1-2, 1-3 and so on up to the last criticality group) is back online.</p>" +
  "<p><b>Time saved</b> = baseline time minus the ABR milestone time (never below zero). <b>Cost avoided</b> = hours saved &times; the downtime cost per hour you enter. Until you enter a rate, only hours are shown.</p>" +
  "<p><b>Why Groups 2-3 are smaller.</b> Total throughput is the same either way, so prioritizing does not shrink the time to restore everything. It changes <i>when</i> each group returns. The gap closes as more data comes back.</p>" +
  "<p><b>Expected wait.</b> Without prioritization a typical Group 1 object returns around the midpoint of the full restore, and the last one at the end.</p>");

// ---------------------------------------------------------------------------
// Mode-aware aggregate helpers (rows in Full/Preview, tierAgg in Summary)
// ---------------------------------------------------------------------------
var EXEC_WL = ["mailboxes", "onedrive", "sharepoint", "teams"];

function execStorageBytesOf(wlKey, storageField) {
  // tierAgg/tenantTotals: mailboxes storage is in MB, OneDrive/SharePoint in bytes, Teams has none.
  if (wlKey === "mailboxes") { return (storageField || 0) * 1048576; }
  if (wlKey === "teams") { return 0; }
  return storageField || 0;
}

// Totals for one workload in one tier. Returns null when that tier is not in the page (Preview Groups 2-4).
function execWlTier(wlKey, tierName) {
  var rows = DATA.workloads[wlKey] || [];
  if (!IS_SUMMARY && rows.length > 0) {
    var any = false, n = 0, bytes = 0, act = 0, items = 0;
    rows.forEach(function (r) {
      if (r.Tier !== tierName) { return; }
      any = true; n++;
      bytes += rowStorageBytes(wlKey, r);
      act += parseFloat(r.metrics && r.metrics.TotalActivity) || 0;
      var f = RECOVERY_FIELDS[wlKey];
      if (f) { items += parseFloat(r.metrics && r.metrics[f.item]) || 0; }
    });
    if (!any && IS_PREVIEW && tierName !== "Critical Group 1") { return null; }
    return { objectCount: n, storageBytes: bytes, activity: act, itemCount: items };
  }
  if (DATA.tierAgg && DATA.tierAgg[wlKey] && DATA.tierAgg[wlKey][tierName]) {
    var a = DATA.tierAgg[wlKey][tierName];
    return { objectCount: a.objectCount || 0, storageBytes: execStorageBytesOf(wlKey, a.storage), activity: a.activity || 0, itemCount: a.itemCount || 0 };
  }
  if (IS_PREVIEW && tierName === "Critical Group 1") { return { objectCount: 0, storageBytes: 0, activity: 0, itemCount: 0 }; }
  return null;
}

// Whole-tenant totals for one workload (all objects, all groups).
function execWlTenant(wlKey) {
  var rows = DATA.workloads[wlKey] || [];
  if (DATA.tenantTotals && DATA.tenantTotals[wlKey]) {
    var t = DATA.tenantTotals[wlKey];
    return { objectCount: t.objectCount || 0, storageBytes: execStorageBytesOf(wlKey, t.storage), activity: (typeof t.activity === "number") ? t.activity : null, itemCount: t.itemCount || 0 };
  }
  var bytes = 0, act = 0, items = 0;
  var f = RECOVERY_FIELDS[wlKey];
  rows.forEach(function (r) {
    bytes += rowStorageBytes(wlKey, r);
    act += parseFloat(r.metrics && r.metrics.TotalActivity) || 0;
    if (f) { items += parseFloat(r.metrics && r.metrics[f.item]) || 0; }
  });
  return { objectCount: rows.length, storageBytes: bytes, activity: act, itemCount: items };
}

// Sum across workloads for one tier. Returns null if any workload's tier data is missing (locked).
function execTierSum(tierName) {
  var objects = 0, bytes = 0, locked = false;
  EXEC_WL.forEach(function (k) {
    var t = execWlTier(k, tierName);
    if (!t) { locked = true; return; }
    objects += t.objectCount; bytes += t.storageBytes;
  });
  return locked ? null : { objects: objects, bytes: bytes };
}
function execTenantSum() {
  var objects = 0, bytes = 0;
  EXEC_WL.forEach(function (k) { var t = execWlTenant(k); objects += t.objectCount; bytes += t.storageBytes; });
  return { objects: objects, bytes: bytes };
}

// Group 1 share of objects / storage / activity. Activity is averaged across workloads (each workload's
// activity unit is different, so a straight sum would let mailbox event counts swamp everything else).
function execConcentration() {
  var g1 = execTierSum("Critical Group 1");
  var ten = execTenantSum();
  if (!g1 || ten.objects <= 0) { return null; }
  var shares = [];
  EXEC_WL.forEach(function (k) {
    var t1 = execWlTier(k, "Critical Group 1");
    var tt = execWlTenant(k);
    if (t1 && tt.activity !== null && tt.activity > 0) { shares.push(t1.activity / tt.activity); }
  });
  var actPct = shares.length ? (shares.reduce(function (s, v) { return s + v; }, 0) / shares.length) * 100 : null;
  return {
    objects: g1.objects, tenantObjects: ten.objects,
    objPct: (g1.objects / ten.objects) * 100,
    bytes: g1.bytes, tenantBytes: ten.bytes,
    bytesPct: ten.bytes > 0 ? (g1.bytes / ten.bytes) * 100 : null,
    actPct: actPct
  };
}

// Distinct person key for Group 1 mailbox / OneDrive rows
function execPersonKey(r) { return String((r.ObjectName || r.Identifier || "")).trim().toLowerCase(); }

// Who is in Group 1: distinct people, top departments, title-keyword hits.
function execGroup1Profile() {
  var gp = (DATA.meta && DATA.meta.group1Profile) || DATA.group1Profile || null;
  var rows = ["mailboxes", "onedrive"].reduce(function (acc, k) {
    return acc.concat((DATA.workloads[k] || []).filter(function (r) { return r.Tier === "Critical Group 1"; }));
  }, []);
  if (IS_SUMMARY || (rows.length === 0 && gp)) {
    if (!gp) { return { people: 0, departments: [], titles: [], available: false }; }
    return { people: gp.group1People || 0, departments: (gp.topDepartments || []).slice(0, 8), titles: (gp.titleKeywordHits || []).slice(0, 8), available: true };
  }
  var people = {}, deptCount = {}, titleCount = {};
  rows.forEach(function (r) {
    var key = execPersonKey(r);
    if (!key) { return; }
    var seen = people[key];
    if (!seen) { people[key] = { dept: r.Department || "", titles: {} }; seen = people[key]; }
    if (!seen.dept && r.Department) { seen.dept = r.Department; }
    var m = /Title match: ([^;]+)/.exec(r.CriteriaTags || "");
    if (m) { seen.titles[m[1].trim()] = true; }
  });
  Object.keys(people).forEach(function (k) {
    var p = people[k];
    if (p.dept) { deptCount[p.dept] = (deptCount[p.dept] || 0) + 1; }
    Object.keys(p.titles).forEach(function (t) { titleCount[t] = (titleCount[t] || 0) + 1; });
  });
  function top(map, keyName) {
    return Object.keys(map).map(function (k) { var o = { count: map[k] }; o[keyName] = k; return o; })
      .sort(function (a, b) { return b.count - a.count || (a[keyName] < b[keyName] ? -1 : 1); }).slice(0, 8);
  }
  return { people: Object.keys(people).length, departments: top(deptCount, "name"), titles: top(titleCount, "keyword"), available: true };
}

// Hours-saved formatter (always hours, minutes only when under an hour)
function fmtSaved(min) {
  if (!isFinite(min) || min <= 0) { return "0 hr"; }
  if (min < 60) { return Math.round(min) + " min"; }
  var h = min / 60;
  return h.toLocaleString(undefined, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) + " hr";
}

function onExecCostChange(v) {
  var n = parseFloat(String(v).replace(/[^0-9.]/g, ""));
  state.recovery.costPerHour = (isNaN(n) || n < 0) ? 0 : n;
  recomputeAll();
}

// "Confirm your Group 1" export (Full only)
function exportGroup1Csv() {
  if (IS_PREVIEW || IS_SUMMARY) { return; }
  var cols = ["Workload", "ObjectName", "Identifier", "JobTitle", "Department", "Manager", "ScorePct", "WhyInGroup1", "LastActivityDate", "ItemCount", "Storage (" + storageUnit() + ")"];
  var out = [];
  WORKLOAD_DEFS.forEach(function (wd) {
    (DATA.workloads[wd.key] || []).forEach(function (r) {
      if (r.Tier !== "Critical Group 1") { return; }
      var row = {
        "Workload": wd.label, "ObjectName": r.ObjectName || "", "Identifier": r.Identifier || "", "JobTitle": r.JobTitle || "",
        "Department": r.Department || "", "Manager": r.Manager || "", "ScorePct": Math.round((r._Score || 0) * 100),
        "WhyInGroup1": r.CriteriaTags || "", "LastActivityDate": r.LastActivityDate || "",
        "ItemCount": (r.metrics && r.metrics[wd.itemField] != null) ? r.metrics[wd.itemField] : ""
      };
      row["Storage (" + storageUnit() + ")"] = wd.storageField ? fmtStorageNum(rowStorageBytes(wd.key, r)) : "";
      row._s = r._Score || 0; row._w = wd.label;
      out.push(row);
    });
  });
  out.sort(function (a, b) { return a._w === b._w ? b._s - a._s : (a._w < b._w ? -1 : 1); });
  var blob = new Blob([rowsToCsv(out, cols)], { type: "text/csv;charset=utf-8;" });
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "Group1_ToConfirm_" + DATA.meta.runId + ".csv";
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

// ---------------------------------------------------------------------------
// Binding constraint per workload (what actually limits recovery speed)
// ---------------------------------------------------------------------------
function execConstraints(model) {
  var out = [];
  var spT = tenantTotalsFor("sharepoint"), odT = tenantTotalsFor("onedrive"), exT = tenantTotalsFor("mailboxes");
  var spodTier = resolveLicenseTier(state.recovery.licenseTier, Math.max(spT.objectCount, odT.objectCount));
  function spod(label, key, t, rate, massMin) {
    if (t.objectCount <= 0) { return; }
    var ipm = Math.min(t.objectCount, spodTier.Parallelism) * rate;
    var avgMb = t.itemCount > 0 ? (t.storage / t.itemCount) / 1048576 : 0;
    var sf = avgMb > 0 ? Math.max(1, avgMb / SIZE_FACTOR_BASELINE_MB) : 1;
    out.push({ label: label, kind: "items", constraint: "Item count (API throughput)", ipm: ipm, items: t.itemCount, massMin: massMin,
      note: "No byte-rate cap; restore time follows items restored per minute" + (sf > 1 ? " (larger average file raises the effective item cost " + sf.toFixed(2) + "x)." : ".") });
  }
  spod("SharePoint", "sp", spT, SP_ITEMS_PER_MIN_PER_UNIT, model.perWorkloadMassRecoveryMin.sp);
  spod("OneDrive", "od", odT, OD_ITEMS_PER_MIN_PER_UNIT, model.perWorkloadMassRecoveryMin.od);
  if (exT.objectCount > 0) {
    var eff = Math.min(exT.objectCount, EX_BENCHMARK.MaxParallelMailboxes);
    var tBytes = exT.storage / (eff * EX_BENCHMARK.PerMailboxMBPerMin);
    var tItems = exT.itemCount / (eff * EX_BENCHMARK.PerMailboxItemsPerMin);
    var itemBound = tItems > tBytes;
    var exBytesPerMin = eff * EX_BENCHMARK.PerMailboxMBPerMin * 1048576;
    out.push({ label: "Exchange", kind: itemBound ? "items" : "bytes", constraint: itemBound ? "Item count (items restored per minute)" : "Data volume (per-mailbox transfer rate)",
      ipm: eff * EX_BENCHMARK.PerMailboxItemsPerMin, ceilingText: itemBound ? null : (fmtStorage(exBytesPerMin) + "/min"), ceilingSort: itemBound ? null : exBytesPerMin,
      items: exT.itemCount, massMin: model.perWorkloadMassRecoveryMin.ex,
      note: itemBound ? "Items per minute is the slower of the two limits for this tenant." : "Transfer volume per mailbox is the slower of the two limits for this tenant; item count is the second limit." });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Executive Summary blocks
// ---------------------------------------------------------------------------
function exLink(target, text) { return '<span class="linkout ex2-details" ' + navAttr(target) + '>' + (text || "Details") + ' &rarr;</span>'; }
function exLocked(label) { return '<span class="ex2-locked">' + pvLocked("&bull;&bull;&bull;") + '</span>'; }

function exBlockHeadline(c) {
  var conc = c.conc, prof = c.profile, g1 = c.g1;
  var nSites = (execWlTier("sharepoint", "Critical Group 1") || { objectCount: 0 }).objectCount + (execWlTier("teams", "Critical Group 1") || { objectCount: 0 }).objectCount;
  var nPeople = prof.people;
  var who = '<b>' + fmtNum(nPeople + nSites) + '</b> users and sites';
  var sentence;
  if (conc) {
    sentence = who + ' (<b>' + Math.round(conc.objPct) + '%</b> of your tenant' + (conc.bytes > 0 ? ', <b>' + fmtStorage(conc.bytes) + '</b>' : '') + ') drive your business. Rubrik brings them back in <b>' + fmtMin(g1.wallClockCumMin) +
      '</b>, instead of waiting <b>' + fmtMin(c.model.fullRestoreMin) + '</b> for a full restore.';
  } else {
    sentence = who + ' drive your business. Rubrik brings them back in <b>' + fmtMin(g1.wallClockCumMin) + '</b>, instead of waiting <b>' + fmtMin(c.model.fullRestoreMin) + '</b> for a full restore.';
  }
  var sub = '<div class="ex2-sub">' + fmtNum(nPeople) + ' people (mailbox and OneDrive owners) and ' + fmtNum(nSites) + ' SharePoint sites and Teams are in Critical Group 1 ' + exLink("groups:grp-by-group:grp-g1", "See Group 1") + '</div>';
  return '<section class="ex2-block ex2-hero" id="exec-who"><div class="ex2-eyebrow">Who matters most</div><div class="ex2-headline">' + sentence + '</div>' + sub + '</section>';
}

function exBlockFast(c) {
  return '<section class="ex2-block ex2-tile" id="exec-fast"><div class="ex2-eyebrow">Time to critical data ' + exLink("report:report-by-group", "Details") + '</div>' +
    '<div class="ex2-big">' + fmtMin(c.g1.wallClockCumMin) + '</div>' +
    '<div class="ex2-tile-sub">instead of <b>' + fmtMin(c.model.fullRestoreMin) + '</b> with a traditional, random-order restore</div></section>';
}

function exBlockWorth(c) {
  var ca = c.ca, r1 = ca.rows[0], r2 = ca.rows[1], r3 = ca.rows[groupN() - 1];
  var rateInput = '<label class="ex2-rate">Downtime cost per hour (USD) <input type="number" min="0" step="100" id="exec-cost-input" value="' + (ca.perHour || 0) + '" onchange="onExecCostChange(this.value)" aria-label="Estimated downtime cost per hour in dollars"></label>';
  var big = r1.locked ? exLocked() : fmtSaved(r1.savedMin);
  var dollars;
  if (r1.locked) { dollars = exLocked(); }
  else if (ca.hasRate) { dollars = '<span class="ex2-money">' + fmtMoney(r1.cost) + '</span> cost avoided'; }
  else { dollars = costPromptHtml(); }
  function small(r, label) {
    if (r.locked) { return '<div class="ex2-small-row"><span>' + label + '</span><span>' + exLocked() + '</span></div>'; }
    var d = ca.hasRate ? ' &middot; ' + fmtMoney(r.cost) : '';
    return '<div class="ex2-small-row"><span>' + label + '</span><span><b>' + fmtSaved(r.savedMin) + '</b> saved' + d + '</span></div>';
  }
  return '<section class="ex2-block ex2-tile ex2-worth" id="exec-worth"><div class="ex2-eyebrow">Hours saved to reach Group 1 ' + infoBtn("cost-avoided", "How we estimate cost avoided") + ' ' + exLink("report:report-by-group", "Details") + '</div>' +
    '<div class="ex2-big">' + big + '</div>' +
    '<div class="ex2-dollars">' + dollars + '</div>' +
    '<div class="ex2-smalls">' + small(r2, "Groups 1-2 online") + small(r3, scopeName(groupN()) + " online") + '</div>' +
    rateInput + '</section>';
}

function exBlockConcentration(c) {
  var conc = c.conc;
  var body;
  if (!conc) { body = '<div class="ex2-note">Not enough data to compare Group 1 with the rest of the tenant.</div>'; }
  else {
    function bar(label, pct, detail) {
      if (pct === null || isNaN(pct)) { return ""; }
      var w = Math.max(1, Math.min(100, pct));
      return '<div class="ex2-conc-row"><div class="ex2-conc-label">' + label + '</div><div class="ex2-conc-track" role="img" aria-label="' + label + ' ' + Math.round(pct) + ' percent"><span style="width:' + w.toFixed(1) + '%"></span></div><div class="ex2-conc-val">' + Math.round(pct) + '%</div><div class="ex2-conc-detail">' + detail + '</div></div>';
    }
    body = '<div class="ex2-conc">' +
      bar("Objects", conc.objPct, fmtNum(conc.objects) + ' of ' + fmtNum(conc.tenantObjects)) +
      bar("Storage", conc.bytesPct, fmtStorage(conc.bytes) + ' of ' + fmtStorage(conc.tenantBytes)) +
      bar("Recent activity", conc.actPct, 'average share across workloads') +
      '</div>' +
      '<div class="ex2-note">Group 1 is <b>' + Math.round(conc.objPct) + '%</b> of your objects and <b>' + (conc.bytesPct === null ? "n/a" : Math.round(conc.bytesPct) + '%') + '</b> of your storage' +
      (conc.actPct !== null ? ', but <b>' + Math.round(conc.actPct) + '%</b> of the recent activity' : '') + '. That concentration is why restoring in priority order works in your environment.</div>';
  }
  return '<section class="ex2-block" id="exec-concentration"><div class="ex2-eyebrow">Why prioritizing works ' + exLink("groups:grp-headline", "Group 1 detail") + '</div>' + body + '</section>';
}

function exBlockLadder(c) {
  var ladder = buildRecoveryLadderHtml(c.model);
  var pv = "";
  if (IS_PREVIEW) { pv = pvLockedPanel("Group 2 and 3 milestones", "The Groups 1-2 and 1-3 milestones are calculated in the full assessment."); }
  return '<section class="ex2-block ex2-wide" id="exec-ladder"><div class="ex2-eyebrow">Recovery ladder ' + exLink("groups:grp-by-group", "Group breakdown") + '</div>' + ladder + pv + '</section>';
}

function exBlockConstraint(c) {
  var cons = execConstraints(c.model);
  var allItems = cons.length > 0 && cons.every(function (x) { return x.kind === "items"; });
  var line = allItems
    ? "Recovery speed is limited by how many items can be restored per minute, not by bandwidth or storage size. Adding network capacity does not shorten it; restoring the right items first does."
    : "Recovery speed is limited by items restored per minute for SharePoint and OneDrive, and by whichever is slower, item rate or per-mailbox transfer rate, for Exchange. It is not limited by your network bandwidth.";
  var rows = cons.map(function (x) {
    return '<tr><td>' + esc(x.label) + '</td><td>' + esc(x.constraint) + '</td><td data-sort="' + Math.round(x.ceilingSort != null ? x.ceilingSort : x.ipm) + '">' + (x.ceilingText || (fmtNum(x.ipm) + ' items/min')) + '</td><td data-sort="' + Math.round(x.massMin) + '">' + fmtMin(x.massMin) + '</td></tr>';
  }).join("");
  var table = rows ? '<div class="table-wrap"><table class="ex2-table"><thead><tr><th>Workload</th><th>What limits speed</th><th>Throughput ceiling</th><th>Whole-workload restore</th></tr></thead><tbody>' + rows + '</tbody></table></div>' : '<div class="ex2-note">No recovery-time workloads were found.</div>';
  return '<section class="ex2-block ex2-wide" id="exec-constraint"><div class="ex2-eyebrow">Why recovery speed is limited ' + exLink("methodology", "How it is calculated") + '</div><div class="ex2-lead">' + line + '</div>' + table + '</section>';
}

function exBlockG1List(c) {
  var p = c.profile;
  var body;
  if (!p.available) { body = '<div class="ex2-note">Group 1 profile data is not available in this build.</div>'; }
  else {
    var dRows = p.departments.map(function (d) { return '<tr><td>' + esc(d.name) + '</td><td data-sort="' + d.count + '">' + fmtNum(d.count) + '</td></tr>'; }).join("") || '<tr><td colspan="2">No department data in this tenant</td></tr>';
    var tRows = p.titles.map(function (t) { return '<tr><td>' + esc(t.keyword) + '</td><td data-sort="' + t.count + '">' + fmtNum(t.count) + '</td></tr>'; }).join("") || '<tr><td colspan="2">No title-keyword matches</td></tr>';
    body = '<div class="ex2-two">' +
      '<div><div class="ex2-mini-title">Top departments (people)</div><div class="table-wrap"><table class="ex2-table"><thead><tr><th>Department</th><th>People</th></tr></thead><tbody>' + dRows + '</tbody></table></div></div>' +
      '<div><div class="ex2-mini-title">Title keywords matched</div><div class="table-wrap"><table class="ex2-table"><thead><tr><th>Keyword</th><th>People</th></tr></thead><tbody>' + tRows + '</tbody></table></div></div></div>';
  }
  var btn = (IS_PREVIEW || IS_SUMMARY) ? "" : '<button type="button" class="ex2-btn full-only" onclick="exportGroup1Csv()">Confirm your Group 1 (CSV)</button>';
  var lede = '<div class="ex2-lead"><b>' + fmtNum(p.people) + '</b> people own the mailboxes and OneDrive accounts in Group 1. Take this list to the business owners and confirm it matches how they would rank their own people and sites.</div>';
  return '<section class="ex2-block ex2-wide" id="exec-g1list"><div class="ex2-eyebrow">Who is in Group 1 ' + exLink("groups:grp-by-group:grp-g1", "Full Group 1 list") + '</div>' + lede + body + btn + '</section>';
}

function exBlockRto(c) {
  var model = c.model;
  var defs = critKeys().map(function (key, i) { return [key, scopeName(i + 1), groupHoursOf(i + 1)]; });
  var rows = defs.map(function (d) {
    var m = model.milestones[d[0]];
    if (!m || m.locked) {
      return '<tr><td>' + d[1] + '</td><td data-sort="' + (d[2] * 60) + '">' + d[2] + ' hr</td><td>' + exLocked() + '</td><td>' + exLocked() + '</td></tr>';
    }
    var met = !m.exceedsTarget;
    var badge = met ? '<span class="ex2-badge ok">Within target</span>' : '<span class="ex2-badge bad">Over by ' + fmtMin(m.targetGapMin) + '</span>';
    return '<tr><td>' + d[1] + '</td><td data-sort="' + (d[2] * 60) + '">' + d[2] + ' hr</td><td data-sort="' + Math.round(m.wallClockCumMin) + '">' + fmtMin(m.wallClockCumMin) + '</td><td>' + badge + '</td></tr>';
  }).join("");
  var table = '<div class="table-wrap"><table class="ex2-table"><thead><tr><th>Milestone</th><th>Your Recovery Window (RTO)</th><th>Modeled with ABR</th><th>Status</th></tr></thead><tbody>' + rows + '</tbody></table></div>';

  var gap = "";
  var g1 = c.g1;
  if (g1.exceedsTarget) {
    var parts = [{ n: "SharePoint", v: g1.sp.cumMin }, { n: "OneDrive", v: g1.od.cumMin }, { n: "Exchange", v: g1.ex.cumMin }].sort(function (a, b) { return b.v - a.v; });
    var pole = parts[0], next = parts[1];
    var lines = [];
    lines.push('<li><b>' + pole.n + '</b> is the long pole for Group 1 (' + fmtMin(pole.v) + ' of ABR time' + (next.v > 0 ? ', next slowest is ' + next.n + ' at ' + fmtMin(next.v) : '') + '). Bringing it down to the next workload would put Group 1 near ' + fmtMin(Math.max(next.v, 0)) + '.</li>');
    var ins = (typeof getInsightsSummary === "function") ? getInsightsSummary() : null;
    if (ins && ins.headline && ins.excludedCount > 0) {
      var h = ins.headline;
      lines.push('<li>Recovery Insights flagged ' + fmtNum(ins.excludedCount) + ' abnormal object' + (ins.excludedCount === 1 ? '' : 's') + '. Group 1 is <b>' + fmtMin(h.excludedG1Min) + '</b> without them and <b>' + fmtMin(h.includedG1Min) + '</b> with them ' + exLink("insights:insights-table", "Review flagged objects") + '.</li>');
    }
    lines.push('<li>Or set a Group 1 target that matches the modeled time (' + fmtMin(g1.wallClockCumMin) + '), or move some objects out of Group 1 ' + exLink("groups:grp-controls", "Adjust targets and scoring") + '.</li>');
    gap = '<div class="ex2-gap"><div class="ex2-mini-title">Gap analysis: Group 1 misses its ' + state.recovery.group1Hours + ' hr target by ' + fmtMin(g1.targetGapMin) + '</div><ul>' + lines.join("") + '</ul></div>';
  } else {
    gap = '<div class="ex2-note">Group 1 is within its stated ' + state.recovery.group1Hours + ' hr target. ' + exLink("groups:grp-controls", "Adjust targets") + '</div>';
  }
  return '<section class="ex2-block ex2-wide" id="exec-rto"><div class="ex2-eyebrow">Recovery Window (RTO) scorecard ' + exLink("groups:grp-controls", "Targets and inputs") + '</div>' + table + gap + '</section>';
}

function exBlockRisks() {
  var ins = (typeof getInsightsSummary === "function") ? getInsightsSummary() : { topRisks: [], total: 0 };
  var items;
  if (IS_SUMMARY) { items = '<div class="ex2-note">Object-level Recovery Insights are in the interactive report. ' + exLink("insights", "About Recovery Insights") + '</div>'; }
  else if (ins.topRisks && ins.topRisks.length > 0) {
    items = '<ol class="ex2-risks">' + ins.topRisks.slice(0, 3).map(function (r) {
      return '<li><span class="ex2-risk-title" ' + navAttr(r.link || "insights:insights-table") + '>' + esc(r.title) + '</span><div class="ex2-risk-detail">' + esc(r.detail || "") + '</div></li>';
    }).join("") + '</ol>';
  } else {
    items = '<div class="ex2-note">No abnormal objects were found that would extend your recovery time' + (IS_PREVIEW ? ' among the Group 1 objects.' : '.') + '</div>';
  }
  var pvNote = IS_PREVIEW ? '<div class="ex2-note">Insights for the remaining groups are part of the full assessment.</div>' : "";
  return '<section class="ex2-block" id="exec-risks"><div class="ex2-eyebrow">Top risks to recovery speed ' + exLink("insights:insights-summary", "All insights") + '</div>' + items + pvNote + '</section>';
}

function exBlockNext() {
  var items = [];
  items.push('<li>Validate Group 1 with the business owners ' + (IS_PREVIEW || IS_SUMMARY ? exLink("groups:grp-by-group:grp-g1", "See who is in Group 1") : exLink("groups:grp-by-group:grp-g1", "Review and adjust Group 1")) + '</li>');
  items.push('<li>Review the flagged objects and decide how to handle them ' + exLink("insights:insights-table", "Recovery Insights") + '</li>');
  if (IS_PREVIEW) { items.push('<li>Run the full assessment for Group 2-4 detail and recovery sequencing: <a href="' + CONTACT_SALES_URL + '" target="_blank" rel="noopener">contact your Rubrik representative</a></li>'); }
  else if (IS_SUMMARY) { items.push('<li>Open the interactive report for object-level detail and live adjustment of weights and targets</li>'); }
  else { items.push('<li>Tune scoring weights and Recovery Window (RTO) targets to match your priorities ' + exLink("groups:grp-controls", "Groups &amp; Recovery Model") + '</li>'); }
  return '<section class="ex2-block ex2-wide" id="exec-next"><div class="ex2-eyebrow">Suggested next steps</div><ol class="ex2-next">' + items.join("") + '</ol></section>';
}

// ---------------------------------------------------------------------------
// v2.0 Executive Summary: three numbers, one ladder, two status pills. Everything else lives on the Report tab.
// ---------------------------------------------------------------------------
var REC_NOW = new Date(); // "if recovery started now": dates in the ladder and calendar run from when the page was opened
function recAt(min) { return new Date(REC_NOW.getTime() + min * 60000); }
function recWhen(min) {
  var d = recAt(min);
  var today = d.toDateString() === REC_NOW.toDateString();
  var t = d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  return today ? ("today at " + t) : (d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }) + (min < 2880 ? " " + t : ""));
}
function recDate(min) { return recAt(min).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" }); }

function xsTileFast(c) {
  var n = reportMsObjs(c.g1);
  return '<section class="xs-tile xs-teal" id="exec-fast" ' + navAttr("report:report-by-group") + '><div class="xs-big">' + fmtMin(c.g1.wallClockCumMin) + '</div>' +
    '<div class="xs-cap">until your <b>' + fmtNum(n) + '</b> most critical objects are back (instead of <b>' + fmtMin(c.model.fullRestoreMin) + '</b>)</div></section>';
}
function xsTileWorth(c) {
  var ca = c.ca, r1 = ca.rows[0];
  var big = r1.locked ? exLocked() : fmtSaved(r1.savedMin);
  var money = ca.hasRate ? ('<div class="xs-money">' + fmtMoney(r1.cost) + ' cost avoided</div>') : '';
  return '<section class="xs-tile xs-mint" id="exec-worth"><div class="xs-big">' + big + '</div>' +
    '<div class="xs-cap">of downtime avoided to reach Group 1 ' + infoBtn("cost-avoided", "How we estimate cost avoided") + '</div>' + money +
    '<label class="xs-rate">At $ <input type="number" min="0" step="100" id="exec-cost-input" value="' + (ca.perHour || "") + '" placeholder="per hour" onchange="onExecCostChange(this.value)" aria-label="Estimated downtime cost per hour in US dollars"></label></section>';
}
function xsTileConc(c) {
  var conc = c.conc;
  if (!conc) { return '<section class="xs-tile" id="exec-concentration"><div class="xs-big">&mdash;</div><div class="xs-cap">Not enough data to compare Group 1 with the rest of the tenant.</div></section>'; }
  var bits = [];
  if (conc.bytesPct !== null) { bits.push('<b>' + Math.round(conc.bytesPct) + '%</b> of storage'); }
  if (conc.actPct !== null) { bits.push('<b>' + Math.round(conc.actPct) + '%</b> of recent activity'); }
  return '<section class="xs-tile" id="exec-concentration" ' + navAttr("report:report-concentration") + '><div class="xs-big">' + Math.round(conc.objPct) + '%</div>' +
    '<div class="xs-cap">of objects carry ' + (bits.length ? bits.join(" and ") : "most of the value") + '. That is why order matters.</div></section>';
}

// Critical data back in X, then mass recovery takes Y: a dated timeline chart (to scale), read at a glance.
function xlTicks(totalMin) {
  var td = totalMin / 1440, out = [], i;
  function lab(m) { return recAt(m).toLocaleDateString(undefined, { month: "short", day: "numeric" }); }
  if (td <= 10) { for (i = 0; i <= td; i++) { out.push({ m: i * 1440, l: i ? lab(i * 1440) : "Today" }); } }
  else if (td <= 70) { for (i = 0; i <= td; i += 7) { out.push({ m: i * 1440, l: i ? lab(i * 1440) : "Today" }); } }
  else {
    out.push({ m: 0, l: "Today" });
    var d = new Date(REC_NOW.getFullYear(), REC_NOW.getMonth() + 1, 1);
    while ((d - REC_NOW) / 60000 < totalMin && out.length < 60) { out.push({ m: (d - REC_NOW) / 60000, l: d.toLocaleDateString(undefined, { month: "short" }) }); d = new Date(d.getFullYear(), d.getMonth() + 1, 1); }
  }
  return out;
}
function xsLadderHtml(c) {
  var ladder = buildRecoveryLadderHtml(c.model);
  var head = '<div class="xs-ladder-h2"><span class="rl-title">Recovery Ladder</span> ' + exLink("report:report-calendar", "See it on a calendar") + '</div>';
  return '<section class="recovery-ladder" id="exec-ladder">' + head + ladder.replace('<div class="recovery-ladder">', '<div class="rl-inner">') + '</section>';
}

function xsPills(c) {
  var model = c.model;
  var defs = critKeys().map(function (key, i) { return [key, groupHoursOf(i + 1)]; });
  var ms = defs.map(function (d) { return reportMsOf(model, d[0]); }).filter(function (m) { return !!m; });
  var met = ms.filter(function (m) { return !m.exceedsTarget; }).length;
  var all = ms.length > 0 && met === ms.length;
  var head = IS_PREVIEW ? (all ? "Group 1 within target" : "Group 1 over target") : (all ? "All " + ms.length + " within target" : met + " of " + ms.length + " within target");
  var rto = '<div class="xs-pill' + (all ? "" : " warn") + '" ' + navAttr("report:exec-rto") + '><div class="xs-pill-big">' + head + '</div><div class="xs-pill-sub">Recovery Window (RTO) ' + (IS_PREVIEW ? state.recovery.group1Hours : (groupN() > 4 ? state.recovery.group1Hours + " ... " + groupHoursOf(groupN()) : state.recovery.groupHours.slice(0, groupN()).join(" / "))) + ' hr</div></div>';
  var ins = (typeof getInsightsSummary === "function") ? getInsightsSummary() : null;
  var risk;
  if (IS_SUMMARY) { risk = '<div class="xs-pill" ' + navAttr("insights") + '><div class="xs-pill-big">Recovery Insights</div><div class="xs-pill-sub">Object-level flags are in the interactive report</div></div>'; }
  else {
    var n = ins ? (ins.total || 0) : 0;
    risk = '<div class="xs-pill' + (n > 0 ? " warn" : "") + '" ' + navAttr("report:exec-risks") + '><div class="xs-pill-big">' + (n > 0 ? fmtNum(n) + " flagged" : "Nothing flagged") + '</div><div class="xs-pill-sub">' + (n > 0 ? "abnormal objects could slow recovery" : "no abnormal objects found") + '</div></div>';
  }
  return '<div class="xs-pills" id="exec-pills">' + rto + risk + '</div>';
}

function renderExecLean() {
  var model = computeRecoveryModel();
  var g1 = model.milestones["Critical Group 1"];
  var el = document.getElementById("exec-lean");
  if (!el) { return; }
  if (!(model.fullRestoreMin > 0) || !g1 || g1.locked) {
    el.innerHTML = '<div class="exec-hero-note">No objects with recent activity were found across the scanned workloads, so there is nothing to summarize yet.</div>';
    return;
  }
  var c = { model: model, g1: g1, ca: computeCostAvoided(model), conc: execConcentration(), profile: execGroup1Profile() };
  el.innerHTML =
    '<div class="xs-hero">' + xsTileFast(c) + xsTileWorth(c) + xsTileConc(c) + '</div>' +
    xsLadderHtml(c) + xsPills(c) +
    '<div class="xs-foot"><span>This is the one-screen version. Everything behind it is one click away.</span> ' + exLink("report", "Open the full report") + '</div>';
}

// ---------------------------------------------------------------------------
// Recovery ladder (shared by Exec block 4; Preview shows Group 1 + baseline only)
// ---------------------------------------------------------------------------
// Ladder geometry. Groups 1-3 end-lines are proportional to their cumulative times inside a fixed zone (with a minimum
// segment width so a very fast Group 1 stays visible); mass recovery is the elastic middle and is never to scale; Group 4's
// window is sized from its duration relative to Groups 1-3, log-compressed and clamped so any tenant (7 to 300+ days) fits.
function ladderLayout(cums, g4startMin, fullMin, minSegPct, g4MinPct) {
  // minSegPct = one flag's width in % of the track, so every end-line is at least a flag apart and each label can sit
  // directly under its own line (no label ever has to be pushed over another group's line).
  var n = cums.length, MINSEG = Math.max(3, minSegPct || 6), top = cums[n - 1] || 1;
  var ZONE = Math.max(n >= 3 ? 34 : (n === 2 ? 24 : 10), n * MINSEG);
  var abr = [], prev = 0;
  for (var i = 0; i < n; i++) {
    var p = ZONE * cums[i] / top;
    p = Math.max(p, prev + MINSEG);
    abr.push(p); prev = p;
  }
  var r = Math.max(0, fullMin - g4startMin) / top;
  var g4w = Math.min(30, Math.max(8, g4MinPct || MINSEG, 12 * Math.log(1 + r) / Math.LN2));
  return { abr: abr, g4w: g4w };
}

function buildRecoveryLadderHtml(model) {
  var full = model.fullRestoreMin;
  if (!full || full <= 0) { return ""; }

  var defs = critKeys().slice(0, 3).map(function (key, i) {
    return { tier: key, k: i + 1, short: tierTitle(i + 1), verb: i === 0 ? "back online" : "cumulative" };
  });

  var milestones = defs.filter(function (d) {
    var m = model.milestones[d.tier];
    return m && !m.locked;
  }).map(function (d) {
    var t = execTierSum(d.tier);
    return { tier: d.tier, k: d.k, short: d.short, verb: d.verb, color: groupColor(d.k), cumMin: model.milestones[d.tier].wallClockCumMin, count: t ? t.objects : 0 };
  }).filter(function (m) { return m.count > 0; });

  if (milestones.length === 0) { return ""; }

  // Compact mode (5+ groups): every group keeps its line, but only Group 1 and the last group carry a full time/label flag;
  // the groups in between show a small number under their line (time on hover) so 12 flags never collide.
  var compact = false; // the ladder always shows Groups 1-3; any further groups are summarised in the note below it
  var lastCum = milestones[milestones.length - 1].cumMin;
  var lastM = model.milestones[lastCritKey()] && !model.milestones[lastCritKey()].locked ? model.milestones[lastCritKey()] : null;
  var g13Mass = lastM ? lastM.massRecoveryCumMin : 0;
  var showG13 = g13Mass > lastCum && g13Mass < full * 0.97;
  var C_G4 = "#F5A524", C_MASS = "#8793A6";
  var lowN = lowName(), lastScope = scopeName(groupN()), ladderScope = scopeName(Math.min(3, groupN()));
  var wrapEl = document.getElementById("exec-lean");
  var wrapPx = Math.max(480, ((wrapEl && wrapEl.clientWidth) || 900) - 72);
  var nFlags = (compact ? 2 : milestones.length) + (showG13 ? 2 : 1);
  var FLAG_PX = Math.max(84, Math.min(132, Math.floor(wrapPx / (nFlags + 0.6))));
  var layout = ladderLayout(milestones.map(function (m) { return m.cumMin; }), showG13 ? g13Mass : lastCum, full, compact ? 4 : ((FLAG_PX + 4) / wrapPx) * 100, ((FLAG_PX + 4) / wrapPx) * 100);
  var abrPos = layout.abr;
  var pts = [], pos = 0;
  milestones.forEach(function (m, i) {
    pos = abrPos[i];
    var minor = compact && i !== 0 && i !== milestones.length - 1;
    pts.push({ pos: pos, time: fmtMin(m.cumMin), color: m.color, label: esc(compact ? "Group " + m.k : m.short) + "<br>" + esc(m.verb), kind: "abr", minor: minor, k: m.k });
  });
  var g4dur = Math.max(0, full - (showG13 ? g13Mass : lastCum));
  var g4w = layout.g4w;
  var g4pos = 100, g4start = 100 - g4w;
  var tailStart = pos + (g4start - pos) * 0.3;
  if (showG13) {
    pts.push({ pos: g4start, time: fmtMin(g13Mass), color: C_G4, label: esc(lowN) + " starts<br>(" + esc(lastScope) + " fully restored)", kind: "g4" });
    pts.push({ pos: g4pos, time: fmtMin(full), color: C_G4, label: "Everything recovered<br>(" + esc(lowN) + " done, whole tenant back)", kind: "g4" });
  } else {
    pts.push({ pos: g4pos, time: fmtMin(full), color: C_G4, label: "Everything recovered<br>(" + esc(lowN) + " last, by mass recovery)", kind: "g4" });
  }

  var flagged = pts.filter(function (pt) { return !pt.minor; });
  var minGap = ((FLAG_PX + 2) / wrapPx) * 100;
  var halfPct = (FLAG_PX / 2 / wrapPx) * 100;
  var lastPos = -999;
  flagged.forEach(function (pt) {
    pt.labelPos = Math.max(pt.pos, halfPct, lastPos + minGap);
    lastPos = pt.labelPos;
  });
  var limit = 100 - halfPct;
  for (var i = flagged.length - 1; i >= 0; i--) {
    if (flagged[i].labelPos > limit) { flagged[i].labelPos = limit; }
    limit = flagged[i].labelPos - minGap;
  }
  // Never let a label fall off the left edge (a narrow window used to push Group 1 out of view): re-run forward from the edge.
  if (flagged[0].labelPos < halfPct) {
    var lp = -999;
    flagged.forEach(function (pt) { pt.labelPos = Math.max(pt.labelPos, halfPct, lp + minGap); lp = pt.labelPos; });
  }
  // A label held back from its line by the right edge is anchored to the line instead (text runs leftward from it).
  flagged.forEach(function (pt) { if (pt.labelPos < pt.pos - 0.5) { pt.labelPos = pt.pos; pt.end = true; } });
  // Likewise a first label held back by the left edge starts at its line and reads rightward.
  if (flagged[0].labelPos > flagged[0].pos + 0.5 && (flagged.length < 2 || flagged[0].pos + 0.5 + (FLAG_PX / wrapPx) * 100 <= flagged[1].labelPos - (FLAG_PX / 2 / wrapPx) * 100)) { flagged[0].labelPos = flagged[0].pos; flagged[0].start = true; }

  var segs = [], prev = 0;
  milestones.forEach(function (m, i) { segs.push({ w: pts[i].pos - prev, bg: m.color, cls: "" }); prev = pts[i].pos; });
  if (showG13) {
    segs.push({ w: g4start - prev, bg: "", cls: " tail g13" }); prev = g4start;
    segs.push({ w: g4pos - prev, bg: "", cls: " tail g4" });
  } else {
    segs.push({ w: g4pos - prev, bg: "", cls: " tail g13" });
  }
  var segHtml = segs.map(function (s) {
    return '<div class="rl-seg' + s.cls + '" style="width:' + s.w + '%;' + (s.bg ? 'background:' + s.bg + ';' : '') + '"></div>';
  }).join("");

  var g3pt = pts[milestones.length - 1], g4pt = pts[milestones.length];
  var segRoomPx = showG13 ? ((g4pt.labelPos - g3pt.labelPos - 2 * (FLAG_PX / 2 / wrapPx) * 100) / 100) * wrapPx : 0;
  var segLabel = showG13 && segRoomPx >= 130 ? '<div class="rl-seglabel" style="left:' + ((g3pt.labelPos + g4pt.labelPos) / 2) + '%;"><span class="rl-seglabel-t">Mass recovery,<br>' + esc(lastScope) + ' older data</span></div>' : "";
  var flagsHtml = segLabel + '<div class="rl-break" style="left:' + tailStart + '%;" title="Spacing after ' + esc(lastScope) + ' is not to scale">&#8776;</div>' + pts.map(function (pt) {
    var line = '<div class="rl-line" style="left:' + pt.pos + '%;background:' + pt.color + ';"' + (pt.minor ? ' title="Group ' + pt.k + ' online in ' + pt.time + '"' : '') + '></div>';
    if (pt.minor) { return line + '<div class="rl-tickn" style="left:' + pt.pos + '%;" title="Group ' + pt.k + ' online in ' + pt.time + '">' + pt.k + '</div>'; }
    return line +
      '<div class="rl-flag' + (pt.end ? ' end' : '') + (pt.start ? ' start' : '') + (compact ? ' compact' : '') + '" style="left:' + pt.labelPos + '%;width:' + FLAG_PX + 'px;">' +
        '<div class="rl-time"' + (pt.kind === "g4" ? ' style="color:var(--g4-text,#B9740A)"' : '') + '>' + pt.time + '</div>' +
        '<div class="rl-label">' + pt.label + '</div>' +
      '</div>';
  }).join("");

  var noteHtml = "";
  var anyCapped = TIER_ORDER.some(function (t) { return model.milestones[t] && !model.milestones[t].locked && model.milestones[t].cappedByMass; });
  if (anyCapped) {
    noteHtml = '<div class="rl-note">ABR is never slower than bulk-restoring the same groups: where per-object job scheduling would push a milestone past the Mass Recovery time for that scope, the milestone is held at the Mass Recovery time. Critical (Group 1) data is still back <b>' + fmtMin(Math.max(0, full - milestones[0].cumMin)) + ' sooner</b> than a bulk restore of the whole tenant.</div>';
  }

  if (groupN() > 3) {
    var gN = model.milestones[lastCritKey()];
    noteHtml += '<div class="rl-note rl-more">The ladder shows Groups 1-3. <b>Groups 4-' + groupN() + '</b> follow with ABR' + (gN && !gN.locked ? ' (' + esc(scopeName(groupN())) + ' online in <b>' + fmtMin(gN.wallClockCumMin) + '</b>)' : '') + ' and are listed with their own times in ' + exLink("report:report-by-group", "Recovery by group") + '.</div>';
  }

  return '<div class="recovery-ladder">' +
    '<div class="rl-sub">' + esc(ladderScope) + ' are drawn to scale against each other, and ' + esc(lowN) + ' is sized against them. Mass recovery in the middle is not to scale (&asymp;).</div>' +
    '<div class="rl-track-wrap">' +
      '<div class="rl-track">' + segHtml + '</div>' +
      flagsHtml +
    '</div>' +
    noteHtml +
  '</div>';
}

// ---------------------------------------------------------------------------
// Report tab
// ---------------------------------------------------------------------------
function reportTimelineHtml(model, g1) {
  var tlSegs = [], prevCum = 0, lastCum = 0, g3ok = false;
  critKeys().forEach(function (key, i) {
    var m = model.milestones[key];
    if (!m || m.locked) { return; }
    tlSegs.push({ label: "Group " + (i + 1), dur: Math.max(0, m.wallClockCumMin - prevCum), color: groupColor(i + 1) });
    prevCum = m.wallClockCumMin; lastCum = m.wallClockCumMin; g3ok = i > 0;
  });
  var g3 = { wallClockCumMin: lastCum };
  var realClusterPct = (lastCum / model.fullRestoreMin) * 100;
  var clusterPct = Math.min(94, Math.max(realClusterPct, 6));

  var chipsHtml = tlSegs.map(function (s) {
    var isEmpty = s.dur <= 0;
    var bgStyle = isEmpty ? "background:repeating-linear-gradient(45deg, var(--mid-gray) 0, var(--mid-gray) 2px, var(--bg-card) 2px, var(--bg-card) 4px);" : ("background:" + s.color + ";");
    var flexStyle = "flex:" + Math.max(s.dur, 0.01) + " 1 0;";
    var titleText = s.label + " (ABR): " + fmtMin(s.dur);
    return '<div class="fin-tl-chip" style="' + bgStyle + flexStyle + '" title="' + titleText.replace(/"/g, "&quot;") + '"></div>';
  }).join("");

  var withAbrBarHtml = '<div class="fin-tl-track-row">' +
    '<div class="fin-tl-track-bar with-abr">' +
      '<div class="fin-tl-chip-cluster" style="flex:0 0 ' + clusterPct.toFixed(2) + '%;">' + chipsHtml + "</div>" +
      '<div class="fin-tl-bg-fill" title="Mass Recovery still restoring in the background, in random order: ' + fmtMin(model.fullRestoreMin).replace(/"/g, "&quot;") + '">rest of tenant restoring in random order</div>' +
    "</div>" +
    '<div class="fin-tl-track-endlabel">' + fmtMin(model.fullRestoreMin) + ' <span class="arrow">&#8599;</span></div>' +
  "</div>";
  var withoutAbrBarHtml = '<div class="fin-tl-track-row">' +
    '<div class="fin-tl-track-bar hatched"><span class="fin-tl-track-bar-text">Restored in random order &ndash; the exact data a user needs may not come back until this finishes</span></div>' +
    '<div class="fin-tl-track-endlabel">' + fmtMin(model.fullRestoreMin) + ' <span class="arrow">&#8599;</span></div>' +
  "</div>";
  var legendHtml = '<div class="fin-tl-legend">' + tlSegs.map(function (s) {
    var swatchStyle = s.dur <= 0 ? "background:repeating-linear-gradient(45deg, var(--mid-gray) 0, var(--mid-gray) 3px, var(--bg-card) 3px, var(--bg-card) 6px);" : ("background:" + s.color + ";");
    return '<div class="fin-tl-legend-item"><span class="fin-tl-swatch" style="' + swatchStyle + '"></span><span>' + s.label + "</span></div>";
  }).join("") + '<div class="fin-tl-legend-item"><span class="fin-tl-swatch" style="background:var(--mid-gray);"></span><span>Mass recovery</span></div>' + "</div>";

  var callout = g3ok
    ? 'Same timescale for both rows. The data your users actually need is back in <b>' + fmtMin(g3.wallClockCumMin) + "</b> with ABR, vs. <b>" + fmtMin(model.fullRestoreMin) + "</b> for a fully random-order restore."
    : 'Same timescale for both rows. Critical Group 1 is back in <b>' + fmtMin(g1.wallClockCumMin) + "</b> with ABR, vs. <b>" + fmtMin(model.fullRestoreMin) + "</b> for a fully random-order restore.";

  return '<div class="fin-timeline">' +
    '<div class="fin-tl-title">Mass Recovery vs. ABR: Same Timescale, Different Order</div>' +
    '<div class="fin-tl-desc">Mass Recovery &ndash; the industry standard, Rubrik included &ndash; restores pieces in random order: like dumping out a puzzle and gluing down whatever you grab first, nothing forms a complete, usable picture until the whole box is done, ' + fmtMin(model.fullRestoreMin) + ' here. ABR does what any puzzle solver does first &ndash; corners and edges, the pieces that actually give you something to work with &ndash; prioritizing recently accessed, modified, and created data so the business is operational in ' + fmtMin(g1.wallClockCumMin) + '.</div>' +
    '<div class="fin-tl-track-block"><div class="fin-tl-track-label">Without ABR</div><div class="fin-tl-track-sublabel">Mass Recovery &ndash; random restore order</div>' + withoutAbrBarHtml + "</div>" +
    '<div class="fin-tl-track-block"><div class="fin-tl-track-label">With ABR</div><div class="fin-tl-track-sublabel">recently modified data restored first</div>' + withAbrBarHtml + "</div>" +
    '<div class="fin-tl-gap-callout">' + callout + "</div>" +
    legendHtml +
  "</div>";
}

function reportLowActivityHtml(model) {
  var g4 = TIER_ORDER[TIER_ORDER.length - 1];
  if (IS_PREVIEW) {
    return '<div id="report-low-activity-inner">' + accHtml({ id: "low", title: "Group 4 Detail", summary: '<span>Available in the full assessment</span>',
      body: function () { return pvLockedPanel("Group 4 detail", "Group 4 counts and recovery times are part of the full assessment."); } }) + '</div>';
  }
  var MASS_KEY = { mailboxes: "ex", onedrive: "od", sharepoint: "sp" };
  var perWl = WORKLOAD_DEFS.map(function (wd) {
    var t = execWlTier(wd.key, g4), ten = execWlTenant(wd.key);
    var cnt = t ? t.objectCount : 0, tot = ten.objectCount;
    var mk = MASS_KEY[wd.key];
    return { label: wd.label, count: cnt, total: tot, pct: tot > 0 ? Math.round((cnt / tot) * 100) : 0, massMin: mk ? model.perWorkloadMassRecoveryMin[mk] : null };
  }).filter(function (d) { return d.total > 0; });
  var totAll = perWl.reduce(function (s, d) { return s + d.total; }, 0);
  var cntAll = perWl.reduce(function (s, d) { return s + d.count; }, 0);
  var pctAll = totAll > 0 ? Math.round((cntAll / totAll) * 100) : 0;
  if (totAll <= 0) { return ""; }
  var sorted = perWl.slice().sort(function (x, y) { return y.pct - x.pct; });
  var body = function () {
    return '<div class="exec-dormant-headline"><b>' + pctAll + '%</b> of this tenant (' + fmtNum(cntAll) + ' of ' + fmtNum(totAll) + ' objects) falls into Group 4 - limited activity across every metric in the reporting window. Group 4 gets no ABR priority and is recovered entirely by Mass Recovery, alongside whatever else hasn\'t come back yet.</div>' +
      '<div class="exec-dormant-grid">' + sorted.map(function (d) {
        var timeHtml = d.massMin !== null
          ? '<div class="exec-dormant-time">Mass Recovery: ~' + fmtMin(d.massMin) + ' (whole workload)</div>'
          : '<div class="exec-dormant-time-na">No independent recovery-time model - Teams content lives in SharePoint/Exchange</div>';
        return '<div class="exec-dormant-cell"><div class="exec-dormant-pct">' + d.pct + '%</div><div class="exec-dormant-label">' + esc(d.label) + '</div><div class="exec-dormant-sub">' + fmtNum(d.count) + ' of ' + fmtNum(d.total) + ' in Group 4</div>' + timeHtml + '</div>';
      }).join("") + '</div>';
  };
  return accHtml({ id: "low", title: "Group 4 Detail", summary: '<span>' + pctAll + '% (' + fmtNum(cntAll) + ' of ' + fmtNum(totAll) + ' objects)</span>', body: body });
}

function reportDataQualityHtml() {
  var meta = DATA.meta || {};
  var ci = mailboxClassInfo();
  var rowsHtml = [];
  function add(area, status, detail, ok) {
    rowsHtml.push('<tr><td>' + esc(area) + '</td><td><span class="ex2-badge ' + (ok === true ? "ok" : (ok === false ? "bad" : "neutral")) + '">' + esc(status) + '</span></td><td>' + detail + '</td></tr>');
  }
  var counts = WORKLOAD_DEFS.map(function (wd) { return wd.label + ": " + fmtNum(execWlTenant(wd.key).objectCount); }).join(" &middot; ");
  add("Lookback period", periodDays() + " days", "Usage reports were pulled for the last " + periodDays() + " days. Group 4 means little to no activity in that window. The 7-day recent-activity window used for ABR is always collected separately.", true);
  add("Objects collected", "Collected", counts, true);
  var zero = WORKLOAD_DEFS.filter(function (wd) { return execWlTenant(wd.key).objectCount === 0; }).map(function (wd) { return wd.label; });
  if (zero.length) { add("Workloads with no data", zero.join(", "), "No objects were returned for these workloads (not licensed, not in use, or the report returned nothing). They contribute nothing to the figures.", null); }

  if (ci.known) {
    var mc = ci.mc;
    add("License classification", "Available", "Licensed users: <b>" + fmtNum(mc.licensedCount) + "</b>. Shared / group / other mailboxes: <b>" + fmtNum(mc.sharedCount) + "</b> (protected, no license needed)." + (mc.unknownCount > 0 ? " Unclassified: " + fmtNum(mc.unknownCount) + "." : ""), true);
    if (mc.excludedCount > 0) { add("Mailboxes excluded", fmtNum(mc.excludedCount) + " mailboxes", "Belong to enabled, unlicensed users (" + fmtStorage(mc.excludedStorageBytes) + ", " + fmtNum(mc.excludedItems) + " items). Rubrik does not protect them, so they are left out of every figure in this report.", null); }
    if (mc.unmappedSkus && mc.unmappedSkus.length) {
      add("Unrecognized license SKUs", fmtNum(mc.unmappedSkus.length) + " SKU" + (mc.unmappedSkus.length === 1 ? "" : "s"), "These are shown as &quot;Other&quot; in the plan breakdown: " + mc.unmappedSkus.slice(0, 5).map(function (s) { return esc((s.skuId || s.id || s.sku || JSON.stringify(s)) + (s.users != null ? " (" + s.users + " users)" : "")); }).join(", ") + ".", null);
    }
    add("Shared mailbox detection", ci.mc.exoConfirmedShared ? "Confirmed" : "Estimated", ci.mc.exoConfirmedShared ? "Confirmed through Exchange Online (" + fmtNum(ci.mc.exoSharedCount) + " shared mailboxes)." : "Estimated from license data. Run with -DetailedSizing to confirm shared mailboxes through Exchange Online.", ci.mc.exoConfirmedShared ? true : null);
  } else {
    add("License classification", "Not available", "Licensed versus shared mailboxes could not be classified from license data (profile enrichment failed or returned nothing). Every mailbox is included and no unlicensed mailboxes were excluded, so mailbox counts may be overstated.", false);
  }

  // Enrichment availability (rows only - not measurable in the Summary build)
  if (IS_SUMMARY) {
    add("Profile enrichment", "Not shown", "Job title, department and group coverage is measured in the interactive report.", null);
  } else {
    var enrichRows = ["mailboxes", "onedrive"].reduce(function (a, k) { return a.concat(DATA.workloads[k] || []); }, []);
    var scope = IS_PREVIEW ? " (Group 1 objects)" : "";
    if (enrichRows.length === 0) { add("Profile enrichment", "No data", "No mailbox or OneDrive objects to measure.", null); }
    else {
      function share(f) { var n = enrichRows.filter(function (r) { var v = r[f]; return Array.isArray(v) ? v.length > 0 : !!v; }).length; return Math.round((n / enrichRows.length) * 100); }
      var jt = share("JobTitle"), dp = share("Department"), gr = share("Groups");
      var okEnrich = jt >= 50 && dp >= 50;
      add("Profile enrichment" + scope, okEnrich ? "Good" : "Limited", "Job title present for <b>" + jt + "%</b>, department for <b>" + dp + "%</b>, Entra group membership for <b>" + gr + "%</b> of mailbox and OneDrive objects. Title-weight scoring and department filters depend on these fields.", okEnrich ? true : null);
    }
  }
  if (meta.offlineMode) { add("Collection method", "Offline", "Built from usage reports exported from the Microsoft 365 admin center. No Graph or Exchange connection was made, so directory, license, group and Exchange detail were not collected." + (meta.offlineMissing && meta.offlineMissing.length ? " Optional exports not supplied: " + meta.offlineMissing.map(esc).join(", ") + "." : ""), null); }
  add("Entra group data", meta.groupsRequested ? "Collected" : "Skipped", meta.groupsRequested ? "Group membership was requested and powers filter-by-group tools." : "Group membership was skipped (-NoGroups), so group filters are empty.", meta.groupsRequested ? true : null);
  add("Detailed sizing", meta.detailedSizingRequested ? "Collected" : "Not collected", meta.detailedSizingRequested ? "Archive mailbox and Recoverable Items sizing was collected." : "Archive mailbox storage and Recoverable Items were not sized (run with -DetailedSizing). They are not part of the figures.", meta.detailedSizingRequested ? true : null);

  var cannot = [];
  if (meta.offlineMode) { cannot.push("a live tenant connection (offline run, reduced confidence)"); }
  if (!ci.known) { cannot.push("license-based mailbox classification"); }
  if (!meta.detailedSizingRequested) { cannot.push("archive mailbox and Recoverable Items sizes"); }
  if (!meta.groupsRequested) { cannot.push("Entra group membership"); }
  if (zero.length) { cannot.push("data for " + zero.join(", ")); }
  var stmt = cannot.length
    ? '<div class="ex2-note"><b>Could not be collected or was not requested:</b> ' + cannot.join("; ") + '. Everything else in this report was collected as described above.</div>'
    : '<div class="ex2-note">Everything this report relies on was collected. Nothing was skipped.</div>';

  var table = '<div class="table-wrap"><table class="ex2-table"><thead><tr><th>Area</th><th>Status</th><th>Detail</th></tr></thead><tbody>' + rowsHtml.join("") + '</tbody></table></div>';
  var summary = cannot.length ? '<span>' + cannot.length + ' item' + (cannot.length === 1 ? '' : 's') + ' not collected</span>' : '<span>All collected</span>';
  return accHtml({ id: "dq", title: "Data quality &amp; coverage", summary: summary, body: function () { return table + stmt; } });
}

// ---------------------------------------------------------------------------
// v2.0 Report tab: the evidence behind the Executive Summary (no repeat of its hero or timeline).
// Order: verdict + confidence, four-step case, recovery by group, drivers, sensitivity,
// concentration, where objects sit, Group 4, decisions, data quality.
// Preview/Summary: Group 1 only where Groups 2-4 would be needed (locked rows, never invented numbers).
// ---------------------------------------------------------------------------
function reportMsOf(model, tier) { var m = model.milestones[tier]; return (m && !m.locked) ? m : null; }
function reportMsObjs(m) { return m.sp.objectCount + m.od.objectCount + m.ex.objectCount; }
function reportMsItems(m) { return m.sp.itemCount + m.od.itemCount + m.ex.itemCount; }
function reportMsBytes(m) { return m.sp.storage + m.od.storage + m.ex.storage * 1048576; }
function reportLongPole(m) {
  var parts = [{ n: "SharePoint", v: m.sp.cumMin, k: "items" }, { n: "OneDrive", v: m.od.cumMin, k: "items" }, { n: "Exchange", v: m.ex.cumMin, k: null }]
    .sort(function (a, b) { return b.v - a.v; });
  var p = parts[0];
  if (!(p.v > 0)) { return "&mdash;"; }
  var why = "items per minute";
  if (p.n === "Exchange") {
    var cons = execConstraints(computeRecoveryModel()).filter(function (x) { return x.label === "Exchange"; })[0];
    why = (cons && cons.kind === "bytes") ? "data volume" : "items per minute";
  }
  return esc(p.n) + " (" + why + ")";
}

function reportConfidence() {
  var meta = DATA.meta || {};
  var ci = mailboxClassInfo();
  var notes = [], level = "High";
  function bump(l) { if (l === "Limited" || (l === "Moderate" && level === "High")) { level = l; } }
  var zero = WORKLOAD_DEFS.filter(function (wd) { return execWlTenant(wd.key).objectCount === 0; }).map(function (wd) { return wd.label; });
  if (zero.length) { notes.push("no data for " + zero.join(", ")); bump("Moderate"); }
  if (!ci.known) { notes.push("licensed versus shared mailboxes not classified"); bump("Limited"); }
  else {
    if (ci.mc.excludedCount > 0) { notes.push(fmtNum(ci.mc.excludedCount) + " unlicensed mailboxes excluded"); }
    if (!ci.mc.exoConfirmedShared) { notes.push("shared mailboxes estimated from license data"); bump("Moderate"); }
  }
  if (!IS_PREVIEW && !IS_SUMMARY) {
    var ins = (typeof getInsightsSummary === "function") ? getInsightsSummary() : null;
    if (ins && ins.excludedCount > 0 && state.insights.exclude) { notes.push(fmtNum(ins.excludedCount) + " abnormal object" + (ins.excludedCount === 1 ? "" : "s") + " left out of the estimates"); bump("Moderate"); }
  }
  notes.push("usage lookback " + periodDays() + " days");
  return { level: level, notes: notes };
}

function reportVerdictHtml(model, g1, ca) {
  var r1 = ca.rows[0];
  var nObj = reportMsObjs(g1);
  var tenant = execTenantSum();
  var pct = tenant.objects > 0 ? Math.round((nObj / tenant.objects) * 100) : 0;
  var conf = reportConfidence();
  var saved = r1.locked ? "" : (' That saves <b>' + fmtSaved(r1.savedMin) + '</b>' + (ca.hasRate ? ' (<b>' + fmtMoney(r1.cost) + '</b> cost avoided at ' + fmtMoney(ca.perHour) + ' per hour).' : '.'));
  return '<div class="rep-verdict"><div class="rep-verdict-text">Group 1 (<b>' + fmtNum(nObj) + '</b> objects, <b>' + pct + '%</b> of your tenant) is usable in <b>' + fmtMin(g1.wallClockCumMin) + '</b> with ABR, instead of <b>' + fmtMin(model.fullRestoreMin) + '</b> with a random-order restore.' + saved +
    ' ' + exLink("exec", "Executive Summary") + '</div>' +
    '<div class="rep-confidence" ' + navAttr("report:report-data-quality:dq") + '><span class="rep-conf-badge ' + conf.level.toLowerCase() + '">Confidence: ' + conf.level + '</span> <span class="rep-conf-notes">' + conf.notes.join(" &middot; ") + '</span> ' + exLink("report:report-data-quality:dq", "Data quality") + '</div></div>';
}

function reportCaseHtml(model, g1, conc) {
  var g1Target = state.recovery.group1Hours;
  var met = critKeys().filter(function (k) { var m = reportMsOf(model, k); return m && !m.exceedsTarget; }).length;
  var avail = critKeys().filter(function (k) { return reportMsOf(model, k); }).length;
  var evidence = conc
    ? 'Group 1 is <b>' + Math.round(conc.objPct) + '%</b> of objects but <b>' + (conc.bytesPct === null ? "n/a" : Math.round(conc.bytesPct) + '%') + '</b> of storage' + (conc.actPct !== null ? ' and <b>' + Math.round(conc.actPct) + '%</b> of recent activity.' : '.')
    : 'Group 1 is a small share of the tenant that carries most of the recent activity.';
  function step(n, title, body, link) {
    return '<div class="rep-step" ' + navAttr(link) + '><div class="rep-step-n">' + n + '</div><div class="rep-step-body"><div class="rep-step-title">' + title + '</div><div class="rep-step-text">' + body + '</div></div></div>';
  }
  return '<div class="rep-case">' +
    step(1, "The problem", 'A tenant-wide restore takes <b>' + fmtMin(model.fullRestoreMin) + '</b> and returns data in no useful order.', "report:report-by-group") +
    step(2, "What changes", 'ABR restores what people were just working on first. Group 1 is online in <b>' + fmtMin(g1.wallClockCumMin) + '</b>.', "groups:grp-headline") +
    step(3, "The evidence", evidence, "report:report-concentration") +
    step(4, "The decision", 'Confirm Group 1 and the Recovery Window (RTO) targets. <b>' + met + ' of ' + avail + '</b> targets are met' + (IS_PREVIEW ? " for Group 1." : "."), "report:report-decisions") +
  '</div>';
}

function reportByGroupHtml(model) {
  var ca = computeCostAvoided(model);
  var defs = critKeys().map(function (key, i) { var k = i + 1; return [key, k === 1 ? "Critical users (Group 1)" : "+ " + (groupN() === 3 ? (k === 2 ? "Important users" : "Standard users") : "Group " + k) + " (" + scopeName(k) + ")", groupHoursOf(k)]; });
  var rate = ca.hasRate;
  var cumO = 0, cumI = 0, cumB = 0;
  var rows = defs.map(function (d, idx) {
    var m = reportMsOf(model, d[0]);
    if (m) { cumO += reportMsObjs(m); cumI += reportMsItems(m); cumB += reportMsBytes(m); }
    if (!m) {
      return '<tr><td>' + d[1] + '</td><td colspan="' + (rate ? 10 : 9) + '">' + exLocked() + ' <span class="rep-lock-note">Run the Full assessment to see this row.</span></td></tr>';
    }
    var cr = ca.rows[idx];
    var badge = m.exceedsTarget ? '<span class="ex2-badge bad">Over by ' + fmtMin(m.targetGapMin) + '</span>' : '<span class="ex2-badge ok">Within target</span>';
    return '<tr><td>' + d[1] + '</td>' +
      '<td data-sort="' + cumO + '">' + fmtNum(cumO) + '</td>' +
      '<td data-sort="' + Math.round(cumI) + '">' + fmtNum(cumI) + '</td>' +
      '<td data-sort="' + Math.round(cumB) + '">' + fmtStorageNum(cumB) + '</td>' +
      '<td data-sort="' + Math.round(m.wallClockCumMin) + '">' + fmtMin(m.wallClockCumMin) + '</td>' +
      '<td data-sort="' + (d[2] * 60) + '">' + d[2] + ' hr</td>' +
      '<td>' + badge + '</td>' +
      '<td data-sort="' + Math.round(m.massRecoveryCumMin) + '">~' + fmtMin(m.massRecoveryCumMin) + '</td>' +
      '<td data-sort="' + Math.round(cr.savedMin) + '">' + fmtSaved(cr.savedMin) + '</td>' +
      (rate ? '<td data-sort="' + Math.round(cr.cost) + '">' + fmtMoney(cr.cost) + '</td>' : '') +
      '<td>' + reportLongPole(m) + '</td></tr>';
  }).join("");
  var full = '<tr class="total-row no-sort-row"><td>Full tenant</td><td colspan="3">Mass Recovery baseline, no prioritization</td><td>' + fmtMin(model.fullRestoreMin) + '</td><td colspan="' + (rate ? 6 : 5) + '"></td></tr>';
  var head = '<tr><th>Milestone</th><th>Objects</th><th>Items / files</th><th>' + storageHeader("Storage") + '</th><th>ABR time</th><th>Recovery Window (RTO) target</th><th>Status</th><th>Mass Recovery, same scope</th><th>Hours saved</th>' + (rate ? '<th>Cost avoided</th>' : '') + '<th>Slowest workload (limit)</th></tr>';
  var note = '<div class="ex2-note">Cumulative: each row includes the groups before it. ' + (rate ? "" : costPromptHtml() + ' ') + 'Recovery speed is limited by items restored per minute for SharePoint and OneDrive, and by the slower of item rate and per-mailbox transfer rate for Exchange, not by network bandwidth. ' + exLink("methodology", "How it is calculated") + ' ' + exLink("groups:grp-controls", "Adjust Recovery Window (RTO) targets") + '</div>';
  return '<h2>Recovery by group</h2><div class="table-wrap"><table class="ex2-table rep-table"><thead>' + head + '</thead><tbody>' + rows + full + '</tbody></table></div>' + note;
}

function reportDriversHtml() {
  var ins = (!IS_PREVIEW && !IS_SUMMARY && typeof getInsightsSummary === "function") ? getInsightsSummary() : null;
  var model = computeRecoveryModel();
  var items = [];
  items.push(['Usage lookback', periodDays() + ' days', 'Set when the script ran (-Period). Decides who lands in ' + lowName() + '.', null]);
  items.push(['Recent-data window', state.recovery.windowDays + ' days', 'How much recent data ABR restores first (maximum 7).', "groups:grp-controls"]);
  items.push(['Recovery Window (RTO) targets', (groupN() > 4 ? state.recovery.group1Hours + ' ... ' + groupHoursOf(groupN()) : state.recovery.groupHours.slice(0, groupN()).join(' / ')) + ' hr', groupN() + ' criticality groups, cumulative. They move the group boundaries.', "groups:grp-controls"]);
  var cells = items.map(function (x) {
    return '<div class="rep-driver"' + (x[3] ? ' ' + navAttr(x[3]) : '') + '><div class="rep-driver-label">' + x[0] + '</div><div class="rep-driver-val">' + x[1] + '</div><div class="rep-driver-note">' + x[2] + '</div></div>';
  }).join("");
  var live = '<div class="rep-live"><label class="ex2-rate">Downtime cost per hour (USD) <input type="number" min="0" step="100" id="rep-cost-input" value="' + (parseFloat(state.recovery.costPerHour) || 0) + '" onchange="onExecCostChange(this.value)"></label>';
  if (ins && ins.excludedCount > 0) {
    var on = !!state.insights.exclude;
    live += ' <span class="rep-toggle">Abnormal objects (' + fmtNum(ins.excludedCount) + '): <button type="button" class="ins-toggle-btn' + (on ? " active" : "") + '" aria-pressed="' + on + '" onclick="setExcludeOutliers(true)">Exclude</button><button type="button" class="ins-toggle-btn' + (on ? "" : " active") + '" aria-pressed="' + (!on) + '" onclick="setExcludeOutliers(false)">Include</button> <span class="linkout" ' + navAttr("insights:insights-table") + '>See which objects &rarr;</span></span>';
  }
  live += '</div>';
  return '<h2>What drives these numbers</h2><div class="rep-drivers">' + cells + '</div>' + live;
}

// Scenario runs re-tier the tenant, so they are computed on request (Full only) and cached against the inputs.
function reportScenarioSig() {
  var r = state.recovery;
  return [r.windowDays, r.licenseTier, r.groupCount, r.groupHours.join(','), state.insights.exclude, JSON.stringify(state.weights)].join("|");
}
function reportScenarioResult() {
  var s = uiState.scenarios;
  return (s && s.sig === reportScenarioSig()) ? s : null;
}
function runReportScenarios() {
  if (IS_PREVIEW || IS_SUMMARY) { return; }
  var keep = { w: state.recovery.windowDays, g: state.recovery.groupHours.slice() };
  var sig = reportScenarioSig();
  var tenantObjs = execTenantSum().objects;
  var defs = [];
  function sameHours(h) { return h.length === keep.g.length && h.every(function (v, i) { return v === keep.g[i]; }); }
  [1, 3, 7].forEach(function (d) { defs.push({ label: "Recent-data window " + d + " day" + (d === 1 ? "" : "s"), w: d, g: keep.g.slice(), current: d === keep.w }); });
  var presetDefs = groupN() === 3 ? [["Standard targets (4 / 24 / 72 hr)", [4, 24, 72]], ["Enterprise targets (24 / 120 / 240 hr)", [24, 120, 240]]] : [];
  presetDefs.push(["Enterprise Plus targets (sized to tenant)", enterprisePlusHours(groupN())]);
  presetDefs.forEach(function (p) { defs.push({ label: p[0], w: keep.w, g: p[1], current: sameHours(p[1]) }); });
  var rows = [];
  try {
    defs.forEach(function (sc) {
      state.recovery.windowDays = sc.w; state.recovery.groupHours = sc.g.slice();
      WORKLOAD_DEFS.forEach(function (wd) { computeScoresAndTiers(wd.key); });
      var m = computeRecoveryModel().milestones["Critical Group 1"];
      if (m && !m.locked) { rows.push({ label: sc.label, current: sc.current, g1Objects: reportMsObjs(m), g1Min: m.wallClockCumMin, share: tenantObjs > 0 ? reportMsObjs(m) / tenantObjs : 0 }); }
    });
  } finally {
    state.recovery.windowDays = keep.w; state.recovery.groupHours = keep.g;
    WORKLOAD_DEFS.forEach(function (wd) { computeScoresAndTiers(wd.key); });
  }
  uiState.scenarios = { sig: sig, rows: rows };
  recomputeAll();
}

function reportSensitivityHtml(model) {
  var head = '<h2>Group 1 Insights</h2>';
  if (IS_PREVIEW || IS_SUMMARY) {
    return head + '<div class="ex2-note">Scenario runs re-sort the whole tenant, which needs the Full assessment. ' + (IS_PREVIEW ? '<a href="' + CONTACT_SALES_URL + '" target="_blank" rel="noopener">Contact your Rubrik representative</a>' : "Open the interactive report to run them.") + '</div>';
  }
  var sc = reportScenarioResult();
  var intro = '<p class="ex2-note">Group 1 is sized to its own Recovery Window (RTO) target, so its online time stays close to the target. What moves is how many objects fit inside it. Each scenario re-sorts the tenant with that setting and leaves your current inputs untouched.</p>';
  if (!sc) {
    return head + intro + '<button type="button" class="ins-toggle-btn active" onclick="runReportScenarios()">Run scenarios</button>';
  }
  var body = sc.rows.map(function (r) {
    return '<tr' + (r.current ? ' class="rep-current"' : '') + '><td>' + esc(r.label) + (r.current ? ' <span class="ex2-badge neutral">current</span>' : '') + '</td><td data-sort="' + r.g1Objects + '">' + fmtNum(r.g1Objects) + '</td><td data-sort="' + Math.round(r.share * 1000) + '">' + (r.share * 100).toFixed(1) + '%</td><td data-sort="' + Math.round(r.g1Min) + '">' + fmtMin(r.g1Min) + '</td></tr>';
  }).join("");
  var out = head + intro + '<div class="table-wrap"><table class="ex2-table"><thead><tr><th>Scenario</th><th>Group 1 objects</th><th>Share of tenant</th><th>Group 1 online in</th></tr></thead><tbody>' + body + '</tbody></table></div>';
  var ins = (typeof getInsightsSummary === "function") ? getInsightsSummary() : null;
  if (ins && ins.headline && ins.excludedCount > 0) {
    out += '<div class="ex2-note">Abnormal objects: Group 1 is <b>' + fmtMin(ins.headline.excludedG1Min) + '</b> with the ' + fmtNum(ins.excludedCount) + ' flagged object' + (ins.excludedCount === 1 ? "" : "s") + ' left out and <b>' + fmtMin(ins.headline.includedG1Min) + '</b> with them included.</div>';
  }
  return out + '<button type="button" class="ins-toggle-btn" onclick="runReportScenarios()">Re-run</button>';
}

function reportDecisionItems(model, g1) {
  var items = [];
  var nG1 = reportMsObjs(g1);
  items.push({ text: 'Confirm the ' + fmtNum(nG1) + ' Group 1 objects with the business owners' + ((IS_PREVIEW || IS_SUMMARY) ? '' : ' and move any that belong elsewhere'), link: "groups:grp-by-group:grp-g1", linkText: (IS_PREVIEW || IS_SUMMARY) ? "See Group 1" : "Review and adjust Group 1" });
  var over = critKeys().map(function (key, i) { return [key, scopeName(i + 1)]; }).filter(function (d) { var m = reportMsOf(model, d[0]); return m && m.exceedsTarget; });
  items.push({ text: over.length ? ('Decide how to close the Recovery Window (RTO) gap: ' + over.map(function (d) { return d[1] + ' is over by ' + fmtMin(reportMsOf(model, d[0]).targetGapMin); }).join("; ")) : 'Confirm the Recovery Window (RTO) targets (' + (groupN() > 4 ? state.recovery.group1Hours + ' ... ' + groupHoursOf(groupN()) : state.recovery.groupHours.slice(0, groupN()).join(' / ')) + ' hr); all are currently met', link: "groups:grp-controls", linkText: "Recovery Window (RTO) targets" });
  var ins = (!IS_PREVIEW && !IS_SUMMARY && typeof getInsightsSummary === "function") ? getInsightsSummary() : null;
  if (ins && ins.total > 0) { items.push({ text: 'Review the ' + fmtNum(ins.total) + ' flagged object' + (ins.total === 1 ? "" : "s") + ' and decide how to handle them', link: "insights:insights-table", linkText: "Recovery Insights" }); }
  if (!(parseFloat(state.recovery.costPerHour) > 0)) { items.push({ text: 'Enter your estimated downtime cost per hour to see potential cost avoidance', link: "report:report-drivers", linkText: "Enter it here" }); }
  var conf = reportConfidence();
  if (conf.level !== "High") { items.push({ text: 'Close the data gaps behind the ' + conf.level.toLowerCase() + ' confidence rating', link: "report:report-data-quality:dq", linkText: "Data quality" }); }
  if (IS_PREVIEW) { items.push({ text: 'Run the Full assessment to see Groups 2-4 and the complete recovery sequence', href: CONTACT_SALES_URL, linkText: "Contact your Rubrik representative" }); }
  return items;
}
function reportDecisionsHtml(model, g1) {
  var lis = reportDecisionItems(model, g1).map(function (d) {
    var l = d.href ? ('<a href="' + d.href + '" target="_blank" rel="noopener">' + d.linkText + '</a>') : exLink(d.link, d.linkText);
    return '<li><span class="rep-check" aria-hidden="true"></span><span>' + d.text + ' ' + l + '</span></li>';
  }).join("");
  return '<h2>Decisions and next steps</h2><ul class="rep-decisions">' + lis + '</ul>';
}

// Recovery calendar (Report tab): the ladder laid over real dates from when the page was opened.
// Long recoveries show month 1, a fading month 2, a gap marker, then the final month fading back in.
function reportCalendarHtml(model) {
  var g1 = reportMsOf(model, "Critical Group 1");
  var M = model.fullRestoreMin;
  if (!(M > 0) || !g1) { return ""; }
  var DAYM = 1440;
  var s0 = new Date(REC_NOW); s0.setHours(0, 0, 0, 0);
  var off = (REC_NOW - s0) / 60000;
  var total = Math.ceil((M + off) / DAYM);
  var big = total <= 31;
  var ends = [], cols = [], prevEnd = 0;
  critKeys().forEach(function (key, i) {
    var m = reportMsOf(model, key);
    prevEnd = Math.max(prevEnd, Math.min(m ? m.wallClockCumMin : prevEnd, M));
    ends.push(prevEnd); cols.push(groupColor(i + 1));
  });
  ends.push(M); cols.push("var(--massc)");
  function grad(d) {
    var a = d * DAYM - off, b = a + DAYM, prev = Math.max(a, 0), stops = [];
    if (b <= 0 || a >= M) { return ""; }
    if (a < 0) { stops.push("var(--inset-cell) 0%", "var(--inset-cell) " + (-a / DAYM * 100).toFixed(1) + "%"); }
    for (var k = 0; k < ends.length; k++) {
      var e = Math.min(ends[k], b);
      if (e > prev) { stops.push(cols[k] + " " + ((prev - a) / DAYM * 100).toFixed(1) + "%", cols[k] + " " + ((e - a) / DAYM * 100).toFixed(1) + "%"); prev = e; }
    }
    if (prev < b) { stops.push("var(--inset-cell) " + ((prev - a) / DAYM * 100).toFixed(1) + "%", "var(--inset-cell) 100%"); }
    return "linear-gradient(90deg," + stops.join(",") + ")";
  }
  function fD(d) { return d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }); }
  var m0 = new Date(s0.getFullYear(), s0.getMonth(), 1), endD = recAt(M);
  var months = Math.min(60, (endD.getFullYear() - m0.getFullYear()) * 12 + endD.getMonth() - m0.getMonth() + 1);
  function monthHtml(mi, cls) {
    var ms = new Date(m0.getFullYear(), m0.getMonth() + mi, 1), dim = new Date(ms.getFullYear(), ms.getMonth() + 1, 0).getDate();
    var lead = (ms.getDay() + 6) % 7;
    var h = '<div class="cal-mon ' + (cls || "") + '"><h4>' + ms.toLocaleDateString(undefined, { month: "long", year: "numeric" }) + '</h4><div class="cal-g">' +
      ["M", "T", "W", "T", "F", "S", "S"].map(function (x) { return '<div class="cal-h">' + x + '</div>'; }).join("");
    for (var i = 0; i < lead; i++) { h += '<div class="cal-cell blank"></div>'; }
    for (var dd = 1; dd <= dim; dd++) {
      var dt = new Date(ms.getFullYear(), ms.getMonth(), dd), idx = Math.round((dt - s0) / 86400000);
      var g = grad(idx), c = "cal-cell" + (g ? " in" : ""), tag = "";
      if (idx === 0) { c += " today"; tag = '<span class="cal-tag">TODAY</span>'; }
      if (idx === total - 1 && g) { c += " done"; tag = '<span class="cal-tag dtag">DONE</span>'; }
      h += '<div class="' + c + '"' + (g ? ' style="background:' + g + '"' : '') + ' title="' + fD(dt) + '">' + dd + tag + '</div>';
    }
    return h + '</div></div>';
  }
  var html = '';
  
  if (months <= 3) { for (var mi = 0; mi < months; mi++) { html += monthHtml(mi, ""); } }
  else {
    html += monthHtml(0, "") + monthHtml(1, "fadeout");
    var hidden = months - 3;
    html += '<div class="cal-gap"><div class="cal-dots">&middot; &middot; &middot;</div><div class="cal-gap-n">' + hidden + ' more month' + (hidden === 1 ? "" : "s") + ' of recovery</div>' +
      '<div>What launches, releases, audits and customer commitments land in these months, and what would it cost if the data behind them is still being restored?</div><div class="cal-dots">&middot; &middot; &middot;</div></div>';
    html += monthHtml(months - 1, "fadein");
  }
  html += '</div><div class="cal-legend">' + critKeys().map(function (key, i) { return '<span><i style="background:' + groupColor(i + 1) + '"></i>' + (i === 0 ? 'Critical users (Group 1)' : tierTitle(i + 1)) + '</span>'; }).join("") + '<span><i style="background:var(--massc)"></i>Mass recovery still running</span></div>' +
    '<div class="cal-ends"><span>Starts <b>' + fD(REC_NOW) + '</b></span><span>Mass recovery finishes <b>' + recDate(M) + '</b> (' + fmtMin(M) + ' from now)</span></div>';
  return '<h2>If recovery started today</h2>' + html;
}

function renderExecSummary() {
  var model = computeRecoveryModel();
  var g1 = reportMsOf(model, "Critical Group 1");
  function put(id, html) { var el = document.getElementById(id); if (el) { el.innerHTML = html; } }
  if (!(model.fullRestoreMin > 0) || !g1) {
    put("report-verdict", '<div class="exec-hero-note">No objects with recent activity were found, so there is no recovery time to report yet.</div>');
    ["report-case", "report-by-group", "report-calendar", "report-drivers", "report-sensitivity", "report-concentration", "report-g1list", "report-rto", "report-risks", "report-decisions"].forEach(function (id) { put(id, ""); });
  } else {
    var ca = computeCostAvoided(model);
    var conc = execConcentration();
    put("report-verdict", reportVerdictHtml(model, g1, ca));
    put("report-case", reportCaseHtml(model, g1, conc));
    put("report-by-group", reportByGroupHtml(model));
    put("report-drivers", reportDriversHtml());
    put("report-sensitivity", reportSensitivityHtml(model));
    var c = { model: model, g1: g1, ca: ca, conc: conc, profile: execGroup1Profile() };
    put("report-concentration", exBlockConcentration(c).replace(' id="exec-concentration"', ""));
    put("report-calendar", reportCalendarHtml(model));
    put("report-g1list", exBlockG1List(c));
    put("report-rto", exBlockRto(c));
    put("report-risks", exBlockRisks());
    put("report-decisions", reportDecisionsHtml(model, g1));
  }
  put("report-low-activity", reportLowActivityHtml(model));
  put("report-data-quality", reportDataQualityHtml());

  // Where the objects sit: per-workload cards (unchanged data, now below the evidence).
  var cardsHtml = "";
  WORKLOAD_DEFS.forEach(function (wd) {
    var ten = execWlTenant(wd.key);
    var total = ten.objectCount;
    var segs = "", legend = "";
    if (IS_PREVIEW) {
      var t1 = execWlTier(wd.key, "Critical Group 1") || { objectCount: 0 };
      var rest = Math.max(0, total - t1.objectCount);
      if (total > 0 && t1.objectCount > 0) { segs += '<span style="width:' + (Math.round((t1.objectCount / total) * 10000) / 100) + '%;background:' + TIER_META["Critical Group 1"].bg + ';"></span>'; }
      legend += '<div><span class="ex2-dot" style="background:' + TIER_META["Critical Group 1"].bg + ';"></span>Group 1: ' + fmtNum(t1.objectCount) + '</div>';
      legend += '<div><span class="ex2-dot" style="background:' + TIER_META["Group 4"].bg + ';"></span>Remaining groups: ' + fmtNum(rest) + '</div>';
    } else {
      TIER_ORDER.forEach(function (t) {
        var x = execWlTier(wd.key, t);
        var count = x ? x.objectCount : 0;
        if (total > 0 && count > 0) { segs += '<span style="width:' + (Math.round((count / total) * 10000) / 100) + '%;background:' + TIER_META[t].bg + ';"></span>'; }
        legend += '<div><span class="ex2-dot" style="background:' + TIER_META[t].bg + ';"></span>' + TIER_META[t].named + ": " + fmtNum(count) + "</div>";
      });
    }
    var stor = wd.storageField ? '<div class="ex2-card-sub">' + fmtStorage(ten.storageBytes) + '</div>' : "";
    cardsHtml += '<div class="summary-card" ' + navAttr("groups:grp-by-workload:wl-" + wd.key) + '>' +
      "<h3>" + esc(wd.label) + '</h3><div class="total">' + fmtNum(total) + '</div>' + stor + '<div class="tier-bar">' + segs + '</div><div class="tier-legend">' + legend + "</div></div>";
  });
  var tenant = execTenantSum();
  var totalLine = '<div class="ex2-note">Whole tenant: <b>' + fmtNum(tenant.objects) + '</b> objects, <b>' + fmtStorage(tenant.bytes) + '</b>.</div>';
  put("report-group-overview", '<h2>Where your objects sit</h2><div class="summary-grid">' + cardsHtml + '</div>' + totalLine);
}

'@

$script:ReportJsRenderTables = @'
// ===================================================================================
// v2.0 object tables + group/workload aggregates (Groups & Recovery Model tab).
//
// One table builder serves both sections of the tab:
//   - "By group"      tables are fixed to one tier and one workload at a time  (tkey like "g1-mailboxes")
//   - "By workload"   tables show one workload with tier filter chips           (tkey = the workload key, e.g. "mailboxes")
// All search / filter / sort / show-all state is per table key (tkey).
// Every column header is sortable. Sorting runs on the FULL filtered set BEFORE the MAX_TABLE_ROWS cap,
// so the cap never hides the real top or bottom rows (data-driven helpers live in ReportJsUi.js).
// Storage is always shown through fmtStorageNum()/storageHeader() (one unit for the whole report).
// ===================================================================================

var TKEY_META = {};   // tkey -> { wdKey, tier|null }
function registerTable(tkey, wdKey, tier) { TKEY_META[tkey] = { wdKey: wdKey, tier: tier || null }; }
function wdByKey(key) { return WORKLOAD_DEFS.filter(function (w) { return w.key === key; })[0]; }
function tierIdOf(tierName) { return tierName === LOW_KEY ? "glow" : (tierNum(tierName) ? "g" + tierNum(tierName) : undefined); }
function tierNameOfId(id) { if (id === "glow") { return LOW_KEY; } var m = /^g(\d+)$/.exec(id || ""); return m ? critKey(parseInt(m[1], 10)) : undefined; }
function canEditTiers() { return !IS_PREVIEW && !IS_SUMMARY; }

function goToWorkload(key) {
  navigateTo("groups:wl-" + key + ":wl-" + key);
}

// ---------- aggregates (rows when present, generation-time aggregates otherwise) ----------
// Returns { objects, items, storageBytes } for one workload in one tier, or null when that data is not in the page
// (Preview: Groups 2-4). Unlike the recovery model's slices this NEVER drops outlier-flagged objects - a group's
// object count is a fact about the tenant; only the headline recovery estimate leaves flagged objects out.
function groupTotals(wlKey, tierName) {
  var wd = wdByKey(wlKey);
  var rec = RECOVERY_FIELDS[wlKey];
  var rows = DATA.workloads[wlKey] || [];
  if (IS_SUMMARY || (rows.length === 0 && DATA.tierAgg)) {
    var a = DATA.tierAgg && DATA.tierAgg[wlKey] && DATA.tierAgg[wlKey][tierName];
    if (!a) { return null; }
    var sb = rec ? (wlKey === "mailboxes" ? (a.storage || 0) * 1048576 : (a.storage || 0)) : 0;
    return { objects: a.objectCount || 0, items: rec ? (a.itemCount || 0) : 0, storageBytes: sb };
  }
  if (IS_PREVIEW && tierName !== "Critical Group 1") { return null; }
  var objects = 0, items = 0, bytes = 0;
  rows.forEach(function (r) {
    if (r.Tier !== tierName) { return; }
    objects++;
    if (rec) { items += parseFloat(r.metrics[rec.item]) || 0; bytes += rowStorageBytes(wlKey, r); }
  });
  return { objects: objects, items: items, storageBytes: bytes };
}
// Sum across the four workloads (items and storage only exist for mailboxes / OneDrive / SharePoint).
function groupTotalsAll(tierName) {
  var out = { objects: 0, items: 0, storageBytes: 0, byWl: {}, complete: true };
  WORKLOAD_DEFS.forEach(function (wd) {
    var t = groupTotals(wd.key, tierName);
    out.byWl[wd.key] = t;
    if (!t) { out.complete = false; return; }
    out.objects += t.objects; out.items += t.items; out.storageBytes += t.storageBytes;
  });
  return out;
}
// Preview: everything that is NOT Group 1 (whole-tenant totals minus Group 1). One lump - never split by group.
function remainderTotals(wlKey) {
  var t = tenantTotalsFor(wlKey);
  var g = groupTotals(wlKey, "Critical Group 1") || { objects: 0, items: 0, storageBytes: 0 };
  var rec = RECOVERY_FIELDS[wlKey];
  var tenantBytes = rec ? (wlKey === "mailboxes" ? t.storage * 1048576 : t.storage) : 0;
  return { objects: Math.max(0, t.objectCount - g.objects), items: rec ? Math.max(0, t.itemCount - g.items) : 0, storageBytes: rec ? Math.max(0, tenantBytes - g.storageBytes) : 0 };
}
function remainderTotalsAll() {
  var out = { objects: 0, items: 0, storageBytes: 0 };
  WORKLOAD_DEFS.forEach(function (wd) { var r = remainderTotals(wd.key); out.objects += r.objects; out.items += r.items; out.storageBytes += r.storageBytes; });
  return out;
}
function teamsObjectCount() {
  var t = DATA.tenantTotals && DATA.tenantTotals.teams;
  return t ? (t.objectCount || 0) : (DATA.workloads.teams || []).length;
}

function distinctValues(rows, field) {
  var set = {};
  rows.forEach(function (r) { var v = r[field]; if (v) { set[v] = true; } });
  return Object.keys(set).sort();
}

// Same idea as distinctValues, but for an ARRAY field (row.Groups) - a row
// can belong to several groups at once, so every value in every row's array
// goes into the set, not just the row's single field value.
function distinctGroupNames(rows) {
  var set = {};
  rows.forEach(function (r) { (r.Groups || []).forEach(function (g) { if (g) { set[g] = true; } }); });
  return Object.keys(set).sort();
}

// Free-text search haystack for a row - every string-ish field we have,
// joined lowercase. Cached on the row (_searchHaystack) since these source
// fields never change during a session (only Tier/IsOverride do, and
// neither is part of the haystack), so it's safe to compute once.
function rowSearchHaystack(row) {
  if (row._searchHaystack) { return row._searchHaystack; }
  var parts = [row.ObjectName, row.Identifier, row.JobTitle, row.Department, row.Manager,
    row.OfficeLocation, row.MailboxTypeHeuristic, row.RecipientType, row.EmployeeType, row.CriteriaTags];
  if (row.ManagerChain && row.ManagerChain.length) { parts = parts.concat(row.ManagerChain); }
  if (row.Groups && row.Groups.length) { parts = parts.concat(row.Groups); }
  row._searchHaystack = parts.filter(Boolean).join(" ").toLowerCase();
  return row._searchHaystack;
}

// tkey identifies the table (see header). A "by group" table is fixed to its tier; a "by workload" table filters by tier chip.
function rowPassesFilters(row, tkey) {
  var meta = TKEY_META[tkey];
  if (meta && meta.tier && row.Tier !== meta.tier) { return false; }
  var f = state.activeFilters[tkey] || {};
  if (f.tier && f.tier !== "all" && row.Tier !== f.tier) { return false; }
  if (f.department && row.Department !== f.department) { return false; }
  if (f.employeeType && row.EmployeeType !== f.employeeType) { return false; }
  if (f.officeLocation && row.OfficeLocation !== f.officeLocation) { return false; }
  if (f.mailboxType && row.MailboxTypeHeuristic !== f.mailboxType) { return false; }
  if (f.hubSite) {
    var isHub = !!row.HubSiteCandidate;
    if ((f.hubSite === "Yes") !== isHub) { return false; }
  }
  if (f.manager && (!row.ManagerChain || row.ManagerChain.indexOf(f.manager) === -1) && row.Manager !== f.manager) { return false; }
  if (f.group && (!row.Groups || row.Groups.indexOf(f.group) === -1)) { return false; }
  if (f.titleContains) {
    var t = (row.JobTitle || "").toLowerCase();
    if (t.indexOf(f.titleContains.toLowerCase()) === -1) { return false; }
  }
  if (f.search && rowSearchHaystack(row).indexOf(f.search.toLowerCase()) === -1) { return false; }
  return true;
}

function storageCellForTotals(wdKey, v) {
  // getTierTotals() returns storage in the workload's own field unit (MB for mailboxes, GB for OneDrive/SharePoint).
  return wdKey === "mailboxes" ? fmtStorageMB(v) : fmtStorageGBVal(v);
}

// Totals for a pre-filtered row subset (the "Filtered View" strip). Preview shows only the Group 1 cell (nothing else exists).
function buildWorkloadTotalsRow(wdKey, rowsOverride, headingLabel) {
  var totals = getTierTotals(wdKey, rowsOverride);
  var wd = wdByKey(wdKey);
  var heading = headingLabel ? ('<div class="totals-heading">' + esc(headingLabel) + "</div>") : "";
  var html = heading + '<div class="totals-grid">';
  (IS_PREVIEW ? ["Critical Group 1"] : TIER_ORDER).forEach(function (t) {
    var tt = totals[t];
    var storageBit = wd.storageField ? (", " + storageCellForTotals(wdKey, tt.storageTotal)) : "";
    var itemBit = wdKey === "teams" ? "" : (fmtNum(tt.itemTotal) + " " + wd.itemLabel.toLowerCase());
    html += '<div class="totals-cell"><div class="label">' + TIER_META[t].named + '</div><div class="value">' + fmtNum(tt.objectCount) + ' objs</div><div class="totals-sub">' + itemBit + storageBit + "</div></div>";
  });
  html += "</div>";
  return html;
}

// ---------- column definitions ----------
function tierBadgeHtml(row) {
  var tierMeta = TIER_META[row.Tier] || TIER_META[TIER_ORDER[TIER_ORDER.length - 1]];
  var overrideBadge = row.IsOverride ? '<span class="badge override" title="' + esc(row.OverrideReason) + '">override</span>' : "";
  return '<span class="badge" style="background:' + tierMeta.bg + ";color:" + tierMeta.fg + ';">' + tierMeta.short + "</span>" + overrideBadge;
}
function flagChipHtml(row) {
  var out = "";
  if (row._flags && row._flags.length) {
    out += ' <span class="flag-chip" ' + navAttr("insights:insights-table") + ' title="Flagged by Recovery Insights: ' + esc(row._flags.join(", ")) + '">Flagged</span>';
  }
  if (isExcludedRow(row)) { out += ' <span class="flag-chip excluded" title="Left out of the headline recovery estimates (see Recovery Insights)">Excluded from estimates</span>'; }
  return out;
}
function objColumns(wdKey, hasEnrichment, hasMailboxType, hasGroups) {
  var wd = wdByKey(wdKey);
  var edit = canEditTiers();
  var itemsLabel = wdKey === "teams" ? "Users with recent activity" : wd.itemLabel;
  var cols = [
    { key: "name", label: "Object", type: "text", get: function (r) { return r.ObjectName || ""; }, cell: function (r) { return "<td>" + esc(r.ObjectName) + flagChipHtml(r) + "</td>"; } },
    { key: "id", label: "Identifier", type: "text", get: function (r) { return r.Identifier || ""; }, cell: function (r) { return "<td>" + esc(r.Identifier) + "</td>"; } },
    { key: "tier", label: "Tier", type: "text", get: function (r) { return r.Tier || ""; }, cell: function (r) {
        var options = TIER_ORDER.map(function (t) { return '<option value="' + t + '"' + (r.Tier === t ? " selected" : "") + ">" + TIER_META[t].named + "</option>"; }).join("");
        var sel = edit ? '<br><select class="tier-select" onchange="onTierDropdownChange(\'' + wdKey + "','" + String(r.Identifier).replace(/\\/g, "\\\\").replace(/'/g, "\\'") + '\',this.value)">' + options + "</select>" : "";
        return "<td>" + tierBadgeHtml(r) + sel + "</td>";
      } },
    { key: "score", label: "Score", type: "num", get: function (r) { return r._Score || 0; }, cell: function (r) {
        var pct = Math.round((r._Score || 0) * 100);
        return '<td data-sort="' + pct + '"><div class="score-bar-wrap"><div class="score-bar"><span style="width:' + pct + '%;"></span></div>' + pct + "%</div></td>";
      } },
    { key: "why", label: "Why", type: "text", cls: "col-detail", get: function (r) { return r.CriteriaTags || ""; }, cell: function (r) { return '<td class="criteria-tags col-detail">' + esc(r.CriteriaTags) + "</td>"; } },
    { key: "last", label: "Last Activity", type: "text", get: function (r) { return r.LastActivityDate || ""; }, cell: function (r) { return "<td>" + esc(r.LastActivityDate) + "</td>"; } },
    { key: "items", label: itemsLabel, type: "num", get: function (r) { return parseFloat(r.metrics[wd.itemField]) || 0; }, cell: function (r) { return "<td>" + fmtNum(r.metrics[wd.itemField]) + "</td>"; } }
  ];
  if (wd.storageField) {
    cols.push({ key: "storage", label: storageHeader("Storage"), type: "num", get: function (r) { return rowStorageBytes(wdKey, r); }, cell: function (r) { return "<td>" + fmtStorageNum(rowStorageBytes(wdKey, r)) + "</td>"; } });
  }
  if (hasEnrichment) {
    cols.push({ key: "title", label: "Job Title", type: "text", cls: "col-detail", get: function (r) { return r.JobTitle || ""; }, cell: function (r) { return '<td class="col-detail">' + esc(r.JobTitle) + "</td>"; } });
    cols.push({ key: "dept", label: "Department", type: "text", cls: "col-detail", get: function (r) { return r.Department || ""; }, cell: function (r) { return '<td class="col-detail">' + esc(r.Department) + "</td>"; } });
    cols.push({ key: "mgr", label: "Manager", type: "text", cls: "col-detail", get: function (r) { return r.Manager || ""; }, cell: function (r) { return '<td class="col-detail">' + esc(r.Manager) + "</td>"; } });
  }
  if (hasGroups) {
    cols.push({ key: "groups", label: "Entra ID Groups", type: "text", cls: "col-detail", get: function (r) { return (r.Groups || []).join(", "); }, cell: function (r) { return '<td class="col-detail">' + esc((r.Groups || []).join(", ")) + "</td>"; } });
  }
  if (hasMailboxType) {
    cols.push({ key: "mbtype", label: "Mailbox Type", type: "text", cls: "col-detail", get: function (r) { return r.MailboxTypeHeuristic || ""; }, cell: function (r) { return '<td class="col-detail">' + esc(r.MailboxTypeHeuristic) + "</td>"; } });
  }
  return cols;
}

// ---------- the object table ----------
// Builds the container for one table. Everything inside #otbl-<tkey> is re-rendered by rerenderObjTable(tkey).
function buildObjectTable(tkey, wdKey, tierName) {
  registerTable(tkey, wdKey, tierName);
  SORT_RERENDER["obj-" + tkey] = function () { rerenderObjTable(tkey); };
  if (typeof queueScrollAttach === "function") { queueScrollAttach(tkey); }
  return '<div class="obj-table" id="otbl-' + tkey + '">' + buildObjectTableInner(tkey) + "</div>";
}

function buildObjectTableInner(tkey) {
  var meta = TKEY_META[tkey];
  var wdKey = meta.wdKey, fixedTier = meta.tier;
  var wd = wdByKey(wdKey);
  var allRows = DATA.workloads[wdKey] || [];
  var scopeRows = fixedTier ? allRows.filter(function (r) { return r.Tier === fixedTier; }) : allRows;
  var hasEnrichment = allRows.some(function (r) { return !!r.JobTitle || !!r.Department; });
  var hasMailboxType = wdKey === "mailboxes" && allRows.some(function (r) { return !!r.MailboxTypeHeuristic; });
  var hasGroups = allRows.some(function (r) { return r.Groups && r.Groups.length; });
  var edit = canEditTiers();

  var f = state.activeFilters[tkey] || (state.activeFilters[tkey] = {});
  var chips = "";
  if (!fixedTier) {
    (IS_PREVIEW ? ["all", "Critical Group 1"] : ["all"].concat(TIER_ORDER)).forEach(function (t) {
      var count = t === "all" ? scopeRows.length : scopeRows.filter(function (r) { return r.Tier === t; }).length;
      var label = t === "all" ? (IS_PREVIEW ? "Group 1" : "All") : TIER_META[t].named;
      var activeClass = ((f.tier || "all") === t) ? " active" : "";
      chips += '<button class="chip' + activeClass + '" onclick="setFilter(\'' + tkey + '\',\'tier\',\'' + t + '\')">' + label + " (" + fmtNum(count) + ")</button>";
    });
  }

  var searchBox = '<input type="text" class="search-box" id="search-' + tkey + '" placeholder="Search ' + esc(wd.label.toLowerCase()) + ' - name, title, department, manager, criteria..." value="' + esc(f.search || "") + '" oninput="onSearchInput(\'' + tkey + '\',this.value)" aria-label="Search ' + esc(wd.label) + '">';

  var attrFilters = "";
  if (hasEnrichment) {
    attrFilters += buildSelectFilter(tkey, "department", "Department", distinctValues(scopeRows, "Department"));
    attrFilters += buildSelectFilter(tkey, "employeeType", "Employee Type", distinctValues(scopeRows, "EmployeeType"));
    attrFilters += buildSelectFilter(tkey, "officeLocation", "Office Location", distinctValues(scopeRows, "OfficeLocation"));
    attrFilters += '<input type="text" class="attr-input" id="titlefilter-' + tkey + '" placeholder="Title contains..." value="' + esc(f.titleContains || "") + '" oninput="setFilter(\'' + tkey + '\',\'titleContains\',this.value)">';
    attrFilters += '<input type="text" class="attr-input" id="managerfilter-' + tkey + '" placeholder="Manager display name..." value="' + esc(f.manager || "") + '" oninput="setFilter(\'' + tkey + '\',\'manager\',this.value)">';
  }
  if (hasMailboxType) { attrFilters += buildSelectFilter(tkey, "mailboxType", "Mailbox Type", distinctValues(scopeRows, "MailboxTypeHeuristic")); }
  if (wdKey === "sharepoint") { attrFilters += buildSelectFilter(tkey, "hubSite", "Hub Site", ["Yes", "No"]); }
  if (hasGroups) { attrFilters += buildSelectFilter(tkey, "group", "Entra ID Group", distinctGroupNames(scopeRows)); }

  var visibleRows = scopeRows.filter(function (r) { return rowPassesFilters(r, tkey); });
  var isFiltered = visibleRows.length !== scopeRows.length;
  var filteredTotalsHtml = (isFiltered && !fixedTier && !IS_SUMMARY)
    ? buildWorkloadTotalsRow(wdKey, visibleRows, "Filtered View (" + fmtNum(visibleRows.length) + " of " + fmtNum(scopeRows.length) + " shown)")
    : "";

  var cols = objColumns(wdKey, hasEnrichment, hasMailboxType, hasGroups);
  var sortedVisible = applySort(visibleRows, "obj-" + tkey, cols, "score", "desc");
  var showAll = !!state.showAllRows[tkey];
  var renderedRows = showAll ? sortedVisible : sortedVisible.slice(0, MAX_TABLE_ROWS);
  var isCapped = !showAll && sortedVisible.length > MAX_TABLE_ROWS;
  var bodyRows = renderedRows.map(function (row) { return "<tr>" + cols.map(function (c) { return c.cell(row); }).join("") + "</tr>"; }).join("");
  if (!bodyRows) { bodyRows = '<tr class="no-sort-row"><td colspan="' + cols.length + '" class="empty-cell">No rows match the current filters.</td></tr>'; }
  var s = getSort("obj-" + tkey, "score", "desc");
  var sortNote = (s.col === "score" && s.dir === "desc") ? "sorted by score" : "sorted by your selected column";
  var capNoticeHtml = isCapped
    ? '<div class="table-cap-notice">Showing the first ' + fmtNum(MAX_TABLE_ROWS) + ' of ' + fmtNum(sortedVisible.length) + ' rows (' + sortNote + ') - search or filter above to narrow, or <button onclick="setShowAllRows(\'' + tkey + '\')">show all ' + fmtNum(sortedVisible.length) + ' rows</button> (can be slow for a large tenant).</div>'
    : (showAll && sortedVisible.length > MAX_TABLE_ROWS
      ? '<div class="table-cap-notice">Showing all ' + fmtNum(sortedVisible.length) + ' rows. <button onclick="setShowAllRows(\'' + tkey + '\', true)">Back to the first ' + fmtNum(MAX_TABLE_ROWS) + '</button></div>'
      : "");

  var showDetail = state.columnPrefs[tkey] !== false;
  var detailColLabels = ["Why / criteria tags"];
  if (hasEnrichment) { detailColLabels.push("Job Title", "Department", "Manager"); }
  if (hasGroups) { detailColLabels.push("Entra ID Groups"); }
  if (hasMailboxType) { detailColLabels.push("Mailbox Type"); }
  var toolbar = '<div class="table-toolbar">' +
    '<label class="col-toggle"><input type="checkbox" id="coltoggle-' + tkey + '"' + (showDetail ? " checked" : "") + ' onchange="onColumnToggleChange(\'' + tkey + '\',this.checked)"> Show detail columns <span class="col-toggle-hint">(' + detailColLabels.join(", ") + ')</span></label>' +
    '<span class="scroll-hint" id="scrollhint-' + tkey + '">&#9664; scroll for more &#9654;</span>' +
    "</div>";

  var massBar = edit
    ? '<div class="mass-edit-bar" id="mass-edit-bar-' + tkey + '">' +
        '<span class="mass-edit-label">Mass-reassign all <b>' + fmtNum(visibleRows.length) + '</b> currently-filtered rows to:</span>' +
        '<select id="mass-tier-' + tkey + '">' + TIER_ORDER.map(function (t) { return '<option value="' + t + '">' + TIER_META[t].named + '</option>'; }).join("") + '</select>' +
        '<button onclick="massReassign(\'' + tkey + '\')">Apply</button></div>'
    : "";

  var headCount = isFiltered ? (fmtNum(visibleRows.length) + " of " + fmtNum(scopeRows.length) + " shown") : (fmtNum(scopeRows.length) + " objects");
  var theadHtml = "<tr>" + cols.map(function (c) { return sortThHtml("obj-" + tkey, c, "score", "desc"); }).join("") + "</tr>";

  return '<div class="obj-count">' + esc(wd.label) + (fixedTier ? " in " + TIER_META[fixedTier].named : "") + ' <span class="obj-count-n">(' + headCount + ")</span></div>" +
    '<div class="search-box-row">' + searchBox + "</div>" +
    (chips ? '<div class="filter-chips">' + chips + "</div>" : "") +
    (attrFilters ? '<div class="filter-chips" id="attr-filters-' + tkey + '">' + attrFilters + "</div>" : "") +
    filteredTotalsHtml + massBar + toolbar +
    '<div class="table-scroll-shell" id="shell-' + tkey + '">' +
      '<div class="table-wrap' + (showDetail ? "" : " essentials-only") + '" id="tbl-wrap-' + tkey + '"><table id="tbl-' + tkey + '" data-datasort="1"><thead>' + theadHtml + "</thead><tbody>" + bodyRows + "</tbody></table></div>" +
      '<div class="scroll-fade-right" aria-hidden="true"></div>' +
    "</div>" + capNoticeHtml;
}

function buildSelectFilter(tkey, field, label, values) {
  // Reads the currently active value for this field so the dropdown shows the right selection after a re-render.
  var current = (state.activeFilters[tkey] || {})[field] || "";
  var opts = '<option value=""' + (current === "" ? " selected" : "") + '>' + label + ": All</option>";
  values.forEach(function (v) { opts += '<option value="' + esc(v) + '"' + (current === v ? " selected" : "") + ">" + esc(v) + "</option>"; });
  return '<select aria-label="' + esc(label) + '" onchange="setFilter(\'' + tkey + "','" + field + '\',this.value)">' + opts + "</select>";
}

function setFilter(tkey, field, value) {
  var f = state.activeFilters[tkey] || (state.activeFilters[tkey] = {});
  f[field] = value;
  rerenderObjTable(tkey);
}

// See MAX_TABLE_ROWS (Engine). reset=true flips back to the fast, capped view; omitted/false renders every row passing filters.
function setShowAllRows(tkey, reset) {
  state.showAllRows[tkey] = !reset;
  rerenderObjTable(tkey);
}

// Debounces the live search box so a fast typist on a large tenant doesn't trigger a full filter+sort+render on every keystroke.
var SEARCH_DEBOUNCE_MS = 250;
var searchDebounceTimers = {};
function onSearchInput(tkey, value) {
  clearTimeout(searchDebounceTimers[tkey]);
  searchDebounceTimers[tkey] = setTimeout(function () { setFilter(tkey, "search", value); }, SEARCH_DEBOUNCE_MS);
}

function onTierDropdownChange(wdKey, identifier, newTier) {
  if (!canEditTiers()) { return; }
  setOverride(wdKey, identifier, newTier, "Manual (dropdown)");
  recomputeAll();
}

function massReassign(tkey) {
  if (!canEditTiers()) { return; }
  var meta = TKEY_META[tkey];
  var sel = document.getElementById("mass-tier-" + tkey);
  var tier = sel.value;
  var rows = (DATA.workloads[meta.wdKey] || []).filter(function (r) { return rowPassesFilters(r, tkey); });
  rows.forEach(function (r) { setOverride(meta.wdKey, r.Identifier, tier, "Mass reassignment via filter"); });
  recomputeAll();
}

function rerenderObjTable(tkey) {
  // Search/title boxes filter live on every keystroke, which rebuilds the table's HTML each time. Capture the focused
  // element (if inside this table) and restore focus + cursor position by id afterwards, or typing would be interrupted.
  var el = document.getElementById("otbl-" + tkey);
  if (!el) { return; }
  var active = document.activeElement;
  var restoreId = null, restoreStart = null, restoreEnd = null;
  if (active && active.id && el.contains(active)) {
    restoreId = active.id;
    if (typeof active.selectionStart === "number") { restoreStart = active.selectionStart; restoreEnd = active.selectionEnd; }
  }
  el.innerHTML = buildObjectTableInner(tkey);
  attachScrollAffordance(tkey);
  if (restoreId) {
    var restored = document.getElementById(restoreId);
    if (restored) {
      restored.focus();
      if (restoreStart !== null && typeof restored.setSelectionRange === "function") {
        try { restored.setSelectionRange(restoreStart, restoreEnd); } catch (e) {}
      }
    }
  }
}

// Column-visibility toggle + scroll affordances.
function onColumnToggleChange(tkey, checked) {
  state.columnPrefs[tkey] = checked;
  saveColumnPrefsToStorage();
  var wrap = document.getElementById("tbl-wrap-" + tkey);
  if (wrap) { wrap.classList.toggle("essentials-only", !checked); }
  refreshScrollAffordance(tkey);
}

// key is a table key OR a workload key (Bootstrap's resize handler passes workload keys): refresh every table of that workload.
function refreshScrollAffordance(key) {
  var keys = [];
  if (TKEY_META[key]) { keys.push(key); }
  Object.keys(TKEY_META).forEach(function (k) { if (TKEY_META[k].wdKey === key && keys.indexOf(k) === -1) { keys.push(k); } });
  keys.forEach(function (tkey) {
    var wrap = document.getElementById("tbl-wrap-" + tkey);
    var shell = document.getElementById("shell-" + tkey);
    var hint = document.getElementById("scrollhint-" + tkey);
    if (!wrap || !shell) { return; }
    var hasOverflow = wrap.scrollWidth > wrap.clientWidth + 2;
    var atRightEdge = (wrap.scrollLeft + wrap.clientWidth) >= (wrap.scrollWidth - 2);
    shell.classList.toggle("has-more-right", hasOverflow && !atRightEdge);
    if (hint) { hint.style.display = hasOverflow ? "" : "none"; }
  });
}

function attachScrollAffordance(tkey) {
  var wrap = document.getElementById("tbl-wrap-" + tkey);
  var hint = document.getElementById("scrollhint-" + tkey);
  if (!wrap) { return; }
  wrap.addEventListener("scroll", function () {
    if (hint && wrap.scrollLeft > 4) { hint.classList.add("scrolled"); }
    refreshScrollAffordance(tkey);
  });
  refreshScrollAffordance(tkey);
}

// ---------- Group 1, every workload in one list (the "confirm your Group 1" list) ----------
function g1AllCols() {
  return [
    { key: "wl", label: "Workload", type: "text", get: function (c) { return c.workload; } },
    { key: "name", label: "Object", type: "text", get: function (c) { return c.objectName; } },
    { key: "id", label: "Identifier", type: "text", get: function (c) { return c.identifier; } },
    { key: "score", label: "Score", type: "num", get: function (c) { return c.score; } },
    { key: "why", label: "Why", type: "text", get: function (c) { return c.tags; } },
    { key: "last", label: "Last Activity", type: "text", get: function (c) { return c.lastActivity; } },
    { key: "items", label: "Items / files", type: "num", get: function (c) { return c.items; } },
    { key: "storage", label: storageHeader("Storage"), type: "num", get: function (c) { return c.storageBytes; } }
  ];
}
function buildGroup1AllInner() {
  var combined = [];
  WORKLOAD_DEFS.forEach(function (wd) {
    (DATA.workloads[wd.key] || []).filter(function (r) { return r.Tier === "Critical Group 1"; }).forEach(function (r) {
      combined.push({ workload: wd.label, objectName: r.ObjectName, identifier: r.Identifier, score: r._Score || 0, lastActivity: r.LastActivityDate || "", tags: r.CriteriaTags || "", flagged: !!(r._flags && r._flags.length), items: wd.storageField ? (parseFloat(r.metrics[wd.itemField]) || 0) : null, storageBytes: wd.storageField ? rowStorageBytes(wd.key, r) : null });
    });
  });
  var cols = g1AllCols();
  var sorted = applySort(combined, "g1all", cols, "score", "desc");
  var showAll = !!state.group1ShowAll;
  var rendered = showAll ? sorted : sorted.slice(0, MAX_TABLE_ROWS);
  var capped = !showAll && sorted.length > MAX_TABLE_ROWS;
  var rows = rendered.map(function (c) {
    return "<tr><td>" + esc(c.workload) + "</td><td>" + esc(c.objectName) + (c.flagged ? ' <span class="flag-chip" ' + navAttr("insights:insights-table") + '>Flagged</span>' : "") + "</td><td>" + esc(c.identifier) + '</td><td data-sort="' + Math.round(c.score * 100) + '">' + Math.round(c.score * 100) + '%</td><td class="criteria-tags">' + esc(c.tags) + "</td><td>" + esc(c.lastActivity) + "</td><td>" + (c.items === null ? "&mdash;" : fmtNum(c.items)) + "</td><td>" + (c.storageBytes === null ? "&mdash;" : fmtStorageNum(c.storageBytes)) + "</td></tr>";
  }).join("") || '<tr class="no-sort-row"><td colspan="8" class="empty-cell">No Critical Group 1 objects.</td></tr>';
  var cap = capped
    ? '<div class="table-cap-notice">Showing the first ' + fmtNum(MAX_TABLE_ROWS) + ' of ' + fmtNum(sorted.length) + ' rows - <button onclick="setGroup1ShowAll()">show all ' + fmtNum(sorted.length) + ' rows</button> (can be slow for a large tenant).</div>'
    : (showAll && sorted.length > MAX_TABLE_ROWS ? '<div class="table-cap-notice">Showing all ' + fmtNum(sorted.length) + ' rows. <button onclick="setGroup1ShowAll(true)">Back to the first ' + fmtNum(MAX_TABLE_ROWS) + '</button></div>' : "");
  return '<h4 class="g1all-title">Every Critical Group 1 object, all workloads <span class="obj-count-n">(' + fmtNum(combined.length) + ')</span></h4>' +
    '<p class="pill-note">The full recover-first list in one place' + (IS_PREVIEW ? "." : ". Recomputes live with the scoring controls.") + '</p>' +
    '<div class="table-wrap"><table data-datasort="1"><thead><tr>' + cols.map(function (c) { return sortThHtml("g1all", c, "score", "desc"); }).join("") + "</tr></thead><tbody>" + rows + "</tbody></table></div>" + cap;
}
function buildGroup1All() {
  SORT_RERENDER["g1all"] = rerenderGroup1All;
  return '<section class="g1all" id="group1-overview"><div id="g1all-inner">' + buildGroup1AllInner() + "</div></section>";
}
function rerenderGroup1All() {
  var el = document.getElementById("g1all-inner");
  if (el) { el.innerHTML = buildGroup1AllInner(); }
}
function setGroup1ShowAll(reset) {
  state.group1ShowAll = !reset;
  rerenderGroup1All();
}

'@

#endregion

#region ---------- HTML report JS: rendering (controls, groups tab, inactive tab) ----------

$script:ReportJsRenderB = @'
// NEW: weights are now shown/edited as a 0-100% share (was a raw 0-1
// decimal, which read as an arbitrary number with no obvious scale). Each
// workload's own metrics still sum to 100 internally exactly as before -
// this only changes the display/input scale and adds a live total/remaining
// readout so it's obvious when a workload isn't (yet) at 100%. Storage in
// state.weights stays a 0-1 fraction throughout (percent / 100), so nothing
// downstream (computeScoresAndTiers, the Methodology tab's weights table,
// the PDF exports) needs to change - only the slider markup and its handler.
// Editable keyword -> weight table backing the Title-weight bonus above.
// Replaces the old command-line-only -TitleWeights hashtable with a live
// UI: add/rename/reweight/remove rows, recomputes instantly. Matching stays
// case-insensitive substring against JobTitle (see computeTitleWeight) - a
// single keyword like "Chief" already catches "Chief Operating Officer,"
// "Chief People Officer," etc. without any wildcard syntax; acronyms (COO,
// CPO, VP...) still need their own row since one can't be derived from the
// other. Pre-populated with Rubrik's default seniority list (kept
// intentionally, unlike the blank-by-default hub-site keywords - title/
// seniority as a criticality signal is a defensible universal default in a
// way "which SharePoint site names matter" isn't).
function buildTitleWeightTableHtml() {
  var rows = state.titleWeightRows.map(function (r, idx) {
    return '<div class="tw-row">' +
      '<input type="text" value="' + esc(r.keyword) + '" onchange="onTitleWeightKeywordChange(' + idx + ',this.value)">' +
      '<input type="number" min="0" max="1" step="0.05" value="' + r.weight + '" onchange="onTitleWeightWeightChange(' + idx + ',this.value)">' +
      '<button type="button" class="tw-rm" onclick="removeTitleWeightRow(' + idx + ')" title="Remove">&times;</button>' +
      "</div>";
  }).join("");
  var tableHtml = '<div class="tw-table"><div class="tw-head"><span>Title keyword</span><span>Weight</span><span></span></div>' + rows +
    '<div class="tw-add-row"><button type="button" onclick="addTitleWeightRow()">+ Add keyword</button></div></div>' +
    '<div class="tw-note">Matches are a case-insensitive substring against Job Title, so "Chief" alone already catches every "Chief &hellip; Officer" variant - list acronyms (COO, CPO&hellip;) as their own row since they can\'t be derived automatically. Highest-weight match wins per person.</div>';
  // Collapsed by default - a 24-row default keyword table dominated this
  // panel visually. Same rt-toggle/rt-detail pattern already used for the
  // Recovery tab's "+ Workload breakdown" - state.titleWeightTableExpanded
  // persists the open/closed state across full recomputes (e.g. editing a
  // row inside triggers recomputeAll(), which would otherwise silently
  // re-collapse this every time).
  var isOpen = !!state.titleWeightTableExpanded;
  var toggleLabel = (isOpen ? "&minus; Hide" : "+ Show") + " title keywords (" + state.titleWeightRows.length + ")";
  return '<div class="rt-toggle" onclick="toggleTitleWeightTable()">' + toggleLabel + "</div>" +
    '<div class="rt-detail' + (isOpen ? " open" : "") + '" id="tw-detail">' + tableHtml + "</div>";
}

function toggleTitleWeightTable() {
  state.titleWeightTableExpanded = !state.titleWeightTableExpanded;
  var el = document.getElementById("tw-detail");
  if (el) { el.classList.toggle("open", state.titleWeightTableExpanded); }
  var toggle = el ? el.previousElementSibling : null;
  if (toggle) { toggle.innerHTML = (state.titleWeightTableExpanded ? "&minus; Hide" : "+ Show") + " title keywords (" + state.titleWeightRows.length + ")"; }
}

function buildControlsSliders() {
  var html = '<div class="controls-panel" id="scoring-panel"><h4 class="panel-title">' + (canEditTiers() ? "Live scoring controls" : "Scoring controls") + '</h4>' +
    '<p class="panel-sub">Each workload\'s metrics are weighted as a share of <b>100%</b> - adjust one and everything below recomputes instantly. Title-weight and hub-site bonus further down are separate <b>bonus points added on top</b>, capped so no single factor can dominate a score.</p>';
  WORKLOAD_DEFS.filter(function (w) { return w.spExOd !== null || w.key === "teams"; }).forEach(function (wd) {
    var weights = state.weights[wd.key] || {};
    html += '<div class="wd-block"><div class="wd-head"><b>' + esc(wd.label) + '</b><span class="wd-total" id="wtotal-' + wd.key + '"></span></div>';
    Object.keys(weights).forEach(function (field) {
      var pct = Math.round(weights[field] * 100);
      html += '<div class="control-row"><label>' + (FRIENDLY[field] || field) + '</label>' +
        '<input type="range" id="wslider-' + wd.key + '-' + field + '" min="0" max="100" step="5" value="' + pct + '" data-wd="' + wd.key + '" data-field="' + field + '" oninput="onWeightSlide(this)">' +
        '<span class="valdisp" id="wval-' + wd.key + '-' + field + '">' + pct + '%</span></div>';
    });
    html += '<div class="remaining-hint" id="wremain-' + wd.key + '"></div></div>';
  });
  html += '<div class="bonus-section"><div class="bonus-label-row"><b class="bonus-title">Bonus modifiers</b><span class="bonus-tag">Additive, not part of the 100%</span></div>' +
    '<p class="bonus-hint">Layered on top of a workload\'s score above. Capped so an object can\'t exceed a perfect score from bonuses alone.</p>';
  var twPct = Math.round(state.titleWeightContribution * 100);
  var hsPct = Math.round(state.hubSiteBonus * 100);
  html += '<div class="control-row"><label>Title-weight bonus</label><input type="range" id="wslider-_bonus-titleWeight" min="0" max="100" step="5" value="' + twPct + '" data-wd="_bonus" data-field="titleWeight" oninput="onWeightSlide(this)"><span class="valdisp" id="wval-_bonus-titleWeight">' + twPct + '%</span></div>';
  html += buildTitleWeightTableHtml();
  html += '<div class="control-row"><label>Hub-site bonus</label><input type="range" id="wslider-_bonus-hubSite" min="0" max="100" step="5" value="' + hsPct + '" data-wd="_bonus" data-field="hubSite" oninput="onWeightSlide(this)"><span class="valdisp" id="wval-_bonus-hubSite">' + hsPct + '%</span></div>';
  html += "</div>";
  html += '<div class="control-row" style="margin-top:.9rem;"><label>Hub-site keywords</label><input type="text" style="flex:1;max-width:400px;" placeholder="e.g. Payroll, HR, Finance, IT Help Desk (blank = no hub-site matching)" value="' + esc(state.hubSiteKeywords.join(", ")) + '" onchange="onHubKeywordsChange(this.value)"></div>';
  html += "</div>";
  return html;
}
// NOTE: "Filter to org under manager" and "Filter to Entra ID group" used to
// live here as global controls, but they're row filters like Department/
// Title/Mailbox Type - they belong in each workload's own filter bar next to
// the mass-reassign action, not in the scoring-weights panel. Moved into
// buildWorkloadSection() (see the hasEnrichment/hasGroups blocks) so
// "filter down to this manager or group, then mass-reassign the filtered set"
// is one continuous motion instead of two separate panels. rowPassesFilters
// already read f.manager/f.group generically, so this was a pure UI move -
// no filtering-logic change.

// Keeps a workload's weights from ever summing past 100%, WITHOUT ever
// touching a slider other than the one the user is actively dragging (a
// dynamically-shrunk `max` on a SIBLING slider visibly slides its handle
// even when its value doesn't change, since a native range input draws its
// handle at value/max - that's what makes cross-slider constraints look
// like "everything moves"). Instead, only the dragged slider's own value is
// clamped down to whatever room the OTHER (untouched) fields' current
// values leave - so it simply stops at the 100% ceiling; nothing else reacts
// until you lower a sibling yourself.
function onWeightSlide(el) {
  var wdKey = el.getAttribute("data-wd"), field = el.getAttribute("data-field"), rawPct = parseInt(el.value, 10);
  if (wdKey === "_bonus") {
    var frac = rawPct / 100;
    if (field === "titleWeight") { state.titleWeightContribution = frac; } else { state.hubSiteBonus = frac; }
    document.getElementById("wval-_bonus-" + field).textContent = rawPct + "%";
  } else {
    var weights = state.weights[wdKey];
    var otherSumPct = 0;
    Object.keys(weights).forEach(function (f) { if (f !== field) { otherSumPct += Math.round(weights[f] * 100); } });
    var pct = Math.min(rawPct, Math.max(0, 100 - otherSumPct));
    weights[field] = pct / 100;
    if (pct !== rawPct) { el.value = pct; }
    document.getElementById("wval-" + wdKey + "-" + field).textContent = pct + "%";
    refreshWeightTotal(wdKey);
  }
  // CHANGED: used to call recomputeTiersLive() here, on every single oninput
  // tick - dragging a slider fires this dozens of times a second, and
  // recomputeTiersLive() rebuilds full HTML tables across all four workloads
  // (thousands of rows on a live tenant), which is what made dragging feel
  // slow. Now a drag only ever touches this slider's own value/label/total -
  // genuinely cheap - and marks the output areas (Live Impact Preview + the
  // group tables below) as stale. The actual recompute happens once, on
  // demand, when Recalculate is clicked (see recalculateImpact()).
  markWeightsDirty();
}

// Greys out the Live Impact Preview body and the group tables below (both
// are now out of sync with the sliders) and arms the Recalculate button -
// touches only a handful of existing DOM nodes, never rebuilds any HTML, so
// this is safe to call on every keystroke/drag tick.
function markWeightsDirty() {
  var btn = document.getElementById("recalc-btn");
  if (btn) { btn.disabled = false; btn.classList.add("pending"); }
  var note = document.getElementById("stale-note");
  if (note) { note.style.display = "block"; }
  var body = document.getElementById("impact-preview-body");
  if (body) { body.classList.add("is-stale"); }
  var groupsBody = document.getElementById("groups-body-wrap");
  if (groupsBody) { groupsBody.classList.add("is-stale"); }
}

// The Recalculate button's handler - the one place the expensive full
// recompute (scores, tiers, group tables, impact preview, recovery/
// methodology/compare tabs) actually runs. refreshImpactPreview() below
// rebuilds #impact-preview-wrap from scratch, which naturally puts the
// button/stale-note back in their default (not dirty) state - no extra
// cleanup needed there. #groups-body-wrap keeps its own DOM node across a
// refresh (only its innerHTML is replaced), so refreshGroupsBody() clears
// its "is-stale" class explicitly.
function recalculateImpact() {
  recomputeTiersLive();
}

function refreshWeightTotal(wdKey) {
  var weights = state.weights[wdKey];
  var sum = 0;
  Object.keys(weights).forEach(function (f) { sum += Math.round(weights[f] * 100); });
  var totalEl = document.getElementById("wtotal-" + wdKey);
  if (totalEl) { totalEl.textContent = "= " + sum + "%"; totalEl.className = "wd-total " + (sum === 100 ? "ok" : "warn"); }
  var remainEl = document.getElementById("wremain-" + wdKey);
  if (remainEl) {
    var left = 100 - sum;
    remainEl.textContent = left > 0 ? (left + "% left to allocate") : "Fully allocated";
    remainEl.className = "remaining-hint" + (left > 0 ? " has-room" : "");
  }
}
function refreshAllWeightTotals() {
  WORKLOAD_DEFS.filter(function (w) { return w.spExOd !== null || w.key === "teams"; }).forEach(function (wd) { refreshWeightTotal(wd.key); });
}

// NEW: Live Impact Preview - group-first breakdown by workload, with +N/-N
// showing objects that moved in/out of that group for that workload since
// the last recompute. A tier's SIZE never changes from a weight adjustment
// alone (Group 1/2/3 are always the top/middle/bottom third of the active
// population BY COUNT), so movedIn/movedOut for a given tier are generally
// equal - that's expected (group size is conserved), and still shows real
// churn that a net count delta would hide entirely (it would always read
// +0). lastTierByWorkload starts empty, so the very first render naturally
// shows no chips (nothing to compare against yet) with no extra flag needed.
var lastTierByWorkload = {};

function computeImpactData() {
  var totalChanged = 0;
  var wdData = {};
  WORKLOAD_DEFS.forEach(function (wd) {
    var rows = DATA.workloads[wd.key] || [];
    var newTiers = rows.map(function (r) { return r.Tier; });
    var prevTiers = lastTierByWorkload[wd.key];
    var churn = null;
    if (prevTiers) {
      churn = {};
      TIER_ORDER.forEach(function (t) { churn[t] = { "in": 0, "out": 0 }; });
      newTiers.forEach(function (t, i) {
        var prevT = prevTiers[i];
        if (prevT !== t) {
          churn[t]["in"]++;
          if (churn[prevT]) { churn[prevT]["out"]++; }
          totalChanged++;
        }
      });
    }
    lastTierByWorkload[wd.key] = newTiers;
    var counts = {};
    TIER_ORDER.forEach(function (t) { counts[t] = 0; });
    newTiers.forEach(function (t) { if (counts[t] !== undefined) { counts[t]++; } });
    wdData[wd.key] = { counts: counts, total: newTiers.length, churn: churn };
  });
  return { wdData: wdData, totalChanged: totalChanged };
}

function buildLiveImpactPreview(computed) {
  var wdData = computed.wdData, totalChanged = computed.totalChanged;
  // NEW: "Recalculate" replaces the old "Live" badge - weight adjustments no
  // longer recompute this panel (or the group tables below) on every slider
  // tick; both stay on the last recalculation, visibly greyed via
  // markWeightsDirty(), until this button is clicked. Rebuilt fresh here
  // (disabled, stale-note hidden) every time this function runs, which only
  // ever happens right after a real recompute - so it's always correct
  // without any separate reset logic.
  var html = '<div class="preview-card"><div class="preview-head"><h5>Live Impact Preview</h5>' +
    '<button class="recalc-btn" id="recalc-btn" onclick="recalculateImpact()" disabled>Recalculate</button></div>' +
    '<p class="preview-sub">By group, broken down by workload. Adjust sliders freely, then click <b>Recalculate</b> to see the effect - a +/- next to a workload shows objects that moved into or out of that group at the last recalculation.</p>' +
    '<p class="stale-note" id="stale-note" style="display:none;">Weights have changed since the last recalculation - this is still showing the OLD breakdown.</p>' +
    '<div id="impact-preview-body"><div class="headline-delta"><div class="n">' + totalChanged + (totalChanged === 1 ? " object" : " objects") + '</div><div class="t">changed group at the last recalculation</div></div>';
  TIER_ORDER.forEach(function (tier) {
    var groupTotal = 0;
    WORKLOAD_DEFS.forEach(function (wd) { groupTotal += wdData[wd.key].counts[tier]; });
    html += '<div class="group-section"><div class="group-head"><span class="tier-dot" style="background:' + TIER_META[tier].bg + ';"></span>' +
      '<span class="group-name">' + TIER_META[tier].named + '</span><span class="group-total">' + fmtNum(groupTotal) + ' objects</span></div>';
    WORKLOAD_DEFS.forEach(function (wd) {
      var d = wdData[wd.key];
      var count = d.counts[tier];
      var pct = d.total ? (100 * count / d.total) : 0;
      var deltaHtml = '<span class="wd-delta">&nbsp;</span>';
      if (d.churn) {
        var c = d.churn[tier];
        var parts = [];
        if (c["in"] > 0) { parts.push('<span class="wd-delta up">+' + c["in"] + '</span>'); }
        if (c["out"] > 0) { parts.push('<span class="wd-delta down">-' + c["out"] + '</span>'); }
        if (parts.length) { deltaHtml = parts.join(""); }
      }
      html += '<div class="group-wd-row"><span class="wd-name">' + esc(wd.label) + '</span>' +
        '<span class="wd-bar-track"><span class="wd-bar-fill" style="width:' + pct + '%;background:' + TIER_META[tier].bg + ';"></span></span>' +
        '<span class="wd-count">' + fmtNum(count) + '</span>' + deltaHtml + '</div>';
    });
    html += '</div>';
  });
  html += '<span class="reset-link" onclick="resetImpactBaseline()">Reset comparison baseline</span></div></div>';
  return html;
}

function resetImpactBaseline() {
  lastTierByWorkload = {};
  refreshImpactPreview();
}

function onHubKeywordsChange(value) { state.hubSiteKeywords = value.split(",").map(function (s) { return s.trim(); }).filter(Boolean); recomputeAll(); }

// Rebuilds state.titleWeights (the plain object computeTitleWeight() actually
// reads) from state.titleWeightRows (the ordered array the editable table
// works against). Blank/whitespace-only keyword rows are skipped - lets a
// half-filled "Add keyword" row sit in the table without matching every
// title. Duplicate keywords simply let the later row win (last write wins on
// object-key assignment), same as if two same-named entries were passed via
// -TitleWeights on the command line.
function syncTitleWeights() {
  var next = {};
  state.titleWeightRows.forEach(function (r) {
    var kw = (r.keyword || "").trim();
    if (kw) { next[kw] = r.weight; }
  });
  state.titleWeights = next;
}
function onTitleWeightKeywordChange(idx, value) { state.titleWeightRows[idx].keyword = value; syncTitleWeights(); recomputeAll(); }
function onTitleWeightWeightChange(idx, value) {
  var n = parseFloat(value);
  if (isNaN(n)) { n = 0; }
  n = Math.max(0, Math.min(1, n));
  state.titleWeightRows[idx].weight = n;
  syncTitleWeights();
  recomputeAll();
}
function removeTitleWeightRow(idx) { state.titleWeightRows.splice(idx, 1); syncTitleWeights(); recomputeAll(); }
function addTitleWeightRow() { state.titleWeightRows.push({ keyword: "", weight: 0.5 }); syncTitleWeights(); recomputeAll(); }

// ===================================================================================
// v2.0 "Groups & Recovery Model" tab
//   [Scoring & recovery inputs]  collapsed panel (sliders, keywords, RTO targets, window, tier, $/hr)
//   [Group 1 headline]           hours saved (big), Group 1 online time, per-workload table, cost avoided
//   [By group]                   Group 1-4 accordions, all collapsed (Preview: Group 1 + one "Remaining groups" card)
//   ---- Or slice by workload ----
//   [By workload]                Exchange / OneDrive / SharePoint / Teams accordions, all collapsed
// ===================================================================================
var IMPACT_CACHE = null;
var PENDING_ATTACH = [];
var pendingAttachTimer = null;
function queueScrollAttach(tkey) {
  PENDING_ATTACH.push(tkey);
  if (pendingAttachTimer) { return; }
  // Accordion bodies are inserted AFTER their html builder returns, so wire up the scroll hints one tick later.
  pendingAttachTimer = setTimeout(function () {
    pendingAttachTimer = null;
    var keys = PENDING_ATTACH; PENDING_ATTACH = [];
    keys.forEach(function (k) { attachScrollAffordance(k); });
  }, 0);
}

if (!INFO["cost-avoided"]) {
  registerInfo("cost-avoided", "How we estimate cost avoided",
    "<p><b>Baseline:</b> restoring the whole tenant as one undifferentiated job (Mass Recovery). Nothing is usable until that job finishes.</p>" +
    "<p><b>With ABR:</b> Autonomous Business Recovery brings Group 1 back first, then Groups 2 and 3, so the people and sites you depend on are working while the rest restores.</p>" +
    "<p><b>Hours saved</b> = whole-tenant Mass Recovery time minus the time until that group is online. It is never shown as negative. <b>Cost avoided</b> = hours saved &times; the downtime cost per hour you enter. No rate is assumed.</p>" +
    "<p>Groups 2 and 3 save less because by then ABR and Mass Recovery are close to moving the same total data through the same throughput.</p>");
}
registerInfo("abr-vs-mass", "ABR vs Mass Recovery",
  "<p><b>ABR</b> (Autonomous Business Recovery) restores each object's recent data first, one group at a time. <b>Mass Recovery</b> restores everything as one undifferentiated batch.</p>" +
  "<p>For a given group, the Mass Recovery figure restores that same cumulative set (Groups 1 through this one) as one batch. The two converge for the whole tenant: prioritizing does not shrink the total time, it changes <b>when</b> each group comes back.</p>");

function tierLabelHtml(tierName) {
  var meta = TIER_META[tierName];
  var sub = tierName === "Group 4" ? "recovered last" : (tierName === "Critical Group 1" ? "recover first" : "");
  return '<span class="tier-dot" style="background:' + meta.bg + ';"></span>' + meta.named + (sub ? ' <span class="acc-sub">' + sub + "</span>" : "");
}

// ---------- scoring & recovery inputs ----------
function buildControlsPanelBody() {
  var inner = '<div class="controls-panel-grid"><div id="controls-sliders-wrap">' + buildControlsSliders() + "</div>" +
    (canEditTiers() ? '<div id="impact-preview-wrap">' + buildLiveImpactPreview(IMPACT_CACHE || computeImpactData()) + "</div>" : "") +
    "</div>" + buildRecoveryControls();
  if (canEditTiers()) { return inner; }
  return '<div class="locked-note">Locked in the ' + (IS_PREVIEW ? "Preview" : "Summary") + ' - adjust in the full assessment. These are the settings that produced Group 1 below. ' +
    '<a href="' + CONTACT_SALES_URL + '" target="_blank" rel="noopener">Contact your Rubrik representative</a>.</div>' +
    '<fieldset class="locked-controls" disabled>' + inner + "</fieldset>";
}
function controlsSummaryHtml() {
  return "<span><b>" + groupN() + "</b> criticality groups</span><span>Group 1 Recovery Window (RTO) <b>" + state.recovery.group1Hours + " hr</b></span><span>Recent-data window <b>" + state.recovery.windowDays + " days</b></span>" +
    (canEditTiers() ? "" : '<span class="lock-tag">Locked</span>');
}

// ---------- Group 1 headline ----------
function buildExclusionNote() {
  if (IS_PREVIEW || IS_SUMMARY || typeof getInsightsSummary !== "function") { return ""; }
  var s = getInsightsSummary();
  if (!s || !(s.excludedCount > 0)) { return ""; }
  var h = s.headline;
  var cmp = (h && isFinite(h.excludedG1Min) && isFinite(h.includedG1Min))
    ? " Group 1: " + fmtMin(h.excludedG1Min) + " with them left out, " + fmtMin(h.includedG1Min) + " if included." : "";
  var excl = state.insights.exclude;
  return '<div class="grp-exclusion-note"><span>' + (excl
    ? fmtNum(s.excludedCount) + " flagged object" + (s.excludedCount === 1 ? " is" : "s are") + " left out of these estimates." + cmp
    : fmtNum(s.excludedCount) + " flagged object" + (s.excludedCount === 1 ? " is" : "s are") + " included in these estimates." + cmp) +
    ' <span class="linkout" ' + navAttr("insights:insights-summary") + '>See Recovery Insights</span></span>' +
    '<button type="button" onclick="setExcludeOutliers(' + (excl ? "false" : "true") + ')">' + (excl ? "Include them" : "Leave them out") + "</button></div>";
}

function buildGroup1Headline(model) {
  var ca = computeCostAvoided(model);
  var g1 = ca.rows[0];
  var m1 = model.milestones["Critical Group 1"];
  var tot = groupTotalsAll("Critical Group 1");
  var teamsG1 = groupTotals("teams", "Critical Group 1");

  var big, bigSub;
  if (g1.locked) { big = pvLocked("0.0 hr"); bigSub = ""; }
  else {
    big = fmtMin(g1.savedMin);
    bigSub = "Group 1 is online in <b>" + fmtMin(g1.abrMin) + "</b> instead of waiting <b>" + fmtMin(g1.baselineMin) + "</b> for the whole-tenant Mass Recovery to finish." +
      (m1.exceedsTarget ? ' <span class="badge exceeds-target">Exceeds target</span>' : "");
  }
  var moneyBig = ca.hasRate && !g1.locked ? fmtMoney(g1.cost) : "&mdash;";
  var smallRows = ca.rows.slice(1).map(function (r) {
    var val = r.locked ? pvLocked("0.0 hr") : (r.savedHours.toFixed(1) + " hr sooner" + (ca.hasRate ? " &middot; " + fmtMoney(r.cost) : ""));
    return '<div class="hl-small"><span class="hl-small-label">' + r.label + "</span><span>" + val + "</span></div>";
  }).join("");

  var wlRows = WORKLOAD_DEFS.map(function (wd) {
    var t = groupTotals(wd.key, "Critical Group 1") || { objects: 0, items: 0, storageBytes: 0 };
    var has = wd.key !== "teams";
    return "<tr " + navAttr("groups:wl-" + wd.key + ":wl-" + wd.key) + "><td>" + esc(wd.label) + "</td><td>" + fmtNum(t.objects) + "</td><td>" + (has ? fmtNum(t.items) : "&ndash;") + "</td><td>" + (has ? fmtStorageNum(t.storageBytes) : "&ndash;") + "</td></tr>";
  }).join("");
  var totalRow = '<tr class="no-sort-row total-row" ' + navAttr("groups:grp-by-group:grp-g1") + "><td><b>Total</b></td><td><b>" + fmtNum(tot.objects) + "</b></td><td><b>" + fmtNum(tot.items) + "</b></td><td><b>" + fmtStorageNum(tot.storageBytes) + "</b></td></tr>";

  var html = '<section class="grp-headline" id="grp-headline"><h3 class="grp-section-title">Group 1 headline</h3>' +
    '<div class="hl-grid">' +
      '<div class="hl-card hl-time" ' + navAttr("groups:grp-by-group:grp-g1") + '><div class="hl-label">Hours saved for Group 1 ' + infoBtn("cost-avoided") + '</div><div class="hl-big">' + big + '</div><div class="hl-sub">' + bigSub + "</div></div>" +
      '<div class="hl-card hl-money"><div class="hl-label">Potential cost avoided, Group 1 ' + infoBtn("cost-avoided") + '</div><div class="hl-big">' + moneyBig + "</div>" +
        (ca.hasRate ? "" : '<div class="hl-sub">' + costPromptHtml() + "</div>") +
        '<div class="hl-smalls">' + smallRows + "</div></div>" +
    "</div>" +
    buildExclusionNote() +
    '<div class="table-wrap"><table class="hl-wl-table"><thead><tr><th>Group 1 by workload</th><th>Objects</th><th>Items</th><th>' + storageHeader("Storage") + "</th></tr></thead><tbody>" + wlRows + totalRow + "</tbody></table></div>" +
    (teamsG1 ? '<div class="pill-note">Teams have no item or storage figures; they are counted as objects and tiered by activity.</div>' : "") +
    "</section>";
  return html;
}

// ---------- By group ----------
function groupSummaryHtml(tierName, model) {
  var tot = groupTotalsAll(tierName);
  var m = model.milestones[tierName];
  var abr = tierName === "Group 4" ? "recovered last" : (m && !m.locked ? "ABR online in " + fmtMin(m.wallClockCumMin) : "");
  var exceeds = (m && !m.locked && m.exceedsTarget) ? '<span class="badge exceeds-target">Exceeds target</span>' : "";
  return "<span><b>" + fmtNum(tot.objects) + "</b> objects</span><span><b>" + fmtNum(tot.items) + "</b> items</span><span><b>" + fmtStorage(tot.storageBytes) + "</b></span>" +
    (abr ? "<span><b>" + abr + "</b></span>" : "") + exceeds;
}

function setGroupWl(tierName, wlKey) {
  uiState.groupWl = uiState.groupWl || {};
  uiState.groupWl[tierName] = wlKey;
  var el = document.getElementById("gwl-" + tierIdOf(tierName));
  if (el) { el.innerHTML = buildGroupWorkloadPicker(tierName); enhanceTables(el); }
}
function buildGroupWorkloadPicker(tierName) {
  var id = tierIdOf(tierName);
  uiState.groupWl = uiState.groupWl || {};
  var sel = uiState.groupWl[tierName];
  if (!sel) {
    var firstWith = WORKLOAD_DEFS.filter(function (wd) { var t = groupTotals(wd.key, tierName); return t && t.objects > 0; })[0];
    sel = (firstWith || WORKLOAD_DEFS[0]).key;
  }
  var chips = WORKLOAD_DEFS.map(function (wd) {
    var t = groupTotals(wd.key, tierName) || { objects: 0 };
    return '<button type="button" class="chip' + (sel === wd.key ? " active" : "") + '" onclick="setGroupWl(\'' + tierName + '\',\'' + wd.key + '\')">' + esc(wd.label) + " (" + fmtNum(t.objects) + ")</button>";
  }).join("");
  return '<div class="filter-chips grp-wl-chips" role="group" aria-label="Workload">' + chips + "</div>" + buildObjectTable(id + "-" + sel, sel, tierName);
}

function buildGroupBody(tierName) {
  var model = computeRecoveryModel();
  var idx = TIER_ORDER.indexOf(tierName);
  var isG4 = tierName === "Group 4";
  var html = "";
  if (isG4) {
    html += '<p class="g4-note">' + esc(group4Disclaimer()) + " ABR does not sequence these objects; they come back through Mass Recovery after " + scopeName(groupN()) + ".</p>";
  } else {
    html += buildGroupCompareCards(model, tierName, idx);
  }
  html += buildWorkloadBreakdownTable(model, tierName);
  if (isG4) { html += buildWholeTenantCompare(model); }
  if (IS_SUMMARY) { return html + '<p class="pill-note">Per-object detail is not part of the summary report.</p>'; }
  if (tierName === "Critical Group 1") { html += buildGroup1All(); }
  html += '<div class="grp-wl-wrap" id="gwl-' + tierIdOf(tierName) + '">' + buildGroupWorkloadPicker(tierName) + "</div>";
  return html;
}

function buildRemainingCard() {
  var rem = remainderTotalsAll();
  var teamsRem = Math.max(0, teamsObjectCount() - (groupTotals("teams", "Critical Group 1") || { objects: 0 }).objects);
  var rows = WORKLOAD_DEFS.map(function (wd) {
    var r = remainderTotals(wd.key);
    var has = wd.key !== "teams";
    var objs = wd.key === "teams" ? teamsRem : r.objects;
    return "<tr><td>" + esc(wd.label) + "</td><td>" + fmtNum(objs) + "</td><td>" + (has ? fmtNum(r.items) : "&ndash;") + "</td><td>" + (has ? fmtStorageNum(r.storageBytes) : "&ndash;") + "</td></tr>";
  }).join("");
  return '<div class="remaining-card" id="grp-remaining"><h4>Remaining groups <span class="lock-tag">Full assessment</span></h4>' +
    '<p class="pill-note">Everything outside Group 1, as one total. Group 2, 3 and 4 sizes, recovery sequencing and cost avoidance by group are in the full assessment.</p>' +
    '<div class="table-wrap"><table class="grp-breakdown"><thead><tr><th>Workload</th><th>Objects</th><th>Items</th><th>' + storageHeader("Storage") + "</th></tr></thead><tbody>" + rows + "</tbody></table></div>" +
    pvLockedPanel("Groups 2-4 are locked in the Preview", "Re-run the full assessment to see how the rest of your tenant breaks down and how fast each group comes back.") + "</div>";
}

function buildByGroupSection(model) {
  var html = '<section class="grp-section" id="grp-by-group"><h3 class="grp-section-title">By group</h3>' +
    '<p class="pill-note">Each group is collapsed - open one to see its recovery comparison, per-workload breakdown, and every object in it. ' + infoBtn("abr-vs-mass") + "</p>";
  var tiers = IS_PREVIEW ? ["Critical Group 1"] : TIER_ORDER;
  tiers.forEach(function (t) {
    html += accHtml({ id: "grp-" + tierIdOf(t), title: tierLabelHtml(t), summary: groupSummaryHtml(t, model), body: function () { return buildGroupBody(t); } });
  });
  if (IS_PREVIEW) { html += buildRemainingCard(); }
  return html + "</section>";
}

// ---------- By workload ----------
function workloadTotalsRaw(wlKey) {
  var objects = 0, items = 0, bytes = 0;
  if (IS_PREVIEW) {
    var g = groupTotals(wlKey, "Critical Group 1") || { objects: 0, items: 0, storageBytes: 0 };
    var r = remainderTotals(wlKey);
    if (wlKey === "teams") { return { objects: teamsObjectCount(), items: 0, storageBytes: 0 }; }
    return { objects: g.objects + r.objects, items: g.items + r.items, storageBytes: g.storageBytes + r.storageBytes };
  }
  TIER_ORDER.forEach(function (t) {
    var x = groupTotals(wlKey, t);
    if (x) { objects += x.objects; items += x.items; bytes += x.storageBytes; }
  });
  return { objects: objects, items: items, storageBytes: bytes };
}

function buildWorkloadGroupTable(wlKey, model) {
  var field = { mailboxes: "ex", onedrive: "od", sharepoint: "sp" }[wlKey];
  var hasStorage = wlKey !== "teams";
  function rowHtml(tierName) {
    var t = groupTotals(wlKey, tierName) || { objects: 0, items: 0, storageBytes: 0 };
    var m = model.milestones[tierName];
    var w = (m && !m.locked && field) ? m[field] : null;
    var isLast = tierName === TIER_ORDER[TIER_ORDER.length - 1];
    return "<tr " + navAttr("groups:grp-by-group:grp-" + tierIdOf(tierName)) + '><td data-sort="' + TIER_ORDER.indexOf(tierName) + '">' + tierLabelHtml(tierName) + "</td><td>" + fmtNum(t.objects) + "</td><td>" + (hasStorage ? fmtNum(t.items) : "&ndash;") + "</td><td>" + (hasStorage ? fmtStorageNum(t.storageBytes) : "&ndash;") + "</td>" +
      "<td" + (w ? ' data-sort="' + w.timeMin + '"' : "") + ">" + (w && !isLast ? fmtMin(w.timeMin) : "&ndash;") + "</td><td" + (w ? ' data-sort="' + w.massTimeMin + '"' : "") + ">" + (w ? "~" + fmtMin(w.massTimeMin) : "&ndash;") + "</td></tr>";
  }
  var body = "";
  if (IS_PREVIEW) {
    var r = remainderTotals(wlKey);
    var objs = wlKey === "teams" ? Math.max(0, teamsObjectCount() - (groupTotals("teams", "Critical Group 1") || { objects: 0 }).objects) : r.objects;
    body = rowHtml("Critical Group 1") + '<tr class="no-sort-row"><td>Remaining groups ' + '<span class="lock-tag">Full assessment</span></td><td>' + fmtNum(objs) + "</td><td>" + (hasStorage ? fmtNum(r.items) : "&ndash;") + "</td><td>" + (hasStorage ? fmtStorageNum(r.storageBytes) : "&ndash;") + "</td><td>&ndash;</td><td>&ndash;</td></tr>";
  } else {
    body = TIER_ORDER.map(rowHtml).join("");
  }
  return '<div class="table-wrap"><table class="grp-breakdown"><thead><tr><th>Group</th><th>Objects</th><th>' + (wlKey === "teams" ? "Users with recent activity" : "Items") + "</th><th>" + storageHeader("Storage") + "</th><th>ABR time (this group)</th><th>Mass Recovery (cumulative scope)</th></tr></thead><tbody>" + body + "</tbody></table></div>";
}

function buildWorkloadBody(wlKey) {
  var model = computeRecoveryModel();
  var html = buildWorkloadGroupTable(wlKey, model);
  if (IS_SUMMARY) { return html + '<p class="pill-note">Per-object detail is not part of the summary report.</p>'; }
  return html + buildObjectTable(wlKey, wlKey, null);
}

function buildByWorkloadSection() {
  var html = '<div class="grp-divider" role="separator"><span>Or slice by workload</span></div>' +
    '<section class="grp-section" id="grp-by-workload"><h3 class="grp-section-title">By workload</h3>' +
    '<p class="pill-note">The same objects, grouped by Exchange, OneDrive, SharePoint and Teams. Open a workload to see how it splits across groups and to search, filter and sort its objects.</p>';
  WORKLOAD_DEFS.forEach(function (wd) {
    var t = workloadTotalsRaw(wd.key);
    var has = wd.key !== "teams";
    html += accHtml({
      id: "wl-" + wd.key,
      title: esc(wd.label),
      summary: "<span><b>" + fmtNum(t.objects) + "</b> objects</span>" + (has ? "<span><b>" + fmtNum(t.items) + "</b> items</span><span><b>" + fmtStorage(t.storageBytes) + "</b></span>" : ""),
      body: function () { return buildWorkloadBody(wd.key); }
    });
  });
  return html + "</section>";
}

function buildGroupsBody() {
  var model = computeRecoveryModel();
  return buildGroup1Headline(model) + buildByGroupSection(model) + buildByWorkloadSection();
}

function renderGroupsTab() {
  var panel = document.getElementById("panel-groups");
  if (!panel) { return; }
  IMPACT_CACHE = canEditTiers() ? computeImpactData() : null;
  panel.innerHTML = '<h2>Groups &amp; Recovery Model</h2>' +
    '<p class="tab-lead">How every mailbox, OneDrive, SharePoint site and Team is scored into a recovery group, how fast ABR brings each group back, and the objects in every group. Everything below is collapsed - open what you need.</p>' +
    '<div id="grp-controls">' + accHtml({ id: "grp-controls-acc", title: "Scoring &amp; Recovery inputs", summary: controlsSummaryHtml(), body: buildControlsPanelBody }) + "</div>" +
    '<div id="groups-body-wrap">' + buildGroupsBody() + "</div>";
  refreshAllWeightTotals();
}

function refreshGroupsBody() {
  var el = document.getElementById("groups-body-wrap");
  if (!el) { renderGroupsTab(); return; }
  // Only innerHTML is replaced - the wrapper (and any "is-stale" class markWeightsDirty() added) survives, so clear it explicitly.
  el.classList.remove("is-stale");
  el.innerHTML = buildGroupsBody();
  enhanceTables(el);
}

function refreshImpactPreview() {
  var el = document.getElementById("impact-preview-wrap");
  var computed = computeImpactData();
  IMPACT_CACHE = computed;
  if (!el) { return; }
  el.innerHTML = buildLiveImpactPreview(computed);
}

// Lightweight recompute path for slider drags: never rebuilds #controls-sliders-wrap (so the slider being dragged is never
// re-created), only refreshes the groups body, the impact preview, and the other tabs that depend on scores/tiers.
function recomputeTiersLive() {
  WORKLOAD_DEFS.forEach(function (wd) { computeScoresAndTiers(wd.key); });
  if (typeof computeInsights === "function") { computeInsights(); }
  ["renderExecLean", "renderExecSummary"].forEach(function (name) { if (typeof window[name] === "function") { window[name](); } });
  refreshGroupsBody();
  refreshImpactPreview();
  ["renderInsightsTab", "renderMethodologyTab", "renderCompareTab"].forEach(function (name) { if (typeof window[name] === "function") { window[name](); } });
  enhanceTables(document);
  saveOverridesToStorage();
}

'@

#endregion

#region ---------- HTML report JS: recovery tab, methodology tab, compare tab ----------

$script:ReportJsRenderRecovery = @'
// ===================================================================================
// v2.0: recovery inputs + per-group recovery comparison, now living INSIDE the merged
// "Groups & Recovery Model" tab (the old standalone Recovery tab is gone).
//   - buildRecoveryControls()        the recovery inputs / RTO targets (goes in the "Scoring & recovery inputs" panel)
//   - buildGroupCompareCards()       ABR vs Mass Recovery cards for one group (goes in that group's accordion body)
//   - buildWorkloadBreakdownTable()  per-workload breakdown for one group
//   - buildWholeTenantCompare()      the whole-tenant total (ABR and Mass converge) - shown in the Group 4 body
// Handlers (onRtoTargetChange, onRecoveryInputChange, applyRtoPreset, ...) are unchanged in behavior.
// ===================================================================================
function buildRecoveryControls() {
  var opts = ["Auto"].concat(SPOD_TIER_TABLE.map(function (t) { return t.Bucket; })).map(function (b) {
    return '<option value="' + b + '"' + (state.recovery.licenseTier === b ? " selected" : "") + ">" + b + "</option>";
  }).join("");
  var noRate = !(parseFloat(state.recovery.costPerHour) > 0);
  var html = '<div class="controls-panel" id="recovery-inputs-panel"><h4>Recovery modeling inputs</h4>';
  html += '<div class="control-row"><label for="recovery-window-input">Recent-data window (days)</label><input type="number" id="recovery-window-input" min="0" max="7" step="0.5" value="' + state.recovery.windowDays + '" onchange="onRecoveryInputChange(\'windowDays\',this.value)" style="width:80px;"></div>';
  html += '<div class="pill-note" style="margin-top:-.4rem;">ABR can recover up to the last 7 days of recent activity - drag this down to model a shorter window (linearly scales the real 7-day activity signal; not a separately measured figure).</div>';
  html += '<div class="control-row"><label for="downtime-cost-input">Downtime cost ($/hour)</label><input type="number" id="downtime-cost-input" min="0" step="100" value="' + state.recovery.costPerHour + '" onchange="onRecoveryInputChange(\'costPerHour\',this.value)" style="width:120px;"></div>';
  html += '<div class="pill-note cost-note" style="margin-top:-.4rem;">' + (noRate ? "Enter your estimated downtime cost per hour to see potential cost avoidance. Hours saved are shown either way." : "Used only to turn hours saved into potential cost avoided.") + "</div>";
  // Number of criticality groups (Full report only). The low-activity group is always one more than this.
  if (canEditTiers()) {
    html += '<div class="control-row"><label for="group-count-input">Criticality groups</label><input type="number" id="group-count-input" min="' + MIN_GROUPS + '" max="' + MAX_GROUPS + '" step="1" value="' + groupN() + '" onchange="setGroupCount(this.value)" style="width:80px;"> <span class="rt-current">+ Group ' + (groupN() + 1) + ' (low activity)</span></div>';
    html += '<div class="pill-note" style="margin-top:-.4rem;">' + MIN_GROUPS + '-' + MAX_GROUPS + ' groups, split by recovery-time budget (below). ABR sequences every criticality group in order; Group ' + (groupN() + 1) + ' holds the objects with no activity and is recovered by Mass Recovery only. Above 3 groups the targets default to <b>Enterprise Plus</b>, sized to this tenant.</div>';
  }
  html += "</div>";

  html += '<div class="controls-panel" id="rto-panel"><h4>Recovery Window (RTO) - Mailboxes / OneDrive / SharePoint tiering (Teams unaffected)</h4>';
  html += '<div class="rt-preset-row">';
  var presets = groupN() === 3 ? ["Standard", "Enterprise", "Enterprise Plus"] : ["Enterprise Plus"];
  presets.forEach(function (p) {
    var activeClass = state.recovery.rtoPreset === p ? " active" : "";
    var hrs = p === "Standard" ? "4h / 24h / 72h" : (p === "Enterprise" ? "24h / 120h / 240h" : "sized to tenant");
    html += '<button type="button" class="rt-preset-btn' + activeClass + '" onclick="applyRtoPreset(\'' + p + '\')">' + p + " (" + hrs + ")</button>";
  });
  html += '<span class="rt-current">Current: <b>' + esc(state.recovery.rtoPreset) + '</b></span>';
  html += "</div>";
  html += '<div class="rto-grid">';
  for (var gk = 1; gk <= groupN(); gk++) {
    html += '<div class="control-row"><label for="group' + gk + '-target-input">Group ' + gk + ' Recovery Window (RTO), hr' + (gk > 1 ? " cumulative" : "") + '</label><input type="number" id="group' + gk + '-target-input" min="0.1" step="0.5" value="' + groupHoursOf(gk) + '" onchange="onRtoTargetChange(' + gk + ',this.value)" style="width:90px;"></div>';
  }
  html += '</div>';
  html += buildAutoSuggestBanner();
  html += "</div>";
  return html;
}

function computeAutoSuggestedPreset() {
  // Mirrors -RTOPreset Auto's server-side threshold: >= 5 days (7200 min) of estimated full-tenant recovery time suggests
  // Enterprise (24/120/240h), else Standard (4/24/72h). Recomputed reactively so it stays current as data/targets change.
  var model = computeRecoveryModel();
  return model.fullRestoreMin >= 7200 ? "Enterprise" : "Standard";
}

function buildAutoSuggestBanner() {
  if (state.recovery.autoBannerDismissed || state.recovery.rtoPreset === "Enterprise Plus" || groupN() !== 3) { return ""; }
  var suggested = computeAutoSuggestedPreset();
  if (suggested === state.recovery.rtoPreset) { return ""; }
  var hrs = suggested === "Enterprise" ? "24h / 120h / 240h" : "4h / 24h / 72h";
  return '<div class="rt-auto-banner"><span>Based on this tenant\'s current data scale, <b>Auto</b> would suggest the <b>' + suggested + '</b> preset (' + hrs + ') - you are currently on <b>' + esc(state.recovery.rtoPreset) + '</b>.</span>' +
    '<span><button type="button" onclick="applyRtoPreset(\'' + suggested + '\')">Switch to ' + suggested + '</button> <button type="button" onclick="dismissAutoBanner()">Dismiss</button></span></div>';
}

function applyRtoPreset(preset) {
  if (!canEditTiers()) { return; }
  if (preset === "Standard" && groupN() === 3) { state.recovery.groupHours = [4, 24, 72]; }
  else if (preset === "Enterprise" && groupN() === 3) { state.recovery.groupHours = [24, 120, 240]; }
  else if (preset === "Enterprise Plus") { state.recovery.groupHours = enterprisePlusHours(groupN()); }
  state.recovery.rtoPreset = preset;
  state.recovery.autoBannerDismissed = false;
  recomputeAll();
}

function dismissAutoBanner() {
  state.recovery.autoBannerDismissed = true;
  renderGroupsTab();
}

function onRtoTargetChange(k, value) {
  if (!canEditTiers()) { return; }
  // Any manual edit of an RTO input flips the state to Custom, per spec.
  var v = parseFloat(value);
  if (!(v > 0)) { renderGroupsTab(); return; }
  state.recovery.groupHours[k - 1] = v;
  state.recovery.rtoPreset = "Custom";
  state.recovery.autoBannerDismissed = false;
  // RTO targets drive the TIERING itself (not just recovery-time display) for Mailboxes/OneDrive/SharePoint - full recompute.
  recomputeAll();
}

function onRecoveryInputChange(field, value) {
  if (!canEditTiers()) { return; }
  state.recovery[field] = (field === "licenseTier") ? value : parseFloat(value);
  // licenseTier also feeds the budget walk, so this needs a full retiering recompute, not just a re-render.
  recomputeAll();
}

// Per-workload breakdown for one group. Object/item/storage numbers are the true group totals; the times come from the model
// (which leaves Recovery-Insights-excluded objects out of the headline estimate, see the note under the table when that applies).
function buildWorkloadBreakdownTable(model, tierName) {
  var m = model.milestones[tierName];
  if (!m || m.locked) { return ""; }
  var defs = [
    { key: "mailboxes", label: "Exchange", t: m.ex },
    { key: "onedrive", label: "OneDrive", t: m.od },
    { key: "sharepoint", label: "SharePoint", t: m.sp },
    { key: "teams", label: "Teams", t: null }
  ];
  var isLast = tierName === TIER_ORDER[TIER_ORDER.length - 1];
  var body = defs.map(function (d) {
    var g = groupTotals(d.key, tierName) || { objects: 0, items: 0, storageBytes: 0 };
    var hasStorage = d.key !== "teams";
    return "<tr><td>" + d.label + "</td><td>" + fmtNum(g.objects) + "</td><td>" + (hasStorage ? fmtNum(g.items) : "&ndash;") + "</td><td>" + (hasStorage ? fmtStorageNum(g.storageBytes) : "&ndash;") + "</td>" +
      "<td" + (d.t ? ' data-sort="' + d.t.timeMin + '"' : "") + ">" + (d.t && !isLast ? fmtMin(d.t.timeMin) : "&ndash;") + "</td>" +
      "<td" + (d.t ? ' data-sort="' + d.t.massTimeMin + '"' : "") + ">" + (d.t ? "~" + fmtMin(d.t.massTimeMin) : "&ndash;") + "</td></tr>";
  }).join("");
  return '<div class="table-wrap"><table class="grp-breakdown"><thead><tr><th>Workload</th><th>Objects</th><th>Items</th><th>' + storageHeader("Storage") + '</th><th>ABR time (this group)</th><th>Mass Recovery (that workload, this cumulative scope)</th></tr></thead><tbody>' + body + "</tbody></table></div>";
}

// ABR vs Mass Recovery cards for one criticality group. hoursSaved is measured against the whole-tenant Mass Recovery
// (computeCostAvoided) - the same baseline as the headline - and the same-scope Mass figure is shown for reference.
function buildGroupCompareCards(model, tierName, idx) {
  var m = model.milestones[tierName];
  if (!m || m.locked) { return ""; }
  var label = TIER_META[tierName].short;
  var targetHoursArr = state.recovery.groupHours;
  var ca = computeCostAvoided(model);
  var row = ca.rows[idx];
  var g = groupTotalsAll(tierName);
  var isEmpty = g.objects === 0;
  var html = "";
  if (isEmpty) {
    html += idx === 0
      ? '<div class="rt-empty-note">No objects fall in Group 1 at the current target (' + state.recovery.group1Hours + " hr) - either everything qualifies for a later group, or see " + lowName() + " below.</div>"
      : '<div class="rt-empty-note">No objects fall in ' + label + " - the figures below are carried over unchanged from the previous group (nothing new to add at this step).</div>";
  }
  if (m.exceedsTarget) {
    html += '<div class="rt-empty-note exceeds">Exceeds the ' + label + " target (" + targetHoursArr[idx] + " hr) by " + fmtMin(m.targetGapMin) + " - this group's own recent data takes longer than the stated window to recover via ABR.</div>";
  }
  var scopeText = scopeName(idx + 1);
  html += '<div class="rt-compare-grid">' +
    '<div class="rt-compare-card abr"><div class="rt-label">ABR - ' + scopeText + ' online in</div><div class="rt-time">' + fmtMin(m.wallClockCumMin) + '</div></div>' +
    '<div class="rt-compare-card mass"><div class="rt-label">Mass Recovery - whole tenant, no prioritization</div><div class="rt-time">~' + fmtMin(model.fullRestoreMin) + '</div>' +
      '<div class="rt-cost">Same scope as one batch (' + scopeText + "): ~" + fmtMin(m.massRecoveryCumMin) + "</div></div>" +
    "</div>";
  var money = ca.hasRate ? (" &middot; " + fmtMoney(row.cost) + " potential cost avoided") : "";
  html += '<div class="rt-savings-bar"><span>' + scopeText + ' online sooner than the whole-tenant restore ' + infoBtn("cost-avoided") + '</span><span>' + row.savedHours.toFixed(1) + " hr" + money + "</span></div>";
  if (!ca.hasRate) { html += '<div class="pill-note">' + costPromptHtml() + "</div>"; }
  return html;
}

// Whole-tenant total (Group 4 body). ABR and Mass Recovery converge here on purpose.
function buildWholeTenantCompare(model) {
  var lastTier = TIER_ORDER[TIER_ORDER.length - 1];
  var totalM = model.milestones[lastTier];
  if (!totalM || totalM.locked) { return ""; }
  var all = TIER_ORDER.map(function (t) { return groupTotalsAll(t); });
  var totalObjs = all.reduce(function (s, a) { return s + a.objects; }, 0);
  return '<div class="rt-group-section total"><h4>Whole tenant <span class="obj-count-n">(' + fmtNum(totalObjs) + ' objects, including ' + lowName() + ')</span></h4>' +
    '<div class="rt-subtitle">Every object, Groups 1-' + (groupN() + 1) + ' (' + lowName() + ' has no ABR priority - Mass Recovery only)</div>' +
    '<div class="rt-compare-grid">' +
      '<div class="rt-compare-card abr"><div class="rt-label">ABR - everything online in</div><div class="rt-time">~' + fmtMin(totalM.wallClockCumMin) + '</div></div>' +
      '<div class="rt-compare-card mass"><div class="rt-label">Mass Recovery - everything online in</div><div class="rt-time">~' + fmtMin(totalM.massRecoveryCumMin) + '</div></div>' +
    "</div>" +
    '<div class="rt-total-note">These two numbers converge here on purpose: recovering everything takes about the same total time either way, because the same throughput has to move the same total data in any order. The value of ABR is in <b>when</b> each group comes back, not how long the full job takes.</div></div>';
}

'@

$script:ReportJsRenderC = @'
// ===================================================================================
// v2.0 RenderC: Methodology & Glossary, Sizing, PDF/print export, Changes-since-last-run.
// (The Recovery tab was merged into "Groups & Recovery Model"; see ReportJsRenderB/Recovery.)
// Rules: storage through the fmtStorage family only; never the words active/inactive/dormant
// about objects; dollars only as Group 1 cost avoided (plus smaller Groups 2-3 lines when a rate is set).
// ===================================================================================

function buildGlossaryHtml() {
  var g4 = group4Disclaimer();
  var html = '<dl class="glossary">';
  html += "<dt>Groups &amp; Recovery Model tab</dt><dd>One place for everything that decides who lands in Group 1 and how long recovery takes: the scoring weights and recovery inputs, the Group 1 headline, every group (collapsed - click to expand), and the same data sliced by workload. Change a weight or a recovery target and every score, group, total, and recovery figure in the report recomputes instantly.</dd>";
  html += "<dt>Composite score</dt><dd>Each metric is percentile-ranked (0-1) within its workload's dataset, then combined using the weights shown, so metrics on very different scales (item counts vs. storage size) don't dominate each other.</dd>";
  html += "<dt>Groups (criticality-ranked, budget-constrained)</dt><dd>Mailboxes, OneDrive, and SharePoint are ranked by composite score. Group 1 holds as many top-ranked objects as fit inside its own recovery time target; the rest spill into Group 2 against its remaining budget, then the next group, and so on; the last criticality group takes everything that remains. The number of criticality groups (3 to 12, default 3) is set in Recovery modeling inputs; one more group (the last number) always holds low-activity objects. Teams has no independent recovery-time model and is split evenly (or by -TierSplit when there are 3 groups). Change an Recovery Window (RTO) target and the group boundaries move with it.</dd>";
  html += "<dt>ABR recovery time (last 7 days first)</dt><dd>Autonomous Business Recovery (ABR) restores each object's most recent data first - up to the last 7 days of changes - estimated from real telemetry already collected (SharePoint's recently used file count, OneDrive's viewed/edited file count, Mailboxes' send+receive volume), applied proportionally to storage. Mass Recovery then continues restoring the remaining, older data. A large object is therefore not automatically slow to bring back: its recently changed working set is usually a small fraction of its total size.</dd>";
  html += "<dt>Mass Recovery</dt><dd>An undifferentiated restore with no prioritization: the whole scope restores as one job, and nothing is usable until it finishes. It is the comparison point for ABR.</dd>";
  html += "<dt>ABR vs. Mass Recovery</dt><dd>ABR sequences the criticality groups in order - Group 1 first, then Group 2, and so on - so a milestone is reached once every workload finishes its own Groups 1..N. Prioritizing does not shrink the TOTAL time to recover everything (same throughput, same data); it changes WHEN each group comes back online. That is what hours saved measures.</dd>";
  html += "<dt>Hours saved and cost avoided</dt><dd>Hours saved = the time a whole-tenant Mass Recovery takes to finish minus the time until a group is back online with ABR (never below zero). Cost avoided = hours saved x the downtime cost per hour you enter (default 0, so only hours are shown until you enter a rate). Group 1 is the headline; Groups 1-2 and 1-3 are smaller figures because the gap closes as more data returns.</dd>";
  html += "<dt>Why recovery speed is limited</dt><dd>Restores run through Microsoft's APIs, so speed is set by how many items can be restored per minute - not by bandwidth or storage size. SharePoint and OneDrive are item-throughput bound (larger files cost proportionally more through the size factor). Exchange is bound by whichever is slower, items or data volume. That is why the ORDER of recovery matters: the same throughput, spent on the most important objects first.</dd>";
  html += "<dt>Exceeds target</dt><dd>What can still happen is a group's own ABR cumulative time running over its own stated Recovery Window (RTO) target. It is flagged in place with the exact shortfall rather than moving objects into a separate bucket.</dd>";
  html += "<dt>Recovery Window (RTO) targets and presets</dt><dd>Group targets (hours, cumulative) are the recovery time budgets that drive the group boundaries and the compliance check. Standard = 4h / 24h / 72h. Enterprise = 24h / 120h / 240h. Enterprise Plus is used above 3 groups: Group 1 at 24 hr and the last group at this tenant's whole-tenant ABR time (never under 240 hr), with the groups in between spaced geometrically and rounded to 12 hr. Every target stays editable. Auto suggests Standard or Enterprise from this tenant's estimated full recovery time (5 days or more picks Enterprise) and tells you which it picked and why.</dd>";
  html += "<dt>" + esc(lowName()) + " (low activity)</dt><dd>" + esc(g4) + " " + lowName() + " is carved out before scoring, gets no ABR timing, and is recovered by Mass Recovery alongside the rest of the tenant. It is still protected; it is just not on the critical path to getting the business running again.</dd>";
  html += "<dt>Recovery Insights</dt><dd>Some objects stand out from the rest of the tenant: far larger, far more items, or unusually busy. They are found by comparing each object with the tenant's own typical objects (no fixed size thresholds). <b>Peer outliers</b> are more than 5x the 99th percentile of their workload and at least 0.1% of its total; <b>concentration</b> objects hold 2% or more of a workload's storage or items. Both kinds are left out of the headline recovery estimates by default (ABR and Mass Recovery alike, so the comparison stays like-for-like) and called out; toggle them back in to see the impact. <b>Long-pole</b> objects are ones whose own restore time (hot data for ABR, full data for Mass Recovery) is longer than the estimate for the group they sit in; they are shown as insight only. SharePoint and OneDrive long-pole times are shown as a range because how much of one large site can restore in parallel is still being confirmed.</dd>";
  html += "<dt>Storage units</dt><dd>Every storage figure in the report uses one unit, GB or TB, chosen once from the size of the tenant (TB above 5 TB). Use the GB / TB switch in the header to change it for the whole report.</dd>";
  html += "<dt>Manual override</dt><dd>Set via the tier dropdown on any row, or via mass-reassignment on a filtered set. Overrides always win over the computed group and are flagged with an \"override\" badge. Use Export overrides to save them and pass the file back in via -OverridesFile on the next run so they persist.</dd>";
  html += "<dt>Export Criticality Groups (CSV)</dt><dd>One CSV listing every object in every workload with its final group, including manual overrides made in this page. Meant as a hand-off file: identifier, group, and enrichment (department/manager/Entra ID groups) per row for a downstream automation to consume.</dd>";
  html += "<dt>Job title weight</dt><dd>Job title is matched (case-insensitive substring) against a customer-editable keyword table; the highest-weighted match contributes an extra percentile-ranked factor into the composite score.</dd>";
  html += "<dt>Department hub site (heuristic)</dt><dd>SharePoint sites whose name/URL matches a department keyword (Payroll, HR, IT, etc.) AND whose page-view/file activity ranks in the top quartile of all SharePoint sites in this run. This is a proxy for \"many people across the org rely on this site\" using data already collected - not a true unique-accessor count. Treat it as a nudge to double-check, not a certainty.</dd>";
  html += "<dt>Mailbox type</dt><dd>Classified from <b>assigned licenses</b> (the usage report no longer returns a usable Recipient Type column). <b>Licensed</b> = at least one license assigned (counts toward the Rubrik license quote). <b>Shared / group / other</b> = unlicensed accounts that are disabled or carry the standard mailbox limit Exchange gives shared/resource mailboxes, mailboxes with no matching user account, and (with -DetailedSizing in the Full script) mailboxes confirmed as Shared/Room/Equipment by Exchange Online: protected and sized, but no Rubrik license needed. <b>Enabled, unlicensed</b> users are not protected and are excluded from the report. Without Exchange Online this is an estimate.</dd>";
  html += "<dt>Manager roll-up</dt><dd>Each user's manager chain is resolved from a single directory pull. Use the \"Filter to org under manager\" box to isolate or mass-reassign everyone reporting up through a given leader.</dd>";
  html += "<dt>Entra ID group filter</dt><dd>On by default (requests Group.Read.All; pass -NoGroups to opt out). Each user's Entra ID group membership is resolved alongside manager enrichment. Use the \"Filter to Entra ID group\" dropdown to isolate or mass-reassign everyone in a group.</dd>";
  html += "<dt>Recovery time model</dt><dd>SharePoint/OneDrive recovery is item-throughput bound by a size-tier lookup; Exchange uses per-mailbox benchmark constants and takes the slower of items and data volume. Time = items &divide; effective items per minute (SharePoint/OneDrive) or the larger of the item time and data time (Exchange). These constants come from the Rubrik M365 recovery time estimator and are the same as the previous version of this assessment (calibration " + esc((DATA.meta && DATA.meta.calibrationVersion) || "v1") + ").</dd>";
  html += "</dl>";
  return html;
}

function buildWeightsTableHtml() {
  var html = '<table class="weights-table"><thead><tr><th>Workload</th><th>Metric</th><th>Weight</th></tr></thead><tbody>';
  Object.keys(state.weights).forEach(function (wdKey) {
    Object.keys(state.weights[wdKey]).forEach(function (field) {
      html += "<tr><td>" + wdKey + "</td><td>" + (FRIENDLY[field] || field) + "</td><td>" + state.weights[wdKey][field] + "</td></tr>";
    });
  });
  html += "</tbody></table>";
  return html;
}

// Recovery model constants (the calibration). One builder for the screen (Methodology tab) and print.
function buildCalibrationHtml(mode) {
  var pr = mode === "print";
  var T = pr ? "pr-table" : "exec-cost-table", N = pr ? ' class="num"' : "";
  function title(t) { return pr ? '<div class="pr-section-title">' + t + "</div>" : "<h3>" + t + "</h3>"; }
  function note(t) { return pr ? '<div class="pr-subnote">' + t + "</div>" : '<p class="sizing-footnote">' + t + "</p>"; }
  var model = computeRecoveryModel();
  var html = title("Recovery model constants (calibration " + esc((DATA.meta && DATA.meta.calibrationVersion) || "v1") + ")");
  html += note("These are the throughput constants behind every recovery time in this report. They match the previous version of this assessment, so a repeat run on the same data produces the same recovery times. Source: Rubrik M365 recovery time model.");
  html += '<table class="' + T + '"><tbody>';
  html += "<tr><td>Recent-data window (ABR looks back up to 7 days)</td><td" + N + ">" + state.recovery.windowDays + " days</td></tr>";
  html += "<tr><td>SharePoint/OneDrive throughput tier (automatic, from object counts)</td><td" + N + ">" + esc(model.spodTierBucket) + "</td></tr>";
  html += "<tr><td>Downtime cost per hour</td><td" + N + ">" + (state.recovery.costPerHour > 0 ? fmtMoney(state.recovery.costPerHour) : "not set (hours saved only)") + "</td></tr>";
  html += "<tr><td>RTO preset</td><td" + N + ">" + esc(state.recovery.rtoPreset) + "</td></tr>";
  html += "<tr><td>Criticality groups</td><td" + N + ">" + groupN() + " (+ " + lowName() + " low activity)</td></tr>";
  html += "<tr><td>Group 1-" + groupN() + " Recovery Window (RTO) targets (cumulative)</td><td" + N + ">" + state.recovery.groupHours.slice(0, groupN()).join(" hr / ") + " hr</td></tr>";
  html += "<tr><td>Teams split (Group 1-" + groupN() + ")</td><td" + N + ">" + (groupN() === 3 ? state.tierSplit : state.recovery.groupHours.slice(0, groupN()).map(function () { return 1 / groupN(); })).map(function (f) { return Math.round(f * 100) + "%"; }).join(" / ") + "</td></tr>";
  if (state.titleWeightContribution) { html += "<tr><td>Job title weight contribution</td><td" + N + ">" + state.titleWeightContribution + "</td></tr>"; }
  if (state.hubSiteBonus) { html += "<tr><td>Hub site bonus</td><td" + N + ">" + state.hubSiteBonus + "</td></tr>"; }
  html += "<tr><td>Usage lookback (scoring and " + lowName() + ")</td><td" + N + ">" + periodDays() + " days</td></tr>";
  html += "</tbody></table>";

  html += title("SharePoint / OneDrive throughput tiers");
  html += note("Parallelism-based throughput, auto-selected from this tenant's object counts unless overridden. A file bigger than the " + fmtNum(SIZE_FACTOR_BASELINE_MB) + " MiB tenant-wide average costs proportionally more (size factor) rather than a separate data-rate cap.");
  html += '<table class="' + T + '"><thead><tr><th>Bucket</th><th' + N + '>Max objects</th><th' + N + '>Parallelism</th><th' + N + '>SharePoint items/min</th><th' + N + '>OneDrive items/min</th></tr></thead><tbody>';
  SPOD_TIER_TABLE.forEach(function (t) {
    var maxDisplay = (t.Max === undefined || t.Max === null) ? "&infin;" : fmtNum(t.Max);
    html += "<tr><td>" + esc(t.Bucket) + "</td><td" + N + ">" + maxDisplay + "</td><td" + N + ">" + t.Parallelism + "</td><td" + N + ">" + fmtNum(t.Parallelism * SP_ITEMS_PER_MIN_PER_UNIT) + "</td><td" + N + ">" + fmtNum(t.Parallelism * OD_ITEMS_PER_MIN_PER_UNIT) + "</td></tr>";
  });
  html += "</tbody></table>";

  html += title("Exchange (mailbox) throughput benchmark");
  html += '<table class="' + T + '"><tbody>';
  html += "<tr><td>Per-mailbox items/min</td><td" + N + ">" + fmtNum(EX_BENCHMARK.PerMailboxItemsPerMin) + "</td></tr>";
  html += "<tr><td>Per-mailbox MB/min</td><td" + N + ">" + fmtNum(EX_BENCHMARK.PerMailboxMBPerMin) + "</td></tr>";
  html += "<tr><td>Max parallel mailboxes</td><td" + N + ">" + fmtNum(EX_BENCHMARK.MaxParallelMailboxes) + "</td></tr>";
  html += "<tr><td>Items/min cap (tenant-wide)</td><td" + N + ">" + fmtNum(EX_BENCHMARK.MaxParallelMailboxes * EX_BENCHMARK.PerMailboxItemsPerMin) + "</td></tr>";
  html += "<tr><td>MB/min cap (tenant-wide)</td><td" + N + ">" + fmtNum(EX_BENCHMARK.MaxParallelMailboxes * EX_BENCHMARK.PerMailboxMBPerMin) + "</td></tr>";
  html += "<tr><td>Overhead buffer</td><td" + N + ">" + EX_BENCHMARK.OverheadBuffer + "x</td></tr>";
  html += "</tbody></table>";

  html += title("ABR scheduling overhead");
  html += note("Applies to ABR recovery time only, not Mass Recovery - every object touched by a restore needs its own job, regardless of how much of it changed.");
  html += '<table class="' + T + '"><tbody>';
  html += "<tr><td>Job scheduling rate</td><td" + N + ">" + JOB_SCHEDULING_RATE_PER_MIN.toFixed(2) + "/min (~" + (60 / JOB_SCHEDULING_RATE_PER_MIN).toFixed(1) + "s/job)</td></tr>";
  html += "<tr><td>Minimum recovery time floor</td><td" + N + ">" + MIN_RECOVERY_MINUTES + " min</td></tr>";
  html += "</tbody></table>";
  return html;
}

// Sizing tab/PDF: always GB (1024^3) and items in millions with six decimals, no thousands separators,
// so the figures can be pasted straight into the sizing tool (1234567 -> 1.234567).
function szGB(bytes) { var v = (bytes || 0) / BYTES_PER_GB; return isFinite(v) ? v.toFixed(2) : "0.00"; }
function szHdr(label) { return (label || "Storage") + " (GB)"; }
function szM(n) { var v = (parseFloat(n) || 0) / 1000000; return v.toFixed(6); }

// ==================== Sizing ====================
// Built from the data already collected. Full: from the object rows. Preview/Summary: from DATA.sizingAgg (whole-tenant
// aggregates computed at generation time; no per-object rows are in those pages).
function buildSizingSummaryFromRows() {
  var mbRows = (DATA.workloads.mailboxes || []);
  var odRows = (DATA.workloads.onedrive || []);
  var spRows = (DATA.workloads.sharepoint || []);

  function metric(r, f) { return (r.metrics && typeof r.metrics[f] === "number") ? r.metrics[f] : 0; }
  function sumMetric(rows, f) { return rows.reduce(function (s, r) { return s + metric(r, f); }, 0); }

  var ci = mailboxClassInfo();
  function isSharedLegacy(r) { return /shared/i.test(r.RecipientType || ""); }
  var userMb, sharedMb;
  if (ci.known) {
    sharedMb = mbRows.filter(function (r) { return r.MailboxClass === "Shared"; });
    userMb = mbRows.filter(function (r) { return r.MailboxClass !== "Shared"; });
  } else {
    userMb = mbRows.filter(function (r) { return !isSharedLegacy(r); });
    sharedMb = mbRows.filter(isSharedLegacy);
  }
  var archiveMb = mbRows.filter(function (r) { return r.HasArchive === true; });

  var ex = {
    userCount: userMb.length,
    userStorageBytes: sumMetric(userMb, "StorageBytes"),
    userItems: sumMetric(userMb, "ItemCount"),
    sharedCount: sharedMb.length,
    sharedStorageBytes: sumMetric(sharedMb, "StorageBytes"),
    sharedItems: sumMetric(sharedMb, "ItemCount"),
    archiveCount: archiveMb.length,
    classKnown: ci.known,
    userLabel: ci.known ? "Licensed user mailboxes" : "User Mailboxes",
    sharedLabel: ci.known ? "Shared / group / other (no license needed)" : "Shared Mailboxes",
    totalLabel: ci.known ? "Total protected mailboxes" : "Total",
    totalCount: mbRows.length,
    totalStorageBytes: sumMetric(mbRows, "StorageBytes"),
    totalItems: sumMetric(mbRows, "ItemCount")
  };
  var od = { count: odRows.length, storageBytes: sumMetric(odRows, "StorageBytes"), files: sumMetric(odRows, "FileCount") };
  var sp = { count: spRows.length, storageBytes: sumMetric(spRows, "StorageBytes"), files: sumMetric(spRows, "FileCount") };
  return { ex: ex, od: od, sp: sp };
}

function buildSizingSummary() {
  var base;
  if ((IS_PREVIEW || IS_SUMMARY) && DATA.sizingAgg) { base = { ex: DATA.sizingAgg.ex, od: DATA.sizingAgg.od, sp: DATA.sizingAgg.sp }; }
  else { base = buildSizingSummaryFromRows(); }
  var ex = base.ex, od = base.od, sp = base.sp;
  var ci = mailboxClassInfo();
  var totalObjects = ex.totalCount + od.count + sp.count;
  var totalStorageBytes = ex.totalStorageBytes + od.storageBytes + sp.storageBytes;
  var totalItemsFiles = ex.totalItems + od.files + sp.files;
  // License estimate mirrors the original sizing script (max of user mailboxes, shared mailboxes, OneDrive accounts);
  // with license data the basis is LICENSED users only (shared/group mailboxes need no Rubrik license).
  var licenseEstimate = ci.known ? Math.max(ex.userCount, od.count) : Math.max(ex.userCount, ex.sharedCount, od.count);
  return { ex: ex, od: od, sp: sp, totalObjects: totalObjects, totalStorageBytes: totalStorageBytes, totalItemsFiles: totalItemsFiles, licenseEstimate: licenseEstimate };
}

var PLAN_FAMILY = { "E7": "Enterprise", "E5": "Enterprise", "E3": "Enterprise", "E1": "Enterprise", "F3": "Frontline", "F1": "Frontline", "G5": "Government", "G3": "Government", "G1": "Government", "A5": "Education", "A3": "Education", "A1": "Education", "Business Premium": "Business", "Business Standard": "Business", "Business Basic": "Business", "Exchange Online (Plan 2)": "Exchange only", "Exchange Online (Plan 1)": "Exchange only", "Exchange Online Essentials": "Exchange only", "Exchange Online Kiosk": "Exchange only", "Other (unrecognized)": "Other" };
var PLAN_ORDER = ["E7", "E5", "E3", "E1", "F3", "F1", "G5", "G3", "G1", "A5", "A3", "A1", "Business Premium", "Business Standard", "Business Basic", "Exchange Online (Plan 2)", "Exchange Online (Plan 1)", "Exchange Online Essentials", "Exchange Online Kiosk", "Other (unrecognized)"];

function mailboxClassInfo() {
  var mc = (DATA.meta && DATA.meta.mailboxClassification) || null;
  return { mc: mc, known: !!(mc && mc.licenseDataAvailable) };
}

function buildLicenseNoteHtml(s, cssClass) {
  var ci = mailboxClassInfo();
  var note;
  if (ci.known) {
    var mc = ci.mc;
    note = "<b>Licensed users (Rubrik license basis): " + fmtNum(s.ex.userCount) + ".</b> Shared / group / other mailboxes (" + fmtNum(s.ex.sharedCount) +
      ") are protected and sized here but need no Rubrik license. ";
    if (mc.excludedCount > 0) {
      note += fmtNum(mc.excludedCount) + " mailboxes belonging to enabled, unlicensed users (" + szGB(mc.excludedStorageBytes) + " GB" + ", " + szM(mc.excludedItems) +
        " items) are not protected by Rubrik and are excluded from every figure in this report. ";
    }
    note += mc.exoConfirmedShared
      ? "Shared mailboxes were confirmed via Exchange Online (" + fmtNum(mc.exoSharedCount) + ")."
      : "Shared mailboxes are an <b>estimate</b> from license data: unlicensed accounts that are disabled or carry the standard mailbox limit Exchange gives shared/resource mailboxes, plus mailboxes with no matching user account. A shared mailbox that is enabled, unlicensed, and has a non-default limit would be counted as an unlicensed user; run with -DetailedSizing to confirm shared mailboxes via Exchange Online.";
  } else {
    note = "Licensed vs. shared mailboxes <b>could not be classified from license data</b> (user profile enrichment failed or returned nothing, or this report predates license-based classification). The split above relies on the Exchange Recipient Type field, which Microsoft's usage report no longer reliably returns, so Shared Mailboxes may be understated and no unlicensed mailboxes were excluded.";
  }
  return '<div class="' + cssClass + '">' + note + "</div>";
}

function licensePlanData() {
  if ((IS_PREVIEW || IS_SUMMARY) && DATA.sizingAgg && DATA.sizingAgg.licensePlans) {
    return { by: DATA.sizingAgg.licensePlans, total: DATA.sizingAgg.licensedUsers || 0, archiveAddon: DATA.sizingAgg.archiveAddon || 0 };
  }
  var rows = (DATA.workloads.mailboxes || []).filter(function (r) { return r.MailboxClass === "Licensed"; });
  var by = {}, archiveAddon = 0;
  rows.forEach(function (r) {
    var k = r.LicensePlan || "Other (unrecognized)";
    if (!by[k]) { by[k] = { users: 0, bytes: 0 }; }
    by[k].users++;
    by[k].bytes += (r.metrics && typeof r.metrics.StorageBytes === "number") ? r.metrics.StorageBytes : 0;
    if (r.HasArchiveAddon) { archiveAddon++; }
  });
  return { by: by, total: rows.length, archiveAddon: archiveAddon };
}

function buildLicensePlanTableHtml(printMode) {
  var ci = mailboxClassInfo();
  if (!ci.known) { return ""; }
  var d = licensePlanData();
  if (d.total === 0) { return ""; }
  var by = d.by;
  var keys = PLAN_ORDER.filter(function (k) { return by[k]; });
  Object.keys(by).forEach(function (k) { if (keys.indexOf(k) < 0) { keys.push(k); } });
  var tcls = printMode ? "pr-table" : "exec-cost-table";
  var nc = printMode ? ' class="num"' : "";
  var totalBytes = 0;
  var body = keys.map(function (k) {
    totalBytes += by[k].bytes;
    return "<tr><td>" + esc(PLAN_FAMILY[k] || "Other") + "</td><td>" + esc(k) + "</td><td" + nc + ">" + fmtNum(by[k].users) + "</td><td" + nc + ">" + szGB(by[k].bytes) + "</td><td" + nc + ">" +
      (100 * by[k].users / d.total).toFixed(1) + "%</td></tr>";
  }).join("");
  body += '<tr class="total-row no-sort-row"><td colspan="2">Total licensed users</td><td' + nc + ">" + fmtNum(d.total) + "</td><td" + nc + ">" + szGB(totalBytes) + "</td><td" + nc + ">100%</td></tr>";
  var h = (printMode ? '<div class="pr-section-title" style="font-size:1rem">' : "<h3>") + "Licensed users by plan" + (printMode ? "</div>" : "</h3>");
  h += '<table class="' + tcls + '"><thead><tr><th>Family</th><th>Plan</th><th' + nc + '>Users</th><th' + nc + '>' + szHdr("Mailbox storage") + '</th><th' + nc + '>% of licensed</th></tr></thead><tbody>' + body + "</tbody></table>";
  var um = (ci.mc && ci.mc.unmappedSkus) || [];
  if (um.length > 0 && by["Other (unrecognized)"]) {
    h += '<div class="' + (printMode ? "pr-note" : "sizing-footnote") + '">Unrecognized license SKU ids (users holding them): ' +
      um.map(function (u) { return esc(u.skuId) + " (" + fmtNum(u.users) + ")"; }).join(", ") + ".</div>";
  }
  h += '<div class="' + (printMode ? "pr-note" : "sizing-footnote") + '">Each licensed user is counted once, under their highest plan (E5 over E3, etc.). Counts cover users with a mailbox. Plan names come from a built-in table of Microsoft license SKU ids; anything not in that table is listed as "Other (unrecognized)". ' +
    "Exchange Online Archiving add-on (standalone SKU): " + fmtNum(d.archiveAddon) + " user(s). E3/E5/F3/A-series plans already include the In-Place Archive, so this add-on count is separate from the Archive Mailboxes count above.</div>";
  return h;
}

// One builder for the sizing tables, screen and print.
function buildSizingTablesHtml(s, mode) {
  var pr = mode === "print";
  var detailed = !!(DATA.meta && DATA.meta.detailedSizingRequested);
  var T = pr ? "pr-table" : "exec-cost-table", N = pr ? ' class="num"' : "";
  var avgDash = "0";
  var archiveStorageCell, archiveItemsCell, archiveAvgCell, rifRow;
  var totalStorageForAvg = s.ex.totalStorageBytes;
  if (detailed && DATA.meta.sizing) {
    var archStorage = DATA.meta.sizing.archiveStorageBytes || 0;
    var rifStorage = DATA.meta.sizing.recoverableItemsStorageBytes || 0;
    var rifItems = DATA.meta.sizing.recoverableItemsItems || 0;
    var rifCount = DATA.meta.sizing.recoverableItemsCount || 0;
    archiveStorageCell = szGB(archStorage);
    archiveItemsCell = szM(DATA.meta.sizing.archiveItems || 0);
    archiveAvgCell = s.ex.archiveCount > 0 ? szGB(archStorage / s.ex.archiveCount) : avgDash;
    rifRow = "<tr><td>Recoverable Items</td><td" + N + ">" + fmtNum(rifCount) + "</td><td" + N + ">" + szGB(rifStorage) + "</td><td" + N + ">" + szM(rifItems) + "</td><td" + N + ">" + (rifCount > 0 ? szGB(rifStorage / rifCount) : avgDash) + "</td></tr>";
    totalStorageForAvg += archStorage + rifStorage;
  } else {
    archiveStorageCell = "*"; archiveItemsCell = "*"; archiveAvgCell = "*";
    rifRow = "<tr><td>Recoverable Items</td><td" + N + ">*</td><td" + N + ">*</td><td" + N + ">*</td><td" + N + ">*</td></tr>";
  }
  var h = '<table class="' + T + '"><thead><tr><th>Mailbox Type</th><th' + N + '>Count</th><th' + N + '>' + szHdr("Storage") + '</th><th' + N + '>Items (millions)</th><th' + N + '>' + szHdr("Avg per mailbox") + '</th></tr></thead><tbody>' +
    "<tr><td>" + s.ex.userLabel + "</td><td" + N + ">" + fmtNum(s.ex.userCount) + "</td><td" + N + ">" + szGB(s.ex.userStorageBytes) + "</td><td" + N + ">" + szM(s.ex.userItems) + "</td><td" + N + ">" + (s.ex.userCount > 0 ? szGB(s.ex.userStorageBytes / s.ex.userCount) : avgDash) + "</td></tr>" +
    "<tr><td>" + s.ex.sharedLabel + "</td><td" + N + ">" + fmtNum(s.ex.sharedCount) + "</td><td" + N + ">" + szGB(s.ex.sharedStorageBytes) + "</td><td" + N + ">" + szM(s.ex.sharedItems) + "</td><td" + N + ">" + (s.ex.sharedCount > 0 ? szGB(s.ex.sharedStorageBytes / s.ex.sharedCount) : avgDash) + "</td></tr>" +
    "<tr><td>Archive Mailboxes</td><td" + N + ">" + fmtNum(s.ex.archiveCount) + "</td><td" + N + ">" + archiveStorageCell + "</td><td" + N + ">" + archiveItemsCell + "</td><td" + N + ">" + archiveAvgCell + "</td></tr>" +
    rifRow +
    '<tr class="total-row no-sort-row"><td>' + s.ex.totalLabel + "</td><td" + N + ">" + fmtNum(s.ex.totalCount) + "</td><td" + N + ">" + szGB(totalStorageForAvg) + "</td><td" + N + ">" + szM(s.ex.totalItems) + "</td><td" + N + ">" + (s.ex.totalCount > 0 ? szGB(totalStorageForAvg / s.ex.totalCount) : avgDash) + "</td></tr>" +
    "</tbody></table>";
  h += buildLicenseNoteHtml(s, pr ? "pr-note" : "sizing-footnote");
  if (!detailed) {
    h += '<div class="' + (pr ? "pr-note" : "sizing-footnote") + '">*Note: Not collected - run script with the -DetailedSizing switch to capture Recoverable Items and In Place Archive details. Capturing In Place Archive and Recoverable Items can take time, depending on the size of the M365 subscription.</div>';
  }
  return h;
}

function renderSizingTab() {
  var s = buildSizingSummary();
  var html = "<h2>M365 Sizing</h2>" +
    '<p class="lede">Tenant-wide capacity and object counts across Exchange, OneDrive, and SharePoint - independent of the criticality groups elsewhere in this report. Pulled from the same Graph usage reports already used for this assessment; no extra permissions required for the totals below. Send this tab along with your recovery metrics for Rubrik sizing.</p>';

  html += '<div class="sizing-section"><h3>Exchange Online</h3>' + buildSizingTablesHtml(s, "screen") + "</div>";
  var planHtml = buildLicensePlanTableHtml(false);
  if (planHtml) { html += '<div class="sizing-section">' + planHtml + "</div>"; }

  html += '<div class="sizing-section"><h3>OneDrive</h3><table class="exec-cost-table"><thead><tr><th>Accounts</th><th>' + szHdr("Storage") + '</th><th>Files (millions)</th><th>' + szHdr("Avg per account") + '</th></tr></thead><tbody>' +
    "<tr><td>" + fmtNum(s.od.count) + "</td><td>" + szGB(s.od.storageBytes) + "</td><td>" + szM(s.od.files) + "</td><td>" + (s.od.count > 0 ? szGB(s.od.storageBytes / s.od.count) : "0") + "</td></tr>" +
    "</tbody></table></div>";
  html += '<div class="sizing-section"><h3>SharePoint</h3><table class="exec-cost-table"><thead><tr><th>Sites</th><th>' + szHdr("Storage") + '</th><th>Files (millions)</th><th>' + szHdr("Avg per site") + '</th></tr></thead><tbody>' +
    "<tr><td>" + fmtNum(s.sp.count) + "</td><td>" + szGB(s.sp.storageBytes) + "</td><td>" + szM(s.sp.files) + "</td><td>" + (s.sp.count > 0 ? szGB(s.sp.storageBytes / s.sp.count) : "0") + "</td></tr>" +
    "</tbody></table></div>";

  var perUserAvg = s.licenseEstimate > 0 ? szGB(s.totalStorageBytes / s.licenseEstimate) : "0";
  html += '<div class="sizing-section"><h3>Discovery Summary</h3><div class="sizing-discovery-grid">' +
    '<div class="sizing-discovery-cell"><div class="label">Total Users / Accounts</div><div class="value">' + fmtNum(s.licenseEstimate) + "</div></div>" +
    '<div class="sizing-discovery-cell"><div class="label">' + szHdr("Total storage") + '</div><div class="value">' + szGB(s.totalStorageBytes) + "</div></div>" +
    '<div class="sizing-discovery-cell"><div class="label">Total Items &amp; Files (millions)</div><div class="value">' + szM(s.totalItemsFiles) + "</div></div>" +
    '<div class="sizing-discovery-cell"><div class="label">' + szHdr("Avg per user/account") + '</div><div class="value">' + perUserAvg + "</div></div>" +
  "</div></div>";
  document.getElementById("panel-sizing").innerHTML = html;
}

// ==================== Recovery Playbook ====================
// How to USE the groups in a real recovery. Sequence from field guidance plus Rubrik's
// "M365 Recovery Best Practices" white paper (RWP-0673). Numbers come from the live recovery model.
function pbStep(n, title, tag, bodyHtml, metaHtml) {
  return '<div class="pb-step"><div class="pb-n">' + n + '</div><div class="pb-body"><div class="pb-title">' + title + (tag ? ' <span class="pb-tag">' + tag + '</span>' : '') + '</div>' + bodyHtml + (metaHtml ? '<div class="pb-meta">' + metaHtml + '</div>' : '') + '</div></div>';
}
function pbScope(m, label) {
  if (!m) { return '<span class="pb-lock">' + exLocked() + ' <span class="pb-locknote">Part of the full assessment</span></span>'; }
  return '<span><b>' + fmtNum(reportMsObjs(m)) + '</b> objects (' + fmtNum(reportMsItems(m)) + ' items, ' + fmtStorage(reportMsBytes(m)) + ')</span>';
}

function buildPlaybookHtml() {
  var model = computeRecoveryModel();
  var G = groupN(), gm = critKeys().map(function (k) { return reportMsOf(model, k); }), g1 = gm[0], gLast = gm[G - 1], lowN = lowName(), lastScope = scopeName(G);
  var win = state.recovery.windowDays;
  var full = model.fullRestoreMin;
  var lowObjs = 0, lowBytes = 0;
  if (!IS_PREVIEW) { var s4 = execTierSum("Group 4"); if (s4) { lowObjs = s4.objects; lowBytes = s4.bytes; } }
  // per-group slice (this group only) for scope lines
  function slice(tier) { var s = execTierSum(tier); return s; }
  var h = '<h2>Recovery Playbook</h2>';
  h += '<p class="lede">How to use the groups when you actually have to recover. The groups tell you <b>what</b> comes back first; this is the <b>order of operations</b> that goes with them. It follows Rubrik\'s M365 Recovery Best Practices (RWP-0673) and field guidance, with your own numbers filled in.</p>';
  h += '<div class="pb-note"><b>Use this for a mass deletion event or tenant-wide compromise</b>: accidental, insider, external attacker or a rogue AI agent. For a few items, use granular or self-service restore.</div>';

  // at a glance
  var rows = [];
  rows.push(["0", "Recover identity", "AD, sync server, Entra ID", "Before any M365 data", "Not modeled (depends on your AD)"]);
  gm.forEach(function (m, i) {
    var k = i + 1;
    rows.push([String(k), tierTitle(k) + ", prioritized recovery", m ? fmtNum(reportMsObjs(m) - (i > 0 && gm[i - 1] ? reportMsObjs(gm[i - 1]) : 0)) + " objects" : (i === 0 ? "&mdash;" : exLocked()), "Last " + win + " days", m ? fmtMin(m.wallClockCumMin) + " &middot; " + recWhen(m.wallClockCumMin) : (i === 0 ? "&mdash;" : exLocked())]);
  });
  rows.push([String(G + 1), "Mass recovery, " + lastScope, gLast ? fmtNum(reportMsObjs(gLast)) + " objects, older data" : exLocked(), "Historical data", gLast ? "~" + fmtMin(gLast.massRecoveryCumMin) + " for this scope" : exLocked()]);
  rows.push([String(G + 2), "Mass recovery, " + lowN, IS_PREVIEW ? exLocked() : fmtNum(lowObjs) + " low-activity objects", "Everything remaining", "Whole tenant baseline " + fmtMin(full)]);
  h += '<h3>Your sequence at a glance</h3><div class="table-wrap"><table class="ex2-table"><thead><tr><th>Step</th><th>What</th><th>Scope</th><th>Data restored</th><th>Online by (if started ' + recWhen(0) + ')</th></tr></thead><tbody>' +
    rows.map(function (r) { return "<tr><td>" + r[0] + "</td><td>" + r[1] + "</td><td>" + r[2] + "</td><td>" + r[3] + "</td><td>" + r[4] + "</td></tr>"; }).join("") + '</tbody></table></div>';
  h += '<div class="ex2-note">Times are ABR estimates from this assessment and are cumulative (each step includes the ones before it). Prioritizing does not shorten the total time to restore everything; it changes <b>when</b> each group comes back.</div>';

  // steps
  h += '<h3>The steps</h3><div class="pb-steps">';
  h += pbStep(0, "Recover identity first", "Always", 
    '<p>Nothing in M365 works without identity. Restore in this order:</p><ol class="pb-sub"><li><b>On-premises Active Directory</b>, usually the source of truth for users and groups.</li><li><b>The Entra ID (Azure AD) Connect / sync server</b>, which translates AD and uploads it to Entra ID.</li><li><b>Microsoft Entra ID</b>, most importantly users and the <b>Microsoft 365 (modern) groups</b>. Teams, SharePoint and access to other services depend on them, and Mass Recovery selects Exchange and OneDrive users through Entra ID groups, so those groups must exist first.</li></ol>' +
    '<p>Why order matters: Rubrik preserves the relationships between AD and Entra ID (SIDs, GUIDs, UPNs, app authorizations, Conditional Access policies). A user restored with a new SID can break Conditional Access, app integrations and MFA, and Entra ID may create a new object without the old policies.</p>',
    'Time is not modeled here because it depends on the size of your directory. Plan it as the first block of the timeline.');
  var fullBtn = (IS_PREVIEW || IS_SUMMARY) ? "" : ' <button type="button" class="ex2-btn" onclick="exportGroup1Csv()">Export the Group 1 list (CSV)</button>';
  h += pbStep(1, "Critical users (Group 1): prioritized recovery, last " + win + " days", "Recover first",
    '<p>Run <b>Prioritized Data Recovery</b> on Group 1 for the last ' + win + ' days of data, and <b>hold off on full mass recovery</b>. This gets people working again fastest. Group 1 is ' + pbScope(g1) + '.</p>' +
    '<p>Build the recovery groups in Rubrik Security Cloud: <b>Entra ID groups</b> for Exchange and OneDrive, and <b>wildcard groups</b> (simple name patterns) for SharePoint sites and Teams.' + fullBtn + '</p>',
    g1 ? ('Online in <b>' + fmtMin(g1.wallClockCumMin) + '</b> (' + recWhen(g1.wallClockCumMin) + '). Recovery Window (RTO) target ' + state.recovery.group1Hours + ' hr: ' + (g1.exceedsTarget ? '<b>over by ' + fmtMin(g1.targetGapMin) + '</b>' : 'met') + '.') : 'Group 1 timing is shown in the full assessment.');
  gm.forEach(function (m, i) {
    var k = i + 1;
    if (k === 1) { return; }
    h += pbStep(k, tierTitle(k) + ": prioritized recovery, last " + win + " days", "",
      '<p>' + (k === 2 ? 'Same approach for Group 2, once Group 1 has finished its prioritized data.' : 'Same again for Group ' + k + '.') + ' Group ' + k + ' adds ' + (m && gm[i - 1] ? '<b>' + fmtNum(reportMsObjs(m) - reportMsObjs(gm[i - 1])) + '</b> objects' : exLocked()) + '.</p>',
      m ? (scopeName(k) + ' online in <b>' + fmtMin(m.wallClockCumMin) + '</b> (' + recWhen(m.wallClockCumMin) + '). Target ' + groupHoursOf(k) + ' hr: ' + (m.exceedsTarget ? '<b>over by ' + fmtMin(m.targetGapMin) + '</b>' : 'met') + '.') : scopeName(k) + ' timing is part of the full assessment.');
  });
  h += pbStep(G + 1, "Mass recovery of " + lastScope, "",
    '<p>With the recent data back and people working, start <b>mass recovery for ' + lastScope + '</b> to bring back the older, historical data. Mass recovery restores objects in parallel and runs in the background.</p>',
    gLast ? ('Mass recovery of this scope: about <b>' + fmtMin(gLast.massRecoveryCumMin) + '</b> on its own.') : '');
  h += pbStep(G + 2, "Mass recovery of " + lowN, "Last",
    '<p>Finish with ' + lowN + ', the low-activity objects (part of mass recovery, never prioritized): ' + (IS_PREVIEW ? exLocked() : 'about <b>' + fmtNum(lowObjs) + '</b> objects, ' + fmtStorage(lowBytes)) + '. These may be orphaned, rarely used or held for compliance. They are still protected; they are just not needed to get the business running.</p>' +
    '<p>' + esc(group4Disclaimer()) + '</p>',
    'Whole-tenant mass recovery baseline: <b>' + fmtMin(full) + '</b>. Finishing everything takes about the same total time either way; the sequence changes when each group is usable.');
  h += '</div>';

  // decisions
  h += '<h3>Choices that depend on the situation</h3><div class="pb-cards">';
  h += '<div class="pb-card"><div class="pb-card-t">Prioritized recovery, with or without waterfall</div>' +
    '<p>Prioritized recovery restores the latest data first (1 to 30 days), then <b>pauses</b>. <b>Waterfall</b> carries straight on into historical data.</p>' +
    '<p><b>Rule of thumb:</b> no waterfall while working through the prioritized groups, so history does not compete with the next group\'s recent data. Waterfall for the last group, or when no one is watching.</p></div>';
  h += '<div class="pb-card"><div class="pb-card-t">VIP group outside Groups 1 to 4</div>' +
    '<p>Executives and other critical users who need <b>everything</b>, not just ' + win + ' days: put them in their own Entra ID group and run <b>mass recovery</b> for it alongside identity or Group 1. It is small, so it adds little time.</p></div>';
  h += '<div class="pb-card"><div class="pb-card-t">Tenant-wide compromise</div>' +
    '<p>Find a clean recovery point first (Anomaly Detection, Threat Hunting) so you do not reinfect. If the tenant itself is suspect, restore into a new, clean tenant with cross-subscription restoration.</p></div>';
  h += '</div>';
  h += '<div class="ex2-note">Sources: Rubrik, <i>M365 Recovery Best Practices</i> (RWP-0673, Aug 2025), plus field guidance. Times are modeled estimates; validate in a recovery test. Teams support for prioritized recovery was "coming soon" in Aug 2025, so confirm current availability.</div>';
  return h;
}
function renderPlaybookTab() {
  var el = document.getElementById("panel-playbook");
  if (!el) { return; }
  var model = computeRecoveryModel();
  if (!(model.fullRestoreMin > 0)) { el.innerHTML = '<h2>Recovery Playbook</h2><div class="exec-hero-note">No objects with recent activity were found, so there is nothing to sequence yet.</div>'; return; }
  el.innerHTML = buildPlaybookHtml();
}

function renderMethodologyTab() {
  var html = "<h2>Methodology &amp; Glossary</h2>" + buildGlossaryHtml();
  html += '<div class="sizing-section">' + buildCalibrationHtml("screen") + "</div>";
  html += "<h3>Current scoring weights</h3>" + buildWeightsTableHtml();
  document.getElementById("panel-methodology").innerHTML = html;
}

// ==================== PDF export (Full build only) ====================
// Browser print-to-PDF of a static document recomputed from DATA/state/computeRecoveryModel() (never scraped from the DOM).
function buildPrintHeaderHtml(subtitle) {
  return '<div class="pr-header">' +
    '<div class="pr-eyebrow">Recovery Assessment &ndash; ' + esc(subtitle) + '</div>' +
    '<div class="pr-title">Recovery Assessment - M365 - ' + esc(DATA.meta.customerLabel) + '</div>' +
    '<div class="pr-meta">' +
      '<span>Usage window: <b>' + esc(DATA.meta.period) + '</b></span>' +
      '<span>Storage unit: <b>' + storageUnit() + '</b></span>' +
      '<span>Generated: <b>' + esc(DATA.meta.generatedAt) + '</b></span>' +
    "</div>" +
  "</div>";
}

// Group 4 numbers: count and share per workload (same calculation as the Report tab).
function computeLowActivitySummary(model) {
  var MASS_KEY = { mailboxes: "ex", onedrive: "od", sharepoint: "sp" };
  var g4 = TIER_ORDER[TIER_ORDER.length - 1];
  var byWorkload = WORKLOAD_DEFS.map(function (wd) {
    var rows = DATA.workloads[wd.key] || [];
    var cnt = rows.filter(function (r) { return r.Tier === g4; }).length;
    var pct = rows.length > 0 ? Math.round((cnt / rows.length) * 100) : 0;
    var massKey = MASS_KEY[wd.key];
    return { label: wd.label, count: cnt, total: rows.length, pct: pct, massRecoveryMin: (model && massKey) ? model.perWorkloadMassRecoveryMin[massKey] : null };
  }).filter(function (d) { return d.total > 0; });
  var totalAll = byWorkload.reduce(function (s, d) { return s + d.total; }, 0);
  var cntAll = byWorkload.reduce(function (s, d) { return s + d.count; }, 0);
  return { byWorkload: byWorkload, totalObjectsAll: totalAll, totalGroup4: cntAll, overallPct: totalAll > 0 ? Math.round((cntAll / totalAll) * 100) : 0 };
}

function buildGroupOverviewTableHtml() {
  var html = '<table class="pr-table"><thead><tr><th>Workload</th>' +
    TIER_ORDER.map(function (t) { return '<th class="num">' + TIER_META[t].named + "</th>"; }).join("") +
    '<th class="num">Total</th></tr></thead><tbody>';
  var grandTotals = {}; TIER_ORDER.forEach(function (t) { grandTotals[t] = 0; });
  var grandTotal = 0;
  WORKLOAD_DEFS.forEach(function (wd) {
    var rows = DATA.workloads[wd.key] || [];
    var rowHtml = "<tr><td>" + esc(wd.label) + "</td>";
    TIER_ORDER.forEach(function (t) {
      var count = rows.filter(function (r) { return r.Tier === t; }).length;
      grandTotals[t] += count;
      rowHtml += '<td class="num">' + fmtNum(count) + "</td>";
    });
    grandTotal += rows.length;
    rowHtml += '<td class="num">' + fmtNum(rows.length) + "</td></tr>";
    html += rowHtml;
  });
  html += '<tr class="total-row no-sort-row"><td>Total</td>' +
    TIER_ORDER.map(function (t) { return '<td class="num">' + fmtNum(grandTotals[t]) + "</td>"; }).join("") +
    '<td class="num">' + fmtNum(grandTotal) + "</td></tr>";
  html += "</tbody></table>";
  return html;
}

function buildStaticBreakdownTableHtml(model, tierName) {
  var m = model.milestones[tierName];
  var rows = [
    { label: "SharePoint", objs: m.sp.objectCount, abr: m.sp.timeMin, mass: m.sp.massTimeMin },
    { label: "OneDrive", objs: m.od.objectCount, abr: m.od.timeMin, mass: m.od.massTimeMin },
    { label: "Exchange", objs: m.ex.objectCount, abr: m.ex.timeMin, mass: m.ex.massTimeMin }
  ];
  var body = rows.map(function (r) {
    return "<tr><td>" + r.label + "</td><td class=\"num\">" + fmtNum(r.objs) + "</td><td class=\"num\">" + fmtMin(r.abr) + '</td><td class="num">~' + fmtMin(r.mass) + "</td></tr>";
  }).join("");
  return '<table class="pr-table"><thead><tr><th>Workload</th><th class="num">Objects (this group)</th><th class="num">ABR Time</th><th class="num">Mass Recovery Time</th></tr></thead><tbody>' + body + "</tbody></table>";
}

function printCostBlockHtml(model) {
  var ca = computeCostAvoided(model);
  var g1 = ca.rows[0];
  var html = '<div class="pr-tiles">' +
    '<div class="pr-tile"><div class="pr-tile-label">Time to Critical Data</div><div class="pr-tile-value">' + fmtMin(g1.abrMin) + '</div><div class="pr-tile-sub">instead of ' + fmtMin(model.fullRestoreMin) + " waiting for a full, undifferentiated restore</div></div>" +
    '<div class="pr-tile"><div class="pr-tile-label">Hours Saved (Group 1)</div><div class="pr-tile-value">' + g1.savedHours.toFixed(1) + ' hr</div><div class="pr-tile-sub">' + (ca.hasRate ? ("Cost avoided: " + fmtMoney(g1.cost)) : "Enter your downtime cost per hour in the report to see potential cost avoidance") + "</div></div>" +
  "</div>";
  var rN = ca.rows[groupN() - 1];
  var lockedRows = ca.rows[1].locked || rN.locked;
  if (lockedRows) {
    html += '<div class="pr-subnote">Groups 1-2 and 1-' + groupN() + ' figures are part of the full assessment.</div>';
  } else if (ca.hasRate) {
    html += '<div class="pr-subnote">Smaller figures: ' + ca.rows.slice(1).map(function (r) { return r.label + " &ndash; " + r.savedHours.toFixed(1) + " hr, " + fmtMoney(r.cost); }).join("; ") + ".</div>";
  } else {
    html += '<div class="pr-subnote">Hours saved, Groups 1-2 online: ' + ca.rows[1].savedHours.toFixed(1) + " hr; " + scopeName(groupN()) + " online: " + rN.savedHours.toFixed(1) + " hr.</div>";
  }
  return html;
}

function buildAssumptionsHtml() {
  var html = buildCalibrationHtml("print");
  html += '<div class="pr-section-title">Composite Score Weights</div>';
  html += '<div class="pr-subnote">Current live weights used to rank objects within each workload.</div>';
  html += buildWeightsTableHtml();
  html += '<div class="pr-section-title">Methodology &amp; Glossary</div>';
  html += '<div class="pr-glossary">' + buildGlossaryHtml() + "</div>";
  return html;
}

// Report-tab content that also belongs on the one-pager: confidence, sensitivity, decisions (same builders as the screen).
function printReportExtrasHtml(model) {
  var conf = reportConfidence();
  var h = '<div class="pr-subnote"><b>Confidence: ' + conf.level + '.</b> ' + conf.notes.join("; ") + '.</div>';
  var sc = reportScenarioResult();
  if (sc) {
    h += '<div class="pr-section-title">Group 1 Sensitivity</div><table class="pr-table"><thead><tr><th>Scenario</th><th class="num">Group 1 objects</th><th class="num">Group 1 online in</th></tr></thead><tbody>' +
      sc.rows.map(function (r) { return "<tr><td>" + esc(r.label) + (r.current ? " (current)" : "") + '</td><td class="num">' + fmtNum(r.g1Objects) + '</td><td class="num">' + fmtMin(r.g1Min) + "</td></tr>"; }).join("") + "</tbody></table>";
  }
  var g1 = model.milestones["Critical Group 1"];
  if (g1 && !g1.locked) {
    h += '<div class="pr-section-title">Decisions and Next Steps</div><ul class="pr-list">' +
      reportDecisionItems(model, g1).map(function (d) { return "<li>" + d.text + "</li>"; }).join("") + "</ul>";
  }
  return h;
}

function buildPrintSummaryHtml() {
  var model = computeRecoveryModel();
  var html = buildPrintHeaderHtml("One Page Summary");
  html += printCostBlockHtml(model);
  html += '<div class="pr-mechanism">ABR restores recently accessed, modified, and created data first &ndash; the data people were actually working on &ndash; so the business is operational in hours, while Mass Recovery continues restoring everything else in the background.</div>';
  html += '<div class="pr-section-title">Recovery Times by Group</div>';
  html += '<table class="pr-table"><thead><tr><th>Milestone</th><th class="num">ABR Time</th><th class="num">Target</th><th>Status</th></tr></thead><tbody>';
  critKeys().map(function (key, i) { return { label: scopeName(i + 1) + " online", m: model.milestones[key], target: groupHoursOf(i + 1) }; }).forEach(function (row) {
    var status = row.m.exceedsTarget ? '<span class="pr-badge exceeds">Exceeds target</span>' : "Within target";
    html += "<tr><td>" + row.label + "</td><td class=\"num\">" + fmtMin(row.m.wallClockCumMin) + "</td><td class=\"num\">" + row.target + " hr</td><td>" + status + "</td></tr>";
  });
  html += '<tr class="total-row no-sort-row"><td>Full tenant (Mass Recovery baseline)</td><td class="num">' + fmtMin(model.fullRestoreMin) + '</td><td class="num">&mdash;</td><td>&mdash;</td></tr>';
  html += "</tbody></table>";
  html += printReportExtrasHtml(model);
  html += '<div class="pr-section-title">Group Overview by Workload</div>';
  html += buildGroupOverviewTableHtml();
  html += '<div class="pr-subnote">' + esc(group4Disclaimer()) + "</div>";
  html += '<div class="pr-footer">Recent-data window: ' + state.recovery.windowDays + " days &middot; SP/OD throughput tier: " + model.spodTierBucket + " &middot; Calibration " + esc((DATA.meta && DATA.meta.calibrationVersion) || "v1") + " &middot; Downtime cost: " + (state.recovery.costPerHour > 0 ? fmtMoney(state.recovery.costPerHour) + "/hour" : "not set") + ". Full per-group breakdown, flagged objects, and every assumption behind these numbers: see the Full Report PDF export.</div>";
  return html;
}

function buildSizingPdfHtml() {
  var s = buildSizingSummary();
  var html = '<div class="pr-section-title">M365 Sizing</div>';
  html += '<div class="pr-subnote">Tenant-wide capacity and object counts across Exchange, OneDrive, and SharePoint - independent of the criticality groups above.</div>';
  html += buildSizingTablesHtml(s, "print");
  html += buildLicensePlanTableHtml(true);
  html += '<table class="pr-table"><tbody>' +
    "<tr><td>OneDrive accounts</td><td class=\"num\">" + fmtNum(s.od.count) + "</td></tr>" +
    "<tr><td>" + szHdr("OneDrive storage") + "</td><td class=\"num\">" + szGB(s.od.storageBytes) + "</td></tr>" +
    "<tr><td>OneDrive files (millions)</td><td class=\"num\">" + szM(s.od.files) + "</td></tr>" +
    "<tr><td>SharePoint sites</td><td class=\"num\">" + fmtNum(s.sp.count) + "</td></tr>" +
    "<tr><td>" + szHdr("SharePoint storage") + "</td><td class=\"num\">" + szGB(s.sp.storageBytes) + "</td></tr>" +
    "<tr><td>SharePoint files (millions)</td><td class=\"num\">" + szM(s.sp.files) + "</td></tr>" +
    "</tbody></table>";
  html += '<div class="pr-note">Discovery Summary &ndash; Total Users/Accounts: ' + fmtNum(s.licenseEstimate) + ', Total Storage: ' + szGB(s.totalStorageBytes) + " GB" + ', Total Items &amp; Files (millions): ' + szM(s.totalItemsFiles) + '.</div>';
  return html;
}

function buildPrintFullHtml() {
  var model = computeRecoveryModel();
  var totalM = model.milestones[TIER_ORDER[TIER_ORDER.length - 1]];
  var low = computeLowActivitySummary(model);
  var html = buildPrintHeaderHtml("Full Report");
  html += printCostBlockHtml(model);
  html += '<div class="pr-mechanism">ABR restores recently accessed, modified, and created data first &ndash; the data people were actually working on &ndash; so the business is operational in hours, while Mass Recovery continues restoring everything else in the background.</div>';
  html += '<div class="pr-section-title">Mass Recovery vs. ABR: Same Timescale, Different Order</div>';
  html += '<div class="pr-subnote">A Mass Recovery restores everything as one undifferentiated job: nothing forms a complete, usable picture until the whole job is done, ' + fmtMin(model.fullRestoreMin) + ' here. ABR restores the most recently changed data first, so the business is operational in ' + fmtMin(g1.wallClockCumMin) + ".</div>";

  var ins = getInsightsSummary();
  if (ins && ins.excludedCount > 0 && ins.headline) {
    html += '<div class="pr-note"><b>' + fmtNum(ins.excludedCount) + " object(s) are left out of the recovery estimates</b> because they are far larger or heavier than the rest of the tenant. Group 1 recovers in " + fmtMin(ins.headline.excludedG1Min) + " without them and " + fmtMin(ins.headline.includedG1Min) + " with them. See the Recovery Insights tab.</div>";
  }

  html += '<div class="pr-page-break"></div>';
  html += '<div class="pr-section-title">Recovery Times - Per-Group Detail</div>';
  html += '<div class="pr-subnote">ABR (sequenced by group) vs. Mass Recovery (undifferentiated). Mass Recovery for a given group means restoring that same cumulative set of objects (Groups 1 through this one) as a single batch - it converges with ABR only at the full tenant.</div>';
  critKeys().map(function (key, i) { return { label: "Group " + (i + 1), tier: key, subtitle: (i === 0 ? "Recover-first group" : "Cumulative through Group " + (i + 1)) + " (target: " + groupHoursOf(i + 1) + " hr)", m: model.milestones[key] }; }).forEach(function (g, idx) {
    var objCount = g.m.sp.objectCount + g.m.od.objectCount + g.m.ex.objectCount;
    var savingsHrs = Math.max(0, (model.fullRestoreMin - g.m.wallClockCumMin) / 60);
    var exceedsBadge = g.m.exceedsTarget ? '<span class="pr-badge exceeds">Exceeds target</span>' : "";
    var emptyBadge = objCount === 0 ? '<span class="pr-badge empty">Empty</span>' : "";
    html += '<div class="pr-avoid-break">';
    html += '<h4 style="margin:.7rem 0 .1rem;font-size:.85rem;">' + g.label + emptyBadge + exceedsBadge + " - " + fmtNum(objCount) + " objects</h4>";
    html += '<div class="pr-subnote" style="margin-top:0;">' + g.subtitle + "</div>";
    html += '<table class="pr-table"><thead><tr><th></th><th class="num">Time</th></tr></thead><tbody>' +
      '<tr><td>ABR - ' + g.label + ' online in</td><td class="num">' + fmtMin(g.m.wallClockCumMin) + "</td></tr>" +
      '<tr><td>Mass Recovery of the same scope</td><td class="num">~' + fmtMin(g.m.massRecoveryCumMin) + "</td></tr>" +
      "</tbody></table>";
    html += '<div class="pr-note">Hours saved vs. a whole-tenant Mass Recovery: ' + savingsHrs.toFixed(1) + " hr.</div>";
    html += buildStaticBreakdownTableHtml(model, g.tier);
    html += "</div>";
  });
  var totalObjCount = totalM.sp.objectCount + totalM.od.objectCount + totalM.ex.objectCount;
  html += '<div class="pr-avoid-break"><h4 style="margin:.7rem 0 .1rem;font-size:.85rem;">Total (whole tenant, including ' + lowName() + ') - ' + fmtNum(totalObjCount) + " objects</h4>" +
    '<table class="pr-table"><thead><tr><th></th><th class="num">Time</th></tr></thead><tbody>' +
    '<tr><td>ABR - everything online in</td><td class="num">~' + fmtMin(totalM.wallClockCumMin) + "</td></tr>" +
    '<tr><td>Mass Recovery - everything online in</td><td class="num">~' + fmtMin(totalM.massRecoveryCumMin) + "</td></tr>" +
    "</tbody></table>" +
    '<div class="pr-note">These converge here on purpose: recovering everything takes about the same total time either way (same throughput, same data). ABR\'s value is in WHEN each group comes back.</div></div>';

  html += '<div class="pr-page-break"></div>';
  html += '<div class="pr-section-title">' + esc(lowName()) + ' Detail</div>';
  if (low.totalObjectsAll > 0) {
    html += '<div class="pr-subnote"><b>' + low.overallPct + "%</b> of this tenant (" + fmtNum(low.totalGroup4) + " of " + fmtNum(low.totalObjectsAll) + ") falls into " + lowName() + ". " + esc(group4Disclaimer()) + " " + lowName() + " gets no ABR priority and is recovered by Mass Recovery alongside whatever else has not come back yet. Still protected; just not on the critical path to getting the business running again.</div>";
    html += '<table class="pr-table"><thead><tr><th>Workload</th><th class="num">' + esc(lowName()) + '</th><th class="num">Total</th><th class="num">' + esc(lowName()) + ' %</th><th class="num">Mass Recovery (whole workload)</th></tr></thead><tbody>';
    low.byWorkload.slice().sort(function (a, b) { return b.pct - a.pct; }).forEach(function (d) {
      var massCell = d.massRecoveryMin !== null ? fmtMin(d.massRecoveryMin) : "N/A - no independent model";
      html += "<tr><td>" + esc(d.label) + "</td><td class=\"num\">" + fmtNum(d.count) + "</td><td class=\"num\">" + fmtNum(d.total) + "</td><td class=\"num\">" + d.pct + "%</td><td class=\"num\">" + massCell + "</td></tr>";
    });
    html += "</tbody></table>";
  }
  html += '<div class="pr-section-title">Group Overview by Workload</div>';
  html += buildGroupOverviewTableHtml();

  var flagged = (ins && ins.total > 0) ? getInsights().flagged : [];
  if (flagged.length > 0) {
    html += '<div class="pr-page-break"></div><div class="pr-section-title">Recovery Insights: Flagged Objects</div>';
    html += '<div class="pr-subnote">Objects that stand out from the rest of this tenant (compared with the tenant\'s own typical objects). Top 25 shown; see the Recovery Insights tab for the full list.</div>';
    html += '<table class="pr-table"><thead><tr><th>Workload</th><th>Object</th><th>Why flagged</th></tr></thead><tbody>';
    flagged.slice(0, 25).forEach(function (f) {
      html += "<tr><td>" + esc(f.wl) + "</td><td>" + esc((f.row && (f.row.ObjectName || f.row.Identifier)) || "") + "</td><td>" + esc(f.reason || "") + "</td></tr>";
    });
    html += "</tbody></table>";
  }

  html += '<div class="pr-page-break"></div>';
  html += buildAssumptionsHtml();
  html += '<div class="pr-page-break"></div>';
  html += buildSizingPdfHtml();
  return html;
}

function exportPdf(mode) {
  if (IS_PREVIEW || IS_SUMMARY) { window.print(); return; }
  var root = document.getElementById("print-root");
  if (!root) { return; }
  root.innerHTML = mode === "summary" ? buildPrintSummaryHtml() : buildPrintFullHtml();
  var cls = mode === "summary" ? "printing-summary" : "printing-full";
  document.body.classList.add(cls);
  function cleanup() {
    document.body.classList.remove("printing-summary", "printing-full");
    window.removeEventListener("afterprint", cleanup);
  }
  window.addEventListener("afterprint", cleanup);
  // Some browsers do not reliably fire afterprint; clear the print-mode class after a generous timeout regardless.
  setTimeout(cleanup, 20000);
  window.print();
}

// ==================== Changes since last run ====================
function renderCompareTab() {
  if (!DATA.priorRun || IS_PREVIEW || IS_SUMMARY) { return; }
  document.getElementById("compare-tab-btn").style.display = "";
  var moves = [];
  WORKLOAD_DEFS.forEach(function (wd) {
    var priorRows = (DATA.priorRun.workloads && DATA.priorRun.workloads[wd.key]) || [];
    var priorByKey = {};
    priorRows.forEach(function (r) { priorByKey[r.Identifier] = r.Tier; });
    (DATA.workloads[wd.key] || []).forEach(function (row) {
      var priorTier = priorByKey[row.Identifier];
      if (priorTier && priorTier !== row.Tier) {
        moves.push({ workload: wd.label, objectName: row.ObjectName, identifier: row.Identifier, from: priorTier, to: row.Tier });
      } else if (!priorTier) {
        moves.push({ workload: wd.label, objectName: row.ObjectName, identifier: row.Identifier, from: "(new)", to: row.Tier });
      }
    });
  });
  var rows = moves.map(function (m) {
    return "<tr><td>" + esc(m.workload) + "</td><td>" + esc(m.objectName) + "</td><td>" + esc(m.identifier) + "</td><td>" + esc(m.from) + "</td><td>" + esc(m.to) + "</td></tr>";
  }).join("") || '<tr class="no-sort-row"><td colspan="5" style="text-align:center;color:var(--text-muted);padding:2rem;">No group changes since the prior run.</td></tr>';
  var priorLookback = (DATA.priorRun.meta && DATA.priorRun.meta.period) || "";
  var lookbackNote = (priorLookback && priorLookback !== DATA.meta.period)
    ? '<p class="lede">Note: the prior run used a ' + esc(priorLookback) + ' usage lookback and this run uses ' + esc(DATA.meta.period) + ', so some objects may have moved groups only because of the longer window (Group 4 membership in particular).</p>'
    : "";
  document.getElementById("panel-compare").innerHTML = '<h2>Changes Since ' + esc(DATA.priorRun.meta.generatedAt || "prior run") + "</h2>" + lookbackNote +
    '<div class="table-wrap"><table><thead><tr><th>Workload</th><th>Object</th><th>Identifier</th><th>Previously</th><th>Now</th></tr></thead><tbody>' + rows + "</tbody></table></div>";
}

'@

#endregion

#region ---------- HTML report JS: guided tour ----------

<#
    Self-contained, vanilla JS - no external tour library, consistent with
    the report's zero-dependency design. Ported from the Full script's tour
    with one adaptation: this Preview build has no mass-edit-bar (bulk tier
    reassignment is frozen/read-only here, see buildWorkloadSection/buildRowHtml),
    so the "Make Adjustments" step is centered narration rather than a
    spotlight on a control that doesn't exist in this build.

    Rewritten per reviewer feedback (Google Doc "Recovery Assessment Tour
    feedback", 2026-08-28), mirrored from the Full script: open with a
    leader-facing question ("who actually needs to be back up first") to set
    up stakes before diving into numbers; lead the Executive Summary
    walkthrough with the dollar-cost tile rather than the time-to-recover
    tile; replaced the NBA analogy with an evacuation-airlift analogy (one
    manifest ranked by need, not one list per department) split into a
    pure-analogy hook step followed by a mechanics step; rewrote the Group 1
    overview step with named, human examples (the CFO, the legal team)
    while keeping this build's real/unredacted-Group-1 callout; closed by
    tying back to the opening question. Selected phrases use inline <b> tags
    via the "htmlBody" flag below (trusted hand-authored copy, not user
    input) - every other step's body is a plain string still run through
    esc().

    Second feedback pass on the same Google Doc (picked up 2026-08-28, after
    the doc was updated post-first-pass), mirrored from the Full script: the
    Recovery Modeling Inputs step now uses the reviewer's suggested
    customer-facing wording for why the default downtime cost is
    conservative; "Now try something below" -> "Let's adjust the recovery
    target below"; the RTO-targets step's wording was rewritten to be less
    internal/confusing ("you can use our default RTO targets... or fully
    customize them"); and the closing step's title spells out the ABR
    acronym in full ("Why Autonomous Business Recovery Matters") since it's
    never expanded anywhere else in the tour.

    Third feedback item on the same doc (added 2026-08-31): arrow-key
    navigation, matching how presenters already click through Storylane/
    DforD demos - ArrowRight/ArrowLeft call the same tourNext()/tourBack()
    the click-based Next/Back buttons already call, bound only while
    tourState.active (see startTour()/endTour()) and skipped when focus is
    in a form control (see tourKeydownHandler()) so it doesn't hijack the
    "Try It Yourself" step's #group1-target-input number field.

    Two of the recovery-tab steps (Group 1's baseline and post-change object
    count) supply body as a function rather than a string, computed live via
    getGroup1Snapshot() (wraps computeRecoveryModel()) so the numbers always
    match what's actually rendered, and so the "updated" step can show a
    real before/after delta rather than repeating static copy.
#>
$script:ReportJsTour = @'
// getGroup1Snapshot(): reads the live tiering model (not the DOM) for
// Group 1's current object count + RTO target, so the two dynamic tour
// steps below (baseline and "updated") always match whatever
// computeRecoveryModel() would actually render, regardless of what other
// controls (recovery window, license tier, filters) are set at the time.
function getGroup1Snapshot() {
  var model = computeRecoveryModel();
  var m = model.milestones["Critical Group 1"];
  var count = m.sp.objectCount + m.od.objectCount + m.ex.objectCount;
  return { count: count, hours: state.recovery.group1Hours };
}

function tourOpenControls() { if (typeof openAcc === "function") { openAcc("grp-controls-acc"); } }
// v2.0 walkthrough. fullOnly steps are skipped in the Preview (its controls are locked); previewOnly steps are skipped in Full.
var TOUR_STEPS_ALL = [
  { tab: "exec", selector: null, htmlBody: true, title: "Welcome to the Recovery Assessment", body: "<b>If SaaS went down right now, who needs to be back first, and how fast?</b> This overview answers that. We will <b>come back to the Executive Summary</b> at the end, once we have shown how every number on it is built." },

  { tab: "groups", fullOnly: true, before: tourOpenControls, selector: "#scoring-panel", htmlBody: true, title: "Step 1: Live Scoring Controls", body: "We <b>stack-rank every user and site</b> by how much they use M365 to do their job: mail, files, pages, meetings. The more someone uses it, the more important it is to their role. Job titles and other signals add to the score. <b>Change a weight and everything recomputes.</b>" },
  { tab: "groups", fullOnly: true, before: tourOpenControls, selector: "#recovery-inputs-panel", htmlBody: true, title: "Step 2: Recovery Modeling", body: "<b>How many days back do we restore in the first pass?</b> The default is 7 days of recent data. Add your <b>downtime cost per hour</b> and the hours saved turn into cost avoided." },
  { tab: "groups", fullOnly: true, before: tourOpenControls, selector: "#rto-panel", htmlBody: true, title: "Step 3: The Recovery Window (RTO)", body: "<b>This is the window of time you have to recover as many objects and items as possible.</b> We cut the ranked list to fit inside it. A <b>larger window fits more objects</b> into each group; a tighter window keeps the group small." },
  { tab: "groups", fullOnly: true, before: tourOpenControls, selector: "#grp-headline", title: "Group 1, By the Numbers",
    body: function () {
      var snap = getGroup1Snapshot();
      tourState.g1Before = snap;
      return "Right now <b>" + fmtNum(snap.count) + " objects</b> fit inside Group 1's <b>" + snap.hours + "-hour</b> Recovery Window. Try changing the window and watch the count move.";
    }
  },
  { tab: "groups", fullOnly: true, before: tourOpenControls, selector: "#group1-target-input", title: "Try It Yourself", body: "Change the Group 1 Recovery Window, then back again. A bigger window fits more objects in Group 1. Click Continue when you are ready.", manualAdvance: true },
  { tab: "groups", fullOnly: true, selector: "#grp-headline", title: "Group 1, Updated",
    body: function () {
      var before = tourState.g1Before;
      var after = getGroup1Snapshot();
      if (!before) { return "Group 1 now has <b>" + fmtNum(after.count) + " objects</b> at a " + after.hours + "-hour window."; }
      var delta = after.count - before.count, abs = Math.abs(delta);
      var verb = delta > 0 ? "an increase" : (delta < 0 ? "a decrease" : "no change");
      return "You moved the window from " + before.hours + " hr to " + after.hours + " hr. Group 1 went from <b>" + fmtNum(before.count) + "</b> to <b>" + fmtNum(after.count) + "</b> objects, " + verb + " of <b>" + fmtNum(abs) + "</b>.";
    }
  },
  { tab: "groups", previewOnly: true, before: tourOpenControls, selector: "#grp-controls", htmlBody: true, title: "How Group 1 Was Built", body: "Every user and site is ranked by how much they use M365, then the ranked list is cut to fit the Recovery Window. These settings are <b>locked in the Preview</b>; the full assessment lets you change them." },
  { tab: "groups", previewOnly: true, selector: "#grp-headline", title: "Group 1 at a Glance", body: "The users and sites that fit inside the Group 1 Recovery Window, and how soon they are back." },

  { tab: "report", selector: "#report-by-group", htmlBody: true, title: "Recovery by Group", body: "Each group's objects, storage and <b>time to critical data</b>, against how long a full restore takes." },
  { tab: "report", selector: "#report-calendar", htmlBody: true, title: "If Recovery Started Today", body: "<b>Look ahead from today.</b> Which projects, launches or audits fall inside the outage? Would they be affected?" },
  { tab: "report", selector: "#report-g1list", htmlBody: true, title: "Who Is in Group 1", body: "<b>The people and sites your business runs on.</b> Review the list with the business owners, then use the Group 1 list to move anyone who belongs elsewhere." },

  { tab: "exec", selector: "#exec-fast", title: "Critical Data Back", body: "How fast your most critical users are back, versus a full restore." },
  { tab: "exec", selector: "#exec-worth", htmlBody: true, title: "Downtime Avoided", body: "Hours saved reaching Group 1 first. <b>Enter your hourly downtime cost</b> to see cost avoided." },
  { tab: "exec", selector: "#exec-concentration", title: "Why Order Matters", body: "The share of objects that carries most of the storage and recent activity." },
  { tab: "exec", selector: "#exec-ladder", title: "The Recovery Timeline", body: "Critical, Important and Standard users come back in order. Group 4 and the older data finish with mass recovery." },
  { tab: "exec", selector: null, htmlBody: true, title: "That Is the Whole Picture", body: "<b>Critical data back in hours, everything else by mass recovery.</b> Use the tour icon in the toolbar to run this again.", isFinal: true }
];
var TOUR_STEPS = TOUR_STEPS_ALL.filter(function (st) { return !((IS_PREVIEW && st.fullOnly) || (!IS_PREVIEW && st.previewOnly)); });

var tourState = { active: false, stepIndex: 0, g1Before: null };

function tourStorageAvailable() {
  try {
    var k = "__m365TourTest__";
    window.localStorage.setItem(k, "1");
    window.localStorage.removeItem(k);
    return true;
  } catch (e) { return false; }
}

function tourShouldAutoShowWelcome() {
  if (!tourStorageAvailable()) { return true; }
  try { return window.localStorage.getItem("m365TourDontShow") !== "1"; } catch (e) { return true; }
}

function showTourWelcome() {
  if (document.getElementById("tour-welcome-backdrop")) { return; }
  var backdrop = document.createElement("div");
  backdrop.className = "tour-welcome-backdrop";
  backdrop.id = "tour-welcome-backdrop";
  backdrop.innerHTML =
    '<div class="tour-welcome-card">' +
      '<div class="tour-welcome-title">Take a 2-minute tour?</div>' +
      '<div class="tour-welcome-body">We\'ll walk through how this report prioritizes recovery - starting with how users are scored, then the Recovery Window, then who is in Group 1, and finally how it rolls up into the Executive Summary.</div>' +
      '<div class="tour-welcome-actions">' +
        '<button class="tour-btn tour-btn-primary" onclick="closeTourWelcome(); startTour();">Start Tour</button>' +
        '<button class="tour-btn tour-btn-secondary" onclick="closeTourWelcome();">Skip for now</button>' +
      "</div>" +
      '<label class="tour-welcome-dontshow"><input type="checkbox" id="tour-dontshow-checkbox"> Don\'t show this again</label>' +
    "</div>";
  document.body.appendChild(backdrop);
}

function closeTourWelcome() {
  var cb = document.getElementById("tour-dontshow-checkbox");
  if (cb && cb.checked) {
    try { window.localStorage.setItem("m365TourDontShow", "1"); } catch (e) {}
  }
  var el = document.getElementById("tour-welcome-backdrop");
  if (el) { el.parentNode.removeChild(el); }
}

function startTour() {
  tourState.active = true;
  tourState.stepIndex = 0;
  document.addEventListener("keydown", tourKeydownHandler);
  renderTourStep();
}

function endTour() {
  tourState.active = false;
  document.removeEventListener("keydown", tourKeydownHandler);
  ["tour-spotlight", "tour-tooltip", "tour-overlay-backdrop"].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) { el.parentNode.removeChild(el); }
  });
}

// Arrow-key navigation, per feedback: presenters using Storylane/
// DforD are used to clicking through with the keyboard, so mirror that here
// rather than requiring a mouse click on Next/Back every step. Skipped
// entirely when focus is in a form control (specifically the "Try It
// Yourself" step's #group1-target-input number field) so arrow keys there
// still move the cursor/adjust the value instead of being hijacked to
// advance or rewind the tour. Click-based Next/Back are untouched - both
// paths call the same tourNext()/tourBack() functions.
function tourKeydownHandler(e) {
  if (!tourState.active) { return; }
  var active = document.activeElement;
  var tag = active && active.tagName ? active.tagName.toUpperCase() : "";
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (active && active.isContentEditable)) { return; }
  if (e.key === "ArrowRight") { e.preventDefault(); tourNext(); }
  else if (e.key === "ArrowLeft") { e.preventDefault(); tourBack(); }
}

function tourNext() {
  if (tourState.stepIndex >= TOUR_STEPS.length - 1) { endTour(); return; }
  tourState.stepIndex++;
  renderTourStep();
}

function tourBack() {
  if (tourState.stepIndex <= 0) { return; }
  tourState.stepIndex--;
  renderTourStep();
}

function renderTourStep() {
  var step = TOUR_STEPS[tourState.stepIndex];
  if (!step) { endTour(); return; }
  if (step.tab) { switchTab(step.tab); }
  if (typeof step.before === "function") { step.before(); }
  // Give the tab switch (and whatever it re-renders) one tick before
  // measuring positions, so getBoundingClientRect reflects the new tab's
  // real layout rather than the previous tab's now-hidden one.
  setTimeout(function () { paintTourStep(step); }, 60);
}

// Placement helpers: keep the tooltip beside the spotlighted data (right, then left), above it when there is
// no side room, and only below / pinned as a last resort, so it does not cover what is being explained.
function tourTabBottom() {
  var tb = document.querySelector(".tabbar");
  return tb ? Math.max(0, tb.getBoundingClientRect().bottom) + 8 : 8;
}
function tourScrollTo(target) {
  var r = target.getBoundingClientRect();
  var top0 = tourTabBottom(), vh = window.innerHeight;
  var dy;
  if (r.height > vh * 0.6) { dy = r.top - top0 - 4; }            // tall panel: show its top, just under the tab bar
  else { dy = r.top - (top0 + (vh - top0 - r.height) / 2); }      // otherwise center it in the visible area
  window.scrollTo({ top: Math.max(0, window.scrollY + dy), behavior: "auto" });
}
function tourVisibleRect(target) {
  var r = target.getBoundingClientRect();
  var top = Math.max(r.top, tourTabBottom()), bottom = Math.min(r.bottom, window.innerHeight - 8);
  if (bottom <= top) { bottom = top + Math.min(r.height, 160); }
  return { top: top, bottom: bottom, left: r.left, right: r.right, width: r.width, height: bottom - top };
}
function tourPlaceTooltip(vr, tooltip) {
  var ttr = tooltip.getBoundingClientRect(), w = ttr.width, h = ttr.height, m = 12, gap = 16;
  var tabB = tourTabBottom(), vw = window.innerWidth, vh = window.innerHeight;
  function clampTop(v) { return Math.min(Math.max(v, tabB), vh - h - m); }
  function clampLeft(v) { return Math.min(Math.max(v, m), vw - w - m); }
  var pos = null;
  if (vw - vr.right - gap - m >= w) { pos = { top: clampTop(vr.top), left: vr.right + gap }; }                       // beside, right
  else if (vr.left - gap - m >= w) { pos = { top: clampTop(vr.top), left: vr.left - gap - w }; }                     // beside, left
  else if (vr.top - tabB - gap >= h) { pos = { top: vr.top - gap - h, left: clampLeft(vr.left) }; }                  // above
  else if (vh - vr.bottom - gap - m >= h) { pos = { top: vr.bottom + gap, left: clampLeft(vr.left) }; }              // below
  else { pos = { top: vh - h - m, left: vw - w - m }; }                                                              // last resort: bottom-right corner
  tooltip.style.top = pos.top + "px";
  tooltip.style.left = pos.left + "px";
}

function paintTourStep(step) {
  if (!tourState.active) { return; }
  var backdrop = document.getElementById("tour-overlay-backdrop");
  if (!backdrop) {
    backdrop = document.createElement("div");
    backdrop.className = "tour-overlay-backdrop";
    backdrop.id = "tour-overlay-backdrop";
    document.body.appendChild(backdrop);
  }

  var target = step.selector ? document.querySelector(step.selector) : null;
  var spotlight = document.getElementById("tour-spotlight");
  if (target) {
    // A spotlighted step already dims everything OUTSIDE the target via
    // .tour-spotlight's own box-shadow, so the plain backdrop stays
    // transparent here - only the no-target ("centered") branch below needs
    // the whole-page dim+blur.
    backdrop.classList.remove("dimmed");
    tourScrollTo(target);
    var rect = tourVisibleRect(target);
    if (!spotlight) {
      spotlight = document.createElement("div");
      spotlight.id = "tour-spotlight";
      spotlight.className = "tour-spotlight";
      document.body.appendChild(spotlight);
    }
    var pad = 8;
    spotlight.style.display = "block";
    spotlight.style.top = (rect.top - pad) + "px";
    spotlight.style.left = (rect.left - pad) + "px";
    spotlight.style.width = (rect.width + pad * 2) + "px";
    spotlight.style.height = (rect.height + pad * 2) + "px";
  } else {
    if (spotlight) { spotlight.style.display = "none"; }
    // NEW: no specific target for this step (the welcome/analogy/closing
    // steps) - dim+blur the whole page behind the centered tooltip instead
    // of leaving it fully visible, so there's nothing pulling attention away
    // from text that isn't about what's on screen right now.
    backdrop.classList.add("dimmed");
  }

  var tooltip = document.getElementById("tour-tooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.id = "tour-tooltip";
    tooltip.className = "tour-tooltip";
    document.body.appendChild(tooltip);
  }

  var isLast = tourState.stepIndex === TOUR_STEPS.length - 1;
  var nextLabel = step.manualAdvance ? "Continue" : (isLast ? "Done" : "Next");
  var backBtn = tourState.stepIndex > 0 ? '<button class="tour-btn tour-btn-secondary" onclick="tourBack()">Back</button>' : "<span></span>";
  // Dynamic steps (Group 1's baseline/updated object count) supply body as a
  // function that reads live tiering state and returns pre-built HTML (bold
  // tags around the numbers) - trusted since it's our own generated markup,
  // not user input, so it skips esc() unlike the hard-coded string steps.
  // step.htmlBody: true marks a small set of hand-authored static strings
  // that intentionally include <b> tags around key phrases (reviewer
  // feedback asked for bolded concepts on the analogy/human-framing steps)
  // - trusted since it's hardcoded copy we wrote, not user input. Every
  // other string step is still run through esc() as before.
  var bodyHtml = typeof step.body === "function" ? step.body() : (step.htmlBody ? step.body : esc(step.body));
  var restartBtn = step.isFinal ? '<button class="tour-btn tour-btn-secondary" onclick="startTour()">Restart Tour</button>' : "";

  tooltip.innerHTML =
    '<div class="tour-tooltip-step">Step ' + (tourState.stepIndex + 1) + " of " + TOUR_STEPS.length + '</div>' +
    '<div class="tour-tooltip-title">' + esc(step.title) + '</div>' +
    '<div class="tour-tooltip-body">' + bodyHtml + '</div>' +
    '<div class="tour-tooltip-actions">' +
      backBtn +
      '<span style="display:flex;gap:.6rem;align-items:center;">' +
        restartBtn +
        '<button class="tour-skip" onclick="endTour()">Skip tour</button>' +
        '<button class="tour-btn tour-btn-primary" onclick="tourNext()">' + nextLabel + "</button>" +
      "</span>" +
    "</div>";

  if (!target) {
    tooltip.classList.add("centered");
    tooltip.style.top = "";
    tooltip.style.left = "";
  } else {
    tooltip.classList.remove("centered");
    tourPlaceTooltip(tourVisibleRect(target), tooltip);
  }
}

// Separate DOMContentLoaded listener from the main bootstrap one below -
// multiple listeners on the same event coexist fine, and this keeps the
// tour fully independent of (and safely removable from) recomputeAll()'s
// own startup sequence.
document.addEventListener("DOMContentLoaded", function () {
  if (tourShouldAutoShowWelcome()) {
    setTimeout(showTourWelcome, 500);
  }
});
'@

#endregion

#region ---------- HTML report JS: overrides export/import, tabs, bootstrap ----------

$script:ReportJsBootstrap = @'
function recomputeAll() {
  WORKLOAD_DEFS.forEach(function (wd) { computeScoresAndTiers(wd.key); });
  if (typeof computeInsights === "function") { computeInsights(); }
  renderHeaderExtras();
  renderModeChrome();
  // v2.0: the old Recovery tab was merged into "Groups & Recovery Model" (groups), and a new
  // "Recovery Insights" tab was added. Steps are looked up by name so a build that does not include a
  // given renderer (e.g. a Summary-only build) still runs.
  ["renderExecLean", "renderExecSummary", "renderPlaybookTab", "renderGroupsTab", "renderInsightsTab", "renderMethodologyTab", "renderSizingTab", "renderCompareTab"].forEach(function (name) {
    if (typeof window[name] === "function") { window[name](); }
  });
  enhanceTables(document);
  if (!IS_PREVIEW && !IS_SUMMARY) { saveOverridesToStorage(); }
}

// Preview: banner + hide full-only toolbar items. Summary: nothing extra here.
function renderModeChrome() {
  var banner = document.getElementById("pv-banner");
  if (banner) { banner.innerHTML = (IS_PREVIEW ? previewBannerHtml() : "") + offlineBannerHtml(); }
  document.body.classList.toggle("is-preview", IS_PREVIEW);
  document.body.classList.toggle("is-summary", IS_SUMMARY);
  Array.prototype.forEach.call(document.querySelectorAll(".full-only"), function (el) { el.style.display = (IS_PREVIEW || IS_SUMMARY) ? "none" : ""; });
  var note = document.getElementById("footer-note");
  if (note && IS_PREVIEW) {
    note.innerHTML = 'Preview build: figures are for Critical Group 1 and the whole-tenant baseline only. Scoring weights, keywords, and recovery targets are shown for transparency and are locked. <a href="' + CONTACT_SALES_URL + '" target="_blank" rel="noopener">Contact your Rubrik representative</a> to run the full assessment.';
  }
}

function exportOverrides() {
  var out = Object.keys(state.overrides).map(function (key) {
    var parts = key.split("|");
    var o = state.overrides[key];
    return { Workload: parts[0], Identifier: parts.slice(1).join("|"), Tier: o.tier, Reason: o.reason, SetBy: o.setBy, Timestamp: o.timestamp };
  });
  var blob = new Blob([JSON.stringify(out, null, 2)], { type: "application/json" });
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "overrides_" + DATA.meta.runId + ".json";
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

function importOverridesFile(input) {
  var file = input.files[0];
  if (!file) { return; }
  var reader = new FileReader();
  reader.onload = function (e) {
    try {
      var items = JSON.parse(e.target.result);
      items.forEach(function (o) {
        state.overrides[o.Workload + "|" + o.Identifier] = { tier: o.Tier, reason: o.Reason || "", setBy: o.SetBy || "imported", timestamp: o.Timestamp || "" };
      });
      recomputeAll();
      alert("Imported " + items.length + " overrides.");
    } catch (err) { alert("Could not parse that file as overrides JSON: " + err.message); }
  };
  reader.readAsText(file);
}

function csvEscapeCell(val) {
  var s = (val === null || val === undefined) ? "" : String(val);
  // RFC 4180 quoting: only wrap in quotes (doubling any internal quotes)
  // when the value actually contains something that would otherwise break
  // a naive comma-split - most cells (numbers, tiers, dates) never hit this.
  if (/[",\r\n]/.test(s)) { return '"' + s.replace(/"/g, '""') + '"'; }
  return s;
}

function rowsToCsv(rows, columns) {
  var lines = [columns.join(",")];
  rows.forEach(function (row) {
    lines.push(columns.map(function (c) { return csvEscapeCell(row[c]); }).join(","));
  });
  // CRLF - the CSV spec default, and what Excel expects without having to
  // guess at line-ending/encoding on Windows.
  return lines.join("\r\n");
}

// buildCriticalityGroupsCsvText(): the actual list-every-object-in-every-
// group export. Reads DATA.workloads directly (not the capped/filtered
// renderedRows a workload's table currently shows), and reads row.Tier -
// which computeScoresAndTiers() already resolves to the FINAL effective
// tier (manual override if one is set, otherwise the computed tier, see
// computeScoresAndTiers) - so this always reflects the live, on-screen
// state of the report at export time, including anything an SE or customer
// has manually reassigned via the tier dropdown or a mass-reassignment,
// not just what the report looked like when the underlying PowerShell
// script originally ran. Intended as the hand-off point for a downstream
// script (e.g. one that calls RSC to create/update criticality groups from
// this list) - kept as a pure string-builder, separate from
// exportCriticalityGroupsCsv()'s actual file-download side effect, so it's
// straightforward to unit test.
function buildCriticalityGroupsCsvText() {
  var columns = ["Workload", "Tier", "ObjectName", "Identifier", "Overridden", "OverrideReason", "ScorePct", "ItemCount", "ItemType", "StorageAmount", "StorageUnit", "JobTitle", "Department", "Manager", "EntraGroups", "LastActivityDate", "CriteriaTags"];
  var rows = [];
  WORKLOAD_DEFS.forEach(function (wd) {
    var wdRows = DATA.workloads[wd.key] || [];
    wdRows.forEach(function (row) {
      var tierMeta = TIER_META[row.Tier];
      rows.push({
        _tierIdx: TIER_ORDER.indexOf(row.Tier),
        Workload: wd.label,
        Tier: tierMeta ? tierMeta.short : row.Tier,
        ObjectName: row.ObjectName || "",
        Identifier: row.Identifier || "",
        Overridden: row.IsOverride ? "Yes" : "No",
        OverrideReason: row.IsOverride ? (row.OverrideReason || "") : "",
        ScorePct: Math.round((row._Score || 0) * 100),
        ItemCount: (row.metrics && row.metrics[wd.itemField] != null) ? row.metrics[wd.itemField] : "",
        ItemType: wd.itemLabel,
        StorageAmount: (wd.storageField && row.metrics) ? (parseFloat(row.metrics[wd.storageField]) || 0).toFixed(2) : "",
        StorageUnit: wd.storageField ? wd.storageLabel.replace(/^Storage \(|\)$/g, "") : "",
        JobTitle: row.JobTitle || "",
        Department: row.Department || "",
        Manager: row.Manager || "",
        EntraGroups: (row.Groups || []).join("; "),
        LastActivityDate: row.LastActivityDate || "",
        CriteriaTags: row.CriteriaTags || ""
      });
    });
  });
  // Group 1 first, then 2/3/4, matching how the rest of the report always
  // orders priority; within a tier, group by workload, then highest score
  // first (mirrors the per-workload table's own default sort).
  rows.sort(function (a, b) {
    if (a._tierIdx !== b._tierIdx) { return a._tierIdx - b._tierIdx; }
    if (a.Workload !== b.Workload) { return a.Workload < b.Workload ? -1 : 1; }
    return b.ScorePct - a.ScorePct;
  });
  return rowsToCsv(rows, columns);
}

function exportCriticalityGroupsCsv() {
  var csv = buildCriticalityGroupsCsvText();
  var blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "CriticalityGroups_" + DATA.meta.runId + ".csv";
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

function switchTab(tabKey) {
  document.querySelectorAll(".tab-btn").forEach(function (b) { b.classList.toggle("active", b.getAttribute("data-tab") === tabKey); });
  document.querySelectorAll(".tab-panel").forEach(function (p) { p.classList.toggle("active", p.getAttribute("data-tab-panel") === tabKey); });
}

// NEW v3.6.0: generic collapsed-by-default section toggle (first use: the
// Dormant Data section at the bottom of the Report tab). Reusable for any
// future .exec-collapsible block - just needs onclick="toggleCollapsible(this)"
// on the header button, with the collapsible content as its next sibling.
function toggleCollapsible(btn) {
  var body = btn.nextElementSibling;
  if (!body) { return; }
  var expanded = btn.getAttribute("aria-expanded") === "true";
  btn.setAttribute("aria-expanded", expanded ? "false" : "true");
  if (expanded) { body.setAttribute("hidden", ""); } else { body.removeAttribute("hidden"); }
}

function sortTable(tableId, colIndex, isNumeric) {
  var table = document.getElementById(tableId);
  if (!table) { return; }
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);
  var asc = table.getAttribute("data-sort-col") != colIndex || table.getAttribute("data-sort-dir") !== "asc";
  rows.sort(function (a, b) {
    var av = a.cells[colIndex].textContent, bv = b.cells[colIndex].textContent;
    if (isNumeric) { av = parseFloat(av) || 0; bv = parseFloat(bv) || 0; return asc ? av - bv : bv - av; }
    av = (av || "").toLowerCase(); bv = (bv || "").toLowerCase();
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(function (r) { tbody.appendChild(r); });
  table.setAttribute("data-sort-col", colIndex);
  table.setAttribute("data-sort-dir", asc ? "asc" : "desc");
}

document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".tab-btn").forEach(function (b) {
    b.addEventListener("click", function () { switchTab(b.getAttribute("data-tab")); });
  });
  initGroupCount();
  recomputeAll();
});

// NEW: presenter pass - re-check scroll affordances (fade/hint) on resize,
// since a presenter may resize the browser window live in front of a
// customer and the tables may go from overflowing to not (or vice versa).
window.addEventListener("resize", function () {
  clearTimeout(window.__m365ResizeTimer);
  window.__m365ResizeTimer = setTimeout(function () {
    WORKLOAD_DEFS.forEach(function (wd) {
      if (typeof refreshScrollAffordance === "function") { refreshScrollAffordance(wd.key); }
    });
  }, 150);
});
'@

#endregion

#region ---------- HTML report: logos + assembly ----------

# Rubrik logo, reverse/white variant - for the navy header band.
$script:RubrikLogoSvg = @'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 720 300"><defs><style>.cls-1{fill:url(#linear-gradient);}.cls-1,.cls-2{stroke-width:0px;}.cls-2{fill:#fff;}</style><linearGradient id="linear-gradient" x1="142.24" y1="102.37" x2="237.37" y2="197.51" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#00b287"/><stop offset=".04" stop-color="#01b28c"/><stop offset=".34" stop-color="#0bb6b9"/><stop offset=".62" stop-color="#12b9d9"/><stop offset=".84" stop-color="#17bbec"/><stop offset="1" stop-color="#19bcf4"/></linearGradient></defs><path class="cls-1" d="m166.23,176.47v16.98c0,1.63-1.34,2.97-2.97,2.97h-16.99c-1.63,0-2.97-1.34-2.97-2.97v-16.98c0-1.63,1.34-2.97,2.97-2.97h16.99c1.64,0,2.97,1.34,2.97,2.97Zm-2.1,23.01l-8.38,8.37c-1.16,1.15-.92,2.73.52,3.51l7.22,3.41c1.51.63,2.75-.2,2.75-1.83v-12.59c0-1.64-.95-2.03-2.1-.87Zm-37.36-73.09h12.6c1.64,0,2.03-.95.87-2.1l-8.38-8.37c-1.16-1.15-2.73-.92-3.51.52l-3.41,7.21c-.63,1.51.2,2.74,1.83,2.74Zm37,25.65c1.16-1.16,1.16-3.05,0-4.2l-18.84-18.82c-1.16-1.16-3.05-1.16-4.2,0l-18.85,18.83c-1.16,1.16-1.16,3.05,0,4.2l18.85,18.83c1.16,1.16,3.05,1.16,4.2,0l18.84-18.83Zm76.48-25.65h12.6c1.63,0,2.46-1.23,1.83-2.75l-3.42-7.21c-.77-1.44-2.35-1.67-3.51-.52l-8.38,8.37c-1.16,1.16-.76,2.1.87,2.1Zm-23.89,0h16.99c1.63,0,2.97-1.34,2.97-2.97v-16.98c0-1.63-1.34-2.97-2.97-2.97h-16.99c-1.64,0-2.97,1.34-2.97,2.97v16.98c0,1.63,1.34,2.97,2.97,2.97Zm-.87-25.98l8.38-8.37c1.16-1.15.92-2.73-.52-3.51l-7.22-3.41c-1.51-.63-2.75.2-2.75,1.83v12.59c0,1.63.95,2.03,2.1.87Zm-76.12,73.09h-12.6c-1.63,0-2.46,1.23-1.83,2.74l3.41,7.21c.77,1.44,2.35,1.67,3.51.52l8.38-8.37c1.16-1.15.76-2.1-.87-2.1Zm113.48,0h-12.6c-1.63,0-2.03.95-.87,2.1l8.38,8.37c1.16,1.15,2.74.92,3.51-.52l3.42-7.21c.62-1.51-.2-2.74-1.83-2.74Zm-19.51,0h-16.99c-1.64,0-2.97,1.34-2.97,2.97v16.98c0,1.63,1.34,2.97,2.97,2.97h16.99c1.63,0,2.97-1.34,2.97-2.97v-16.98c0-1.63-1.34-2.97-2.97-2.97Zm24.4-25.66l-18.84-18.82c-1.16-1.16-3.05-1.16-4.21,0l-18.85,18.83c-1.16,1.16-1.16,3.05,0,4.2l18.85,18.83c1.16,1.16,3.05,1.16,4.21,0l18.84-18.83c1.16-1.16,1.16-3.05,0-4.2Zm-42.26,51.64c-1.16-1.16-2.1-.77-2.1.87v12.59c0,1.63,1.24,2.46,2.75,1.83l7.22-3.41c1.44-.77,1.67-2.35.52-3.51l-8.38-8.37Zm-23.57-117.41c-1.16-1.16-3.05-1.16-4.21,0l-18.85,18.83c-1.16,1.15-1.16,3.05,0,4.2l18.85,18.83c1.16,1.16,3.05,1.16,4.21,0l18.84-18.83c1.16-1.15,1.16-3.05,0-4.2l-18.84-18.83Zm-28.43,3.06l-7.22,3.41c-1.44.77-1.67,2.35-.52,3.51l8.38,8.37c1.16,1.15,2.1.76,2.1-.87v-12.59c0-1.64-1.23-2.46-2.75-1.83Zm-.23,18.35h-16.99c-1.63,0-2.97,1.34-2.97,2.97v16.98c0,1.63,1.34,2.97,2.97,2.97h16.99c1.64,0,2.97-1.34,2.97-2.97v-16.98c0-1.63-1.34-2.97-2.97-2.97Zm28.66,72.62c-1.16-1.16-3.05-1.16-4.21,0l-18.85,18.83c-1.16,1.16-1.16,3.04,0,4.2l18.85,18.82c1.16,1.15,3.05,1.15,4.21,0l18.84-18.82c1.16-1.16,1.16-3.05,0-4.2l-18.84-18.83Z"/><path class="cls-2" d="m508.9,127.79c0,.42-.42,1.25-.98,2.36-.28.53-.55,1.05-.83,1.57-.43.81-.79,1.68-1.36,2.4-.24.3-.52.58-.87.74-.35.15-.75.06-1.1-.05-.94-.32-1.82-.65-2.81-.79-4.25-.59-8.85,1.33-10.96,5.17-1.53,2.78-2.23,6.95-2.23,13.9v26.83c0,3.2-.42,3.61-3.62,3.61h-2.64c-3.2,0-3.62-.42-3.62-3.61v-50.46c0-3.2.42-3.61,3.62-3.61h2.64c3.2,0,3.62.42,3.62,3.61v2.64c5.14-6.12,7.65-7.65,13.2-7.65,4.31,0,8.06,1.53,7.93,3.34Zm-183.58-3.34c-5.56,0-8.06,1.53-13.2,7.65v-2.64c0-3.2-.42-3.61-3.62-3.61h-2.64c-3.2,0-3.61.42-3.61,3.61v50.46c0,3.2.42,3.61,3.61,3.61h2.64c3.2,0,3.62-.42,3.62-3.61v-26.83c0-6.95.69-11.12,2.22-13.9,2.11-3.84,6.71-5.76,10.96-5.17.99.14,1.87.47,2.81.79.35.12.75.21,1.1.05.35-.16.63-.44.87-.74.56-.72.93-1.6,1.36-2.4.27-.52.55-1.04.83-1.57.56-1.11.97-1.95.97-2.36.14-1.81-3.61-3.34-7.92-3.34Zm60.84,1.39h-2.64c-3.2,0-3.61.42-3.61,3.61v30.03c0,5.42-.56,8.34-1.81,10.84-1.95,3.61-6.25,5.84-11.12,5.84s-9.31-2.22-11.26-5.84c-1.25-2.5-1.81-5.42-1.81-10.84v-30.03c0-3.2-.42-3.61-3.62-3.61h-2.64c-3.2,0-3.61.42-3.61,3.61v31.14c0,8.48,1.39,13.07,5.28,17.37,4.17,4.73,10.42,7.23,17.65,7.23s13.35-2.5,17.52-7.23c3.89-4.31,5.28-8.9,5.28-17.37v-31.14c0-3.2-.42-3.61-3.61-3.61Zm77.35,28.77c0,17.66-11.82,30.58-27.8,30.58-8.06,0-14.46-3.06-19.88-9.59v4.31c0,3.2-.42,3.61-3.62,3.61h-2.64c-3.2,0-3.62-.42-3.62-3.61v-94.11c0-3.2.42-3.61,3.62-3.61h2.64c3.2,0,3.62.42,3.62,3.61v48.24c5.7-6.53,11.82-9.45,20.15-9.45,15.85,0,27.52,12.65,27.52,30.02Zm-10.15-.28c0-11.67-8.2-20.71-19.04-20.71s-19.18,8.62-19.18,20.99,7.93,21.55,19.32,21.55,18.9-9.18,18.9-21.83Zm74.67-28.49h-2.64c-3.19,0-3.61.42-3.61,3.61v50.46c0,3.2.42,3.61,3.61,3.61h2.64c3.2,0,3.62-.42,3.62-3.61v-50.46c0-3.2-.42-3.61-3.62-3.61Zm-1.25-28.91c-3.89,0-7.09,3.2-7.09,6.95,0,4.03,3.2,7.23,7.09,7.23s7.09-3.2,7.09-7.09-3.2-7.09-7.09-7.09Zm42.6,53.52l19.88-19.88c1.11-1.11,1.67-1.95,1.67-2.5,0-1.53-.97-2.22-3.47-2.22h-4.31q-2.36,0-4.03,1.67l-19.18,19.6v-61.3c0-3.2-.42-3.61-3.61-3.61h-2.64c-3.2,0-3.62.42-3.62,3.61v94.11c0,3.2.42,3.61,3.62,3.61h2.64c3.19,0,3.61-.42,3.61-3.61v-20.16l2.5-2.5,21.69,24.46q1.53,1.81,4.03,1.81h4.31c2.5,0,3.62-.7,3.62-2.09,0-.55-.56-1.39-1.53-2.64l-25.16-28.36Zm30.34-21.71c0,1.6-1.25,2.85-2.88,2.85s-2.89-1.25-2.89-2.85,1.28-2.81,2.89-2.81,2.88,1.25,2.88,2.81Zm-.72.02c0-1.25-.91-2.26-2.16-2.26s-2.17,1.01-2.17,2.24.92,2.24,2.19,2.24,2.14-.99,2.14-2.23Zm-.99.75c.08.43.14.6.21.7h-.7c-.09-.1-.14-.36-.22-.69-.05-.31-.22-.44-.58-.44h-.31v1.13h-.65v-2.81c.26-.05.62-.09,1.08-.09.53,0,.77.09.98.21.15.12.27.34.27.62,0,.31-.24.55-.58.65v.03c.27.1.43.31.52.68Zm-.63-1.3c0-.26-.19-.43-.6-.43-.17,0-.29.02-.36.03v.81h.31c.36,0,.65-.12.65-.41Z"/></svg>
'@

# Rubrik brandmark (icon only) - favicon.
$script:RubrikBrandmarkSvg = @'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 720 720"><defs><style>.cls-1{fill:url(#linear-gradient);stroke-width:0px;}</style><linearGradient id="linear-gradient" x1="1005.62" y1="-257.45" x2="1351.35" y2="-603.17" gradientTransform="translate(-63.62 -815.87) rotate(90)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#00b287"/><stop offset=".26" stop-color="#08b5ab"/><stop offset=".58" stop-color="#11b8d2"/><stop offset=".84" stop-color="#16bbeb"/><stop offset="1" stop-color="#19bcf4"/></linearGradient></defs><path class="cls-1" d="m281.02,459.01v61.7c0,5.92-4.84,10.8-10.8,10.8h-61.73c-5.95,0-10.8-4.88-10.8-10.8v-61.7c0-5.92,4.88-10.8,10.8-10.8h61.73c5.95,0,10.8,4.84,10.8,10.8Zm-7.65,83.6l-30.45,30.42c-4.19,4.19-3.36,9.93,1.87,12.73l26.23,12.39c5.5,2.28,9.97-.73,9.97-6.64v-45.75c0-5.95-3.43-7.37-7.65-3.15h.03Zm-135.75-265.58h45.78c5.95,0,7.37-3.43,3.15-7.65l-30.45-30.42c-4.19-4.19-9.93-3.36-12.73,1.87l-12.42,26.19c-2.28,5.5.73,9.97,6.64,9.97l.03.03Zm134.43,93.22c4.19-4.19,4.19-11.07,0-15.26l-68.45-68.41c-4.19-4.19-11.07-4.19-15.26,0l-68.51,68.41c-4.19,4.19-4.19,11.07,0,15.26l68.51,68.41c4.19,4.19,11.07,4.19,15.26,0,0,0,68.45-68.41,68.45-68.41Zm277.9-93.22h45.78c5.95,0,8.93-4.5,6.68-9.97l-12.42-26.19c-2.8-5.23-8.55-6.06-12.77-1.87l-30.45,30.42c-4.19,4.19-2.77,7.65,3.15,7.65l.03-.03Zm-86.82,0h61.73c5.95,0,10.8-4.84,10.8-10.8v-61.7c0-5.92-4.84-10.8-10.8-10.8h-61.73c-5.95,0-10.8,4.88-10.8,10.8v61.7c0,5.95,4.84,10.8,10.8,10.8Zm-3.18-94.4l30.45-30.42c4.19-4.19,3.36-9.93-1.87-12.73l-26.23-12.39c-5.47-2.28-9.97.73-9.97,6.64v45.75c0,5.95,3.43,7.37,7.65,3.15h-.03ZM183.4,448.21h-45.78c-5.95,0-8.93,4.5-6.64,9.97l12.42,26.19c2.8,5.23,8.55,6.09,12.73,1.87l30.45-30.42c4.19-4.19,2.77-7.65-3.15-7.65l-.03.03Zm412.33,0h-45.78c-5.95,0-7.37,3.43-3.15,7.65l30.45,30.42c4.19,4.19,9.93,3.36,12.77-1.87l12.42-26.19c2.28-5.47-.73-9.97-6.68-9.97l-.03-.03Zm-70.87,0h-61.73c-5.95,0-10.8,4.84-10.8,10.8v61.7c0,5.92,4.84,10.8,10.8,10.8h61.73c5.95,0,10.8-4.88,10.8-10.8v-61.7c0-5.92-4.84-10.8-10.8-10.8Zm88.69-93.22l-68.45-68.41c-4.19-4.19-11.07-4.19-15.29,0l-68.51,68.41c-4.19,4.19-4.19,11.07,0,15.26l68.51,68.41c4.22,4.19,11.07,4.19,15.29,0l68.45-68.41c4.19-4.19,4.19-11.07,0-15.26Zm-153.57,187.62c-4.19-4.19-7.65-2.77-7.65,3.15v45.75c0,5.92,4.5,8.93,9.97,6.64l26.23-12.39c5.23-2.8,6.09-8.55,1.87-12.73l-30.45-30.42h.03Zm-85.64-426.66c-4.19-4.19-11.07-4.19-15.29,0l-68.51,68.41c-4.19,4.19-4.19,11.07,0,15.26l68.51,68.41c4.22,4.19,11.07,4.19,15.29,0l68.45-68.41c4.19-4.19,4.19-11.07,0-15.26l-68.45-68.41Zm-103.29,11.11l-26.23,12.39c-5.23,2.8-6.09,8.55-1.87,12.73l30.45,30.42c4.19,4.19,7.65,2.77,7.65-3.15v-45.71c0-5.95-4.5-8.93-9.97-6.64l-.03-.03Zm-.83,66.68h-61.73c-5.95,0-10.8,4.88-10.8,10.8v61.7c0,5.95,4.88,10.8,10.8,10.8h61.73c5.95,0,10.8-4.84,10.8-10.8v-61.7c0-5.92-4.84-10.8-10.8-10.8Zm104.12,263.85c-4.19-4.19-11.07-4.19-15.29,0l-68.51,68.41c-4.19,4.19-4.19,11.07,0,15.26l68.51,68.41c4.22,4.19,11.07,4.19,15.29,0l68.45-68.41c4.19-4.22,4.19-11.07,0-15.26l-68.45-68.41Z"/></svg>
'@

function ConvertTo-ReportRows {
    <# Builds the JSON-ready row shape - common fields plus a `metrics` sub-object of raw numeric fields used for client-side scoring/tiering/totals/recovery math. #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]    $Data,
        [Parameter(Mandatory)] [string[]] $MetricFields
    )
    $optionalPassthrough = @('JobTitle','Department','EmployeeType','Manager','ManagerChain','Groups','GroupIds','OfficeLocation','AccountEnabled','MailboxTypeHeuristic','MailboxClass','LicensePlan','HasArchiveAddon','RecipientType','HasArchive','HubSiteCandidate','HubSiteKeywordMatch','SiteId','RootWebTemplate','OwnerUpn')
    $rows = foreach ($row in $Data) {
        $metrics = @{}
        foreach ($f in $MetricFields) {
            $metrics[$f] = if ($row.PSObject.Properties.Name -contains $f) { $row.$f } else { 0 }
        }
        $obj = [ordered]@{
            ObjectName       = $row.ObjectName
            Identifier       = $row.Identifier
            LastActivityDate = $row.LastActivityDate
            Tier             = $row.Tier
            ComputedTier     = $row.ComputedTier
            IsOverride       = [bool]$row.IsOverride
            OverrideReason   = $row.OverrideReason
            CriteriaTags     = $row.CriteriaTags
            metrics          = $metrics
        }
        foreach ($opt in $optionalPassthrough) {
            if ($row.PSObject.Properties.Name -contains $opt) { $obj[$opt] = $row.$opt }
        }
        # v2.0: composite score (0..1, same number the browser computes as _Score) so builds that do not
        # re-score (Preview) can still show it; Mailbox quota (Prohibit Send/Receive) for the limit insight.
        if ($row.PSObject.Properties.Name -contains '_Score' -and $null -ne $row._Score) { $obj['Score'] = [math]::Round([double]$row._Score, 4) }
        if ($row.PSObject.Properties.Name -contains 'SendReceiveQuotaBytes' -and [double]$row.SendReceiveQuotaBytes -gt 0) { $obj['MailboxLimitBytes'] = [double]$row.SendReceiveQuotaBytes }
        [PSCustomObject]$obj
    }
    # NEW: see Full script's matching comment - when $Data is empty, the
    # foreach-as-expression above produces ZERO output objects, and
    # PowerShell's pipeline collapse then assigns $rows = $null (not an empty
    # array) - the same collection-unroll footgun this file already works
    # around elsewhere for ManagerChain/Groups/GroupIds. Without this guard,
    # @($rows) on that $null becomes a ONE-element array containing $null
    # (@($null) is never empty), so a zero-object workload (e.g. a tenant
    # with no Teams) would embed [null] instead of [] in the report's JSON -
    # and the client-side JS, which expects every array entry to be a row
    # object, would throw dereferencing a property on that null.
    if ($null -eq $rows) { return @() }
    return @($rows)
}

#endregion

# ---------------------------------------------------------------------------
# v2.0: aggregate payloads for the browser engine (all pure functions of the
# row sets passed in, so they can be computed from the FULL data before the
# Preview build removes anything). Field names mirror what the JS recovery
# model reads: Mailboxes use ItemCount / StorageUsedMB (MB) / SendRecvActivity7d,
# OneDrive and SharePoint use FileCount / StorageBytes / ViewedOrEditedCount7d
# or ActiveFiles7d. "activity" is the sum of TotalActivity.
# ---------------------------------------------------------------------------
$script:ReportRecoveryFields = @{
    mailboxes  = @{ Item = 'ItemCount'; Storage = 'StorageUsedMB'; Recent = 'SendRecvActivity7d' }
    onedrive   = @{ Item = 'FileCount'; Storage = 'StorageBytes';  Recent = 'ViewedOrEditedCount7d' }
    sharepoint = @{ Item = 'FileCount'; Storage = 'StorageBytes';  Recent = 'ActiveFiles7d' }
}

function Get-ReportTenantTotals {
    <# Whole-tenant totals per workload: objectCount / itemCount / storage / activity (Teams: objectCount / activity). #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Mailboxes,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $OneDrive,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $SharePoint,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Teams
    )
    $sets = [ordered]@{ mailboxes = @($Mailboxes); onedrive = @($OneDrive); sharepoint = @($SharePoint) }
    $out = [ordered]@{}
    foreach ($key in $sets.Keys) {
        $f = $script:ReportRecoveryFields[$key]
        $rows = @($sets[$key])
        $out[$key] = [ordered]@{
            objectCount = $rows.Count
            itemCount   = [double](Get-FieldSum $rows $f.Item)
            storage     = [double](Get-FieldSum $rows $f.Storage)
            activity    = [double](Get-FieldSum $rows 'TotalActivity')
        }
    }
    $teamRows = @($Teams)
    $out['teams'] = [ordered]@{
        objectCount = $teamRows.Count
        activity    = [double](Get-FieldSum $teamRows 'TotalActivity')
    }
    return $out
}

function Get-ReportSizingAgg {
    <# Aggregates behind the Sizing tab (the JS buildSizingSummary() / license-plan table) so a build with no per-object rows can still render it. #>
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $Mailboxes,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $OneDrive,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array] $SharePoint
    )
    $mb = @($Mailboxes)
    $classKnown = [bool]($script:MailboxClassification -and $script:MailboxClassification.licenseDataAvailable)
    if ($classKnown) {
        $sharedMb = @($mb | Where-Object { $_.MailboxClass -eq 'Shared' })
        $userMb   = @($mb | Where-Object { $_.MailboxClass -ne 'Shared' })
    } else {
        $sharedMb = @($mb | Where-Object { [string]$_.RecipientType -match 'shared' })
        $userMb   = @($mb | Where-Object { [string]$_.RecipientType -notmatch 'shared' })
    }
    $archiveCount = @($mb | Where-Object { $_.HasArchive -eq $true }).Count
    $ex = [ordered]@{
        userCount          = $userMb.Count
        userStorageBytes   = [double](Get-FieldSum $userMb 'StorageBytes')
        userItems          = [double](Get-FieldSum $userMb 'ItemCount')
        sharedCount        = $sharedMb.Count
        sharedStorageBytes = [double](Get-FieldSum $sharedMb 'StorageBytes')
        sharedItems        = [double](Get-FieldSum $sharedMb 'ItemCount')
        archiveCount       = $archiveCount
        classKnown         = $classKnown
        userLabel          = $(if ($classKnown) { 'Licensed user mailboxes' } else { 'User Mailboxes' })
        sharedLabel        = $(if ($classKnown) { 'Shared / group / other (no license needed)' } else { 'Shared Mailboxes' })
        totalLabel         = $(if ($classKnown) { 'Total protected mailboxes' } else { 'Total' })
        totalCount         = $mb.Count
        totalStorageBytes  = [double](Get-FieldSum $mb 'StorageBytes')
        totalItems         = [double](Get-FieldSum $mb 'ItemCount')
    }
    $od = @($OneDrive)
    $sp = @($SharePoint)
    $plans = [ordered]@{}
    $archiveAddon = 0
    $licensedRows = @($mb | Where-Object { $_.MailboxClass -eq 'Licensed' })
    foreach ($r in $licensedRows) {
        $k = if ($r.LicensePlan) { [string]$r.LicensePlan } else { 'Other (unrecognized)' }
        if (-not $plans.Contains($k)) { $plans[$k] = [ordered]@{ users = 0; bytes = 0.0 } }
        $plans[$k].users = [int]$plans[$k].users + 1
        $plans[$k].bytes = [double]$plans[$k].bytes + [double]$r.StorageBytes
        if ($r.HasArchiveAddon -eq $true) { $archiveAddon++ }
    }
    return [ordered]@{
        ex            = $ex
        od            = [ordered]@{ count = $od.Count; storageBytes = [double](Get-FieldSum $od 'StorageBytes'); files = [double](Get-FieldSum $od 'FileCount') }
        sp            = [ordered]@{ count = $sp.Count; storageBytes = [double](Get-FieldSum $sp 'StorageBytes'); files = [double](Get-FieldSum $sp 'FileCount') }
        licensePlans  = $plans
        licensedUsers = $licensedRows.Count
        archiveAddon  = $archiveAddon
    }
}

#region ---------- HTML report: page template + New-M365HtmlReport ----------

$script:ReportHtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>__TITLE__</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,__FAVICON__">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<script>(function(){var t="light";try{t=window.localStorage.getItem("m365Theme")||"light"}catch(e){}document.documentElement.setAttribute("data-theme",t==="dark"?"dark":"light")})();</script>
<style>__CSS__</style>
</head>
<body>
<div class="rainbow-bar"></div>
<div class="header">
  <div class="logo">__LOGO__</div>
  <div class="eyebrow">RECOVERY ASSESSMENT <span class="v2-badge" title="Version 2 of the Recovery Assessment">v2</span></div>
  <h1>Recovery Assessment - M365 - __CUSTOMER__</h1>
  <div class="meta">
    <span>Usage window: <b>__PERIOD__</b></span>
    <span>Generated: <b>__GENERATED__</b></span>
    <span id="hdr-calib"></span>
    <span id="hdr-unit"></span>
    <span id="hdr-theme"></span>
  </div>
</div>
<div class="tabbar">
  <button class="tab-btn active" data-tab="exec">Executive Summary</button>
  <button class="tab-btn" data-tab="report">Report</button>
  <button class="tab-btn" data-tab="playbook">Recovery Playbook</button>
  <button class="tab-btn" data-tab="groups">Groups &amp; Recovery Model</button>
  <button class="tab-btn" data-tab="insights">Recovery Insights</button>
  <button class="tab-btn" data-tab="methodology">Methodology &amp; Glossary</button>
  <button class="tab-btn" data-tab="sizing">Sizing</button>
  <button class="tab-btn" data-tab="compare" id="compare-tab-btn" style="display:none;">Changes Since Last Run</button>
  <!-- NEW v3.6.2: icon-only action toolbar, per feedback - moved
       out of the full-width text-button export-bar (previously its own row
       under the tabbar) and docked to the far right of the tabbar itself,
       via margin-left:auto on .tabbar-actions. title/aria-label carry the
       full label for hover tooltips + accessibility since the text is gone
       from the button face. -->
  <div class="tabbar-actions">
    <button class="icon-btn" onclick="startTour()" title="Take the Tour" aria-label="Take the Tour">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21s-7-6.5-7-11a7 7 0 0 1 14 0c0 4.5-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>
    </button>
    <button class="icon-btn full-only" onclick="exportOverrides()" title="Export overrides (for next run)" aria-label="Export overrides (for next run)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v10"/><path d="M8 9l4 4 4-4"/><path d="M4 19h16"/></svg>
    </button>
    <label class="icon-btn full-only" style="cursor:pointer;" title="Import overrides" aria-label="Import overrides">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17V7"/><path d="M8 11l4-4 4 4"/><path d="M4 19h16"/></svg>
      <input type="file" accept=".json" style="display:none;" onchange="importOverridesFile(this)">
    </label>
    <button class="icon-btn full-only" onclick="exportCriticalityGroupsCsv()" title="Export Criticality Groups (CSV)" aria-label="Export Criticality Groups (CSV)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M3 15h18"/><path d="M9 9v12"/></svg>
    </button>
    <button class="icon-btn" onclick="exportPdf('summary')" title="Export PDF: One Page Summary" aria-label="Export PDF: One Page Summary">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 2h7l4 4v16H7z"/><path d="M14 2v4h4"/><path d="M9.5 13h5"/><path d="M9.5 16.5h5"/></svg>
    </button>
    <button class="icon-btn" onclick="exportPdf('full')" title="Export PDF: Full Report" aria-label="Export PDF: Full Report">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 2h6l4 4v13H9z"/><path d="M15 2v4h4"/><path d="M5 6v16h11"/></svg>
    </button>
  </div>
</div>
<main>
  <div id="pv-banner"></div>
  <section class="tab-panel active" data-tab-panel="exec" id="panel-exec">
    <h2>Executive Summary</h2>
    <!-- v2.0: one-screen story built by renderExecLean() (ReportJsRenderA.js): who matters, how fast they come
         back, what that is worth, and what could slow it down. Every block links to its detail. -->
    <div id="exec-lean"></div>
  </section>
  <section class="tab-panel" data-tab-panel="report" id="panel-report">
    <h2>Report</h2>
    <p class="report-intro">The evidence behind the Executive Summary: the verdict, the recovery times by group, what drives them, how sensitive they are, and what to decide next. Every figure links to its detail on the Groups &amp; Recovery Model tab.</p>
    <div id="report-verdict"></div>
    <div id="report-case"></div>
    <div id="report-by-group"></div>
    <div id="report-calendar"></div>
    <div id="report-drivers"></div>
    <div id="report-sensitivity"></div>
    <div id="report-concentration"></div>
    <div id="report-g1list"></div>
    <div id="report-rto"></div>
    <div id="report-risks"></div>
    <div id="report-group-overview"></div>
    <div id="report-low-activity"></div>
    <div id="report-decisions"></div>
    <div id="report-data-quality"></div>
  </section>
  <section class="tab-panel" data-tab-panel="playbook" id="panel-playbook"></section>
  <section class="tab-panel" data-tab-panel="groups" id="panel-groups"></section>
  <section class="tab-panel" data-tab-panel="insights" id="panel-insights"></section>
  <section class="tab-panel" data-tab-panel="methodology" id="panel-methodology"></section>
  <section class="tab-panel" data-tab-panel="sizing" id="panel-sizing"></section>
  <section class="tab-panel" data-tab-panel="compare" id="panel-compare"></section>
</main>
<footer>
  <p id="footer-note">Tiers, totals, and recovery/cost figures are a data-driven starting point computed LIVE in this page from the embedded raw metrics - adjust weights, title/hub-site keywords, or manual overrides and everything recomputes instantly. Nothing you change here is sent anywhere; use "Export overrides" to save your adjustments and pass the file back in via -OverridesFile on the next run so they persist.</p>
</footer>
<!-- NEW v3.6.0: PDF export target. Hidden on screen always; only shown
     during an actual print (see @media print rules) when body carries
     printing-summary/printing-full, populated on demand by exportPdf(). -->
<div id="print-root"></div>
<!-- NEW 2026-09-24: split into one <script> tag per workload (plus a
     meta/weights tag) instead of one combined blob - see ReportJsEngine's
     header comment for why (V8's hard max JS string length, hit by a real
     very large tenant). -->
<script type="application/json" id="report-data-meta">__DATA_META_JSON__</script>
<script type="application/json" id="report-data-mailboxes">__DATA_MAILBOXES_JSON__</script>
<script type="application/json" id="report-data-onedrive">__DATA_ONEDRIVE_JSON__</script>
<script type="application/json" id="report-data-sharepoint">__DATA_SHAREPOINT_JSON__</script>
<script type="application/json" id="report-data-teams">__DATA_TEAMS_JSON__</script>
<script>__JS__</script>
</body>
</html>
'@

function New-M365HtmlReport {
    param(
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $Mailboxes,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $OneDrive,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $SharePoint,
        [AllowEmptyCollection()] [Parameter(Mandatory)] [array]  $Teams,
        [Parameter(Mandatory)] [string] $CustomerLabel,
        [Parameter(Mandatory)] [string] $Period,
        [Parameter(Mandatory)] [string] $OutFile,
        [Parameter(Mandatory)] [string] $RunId,
        [switch]    $Groups,
        [hashtable] $MailboxWeights,
        [hashtable] $OneDriveWeights,
        [hashtable] $SharePointWeights,
        [hashtable] $TeamsWeights,
        [double[]]  $TierSplit,
        [hashtable] $TitleWeights,
        [double]    $TitleWeightContribution,
        [string[]]  $HubSiteKeywords,
        [double]    $HubSiteBonus,
        [double]    $RecoveryWindowDays,
        [string]    $RecoveryLicenseTier,
        [double]    $DowntimeCostPerHour,
        # NEW v3.0.0: resolved RTO targets (hours) + which preset won and why -
        # seeds the Recovery tab's live, adjustable RTO controls.
        [double]    $Group1TargetHours = 4,
        [double]    $Group2TargetHours = 24,
        [double]    $Group3TargetHours = 72,
        [string]    $RTOPresetResolved = 'Standard',
        [string]    $RTOPresetReason = '',
        # v2.0: build mode and pre-aggregated payloads (see Get-ReportTenantTotals etc.)
        [ValidateSet('full','preview','summary')] [string] $BuildMode = 'full',
        $TenantTotals = $null,
        $TierAgg = $null,
        $SizingAgg = $null,
        $Group1Profile = $null,
        $PriorRunData = $null
    )

    # NEW 2026-09-24: see Full script's matching comment - each workload's
    # rows are built and serialized to JSON SEPARATELY from meta/weights/etc,
    # instead of nested inside one combined $dataObject that gets
    # ConvertTo-Json'd as a single blob. A customer tenant
    # (a very large number of objects) produced one combined JSON string of more than 536 million characters - OVER V8's hard-coded maximum JS string length
    # (536,870,888 characters). Splitting per-workload keeps each individual
    # ConvertTo-Json/JSON.parse call comfortably under the limit for every
    # tenant seen to date. This does NOT eliminate the ceiling - an extreme
    # enough SINGLE workload could still someday exceed it on its own.
    $mailboxesRows  = ConvertTo-ReportRows -Data $Mailboxes  -MetricFields @('SendRecvActivity','ReadActivity','Size','TotalActivity','ItemCount','StorageUsedMB','StorageBytes','SendRecvActivity7d')
    $onedriveRows   = ConvertTo-ReportRows -Data $OneDrive   -MetricFields @('FileActivity','Storage','TotalActivity','FileCount','StorageUsedGB','StorageBytes','ViewedOrEditedCount','ViewedOrEditedCount7d')
    $sharepointRows = ConvertTo-ReportRows -Data $SharePoint -MetricFields @('PageViews','ActiveFiles','Storage','TotalActivity','FileCount','StorageUsedGB','StorageBytes','ActiveFiles7d')
    $teamsRows      = ConvertTo-ReportRows -Data $Teams      -MetricFields @('ActiveUsers','ChannelMsgs','Meetings','TotalActivity','ActiveUsersCount')

    $dataObject = [ordered]@{
        meta = [ordered]@{
            runId                        = $RunId
            customerLabel                = $CustomerLabel
            period                       = $Period
            buildMode                    = $BuildMode
            calibrationVersion           = 'v1'
            group1Profile                = $Group1Profile
            generatedAt                  = (Get-Date).ToString('dddd, MMMM d, yyyy - h:mm tt')
            groupsRequested              = [bool]$Groups
            offlineMode                  = [bool]$script:Offline
            offlineMissing               = @($script:OfflineMissing)
            recoveryWindowDays           = $RecoveryWindowDays
            recoveryLicenseTierRequested = $RecoveryLicenseTier
            downtimeCostPerHour          = $DowntimeCostPerHour
            spodTierTable                = $script:SPODTierTable
            exBenchmark                  = $script:EXBenchmark
            # NEW v3.10.0: recovery time model constants - single
            # source of truth is PowerShell (here); the JS engine reads these
            # back out of meta rather than hardcoding a second copy, so the
            # two can never drift. See Get-RecoveryTimeMinutes.
            spItemsPerMinPerUnit         = $script:SP_ItemsPerMinPerUnit
            odItemsPerMinPerUnit         = $script:OD_ItemsPerMinPerUnit
            sizeFactorBaselineMB         = $script:SizeFactorBaselineMB
            jobSchedulingRatePerMin      = $script:JobSchedulingRatePerMin
            minRecoveryMinutes           = $script:MinRecoveryMinutes
            group1TargetHours            = $Group1TargetHours
            group2TargetHours            = $Group2TargetHours
            group3TargetHours            = $Group3TargetHours
            rtoPresetResolved            = $RTOPresetResolved
            rtoPresetReason              = $RTOPresetReason
            # NEW: Sizing tab - Archive Mailbox storage and Recoverable Items
            # (both size and count) require a separate Exchange Online
            # connection and a per-mailbox loop, not yet wired up (planned:
            # -DetailedSizing switch, Full-only). Placeholder false/null
            # keeps the JS's contract stable now.
            mailboxClassification        = $script:MailboxClassification
            detailedSizingRequested      = $false
            sizing                       = $null
        }
        weights = [ordered]@{
            mailboxes  = $MailboxWeights
            onedrive   = $OneDriveWeights
            sharepoint = $SharePointWeights
            teams      = $TeamsWeights
        }
        tierSplit               = $TierSplit
        titleWeights             = $TitleWeights
        titleWeightContribution = $TitleWeightContribution
        hubSiteKeywords          = $HubSiteKeywords
        hubSiteBonus             = $HubSiteBonus
        priorRun = $PriorRunData
    }
    # v2.0: aggregate payloads only present when the caller supplies them (Preview / Summary).
    if ($null -ne $TenantTotals) { $dataObject['tenantTotals'] = $TenantTotals }
    if ($null -ne $TierAgg)      { $dataObject['tierAgg']      = $TierAgg }
    if ($null -ne $SizingAgg)    { $dataObject['sizingAgg']    = $SizingAgg }

    # NEW 2026-09-22: see Full script's matching comment - GC pass right
    # before the most memory-hungry single operation in this script.
    [System.GC]::Collect()
    $reportMetaJson = $dataObject | ConvertTo-Json -Depth 12 -Compress
    Assert-ValidReportJson -Json $reportMetaJson -Context 'the embedded HTML report-data-meta blob'
    # NEW: -InputObject (parameter binding), NOT the pipeline - see Full
    # script's matching comment (avoids the pipe-auto-unroll-a-single-item
    # footgun for a workload with exactly one row).
    $reportMailboxesJson  = ConvertTo-Json -InputObject $mailboxesRows  -Depth 12 -Compress
    $reportOnedriveJson   = ConvertTo-Json -InputObject $onedriveRows   -Depth 12 -Compress
    $reportSharepointJson = ConvertTo-Json -InputObject $sharepointRows -Depth 12 -Compress
    $reportTeamsJson      = ConvertTo-Json -InputObject $teamsRows      -Depth 12 -Compress
    Assert-ValidReportJson -Json $reportMailboxesJson  -Context 'the embedded HTML report-data-mailboxes blob'
    Assert-ValidReportJson -Json $reportOnedriveJson   -Context 'the embedded HTML report-data-onedrive blob'
    Assert-ValidReportJson -Json $reportSharepointJson -Context 'the embedded HTML report-data-sharepoint blob'
    Assert-ValidReportJson -Json $reportTeamsJson      -Context 'the embedded HTML report-data-teams blob'

    $faviconB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:RubrikBrandmarkSvg))
    $allJs = @($script:ReportJsEngine, $script:ReportJsRecovery, $script:ReportJsUi, $script:ReportJsInsights, $script:ReportJsRenderA, $script:ReportJsRenderTables, $script:ReportJsRenderB, $script:ReportJsRenderRecovery, $script:ReportJsRenderC, $script:ReportJsTour, $script:ReportJsBootstrap) -join "`n"

    $html = $script:ReportHtmlTemplate
    $html = $html.Replace('__TITLE__', (ConvertTo-SafeHtml "Recovery Assessment - M365 - $CustomerLabel"))
    $html = $html.Replace('__LOGO__', $script:RubrikLogoSvg)
    $html = $html.Replace('__CUSTOMER__', (ConvertTo-SafeHtml $CustomerLabel))
    $html = $html.Replace('__PERIOD__', (ConvertTo-SafeHtml $Period))
    $html = $html.Replace('__GENERATED__', $dataObject.meta.generatedAt)
    $html = $html.Replace('__FAVICON__', $faviconB64)
    $html = $html.Replace('__CSS__', $script:ReportCss)
    $html = $html.Replace('__JS__', $allJs)
    $html = $html.Replace('__DATA_META_JSON__', $reportMetaJson)
    $html = $html.Replace('__DATA_MAILBOXES_JSON__', $reportMailboxesJson)
    $html = $html.Replace('__DATA_ONEDRIVE_JSON__', $reportOnedriveJson)
    $html = $html.Replace('__DATA_SHAREPOINT_JSON__', $reportSharepointJson)
    $html = $html.Replace('__DATA_TEAMS_JSON__', $reportTeamsJson)

    Set-Content -Path $OutFile -Value $html -Encoding UTF8
    return $OutFile
}

#endregion

#region ---------- Main ----------

Write-Host "=== Recovery Assessment - M365 - PREVIEW BUILD (v2.0.0) ===" -ForegroundColor Cyan
Write-Host "Critical Group 1 only: Groups 2/3/4 are removed from every output (HTML data, CSVs, JSON, console) before anything is written to disk." -ForegroundColor Cyan

# NEW 2026-09-22: see Full script's matching comment - found in field use from a customer whose very large tenant (hundreds of thousands of objects across all four
# workloads) crashed with a raw System.OutOfMemoryException partway through
# raw collection, with no output files written at all. Surfaced here, up
# front, rather than found only after 15-20 minutes of Graph pulls.
$script:Is64BitProcess = [Environment]::Is64BitProcess
Write-Host "PowerShell process: $(if ($script:Is64BitProcess) { '64-bit' } else { '32-bit' })" -ForegroundColor Gray
if (-not $script:Is64BitProcess) {
    Write-Warning "Running under 32-bit PowerShell, which caps this process at roughly 2-4 GB of memory no matter how much RAM this machine has. On a large tenant (tens of thousands of objects per workload), that is a common cause of a late-run 'System.OutOfMemoryException' with no output files written. Strongly recommend re-running from 64-bit PowerShell (Windows PowerShell's 64-bit host is normally C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe, or use PowerShell 7 / pwsh.exe, which is always 64-bit)."
}

if ($ShowEnterpriseAppGuide) {
    Get-EnterpriseAppSetupGuideText | Write-Host
    return
}

Write-Host "Period: $Period | Output: $OutputPath`n"

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$rawDir = Join-Path $OutputPath 'raw'
New-Item -ItemType Directory -Path $rawDir -Force | Out-Null

# Always written, no side effects - the guided (not automated) Enterprise App path.
Get-EnterpriseAppSetupGuideText | Set-Content -Path (Join-Path $OutputPath 'EnterpriseApp-Setup-Guide.md') -Encoding UTF8

if ($Offline) { Test-OfflineInputs -Path $OfflinePath -Period $Period } else {
Assert-GraphModules
Connect-Assessment -Groups:$Groups -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -GraphTimeoutSeconds $GraphTimeoutSeconds
}

$groupsNote = if ($Groups) { " Entra ID group membership (Group.Read.All) is also being resolved for the Group 1 group-column view." } else { " -NoGroups was passed: Group.Read.All was NOT requested and the Group 1 group-column view will be unavailable this run." }
if (-not $Offline) {Write-Host "`nReports.Read.All/User.Read.All/Sites.Read.All requested; enrichment, title-weight scoring, mailbox-type heuristic, and exact Team-site dedupe are active.$groupsNote" -ForegroundColor Magenta}

$overridesIndex = Import-Overrides -Path $OverridesFile

$priorRunData = $null
if ($CompareTo) {
    $priorDataFile = Join-Path $CompareTo '_ReportData.json'
    if (Test-Path $priorDataFile) {
        try {
            $priorRunData = Get-Content -Path $priorDataFile -Raw | ConvertFrom-Json
            Write-Host "Loaded prior run for comparison: $CompareTo" -ForegroundColor Gray
        }
        catch {
            Write-Warning "-CompareTo '$CompareTo' - could not parse _ReportData.json ($($_.Exception.Message)). Continuing without comparison."
        }
    }
    else {
        Write-Warning "-CompareTo '$CompareTo' does not contain a _ReportData.json (only runs from v2.0.0+ have one). Continuing without comparison."
    }
}

Write-Host "`n--- User profile enrichment ---" -ForegroundColor Yellow
$userEnrichment = if ($Offline) { Write-Host 'Skipped in offline mode (no directory access).' -ForegroundColor Gray; @{} } else { Get-UserEnrichmentIndex -IncludeGroups:$Groups }

$results = @{}

# ---------------------------------------------------------------------------
# RAW COLLECTION PHASE: Mailboxes/OneDrive/Teams/SharePoint are pulled before
# any scoring/tiering, because -RTOPreset Auto needs an early, whole-tenant
# recovery-time estimate from their RAW totals to pick Standard-vs-Enterprise
# targets. Teams is still collected before SharePoint so exact Team-site
# exclusion works exactly as before.
# ---------------------------------------------------------------------------
Write-Host "`n--- Collecting raw usage data ---" -ForegroundColor Yellow
$mailboxesRaw = @(Get-MailboxCriticality -Period $Period -WorkDir $rawDir)
Write-Host ("{0,-24} {1,5} rows" -f 'Mailboxes', $mailboxesRaw.Count) -ForegroundColor Gray

# NEW v3.17.0: license-based mailbox classification, done HERE (before the
# Auto-RTO estimate and every tiering/recovery calc below) so unlicensed
# mailboxes never influence any figure. See Add-MailboxTypeHeuristic.
$sharedUpnSet = $null   # Preview has no Exchange Online step; classification is license-based only
$licenseDataAvailable = [bool]($userEnrichment -and $userEnrichment.Count -gt 0)
$mailboxesRaw = @(Add-UserEnrichment -Data $mailboxesRaw -EnrichmentIndex $userEnrichment -UpnField 'Identifier')
# Safety: if almost no mailbox matched a user, the usage report's names are
# probably concealed (tenant setting "Display concealed user, group, and site
# names in all reports") or the directory pull was partial - classifying on
# that would wrongly call everything shared. Treat as "license data not collected".
if ($licenseDataAvailable -and $mailboxesRaw.Count -gt 0) {
    $mbMatched = @($mailboxesRaw | Where-Object { $_.EntraMatched }).Count
    if (($mbMatched / $mailboxesRaw.Count) -lt 0.2) {
        Write-Warning ("Only {0:N0} of {1:N0} mailboxes matched a user account - report names may be concealed (Microsoft 365 admin center > Settings > Org settings > Reports). Mailboxes can't be classified as licensed vs shared this run." -f $mbMatched, $mailboxesRaw.Count)
        $licenseDataAvailable = $false
    }
}
$mailboxesRaw = @(Add-MailboxTypeHeuristic -Data $mailboxesRaw -SharedUpnSet $sharedUpnSet -LicenseDataAvailable $licenseDataAvailable)
$mbLicensed   = @($mailboxesRaw | Where-Object { $_.MailboxClass -eq 'Licensed' })
$mbShared     = @($mailboxesRaw | Where-Object { $_.MailboxClass -eq 'Shared' })
$mbExcluded   = @($mailboxesRaw | Where-Object { $_.MailboxClass -eq 'Unlicensed' })
$mbUnknown    = @($mailboxesRaw | Where-Object { $_.MailboxClass -eq 'Unknown' })
$script:MailboxClassification = [ordered]@{
    licenseDataAvailable = $licenseDataAvailable
    exoConfirmedShared   = ($null -ne $sharedUpnSet)
    exoSharedCount       = if ($null -ne $sharedUpnSet) { $sharedUpnSet.Count } else { 0 }
    licensedCount        = $mbLicensed.Count
    sharedCount          = $mbShared.Count
    unknownCount         = $mbUnknown.Count
    excludedCount        = $mbExcluded.Count
    excludedStorageBytes = [double](Get-FieldSum $mbExcluded 'StorageBytes')
    excludedItems        = [double](Get-FieldSum $mbExcluded 'ItemCount')
    unmappedSkus         = @($script:UnmappedSkuCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { [ordered]@{ skuId = $_.Key; users = $_.Value } })
}
if ($script:UnmappedSkuCounts.Count -gt 0) {
    Write-Host ("License SKUs not in the built-in plan table (shown as 'Other (unrecognized)'): " + (($script:MailboxClassification.unmappedSkus | ForEach-Object { "$($_.skuId) ($($_.users) users)" }) -join ', ')) -ForegroundColor Gray
}
if ($licenseDataAvailable) {
    Write-Host ("Mailbox classification: {0:N0} licensed user, {1:N0} shared/group/other (no license needed), {2:N0} unlicensed enabled users EXCLUDED (not protected)." -f $mbLicensed.Count, $mbShared.Count, $mbExcluded.Count) -ForegroundColor Cyan
    $mailboxesRaw = @($mailboxesRaw | Where-Object { $_.MailboxClass -ne 'Unlicensed' })
}
else {
    Write-Warning "License data was not available (user enrichment failed or returned nothing), so mailboxes could not be classified as licensed vs shared. All mailboxes are included and shown as Unclassified."
}
$onedriveRaw = @(Get-OneDriveCriticality -Period $Period -WorkDir $rawDir)
Write-Host ("{0,-24} {1,5} rows" -f 'OneDrive', $onedriveRaw.Count) -ForegroundColor Gray

$teams = @(Get-TeamsCriticality -Period $Period -WorkDir $rawDir)
Write-Host ("{0,-24} {1,5} rows" -f 'Teams', $teams.Count) -ForegroundColor Gray

# NEW 2026-09-22: see Full script's matching comment - this is the point in
# a very large tenant's run where a customer's raw OutOfMemoryException was
# actually thrown. Advisory only, not a hard stop.
$rawObjectsSoFar = $mailboxesRaw.Count + $onedriveRaw.Count + $teams.Count
if ($rawObjectsSoFar -gt 80000) {
    $riskNote = if (-not $script:Is64BitProcess) { " and this is a 32-bit PowerShell process - see the warning above" } else { '' }
    Write-Warning "Large tenant detected ($('{0:N0}' -f $rawObjectsSoFar) mailbox/OneDrive/Teams objects before SharePoint is even pulled)$riskNote. Assessments at this scale can need several GB of memory once every workload's raw data and the user-enrichment index are held in memory together. If this run ends with a 'System.OutOfMemoryException' and no CSVs were written, that is the most likely cause - re-run from 64-bit PowerShell on a machine with more available RAM, or reach out about a chunked/summary-only mode for tenants this large."
}
[System.GC]::Collect()

Write-Host "Resolving exact Team SharePoint sites..." -ForegroundColor Gray
$exactTeamSiteUrls = if ($Offline) { $null } else { Get-ExactTeamSiteUrls -Teams $teams -Groups:$Groups }

$sharepointResult = Get-SharePointCriticality -Period $Period -WorkDir $rawDir -IncludeGroupConnectedSites:$IncludeGroupConnectedSites -ExactTeamSiteKeys $exactTeamSiteUrls
$sharepointRaw = @($sharepointResult.Sites)
$sharepointExcluded = @($sharepointResult.Excluded)
Write-Host ("{0,-24} {1,5} rows  (excluded as OneDrive/Team: {2})" -f 'SharePoint', $sharepointRaw.Count, $sharepointExcluded.Count) -ForegroundColor Gray

# ---------------------------------------------------------------------------
# RTO TARGET / PRESET RESOLUTION - resolved early so the console/manifest and
# the Build-RecoveryModel call below all see the same targets. As of v3.1.0
# these no longer decide tiering (see Add-Tier below) - they drive a
# per-group ExceedsTarget compliance flag on the ABR recovery-time figures.
# ---------------------------------------------------------------------------
Write-Host "`n--- RTO target resolution ---" -ForegroundColor Yellow
$earlyEstimateMin = Get-FullTenantRecoveryEstimate -SharePoint $sharepointRaw -OneDrive $onedriveRaw -Mailboxes $mailboxesRaw -RecoveryLicenseTier $RecoveryLicenseTier
Write-Host ("Early full-tenant recovery estimate: {0:N1} hr ({1:N1} days) - drives -RTOPreset Auto only" -f ($earlyEstimateMin/60), ($earlyEstimateMin/1440)) -ForegroundColor Gray

# Auto threshold: >= 5 days (7200 min) picks Enterprise (24/120/240h), else Standard (4/24/72h).
$autoEnterpriseThresholdMin = 7200
switch ($RTOPreset) {
    'Standard'   { $g1 = 4.0;  $g2 = 24.0;  $g3 = 72.0;  $resolvedPresetLabel = 'Standard';   $presetReason = 'Standard preset explicitly requested (-RTOPreset Standard).' }
    'Enterprise' { $g1 = 24.0; $g2 = 120.0; $g3 = 240.0; $resolvedPresetLabel = 'Enterprise'; $presetReason = 'Enterprise preset explicitly requested (-RTOPreset Enterprise).' }
    'Custom'     { $g1 = $Group1TargetHours; $g2 = $Group2TargetHours; $g3 = $Group3TargetHours; $resolvedPresetLabel = 'Custom'; $presetReason = 'Custom preset explicitly requested (-RTOPreset Custom) - using -Group1/2/3TargetHours values as given.' }
    default {
        # Auto
        if ($earlyEstimateMin -ge $autoEnterpriseThresholdMin) {
            # Size alone favors Enterprise's generous budget - but NEW
            # v3.10.0: check whether Enterprise's OWN Group 1 budget (24h)
            # would swallow ANY ONE workload's entire active population by
            # itself (the MIN across SP/OD/EX - see Get-WholeTenantABRMinutes
            # for why MIN, not MAX, is the right check). If a tenant's total
            # data is huge but even one workload's ABR/hot-data footprint is
            # tiny, that workload's Group 1 absorbs everything and ITS
            # Groups 2/3 come up empty - a degenerate, non-differentiated
            # spread that defeats the point of showing a criticality-tiered
            # recovery. In that case, fall back to Standard despite tenant
            # size.
            $wholeTenantWindowFactor = [math]::Max(0, [math]::Min(7, $RecoveryWindowDays)) / 7
            $wholeTenantABRMin = Get-WholeTenantABRMinutes -SharePoint $sharepointRaw -OneDrive $onedriveRaw -Mailboxes $mailboxesRaw -RecoveryLicenseTier $RecoveryLicenseTier -WindowFactor $wholeTenantWindowFactor
            $enterpriseGroup1BudgetMin = 24.0 * 60

            if ($wholeTenantABRMin -le $enterpriseGroup1BudgetMin) {
                $g1 = 4.0; $g2 = 24.0; $g3 = 72.0; $resolvedPresetLabel = 'Standard'
                $presetReason = "Auto-suggested 'Standard' - tenant size alone favored Enterprise (early full-tenant recovery estimate {0:N1} hr, threshold >= {1:N0} hr / 5 days), but at least one workload's entire active population fits inside Enterprise's own Group 1 budget (easiest-to-swallow workload's whole-population ABR time is {2:N1} min, versus a {3:N0} min / 24 hr budget) - that would produce a degenerate all-in-Group-1 spread with Groups 2/3 empty for that workload, so Standard's tighter budgets were used instead for a healthier tier distribution." -f ($earlyEstimateMin/60), ($autoEnterpriseThresholdMin/60), $wholeTenantABRMin, $enterpriseGroup1BudgetMin
            } else {
                $g1 = 24.0; $g2 = 120.0; $g3 = 240.0; $resolvedPresetLabel = 'Enterprise'
                $presetReason = "Auto-suggested 'Enterprise' - early full-tenant recovery estimate is {0:N1} hr (threshold: >= {1:N0} hr / 5 days picks Enterprise), and even the easiest-to-swallow workload's whole-population ABR time ({2:N1} min) exceeds Enterprise's own Group 1 budget ({3:N0} min / 24 hr), confirming a healthy multi-group spread is achievable across all workloads." -f ($earlyEstimateMin/60), ($autoEnterpriseThresholdMin/60), $wholeTenantABRMin, $enterpriseGroup1BudgetMin
            }
        } else {
            $g1 = 4.0; $g2 = 24.0; $g3 = 72.0; $resolvedPresetLabel = 'Standard'
            $presetReason = "Auto-suggested 'Standard' - early full-tenant recovery estimate is {0:N1} hr (threshold: >= {1:N0} hr / 5 days picks Enterprise)." -f ($earlyEstimateMin/60), ($autoEnterpriseThresholdMin/60)
        }
    }
}

# Explicit -Group1/2/3TargetHours ALWAYS win over whatever the preset chose,
# per-parameter, regardless of -RTOPreset - never silently overridden.
$explicitOverrideNotes = [System.Collections.Generic.List[string]]::new()
if ($PSBoundParameters.ContainsKey('Group1TargetHours')) { $g1 = $Group1TargetHours; $explicitOverrideNotes.Add("Group1TargetHours explicitly set to $Group1TargetHours") }
if ($PSBoundParameters.ContainsKey('Group2TargetHours')) { $g2 = $Group2TargetHours; $explicitOverrideNotes.Add("Group2TargetHours explicitly set to $Group2TargetHours") }
if ($PSBoundParameters.ContainsKey('Group3TargetHours')) { $g3 = $Group3TargetHours; $explicitOverrideNotes.Add("Group3TargetHours explicitly set to $Group3TargetHours") }
if ($explicitOverrideNotes.Count -gt 0) {
    $resolvedPresetLabel = 'Custom'
    $presetReason = "$presetReason Explicit override(s) win: $($explicitOverrideNotes -join '; ')."
}

function ConvertTo-ScalarDouble {
    # Defensive coercion: guarantees a plain [double] regardless of whether
    # $Value arrived as a scalar or got boxed into a single-element array
    # somewhere upstream (e.g. via $PSBoundParameters/switch-case plumbing) -
    # avoids "[System.Object[]] does not contain a method named 'op_Multiply'"
    # if that ever happens, instead of a cryptic runtime failure.
    param($Value)
    if ($Value -is [array]) { return [double]$Value[0] }
    return [double]$Value
}

$Group1TargetHours = ConvertTo-ScalarDouble $g1
$Group2TargetHours = ConvertTo-ScalarDouble $g2
$Group3TargetHours = ConvertTo-ScalarDouble $g3
$targetsMin = [double[]]@(($Group1TargetHours * 60.0), ($Group2TargetHours * 60.0), ($Group3TargetHours * 60.0))

# NEW v3.8.0/Phase 2: shared inputs for Add-BudgetTier (the PS-side port of
# the JS engine's assignBudgetTiers()), computed once here - before any
# per-workload processing - so Mailboxes/OneDrive/SharePoint's tiering walk
# and Build-RecoveryModel's console-summary figures use the exact same SP/OD
# throughput tier and 0-7 day window scaling. See the Methodology tab.
$tierWindowFactor = [math]::Max(0, [math]::Min(7, $RecoveryWindowDays)) / 7
$tierSpodScale = [math]::Max($onedriveRaw.Count, $sharepointRaw.Count)
$tierSpodTier = Resolve-RecoveryLicenseTier -Requested $RecoveryLicenseTier -ObjectScale $tierSpodScale

Write-Host ("RTO preset resolved: {0}  (Group1={1}h / Group2={2}h / Group3={3}h)" -f $resolvedPresetLabel, $Group1TargetHours, $Group2TargetHours, $Group3TargetHours) -ForegroundColor Cyan
Write-Host ("Reason: {0}" -f $presetReason) -ForegroundColor Gray

# ---------------------------------------------------------------------------
# PROCESSING PHASE: enrichment, scoring, tiering, export - per workload.
# v3.8.0/Phase 2: Mailboxes/OneDrive/SharePoint are now tiered by
# Add-BudgetTier, a budget-constrained walk against their own RTO targets
# using each object's windowed ABR hot-data estimate (from
# Add-RecentDataEstimate, called first) - see Add-BudgetTier's header
# comment. Teams has no independent recovery-time model to walk against, so
# it keeps Add-Tier's original criticality-ranked equal-thirds split
# (-TierSplit). Tiering and the recovery model run on the FULL data in
# memory; Select-PreviewGroup1Rows then strips Groups 2/3/4 before any output
# is written. See the Methodology tab.
# ---------------------------------------------------------------------------

Write-Host "`n--- Mailboxes ---" -ForegroundColor Yellow
$mailboxes = $mailboxesRaw
$mailboxes = @(Add-UserEnrichment -Data $mailboxes -EnrichmentIndex $userEnrichment -UpnField 'Identifier')
$mailboxes = @(Add-TitleWeightScore -Data $mailboxes -TitleWeights $TitleWeights)
$MailboxWeights = $MailboxWeights + @{ TitleWeight = $TitleWeightContribution }
# Recipient Type (authoritative, from the mailbox usage report) runs
# regardless; the AccountEnabled fallback inside only has data to fall
# back to when the enrichment lookup above didn't find this user.
# NEW v3.17.0: mailbox classification already ran right after raw collection.
$mailboxes = @(Add-RecentDataEstimate -Data $mailboxes -TotalItemField 'ItemCount' -TotalStorageField 'StorageUsedMB' -RecentItemField 'SendRecvActivity7d')
$mailboxes = @(Add-CompositeScore -Data $mailboxes -MetricWeights $MailboxWeights)
$mailboxes = @(Add-CriteriaTags -Data $mailboxes -MetricWeights $MailboxWeights)
$mailboxItemTotal = Get-FieldSum $mailboxes 'ItemCount'
$mailboxAvgItemSize = if ($mailboxItemTotal -gt 0) { (Get-FieldSum $mailboxes 'StorageUsedMB') / $mailboxItemTotal } else { 0 }
$mailboxes = @(Add-BudgetTier -Data $mailboxes -InactiveCheckField 'TotalActivity' -AvgItemSize $mailboxAvgItemSize -SPODTier $null -WorkloadType 'EX' -TargetsMin $targetsMin -WindowFactor $tierWindowFactor)
$mailboxes = @(Add-Overrides -Data $mailboxes -OverridesIndex $overridesIndex -Workload 'mailboxes')

Write-Host "`n--- OneDrive ---" -ForegroundColor Yellow
$onedrive = $onedriveRaw
$onedrive = @(Add-UserEnrichment -Data $onedrive -EnrichmentIndex $userEnrichment -UpnField 'OwnerUpn')
$onedrive = @(Add-TitleWeightScore -Data $onedrive -TitleWeights $TitleWeights)
$OneDriveWeights = $OneDriveWeights + @{ TitleWeight = $TitleWeightContribution }
$onedrive = @(Add-RecentDataEstimate -Data $onedrive -TotalItemField 'FileCount' -TotalStorageField 'StorageBytes' -RecentItemField 'ViewedOrEditedCount7d')
$onedrive = @(Add-CompositeScore -Data $onedrive -MetricWeights $OneDriveWeights)
$onedrive = @(Add-CriteriaTags -Data $onedrive -MetricWeights $OneDriveWeights)
$onedriveItemTotal = Get-FieldSum $onedrive 'FileCount'
$onedriveAvgItemSize = if ($onedriveItemTotal -gt 0) { (Get-FieldSum $onedrive 'StorageBytes') / $onedriveItemTotal } else { 0 }
$onedrive = @(Add-BudgetTier -Data $onedrive -InactiveCheckField 'TotalActivity' -AvgItemSize $onedriveAvgItemSize -SPODTier $tierSpodTier -WorkloadType 'OD' -TargetsMin $targetsMin -WindowFactor $tierWindowFactor)
$onedrive = @(Add-Overrides -Data $onedrive -OverridesIndex $overridesIndex -Workload 'onedrive')

Write-Host "`n--- Teams ---" -ForegroundColor Yellow
$teams = @(Add-CompositeScore -Data $teams -MetricWeights $TeamsWeights)
$teams = @(Add-CriteriaTags -Data $teams -MetricWeights $TeamsWeights)
$teams = @(Add-Tier -Data $teams -TierSplit $TierSplit -InactiveCheckField 'TotalActivity')
$teams = @(Add-Overrides -Data $teams -OverridesIndex $overridesIndex -Workload 'teams')

Write-Host "`n--- SharePoint Sites ---" -ForegroundColor Yellow
$sharepoint = $sharepointRaw
$sharepoint = @(Add-HubSiteFlag -Data $sharepoint -Keywords $HubSiteKeywords -Bonus $HubSiteBonus)
$sharepoint = @(Add-RecentDataEstimate -Data $sharepoint -TotalItemField 'FileCount' -TotalStorageField 'StorageBytes' -RecentItemField 'ActiveFiles7d')
$sharepoint = @(Add-CompositeScore -Data $sharepoint -MetricWeights $SharePointWeights)
foreach ($row in $sharepoint) { $row._Score = [math]::Min(1.0, $row._Score + $row.HubSiteBonus) }
$sharepoint = @(Add-CriteriaTags -Data $sharepoint -MetricWeights $SharePointWeights)
$sharepointItemTotal = Get-FieldSum $sharepoint 'FileCount'
$sharepointAvgItemSize = if ($sharepointItemTotal -gt 0) { (Get-FieldSum $sharepoint 'StorageBytes') / $sharepointItemTotal } else { 0 }
$sharepoint = @(Add-BudgetTier -Data $sharepoint -InactiveCheckField 'TotalActivity' -AvgItemSize $sharepointAvgItemSize -SPODTier $tierSpodTier -WorkloadType 'SP' -TargetsMin $targetsMin -WindowFactor $tierWindowFactor)
$sharepoint = @(Add-Overrides -Data $sharepoint -OverridesIndex $overridesIndex -Workload 'sharepoint')
# Recovery model - computed here too (console/manifest visibility); the HTML report
# recomputes its own copy live in JS so it stays in sync with any weight/override changes.
Write-Host "`n--- Recovery time modeling ---" -ForegroundColor Yellow
$recoveryModel = Build-RecoveryModel -SharePoint $sharepoint -OneDrive $onedrive -Mailboxes $mailboxes -RecoveryLicenseTier $RecoveryLicenseTier -TargetsMin $targetsMin -RecoveryWindowDays $RecoveryWindowDays
$group1CumMin = $recoveryModel.Milestones['Critical Group 1'].WallClockCumulativeMin
Write-Host ("SP/OD throughput tier: {0}" -f $recoveryModel.Meta.SPODTierBucket) -ForegroundColor Gray
Write-Host ("Group 1 online in:     {0:N1} min ({1:N1} hr)  [ABR, recent/active data]" -f $group1CumMin, ($group1CumMin/60)) -ForegroundColor Gray
Write-Host ("Full restore (all):    {0:N1} min ({1:N1} hr)  [Mass Recovery, full data]" -f $recoveryModel.FullRestoreUnprioritizedMin, ($recoveryModel.FullRestoreUnprioritizedMin/60)) -ForegroundColor Gray
$m1 = $recoveryModel.Milestones['Critical Group 1']
if ($m1.ExceedsTarget) {
    Write-Host ("Critical Group 1 exceeds its RTO target by: {0:N1} hr ({1:N1} days)" -f ($m1.TargetGapMin/60), ($m1.TargetGapMin/1440)) -ForegroundColor Yellow
}
if ($DowntimeCostPerHour -gt 0) {
    $savedHrs = [math]::Max(0, ($recoveryModel.FullRestoreUnprioritizedMin - $group1CumMin) / 60)
    Write-Host ("Downtime cost avoided (Group 1 online early): {0:C0}" -f ($savedHrs * $DowntimeCostPerHour)) -ForegroundColor Gray
}

$runId = [guid]::NewGuid().ToString('N').Substring(0,12)

# ---------------------------------------------------------------------------
# v2.0 STRIP STEP: compute the whole-tenant aggregates from the FULL rows, then keep ONLY Critical Group 1
# rows. Nothing after this point (CSVs, HTML, JSON, manifest, console) can see a Group 2/3/4 row.
# ---------------------------------------------------------------------------
$previewTenantTotals = Get-ReportTenantTotals -Mailboxes $mailboxes -OneDrive $onedrive -SharePoint $sharepoint -Teams $teams
$previewSizingAgg    = Get-ReportSizingAgg    -Mailboxes $mailboxes -OneDrive $onedrive -SharePoint $sharepoint
$tenantObjectCounts  = @{ Mailboxes = $mailboxes.Count; OneDrive = $onedrive.Count; SharePoint = $sharepoint.Count; Teams = $teams.Count }
$mailboxes  = @(Select-PreviewGroup1Rows -Data $mailboxes)
$onedrive   = @(Select-PreviewGroup1Rows -Data $onedrive)
$sharepoint = @(Select-PreviewGroup1Rows -Data $sharepoint)
$teams      = @(Select-PreviewGroup1Rows -Data $teams)
Write-Host "`n--- Preview output (Critical Group 1 only) ---" -ForegroundColor Yellow
$results['Mailboxes']  = Export-WorkloadResult -Data $mailboxes  -Name 'Mailboxes'       -OutDir $OutputPath
$results['OneDrive']   = Export-WorkloadResult -Data $onedrive   -Name 'OneDrive'        -OutDir $OutputPath
$results['Teams']      = Export-WorkloadResult -Data $teams      -Name 'Teams'           -OutDir $OutputPath
$results['SharePoint'] = Export-WorkloadResult -Data $sharepoint -Name 'SharePointSites' -OutDir $OutputPath

# Master rollup (Critical Group 1 only)
$masterRows = foreach ($set in @($mailboxes, $onedrive, $sharepoint, $teams)) {
    foreach ($row in $set) {
        [PSCustomObject]@{
            Workload           = $row.Workload
            ObjectName         = $row.ObjectName
            Identifier         = $row.Identifier
            Tier               = $row.Tier
            IsOverride         = $row.IsOverride
            RankWithinWorkload = $row.RankWithinWorkload
            Score              = $row._Score
            LastActivityDate   = $row.LastActivityDate
        }
    }
}
$masterPath = Join-Path $OutputPath '_MasterSummary.csv'
$masterRows | Sort-Object Workload, RankWithinWorkload | Export-Csv -Path $masterPath -NoTypeInformation -Encoding UTF8


$htmlReportPath = $null
if (-not $SkipHtmlReport) {
    Write-Host "`n--- HTML report ---" -ForegroundColor Yellow
    $resolvedCustomerLabel = if ($CustomerName) {
        $CustomerName
    } else {
        $acct = (Get-SignedInAccount)
        if ($acct -and $acct.Contains('@')) { $acct.Split('@')[1] } else { 'Customer Tenant' }
    }
    $htmlReportPath = New-M365HtmlReport -Mailboxes $mailboxes -OneDrive $onedrive -SharePoint $sharepoint -Teams $teams `
        -CustomerLabel $resolvedCustomerLabel -Period $Period -RunId $runId -Groups:$Groups `
        -MailboxWeights $MailboxWeights -OneDriveWeights $OneDriveWeights -SharePointWeights $SharePointWeights -TeamsWeights $TeamsWeights `
        -TierSplit $TierSplit -TitleWeights $TitleWeights -TitleWeightContribution $TitleWeightContribution -HubSiteKeywords $HubSiteKeywords -HubSiteBonus $HubSiteBonus `
        -RecoveryWindowDays $RecoveryWindowDays -RecoveryLicenseTier $RecoveryLicenseTier -DowntimeCostPerHour $DowntimeCostPerHour -PriorRunData $priorRunData `
        -Group1TargetHours $Group1TargetHours -Group2TargetHours $Group2TargetHours -Group3TargetHours $Group3TargetHours -RTOPresetResolved $resolvedPresetLabel -RTOPresetReason $presetReason `
        -BuildMode 'preview' -TenantTotals $previewTenantTotals -SizingAgg $previewSizingAgg `
        -OutFile (Join-Path $OutputPath 'CriticalityAssessment_Report.html')

    # Also save the embedded data blob standalone, so a FUTURE run's -CompareTo can load it.
    $reportDataForCompare = [PSCustomObject]@{
        meta = @{ generatedAt = (Get-Date).ToString('dddd, MMMM d, yyyy - h:mm tt') }
        workloads = @{
            mailboxes  = ConvertTo-ReportRows -Data $mailboxes      -MetricFields @('TotalActivity')
            onedrive   = ConvertTo-ReportRows -Data $onedrive       -MetricFields @('TotalActivity')
            sharepoint = ConvertTo-ReportRows -Data $sharepoint     -MetricFields @('TotalActivity')
            teams      = ConvertTo-ReportRows -Data $teams          -MetricFields @('TotalActivity')
        }
    }
    $reportDataForCompareJson = $reportDataForCompare | ConvertTo-Json -Depth 12 -Compress
    Assert-ValidReportJson -Json $reportDataForCompareJson -Context '_ReportData.json (for a future -CompareTo run)'
    $reportDataForCompareJson | Set-Content -Path (Join-Path $OutputPath '_ReportData.json') -Encoding UTF8
    Write-Host "HTML report              ->  $htmlReportPath" -ForegroundColor Gray
}

# Precompute every dynamic value first, then substitute into a LITERAL
# (single-quoted) template via .Replace() - same pattern the HTML report uses
# (.Replace() against __PLACEHOLDER__ tokens) instead of an expandable "@"..."@
# here-string. An expandable here-string re-parses its own source for $/$()
# syntax; a literal one doesn't, so nothing in a run-time value (a tenant
# label, an -OverridesFile path, etc.) can ever be misread as PowerShell
# syntax, however unlikely that is in practice today.
$manifestRunTimeUtc      = (Get-Date).ToUniversalTime().ToString()
$manifestTierSplit       = $TierSplit -join ' / '
$manifestGraphScopes     = if ($Offline) { 'None - OFFLINE run from exported admin center reports (reduced confidence)' } elseif ($Groups) { 'Reports.Read.All, User.Read.All, Sites.Read.All, Group.Read.All' } else { 'Reports.Read.All, User.Read.All, Sites.Read.All' }
$manifestSignedInAs      = (Get-SignedInAccount)
$manifestOverridesFile   = if ($OverridesFile) { $OverridesFile } else { '(none)' }
$manifestComparedAgainst = if ($CompareTo) { $CompareTo } else { '(none)' }
$manifestExceedsLines    = ( @('Critical Group 1') | ForEach-Object {
        $m = $recoveryModel.Milestones[$_]
        if ($m.ExceedsTarget) { "  $_ exceeds its target by: $([math]::Round($m.TargetGapMin / 60, 1)) hr" }
    } ) -join "`n"
$manifestGroupsLine      = if ($Groups) { "`n  Users with >=1 Entra ID group resolved: $((@($userEnrichment.Values) | Where-Object { $_.Groups -and $_.Groups.Count -gt 0 }).Count) of $($userEnrichment.Count)" } else { '' }
$manifestFullEnrichment  = "`nUser profile enrichment:`n  Users profile-enriched: $($userEnrichment.Count)`n  Team sites exactly resolved: $($exactTeamSiteUrls.Count) of $($tenantObjectCounts.Teams)$manifestGroupsLine"
$manifestGroup1CumMin    = ([math]::Round($group1CumMin, 1)).ToString()
$manifestGroup1CumHr     = ([math]::Round($group1CumMin / 60, 1)).ToString()
$manifestFullRestoreMin  = ([math]::Round($recoveryModel.FullRestoreUnprioritizedMin, 1)).ToString()
$manifestFullRestoreHr   = ([math]::Round($recoveryModel.FullRestoreUnprioritizedMin / 60, 1)).ToString()

$manifest = @'
Recovery Assessment - M365 - PREVIEW BUILD - Run Manifest (v2.0.0)
Run time (UTC):        __RUN_TIME_UTC__
Usage report period:   __PERIOD__
Tier split (Teams only): __TIER_SPLIT__
Graph scopes used:     __GRAPH_SCOPES__
Signed in as:          __SIGNED_IN_AS__
Overrides file used:   __OVERRIDES_FILE__
Compared against:      __COMPARED_AGAINST__

Tiering: all four workloads ranked by composite score and split by -TierSplit
(__TIER_SPLIT__) - Group 1 = top tier = recover first. Only Group 1 is reported here.

RTO target (Group 1 compliance check against ABR recovery time - Mailboxes/OneDrive/SharePoint only):
  Preset resolved:       __PRESET_LABEL__
  Reason:                __PRESET_REASON__
  Group 1 target:        __G1_TARGET__ hr
__EXCEEDS_TARGET_LINES__
Object counts by workload (whole tenant; Group 1 rows only are listed in the outputs):
  Mailboxes:               __MAILBOX_COUNT__  (Group 1: __MAILBOX_G1__)
  OneDrive accounts:       __ONEDRIVE_COUNT__  (Group 1: __ONEDRIVE_G1__)
  SharePoint sites:        __SHAREPOINT_COUNT__  (Group 1: __SHAREPOINT_G1__; excluded as OneDrive/Team: __SHAREPOINT_EXCLUDED_COUNT__)
  Teams:                   __TEAMS_COUNT__  (Group 1: __TEAMS_G1__)
__FULL_MODE_ENRICHMENT__

Recovery model (Preview weights/tiers as computed at run time - the HTML report recomputes live):
  SP/OD throughput tier:  __SPOD_TIER__
  Group 1 online in:      __G1_CUM_MIN__ min (__G1_CUM_HR__ hr)  [ABR, recent/active data]
  Full restore (all):     __FULL_RESTORE_MIN__ min (__FULL_RESTORE_HR__ hr)  [Mass Recovery, full data]

PREVIEW BUILD: this is the Preview script, not the full assessment.
It reports Critical Group 1 only. Groups 2/3/4 are removed at generation time
(no per-object rows, scores, storage figures or timing are written anywhere);
only whole-tenant totals and the Mass Recovery baseline are included for context.
Scoring weights, keyword tables and recovery targets appear read-only. To see
Groups 2-4, the recovery ladder and tunable settings, run the full assessment:
https://www.rubrik.com/contact-sales?v2
'@

$manifest = $manifest.
    Replace('__RUN_TIME_UTC__', $manifestRunTimeUtc).
    Replace('__PERIOD__', $Period).
    Replace('__TIER_SPLIT__', $manifestTierSplit).
    Replace('__GRAPH_SCOPES__', $manifestGraphScopes).
    Replace('__SIGNED_IN_AS__', $manifestSignedInAs).
    Replace('__OVERRIDES_FILE__', $manifestOverridesFile).
    Replace('__COMPARED_AGAINST__', $manifestComparedAgainst).
    Replace('__PRESET_LABEL__', $resolvedPresetLabel).
    Replace('__PRESET_REASON__', $presetReason).
    Replace('__G1_TARGET__', $Group1TargetHours.ToString()).
    Replace('__EXCEEDS_TARGET_LINES__', $manifestExceedsLines).
    Replace('__MAILBOX_COUNT__', $tenantObjectCounts.Mailboxes.ToString()).
    Replace('__ONEDRIVE_COUNT__', $tenantObjectCounts.OneDrive.ToString()).
    Replace('__SHAREPOINT_COUNT__', $tenantObjectCounts.SharePoint.ToString()).
    Replace('__SHAREPOINT_EXCLUDED_COUNT__', $sharepointExcluded.Count.ToString()).
    Replace('__TEAMS_COUNT__', $tenantObjectCounts.Teams.ToString()).
    Replace('__MAILBOX_G1__', $mailboxes.Count.ToString()).
    Replace('__ONEDRIVE_G1__', $onedrive.Count.ToString()).
    Replace('__SHAREPOINT_G1__', $sharepoint.Count.ToString()).
    Replace('__TEAMS_G1__', $teams.Count.ToString()).
    Replace('__FULL_MODE_ENRICHMENT__', $manifestFullEnrichment).
    Replace('__SPOD_TIER__', $recoveryModel.Meta.SPODTierBucket).
    Replace('__G1_CUM_MIN__', $manifestGroup1CumMin).
    Replace('__G1_CUM_HR__', $manifestGroup1CumHr).
    Replace('__FULL_RESTORE_MIN__', $manifestFullRestoreMin).
    Replace('__FULL_RESTORE_HR__', $manifestFullRestoreHr)

Set-Content -Path (Join-Path $OutputPath '_RunManifest.txt') -Value $manifest -Encoding UTF8

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host "Group 1 CSVs, _MasterSummary.csv, _ReportData.json, and _RunManifest.txt written to: $OutputPath" -ForegroundColor Green
if ($htmlReportPath) { Write-Host "Open the HTML report:      $htmlReportPath" -ForegroundColor Green }
Write-Host "Enterprise App setup guide: $(Join-Path $OutputPath 'EnterpriseApp-Setup-Guide.md')" -ForegroundColor Green

$masterRows | Group-Object Workload, Tier | Sort-Object Name | Format-Table @{L='Workload / Tier';E={$_.Name}}, Count -AutoSize

if (-not $Offline) { Disconnect-MgGraph | Out-Null }

#endregion

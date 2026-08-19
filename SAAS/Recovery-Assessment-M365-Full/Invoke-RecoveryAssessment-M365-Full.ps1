<#
.SYNOPSIS
    M365 Recovery Criticality Assessment - tiers Mailboxes, OneDrive accounts,
    SharePoint sites, and Teams into Critical Group 1/2/3 based on Microsoft
    Graph usage activity, then models recovery time and downtime cost per
    group for BC/DR recovery-sequencing conversations.

.DESCRIPTION
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
    RECOVERY-MODEL-METHODOLOGY.md for the full before/after rationale and
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
        customer's own MVC Recovery Time Estimator export (see
        RECOVERY-MODEL-METHODOLOGY.md).
      - Manager roll-up (who reports up through whom) for org-based filtering
        and mass-tiering ("everyone under this VP").
      - A heuristic mailbox-type classifier (User vs. likely Shared/Resource)
        and a heuristic "department hub site" flag for SharePoint.
      - A -CompareTo switch to diff this run against a prior run's output.
      - A guided (not automated) path to running this via an Enterprise
        App / application permissions instead of a delegated sign-in - see
        EnterpriseApp-Setup-Guide.md, written alongside every run.

    This is still directional, not exact. Treat tiers, recovery times, and
    costs as a data-driven starting point - the live override system exists
    specifically so the customer can correct anything the data can't see.

.NOTES
    ============================================================================
    PERMISSIONS - PREVIEW (default) vs FULL (-Full)
    ============================================================================
    PREVIEW:    Entra role "Reports Reader". Delegated scope Reports.Read.All
              only. No directory/user/site read access requested or needed.
    FULL: Same role. Adds delegated scopes User.Read.All, Sites.Read.All.
              Buys: user profile enrichment (Job Title, Department, Employee
              Type, Manager, manager roll-up chain, mailbox-type heuristic,
              title-weight scoring) and exact Team<->SharePoint site
              resolution. Never requested unless -Full is passed.
    GROUPS (-Groups, requires -Full): Adds delegated scope Group.Read.All.
              Buys: each user's Entra ID group membership (Mailboxes/OneDrive
              only - same UPN join as manager enrichment, resolved from the
              SAME single directory pull, no extra Graph call), surfaced as
              a "Filter to Entra ID group" control next to the manager filter
              so you can bulk-select/mass-tier "everyone in this group" -
              mirroring how RSC Mass Recovery groups users by AD/Entra ID
              Group for OneDrive/Exchange. Requests the broader Group.Read.All
              rather than the strict-minimum GroupMember.Read.All so a future
              per-group detail lookup (type, owners, dynamic membership rule)
              does not require asking the customer for a second consent grant.
              Ignored (with a warning) if passed without -Full, since there is
              no bulk user pull to expand group membership onto without it.
    DETAILED SIZING (-DetailedSizing, requires -Full): NOT a Graph scope - a
              SEPARATE connection entirely (Connect-ExchangeOnline, via the
              ExchangeOnlineManagement PowerShell module) plus a per-mailbox
              loop over every active mailbox. Buys: Archive Mailbox storage/
              items and Recoverable Items folder storage/items on the Sizing
              tab, ported from the standalone Get-RubrikM365SizingInfo.ps1
              sizing script. Without this switch, the Sizing tab still shows
              Exchange/OneDrive/SharePoint totals and Archive Mailbox COUNT
              (free - already in the same usage report every mode collects) -
              just not Archive storage or Recoverable Items. Opt-in because
              the per-mailbox loop is the slowest, most timeout-prone part of
              the entire run on a large tenant - it runs LAST, after every
              other export has already succeeded, and a failure here never
              affects the rest of the report. Ignored (with a warning) if
              passed without -Full.

    NOTE ON NAMING: "Preview"/"Full" above is the PERMISSION MODE controlled by
    this switch - it is NOT the same axis as which script file you're running.
    This file (Invoke-RecoveryAssessment-M365-Full.ps1) is the full customer-
    engagement script; Invoke-RecoveryAssessment-M365-Preview.ps1 is the
    separate, redacted webinar/trade-show build. Either script file can be run
    in either permission mode - "the Preview build run with -Full permissions"
    is a real, valid combination, not a contradiction.

    Hub-site keyword detection runs in BOTH modes (no extra scope - it reuses
    already-collected page-view/active-file activity as a breadth proxy, NOT
    a true group-membership count - see README "Hub site detection").

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
    Usage report window: D7, D30, D90, or D180. Default D90.

.PARAMETER OutputPath
    Folder to write CSVs/HTML to. Defaults to a timestamped folder.

.EXAMPLE
    .\Invoke-RecoveryAssessment-M365-Full.ps1

.EXAMPLE
    .\Invoke-RecoveryAssessment-M365-Full.ps1 -Full -RecoveryWindowDays 3 -DowntimeCostPerHour 25000

.EXAMPLE
    .\Invoke-RecoveryAssessment-M365-Full.ps1 -CompareTo .\M365CriticalityAssessment_20260615_090000 -OverridesFile .\overrides.json
#>

[CmdletBinding()]
param(
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D90',

    [string]$OutputPath = ".\M365CriticalityAssessment_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    # Per-workload metric weights - percentile-ranked, then weighted-summed into _Score.
    [hashtable]$MailboxWeights       = @{ SendRecvActivity = 0.45; ReadActivity = 0.25; Size = 0.30 },
    [hashtable]$OneDriveWeights      = @{ FileActivity     = 0.60; Storage      = 0.40 },
    [hashtable]$SharePointWeights    = @{ PageViews        = 0.35; ActiveFiles  = 0.35; Storage  = 0.30 },
    [hashtable]$TeamsWeights         = @{ ActiveUsers      = 0.50; ChannelMsgs  = 0.35; Meetings  = 0.15 },

    # NEW v2.0.0: title-keyword weights (0-1 scale). FULL ONLY (needs JobTitle).
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
    # heuristic. No extra Graph scope - see NOTES. Editable live in the report.
    [string[]]$HubSiteKeywords = @('Payroll','HR','Human Resources','Benefits','IT Help','Help Desk','Service Desk','Finance','Legal','Compliance','Onboarding','Policies'),
    [double]$HubSiteBonus = 0.15,

    # Tier split as fractions of the ACTIVE (non-zero-activity) population.
    [double[]]$TierSplit = @(0.33, 0.33, 0.34),

    [string]$CustomerName = '',

    [switch]$SkipHtmlReport,

    [switch]$Full,

    # NEW: Entra ID group membership enrichment (Mailboxes/OneDrive only, same
    # UPN join as manager enrichment) - requires -Full (it rides the same
    # bulk Get-MgUser directory pull) and requests the extra Group.Read.All
    # scope. Lets you bulk-select/mass-tier "everyone in this group," the
    # same selection model RSC Mass Recovery uses for AD/Entra ID Groups. If
    # passed without -Full, it is ignored with a warning - see Main below.
    [switch]$Groups,

    # NEW: Sizing tab detail - Archive Mailbox storage/items and Recoverable
    # Items sizing, ported from the standalone Get-RubrikM365SizingInfo.ps1
    # sizing script. Requires -Full and a SEPARATE Exchange Online connection
    # (ExchangeOnlineManagement module) plus a per-mailbox loop over every
    # active mailbox - can be slow on large tenants, which is exactly why
    # it's opt-in rather than default. Without this switch, the Sizing tab
    # still shows Exchange/OneDrive/SharePoint totals and Archive Mailbox
    # COUNT (all free, from data already collected) - just not Archive
    # storage or Recoverable Items. If passed without -Full, it is ignored
    # with a warning - see Main below.
    [switch]$DetailedSizing,

    [switch]$IncludeGroupConnectedSites,

    # NEW v2.0.0: seed manual tier overrides from a previously-exported JSON file
    # (the HTML report's "Export overrides" button). Overrides always win over
    # the computed tier and are flagged in the report; re-running without this
    # file does NOT lose overrides as long as you pass the same file back in.
    [string]$OverridesFile = '',

    # NEW v2.0.0: point this run at a PRIOR run's output folder to get a
    # month-over-month tier-movement comparison embedded in the report.
    [string]$CompareTo = '',

    # NEW v2.0.0: recovery-time modeling inputs (see RECOVERY-MODEL-METHODOLOGY.md).
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
    # value). See RECOVERY-MODEL-METHODOLOGY.md.
    [ValidateRange(0, 7)]
    [double]$RecoveryWindowDays = 7,
    # Default of 10,000 chosen as a conservative, defensible floor (SMB-scale
    # downtime cost benchmarks run ~$8,000-$25,000/hr) rather than a
    # made-up round number or a mid/large-enterprise headline figure
    # ($300K-$2M+/hr in Gartner/ITIC/New Relic surveys) - those describe
    # whole-business outages, not a subset of M365 objects being
    # unavailable, and would overstate impact for what this tool models.
    # Always override with the customer's real number when known.
    [double]$DowntimeCostPerHour = 10000,

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
    [string]$TenantId = '',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
)

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
    param([switch]$Full, [switch]$Groups, [switch]$DetailedSizing)

    $required = @('Microsoft.Graph.Reports', 'Microsoft.Graph.Authentication')
    foreach ($m in $required) {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            throw "Required module '$m' is not installed. Run: Install-Module $m -Scope CurrentUser"
        }
        Import-Module $m -ErrorAction Stop
    }

    if ($Full) {
        foreach ($m in @('Microsoft.Graph.Users', 'Microsoft.Graph.Sites')) {
            if (-not (Get-Module -ListAvailable -Name $m)) {
                throw "Required module '$m' is not installed for -Full mode. Run: Install-Module $m -Scope CurrentUser"
            }
            Import-Module $m -ErrorAction Stop
        }
    }
    # NOTE: -Groups does NOT require the separate Microsoft.Graph.Groups
    # module today - group membership is pulled via -ExpandProperty MemberOf
    # on the same Get-MgUser -All call in Get-UserEnrichmentIndex (already
    # part of Microsoft.Graph.Users, already required above for -Full). If a
    # future enhancement adds per-group detail lookups (Get-MgGroup for type/
    # owners/dynamic membership rule), THAT would need Microsoft.Graph.Groups
    # added here - it is not a real requirement yet, so it is not asserted.

    # NEW: -DetailedSizing needs a SEPARATE module (not part of the Graph SDK
    # at all) and a SEPARATE connection (Connect-ExchangeOnline, not
    # Connect-MgGraph) - see Get-DetailedSizingInfo. Checked here, up front,
    # so a missing module fails fast with the same install-command pattern
    # as every other required module, rather than partway through the run.
    if ($DetailedSizing) {
        if (-not (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement')) {
            throw "Required module 'ExchangeOnlineManagement' is not installed for -DetailedSizing. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
        }
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
    }
}

function Connect-Assessment {
    param(
        [switch]$Full,
        [switch]$Groups,
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint
    )

    $scopes = @('Reports.Read.All')
    if ($Full) { $scopes += @('User.Read.All', 'Sites.Read.All') }
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
- (Only if you also want Full-mode enrichment/exact Team-site dedupe:)
  User.Read.All
  Sites.Read.All
- (Only if you also want -Groups - Entra ID group-based bulk selection,
  requires -Full above:)
  Group.Read.All

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

## Optional: -DetailedSizing (Exchange Online app access - NOT a Graph permission)
-DetailedSizing connects to Exchange Online, not Microsoft Graph, so it is NOT
covered by the "Add API permissions" step above - ticking more Graph boxes
does nothing for it. It needs the SAME app registration/certificate from
steps 1-4, PLUS an Exchange Online-side grant:

1. API permissions > Add a permission > APIs my organization uses >
   "Office 365 Exchange Online" > Application permissions > Exchange.ManageAsApp.
   Grant admin consent (same Global/Privileged Role Administrator requirement
   as step 2).
2. In Exchange Online PowerShell (an admin, one time):
       Connect-ExchangeOnline
       New-ServicePrincipal -AppId <client-id> -ObjectId <app's Entra object ID>
3. Assign the app's service principal an Exchange Online admin role scoped to
   what it needs (e.g. "View-Only Recipients" is enough to read mailbox/
   folder statistics - avoid a broader role than the read-only access this
   switch actually uses):
       New-ManagementRoleAssignment -Role "View-Only Recipients" -App <client-id>

Without this, -DetailedSizing will authenticate to Graph fine but fail when
it tries to connect to Exchange Online - the rest of the report is
unaffected (see Get-DetailedSizingInfo's error handling).

## 5. Run the assessment
    .\Invoke-RecoveryAssessment-M365-Full.ps1 -TenantId <tenant-id> -ClientId <client-id> -CertificateThumbprint <thumbprint> [-Full] [-DetailedSizing] [other params]

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
        from a single Get-MgUser -All call - no extra per-user Graph calls.
        Joined onto Mailboxes/OneDrive by UPN in Add-UserEnrichment.

        -IncludeGroups (needs -Groups, which needs Group.Read.All): expands
        'MemberOf' on the SAME Get-MgUser -All call (no extra Graph round
        trip) and keeps only entries that are actual Entra ID groups
        (filters out directory roles / administrative units, which also
        come back on memberOf). Without Group.Read.All granted, memberOf
        still resolves object IDs but displayName comes back null/limited -
        so this quietly produces an empty Groups list rather than an error
        if -Groups was passed but the scope wasn't actually consented.
    #>
    param([switch]$IncludeGroups)

    $indexByUpn = @{}
    $indexById  = @{}
    $expand = if ($IncludeGroups) { @('Manager', 'MemberOf') } else { @('Manager') }
    try {
        $users = Get-MgUser -All -Property 'Id,UserPrincipalName,DisplayName,JobTitle,Department,EmployeeType,OfficeLocation,Country,UsageLocation,AccountEnabled' -ExpandProperty $expand -ErrorAction Stop
    }
    catch {
        Write-Warning "User profile enrichment failed ($($_.Exception.Message)). Continuing without it."
        return $indexByUpn
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
        if ($IncludeGroups -and $u.MemberOf) {
            foreach ($m in $u.MemberOf) {
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

function Add-UserEnrichment {
    param(
        [Parameter(Mandatory)] [array]     $Data,
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
        Add-Member -InputObject $row -NotePropertyName 'ManagerChain'   -NotePropertyValue $(if ($enrich) { $enrich.ManagerChain } else { @() })  -Force
        Add-Member -InputObject $row -NotePropertyName 'Groups'         -NotePropertyValue $(if ($enrich) { $enrich.Groups } else { @() })        -Force
        Add-Member -InputObject $row -NotePropertyName 'GroupIds'       -NotePropertyValue $(if ($enrich) { $enrich.GroupIds } else { @() })      -Force
        Add-Member -InputObject $row -NotePropertyName 'OfficeLocation' -NotePropertyValue $(if ($enrich) { $enrich.OfficeLocation } else { '' }) -Force
        Add-Member -InputObject $row -NotePropertyName 'AccountEnabled' -NotePropertyValue $(if ($enrich) { $enrich.AccountEnabled } else { $null }) -Force
    }
    return $Data
}

function Add-MailboxTypeHeuristic {
    <#
        v3.0.0: the mailbox usage report (Get-MgReportMailboxUsageDetail,
        already pulled in PREVIEW mode - no extra scope) includes a real
        'Recipient Type' column (e.g. "User Mailbox", "Shared Mailbox",
        "Room Mailbox", "Equipment Mailbox"). Validated against real customer
        data: the OLD proxy below (AccountEnabled=$false => "likely
        Shared/Resource") caught 0 of 2 real Shared mailboxes in that data -
        both had AccountEnabled=$true - i.e. it was worse than a coin flip.
        Recipient Type is now the AUTHORITATIVE signal and is populated by
        Get-MailboxCriticality regardless of -Full. The old
        AccountEnabled-based guess is kept ONLY as a last-resort fallback for
        the rare tenant/report export where Recipient Type comes back blank,
        and only runs in that case.
    #>
    param([Parameter(Mandatory)] [array] $Data)
    foreach ($row in $Data) {
        $recipientType = [string]$row.RecipientType
        $type = if ($recipientType) {
            switch -Regex ($recipientType) {
                'Shared'    { 'Shared Mailbox (Recipient Type)'; break }
                'Room'      { 'Room Mailbox (Recipient Type)'; break }
                'Equipment' { 'Equipment Mailbox (Recipient Type)'; break }
                'User'      { 'User Mailbox (Recipient Type)'; break }
                default     { "$recipientType (Recipient Type)" }
            }
        }
        elseif ($null -eq $row.AccountEnabled -or $row.AccountEnabled -eq '') {
            'Unknown (Recipient Type blank; run -Full for the AccountEnabled fallback)'
        }
        elseif ($row.AccountEnabled -eq $false) {
            'Likely Shared/Resource (AccountEnabled fallback - Recipient Type was blank; low confidence, see Methodology tab)'
        }
        else {
            'User (AccountEnabled fallback - Recipient Type was blank)'
        }
        Add-Member -InputObject $row -NotePropertyName 'MailboxTypeHeuristic' -NotePropertyValue $type -Force
    }
    return $Data
}

function Add-TitleWeightScore {
    <# FULL ONLY (needs JobTitle). Highest-weight keyword match wins. #>
    param(
        [Parameter(Mandatory)] [array]     $Data,
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
        [Parameter(Mandatory)] [array]    $Data,
        [Parameter(Mandatory)] [string[]] $Keywords,
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
    <# FULL MODE ONLY (needs Sites.Read.All). See v1.2.1/1.2.2 notes retained below. #>
    param([Parameter(Mandatory)] [array] $Teams)

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
        [Parameter(Mandatory)] [array] $Data,
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
        [Parameter(Mandatory)] [array]     $Data,
        [Parameter(Mandatory)] [hashtable] $MetricWeights
    )
    $friendly = @{
        SendRecvActivity = 'Send/receive volume'; ReadActivity = 'Read volume'; Size = 'Mailbox size'
        FileActivity     = 'File activity';       Storage      = 'Storage size'
        PageViews        = 'Page views';          ActiveFiles  = 'Active files'
        ActiveUsers      = 'Active users';        ChannelMsgs  = 'Channel messages'; Meetings = 'Meetings organized'
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
        [Parameter(Mandatory)] [array] $Data,
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
        estimate. See RECOVERY-MODEL-METHODOLOGY.md.

        Tiering itself no longer depends on this - see Add-Tier, now called
        uniformly for all five workloads. This function only feeds
        Build-RecoveryModel's ABR (hot-scope) recovery-time figures.
    #>
    param(
        [Parameter(Mandatory)] [array]  $Data,
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
        Protect-PreviewData's redaction decision in the Preview script and
        the exported CSVs/manifest here - both would silently drift from
        what the live report ends up showing on load if this algorithm ever
        diverges from assignBudgetTiers(). See RECOVERY-MODEL-METHODOLOGY.md.

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
        [Parameter(Mandatory)] [array]  $Data,
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
        [Parameter(Mandatory)] [array]     $Data,
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
        [Parameter(Mandatory)] [array]  $Data,
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
    Reverse-engineered from the customer's own MVC Recovery Time Estimator
    export (mvc-recovery-estimate-2026-07-15.csv, "formula-preserving export").
    Full derivation is in RECOVERY-MODEL-METHODOLOGY.md - summary:

    The source tool computes, for SharePoint/OneDrive/Exchange, an "effective"
    items-per-minute and bytes(or MB)-per-minute throughput, capped by a
    size-tier lookup table (SP/OD) or fixed benchmark constants (EX), then
    Full-restore time = MAX(items / effective items-per-min, storage /
    effective bytes-per-min). We reuse that exact throughput-cap engine, but
    apply it to each CRITICALITY TIER's real object/item/storage totals
    instead of the source tool's modeled "MVC %" sample - because our tiers
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
    @{ Bucket = '50k+';    Max = [double]::PositiveInfinity;  Parallelism = 15 }
)
# NEW v3.10.0 (M365 MVC Recovery Time Estimator - RSC M365 Restoration
# Benchmark, Mar 2025 / M365 Sizing Guidance, Jan 2026 - superseding the
# earlier "MVC Recovery Time Estimator" export this formula was originally
# reverse-engineered from). SharePoint and OneDrive now have DIFFERENT
# per-object-of-parallelism item rates (108/168 items/min/unit - 27/42
# files/sec at 15-way parallelism, divided out so lower tiers scale down),
# instead of sharing one ItemsPerMinCap/BytesPerMinCap table. There is no
# separate bytes/min cap anymore for SP/OD - an oversized average item is
# instead penalized via SizeFactor (inflates the EFFECTIVE item count,
# rather than throttling a second, independent byte-rate). See
# Get-RecoveryTimeMinutes and RECOVERY-MODEL-METHODOLOGY.md.
$script:SP_ItemsPerMinPerUnit = 108
$script:OD_ItemsPerMinPerUnit = 168
# A file bigger than this (MiB, org-wide average) costs proportionally more
# than the ~1-API-call baseline; never speeds up below it (factor floors at
# 1x). Assumed, not measured - the pivot for the whole size-factor concept.
$script:SizeFactorBaselineMB = 3
# Job-launch/scheduling overhead: a FIXED per-object cost (every object
# touched by a restore - even one with a single changed item - needs its
# own restore job) modeling 1,000 restore jobs launched/settled in 6 hours.
# Applies to ABR (the source tool's "MVC") recovery time only - a full/
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

        v3.10.0: reworked to match the M365 MVC Recovery Time Estimator (RSC
        M365 Restoration Benchmark, Mar 2025 / M365 Sizing Guidance, Jan
        2026), superseding the earlier export this formula was originally
        reverse-engineered from. Two structural changes from before:
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
             ABR (the source tool's "MVC") actually costs on top of raw
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
        [Parameter(Mandatory)] [array] $SharePoint,
        [Parameter(Mandatory)] [array] $OneDrive,
        [Parameter(Mandatory)] [array] $Mailboxes,
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
        # live-adjustable. See RECOVERY-MODEL-METHODOLOGY.md.
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

        $milestones[$tierName] = [ordered]@{
            SP = [ordered]@{ ObjectCount = $spSlice.ObjectCount; ItemCount = $spSlice.ItemCount; Storage = $spSlice.Storage; TimeMin = [math]::Round($spTime,2); CumulativeMin = [math]::Round($cumSP,2); MassTimeMin = [math]::Round($massSPTime,2) }
            OD = [ordered]@{ ObjectCount = $odSlice.ObjectCount; ItemCount = $odSlice.ItemCount; Storage = $odSlice.Storage; TimeMin = [math]::Round($odTime,2); CumulativeMin = [math]::Round($cumOD,2); MassTimeMin = [math]::Round($massODTime,2) }
            EX = [ordered]@{ ObjectCount = $exSlice.ObjectCount; ItemCount = $exSlice.ItemCount; Storage = $exSlice.Storage; TimeMin = [math]::Round($exTime,2); CumulativeMin = [math]::Round($cumEX,2); MassTimeMin = [math]::Round($massEXTime,2) }
            WallClockCumulativeMin = [math]::Round([math]::Max([math]::Max($cumSP,$cumOD),$cumEX), 2)
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
        [Parameter(Mandatory)] [array]  $SharePoint,
        [Parameter(Mandatory)] [array]  $OneDrive,
        [Parameter(Mandatory)] [array]  $Mailboxes,
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
        "Budget-constrained tiering" in RECOVERY-MODEL-METHODOLOGY.md for
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
        [Parameter(Mandatory)] [array]  $SharePoint,
        [Parameter(Mandatory)] [array]  $OneDrive,
        [Parameter(Mandatory)] [array]  $Mailboxes,
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

function Get-GraphReport {
    <#
        NEW v3.7.1: actually implements the fix the comment above
        $ProgressPreference always pointed at but never built - confirmed
        2026-07-31 against a real tenant that a failed SharePoint site usage
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
        [Parameter(Mandatory)] [array] $Data,
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

#endregion

#region ---------- Workload collectors ----------

# NEW: -DetailedSizing (Full only) - Archive Mailbox storage/items and
# Recoverable Items sizing, ported from the standalone
# Get-RubrikM365SizingInfo.ps1 sizing script (Get-RecoverableItemsInfo,
# Get-RIFMailboxStats, and the archive-size loop). Requires a SEPARATE
# Exchange Online connection (ExchangeOnlineManagement module, asserted in
# Assert-GraphModules) - Microsoft Graph has no equivalent report for
# either of these. Archive size is scoped to only the mailboxes already
# flagged HasArchive (free, from the usage report) rather than looping
# every mailbox; Recoverable Items loops every active mailbox, same scope
# as the original script, and is the slower/timeout-risk half of this -
# exactly why the whole thing is opt-in.

function Connect-ExchangeOnlineForSizing {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint
    )
    $useAppOnly = $TenantId -and $ClientId -and $CertificateThumbprint
    if ($useAppOnly) {
        Write-Host "Connecting to Exchange Online via Enterprise App (application permissions) as $ClientId..." -ForegroundColor Cyan
        Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -Organization $TenantId -ShowBanner:$false
    } else {
        Write-Host "Connecting to Exchange Online (delegated, interactive) for -DetailedSizing..." -ForegroundColor Cyan
        Connect-ExchangeOnline -ShowBanner:$false
    }
}

function Get-RecoverableItemsInfo {
    <# Per-mailbox Recoverable Items folder size/items (Deletions/Purges/Versions/DiscoveryHolds), primary + optionally In-Place Archive. Ported near-verbatim from Get-RubrikM365SizingInfo.ps1. #>
    param(
        [Parameter(Mandatory)] [string]$Mailbox,
        [Parameter(Mandatory)] [bool]  $IncludeArchiveMailbox
    )
    $result = [PSCustomObject]@{ UserPrincipalName = $Mailbox; RIFSize = 0.0; RIFItems = 0.0 }
    $recoverableItemsSpecialFolders = @('/Deletions', '/Purges', '/Versions', '/DiscoveryHolds')

    $primaryStats = @()
    try {
        $primaryStats = @(Get-MailboxFolderStatistics -Identity $Mailbox -FolderScope RecoverableItems -ErrorAction Stop |
            Where-Object { $recoverableItemsSpecialFolders -contains $_.FolderPath })
    } catch {
        Write-Warning "Recoverable Items folder stats failed for $Mailbox : $($_.Exception.Message)"
    }

    $inPlaceStats = @()
    if ($IncludeArchiveMailbox) {
        try {
            $inPlaceStats = @(Get-MailboxFolderStatistics -Identity $Mailbox -FolderScope RecoverableItems -Archive -ErrorAction Stop |
                Where-Object { $recoverableItemsSpecialFolders -contains $_.FolderPath })
        } catch {
            Write-Warning "In-Place Archive Recoverable Items folder stats failed for $Mailbox : $($_.Exception.Message)"
        }
    }

    $folderStats = @($primaryStats) + @($inPlaceStats)
    foreach ($stats in $folderStats) {
        if ($stats.FolderSize -match '\(([^)]+) bytes\)') {
            $result.RIFSize += [long]($Matches[1] -replace ',', '')
        }
    }
    $totalItems = $folderStats | Measure-Object -Property 'ItemsInFolder' -Sum
    $result.RIFItems = if ($totalItems.Sum) { $totalItems.Sum } else { 0.0 }
    return $result
}

function Get-DetailedSizingInfo {
    <# Archive Mailbox storage/items + Recoverable Items sizing - the -DetailedSizing half of the Sizing tab. Connects to Exchange Online itself; always disconnects before returning, even on error. #>
    param(
        [Parameter(Mandatory)] [array]  $Mailboxes,
        [string] $TenantId,
        [string] $ClientId,
        [string] $CertificateThumbprint
    )

    Write-Host "`n--- Detailed Sizing (Archive + Recoverable Items) ---" -ForegroundColor Yellow
    Write-Host "This connects to Exchange Online separately and loops per-mailbox - can be slow on large tenants." -ForegroundColor Yellow

    $result = [PSCustomObject]@{
        archiveStorageBytes          = 0.0
        archiveItems                 = 0.0
        recoverableItemsCount        = 0
        recoverableItemsStorageBytes = 0.0
        recoverableItemsItems        = 0.0
    }

    try {
        Connect-ExchangeOnlineForSizing -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint

        $archiveMailboxes = @($Mailboxes | Where-Object { $_.HasArchive })
        $archiveCount = $archiveMailboxes.Count
        Write-Host "Gathering Archive Mailbox sizing for $archiveCount mailbox(es) already flagged as having an archive..." -ForegroundColor Gray
        $archiveSizeSum = 0.0
        $archiveItemSum = 0.0
        $i = 0
        foreach ($mb in $archiveMailboxes) {
            $i++
            if (($i % 25) -eq 0) { Write-Host "  [$i / $archiveCount] Archive mailboxes processed..." -ForegroundColor DarkGray }
            try {
                $stats = Get-EXOMailboxStatistics -Archive -Identity $mb.Identifier -ErrorAction Stop
                if ($stats.TotalItemSize -match '\(([^)]+) bytes\)') {
                    $archiveSizeSum += [long]($Matches[1] -replace ',', '')
                    $archiveItemSum += $stats.ItemCount
                }
            } catch {
                Write-Warning "Archive mailbox stats failed for $($mb.Identifier): $($_.Exception.Message)"
            }
        }
        $result.archiveStorageBytes = $archiveSizeSum
        $result.archiveItems = $archiveItemSum

        $rifTotal = $Mailboxes.Count
        Write-Host "Gathering Recoverable Items sizing for $rifTotal mailbox(es)..." -ForegroundColor Gray
        $rifSizeSum = 0.0
        $rifItemSum = 0.0
        $rifCount = 0
        $i = 0
        foreach ($mb in $Mailboxes) {
            $i++
            if (($i % 25) -eq 0) { Write-Host "  [$i / $rifTotal] Recoverable Items processed..." -ForegroundColor DarkGray }
            try {
                $rif = Get-RecoverableItemsInfo -Mailbox $mb.Identifier -IncludeArchiveMailbox ([bool]$mb.HasArchive)
                $rifSizeSum += $rif.RIFSize
                $rifItemSum += $rif.RIFItems
                $rifCount++
            } catch {
                Write-Warning "Recoverable Items info failed for $($mb.Identifier): $($_.Exception.Message)"
            }
        }
        $result.recoverableItemsCount = $rifCount
        $result.recoverableItemsStorageBytes = $rifSizeSum
        $result.recoverableItemsItems = $rifItemSum

        Write-Host "Finished Detailed Sizing." -ForegroundColor Green
        Write-Host ("  Archive: {0} mailbox(es), {1:N2} GB, {2:N0} items" -f $archiveCount, ($archiveSizeSum / 1GB), $archiveItemSum) -ForegroundColor Gray
        Write-Host ("  Recoverable Items: {0} mailbox(es), {1:N2} GB, {2:N0} items" -f $rifCount, ($rifSizeSum / 1GB), $rifItemSum) -ForegroundColor Gray
    }
    finally {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
    }

    return $result
}

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
    # the $Period pull. See RECOVERY-MODEL-METHODOLOGY.md.
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
        # usage report - already pulled in PREVIEW mode, no extra scope needed.
        # Authoritative signal for Add-MailboxTypeHeuristic (replaces the old
        # AccountEnabled proxy - see that function's header for why).
        $recipientType = Get-ColumnValue $u @('Recipient Type') ''
        # NEW: "Has Archive" - straight from the SAME mailbox usage report
        # (getMailboxUsageDetail), no extra scope/module. This is the free
        # half of the Sizing tab's Archive Mailbox line: a real count comes
        # from this flag alone. The archive's actual SIZE/item count needs a
        # separate Exchange Online connection and a per-mailbox loop - see
        # -DetailedSizing - and is intentionally NOT gathered here.
        $hasArchive = (Get-ColumnValue $u @('Has Archive') '') -eq 'TRUE'

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
                "Exact match to a Team's SharePoint site (resolved via Get-MgGroupSite, Full mode) - already tiered under Teams."
            } else {
                "Group/Teams-connected site (RootWebTemplate=$template) - heuristic match, likely already tiered under Teams. Re-run with -IncludeGroupConnectedSites to keep sites like this, or -Full for exact (non-heuristic) matching."
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
            Identifier        = Get-ColumnValue $t @('Team Id') ''
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

$script:ReportCss = @'
:root {
  --teal:#4DD2D2; --cyan:#2FCAFF; --green:#21DDAA; --blue:#0E5BCF;
  --navy:#093565; --navy-dark:#0A2E57; --yellow:#FFBE49;
  --mid-gray:#A4A9A8; --dark-gray:#6C7576; --white:#FFFFFF;
  /* The one deliberate exception to "never use red for mere priority
     ranking" in this report. Reserved for "exceeds RTO target" callouts -
     missing a stated recovery-time commitment is a genuine negative
     outcome, not just a ranking, so it earns a distinct, brand-consistent
     red. */
  --red-target:#E5484D;
}
/* NEW: presenter/1920x1080 pass. Root font-size scales with viewport width
   via clamp() - since virtually every rule in this stylesheet sizes text in
   rem, this single rule makes ALL of it (headings, body, table cells) fill
   out a large presenting display without needing separate clamp() calls on
   every selector. Flat 15px below ~1000px viewport width, flat 18px above
   ~1500px (covers the 1920px presenting case), smooth in between. */
html { font-size: clamp(15px, 0.6vw + 9px, 18px); }
* { box-sizing: border-box; }
body { margin: 0; background: #F4F6F8; color: #1B2430; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
.rainbow-bar { height: 4px; position: fixed; top: 0; left: 0; right: 0; z-index: 1000; background: linear-gradient(90deg, #4DD2D2, #2FCAFF, #8247DD, #21DDAA); }
.header { margin-top: 4px; color: #fff; padding: 2.25rem 3rem 1.75rem; background: linear-gradient(135deg, var(--navy) 0%, var(--navy-dark) 60%, #03142E 100%); }
.header .logo svg { height: 34px; width: auto; display: block; }
.header .eyebrow { font-size: .72rem; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; color: var(--teal); margin: 1.5rem 0 .5rem; }
.header h1 { font-size: clamp(1.6rem, 3vw, 2.4rem); font-weight: 800; margin: 0 0 .6rem; line-height: 1.15; }
.header .meta { font-size: .9rem; color: rgba(255,255,255,.7); display: flex; gap: 1.75rem; flex-wrap: wrap; }
.header .meta b { color: rgba(255,255,255,.95); font-weight: 600; }
.tabbar { position: sticky; top: 4px; z-index: 999; background: #fff; border-bottom: 1px solid #E2E6EA; padding: 0 3rem; display: flex; gap: .25rem; flex-wrap: wrap; box-shadow: 0 2px 6px rgba(0,0,0,.05); }
.tab-btn { border: none; background: none; padding: .9rem 1rem; font-size: .85rem; font-weight: 700; color: var(--dark-gray); cursor: pointer; border-bottom: 3px solid transparent; }
.tab-btn.active { color: var(--navy); border-bottom-color: var(--blue); }
.tab-btn:hover { color: var(--navy); }
main { padding: 2rem 2.75rem 4rem; max-width: 1800px; margin: 0 auto; }
.tab-panel { display: none; }
.tab-panel.active { display: block; }
h2 { font-size: 1.3rem; font-weight: 800; color: var(--navy); margin: 0 0 1.25rem; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.1rem; margin-bottom: 2rem; }
.summary-card { display: block; background: #fff; border-radius: 12px; padding: 1.1rem 1.4rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); border-left: 4px solid var(--accent, var(--blue)); text-decoration: none; color: inherit; cursor: pointer; transition: box-shadow .15s ease, transform .15s ease; }
.summary-card:hover { box-shadow: 0 6px 16px rgba(9,53,101,.14); transform: translateY(-2px); }
.summary-card h3 { margin: 0 0 .15rem; font-size: .82rem; text-transform: uppercase; letter-spacing: 1px; color: var(--dark-gray); }
.summary-card .total { font-size: 2rem; font-weight: 800; color: var(--navy); margin: .1rem 0 .65rem; }
.tier-bar { display: flex; height: 9px; border-radius: 6px; overflow: hidden; margin-bottom: .6rem; background: #EEF1F4; }
.tier-bar span { display: block; height: 100%; }
.tier-legend { font-size: .74rem; color: var(--dark-gray); display: flex; flex-direction: column; gap: .2rem; }
.tier-legend > div { display: flex; align-items: center; gap: .4rem; }
.totals-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: .75rem; margin-bottom: 1.5rem; }
.totals-cell { background: #fff; border-radius: 8px; padding: .8rem 1rem; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
.totals-cell .label { font-size: .72rem; text-transform: uppercase; color: var(--dark-gray); letter-spacing: .5px; }
.totals-cell .value { font-size: 1.3rem; font-weight: 800; color: var(--navy); }

/* NEW: Executive Summary hero sections (Financial Impact, Recovery Times) -
   the point of this whole exercise is breaking critical objects into groups
   to shrink recovery time, so those figures now lead the exec summary
   instead of trailing after the workload cards. Bigger/bolder than
   .totals-cell so they read as the headline, not a footnote. */
.exec-hero-label { font-size: .95rem; font-weight: 800; color: var(--navy); margin: 0 0 .7rem; text-transform: uppercase; letter-spacing: .5px; }
.exec-hero-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.6rem; }
.exec-hero-card { background: #fff; border-radius: 12px; padding: 1.1rem 1.4rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); border-left: 4px solid var(--blue); }
.exec-hero-card.savings { border-left-color: var(--green); }
.exec-hero-card.exposure { border-left-color: var(--red-target); }
.exec-hero-card .exec-hero-tag { font-size: .72rem; text-transform: uppercase; letter-spacing: .5px; color: var(--dark-gray); font-weight: 700; }
.exec-hero-card .exec-hero-value { font-size: 1.9rem; font-weight: 800; color: var(--navy); margin: .2rem 0; }
.exec-hero-card .exec-hero-sub { font-size: .82rem; color: var(--dark-gray); }
.exec-hero-note { font-size: .78rem; color: var(--dark-gray); background: #F0F3F6; border-radius: 8px; padding: .55rem .85rem; margin: -.6rem 0 1.6rem; }
.exec-hero-linkout { font-size: .78rem; color: var(--blue); cursor: pointer; text-decoration: underline; }

/* NEW: Financial Impact as a before/after comparison, closed with a bold
   savings punchline - per feedback 2026-07-15, this is the clearest way to
   show ABR's value: it doesn't change TOTAL recovery time, it changes how
   much downtime cost you accrue before your most critical data is back.
   Two cards side by side (Mass Recovery "before" vs ABR "after"), then one
   bold closing line with $ saved AND a % reduction (percentages read faster
   than raw dollars regardless of company size). */
.exec-fin-compare { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
.exec-fin-compare-card { flex: 1 1 240px; background: #fff; border-radius: 12px; padding: 1.1rem 1.4rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); border-left: 4px solid var(--red-target); }
.exec-fin-compare-card.after { border-left-color: var(--blue); }
.exec-fin-compare-label { font-size: .72rem; text-transform: uppercase; letter-spacing: .5px; color: var(--dark-gray); font-weight: 700; }
.exec-fin-compare-time { font-size: 1.7rem; font-weight: 800; color: var(--navy); margin: .2rem 0; }
.exec-fin-compare-cost { font-size: 1rem; font-weight: 700; color: #2B3542; }
.exec-fin-compare-arrow { font-size: 1.6rem; color: var(--mid-gray); flex: 0 0 auto; }
.exec-fin-punchline { background: #EDFBF6; border: 1px solid #BEEFDD; border-radius: 10px; padding: .9rem 1.3rem; font-size: 1rem; font-weight: 600; color: #0A6B4E; margin-bottom: 1.6rem; }
.exec-fin-punchline b { font-size: 1.35rem; }
/* NEW v3.4.0: time-first headline, per feedback 2026-07-17 - leads with
   "your most critical data is usable in X instead of Y" before any dollar
   figure, since pairing "$ saved" with "without changing total recovery
   time" read as muddy to an exec ("so I still wait Y?"). Time is the hook;
   dollars below it are supporting evidence. Shown even when $/hour isn't
   set, since the time comparison stands on its own. */
.exec-fin-headline { font-size: 1.15rem; font-weight: 700; color: var(--navy); margin: 0 0 1.2rem; max-width: 68ch; }
.exec-fin-headline b { color: #0A6B4E; font-size: 1.35rem; }
/* Recovery Timeline under Financial Impact - v3.3.0 (2026-07-16), third
   redesign of the day. v3.1.1: two stacked rows, ABR on top, NOT drawn to
   scale. v3.1.2: combined into one bar, still not to scale. v3.3.0 (this
   version) flips the whole premise per a reference mockup the user
   provided: go BACK to genuinely-to-scale, real-timescale tracks, but lean
   into that instead of fighting it - "Without ABR" is a full-width bar
   (it's the whole timescale, `model.fullRestoreMin`); "With ABR" is the
   SAME timescale, so Groups 1/2/3 collapse to a small chip cluster near the
   left edge, followed by a large, deliberately de-emphasized "rest of
   tenant continues in background" fill. The tiny cluster IS the point - the
   empty space next to it is what ABR bought you. A floor (min-width, plus a
   minimum overall cluster share) keeps the cluster and each of Groups 1/2/3
   individually visible rather than collapsing to literal sub-pixel widths,
   since the real proportion (a few hours out of ~19 days) would otherwise
   render as nothing at all. Real numbers are always available via tooltips
   and the bold gap callout below the tracks. */
.fin-timeline { margin-top: 1.6rem; }
.fin-tl-title { font-size: 1rem; font-weight: 800; color: var(--navy); margin: 0 0 .3rem; }
.fin-tl-desc { font-size: .85rem; color: var(--dark-gray); margin: 0 0 1.3rem; max-width: 62ch; }
.fin-tl-track-block { margin-bottom: 1.3rem; }
.fin-tl-track-label { font-size: .95rem; font-weight: 800; color: var(--navy); margin: 0 0 .1rem; }
.fin-tl-track-sublabel { font-size: .8rem; color: var(--dark-gray); margin: 0 0 .5rem; }
.fin-tl-track-row { display: flex; align-items: center; gap: .7rem; }
.fin-tl-track-bar { flex: 1 1 auto; height: 52px; border-radius: 10px; overflow: hidden; display: flex; align-items: center; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
/* NEW v3.4.1: both bars now fade to transparent on their trailing edge
   (mask-image), per feedback 2026-07-17 - visually reinforces that both
   rows run out to the SAME real endpoint (the end label just past the
   fade), rather than the hatched bar looking like it just stops. Applied
   to the hatched "Without ABR" bar and, separately, to .fin-tl-bg-fill (the
   "With ABR" row's trailing background-restore portion), which now also
   carries the same diagonal-hatch pattern - both rows use identical
   visual language for "still restoring, in random order, off toward the
   same total." */
.fin-tl-track-bar.hatched { background-color: #D7DCE1; background-image: repeating-linear-gradient(45deg, rgba(255,255,255,.55) 0, rgba(255,255,255,.55) 7px, transparent 7px, transparent 14px); padding: 0 1.2rem; mask-image: linear-gradient(to right, #000 0%, #000 65%, transparent 97%); -webkit-mask-image: linear-gradient(to right, #000 0%, #000 65%, transparent 97%); }
.fin-tl-track-bar-text { font-weight: 700; font-size: .92rem; color: #2B3542; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.fin-tl-track-endlabel { flex: 0 0 auto; font-size: 1.15rem; font-weight: 800; color: var(--navy); white-space: nowrap; display: flex; align-items: center; gap: .3rem; }
.fin-tl-track-endlabel .arrow { color: var(--mid-gray); font-size: 1.1rem; }
.fin-tl-track-bar.with-abr { background: #F0F3F6; padding: 0; }
.fin-tl-chip-cluster { flex: 0 0 auto; display: flex; align-items: stretch; height: 100%; gap: 2px; padding: 6px; box-sizing: border-box; }
.fin-tl-chip { border-radius: 4px; min-width: 6px; }
.fin-tl-bg-fill { flex: 1 1 auto; height: 100%; display: flex; align-items: center; justify-content: center; color: #5A6B7B; font-size: .82rem; font-style: italic; white-space: nowrap; overflow: hidden; background-color: #D7DCE1; background-image: repeating-linear-gradient(45deg, rgba(255,255,255,.55) 0, rgba(255,255,255,.55) 7px, transparent 7px, transparent 14px); mask-image: linear-gradient(to right, #000 0%, #000 40%, transparent 96%); -webkit-mask-image: linear-gradient(to right, #000 0%, #000 40%, transparent 96%); }
.fin-tl-gap-callout { font-size: .95rem; color: var(--dark-gray); margin: 0 0 1.2rem; }
.fin-tl-gap-callout b { color: #0A6B4E; font-size: 1.05rem; }
.fin-tl-legend { display: flex; flex-wrap: wrap; gap: .45rem 1.5rem; margin: .6rem 0 .5rem; }
.fin-tl-legend-item { display: flex; align-items: center; gap: .45rem; font-size: .8rem; color: var(--navy); }
.fin-tl-swatch { width: 12px; height: 12px; border-radius: 3px; flex: 0 0 auto; }
.fin-tl-legend-item b { font-weight: 800; }
.fin-tl-legend-item .fin-tl-sub { color: var(--dark-gray); font-weight: 400; }
.fin-tl-track-note { font-size: .78rem; color: var(--dark-gray); background: #F0F3F6; border-radius: 8px; padding: .55rem .85rem; margin-bottom: 1.6rem; }
/* NEW v3.4.0: Dormant Data callout, per feedback 2026-07-17 - "Dormant: N"
   was sitting as one equally-weighted cell in the tier totals grid, easy to
   miss even though it's often the single most striking fact in the whole
   report: a large majority of a tenant can be genuinely dormant, which Mass
   Recovery restores blindly and in full every time, while ABR already knows
   to leave it for last. Uses the same amber TIER_META color already used
   for the Dormant tier everywhere else, so it reads as "the same thing,"
   just promoted to headline weight. */
.exec-dormant-headline { font-size: 1rem; color: var(--navy); margin: 0 0 1rem; max-width: 72ch; }
.exec-dormant-headline b { font-size: 1.3rem; color: #B8860B; }
.exec-dormant-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .8rem; margin-bottom: 1.6rem; }
.exec-dormant-cell { background: #fff; border-radius: 10px; padding: .9rem 1.1rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); border-left: 4px solid #FFBE49; }
.exec-dormant-pct { font-size: 1.5rem; font-weight: 800; color: var(--navy); }
.exec-dormant-label { font-size: .78rem; font-weight: 700; color: var(--dark-gray); text-transform: uppercase; letter-spacing: .5px; margin-top: .2rem; }
.exec-dormant-sub { font-size: .78rem; color: var(--dark-gray); margin-top: .15rem; }
/* NEW v3.10.1: per-workload Group 4 Mass Recovery time, added below the
   existing count line - see renderExecFinancialAndRecoveryTop for what this
   number represents (that workload's OWN full dataset mass-recovered in one
   undifferentiated batch, not just Group 4's slice - Group 4 has no ABR
   priority, so it rides along with however long that workload's Mass
   Recovery job as a whole takes). */
.exec-dormant-time { font-size: .78rem; color: var(--navy); font-weight: 700; margin-top: .35rem; padding-top: .35rem; border-top: 1px dashed #e2e2e2; }
.exec-dormant-time-na { font-size: .72rem; color: var(--dark-gray); font-style: italic; margin-top: .35rem; padding-top: .35rem; border-top: 1px dashed #e2e2e2; }
/* NEW v3.6.0: Dormant Data collapsible - moved to the bottom of the Report
   tab and collapsed by default, per feedback 2026-07-22. This section is
   context/color for what ABR already deprioritizes, not part of the primary
   financial/recovery-time narrative above it - collapsing it by default
   keeps the tab's reading order focused on the numbers that drive the
   business case, while still making the detail one click away. */
.exec-collapsible { margin-top: 1.8rem; background: #F0F3F6; border-radius: 12px; overflow: hidden; }
.exec-collapsible-toggle { display: flex; align-items: center; gap: .7rem; width: 100%; background: none; border: none; cursor: pointer; padding: 1rem 1.2rem; text-align: left; font-family: inherit; }
.exec-collapsible-toggle:hover { background: rgba(9,53,101,.04); }
.exec-collapsible-chevron { display: inline-block; font-size: .75rem; color: var(--dark-gray); transition: transform .15s ease; flex: 0 0 auto; }
.exec-collapsible-toggle[aria-expanded="true"] .exec-collapsible-chevron { transform: rotate(90deg); }
.exec-collapsible-title { font-weight: 800; color: var(--navy); font-size: .95rem; flex: 1 1 auto; }
.exec-collapsible-summary { font-size: .85rem; color: var(--dark-gray); flex: 0 0 auto; }
.exec-collapsible-body { padding: 0 1.2rem 1.4rem; }
.exec-collapsible-body[hidden] { display: none; }
/* NEW v3.5.0: lean Executive Summary tab - three big stat tiles (Time to
   Critical Data, Downtime Cost Avoided, Dormant Data), a one-sentence
   mechanism callout, and a link down to the Report tab for everything
   else. Deliberately much bigger/bolder than .exec-hero-card - this tab
   has nothing else competing for attention, so the numbers can be huge. */
.exec-lean-tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
.exec-lean-tile { background: #fff; border-radius: 16px; padding: 2.2rem 2rem; box-shadow: 0 4px 18px rgba(9,53,101,.08); border-top: 6px solid var(--blue); }
.exec-lean-tile.money { border-top-color: #0A6B4E; }
.exec-lean-tile.dormant { border-top-color: #FFBE49; }
.exec-lean-tile-label { font-size: .8rem; font-weight: 800; text-transform: uppercase; letter-spacing: .8px; color: var(--dark-gray); margin-bottom: .6rem; }
.exec-lean-tile-value { font-size: 3.2rem; font-weight: 900; color: var(--navy); line-height: 1; margin-bottom: .5rem; }
.exec-lean-tile.money .exec-lean-tile-value { color: #0A6B4E; }
.exec-lean-tile.dormant .exec-lean-tile-value { color: #B8860B; }
.exec-lean-tile-sub { font-size: .95rem; color: #2B3542; }
.exec-lean-tile-sub b { color: var(--navy); }
.exec-lean-mechanism { background: linear-gradient(135deg, var(--navy) 0%, var(--navy-dark) 100%); color: #fff; border-radius: 16px; padding: 1.8rem 2.2rem; font-size: 1.1rem; font-weight: 600; line-height: 1.5; margin-bottom: 1.6rem; }
.exec-lean-mechanism b { color: var(--teal); }
.exec-lean-footer-link { font-size: .9rem; color: var(--dark-gray); text-align: right; }
/* NEW: Recovery Ladder - single to-scale horizontal timeline for the lean
   Executive Summary tab, added per feedback 2026-08-10: leadership needs
   to see how Group 1/2/3 stack up in sequence, not just the single Group 1
   "Time to Critical Data" number. Time value renders ABOVE the track/pin
   (never on top of it) per direct feedback - the pin sits on the track,
   the sub-label sits below. */
.recovery-ladder { background: #fff; border-radius: 16px; padding: 1.8rem 2rem 1.6rem; box-shadow: 0 4px 18px rgba(9,53,101,.08); margin-bottom: 1.6rem; }
.rl-title { font-size: 1rem; font-weight: 800; color: var(--navy); margin: 0 0 .2rem; }
.rl-sub { font-size: .82rem; color: var(--dark-gray); margin: 0 0 2.6rem; }
.rl-track-wrap { position: relative; height: 112px; margin: 0 4px; }
.rl-track { position: absolute; top: 42px; left: 0; right: 0; height: 10px; border-radius: 6px; overflow: hidden; display: flex; box-shadow: inset 0 1px 2px rgba(0,0,0,.08); }
.rl-seg { height: 100%; }
.rl-seg.mass { background-color: #D7DCE1; background-image: repeating-linear-gradient(45deg, rgba(255,255,255,.6) 0, rgba(255,255,255,.6) 6px, transparent 6px, transparent 12px); }
.rl-flag { position: absolute; top: 0; width: 160px; transform: translateX(-50%); text-align: center; }
.rl-flag .rl-time { position: absolute; top: 0; left: 0; right: 0; font-weight: 800; font-size: 1.05rem; color: var(--navy); }
.rl-flag .rl-pin { position: absolute; top: 36px; left: 50%; transform: translateX(-50%); width: 16px; height: 16px; border-radius: 50%; border: 3px solid #fff; box-shadow: 0 0 0 1.5px rgba(9,53,101,.15); }
.rl-flag .rl-label { position: absolute; top: 62px; left: 0; right: 0; font-size: .76rem; color: var(--dark-gray); line-height: 1.25; }
.rl-mass-label { position: absolute; top: 0; right: 0; width: 190px; text-align: right; }
.rl-mass-label .rl-time { font-weight: 800; font-size: 1.05rem; color: var(--dark-gray); }
.rl-mass-label .rl-label { font-size: .76rem; color: var(--dark-gray); margin-top: .2rem; }
/* NEW v3.5.0: Downtime Cost Avoided by Group table (Report tab) - extends
   the existing Group-1-vs-Full comparison to show cost avoided at every
   milestone, not just Group 1. */
.exec-cost-table-wrap { overflow-x: auto; margin-bottom: 1.6rem; }
.exec-cost-table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
.exec-cost-table th { text-align: left; padding: .55rem .85rem; font-size: .7rem; text-transform: uppercase; letter-spacing: .5px; color: var(--dark-gray); background: #F0F3F6; }
.exec-cost-table td { padding: .55rem .85rem; font-size: .85rem; border-top: 1px solid #EEF1F4; color: #2B3542; }
.exec-cost-table tr.total-row td { font-weight: 700; color: var(--navy); border-top: 2px solid #D7DCE1; }
/* NEW: Sizing tab - Exchange/OneDrive/SharePoint/Discovery Summary tables,
   reusing .exec-cost-table for visual consistency with the rest of the
   report. Tenant-wide totals, independent of criticality tiers/weights -
   rendered once at bootstrap (see recomputeAll), not re-rendered on
   slider/weight changes since none of this data is tier-dependent. */
.sizing-section { margin-bottom: 2rem; }
.sizing-section h3 { font-size: .95rem; font-weight: 800; color: var(--navy); margin: 0 0 .6rem; }
.sizing-discovery-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1.2rem; background: #fff; border-radius: 10px; padding: 1.3rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.06); margin-bottom: .6rem; }
.sizing-discovery-cell .label { font-size: .72rem; text-transform: uppercase; letter-spacing: .5px; color: var(--dark-gray); margin-bottom: .3rem; }
.sizing-discovery-cell .value { font-size: 1.6rem; font-weight: 800; color: var(--navy); }
.sizing-footnote { font-size: .78rem; color: var(--dark-gray); font-style: italic; margin: .6rem 0 1.2rem; }
.controls-panel { background: #fff; border-radius: 10px; padding: 1.1rem 1.3rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
.controls-panel h4 { margin: 0 0 .6rem; font-size: .85rem; color: var(--navy); }
.control-row { display: flex; align-items: center; gap: .6rem; margin-bottom: .5rem; flex-wrap: wrap; }
.control-row label { font-size: .78rem; color: var(--dark-gray); min-width: 150px; }
.control-row input[type=range] { flex: 1; max-width: 220px; }
.control-row input[type=number], .control-row input[type=text], .control-row select { border: 1px solid #D7DCE1; border-radius: 6px; padding: .3rem .5rem; font-size: .8rem; }
.control-row .valdisp { font-size: .78rem; font-weight: 700; color: var(--navy); min-width: 40px; }

/* NEW: scoring-controls redesign - percentage weights (was raw 0-1 decimals)
   with a per-workload 100%-cap, plus the Live Impact Preview panel next to
   it. See buildControlsSliders()/onWeightSlide()/buildLiveImpactPreview(). */
.controls-panel-grid { display: grid; grid-template-columns: minmax(360px, 480px) 1fr; gap: 1.6rem; align-items: start; margin-bottom: 1.5rem; }
@media (max-width: 900px) { .controls-panel-grid { grid-template-columns: 1fr; } }
.panel-title { margin: 0 0 .2rem; font-size: .95rem; color: var(--navy); font-weight: 800; }
.panel-sub { margin: 0 0 1.1rem; font-size: .78rem; color: var(--dark-gray); max-width: 60ch; line-height: 1.4; }
.panel-sub b { color: var(--navy); }
.wd-block { margin-bottom: 1rem; border: 1px solid #EBEEF1; border-radius: 8px; padding: .75rem .85rem .6rem; }
.wd-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: .5rem; }
.wd-head b { font-size: .8rem; color: var(--navy); }
.wd-total { font-size: .7rem; font-weight: 800; padding: .18rem .5rem; border-radius: 20px; letter-spacing: .3px; }
.wd-total.ok { background: #E4F9F0; color: #128A5E; }
.wd-total.warn { background: #FDEEDD; color: #C9781B; }
.remaining-hint { font-size: .68rem; color: var(--dark-gray); margin-top: .2rem; }
.remaining-hint.has-room { color: #128A5E; font-weight: 600; }
.bonus-section { margin-top: 1.2rem; padding-top: .9rem; border-top: 1px dashed #D7DCE1; }
.bonus-label-row { display: flex; align-items: center; gap: .5rem; margin-bottom: .5rem; }
.bonus-tag { font-size: .62rem; font-weight: 800; letter-spacing: .5px; text-transform: uppercase; color: #fff; background: var(--teal); padding: .15rem .45rem; border-radius: 4px; }
.bonus-hint { font-size: .72rem; color: var(--dark-gray); margin: -.2rem 0 .7rem; }

.preview-card { background: #FAFBFC; border: 1px solid #EBEEF1; border-radius: 10px; padding: 1.1rem 1.3rem 1.3rem; }
.preview-head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: .15rem; }
.preview-head h5 { margin: 0; font-size: .85rem; color: var(--navy); font-weight: 800; }
.preview-live-dot { display: inline-flex; align-items: center; gap: .35rem; font-size: .68rem; font-weight: 700; color: #128A5E; text-transform: uppercase; letter-spacing: .4px; }
.preview-live-dot span.dot { width: 6px; height: 6px; border-radius: 50%; background: #21DDAA; display: inline-block; animation: pv-pulse 1.6s infinite; }
@keyframes pv-pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
.preview-sub { font-size: .74rem; color: var(--dark-gray); margin: 0 0 1rem; }
.headline-delta { background: #fff; border-radius: 8px; padding: .7rem .9rem; margin-bottom: 1.1rem; border-left: 4px solid var(--blue); }
.headline-delta .n { font-size: 1.5rem; font-weight: 900; color: var(--navy); }
.headline-delta .t { font-size: .74rem; color: var(--dark-gray); margin-top: .1rem; }

.group-section { margin-bottom: 1.1rem; padding-bottom: .8rem; border-bottom: 1px solid #EEF1F3; }
.group-section:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
.group-head { display: flex; align-items: center; gap: .45rem; margin-bottom: .4rem; }
.group-head .tier-dot { width: 10px; height: 10px; border-radius: 50%; flex: 0 0 auto; }
.group-head .group-name { font-size: .8rem; font-weight: 800; color: var(--navy); flex: 1; }
.group-head .group-total { font-size: .7rem; color: var(--dark-gray); font-weight: 700; }
.group-wd-row { display: flex; align-items: center; gap: .5rem; padding: .22rem 0; }
.group-wd-row .wd-name { font-size: .74rem; color: var(--dark-gray); min-width: 108px; flex: 0 0 auto; }
.group-wd-row .wd-bar-track { flex: 1; height: 6px; background: #EEF1F3; border-radius: 3px; overflow: hidden; }
.group-wd-row .wd-bar-fill { height: 100%; border-radius: 3px; transition: width .3s ease; }
.group-wd-row .wd-count { font-size: .76rem; font-weight: 800; color: var(--navy); min-width: 26px; text-align: right; flex: 0 0 auto; }
.group-wd-row .wd-delta { font-size: .68rem; font-weight: 800; min-width: 44px; text-align: right; flex: 0 0 auto; }
.group-wd-row .wd-delta.up { color: #128A5E; margin-right: .3rem; }
.group-wd-row .wd-delta.down { color: #B23A3A; }
.reset-link { display: block; text-align: right; font-size: .7rem; color: var(--blue); cursor: pointer; margin-top: .5rem; text-decoration: underline; }

/* NEW: deferred recompute - slider drags no longer trigger a live rebuild
   (see onWeightSlide()/markWeightsDirty()); the Recalculate button and the
   greyed "is-stale" treatment on #impact-preview-body/#groups-body-wrap
   communicate that the group tables and impact preview are showing the
   last recalculation, not the current slider positions. */
.recalc-btn { font-size: .72rem; font-weight: 800; padding: .3rem .8rem; border-radius: 20px; border: 1px solid var(--blue); background: #fff; color: var(--blue); cursor: pointer; transition: background .15s ease, color .15s ease, opacity .15s ease; }
.recalc-btn:disabled { border-color: #D7DCE1; color: var(--dark-gray); cursor: default; opacity: .55; }
.recalc-btn.pending { background: var(--blue); color: #fff; animation: recalc-pulse 1.4s infinite; }
@keyframes recalc-pulse { 0%,100% { box-shadow: 0 0 0 0 rgba(14,91,207,.35); } 50% { box-shadow: 0 0 0 6px rgba(14,91,207,0); } }
.stale-note { font-size: .72rem; color: #C9781B; font-weight: 700; margin: -.4rem 0 .8rem; }
.is-stale { opacity: .4; filter: saturate(.5); transition: opacity .2s ease; pointer-events: none; }

.mass-edit-bar { background: #F0F3F6; border-radius: 8px; padding: .7rem 1rem; display: flex; gap: .6rem; align-items: center; flex-wrap: wrap; margin-bottom: .8rem; }
.mass-edit-bar select, .mass-edit-bar input, .mass-edit-bar button { border: 1px solid #D7DCE1; border-radius: 6px; padding: .35rem .6rem; font-size: .78rem; }
.mass-edit-bar button, .btn { background: var(--navy); color: #fff; border: none; border-radius: 6px; padding: .4rem .9rem; font-size: .78rem; font-weight: 700; cursor: pointer; }
.mass-edit-bar button:hover, .btn:hover { background: var(--blue); }
section.workload { margin-bottom: 3rem; scroll-margin-top: 90px; }
section.workload h3 { font-size: 1.15rem; font-weight: 800; color: var(--navy); margin: 0; }
.filter-chips { display: flex; gap: .5rem; flex-wrap: wrap; margin: .9rem 0 1rem; }
/* NEW: per-workload free-text search + expanded attribute filters. Search
   is deliberately styled bigger/more prominent than the attribute-filter
   dropdowns below it - it's the "find one specific object" control, not
   just another facet. */
.search-box-row { margin: .5rem 0 0; }
.search-box { width: 100%; max-width: 480px; border: 1px solid #C7CDD5; border-radius: 8px; padding: .55rem .8rem; font-size: .85rem; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
.search-box:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 3px rgba(14,91,207,.15); }
.totals-heading { font-size: .78rem; font-weight: 700; color: var(--navy); text-transform: uppercase; letter-spacing: .5px; margin: 1.1rem 0 .4rem; }
.chip { border: 1px solid #D7DCE1; background: #fff; border-radius: 999px; padding: .32rem .85rem; font-size: .78rem; font-weight: 600; cursor: pointer; color: var(--dark-gray); }
.chip.active { background: var(--navy); color: #fff; border-color: var(--navy); }
/* NEW: presenter pass - horizontal-scroll discoverability. .table-wrap is the
   one shared scroll container used by every data table in the report (built
   once here rather than per-workload), so a thicker always-visible
   scrollbar, a sticky identity column, and a capped height with a sticky
   header (dashboard-card feel instead of the whole page scrolling) all apply
   everywhere for free. */
.table-wrap { position: relative; overflow: auto; max-height: 62vh; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.06); scrollbar-width: auto; scrollbar-color: var(--blue) #E2E6EA; }
.table-wrap::-webkit-scrollbar { width: 14px; height: 14px; }
.table-wrap::-webkit-scrollbar-track { background: #E2E6EA; border-radius: 0 0 10px 10px; }
.table-wrap::-webkit-scrollbar-thumb { background-color: var(--blue); border-radius: 8px; border: 3px solid #E2E6EA; }
.table-wrap::-webkit-scrollbar-thumb:hover { background-color: var(--navy); }
table { width: 100%; border-collapse: collapse; background: #fff; }
thead th { position: sticky; top: 0; z-index: 3; background: #F0F3F6; text-align: left; padding: .6rem .85rem; font-size: .7rem; text-transform: uppercase; letter-spacing: .5px; color: var(--dark-gray); cursor: pointer; user-select: none; white-space: nowrap; }
thead th:hover { color: var(--navy); }
tbody td { padding: .55rem .85rem; font-size: .82rem; border-top: 1px solid #EEF1F4; color: #2B3542; white-space: nowrap; }
tbody tr:hover { background: #FAFBFC; }
/* Sticky leftmost identity column (Object/name) - never lose track of which
   row you're on while scrolled right to see Department/Title/Manager. */
table thead th:first-child, table tbody td:first-child { position: sticky; left: 0; z-index: 2; background: #fff; box-shadow: 3px 0 6px -3px rgba(0,0,0,.18); }
table thead th:first-child { z-index: 4; background: #F0F3F6; }
tbody tr:hover td:first-child { background: #FAFBFC; }
/* Column-visibility toggle: hide the noisy enrichment columns (Job Title,
   Department, Manager, Mailbox Type, Why/criteria tags) for a clean
   no-scroll-needed "essentials" view while presenting. */
.table-wrap.essentials-only .col-detail { display: none; }
.table-toolbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: .5rem; margin-bottom: .5rem; }
.col-toggle { font-size: .78rem; color: var(--dark-gray); display: flex; align-items: center; gap: .4rem; cursor: pointer; user-select: none; }
.col-toggle input { transform: scale(1.05); }
.col-toggle-hint { color: var(--dark-gray); font-weight: 400; }
.table-scroll-shell { position: relative; }
.scroll-fade-right { position: absolute; top: 0; right: 0; bottom: 0; width: 34px; border-radius: 0 10px 10px 0; background: linear-gradient(to right, rgba(244,246,248,0), rgba(244,246,248,.95) 65%); pointer-events: none; opacity: 0; transition: opacity .2s ease; z-index: 5; }
.table-scroll-shell.has-more-right .scroll-fade-right { opacity: 1; }
.scroll-hint { font-size: .74rem; font-weight: 700; color: var(--blue); white-space: nowrap; opacity: 1; transition: opacity .25s ease; }
.scroll-hint.scrolled { opacity: 0; visibility: hidden; }
/* NEW v3.10.3: MAX_TABLE_ROWS cap notice, shown under a workload table (or
   the Group 1 overview) once there are more matching rows than are rendered. */
.table-cap-notice { font-size: .78rem; color: var(--dark-gray); padding: .5rem 0 0; }
.table-cap-notice button { border: 1px solid #D7DCE1; border-radius: 6px; background: #fff; padding: .15rem .5rem; font-size: .76rem; cursor: pointer; color: var(--blue); }
.table-cap-notice button:hover { background: #F4F6F8; }
.badge { display: inline-block; padding: .18rem .6rem; border-radius: 999px; font-size: .7rem; font-weight: 700; white-space: nowrap; }
.badge.override { background: #093565; color: #fff; margin-left: .35rem; }
.tier-select { border: 1px solid #D7DCE1; border-radius: 6px; padding: .2rem .4rem; font-size: .76rem; }
.criteria-tags { font-size: .74rem; color: var(--dark-gray); white-space: normal; max-width: 240px; }
.score-bar-wrap { display: flex; align-items: center; gap: .5rem; }
.score-bar { width: 60px; height: 6px; background: #E7EBEE; border-radius: 4px; overflow: hidden; }
.score-bar span { display: block; height: 100%; background: var(--blue); }
.row-check { transform: scale(1.1); }
.glossary dt { font-weight: 700; color: var(--navy); margin-top: .8rem; }
.glossary dd { margin: .2rem 0 0; color: #2B3542; font-size: .88rem; }
.weights-table td, .weights-table th { padding: .4rem .7rem; font-size: .8rem; }
footer { padding: 1.75rem 3rem 3rem; font-size: .78rem; color: var(--dark-gray); border-top: 1px solid #E2E6EA; }
footer p { max-width: 900px; }
/* NEW v3.6.2: export-bar replaced by the icon-only .tabbar-actions toolbar
   docked to the right of the tabbar itself, per feedback 2026-07-23 - see
   below. Rule kept as a harmless no-op selector in case anything still
   references the class name. */
.export-bar { display: flex; gap: .6rem; margin-bottom: 1rem; }
.tabbar-actions { margin-left: auto; display: flex; align-items: center; gap: .4rem; padding: .4rem 0; flex: 0 0 auto; }
.icon-btn { background: var(--navy); color: #fff; border: none; border-radius: 7px; width: 34px; height: 34px; padding: 0; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; flex: 0 0 auto; }
.icon-btn:hover { background: var(--navy-dark); }
.icon-btn svg { width: 17px; height: 17px; }
.pill-note { font-size: .78rem; color: var(--dark-gray); background: #F0F3F6; border-radius: 8px; padding: .5rem .8rem; margin-bottom: 1rem; max-width: 900px; }

/* Recovery tab - RTO controls, per-group ABR vs Mass Recovery sections,
   exceeds-target shortfall callout, auto-suggest banner. */
.rt-preset-row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; margin-bottom: .8rem; }
.rt-preset-btn { border: 1px solid #D7DCE1; background: #fff; border-radius: 999px; padding: .32rem .95rem; font-size: .78rem; font-weight: 700; cursor: pointer; color: var(--dark-gray); }
.rt-preset-btn.active { background: var(--navy); color: #fff; border-color: var(--navy); }
.rt-auto-banner { display: flex; justify-content: space-between; align-items: center; gap: 1rem; background: #FFF7E6; border: 1px solid #FFE1A6; border-radius: 8px; padding: .7rem 1rem; margin-bottom: 1rem; font-size: .82rem; color: #7A5B00; }
.rt-auto-banner button { background: none; border: 1px solid #7A5B00; color: #7A5B00; border-radius: 6px; padding: .25rem .7rem; font-size: .74rem; font-weight: 700; cursor: pointer; white-space: nowrap; }
.rt-group-section { background: #fff; border-radius: 12px; padding: 1.4rem 1.6rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.rt-group-section.total { border: 2px solid #D7DCE1; }
.rt-group-section.exceeds-target { border-left: 4px solid var(--red-target); }
.rt-group-section h3 { margin: 0 0 .2rem; font-size: 1.15rem; color: var(--navy); font-weight: 800; }
.rt-group-section .rt-subtitle { font-size: .8rem; color: var(--dark-gray); margin-bottom: 1.1rem; }
.rt-compare-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: .9rem; }
.rt-compare-card { border-radius: 10px; padding: 1rem 1.2rem; }
.rt-compare-card.abr { background: #EAF2FF; border: 1px solid #C7DCFF; }
.rt-compare-card.mass { background: #FDEAEA; border: 1px solid #F5C6C6; }
.rt-compare-card .rt-label { font-size: .72rem; text-transform: uppercase; letter-spacing: .5px; color: var(--dark-gray); font-weight: 700; }
.rt-compare-card .rt-time { font-size: 1.7rem; font-weight: 800; color: var(--navy); margin: .25rem 0; }
.rt-compare-card .rt-cost { font-size: .95rem; font-weight: 700; color: #2B3542; }
.rt-savings-bar { display: flex; justify-content: space-between; align-items: center; background: #EDFBF6; border: 1px solid #BEEFDD; border-radius: 8px; padding: .6rem 1rem; font-size: .85rem; color: #0A6B4E; font-weight: 600; }
.rt-shortfall-bar { display: flex; justify-content: space-between; align-items: center; background: #FDEDEE; border: 1px solid #F6C6C9; border-radius: 8px; padding: .6rem 1rem; font-size: .85rem; color: #A5222B; font-weight: 600; }
.rt-toggle { margin-top: .7rem; font-size: .78rem; color: var(--blue); cursor: pointer; user-select: none; }
.rt-detail { display: none; margin-top: .8rem; border-top: 1px solid #EEF1F4; padding-top: .8rem; font-size: .8rem; }
.rt-detail.open { display: block; }
.rt-total-note { font-size: .78rem; color: var(--dark-gray); background: #F0F3F6; border-radius: 8px; padding: .6rem .9rem; margin-top: .9rem; }
.badge.exceeds-target { background: var(--red-target); color: #fff; }
/* Empty-tier callout - a group with 0 objects can happen on a very small
   tenant, or (v3.8.0) when Mailboxes/OneDrive/SharePoint's budget-walk
   tiering already placed the entire active population into an earlier
   group's generous budget, leaving nothing for this one. Neutral gray, not
   alarming - this isn't a shortfall, just a "nothing landed here" fact. */
.badge.empty-tier { background: var(--mid-gray); color: #fff; }
.rt-empty-note, .exec-hero-card .exec-empty-note { font-size: .78rem; color: var(--dark-gray); background: #F0F3F6; border-radius: 8px; padding: .5rem .8rem; margin: .5rem 0 .8rem; }
/* NEW v3.6.0: PDF export (One Page Summary / Full Report), per feedback
   2026-07-23. Mechanism is the browser's native print-to-PDF ("Save as
   PDF" in the print dialog) via a dedicated #print-root container built
   fresh on demand by exportPdf() - no new external dependency, renders
   with the report's own fonts/colors, and gets reliable page breaks for
   free from the browser's print engine. #print-root is always display:none
   on screen; the @media print block below is the ONLY thing that ever
   shows it (gated on a body.printing-summary/printing-full class set right
   before window.print()), so this can never affect the live, on-screen
   report regardless of timing around when that class gets removed
   afterward. */
#print-root { display: none; font-family: 'Inter', -apple-system, Arial, sans-serif; color: var(--navy); }
@media print {
  /* html's normal font-size is a viewport-relative clamp() for the live
     on-screen report - meaningless for a printed page, so pin it to a
     fixed size here for predictable, consistent PDF output. */
  html { font-size: 10pt; }
  @page { size: letter; margin: 0.55in; }
  body.printing-summary > *:not(#print-root),
  body.printing-full > *:not(#print-root) { display: none !important; }
  body.printing-summary #print-root,
  body.printing-full #print-root { display: block !important; }
}
.pr-page-break { page-break-before: always; }
.pr-avoid-break { page-break-inside: avoid; }
.pr-header { border-bottom: 3px solid var(--navy); padding-bottom: .4rem; margin-bottom: .8rem; }
.pr-eyebrow { font-size: .68rem; font-weight: 800; letter-spacing: 1px; color: var(--dark-gray); text-transform: uppercase; }
.pr-title { font-size: 1.2rem; font-weight: 900; color: var(--navy); margin: .15rem 0; }
.pr-meta { font-size: .72rem; color: var(--dark-gray); }
.pr-meta span { margin-right: 1.1rem; }
.pr-meta b { color: var(--navy); }
.pr-section-title { font-size: .92rem; font-weight: 800; color: var(--navy); margin: .9rem 0 .4rem; border-left: 4px solid var(--teal); padding-left: .5rem; }
.pr-section-title:first-of-type { margin-top: 0; }
.pr-subnote { font-size: .7rem; color: var(--dark-gray); margin: -.25rem 0 .5rem; max-width: 90ch; }
.pr-tiles { display: grid; grid-template-columns: repeat(3, 1fr); gap: .6rem; margin-bottom: .7rem; }
.pr-tile { border: 1px solid #DCE3EA; border-radius: 8px; padding: .5rem .7rem; }
.pr-tile-label { font-size: .64rem; font-weight: 800; text-transform: uppercase; color: var(--dark-gray); letter-spacing: .4px; }
.pr-tile-value { font-size: 1.25rem; font-weight: 900; color: var(--navy); margin: .1rem 0; }
.pr-tile-sub { font-size: .68rem; color: #2B3542; }
.pr-mechanism { font-size: .78rem; background: #F0F3F6; border-radius: 8px; padding: .5rem .8rem; margin-bottom: .8rem; }
.pr-table { width: 100%; border-collapse: collapse; font-size: .72rem; margin-bottom: .8rem; }
.pr-table th, .pr-table td { border: 1px solid #DCE3EA; padding: .3rem .45rem; text-align: left; }
.pr-table th { background: #F0F3F6; font-weight: 800; color: var(--navy); }
.pr-table td.num, .pr-table th.num { text-align: right; }
.pr-table tr.total-row td { font-weight: 800; background: #F7F9FB; }
.pr-note { font-size: .68rem; color: var(--dark-gray); margin-bottom: .7rem; }
.pr-footer { font-size: .64rem; color: var(--dark-gray); margin-top: .8rem; border-top: 1px solid #DCE3EA; padding-top: .35rem; }
.pr-glossary dt { font-weight: 800; color: var(--navy); font-size: .78rem; margin-top: .5rem; }
.pr-glossary dd { font-size: .72rem; color: #2B3542; margin: .1rem 0 0; }
.pr-badge { display: inline-block; font-size: .62rem; font-weight: 800; padding: .1rem .4rem; border-radius: 4px; color: #fff; margin-left: .4rem; }
.pr-badge.exceeds { background: var(--red-target); }
.pr-badge.empty { background: var(--mid-gray); }
'@

#endregion

#region ---------- HTML report JS: engine (data, scoring, tiering, overrides) ----------

$script:ReportJsEngine = @'
var DATA = JSON.parse(document.getElementById("report-data").textContent);
// v3.1.0: 4-tier order. All five workloads are tiered the same way
// (criticality-ranked, see computeScoresAndTiers) - there is no more
// separate "Beyond Target" bucket. Group 1/2/3's RTO compliance is now a
// per-group flag on the recovery model instead (see computeRecoveryModel).
// NEW v3.7.0: renamed the 4th tier from "Dormant - No Recent Activity" to
// plain "Group 4", per feedback 2026-07-30 - folds zero-activity data into
// the same Group 1/2/3 naming convention instead of calling it out as its
// own "dormant" category, and swaps its badge from amber (which read as an
// alert) to a neutral gray (--mid-gray) so it doesn't draw the eye.
// NEW v3.10.3: large-tenant render cap. Every workload table (and the Group 1
// cross-workload overview) used to render one <tr> per object with no limit -
// fine at demo scale, but a real tenant with tens of thousands of objects per
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
var TIER_META = {
  "Critical Group 1": {bg:"#0E5BCF", fg:"#FFFFFF", short:"Group 1"},
  "Critical Group 2": {bg:"#2FCAFF", fg:"#093565", short:"Group 2"},
  "Critical Group 3": {bg:"#4DD2D2", fg:"#093565", short:"Group 3"},
  "Group 4": {bg:"#A4A9A8", fg:"#FFFFFF", short:"Group 4"}
};
var FRIENDLY = { SendRecvActivity:"Send/receive volume", ReadActivity:"Read volume", Size:"Mailbox size",
  FileActivity:"File activity", Storage:"Storage size", PageViews:"Page views", ActiveFiles:"Active files",
  ActiveUsers:"Active users", ChannelMsgs:"Channel messages", Meetings:"Meetings organized",
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
  {key:"mailboxes", label:"Mailboxes", idLabel:"UPN", itemField:"ItemCount", itemLabel:"Items", storageField:"StorageUsedMB", storageLabel:"Storage (MB)", spExOd:"EX"},
  {key:"onedrive", label:"OneDrive Accounts", idLabel:"Site URL / Owner UPN", itemField:"FileCount", itemLabel:"Files", storageField:"StorageUsedGB", storageLabel:"Storage (GB)", spExOd:"OD"},
  {key:"sharepoint", label:"SharePoint Sites", idLabel:"Site URL / Owner UPN", itemField:"FileCount", itemLabel:"Files", storageField:"StorageUsedGB", storageLabel:"Storage (GB)", spExOd:"SP"},
  {key:"teams", label:"Teams", idLabel:"Team Id", itemField:"ActiveUsersCount", itemLabel:"Active Users", storageField:null, storageLabel:"", spExOd:null}
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
// name without the suffix. See RECOVERY-MODEL-METHODOLOGY.md.
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
// inline. See RECOVERY-MODEL-METHODOLOGY.md.
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
  // in Group 1/2/3" invariant. See RECOVERY-MODEL-METHODOLOGY.md.
  var tierNames = ["Critical Group 1", "Critical Group 2", "Critical Group 3"];
  var n = active.length;
  var cursor = 0;
  var priorTiersTime = 0;
  for (var t = 0; t < 3; t++) {
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
      if (t < 2 && budget > 0 && candTime > budget && cumObjs > 0) {
        break; // this tier is full relative to its budget - move to the next tier
      }
      row.ComputedTier = tierNames[t];
      cumObjs = candObjs; cumItems = candItems; cumStorage = candStorage;
      cursor++;
      if (t < 2 && budget > 0 && candTime > budget) {
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
    group1Hours: DATA.meta.group1TargetHours, group2Hours: DATA.meta.group2TargetHours, group3Hours: DATA.meta.group3TargetHours,
    rtoPreset: DATA.meta.rtoPresetResolved || "Standard", rtoPresetReason: DATA.meta.rtoPresetReason || "",
    autoBannerDismissed: false
  },
  activeFilters: {}
};

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
    var targetsMin = [state.recovery.group1Hours * 60, state.recovery.group2Hours * 60, state.recovery.group3Hours * 60];
    assignBudgetTiers(active, recoveryFieldInfo.itemField, recoveryFieldInfo.storageField, RECENT_FIELD[workloadKey], avgItemSize, spodTier, recoveryFieldInfo.type, targetsMin, getWindowFactor());
  } else {
    var n = active.length;
    var t1 = Math.ceil(n * state.tierSplit[0]);
    var t2 = Math.ceil(n * (state.tierSplit[0] + state.tierSplit[1]));
    active.forEach(function (row, i) {
      row.ComputedTier = i < t1 ? "Critical Group 1" : (i < t2 ? "Critical Group 2" : "Critical Group 3");
    });
  }
  inactive.forEach(function (row) {
    row.ComputedTier = "Group 4";
  });

  rows.forEach(function (row) {
    var key = workloadKey + "|" + row.Identifier;
    if (state.overrides[key]) {
      row.Tier = state.overrides[key].tier;
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
// NEW v3.10.0 (M365 MVC Recovery Time Estimator - RSC M365 Restoration
// Benchmark, Mar 2025 / M365 Sizing Guidance, Jan 2026): read back out of
// meta (PowerShell is the single source of truth) rather than hardcoded
// here a second time, so the two can never drift. See
// RECOVERY-MODEL-METHODOLOGY.md and Get-RecoveryTimeMinutes.
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

// v3.10.0: reworked to match the M365 MVC Recovery Time Estimator, replacing
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
// neither - pass false for those calls. See RECOVERY-MODEL-METHODOLOGY.md.
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
  var subset = rows.filter(function (r) { return r.Tier === tierName; });
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

function computeRecoveryModel() {
  var sp = DATA.workloads.sharepoint || [];
  var od = DATA.workloads.onedrive || [];
  var ex = DATA.workloads.mailboxes || [];

  var spTotalItems = sumField(sp, "FileCount"), spTotalBytes = sumField(sp, "StorageBytes");
  var odTotalItems = sumField(od, "FileCount"), odTotalBytes = sumField(od, "StorageBytes");
  var exTotalItems = sumField(ex, "ItemCount"), exTotalMB = sumField(ex, "StorageUsedMB");

  var spAvg = spTotalItems > 0 ? spTotalBytes / spTotalItems : 0;
  var odAvg = odTotalItems > 0 ? odTotalBytes / odTotalItems : 0;
  var exAvg = exTotalItems > 0 ? exTotalMB / exTotalItems : 0;

  var scale = Math.max(sp.length, od.length);
  var spodTier = resolveLicenseTier(state.recovery.licenseTier, scale);

  // v3.1.0: ABR time (cumSP/cumOD/cumEX) is now the RECENT/hot-scope
  // cumulative recovery time - what ABR actually restores first - instead
  // of each tier's full data. Mass Recovery (cumSPObjs/... below) is
  // UNCHANGED: full-data cumulative-batch figure, since Mass Recovery has no
  // hot/cold distinction. See RECOVERY-MODEL-METHODOLOGY.md.
  // NEW: ABR's recent-data fields (RECENT_FIELD) are always real D7 counts,
  // regardless of -Period. The live "Recovery window (days)" control (0-7)
  // linearly scales that D7 baseline down for a shorter window - e.g. a
  // 1-day window assumes 1/7 of the D7 activity happened in-scope. This is a
  // proportional estimate (Graph has no finer-than-day telemetry, and no
  // per-item change log at all), not a literal day-level figure - disclosed
  // in the Recovery tab copy. See RECOVERY-MODEL-METHODOLOGY.md.
  var windowFactor = Math.max(0, Math.min(7, state.recovery.windowDays || 0)) / 7;

  var cumSP = 0, cumOD = 0, cumEX = 0;
  var cumSPObjs = 0, cumSPItems = 0, cumSPStorage = 0;
  var cumODObjs = 0, cumODItems = 0, cumODStorage = 0;
  var cumEXObjs = 0, cumEXItems = 0, cumEXStorage = 0;
  var milestones = {};
  TIER_ORDER.forEach(function (tierName) {
    var spSlice = sliceTotals(sp, "FileCount", "StorageBytes", RECENT_FIELD.sharepoint, tierName);
    var odSlice = sliceTotals(od, "FileCount", "StorageBytes", RECENT_FIELD.onedrive, tierName);
    var exSlice = sliceTotals(ex, "ItemCount", "StorageUsedMB", RECENT_FIELD.mailboxes, tierName);

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

    milestones[tierName] = {
      sp: { objectCount: spSlice.objectCount, itemCount: spSlice.itemCount, storage: spSlice.storage, timeMin: spTime, cumMin: cumSP, massTimeMin: massSPTime },
      od: { objectCount: odSlice.objectCount, itemCount: odSlice.itemCount, storage: odSlice.storage, timeMin: odTime, cumMin: cumOD, massTimeMin: massODTime },
      ex: { objectCount: exSlice.objectCount, itemCount: exSlice.itemCount, storage: exSlice.storage, timeMin: exTime, cumMin: cumEX, massTimeMin: massEXTime },
      wallClockCumMin: Math.max(cumSP, cumOD, cumEX),
      massRecoveryCumMin: massCumMin,
      exceedsTarget: false,
      targetGapMin: 0
    };
  });

  // NEW v3.1.0: per-group RTO compliance flag, replacing the old "Beyond
  // Target" tier - each of Group 1/2/3's own ABR (hot-scope) cumulative time
  // is checked against its target; if it runs over, flag it in place rather
  // than exiling the responsible object(s) to a 5th tier.
  var targetsMin = [state.recovery.group1Hours * 60, state.recovery.group2Hours * 60, state.recovery.group3Hours * 60];
  ["Critical Group 1", "Critical Group 2", "Critical Group 3"].forEach(function (tierName, idx) {
    var m = milestones[tierName];
    var target = targetsMin[idx];
    if (target > 0 && m.wallClockCumMin > target) {
      m.exceedsTarget = true;
      m.targetGapMin = m.wallClockCumMin - target;
    }
  });

  var fullSP = recoveryTimeMinutes("SP", sp.length, spTotalItems, spTotalBytes, spAvg, spodTier, false);
  var fullOD = recoveryTimeMinutes("OD", od.length, odTotalItems, odTotalBytes, odAvg, spodTier, false);
  var fullEX = recoveryTimeMinutes("EX", ex.length, exTotalItems, exTotalMB, exAvg, spodTier, false);
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

#region ---------- HTML report JS: rendering (exec summary, tables) ----------

$script:ReportJsRenderA = @'
function renderExecFinancialAndRecoveryTop() {
  // NEW: the whole point of this assessment is breaking critical objects
  // into groups to shrink recovery time - so financial impact and recovery
  // times now lead the Executive Summary, ahead of the per-workload group
  // breakdown. Reuses computeRecoveryModel() (same source of truth as the
  // Recovery tab) so these numbers can never drift from what that tab shows.
  var model = computeRecoveryModel();
  var g1 = model.milestones["Critical Group 1"];
  var g2 = model.milestones["Critical Group 2"];
  var g3 = model.milestones["Critical Group 3"];
  var exceedingGroups = ["Critical Group 1", "Critical Group 2", "Critical Group 3"]
    .map(function (t, i) { return { label: "Group " + (i + 1), m: model.milestones[t] }; })
    .filter(function (g) { return g.m.exceedsTarget; });

  // NOTE: this compares Group 1's ABR time against the FULL-TENANT
  // undifferentiated restore time (model.fullRestoreMin), NOT against Group
  // 1's own cumulative-batch Mass Recovery figure (g1.massRecoveryCumMin).
  // Those two are mathematically identical for Group 1 specifically - it's
  // the first tier, so "mass-recover just Group 1's objects as one batch"
  // and "ABR-recover Group 1" are the same computation, meaning Group 1 can
  // never show savings against its own scope (nothing came before it to
  // sequence against). The comparison that actually captures ABR's value is
  // "how much sooner is my most critical data back, vs. an undifferentiated
  // restore of literally everything, where there's no guarantee anything
  // comes back before the whole job finishes." See chat 2026-07-15 ("why is
  // cost avoided 0") and RECOVERY-MODEL-METHODOLOGY.md.
  var abrTotalCostMoney = fmtHours(g1.wallClockCumMin) * state.recovery.costPerHour;
  var g1SavingsHrs = Math.max(0, (model.fullRestoreMin - g1.wallClockCumMin) / 60);
  var g1SavingsMoney = g1SavingsHrs * state.recovery.costPerHour;
  var fullExposureMoney = fmtHours(model.fullRestoreMin) * state.recovery.costPerHour;
  var pctReduction = fullExposureMoney > 0 ? Math.round((g1SavingsMoney / fullExposureMoney) * 100) : 0;
  // NEW v3.1.0: replaces the old "Beyond Target" object-count callout. Every
  // active object is now IN one of Group 1/2/3 (criticality-ranked, always
  // populated) - what can still happen is a group's OWN ABR time running
  // over ITS OWN target, which this flags per group instead of exiling
  // objects to a 5th bucket.
  var targetGapNote = exceedingGroups.length > 0
    ? ("<span style=\"color:var(--red-target);font-weight:700;\">" + exceedingGroups.map(function (g) { return g.label; }).join(", ") + " exceed" + (exceedingGroups.length === 1 ? "s" : "") + " its stated RTO target</span> - " +
        exceedingGroups.map(function (g) { return g.label + " by " + fmtMin(g.m.targetGapMin); }).join("; ") + ".")
    : "All three groups' ABR recovery times are within their stated RTO targets.";

  // NEW v3.4.0: time-first framing, per feedback 2026-07-17 - the old
  // punchline paired "$X saved" with "without changing total recovery
  // time" in one sentence, which read as muddy to an exec (it invites "so I
  // still wait 19 days?"). The real value is time-to-critical-data, not
  // total recovery time, so that leads now ("your most critical data is
  // usable in X instead of Y") and the dollar savings support it as
  // corroborating evidence underneath, not the headline itself. The
  // headline renders even when $/hour isn't set, since the time comparison
  // stands on its own without a cost model.
  var financialHtml = '<div class="exec-hero-label">Time to Critical Data</div>';
  if (model.fullRestoreMin > 0) {
    financialHtml += '<div class="exec-fin-headline">Your most critical data is usable in <b>' + fmtMin(g1.wallClockCumMin) + '</b> instead of <b>' + fmtMin(model.fullRestoreMin) + '</b>.</div>';
  }
  // Before/after comparison per feedback 2026-07-15 - still valuable as
  // supporting evidence for the time-first headline above: same "before"
  // (Mass Recovery, no prioritization) vs "after" (ABR, Group 1 online)
  // split, in dollar terms, then closes with one line that leads with the
  // dollar amount as a SUPPORTING fact ("that's a $X, Y% reduction...")
  // rather than as the sentence's main verb, and replaces "without changing
  // total recovery time" with the concrete mechanism (Mass Recovery
  // continues in the background) so it reads as an explanation, not a
  // caveat inviting "so I still wait?"
  if (state.recovery.costPerHour > 0) {
    financialHtml +=
      '<div class="exec-fin-compare">' +
        '<div class="exec-fin-compare-card before"><div class="exec-fin-compare-label">Mass Recovery (no prioritization)</div><div class="exec-fin-compare-time">' + fmtMin(model.fullRestoreMin) + '</div><div class="exec-fin-compare-cost">' + fmtMoney(fullExposureMoney) + " in downtime cost</div></div>" +
        '<div class="exec-fin-compare-arrow">&rarr;</div>' +
        '<div class="exec-fin-compare-card after"><div class="exec-fin-compare-label">ABR (Group 1 online)</div><div class="exec-fin-compare-time">' + fmtMin(g1.wallClockCumMin) + '</div><div class="exec-fin-compare-cost">' + fmtMoney(abrTotalCostMoney) + " in downtime cost</div></div>" +
      "</div>" +
      '<div class="exec-fin-punchline">That&rsquo;s a <b>' + fmtMoney(g1SavingsMoney) + "</b> reduction (" + pctReduction + "%) in downtime cost for the data that matters most - Mass Recovery keeps running in the background for everything else.</div>";

    // Recovery Timeline: v3.3.0 "before/after tracks" - two genuinely
    // to-scale rows on the same real timescale (model.fullRestoreMin), per
    // a reference design the user provided. "Without ABR" is a full-width
    // hatched bar (it literally represents the whole timescale). "With ABR"
    // is the SAME timescale, so Group 1/2/3 collapse into a small chip
    // cluster near the left, followed by a de-emphasized "rest of tenant
    // continues in background" fill - the empty space IS the value being
    // communicated. g1/g2/g3.wallClockCumMin are genuinely hot-scope
    // (v3.1.0) - see RECOVERY-MODEL-METHODOLOGY.md.
    if (model.fullRestoreMin > 0) {
      var g1Seg = g1.wallClockCumMin;
      var g2Seg = Math.max(0, g2.wallClockCumMin - g1.wallClockCumMin);
      var g3Seg = Math.max(0, g3.wallClockCumMin - g2.wallClockCumMin);
      var segCost = function (v) { return fmtHours(v) * state.recovery.costPerHour; };
      var tlSegs = [
        { label: "Group 1", dur: g1Seg, color: "#0E5BCF" },
        { label: "Group 2", dur: g2Seg, color: "#2FCAFF" },
        { label: "Group 3", dur: g3Seg, color: "#4DD2D2" }
      ];

      // Real proportion the critical-group cluster would occupy at true
      // scale - typically tiny (hours out of ~19 days here). Floored at 6%
      // of the bar's width so it stays visible as "a little bit," rather
      // than rendering as literally nothing - the mockup's cluster is
      // clearly a deliberate, legible sliver, not a sub-pixel line.
      var realClusterPct = (g3.wallClockCumMin / model.fullRestoreMin) * 100;
      var clusterPct = Math.min(94, Math.max(realClusterPct, 6));

      var chipsHtml = tlSegs.map(function (s) {
        var isEmpty = s.dur <= 0;
        var bgStyle = isEmpty
          ? "background:repeating-linear-gradient(45deg, var(--mid-gray) 0, var(--mid-gray) 2px, #fff 2px, #fff 4px);"
          : ("background:" + s.color + ";");
        // flex-grow proportional to this group's own real share of the
        // cluster - min-width (see CSS) keeps a "0 min" group visible as a
        // hairline instead of disappearing entirely.
        var flexStyle = "flex:" + Math.max(s.dur, 0.01) + " 1 0;";
        var titleText = s.label + " (ABR): " + fmtMin(s.dur) + ", " + fmtMoney(segCost(s.dur));
        return '<div class="fin-tl-chip" style="' + bgStyle + flexStyle + '" title="' + titleText.replace(/"/g, "&quot;") + '"></div>';
      }).join("");

      // NEW v3.4.1: withAbrBarHtml is now a full track-row (bar + end label),
      // matching withoutAbrBarHtml's shape, per feedback 2026-07-17 - both
      // rows now fade out toward the SAME end label (model.fullRestoreMin),
      // reinforcing that Mass Recovery is still running in the background
      // for the same real duration either way; ABR just gets critical data
      // back long before that background job matters.
      var withAbrBarHtml = '<div class="fin-tl-track-row">' +
        '<div class="fin-tl-track-bar with-abr">' +
          '<div class="fin-tl-chip-cluster" style="flex:0 0 ' + clusterPct.toFixed(2) + '%;">' + chipsHtml + "</div>" +
          '<div class="fin-tl-bg-fill" title="Mass Recovery still restoring in the background, in random order: ' + fmtMin(model.fullRestoreMin).replace(/"/g, "&quot;") + ", " + fmtMoney(fullExposureMoney) + '">rest of tenant restoring in random order</div>' +
        "</div>" +
        '<div class="fin-tl-track-endlabel">' + fmtMin(model.fullRestoreMin) + ' <span class="arrow">&#8599;</span></div>' +
      "</div>";

      // NEW v3.4.1: corrected the "Without ABR" label text per feedback
      // 2026-07-17 - Mass Recovery does NOT hold all data unusable until the
      // very end; each file/email/record becomes usable as its own restore
      // completes. The real problem is RANDOM order: like a puzzle
      // reassembled with pieces returned in no particular sequence, the
      // specific file, email, or record a user actually needs may not come
      // back until the whole job finishes - that's the accurate framing,
      // not "nothing is usable until the end."
      var withoutAbrBarHtml = '<div class="fin-tl-track-row">' +
        '<div class="fin-tl-track-bar hatched"><span class="fin-tl-track-bar-text">Restored in random order &ndash; the exact data a user needs may not come back until this finishes</span></div>' +
        '<div class="fin-tl-track-endlabel">' + fmtMin(model.fullRestoreMin) + ' <span class="arrow">&#8599;</span></div>' +
      "</div>";

      var legendHtml = '<div class="fin-tl-legend">' + tlSegs.map(function (s) {
        var swatchStyle = s.dur <= 0
          ? "background:repeating-linear-gradient(45deg, var(--mid-gray) 0, var(--mid-gray) 3px, #fff 3px, #fff 6px);"
          : ("background:" + s.color + ";");
        return '<div class="fin-tl-legend-item"><span class="fin-tl-swatch" style="' + swatchStyle + '"></span><span>' + s.label + "</span></div>";
      }).join("") + '<div class="fin-tl-legend-item"><span class="fin-tl-swatch" style="background:var(--mid-gray);"></span><span>Mass recovery</span></div>' + "</div>";

      // NEW v3.4.2: description tightened and extended the puzzle analogy
      // per feedback 2026-07-17 - "corners and edges first" (how people
      // actually assemble a puzzle) now explicitly maps to ABR restoring
      // recently accessed/modified/created data first, i.e. the pieces that
      // "actually give you something to work with," vs. Mass Recovery
      // gluing down whatever piece it grabs, in no order. Carefully worded
      // as "nothing forms a COMPLETE, usable picture until the whole box is
      // done" rather than "nothing is usable until the end" - individual
      // pieces (files/emails/records) genuinely are usable as each one
      // lands, per the v3.4.1 correction above; it's the complete picture
      // that is missing until the whole random-order job finishes.
      financialHtml += '<div class="fin-timeline">' +
        '<div class="fin-tl-title">Mass Recovery vs. ABR: Same Timescale, Different Order</div>' +
        '<div class="fin-tl-desc">Mass Recovery &ndash; the industry standard, Rubrik included &ndash; restores pieces in random order: like dumping out a puzzle and gluing down whatever you grab first, nothing forms a complete, usable picture until the whole box is done, ' + fmtMin(model.fullRestoreMin) + ' here. ABR does what any puzzle solver does first &ndash; corners and edges, the pieces that actually give you something to work with &ndash; prioritizing recently accessed, modified, and created data so the business is operational in ' + fmtMin(g1.wallClockCumMin) + '.</div>' +
        '<div class="fin-tl-track-block">' +
          '<div class="fin-tl-track-label">Without ABR</div>' +
          '<div class="fin-tl-track-sublabel">Mass Recovery &ndash; random restore order</div>' +
          withoutAbrBarHtml +
        "</div>" +
        '<div class="fin-tl-track-block">' +
          '<div class="fin-tl-track-label">With ABR</div>' +
          '<div class="fin-tl-track-sublabel">recently active data restored first</div>' +
          withAbrBarHtml +
        "</div>" +
        '<div class="fin-tl-gap-callout">Same timescale for both rows. The data your users actually need is back in <b>' + fmtMin(g3.wallClockCumMin) + "</b> with ABR, vs. <b>" + fmtMin(model.fullRestoreMin) + "</b> for a fully random-order restore.</div>" +
        legendHtml +
      "</div>";
    }
  } else {
    financialHtml += '<div class="exec-hero-note">Downtime cost ($/hour) is not set, so dollar figures are $0 below. Set it on the <span class="exec-hero-linkout" onclick="switchTab(\'recovery\')">Recovery tab</span> to turn these into real cost-avoidance numbers for this customer.</div>';
  }

  // NEW v3.4.0: Dormant Data callout, per feedback 2026-07-17 - "Dormant:
  // N" was sitting as one equally-weighted cell in the tier totals grid,
  // easy to miss even though it's often the single most striking fact in
  // the whole report: a large majority of a tenant can be genuinely
  // dormant, which Mass Recovery restores blindly and in full every time,
  // while ABR already knows to leave it for last. Computed across ALL FIVE
  // workloads (not just the three with a wall-clock recovery-time model),
  // and shown unconditionally - this is an object-count story, not a
  // dollar one, so it doesn't depend on $/hour being set.
  // NEW v3.6.0: moved out of financialHtml into its own dormantHtml block,
  // per feedback 2026-07-22 - rendered into #exec-dormant at the very
  // bottom of the Report tab (see panel-report in the HTML template),
  // collapsed by default behind a toggle button. It's supporting color for
  // what ABR already deprioritizes, not part of the primary financial/
  // recovery-time case the tab leads with.
  // NEW v3.10.1: recovery time per tile. Group 4 has no ABR priority and no
  // separate recovery job of its own - per RECOVERY-MODEL-METHODOLOGY.md,
  // it "rides along" with whatever else hasn't come back yet, which means a
  // Group 4 object's data is only guaranteed back once that WORKLOAD's own
  // Mass Recovery finishes end to end (Mass Recovery doesn't sequence by
  // group). So the honest per-tile time is that workload's own full-dataset
  // Mass Recovery total (model.perWorkloadMassRecoveryMin), not an isolated
  // "just Group 4" figure - there is no such isolated job. Teams has no
  // independent recovery-time model (its content lives in SharePoint/
  // Exchange - see "Why Teams needs no recovery-time split" in the
  // methodology doc), so its tile gets a note instead of a number.
  var MASS_RECOVERY_KEY_BY_WORKLOAD = { mailboxes: "ex", onedrive: "od", sharepoint: "sp" };
  var inactiveTierName = TIER_ORDER[TIER_ORDER.length - 1];
  var dormantByWorkload = WORKLOAD_DEFS.map(function (wd) {
    var rows = DATA.workloads[wd.key] || [];
    var inactiveCount = rows.filter(function (r) { return r.Tier === inactiveTierName; }).length;
    var pct = rows.length > 0 ? Math.round((inactiveCount / rows.length) * 100) : 0;
    var massKey = MASS_RECOVERY_KEY_BY_WORKLOAD[wd.key];
    var massRecoveryMin = massKey ? model.perWorkloadMassRecoveryMin[massKey] : null;
    return { label: wd.label, inactiveCount: inactiveCount, total: rows.length, pct: pct, massRecoveryMin: massRecoveryMin };
  }).filter(function (d) { return d.total > 0; });
  var totalObjectsAll = dormantByWorkload.reduce(function (s, d) { return s + d.total; }, 0);
  var totalInactiveAll = dormantByWorkload.reduce(function (s, d) { return s + d.inactiveCount; }, 0);
  var overallDormantPct = totalObjectsAll > 0 ? Math.round((totalInactiveAll / totalObjectsAll) * 100) : 0;
  var sortedDormant = dormantByWorkload.slice().sort(function (a, b) { return b.pct - a.pct; });

  // NEW v3.7.0: retitled from "Dormant Data - What ABR Already Knows" to a
  // Group 4 framing, per feedback 2026-07-30 - Dormant folded into Group 4
  // everywhere (TIER_ORDER/TIER_META), no longer branded as its own
  // "dormant" category. Still collapsed by default at the bottom of the
  // Report tab - this is detail for anyone who digs in, not a headline.
  var dormantHtml = "";
  if (totalObjectsAll > 0) {
    dormantHtml = '<div class="exec-collapsible">' +
      '<button type="button" class="exec-collapsible-toggle" onclick="toggleCollapsible(this)" aria-expanded="false">' +
        '<span class="exec-collapsible-chevron">&#9656;</span>' +
        '<span class="exec-collapsible-title">Group 4 Detail</span>' +
        '<span class="exec-collapsible-summary">' + overallDormantPct + '% (' + fmtNum(totalInactiveAll) + ' of ' + fmtNum(totalObjectsAll) + ' objects)</span>' +
      "</button>" +
      '<div class="exec-collapsible-body" hidden>' +
        '<div class="exec-dormant-headline"><b>' + overallDormantPct + '%</b> of this tenant (' + fmtNum(totalInactiveAll) + ' of ' + fmtNum(totalObjectsAll) + ' objects) falls into Group 4 - limited activity across every metric in the reporting window. Group 4 gets no ABR priority and is recovered entirely by Mass Recovery, alongside whatever else hasn\'t come back yet.</div>' +
        '<div class="exec-dormant-grid">' +
          sortedDormant.map(function (d) {
            var timeHtml = d.massRecoveryMin !== null
              ? '<div class="exec-dormant-time">Mass Recovery: ~' + fmtMin(d.massRecoveryMin) + ' (whole workload)</div>'
              : '<div class="exec-dormant-time-na">No independent recovery-time model - Teams content lives in SharePoint/Exchange</div>';
            return '<div class="exec-dormant-cell"><div class="exec-dormant-pct">' + d.pct + '%</div><div class="exec-dormant-label">' + esc(d.label) + '</div><div class="exec-dormant-sub">' + fmtNum(d.inactiveCount) + ' of ' + fmtNum(d.total) + ' in Group 4</div>' + timeHtml + '</div>';
          }).join("") +
        "</div>" +
      "</div>" +
    "</div>";
  }

  // Flag when a group has zero objects - rare now that all workloads use
  // criticality-ranked -TierSplit (guarantees population as long as there's
  // enough active data), but can still happen on a very small tenant. Call
  // it out rather than showing an unexplained identical cumulative number.
  var g1Count = g1.sp.objectCount + g1.od.objectCount + g1.ex.objectCount;
  var g2Count = g2.sp.objectCount + g2.od.objectCount + g2.ex.objectCount;
  var g3Count = g3.sp.objectCount + g3.od.objectCount + g3.ex.objectCount;
  var g2EmptyBadge = g2Count === 0 ? ' <span class="badge empty-tier">Empty</span>' : "";
  var g3EmptyBadge = g3Count === 0 ? ' <span class="badge empty-tier">Empty</span>' : "";
  var g2EmptyNote = g2Count === 0 ? '<div class="exec-empty-note">Same as Group 1 - no objects fall in Group 2.</div>' : "";
  var g3EmptyNote = g3Count === 0 ? '<div class="exec-empty-note">Same as Groups 1-2 - no objects fall in Group 3.</div>' : "";

  var recoveryHtml = '<div class="exec-hero-label">Recovery Times (ABR, sequenced by group)</div>' +
    '<div class="exec-hero-grid">' +
      '<div class="exec-hero-card"><div class="exec-hero-tag">Group 1 online in</div><div class="exec-hero-value">' + fmtMin(g1.wallClockCumMin) + '</div><div class="exec-hero-sub">' + fmtNum(g1Count) + " objects - target: " + state.recovery.group1Hours + " hr</div></div>" +
      '<div class="exec-hero-card"><div class="exec-hero-tag">Groups 1-2 online in' + g2EmptyBadge + '</div><div class="exec-hero-value">' + fmtMin(g2.wallClockCumMin) + '</div><div class="exec-hero-sub">cumulative - target: ' + state.recovery.group2Hours + " hr</div>" + g2EmptyNote + "</div>" +
      '<div class="exec-hero-card"><div class="exec-hero-tag">Groups 1-3 online in' + g3EmptyBadge + '</div><div class="exec-hero-value">' + fmtMin(g3.wallClockCumMin) + '</div><div class="exec-hero-sub">cumulative - target: ' + state.recovery.group3Hours + " hr</div>" + g3EmptyNote + "</div>" +
      '<div class="exec-hero-card' + (exceedingGroups.length > 0 ? " exposure" : "") + '"><div class="exec-hero-tag">Full tenant, no prioritization</div><div class="exec-hero-value">' + fmtMin(model.fullRestoreMin) + '</div><div class="exec-hero-sub">Mass Recovery baseline for comparison</div></div>' +
    "</div>" +
    '<div class="exec-hero-note">' + targetGapNote + ' <span class="exec-hero-linkout" onclick="switchTab(\'recovery\')">Adjust RTO targets on the Recovery tab &rarr;</span></div>';

  // NEW v3.5.0: "Downtime Cost Avoided by Group" table, added to the Report
  // tab per feedback 2026-07-17 - extends the existing Group-1-vs-Full
  // comparison above to show cost avoided at EVERY milestone (Groups 1,
  // 1-2, and 1-3 cumulative), not just Group 1. On a tenant where hot data
  // is concentrated in Group 1 (see the RubrikDemo outlier discussed in
  // RECOVERY-MODEL-METHODOLOGY.md), all three rows land near the same
  // reduction percentage - that is expected, not a bug - but on a tenant
  // with more evenly distributed hot data this table will show real
  // escalation across the three rows.
  var costTableHtml = "";
  if (state.recovery.costPerHour > 0 && model.fullRestoreMin > 0) {
    var costRows = [
      { label: "Group 1 online", m: g1 },
      { label: "Groups 1-2 online", m: g2 },
      { label: "Groups 1-3 online", m: g3 }
    ].map(function (row) {
      var cost = fmtHours(row.m.wallClockCumMin) * state.recovery.costPerHour;
      var avoided = Math.max(0, fullExposureMoney - cost);
      var pct = fullExposureMoney > 0 ? Math.round((avoided / fullExposureMoney) * 100) : 0;
      return "<tr><td>" + row.label + "</td><td>" + fmtMin(row.m.wallClockCumMin) + "</td><td>" + fmtMoney(cost) + "</td><td>" + fmtMoney(avoided) + "</td><td>" + pct + "%</td></tr>";
    }).join("") + '<tr class="total-row"><td>Full tenant (Mass Recovery baseline)</td><td>' + fmtMin(model.fullRestoreMin) + "</td><td>" + fmtMoney(fullExposureMoney) + "</td><td>&mdash;</td><td>&mdash;</td></tr>";
    costTableHtml = '<div class="exec-hero-label" style="margin-top:1.8rem;">Downtime Cost Avoided by Group</div>' +
      '<div class="exec-cost-table-wrap"><table class="exec-cost-table"><thead><tr><th>Milestone</th><th>Time</th><th>Downtime Cost</th><th>Cost Avoided</th><th>Reduction</th></tr></thead><tbody>' + costRows + "</tbody></table></div>";
  }

  document.getElementById("exec-financial").innerHTML = financialHtml;
  document.getElementById("exec-recovery-times").innerHTML = recoveryHtml;
  document.getElementById("exec-cost-table").innerHTML = costTableHtml;
  document.getElementById("exec-dormant").innerHTML = dormantHtml;
}

// NEW v3.5.0: lean, hard-hitting Executive Summary - split out of the
// (now much longer) detailed content per feedback 2026-07-17: the original
// single Executive Summary tab had grown too long for an exec skim. This
// renders into the new #exec-lean panel (the Executive Summary tab), while
// renderExecFinancialAndRecoveryTop/renderExecSummary below continue to
// render the full detail into the Report tab (same element ids as before -
// only their surrounding panel moved). Exactly three numbers - time to
// critical data, downtime cost avoided, and dormant-data percentage - plus
// one sentence on the mechanism and a link to the Report tab. Deliberately
// does not reuse renderExecFinancialAndRecoveryTop()'s computed values,
// since that function targets Report-tab-only elements; this recomputes
// the (cheap) handful of numbers it needs directly from computeRecoveryModel()
// and DATA, so the lean tab has no dependency on the detailed tab's DOM.
// NEW: Recovery Ladder - single to-scale horizontal timeline for the lean
// Executive Summary tab, added per feedback 2026-08-10. Leadership wants to
// see how Group 1/2/3 stack up in sequence, not just the single Group 1
// "Time to Critical Data" number - this shows cumulative milestones (Group
// 1 online, Groups 1-2 online, Groups 1-3 online) against the Mass Recovery
// baseline, all drawn on the SAME timescale so the visual gap tells the
// story. Groups are relabeled here ONLY (Mission-Critical/Business-
// Important/Standard) as a plain-English translation scoped to this one
// visual - "Group N" stays the term of record everywhere else in the
// report (filters, columns, methodology, CSV).
// Segment widths are true-to-scale (% of model.fullRestoreMin). Flag
// (label) x-positions are separately clamped to a minimum spacing so the
// time values don't visually collide when milestones land close together -
// this does NOT change the underlying track segment widths, only where the
// label callouts anchor, keeping the time value readable above its pin
// instead of overlapping the track. A tier with zero populated objects is
// dropped entirely (no flag, no phantom milestone) rather than showing a
// redundant/confusing duplicate of the previous time.
function buildRecoveryLadderHtml(model) {
  var full = model.fullRestoreMin;
  if (!full || full <= 0) { return ""; }

  var defs = [
    { tier: "Critical Group 1", short: "Mission-Critical", verb: "back online" },
    { tier: "Critical Group 2", short: "Business-Important", verb: "cumulative" },
    { tier: "Critical Group 3", short: "Standard", verb: "cumulative" }
  ];

  function tierCount(tierName) {
    var n = 0;
    WORKLOAD_DEFS.forEach(function (wd) {
      var rows = DATA.workloads[wd.key] || [];
      n += rows.filter(function (r) { return r.Tier === tierName; }).length;
    });
    return n;
  }

  var milestones = defs.map(function (d) {
    return {
      tier: d.tier,
      short: d.short,
      verb: d.verb,
      color: TIER_META[d.tier].bg,
      cumMin: model.milestones[d.tier].wallClockCumMin,
      count: tierCount(d.tier)
    };
  }).filter(function (m) { return m.count > 0; });

  if (milestones.length === 0) { return ""; }

  // Track segments: true-to-scale, sequential deltas summing to 100%.
  var prevPct = 0;
  milestones.forEach(function (m) {
    var pct = Math.max(0, Math.min(100, (m.cumMin / full) * 100));
    m.segWidth = Math.max(0, pct - prevPct);
    m.truePct = pct;
    prevPct = pct;
  });
  var massSegWidth = Math.max(0, 100 - prevPct);

  // Label anchors: same order, minimum-spaced so times stay readable even
  // when milestones land close together on a compressed axis.
  var MIN_GAP = 13, MAX_POS = 86, lastPos = -999;
  milestones.forEach(function (m, i) {
    var pos = i === 0 ? Math.max(m.truePct, 6) : Math.max(m.truePct, lastPos + MIN_GAP);
    pos = Math.min(pos, MAX_POS);
    m.labelPos = pos;
    lastPos = pos;
  });

  var segHtml = milestones.map(function (m) {
    return '<div class="rl-seg" style="width:' + m.segWidth + '%;background:' + m.color + ';"></div>';
  }).join("") + '<div class="rl-seg mass" style="width:' + massSegWidth + '%;"></div>';

  var flagsHtml = milestones.map(function (m) {
    return '<div class="rl-flag" style="left:' + m.labelPos + '%;">' +
      '<div class="rl-time">' + fmtMin(m.cumMin) + '</div>' +
      '<div class="rl-pin" style="background:' + m.color + ';"></div>' +
      '<div class="rl-label">' + esc(m.short) + '<br>' + esc(m.verb) + '</div>' +
    '</div>';
  }).join("");

  return '<div class="recovery-ladder">' +
    '<div class="rl-title">Recovery Ladder</div>' +
    '<div class="rl-sub">Same timescale, cumulative milestones &ndash; how fast the business comes back, group by group.</div>' +
    '<div class="rl-track-wrap">' +
      '<div class="rl-track">' + segHtml + '</div>' +
      flagsHtml +
      '<div class="rl-mass-label"><div class="rl-time">' + fmtMin(full) + '</div><div class="rl-label">Mass Recovery baseline<br>(no prioritization)</div></div>' +
    '</div>' +
  '</div>';
}

function renderExecLean() {
  var model = computeRecoveryModel();
  var g1 = model.milestones["Critical Group 1"];
  var fullExposureMoney = fmtHours(model.fullRestoreMin) * state.recovery.costPerHour;
  var abrCostMoney = fmtHours(g1.wallClockCumMin) * state.recovery.costPerHour;
  var savingsMoney = Math.max(0, fullExposureMoney - abrCostMoney);
  var pctReduction = fullExposureMoney > 0 ? Math.round((savingsMoney / fullExposureMoney) * 100) : 0;

  var html;
  if (model.fullRestoreMin > 0) {
    var moneyTileHtml = state.recovery.costPerHour > 0
      ? ('<div class="exec-lean-tile money"><div class="exec-lean-tile-label">Downtime Cost Avoided</div><div class="exec-lean-tile-value">' + fmtMoney(savingsMoney) + '</div><div class="exec-lean-tile-sub"><b>' + pctReduction + '%</b> reduction vs. a fully random-order restore</div></div>')
      : ('<div class="exec-lean-tile money"><div class="exec-lean-tile-label">Downtime Cost Avoided</div><div class="exec-lean-tile-value">&mdash;</div><div class="exec-lean-tile-sub">Set $/hour on the <span class="exec-hero-linkout" onclick="switchTab(\'recovery\')">Recovery tab</span> to see this figure</div></div>');
    // NEW v3.7.0: Dormant Data hero tile removed per feedback 2026-07-30 -
    // Dormant folded into Group 4 (see TIER_ORDER/TIER_META), and Group 4 is
    // no longer a headline number anywhere in the Executive Summary. Its
    // count/percentage still lives in the Group Overview table and the
    // collapsed Group 4 section at the bottom of the Report tab, for anyone
    // who digs in - just not surfaced as one of the top-line stats.
    html = '<div class="exec-lean-tiles">' +
        '<div class="exec-lean-tile"><div class="exec-lean-tile-label">Time to Critical Data</div><div class="exec-lean-tile-value">' + fmtMin(g1.wallClockCumMin) + '</div><div class="exec-lean-tile-sub">instead of <b>' + fmtMin(model.fullRestoreMin) + '</b> with a traditional, random-order restore</div></div>' +
        moneyTileHtml +
      "</div>" +
      buildRecoveryLadderHtml(model) +
      // NEW v3.7.0: plain, literal (non-metaphor) definition of both terms,
      // per feedback 2026-07-30 - the puzzle analogy on the Report tab stays
      // as the fuller narrative version; this is the short, unambiguous
      // companion for anyone who wants the mechanism in one read.
      '<div class="exec-lean-mechanism">Mass Recovery restores data in undifferentiated, random order until everything is back - there is no telling when any one piece of data returns. ABR (Autonomous Business Recovery) uses real activity data to identify what was <b>recently accessed, modified, or created</b> and restores that first, so the business is operational in hours, not weeks - Mass Recovery then continues in the background to complete the older data.</div>' +
      '<div class="exec-lean-footer-link">Full breakdown, per-group detail, and methodology &rarr; <span class="exec-hero-linkout" onclick="switchTab(\'report\')">See the Report tab</span></div>';
  } else {
    html = '<div class="exec-hero-note">No active objects were found across the scanned workloads - nothing to summarize yet.</div>';
  }
  document.getElementById("exec-lean").innerHTML = html;
}

function renderExecSummary() {
  renderExecFinancialAndRecoveryTop();
  var cardsHtml = "";
  var grandTotals = { objects: 0, tiers: {} };
  TIER_ORDER.forEach(function (t) { grandTotals.tiers[t] = 0; });

  WORKLOAD_DEFS.forEach(function (wd) {
    var rows = DATA.workloads[wd.key] || [];
    var total = rows.length;
    var segs = "", legend = "";
    TIER_ORDER.forEach(function (t) {
      var count = rows.filter(function (r) { return r.Tier === t; }).length;
      grandTotals.tiers[t] += count; grandTotals.objects += (t === TIER_ORDER[0] ? 0 : 0);
      if (total > 0 && count > 0) {
        var pct = Math.round((count / total) * 10000) / 100;
        segs += '<span style="width:' + pct + '%;background:' + TIER_META[t].bg + ';"></span>';
      }
      legend += '<div><span style="width:8px;height:8px;border-radius:50%;background:' + TIER_META[t].bg + ';display:inline-block;"></span>' + TIER_META[t].short + ": " + count + "</div>";
    });
    grandTotals.objects += total;
    cardsHtml += '<div class="summary-card" style="--accent:var(--blue);" onclick="goToWorkload(\'' + wd.key + '\')">' +
      "<h3>" + esc(wd.label) + '</h3><div class="total">' + total + '</div><div class="tier-bar">' + segs + '</div><div class="tier-legend">' + legend + "</div></div>";
  });
  document.getElementById("exec-summary-cards").innerHTML = cardsHtml;

  var totalsHtml = '<div class="totals-grid">';
  TIER_ORDER.forEach(function (t) {
    totalsHtml += '<div class="totals-cell"><div class="label">' + TIER_META[t].short + ' - Objects</div><div class="value">' + fmtNum(grandTotals.tiers[t]) + "</div></div>";
  });
  totalsHtml += "</div>";
  document.getElementById("exec-totals").innerHTML = "<h2>Totals Across All Workloads</h2>" + totalsHtml;
}

function goToWorkload(key) {
  switchTab("groups");
  setTimeout(function () {
    var el = document.getElementById("wl-" + key);
    if (el) { el.scrollIntoView({ behavior: "smooth" }); }
  }, 50);
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

function rowPassesFilters(row, wdKey) {
  var f = state.activeFilters[wdKey] || {};
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

function buildWorkloadTotalsRow(wdKey, rowsOverride, headingLabel) {
  // rowsOverride/headingLabel (optional): render totals for a pre-filtered
  // row subset instead of the whole workload, with a heading identifying
  // it as such - used for the "Filtered View" breakdown in
  // buildWorkloadSection so a filter like Department=Sales shows how many
  // of THOSE rows fall in each tier, not just the whole workload's totals.
  var totals = getTierTotals(wdKey, rowsOverride);
  var wd = WORKLOAD_DEFS.filter(function (w) { return w.key === wdKey; })[0];
  var heading = headingLabel ? ('<div class="totals-heading">' + esc(headingLabel) + "</div>") : "";
  var html = heading + '<div class="totals-grid">';
  TIER_ORDER.forEach(function (t) {
    var tt = totals[t];
    var storageBit = wd.storageField ? (", " + tt.storageTotal.toFixed(1) + " " + wd.storageLabel.replace("Storage (", "").replace(")", "")) : "";
    html += '<div class="totals-cell"><div class="label">' + TIER_META[t].short + '</div><div class="value">' + fmtNum(tt.objectCount) + " objs</div><div style=\"font-size:.72rem;color:var(--dark-gray);\">" + fmtNum(tt.itemTotal) + " " + wd.itemLabel.toLowerCase() + storageBit + "</div></div>";
  });
  html += "</div>";
  return html;
}

function buildWorkloadSection(wdKey) {
  var wd = WORKLOAD_DEFS.filter(function (w) { return w.key === wdKey; })[0];
  var rows = DATA.workloads[wdKey] || [];
  var hasEnrichment = rows.some(function (r) { return !!r.JobTitle || !!r.Department; });
  var hasMailboxType = wdKey === "mailboxes" && rows.some(function (r) { return !!r.MailboxTypeHeuristic; });
  var hasGroups = rows.some(function (r) { return r.Groups && r.Groups.length; });

  var f = state.activeFilters[wdKey] || (state.activeFilters[wdKey] = {});
  var chips = "";
  ["all"].concat(TIER_ORDER).forEach(function (t) {
    var count = t === "all" ? rows.length : rows.filter(function (r) { return r.Tier === t; }).length;
    var label = t === "all" ? "All" : TIER_META[t].short;
    var activeClass = ((f.tier || "all") === t) ? " active" : "";
    chips += '<button class="chip' + activeClass + '" onclick="setFilter(\'' + wdKey + '\',\'tier\',\'' + t + '\')">' + label + " (" + count + ")</button>";
  });

  // Search box: free-text, matches ANY string field we have on the row (see
  // rowSearchHaystack) - the fast way to find one specific object by name,
  // title, department, manager, etc. without knowing which dropdown filter
  // it'd fall under. oninput (live, as-you-type), not onchange, since this
  // is the primary "find this one thing" control - rerenderWorkloadSection
  // preserves focus/cursor position across the re-render so typing doesn't
  // get interrupted.
  var searchBox = '<input type="text" class="search-box" id="search-' + wdKey + '" placeholder="Search ' + esc(wd.label.toLowerCase()) + ' - name, title, department, manager, criteria..." value="' + esc(f.search || "") + '" oninput="onSearchInput(\'' + wdKey + '\',this.value)">';

  var attrFilters = "";
  if (hasEnrichment) {
    attrFilters += buildSelectFilter(wdKey, "department", "Department", distinctValues(rows, "Department"));
    attrFilters += buildSelectFilter(wdKey, "employeeType", "Employee Type", distinctValues(rows, "EmployeeType"));
    attrFilters += buildSelectFilter(wdKey, "officeLocation", "Office Location", distinctValues(rows, "OfficeLocation"));
    attrFilters += '<input type="text" id="titlefilter-' + wdKey + '" placeholder="Title contains..." value="' + esc(f.titleContains || "") + '" oninput="setFilter(\'' + wdKey + '\',\'titleContains\',this.value)" style="border:1px solid #D7DCE1;border-radius:6px;padding:.3rem .5rem;font-size:.78rem;">';
  }
  if (hasMailboxType) {
    attrFilters += buildSelectFilter(wdKey, "mailboxType", "Mailbox Type", distinctValues(rows, "MailboxTypeHeuristic"));
  }
  if (wdKey === "sharepoint") {
    attrFilters += buildSelectFilter(wdKey, "hubSite", "Hub Site", ["Yes", "No"]);
  }

  var visibleRows = rows.filter(function (r) { return rowPassesFilters(r, wdKey); });
  var isFiltered = visibleRows.length !== rows.length;
  var filteredTotalsHtml = isFiltered
    ? buildWorkloadTotalsRow(wdKey, visibleRows, "Filtered View (" + visibleRows.length + " of " + rows.length + " shown)")
    : "";

  var sortedVisible = visibleRows.slice().sort(function (a, b) { return (b._Score || 0) - (a._Score || 0); });
  var showAll = !!state.showAllRows[wdKey];
  var renderedRows = showAll ? sortedVisible : sortedVisible.slice(0, MAX_TABLE_ROWS);
  var isCapped = !showAll && sortedVisible.length > MAX_TABLE_ROWS;
  var bodyRows = renderedRows.map(function (row) {
    return buildRowHtml(row, wd, wdKey, hasEnrichment, hasMailboxType, hasGroups);
  }).join("");
  if (!bodyRows) { bodyRows = '<tr><td colspan="12" style="text-align:center;color:var(--dark-gray);padding:2rem;white-space:normal;">No rows match the current filters.</td></tr>'; }
  var capNoticeHtml = isCapped
    ? '<div class="table-cap-notice">Showing the top ' + fmtNum(MAX_TABLE_ROWS) + ' of ' + fmtNum(sortedVisible.length) + ' rows, sorted by score - search or filter above to narrow, or <button onclick="setShowAllRows(\'' + wdKey + '\')">show all ' + fmtNum(sortedVisible.length) + ' rows</button> (can be slow for a large tenant).</div>'
    : (showAll && sortedVisible.length > MAX_TABLE_ROWS
      ? '<div class="table-cap-notice">Showing all ' + fmtNum(sortedVisible.length) + ' rows. <button onclick="setShowAllRows(\'' + wdKey + '\', true)">Back to top ' + fmtNum(MAX_TABLE_ROWS) + '</button></div>'
      : "");

  var extraHeaders = "";
  if (hasEnrichment) { extraHeaders += '<th class="col-detail">Job Title</th><th class="col-detail">Department</th><th class="col-detail">Manager</th>'; }
  if (hasGroups) { extraHeaders += '<th class="col-detail">Entra ID Groups</th>'; }
  if (hasMailboxType) { extraHeaders += '<th class="col-detail">Mailbox Type</th>'; }

  // NEW: presenter pass - per-workload "essentials only" column toggle, plus
  // a scroll-for-more hint + fade affordance wired up by attachScrollAffordance()
  // after this markup lands in the DOM (see renderGroupsTab/rerenderWorkloadSection).
  var showDetail = state.columnPrefs[wdKey] !== false;
  var detailColLabels = ["Why / criteria tags"];
  if (hasEnrichment) { detailColLabels.push("Job Title", "Department", "Manager"); }
  if (hasGroups) { detailColLabels.push("Entra ID Groups"); }
  if (hasMailboxType) { detailColLabels.push("Mailbox Type"); }
  var toolbar = '<div class="table-toolbar">' +
    '<label class="col-toggle"><input type="checkbox" id="coltoggle-' + wdKey + '"' + (showDetail ? " checked" : "") + ' onchange="onColumnToggleChange(\'' + wdKey + '\',this.checked)"> Show detail columns <span class="col-toggle-hint">(' + detailColLabels.join(", ") + ')</span></label>' +
    '<span class="scroll-hint" id="scrollhint-' + wdKey + '">&#9664; scroll for more &#9654;</span>' +
    "</div>";

  var headerCount = isFiltered ? (fmtNum(visibleRows.length) + " of " + fmtNum(rows.length) + " shown") : String(rows.length);

  return '<section class="workload" id="wl-' + wdKey + '">' +
    "<h3>" + esc(wd.label) + ' <span style="font-weight:400;font-size:.9rem;color:var(--dark-gray);">(' + headerCount + ")</span></h3>" +
    buildWorkloadTotalsRow(wdKey, null, "All Objects") +
    '<div class="search-box-row">' + searchBox + "</div>" +
    '<div class="filter-chips">' + chips + "</div>" +
    '<div class="filter-chips">' + attrFilters + "</div>" +
    filteredTotalsHtml +
    '<div class="mass-edit-bar">' +
      '<span style="font-size:.78rem;color:var(--dark-gray);">Mass-reassign all <b>' + visibleRows.length + '</b> currently-filtered rows to:</span>' +
      '<select id="mass-tier-' + wdKey + '">' + TIER_ORDER.map(function (t) { return '<option value="' + t + '">' + TIER_META[t].short + '</option>'; }).join("") + '</select>' +
      '<button onclick="massReassign(\'' + wdKey + '\')">Apply</button>' +
    "</div>" +
    toolbar +
    '<div class="table-scroll-shell" id="shell-' + wdKey + '">' +
      '<div class="table-wrap' + (showDetail ? "" : " essentials-only") + '" id="tbl-wrap-' + wdKey + '"><table id="tbl-' + wdKey + '"><thead><tr>' +
      '<th>Object</th><th>Identifier</th><th>Tier</th><th>Score</th><th class="col-detail">Why</th><th>Last Activity</th><th>' + wd.itemLabel + "</th>" + (wd.storageField ? "<th>" + wd.storageLabel + "</th>" : "") + extraHeaders +
      "</tr></thead><tbody>" + bodyRows + "</tbody></table></div>" +
      '<div class="scroll-fade-right" aria-hidden="true"></div>' +
    "</div>" +
    capNoticeHtml +
    "</section>";
}

function buildSelectFilter(wdKey, field, label, values) {
  // Reads the currently active value for this field so the dropdown shows
  // the right selection after a re-render, instead of visually resetting to
  // "All" every time (it was still filtering correctly before this fix -
  // just looked like it had forgotten your selection).
  var current = (state.activeFilters[wdKey] || {})[field] || "";
  var opts = '<option value=""' + (current === "" ? " selected" : "") + '>' + label + ": All</option>";
  values.forEach(function (v) { opts += '<option value="' + esc(v) + '"' + (current === v ? " selected" : "") + ">" + esc(v) + "</option>"; });
  return '<select onchange="setFilter(\'' + wdKey + "','" + field + '\',this.value)">' + opts + "</select>";
}

function buildRowHtml(row, wd, wdKey, hasEnrichment, hasMailboxType, hasGroups) {
  var tierMeta = TIER_META[row.Tier] || TIER_META[TIER_ORDER[TIER_ORDER.length - 1]];
  var overrideBadge = row.IsOverride ? '<span class="badge override" title="' + esc(row.OverrideReason) + '">override</span>' : "";
  var pct = Math.round((row._Score || 0) * 100);
  var options = TIER_ORDER.map(function (t) {
    return '<option value="' + t + '"' + (row.Tier === t ? " selected" : "") + ">" + TIER_META[t].short + "</option>";
  }).join("");
  var extra = "";
  if (hasEnrichment) {
    extra += '<td class="col-detail">' + esc(row.JobTitle) + '</td><td class="col-detail">' + esc(row.Department) + '</td><td class="col-detail">' + esc(row.Manager) + "</td>";
  }
  if (hasGroups) { extra += '<td class="col-detail">' + esc((row.Groups || []).join(", ")) + "</td>"; }
  if (hasMailboxType) { extra += '<td class="col-detail">' + esc(row.MailboxTypeHeuristic) + "</td>"; }
  return "<tr>" +
    "<td>" + esc(row.ObjectName) + "</td>" +
    "<td>" + esc(row.Identifier) + "</td>" +
    '<td><span class="badge" style="background:' + tierMeta.bg + ";color:" + tierMeta.fg + ';">' + tierMeta.short + "</span>" + overrideBadge +
      '<br><select class="tier-select" onchange="onTierDropdownChange(\'' + wdKey + "','" + row.Identifier.replace(/'/g, "\\'") + '\',this.value)">' + options + "</select></td>" +
    '<td><div class="score-bar-wrap"><div class="score-bar"><span style="width:' + pct + '%;"></span></div>' + pct + "%</div></td>" +
    '<td class="criteria-tags col-detail">' + esc(row.CriteriaTags) + "</td>" +
    "<td>" + esc(row.LastActivityDate) + "</td>" +
    "<td>" + fmtNum(row.metrics[wd.itemField]) + "</td>" +
    (wd.storageField ? "<td>" + (parseFloat(row.metrics[wd.storageField]) || 0).toFixed(2) + "</td>" : "") +
    extra + "</tr>";
}

function setFilter(wdKey, field, value) {
  var f = state.activeFilters[wdKey] || (state.activeFilters[wdKey] = {});
  f[field] = value;
  rerenderWorkloadSection(wdKey);
}

// NEW v3.10.3: see MAX_TABLE_ROWS above. reset=true flips back to the fast,
// capped view; omitted/false renders every row currently passing filters.
function setShowAllRows(wdKey, reset) {
  state.showAllRows[wdKey] = !reset;
  rerenderWorkloadSection(wdKey);
}

// Same idea as setShowAllRows, for the standalone Group 1 cross-workload
// overview table (buildGroup1Overview) rather than a per-workload section.
function setGroup1ShowAll(reset) {
  state.group1ShowAll = !reset;
  refreshGroupsBody();
}

// NEW v3.10.3: debounces the live search box so a fast typist on a large
// tenant doesn't trigger a full filter+sort+render on every keystroke - only
// once input has paused for SEARCH_DEBOUNCE_MS. The <input> itself is never
// re-created mid-type (rerenderWorkloadSection already preserves focus/cursor
// position), this just delays how often that rebuild actually fires.
var SEARCH_DEBOUNCE_MS = 250;
var searchDebounceTimers = {};
function onSearchInput(wdKey, value) {
  clearTimeout(searchDebounceTimers[wdKey]);
  searchDebounceTimers[wdKey] = setTimeout(function () { setFilter(wdKey, "search", value); }, SEARCH_DEBOUNCE_MS);
}

function onTierDropdownChange(wdKey, identifier, newTier) {
  setOverride(wdKey, identifier, newTier, "Manual (dropdown)");
  recomputeAll();
}

function massReassign(wdKey) {
  var sel = document.getElementById("mass-tier-" + wdKey);
  var tier = sel.value;
  var rows = (DATA.workloads[wdKey] || []).filter(function (r) { return rowPassesFilters(r, wdKey); });
  rows.forEach(function (r) { setOverride(wdKey, r.Identifier, tier, "Mass reassignment via filter"); });
  recomputeAll();
}

function rerenderWorkloadSection(wdKey) {
  // The search box (and title-contains box) filter live, on every keystroke
  // (oninput), which rebuilds this whole section's HTML each time. Without
  // this, replacing outerHTML destroys and recreates the <input> the user
  // is typing into, so it loses focus after every character - unusable for
  // a search box. Capture the focused element (if it's inside this section)
  // before replacing, then restore focus + cursor position by id afterward.
  var el = document.getElementById("wl-" + wdKey);
  if (!el) { return; }
  var active = document.activeElement;
  var restoreId = null, restoreStart = null, restoreEnd = null;
  if (active && active.id && el.contains(active)) {
    restoreId = active.id;
    if (typeof active.selectionStart === "number") { restoreStart = active.selectionStart; restoreEnd = active.selectionEnd; }
  }
  el.outerHTML = buildWorkloadSection(wdKey);
  attachScrollAffordance(wdKey);
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

// NEW: presenter pass - column-visibility toggle + scroll affordances. Kept
// here (once) alongside buildWorkloadSection since that is the one shared
// per-workload table helper used by all five workload tabs, rather than
// duplicating this per-workload.
function onColumnToggleChange(wdKey, checked) {
  state.columnPrefs[wdKey] = checked;
  saveColumnPrefsToStorage();
  var wrap = document.getElementById("tbl-wrap-" + wdKey);
  if (wrap) { wrap.classList.toggle("essentials-only", !checked); }
  refreshScrollAffordance(wdKey);
}

function refreshScrollAffordance(wdKey) {
  var wrap = document.getElementById("tbl-wrap-" + wdKey);
  var shell = document.getElementById("shell-" + wdKey);
  var hint = document.getElementById("scrollhint-" + wdKey);
  if (!wrap || !shell) { return; }
  var hasOverflow = wrap.scrollWidth > wrap.clientWidth + 2;
  var atRightEdge = (wrap.scrollLeft + wrap.clientWidth) >= (wrap.scrollWidth - 2);
  shell.classList.toggle("has-more-right", hasOverflow && !atRightEdge);
  if (hint) { hint.style.display = hasOverflow ? "" : "none"; }
}

function attachScrollAffordance(wdKey) {
  var wrap = document.getElementById("tbl-wrap-" + wdKey);
  var hint = document.getElementById("scrollhint-" + wdKey);
  if (!wrap) { return; }
  wrap.addEventListener("scroll", function () {
    if (hint && wrap.scrollLeft > 4) { hint.classList.add("scrolled"); }
    refreshScrollAffordance(wdKey);
  });
  refreshScrollAffordance(wdKey);
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
function buildControlsSliders() {
  var html = '<div class="controls-panel"><h4 class="panel-title">Live scoring controls</h4>' +
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
  html += '<div class="bonus-section"><div class="bonus-label-row"><b style="font-size:.8rem;color:var(--navy);">Bonus modifiers</b><span class="bonus-tag">Additive, not part of the 100%</span></div>' +
    '<p class="bonus-hint">Layered on top of a workload\'s score above. Capped so an object can\'t exceed a perfect score from bonuses alone.</p>';
  var twPct = Math.round(state.titleWeightContribution * 100);
  var hsPct = Math.round(state.hubSiteBonus * 100);
  html += '<div class="control-row"><label>Title-weight bonus</label><input type="range" id="wslider-_bonus-titleWeight" min="0" max="100" step="5" value="' + twPct + '" data-wd="_bonus" data-field="titleWeight" oninput="onWeightSlide(this)"><span class="valdisp" id="wval-_bonus-titleWeight">' + twPct + '%</span></div>';
  html += '<div class="control-row"><label>Hub-site bonus</label><input type="range" id="wslider-_bonus-hubSite" min="0" max="100" step="5" value="' + hsPct + '" data-wd="_bonus" data-field="hubSite" oninput="onWeightSlide(this)"><span class="valdisp" id="wval-_bonus-hubSite">' + hsPct + '%</span></div>';
  html += "</div>";
  html += '<div class="control-row" style="margin-top:.9rem;"><label>Hub-site keywords</label><input type="text" style="flex:1;max-width:400px;" value="' + esc(state.hubSiteKeywords.join(", ")) + '" onchange="onHubKeywordsChange(this.value)"></div>';
  html += '<div class="control-row"><label>Filter to org under manager</label><input type="text" placeholder="Manager display name..." style="flex:1;max-width:300px;" onchange="onManagerFilterChange(this.value)"></div>';
  html += buildGroupFilterControlHtml();
  html += "</div>";
  return html;
}

// Entra ID group-based bulk selection - same idea and same scope
// (Mailboxes/OneDrive only) as the manager filter above, mirroring how RSC
// Mass Recovery groups users by AD/Entra ID Group. A <select> of exact group
// names (rather than free text like the manager box) since group names are
// canonical identifiers, not something most admins have memorized. Combines
// with the manager filter automatically (both are independent AND
// conditions in rowPassesFilters) - "everyone in this group AND under this
// manager" works without any extra code. Only rendered as usable when
// -Groups actually resolved data this run; otherwise shown disabled with an
// explanatory hint rather than silently doing nothing (which is what the
// manager box does if -Full was never passed - fine for a switch that's
// always been there, less fine for one someone may not know exists yet).
function buildGroupFilterControlHtml() {
  var groupRows = (DATA.workloads.mailboxes || []).concat(DATA.workloads.onedrive || []);
  var groupNames = distinctGroupNames(groupRows);
  var currentGroup = ((state.activeFilters.mailboxes || {}).group) || "";
  if (groupNames.length === 0) {
    return '<div class="control-row"><label>Filter to Entra ID group</label><select disabled title="Not collected this run - re-run with -Full -Groups to enable"><option>Not collected this run</option></select></div>';
  }
  var opts = '<option value="">Filter to Entra ID group: All</option>';
  groupNames.forEach(function (g) { opts += '<option value="' + esc(g) + '"' + (g === currentGroup ? " selected" : "") + ">" + esc(g) + "</option>"; });
  return '<div class="control-row"><label>Filter to Entra ID group</label><select style="flex:1;max-width:300px;" onchange="onGroupFilterChange(this.value)">' + opts + "</select></div>";
}

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
  // (thousands of rows on a real tenant), which is what made dragging feel
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
      '<span class="group-name">' + TIER_META[tier].short + '</span><span class="group-total">' + fmtNum(groupTotal) + ' objects</span></div>';
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

function refreshImpactPreview() {
  var el = document.getElementById("impact-preview-wrap");
  if (!el) { return; }
  el.innerHTML = buildLiveImpactPreview(computeImpactData());
}

function resetImpactBaseline() {
  lastTierByWorkload = {};
  refreshImpactPreview();
}

function onHubKeywordsChange(value) { state.hubSiteKeywords = value.split(",").map(function (s) { return s.trim(); }).filter(Boolean); recomputeAll(); }
function onManagerFilterChange(value) {
  ["mailboxes", "onedrive"].forEach(function (wdKey) {
    var f = state.activeFilters[wdKey] || (state.activeFilters[wdKey] = {});
    f.manager = value || null;
    rerenderWorkloadSection(wdKey);
  });
}
function onGroupFilterChange(value) {
  ["mailboxes", "onedrive"].forEach(function (wdKey) {
    var f = state.activeFilters[wdKey] || (state.activeFilters[wdKey] = {});
    f.group = value || null;
    rerenderWorkloadSection(wdKey);
  });
}

function buildGroup1Overview() {
  var combined = [];
  WORKLOAD_DEFS.forEach(function (wd) {
    (DATA.workloads[wd.key] || []).filter(function (r) { return r.Tier === "Critical Group 1"; }).forEach(function (r) {
      combined.push({ workload: wd.label, objectName: r.ObjectName, identifier: r.Identifier, score: r._Score || 0, lastActivity: r.LastActivityDate, tags: r.CriteriaTags });
    });
  });
  combined.sort(function (a, b) { return b.score - a.score; });
  var g1ShowAll = !!state.group1ShowAll;
  var g1Rendered = g1ShowAll ? combined : combined.slice(0, MAX_TABLE_ROWS);
  var g1Capped = !g1ShowAll && combined.length > MAX_TABLE_ROWS;
  var rows = g1Rendered.map(function (c) {
    return "<tr><td>" + esc(c.workload) + "</td><td>" + esc(c.objectName) + "</td><td>" + esc(c.identifier) + "</td><td>" + Math.round(c.score * 100) + '%</td><td class="criteria-tags">' + esc(c.tags) + "</td><td>" + esc(c.lastActivity) + "</td></tr>";
  }).join("") || '<tr><td colspan="6" style="text-align:center;color:var(--dark-gray);padding:2rem;">No Critical Group 1 objects.</td></tr>';
  var g1CapNoticeHtml = g1Capped
    ? '<div class="table-cap-notice">Showing the top ' + fmtNum(MAX_TABLE_ROWS) + ' of ' + fmtNum(combined.length) + ' rows, sorted by score - <button onclick="setGroup1ShowAll()">show all ' + fmtNum(combined.length) + ' rows</button> (can be slow for a large tenant).</div>'
    : (g1ShowAll && combined.length > MAX_TABLE_ROWS
      ? '<div class="table-cap-notice">Showing all ' + fmtNum(combined.length) + ' rows. <button onclick="setGroup1ShowAll(true)">Back to top ' + fmtNum(MAX_TABLE_ROWS) + '</button></div>'
      : "");
  return '<section class="workload" id="group1-overview"><h3>Critical Group 1 - All Workloads <span style="font-weight:400;font-size:.9rem;color:var(--dark-gray);">(' + combined.length + ')</span></h3>' +
    '<p class="pill-note">Every object tiered Critical Group 1, across all five workloads, in one place - the full recover-first picture. Recomputes live with the controls above.</p>' +
    '<div class="table-wrap"><table><thead><tr><th>Workload</th><th>Object</th><th>Identifier</th><th>Score</th><th>Why</th><th>Last Activity</th></tr></thead><tbody>' + rows + "</tbody></table></div>" +
    g1CapNoticeHtml + "</section>";
}

// Split into a controls-grid (sliders + Live Impact Preview) that's built
// ONCE per full render, and a groups-body-wrap (Group 1 overview + the five
// workload sections) that's rebuilt separately by refreshGroupsBody(). Slider
// drags call recomputeTiersLive() -> refreshGroupsBody() only, so the sliders
// and their surrounding markup are never touched/re-created mid-drag.
function renderGroupsTab() {
  var html = '<div class="controls-panel-grid">' +
    '<div id="controls-sliders-wrap">' + buildControlsSliders() + '</div>' +
    '<div id="impact-preview-wrap">' + buildLiveImpactPreview(computeImpactData()) + '</div>' +
    '</div>' +
    '<div id="groups-body-wrap">' + buildGroup1Overview() + WORKLOAD_DEFS.map(function (wd) { return buildWorkloadSection(wd.key); }).join("") + '</div>';
  document.getElementById("panel-groups").innerHTML = html;
  refreshAllWeightTotals();
  WORKLOAD_DEFS.forEach(function (wd) { attachScrollAffordance(wd.key); });
}

function refreshGroupsBody() {
  var el = document.getElementById("groups-body-wrap");
  if (!el) { renderGroupsTab(); return; }
  // Only innerHTML is replaced below - the wrapper element itself (and any
  // class markWeightsDirty() added to it) survives, so "is-stale" has to be
  // cleared explicitly here rather than relying on the rebuild to reset it.
  el.classList.remove("is-stale");
  el.innerHTML = buildGroup1Overview() + WORKLOAD_DEFS.map(function (wd) { return buildWorkloadSection(wd.key); }).join("");
  WORKLOAD_DEFS.forEach(function (wd) { attachScrollAffordance(wd.key); });
}

// Lightweight recompute path for slider drags: never rebuilds
// #controls-sliders-wrap (so the slider the user is actively dragging is
// never re-created), only refreshes the groups body, the impact preview,
// and the other tabs that depend on scores/tiers.
function recomputeTiersLive() {
  WORKLOAD_DEFS.forEach(function (wd) { computeScoresAndTiers(wd.key); });
  renderExecLean();
  renderExecSummary();
  refreshGroupsBody();
  refreshImpactPreview();
  renderRecoveryTab();
  renderMethodologyTab();
  renderCompareTab();
  saveOverridesToStorage();
}

'@

#endregion

#region ---------- HTML report JS: recovery tab, methodology tab, compare tab ----------

$script:ReportJsRenderC = @'
function buildRecoveryControls() {
  var opts = ["Auto"].concat(SPOD_TIER_TABLE.map(function (t) { return t.Bucket; })).map(function (b) {
    return '<option value="' + b + '"' + (state.recovery.licenseTier === b ? " selected" : "") + ">" + b + "</option>";
  }).join("");
  var html = '<div class="controls-panel"><h4>Recovery modeling inputs</h4>';
  html += '<div class="control-row"><label>Recovery window (days)</label><input type="number" min="0" max="7" step="0.5" value="' + state.recovery.windowDays + '" onchange="onRecoveryInputChange(\'windowDays\',this.value)" style="width:80px;"></div>';
  html += '<div class="pill-note" style="margin-top:-.4rem;">ABR can recover up to the last 7 days of activity - drag this down to model a shorter window (linearly scales the real 7-day activity signal; not a separately measured figure).</div>';
  html += '<div class="control-row"><label>SP/OD throughput tier</label><select onchange="onRecoveryInputChange(\'licenseTier\',this.value)">' + opts + "</select></div>";
  html += '<div class="control-row"><label>Downtime cost ($/hour)</label><input type="number" min="0" step="100" value="' + state.recovery.costPerHour + '" onchange="onRecoveryInputChange(\'costPerHour\',this.value)" style="width:120px;"></div>';
  html += "</div>";

  html += '<div class="controls-panel"><h4>RTO targets - Mailboxes / OneDrive / SharePoint tiering (Teams unaffected)</h4>';
  html += '<div class="rt-preset-row">';
  ["Standard", "Enterprise"].forEach(function (p) {
    var activeClass = state.recovery.rtoPreset === p ? " active" : "";
    var hrs = p === "Standard" ? "4h / 24h / 72h" : "24h / 120h / 240h";
    html += '<button class="rt-preset-btn' + activeClass + '" onclick="applyRtoPreset(\'' + p + '\')">' + p + " (" + hrs + ")</button>";
  });
  html += '<span style="font-size:.78rem;color:var(--dark-gray);">Current: <b>' + esc(state.recovery.rtoPreset) + '</b></span>';
  html += "</div>";
  html += '<div class="control-row"><label>Group 1 target (hr)</label><input type="number" min="0.1" step="0.5" value="' + state.recovery.group1Hours + '" onchange="onRtoTargetChange(\'group1Hours\',this.value)" style="width:90px;"></div>';
  html += '<div class="control-row"><label>Group 2 target (hr, cumulative)</label><input type="number" min="0.1" step="0.5" value="' + state.recovery.group2Hours + '" onchange="onRtoTargetChange(\'group2Hours\',this.value)" style="width:90px;"></div>';
  html += '<div class="control-row"><label>Group 3 target (hr, cumulative)</label><input type="number" min="0.1" step="0.5" value="' + state.recovery.group3Hours + '" onchange="onRtoTargetChange(\'group3Hours\',this.value)" style="width:90px;"></div>';
  html += buildAutoSuggestBanner();
  html += "</div>";
  return html;
}

function computeAutoSuggestedPreset() {
  // Mirrors -RTOPreset Auto's server-side threshold: >= 5 days (7200 min)
  // of estimated full-tenant recovery time suggests Enterprise (24/120/240h),
  // else Standard (4/24/72h). Recomputed reactively (called from
  // buildAutoSuggestBanner every render) so it stays current as data/targets
  // change, not just once at page load.
  var model = computeRecoveryModel();
  return model.fullRestoreMin >= 7200 ? "Enterprise" : "Standard";
}

function buildAutoSuggestBanner() {
  if (state.recovery.autoBannerDismissed) { return ""; }
  var suggested = computeAutoSuggestedPreset();
  if (suggested === state.recovery.rtoPreset) { return ""; }
  var hrs = suggested === "Enterprise" ? "24h / 120h / 240h" : "4h / 24h / 72h";
  return '<div class="rt-auto-banner"><span>Based on this tenant\'s current data scale, <b>Auto</b> would suggest the <b>' + suggested + '</b> preset (' + hrs + ') - you are currently on <b>' + esc(state.recovery.rtoPreset) + '</b>.</span>' +
    '<span><button onclick="applyRtoPreset(\'' + suggested + '\')">Switch to ' + suggested + '</button> <button onclick="dismissAutoBanner()">Dismiss</button></span></div>';
}

function applyRtoPreset(preset) {
  if (preset === "Standard") { state.recovery.group1Hours = 4; state.recovery.group2Hours = 24; state.recovery.group3Hours = 72; }
  else if (preset === "Enterprise") { state.recovery.group1Hours = 24; state.recovery.group2Hours = 120; state.recovery.group3Hours = 240; }
  state.recovery.rtoPreset = preset;
  state.recovery.autoBannerDismissed = false;
  recomputeAll();
}

function dismissAutoBanner() {
  state.recovery.autoBannerDismissed = true;
  renderRecoveryTab();
}

function onRtoTargetChange(field, value) {
  // Any manual edit of an RTO input flips the state to Custom, per spec.
  state.recovery[field] = parseFloat(value);
  state.recovery.rtoPreset = "Custom";
  state.recovery.autoBannerDismissed = false;
  // RTO targets now drive the TIERING itself (not just recovery-time
  // display) for Mailboxes/OneDrive/SharePoint - use the existing
  // recompute-all trigger so a full retiering recompute runs, not a
  // parallel/inconsistent path.
  recomputeAll();
}

function onRecoveryInputChange(field, value) {
  state.recovery[field] = (field === "licenseTier") ? value : parseFloat(value);
  // licenseTier also feeds the time-budget walk (via getWorkloadRecoveryContext),
  // so this also needs a full retiering recompute, not just a recovery-tab rerender.
  recomputeAll();
}

function buildWorkloadBreakdownTable(model, tierName, sectionId) {
  var sp = DATA.workloads.sharepoint || [], od = DATA.workloads.onedrive || [], ex = DATA.workloads.mailboxes || [];
  var m = model.milestones[tierName];
  // Mass column uses THIS tier's own cumulative-scope mass time per
  // workload (massTimeMin), not a flat full-dataset constant - consistent
  // with the group-level cards above.
  var rows = [
    { label: "SharePoint", objs: m.sp.objectCount, abr: m.sp.timeMin, mass: m.sp.massTimeMin },
    { label: "OneDrive", objs: m.od.objectCount, abr: m.od.timeMin, mass: m.od.massTimeMin },
    { label: "Exchange", objs: m.ex.objectCount, abr: m.ex.timeMin, mass: m.ex.massTimeMin }
  ];
  var body = rows.map(function (r) {
    return "<tr><td>" + r.label + "</td><td>" + fmtNum(r.objs) + "</td><td>" + fmtMin(r.abr) + "</td><td>~" + fmtMin(r.mass) + "</td></tr>";
  }).join("");
  return '<div class="rt-toggle" onclick="document.getElementById(\'' + sectionId + '\').classList.toggle(\'open\')">+ Workload breakdown (SharePoint / OneDrive / Exchange)</div>' +
    '<div class="rt-detail" id="' + sectionId + '"><table><thead><tr><th>Workload</th><th>Objects (this tier)</th><th>ABR time (this tier)</th><th>Mass Recovery (that workload, this cumulative scope)</th></tr></thead><tbody>' + body + "</tbody></table></div>";
}

function renderRecoveryTab() {
  var model = computeRecoveryModel();
  var html = buildRecoveryControls();
  html += '<p class="pill-note">ABR (Autonomous Business Recovery, sequenced by group) vs. Mass Recovery (undifferentiated, no prioritization) - time and downtime cost, per group. SP/OD throughput tier: <b>' + model.spodTierBucket + '</b> (auto-selected from object counts unless overridden above). Mass Recovery has no targeting - for a given group, it means restoring that SAME cumulative set of objects (Groups 1 through this one, combined) as a single undifferentiated batch instead of in priority order, so it scales with each group\'s own size just like ABR does - it only converges with ABR\'s total once you reach the full tenant (the Total section below), because at that point there is no "batch vs. sequence" difference left: the same total data has to move through the same total throughput either way. ABR is the only approach where group size and RTO targets actually determine WHEN priority data comes back. See the Methodology tab for the full derivation.</p>';

  var targetHoursArr = [state.recovery.group1Hours, state.recovery.group2Hours, state.recovery.group3Hours];
  var groupTiers = [
    { tier: "Critical Group 1", label: "Group 1", subtitle: "Recover-first tier (target: " + state.recovery.group1Hours + " hr)" },
    { tier: "Critical Group 2", label: "Group 2", subtitle: "Cumulative through Group 2 (target: " + state.recovery.group2Hours + " hr)" },
    { tier: "Critical Group 3", label: "Group 3", subtitle: "Cumulative through Group 3 (target: " + state.recovery.group3Hours + " hr)" }
  ];

  groupTiers.forEach(function (g, idx) {
    var m = model.milestones[g.tier];
    var objCount = m.sp.objectCount + m.od.objectCount + m.ex.objectCount;
    var abrMin = m.wallClockCumMin;
    // Mass Recovery for THIS group's own cumulative scope (Groups 1..this,
    // combined into one undifferentiated batch) - scales with group size,
    // not the flat whole-tenant figure.
    var massMin = m.massRecoveryCumMin;
    var abrCost = fmtHours(abrMin) * state.recovery.costPerHour;
    var massCost = fmtHours(massMin) * state.recovery.costPerHour;
    var savingsHrs = Math.max(0, (massMin - abrMin) / 60);
    var savingsMoney = savingsHrs * state.recovery.costPerHour;

    // Empty-tier callout. Two legitimate causes as of v3.8.0: a very small
    // active population (same as before), or - new and increasingly common
    // now that Mailboxes/OneDrive/SharePoint are tiered by the budget walk
    // (assignBudgetTiers) - Group 1/2's own budgets were generous enough to
    // already absorb the entire active population, leaving a later group
    // with nothing left to place. Both read the same to the viewer: nothing
    // new at this step, figures carried forward. Badge + inline note
    // instead of an unexplained duplicate number.
    var isEmpty = objCount === 0;
    var emptyBadge = isEmpty ? ' <span class="badge empty-tier">Empty</span>' : "";
    var emptyNote = "";
    if (isEmpty) {
      emptyNote = idx === 0
        ? '<div class="rt-empty-note">No active objects fall in Group 1 at the current target (' + state.recovery.group1Hours + " hr) - either everything qualifies for a later group, or see Group 4 in the Criticality Groups tab.</div>"
        : ('<div class="rt-empty-note">No objects fall in ' + g.label + " - the figures below are carried over unchanged from the previous group (nothing new to add at this step).</div>");
    }

    // NEW v3.1.0: per-group RTO compliance flag, replacing the old "Beyond
    // Target" tier - this group's OWN ABR (hot-scope) cumulative time can
    // still run over ITS OWN target (e.g. its active/recent data is itself
    // large), flagged here in place rather than exiling the object(s)
    // responsible to a separate bucket.
    var exceedsBadge = m.exceedsTarget ? ' <span class="badge exceeds-target">Exceeds target</span>' : "";
    var exceedsNote = m.exceedsTarget
      ? ('<div class="rt-empty-note" style="background:#FDEDEE;color:#A5222B;">Exceeds the ' + g.label + " target (" + targetHoursArr[idx] + " hr) by " + fmtMin(m.targetGapMin) + " - this group's own recent/active data takes longer than the stated window to recover via ABR.</div>")
      : "";

    html += '<div class="rt-group-section' + (isEmpty ? " empty-tier" : "") + (m.exceedsTarget ? " exceeds-target" : "") + '">' +
      "<h3>" + g.label + emptyBadge + exceedsBadge + ' <span style="font-weight:400;color:var(--dark-gray);font-size:.85rem;">- ' + fmtNum(objCount) + " objects</span></h3>" +
      '<div class="rt-subtitle">' + g.subtitle + "</div>" +
      emptyNote + exceedsNote +
      '<div class="rt-compare-grid">' +
        '<div class="rt-compare-card abr"><div class="rt-label">ABR - ' + g.label + ' online in</div><div class="rt-time">' + fmtMin(abrMin) + '</div><div class="rt-cost">Downtime cost: ' + fmtMoney(abrCost) + "</div></div>" +
        '<div class="rt-compare-card mass"><div class="rt-label">Mass Recovery - expected wait</div><div class="rt-time">~' + fmtMin(massMin) + '</div><div class="rt-cost">Downtime cost: ' + fmtMoney(massCost) + "</div></div>" +
      "</div>" +
      '<div class="rt-savings-bar"><span>Downtime cost avoided with ABR</span><span>' + fmtMoney(savingsMoney) + " (" + savingsHrs.toFixed(1) + " hr sooner)</span></div>" +
      // Group 1 is the first tier - there's nothing earlier to sequence
      // against, so its own ABR time and its own cumulative-batch Mass
      // Recovery time are mathematically the same computation, and this
      // savings bar will always read $0 (0.0 hr) here. Expected, not a bug -
      // explain it inline instead of leaving it looking broken. The real
      // "what does prioritization buy you" number is on the Report tab
      // (Group 1 vs. the full undifferentiated restore) - moved there from
      // the Executive Summary in v3.5.0, see the panel-report split above.
      (idx === 0 ? '<div class="rt-total-note">Group 1 is the first tier, so there\'s nothing earlier to sequence against - its ABR time and Mass Recovery time are the same computation here by definition. See the <span class="exec-hero-linkout" onclick="switchTab(\'report\')">Report tab</span> for the comparison that shows ABR\'s actual value (Group 1 vs. a fully undifferentiated restore).</div>' : "") +
      buildWorkloadBreakdownTable(model, g.tier, "rt-detail-" + idx) +
      "</div>";
  });

  // Total section - every object, all groups plus Group 4. ABR and Mass
  // Recovery converge here by design (same total data, same total throughput
  // capacity, regardless of ordering). Group 4 itself gets no ABR timing at
  // all (per feedback 2026-07-30) - it's recovered entirely by Mass Recovery,
  // which is why it only shows up here in the whole-tenant total, never as
  // its own ABR milestone above.
  var lastTier = TIER_ORDER[TIER_ORDER.length - 1];
  var totalM = model.milestones[lastTier];
  var totalObjCount = totalM.sp.objectCount + totalM.od.objectCount + totalM.ex.objectCount;
  var totalAbrMin = totalM.wallClockCumMin;
  // Cumulative scope through the last tier (Group 4) IS the whole tenant,
  // so this should equal model.massRecoveryMin/fullRestoreMin - using the
  // same milestone field as every other group keeps this one source of truth
  // instead of a separately-tracked constant.
  var totalMassMin = totalM.massRecoveryCumMin;
  html += '<div class="rt-group-section total">' +
    '<h3>Total (whole tenant, incl. Group 4) <span style="font-weight:400;color:var(--dark-gray);font-size:.85rem;">- ' + fmtNum(totalObjCount) + " objects</span></h3>" +
    '<div class="rt-subtitle">Every object, all groups plus Group 4 (no ABR priority - Mass Recovery only) - full tenant recovery</div>' +
    '<div class="rt-compare-grid">' +
      '<div class="rt-compare-card abr"><div class="rt-label">ABR - everything online in</div><div class="rt-time">~' + fmtMin(totalAbrMin) + '</div><div class="rt-cost">Downtime cost: ' + fmtMoney(fmtHours(totalAbrMin) * state.recovery.costPerHour) + "</div></div>" +
      '<div class="rt-compare-card mass"><div class="rt-label">Mass Recovery - everything online in</div><div class="rt-time">~' + fmtMin(totalMassMin) + '</div><div class="rt-cost">Downtime cost: ' + fmtMoney(fmtHours(totalMassMin) * state.recovery.costPerHour) + "</div></div>" +
    "</div>" +
    '<div class="rt-total-note">These two numbers converge here on purpose: recovering everything takes about the same total time either way - the SAME throughput capacity has to move the SAME total data no matter what order you do it in. The entire value of ABR is in the group sections above: it determines <b>when</b> each group comes back, not how long the full job takes.</div>' +
    "</div>";

  document.getElementById("panel-recovery").innerHTML = html;
}

// NEW v3.6.0: extracted out of renderMethodologyTab() so the Full Report PDF
// (buildPrintFullHtml) can reuse the EXACT same glossary/weights text instead
// of a hand-copied duplicate that could quietly drift out of sync with the
// live Methodology tab.
function buildGlossaryHtml() {
  var html = '<dl class="glossary">';
  html += "<dt>Composite score</dt><dd>Each metric below is percentile-ranked (0-1) within its workload's dataset, then combined using the weights shown, so metrics on very different scales (item counts vs. storage bytes) don't dominate each other. Adjust any weight in the Criticality Groups tab and every score, tier, total, and recovery figure recomputes instantly.</dd>";
  html += "<dt>Tiers - all four workloads (criticality-ranked)</dt><dd>Every workload's ACTIVE population is ranked by composite score and split into thirds by the tier-split fractions (-TierSplit) - Group 1 = top third = recover first. This guarantees every group gets a population as long as there's enough active data. Through v3.0.0, Mailboxes/OneDrive/SharePoint instead used an efficiency-ranked time-budget walk (rank by score-per-minute-of-full-object-recovery-time, fill groups until an RTO budget was exceeded) - real tenant data showed this let one large object's FULL size jump the walk straight past an entire group in one step, leaving it empty. Reverted to the same criticality-ranked approach Teams always used; see RECOVERY-MODEL-METHODOLOGY.md.</dd>";
  html += "<dt>ABR recovery time (recent/active data)</dt><dd>Recovery TIME is now a separate calculation layered on top of tiering, not the thing that decides tiering. ABR recovers each object's RECENT/ACTIVE data first - estimated from real telemetry already collected (SharePoint's Active File Count, OneDrive's Viewed/Edited File Count, Mailboxes' Send+Receive volume), applied proportionally to storage - and Mass Recovery continues afterward to fully restore the remaining (older) data. This is why a large object isn't automatically slow to bring back online: its ACTIVE working set is usually a small fraction of its total size.</dd>";
  html += "<dt>Exceeds target</dt><dd>Replaces the old \"Beyond Target\" tier. Every active object is always in Group 1, 2, or 3 - what can still happen is a group's OWN ABR (recent-data) cumulative time running over ITS OWN stated RTO target (its active/recent data is itself large). Flagged in place with a red badge and the exact shortfall, rather than exiling the object(s) responsible to a separate bucket.</dd>";
  html += "<dt>RTO targets and presets</dt><dd>Group 1/2/3 targets (hours, cumulative) are a compliance check against each group's ABR cumulative time - NOT a tiering rule (see above). Standard = 4h / 24h / 72h. Enterprise = 24h / 120h / 240h (Day 1 / 5 days / 10 days). Auto suggests Standard or Enterprise based on this tenant's estimated full recovery time (&ge; 5 days / 7200 min picks Enterprise) and always tells you which it picked and why - it never silently overrides an explicit choice.</dd>";
  html += "<dt>Group 4</dt><dd>Limited activity across every metric in the reporting window - carved out before any scoring/tiering runs, for every workload. Gets no ABR timing at all and is recovered entirely by Mass Recovery, alongside the rest of the tenant. Still protected; just not on the critical path to getting the business running again.</dd>";
  html += "<dt>Manual override</dt><dd>Set via the tier dropdown on any row, or via mass-reassignment on a filtered set. Overrides always win over the computed tier and are flagged with an \"override\" badge. Use Export overrides to save them to a file and pass it back in via -OverridesFile on the next run so they persist.</dd>";
  html += "<dt>Job title weight</dt><dd>Full mode only. Job title is matched (case-insensitive substring) against a customer-editable keyword table; the highest-weighted match contributes an extra percentile-ranked factor into the composite score.</dd>";
  html += "<dt>Department hub site (heuristic)</dt><dd>SharePoint sites whose name/URL matches a department keyword (Payroll, HR, IT, etc.) AND whose page-view/active-file activity ranks in the top quartile of all SharePoint sites in this run. This is a PROXY for \"many people across the org rely on this site\" using activity data already collected - it is NOT a true unique-accessor or group-membership count, which would need additional Graph permissions not requested by default. Treat it as a nudge to double-check, not a certainty.</dd>";
  html += "<dt>Mailbox type</dt><dd>NEW v3.0.0: uses the real Exchange \"Recipient Type\" column from the mailbox usage report (already pulled in PREVIEW mode, no extra scope) as the authoritative signal (User / Shared / Room / Equipment). The old proxy - a disabled Entra account flagged as \"likely Shared/Resource\" - was validated against real customer data and caught 0 of 2 real Shared mailboxes, so it is now only a last-resort fallback for the rare case where Recipient Type comes back blank.</dd>";
  html += "<dt>Manager roll-up</dt><dd>Full mode only. Each user's manager chain (immediate manager up through the org to the top) is resolved offline from a single directory pull - no extra Graph calls. Use the \"Filter to org under manager\" box to isolate or mass-tier everyone reporting up through a given leader.</dd>";
  html += "<dt>Entra ID group filter</dt><dd>Full mode + -Groups only (requests the additional Group.Read.All scope). Each user's Entra ID group membership (Mailboxes/OneDrive) is resolved from the SAME directory pull as manager enrichment - no extra Graph call. Use the \"Filter to Entra ID group\" dropdown to isolate or mass-tier everyone in a given group; combine it with the manager filter for \"everyone in this group AND under this manager.\" Mirrors how RSC Mass Recovery groups users by AD/Entra ID Group for OneDrive/Exchange.</dd>";
  html += "<dt>Recovery time model (unchanged)</dt><dd>Reverse-engineered from the customer-provided MVC Recovery Time Estimator export. SharePoint/OneDrive throughput is capped by a size-tier lookup (auto-selected from object counts, matching the source tool's own tier boundaries); Exchange throughput uses fixed per-mailbox benchmark constants. Each tier's recovery time = MAX(items &divide; effective items/min, storage &divide; effective bytes-per-min), using a dataset-wide average item size. This formula is unchanged in v3.0.0 - what changed is which objects land in which tier (see above), not how recovery time itself is calculated.</dd>";
  html += "<dt>ABR vs. Mass Recovery</dt><dd>ABR (Autonomous Business Recovery) sequences groups - Group 1 first, then Group 2, etc. - so a milestone is reached once every workload finishes its own Groups 1..N. Mass Recovery (undifferentiated, no prioritization) has no per-group targeting; it recovers the whole workload as a single job, so the SAME full-restore figure is shown at every group on the Recovery tab for comparison. Prioritizing does not shrink the TOTAL time to recover everything (same total throughput capacity, same total data) - it changes WHEN each group comes back online, which is exactly what the downtime-cost comparison on the Recovery tab quantifies.</dd>";
  html += "<dt>Downtime cost</dt><dd>Cumulative wall-clock hours to reach a milestone, multiplied by the $/hour you set on the Recovery tab. The \"cost avoided\" figure compares ABR (that group online early) against Mass Recovery (the same undifferentiated full-restore wait, every time). Industry research from IDC, ITIC, CloudSecureTech, and others puts downtime cost at over $5,000 per minute ($300K per hour) on average, reaching $1M per hour or more for Fortune 1000 companies.</dd>";
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

// NEW: Sizing tab - ports the Exchange/OneDrive/SharePoint/Discovery Summary
// tables from the standalone Get-RubrikM365SizingInfo.ps1 sizing script,
// added per feedback 2026-08-11 so a customer can run this assessment once
// and send Rubrik both recovery metrics and sizing in a single report.
// Built ENTIRELY from data already collected for the criticality scoring
// above (StorageBytes/ItemCount/FileCount metrics, RecipientType, and the
// new HasArchive flag - all already flowing through ConvertTo-ReportRows) -
// no new Graph scope or module for the numbers below. Tenant-wide totals,
// independent of criticality tiers/weights, so this is computed once at
// bootstrap (see recomputeAll) and never re-rendered by
// recomputeTiersLive() - none of it changes when weights/sliders change.
// Archive Mailbox STORAGE and Recoverable Items (both size and count)
// require a separate Exchange Online connection and a per-mailbox loop -
// see -DetailedSizing - and show a "not collected" note until that switch
// is available. Archive Mailbox COUNT is free (same usage report) and
// always shown.
function buildSizingSummary() {
  var mbRows = (DATA.workloads.mailboxes || []);
  var odRows = (DATA.workloads.onedrive || []);
  var spRows = (DATA.workloads.sharepoint || []);

  function metric(r, f) { return (r.metrics && typeof r.metrics[f] === "number") ? r.metrics[f] : 0; }
  function sumMetric(rows, f) { return rows.reduce(function (s, r) { return s + metric(r, f); }, 0); }

  // NOTE: case-insensitive SUBSTRING match on RecipientType (not exact
  // equality) - matches Add-MailboxTypeHeuristic's own `-Regex` switch on
  // this same field, which the codebase already validated against real
  // tenant data. The standalone sizing script's original `-eq 'Shared'`
  // exact check is NOT assumed reliable here, since the field's real-world
  // values aren't guaranteed to be the bare word "Shared".
  function isSharedMailbox(r) { return /shared/i.test(r.RecipientType || ""); }
  var userMb = mbRows.filter(function (r) { return !isSharedMailbox(r); });
  var sharedMb = mbRows.filter(isSharedMailbox);
  var archiveMb = mbRows.filter(function (r) { return r.HasArchive === true; });

  var ex = {
    userCount: userMb.length,
    userStorageBytes: sumMetric(userMb, "StorageBytes"),
    userItems: sumMetric(userMb, "ItemCount"),
    sharedCount: sharedMb.length,
    sharedStorageBytes: sumMetric(sharedMb, "StorageBytes"),
    sharedItems: sumMetric(sharedMb, "ItemCount"),
    archiveCount: archiveMb.length,
    totalCount: mbRows.length,
    totalStorageBytes: sumMetric(mbRows, "StorageBytes"),
    totalItems: sumMetric(mbRows, "ItemCount")
  };
  var od = { count: odRows.length, storageBytes: sumMetric(odRows, "StorageBytes"), files: sumMetric(odRows, "FileCount") };
  var sp = { count: spRows.length, storageBytes: sumMetric(spRows, "StorageBytes"), files: sumMetric(spRows, "FileCount") };

  var totalObjects = ex.totalCount + od.count + sp.count;
  var totalStorageBytes = ex.totalStorageBytes + od.storageBytes + sp.storageBytes;
  var totalItemsFiles = ex.totalItems + od.files + sp.files;

  // License estimate mirrors the original sizing script's own logic exactly
  // (max of User Mailboxes, Shared Mailboxes, OneDrive Accounts) - not
  // "corrected" here, since the ask was to port what that script produces.
  var licenseEstimate = Math.max(ex.userCount, ex.sharedCount, od.count);

  return { ex: ex, od: od, sp: sp, totalObjects: totalObjects, totalStorageBytes: totalStorageBytes, totalItemsFiles: totalItemsFiles, licenseEstimate: licenseEstimate };
}

function buildSizingExchangeTableHtml(s) {
  var detailed = !!(DATA.meta && DATA.meta.detailedSizingRequested);
  var archiveStorageCell, archiveItemsCell, archiveAvgCell, rifRow;

  if (detailed && DATA.meta.sizing) {
    var archStorage = DATA.meta.sizing.archiveStorageBytes || 0;
    var archItems = DATA.meta.sizing.archiveItems || 0;
    archiveStorageCell = fmtGB(archStorage);
    archiveItemsCell = fmtNum(archItems);
    archiveAvgCell = s.ex.archiveCount > 0 ? fmtGB(archStorage / s.ex.archiveCount) : "0.00";
    var rifStorage = DATA.meta.sizing.recoverableItemsStorageBytes || 0;
    var rifItems = DATA.meta.sizing.recoverableItemsItems || 0;
    var rifCount = DATA.meta.sizing.recoverableItemsCount || 0;
    rifRow = "<tr><td>Recoverable Items</td><td>" + fmtNum(rifCount) + "</td><td>" + fmtGB(rifStorage) + "</td><td>" + fmtNum(rifItems) + "</td><td>" + (rifCount > 0 ? fmtGB(rifStorage / rifCount) : "0.00") + "</td></tr>";
  } else {
    // NEW: simplified to a bare "*" per skipped cell, per feedback
    // 2026-08-11 - a single footnote below the table (see renderSizingTab)
    // explains what the asterisk means, rather than repeating an inline
    // explanation in every cell/row label.
    archiveStorageCell = "*";
    archiveItemsCell = "*";
    archiveAvgCell = "*";
    rifRow = "<tr><td>Recoverable Items</td><td>*</td><td>*</td><td>*</td><td>*</td></tr>";
  }

  var totalStorageForAvg = s.ex.totalStorageBytes;
  if (detailed && DATA.meta.sizing) { totalStorageForAvg += (DATA.meta.sizing.archiveStorageBytes || 0) + (DATA.meta.sizing.recoverableItemsStorageBytes || 0); }

  var tableHtml = '<table class="exec-cost-table"><thead><tr><th>Mailbox Type</th><th>Count</th><th>Storage (GB)</th><th>Items</th><th>Avg per Mailbox (GB)</th></tr></thead><tbody>' +
    "<tr><td>User Mailboxes</td><td>" + fmtNum(s.ex.userCount) + "</td><td>" + fmtGB(s.ex.userStorageBytes) + "</td><td>" + fmtNum(s.ex.userItems) + "</td><td>" + (s.ex.userCount > 0 ? fmtGB(s.ex.userStorageBytes / s.ex.userCount) : "0.00") + "</td></tr>" +
    "<tr><td>Shared Mailboxes</td><td>" + fmtNum(s.ex.sharedCount) + "</td><td>" + fmtGB(s.ex.sharedStorageBytes) + "</td><td>" + fmtNum(s.ex.sharedItems) + "</td><td>" + (s.ex.sharedCount > 0 ? fmtGB(s.ex.sharedStorageBytes / s.ex.sharedCount) : "0.00") + "</td></tr>" +
    "<tr><td>Archive Mailboxes</td><td>" + fmtNum(s.ex.archiveCount) + "</td><td>" + archiveStorageCell + "</td><td>" + archiveItemsCell + "</td><td>" + archiveAvgCell + "</td></tr>" +
    rifRow +
    '<tr class="total-row"><td>Total</td><td>' + fmtNum(s.ex.totalCount) + "</td><td>" + fmtGB(totalStorageForAvg) + "</td><td>" + fmtNum(s.ex.totalItems) + "</td><td>" + (s.ex.totalCount > 0 ? fmtGB(totalStorageForAvg / s.ex.totalCount) : "0.00") + "</td></tr>" +
    "</tbody></table>";

  if (!detailed) {
    tableHtml += '<div class="sizing-footnote">*Note: Not collected - run script with the -DetailedSizing switch to capture Recoverable Items and In Place Archive details. Capturing In Place Archive and Recoverable Items can take time, depending on the size of the M365 subscription.</div>';
  }
  return tableHtml;
}

function renderSizingTab() {
  var s = buildSizingSummary();
  var detailed = !!(DATA.meta && DATA.meta.detailedSizingRequested);

  var html = "<h2>M365 Sizing</h2>" +
    '<p style="color:var(--dark-gray);font-size:.9rem;max-width:70ch;margin:-1rem 0 1.5rem;">Tenant-wide capacity and object counts across Exchange, OneDrive, and SharePoint - independent of the criticality groups elsewhere in this report. Pulled from the same Graph usage reports already used for this assessment; no extra permissions required for the totals below. Send this tab along with your recovery metrics for Rubrik sizing.</p>';

  html += '<div class="sizing-section"><h3>Exchange Online</h3>' + buildSizingExchangeTableHtml(s) + "</div>";

  html += '<div class="sizing-section"><h3>OneDrive</h3><table class="exec-cost-table"><thead><tr><th>Accounts</th><th>Storage (GB)</th><th>Files</th><th>Avg per Account (GB)</th></tr></thead><tbody>' +
    "<tr><td>" + fmtNum(s.od.count) + "</td><td>" + fmtGB(s.od.storageBytes) + "</td><td>" + fmtNum(s.od.files) + "</td><td>" + (s.od.count > 0 ? fmtGB(s.od.storageBytes / s.od.count) : "0.00") + "</td></tr>" +
    "</tbody></table></div>";

  html += '<div class="sizing-section"><h3>SharePoint</h3><table class="exec-cost-table"><thead><tr><th>Sites</th><th>Storage (GB)</th><th>Files</th><th>Avg per Site (GB)</th></tr></thead><tbody>' +
    "<tr><td>" + fmtNum(s.sp.count) + "</td><td>" + fmtGB(s.sp.storageBytes) + "</td><td>" + fmtNum(s.sp.files) + "</td><td>" + (s.sp.count > 0 ? fmtGB(s.sp.storageBytes / s.sp.count) : "0.00") + "</td></tr>" +
    "</tbody></table></div>";

  var perUserAvg = s.licenseEstimate > 0 ? fmtGB(s.totalStorageBytes / s.licenseEstimate) : "0.00";
  html += '<div class="sizing-section"><h3>Discovery Summary</h3><div class="sizing-discovery-grid">' +
    '<div class="sizing-discovery-cell"><div class="label">Total Users / Accounts</div><div class="value">' + fmtNum(s.licenseEstimate) + "</div></div>" +
    '<div class="sizing-discovery-cell"><div class="label">Total Storage (GB)</div><div class="value">' + fmtGB(s.totalStorageBytes) + "</div></div>" +
    '<div class="sizing-discovery-cell"><div class="label">Total Items &amp; Files</div><div class="value">' + fmtNum(s.totalItemsFiles) + "</div></div>" +
    '<div class="sizing-discovery-cell"><div class="label">Avg per User/Account (GB)</div><div class="value">' + perUserAvg + "</div></div>" +
  "</div></div>";

  document.getElementById("panel-sizing").innerHTML = html;
}

function renderMethodologyTab() {
  var html = "<h2>Methodology &amp; Glossary</h2>" + buildGlossaryHtml();
  html += '<h3 style="margin-top:2rem;font-size:1rem;color:var(--navy);">Current live weights</h3>' + buildWeightsTableHtml();
  document.getElementById("panel-methodology").innerHTML = html;
}

// ==================== NEW v3.6.0: PDF export ====================
// Per feedback 2026-07-23: two export options, both via the browser's
// native print-to-PDF (window.print(), user picks "Save as PDF" in the
// print dialog) - no new external dependency, consistent with this report's
// existing single-file/offline-first design. Both builders recompute
// straight from DATA/state/computeRecoveryModel() rather than scraping the
// live tab DOM, so the numbers can never drift from what the report shows,
// and the output is plain static markup (no buttons/dropdowns/onclick
// handlers to strip).

function buildPrintHeaderHtml(subtitle) {
  return '<div class="pr-header">' +
    '<div class="pr-eyebrow">Recovery Sequencing Assessment &ndash; ' + esc(subtitle) + '</div>' +
    '<div class="pr-title">Recovery Assessment - M365 - ' + esc(DATA.meta.customerLabel) + '</div>' +
    '<div class="pr-meta">' +
      '<span>Usage window: <b>' + esc(DATA.meta.period) + '</b></span>' +
      '<span>Sign-in lookback: <b>' + esc(DATA.meta.signInLookbackDays) + ' days</b></span>' +
      '<span>Generated: <b>' + esc(DATA.meta.generatedAt) + '</b></span>' +
      '<span>Permission mode: <b>' + esc(DATA.meta.mode) + '</b></span>' +
    "</div>" +
  "</div>";
}

// Cross-workload Dormant Data numbers - same calculation used by
// renderExecLean()/renderExecFinancialAndRecoveryTop()'s dormantHtml, kept
// in sync by construction since all three call sites compute it the same
// way (filter every workload's rows down to the last TIER_ORDER entry).
// NEW v3.10.1: takes the already-computed recovery `model` (callers all
// have one on hand) so byWorkload can carry each workload's Mass Recovery
// time alongside its Group 4 count/pct - see
// renderExecFinancialAndRecoveryTop's matching dormantByWorkload block for
// why that whole-workload total, not an isolated "just Group 4" figure, is
// the honest number here (Group 4 has no ABR priority or separate job).
function computeDormantSummary(model) {
  var MASS_RECOVERY_KEY_BY_WORKLOAD = { mailboxes: "ex", onedrive: "od", sharepoint: "sp" };
  var inactiveTierName = TIER_ORDER[TIER_ORDER.length - 1];
  var byWorkload = WORKLOAD_DEFS.map(function (wd) {
    var rows = DATA.workloads[wd.key] || [];
    var inactiveCount = rows.filter(function (r) { return r.Tier === inactiveTierName; }).length;
    var pct = rows.length > 0 ? Math.round((inactiveCount / rows.length) * 100) : 0;
    var massKey = MASS_RECOVERY_KEY_BY_WORKLOAD[wd.key];
    var massRecoveryMin = (model && massKey) ? model.perWorkloadMassRecoveryMin[massKey] : null;
    return { label: wd.label, inactiveCount: inactiveCount, total: rows.length, pct: pct, massRecoveryMin: massRecoveryMin };
  }).filter(function (d) { return d.total > 0; });
  var totalObjectsAll = byWorkload.reduce(function (s, d) { return s + d.total; }, 0);
  var totalInactiveAll = byWorkload.reduce(function (s, d) { return s + d.inactiveCount; }, 0);
  var overallPct = totalObjectsAll > 0 ? Math.round((totalInactiveAll / totalObjectsAll) * 100) : 0;
  return { byWorkload: byWorkload, totalObjectsAll: totalObjectsAll, totalInactiveAll: totalInactiveAll, overallPct: overallPct };
}

// Per-workload tier counts, one row per workload plus a grand-total row -
// backs the "Group Overview by Workload" table in both PDF modes.
function buildGroupOverviewTableHtml() {
  var html = '<table class="pr-table"><thead><tr><th>Workload</th>' +
    TIER_ORDER.map(function (t) { return '<th class="num">' + TIER_META[t].short + "</th>"; }).join("") +
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
  html += '<tr class="total-row"><td>Total</td>' +
    TIER_ORDER.map(function (t) { return '<td class="num">' + fmtNum(grandTotals[t]) + "</td>"; }).join("") +
    '<td class="num">' + fmtNum(grandTotal) + "</td></tr>";
  html += "</tbody></table>";
  return html;
}

// Static (non-toggling) version of buildWorkloadBreakdownTable() for print -
// the live report's "+" expand/collapse makes no sense on paper, so this
// always renders the table body directly.
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
  return '<table class="pr-table"><thead><tr><th>Workload</th><th class="num">Objects (this tier)</th><th class="num">ABR Time</th><th class="num">Mass Recovery Time</th></tr></thead><tbody>' + body + "</tbody></table>";
}

// Every assumption/input that feeds the recovery-time and cost numbers -
// Full Report only, per feedback 2026-07-23 ("including all the assumptions
// used to put together the estimates"). Reuses buildGlossaryHtml()/
// buildWeightsTableHtml() (shared with the live Methodology tab) so this
// can't drift out of sync with what that tab shows.
function buildAssumptionsHtml() {
  var model = computeRecoveryModel();
  var html = '<div class="pr-section-title">Assumptions &amp; Recovery Modeling Inputs</div>';
  html += '<div class="pr-subnote">Snapshot as of this export - every input below is live-adjustable in the HTML report itself (Recovery tab / Criticality Groups tab controls), so re-export after any change to keep this in sync.</div>';
  html += '<table class="pr-table"><tbody>';
  html += "<tr><td>Recovery window</td><td class=\"num\">" + state.recovery.windowDays + " days</td></tr>";
  html += "<tr><td>SP/OD throughput tier (auto-selected unless overridden)</td><td class=\"num\">" + esc(model.spodTierBucket) + " (requested: " + esc(state.recovery.licenseTier) + ")</td></tr>";
  html += "<tr><td>Downtime cost</td><td class=\"num\">" + (state.recovery.costPerHour > 0 ? fmtMoney(state.recovery.costPerHour) + "/hour" : "not set") + "</td></tr>";
  html += "<tr><td>RTO preset</td><td class=\"num\">" + esc(state.recovery.rtoPreset) + "</td></tr>";
  html += "<tr><td>Group 1 / 2 / 3 RTO targets (cumulative)</td><td class=\"num\">" + state.recovery.group1Hours + " hr / " + state.recovery.group2Hours + " hr / " + state.recovery.group3Hours + " hr</td></tr>";
  html += "<tr><td>Tier split (Group 1 / 2 / 3 thirds of active data)</td><td class=\"num\">" + state.tierSplit.map(function (f) { return Math.round(f * 100) + "%"; }).join(" / ") + "</td></tr>";
  if (state.titleWeightContribution) {
    html += "<tr><td>Job title weight contribution</td><td class=\"num\">" + state.titleWeightContribution + "</td></tr>";
  }
  if (state.hubSiteBonus) {
    html += "<tr><td>Hub site bonus</td><td class=\"num\">" + state.hubSiteBonus + "</td></tr>";
  }
  html += "</tbody></table>";

  html += '<div class="pr-section-title">SharePoint / OneDrive Throughput Tiers</div>';
  html += '<div class="pr-subnote">Parallelism-based throughput used to estimate SharePoint/OneDrive recovery time - auto-selected from this tenant\'s object counts unless overridden above. SharePoint and OneDrive each have their own per-object item rate (below); a file bigger than the ' + fmtNum(SIZE_FACTOR_BASELINE_MB) + ' MiB tenant-wide average costs proportionally more (Size Factor), rather than a separate bytes/min cap. Source: M365 MVC Recovery Time Estimator (RSC M365 Restoration Benchmark, Mar 2025 / M365 Sizing Guidance, Jan 2026).</div>';
  html += '<table class="pr-table"><thead><tr><th>Bucket</th><th class="num">Max Objects</th><th class="num">Parallelism</th><th class="num">SharePoint Items/Min</th><th class="num">OneDrive Items/Min</th></tr></thead><tbody>';
  SPOD_TIER_TABLE.forEach(function (t) {
    var maxDisplay = (t.Max === undefined || t.Max === null) ? "&infin;" : fmtNum(t.Max);
    var spIpm = t.Parallelism * SP_ITEMS_PER_MIN_PER_UNIT;
    var odIpm = t.Parallelism * OD_ITEMS_PER_MIN_PER_UNIT;
    html += "<tr><td>" + esc(t.Bucket) + "</td><td class=\"num\">" + maxDisplay + "</td><td class=\"num\">" + t.Parallelism + "</td><td class=\"num\">" + fmtNum(spIpm) + "</td><td class=\"num\">" + fmtNum(odIpm) + "</td></tr>";
  });
  html += "</tbody></table>";

  html += '<div class="pr-section-title">Exchange (Mailbox) Throughput Benchmark</div>';
  html += '<table class="pr-table"><tbody>';
  html += "<tr><td>Per-mailbox items/min</td><td class=\"num\">" + fmtNum(EX_BENCHMARK.PerMailboxItemsPerMin) + "</td></tr>";
  html += "<tr><td>Per-mailbox MB/min</td><td class=\"num\">" + fmtNum(EX_BENCHMARK.PerMailboxMBPerMin) + "</td></tr>";
  html += "<tr><td>Max parallel mailboxes</td><td class=\"num\">" + fmtNum(EX_BENCHMARK.MaxParallelMailboxes) + "</td></tr>";
  html += "<tr><td>Items/min cap (tenant-wide)</td><td class=\"num\">" + fmtNum(EX_BENCHMARK.MaxParallelMailboxes * EX_BENCHMARK.PerMailboxItemsPerMin) + "</td></tr>";
  html += "<tr><td>MB/min cap (tenant-wide)</td><td class=\"num\">" + fmtNum(EX_BENCHMARK.MaxParallelMailboxes * EX_BENCHMARK.PerMailboxMBPerMin) + "</td></tr>";
  html += "<tr><td>Overhead buffer</td><td class=\"num\">" + EX_BENCHMARK.OverheadBuffer + "x</td></tr>";
  html += "</tbody></table>";

  html += '<div class="pr-section-title">ABR Scheduling Overhead</div>';
  html += '<div class="pr-subnote">Applies to ABR recovery time only, not Mass Recovery - every object touched by a restore needs its own job, regardless of how much of it actually changed.</div>';
  html += '<table class="pr-table"><tbody>';
  html += "<tr><td>Job scheduling rate</td><td class=\"num\">" + JOB_SCHEDULING_RATE_PER_MIN.toFixed(2) + "/min (~" + (60 / JOB_SCHEDULING_RATE_PER_MIN).toFixed(1) + "s/job)</td></tr>";
  html += "<tr><td>Minimum recovery time floor</td><td class=\"num\">" + MIN_RECOVERY_MINUTES + " min</td></tr>";
  html += "</tbody></table>";

  html += '<div class="pr-section-title">Composite Score Weights</div>';
  html += '<div class="pr-subnote">Current live weights used to rank objects within each workload - see the glossary below for how these combine into a composite score.</div>';
  html += buildWeightsTableHtml();

  html += '<div class="pr-section-title">Methodology &amp; Glossary</div>';
  html += '<div class="pr-glossary">' + buildGlossaryHtml() + "</div>";

  return html;
}

// One Page Summary: the headline numbers plus enough supporting detail to
// defend them, deliberately excluding the Recovery Timeline graphic/puzzle
// narrative and the full Group 4 per-workload breakdown so it fits a
// single printed page in the common case - see Full Report for everything.
// NEW v3.7.0: dropped the "Dormant Data" hero tile here too, per feedback
// 2026-07-30 - matches renderExecLean(); Group 4 is no longer a headline
// number anywhere, just detail further down (Full Report only).
function buildPrintSummaryHtml() {
  var model = computeRecoveryModel();
  var g1 = model.milestones["Critical Group 1"];
  var g2 = model.milestones["Critical Group 2"];
  var g3 = model.milestones["Critical Group 3"];
  var fullExposureMoney = fmtHours(model.fullRestoreMin) * state.recovery.costPerHour;
  var abrCostG1 = fmtHours(g1.wallClockCumMin) * state.recovery.costPerHour;
  var savingsMoney = Math.max(0, fullExposureMoney - abrCostG1);
  var pctReduction = fullExposureMoney > 0 ? Math.round((savingsMoney / fullExposureMoney) * 100) : 0;

  var html = buildPrintHeaderHtml("One Page Summary");

  html += '<div class="pr-tiles">' +
    '<div class="pr-tile"><div class="pr-tile-label">Time to Critical Data</div><div class="pr-tile-value">' + fmtMin(g1.wallClockCumMin) + '</div><div class="pr-tile-sub">instead of ' + fmtMin(model.fullRestoreMin) + " with a traditional, random-order restore</div></div>" +
    '<div class="pr-tile"><div class="pr-tile-label">Downtime Cost Avoided</div><div class="pr-tile-value">' + (state.recovery.costPerHour > 0 ? fmtMoney(savingsMoney) : "n/a") + '</div><div class="pr-tile-sub">' + (state.recovery.costPerHour > 0 ? (pctReduction + "% reduction vs. a fully random-order restore") : "set $/hour on the Recovery tab for a dollar figure") + "</div></div>" +
  "</div>";

  html += '<div class="pr-mechanism">ABR restores recently accessed, modified, and created data first &ndash; the data people were actually working on &ndash; so the business is operational in hours, not weeks, while Mass Recovery continues restoring everything else in the background, in whatever order it happens to land.</div>';

  html += '<div class="pr-section-title">Recovery Times by Group</div>';
  html += '<table class="pr-table"><thead><tr><th>Milestone</th><th class="num">ABR Time</th><th class="num">Target</th><th>Status</th></tr></thead><tbody>';
  [
    { label: "Group 1 online", m: g1, target: state.recovery.group1Hours },
    { label: "Groups 1-2 online", m: g2, target: state.recovery.group2Hours },
    { label: "Groups 1-3 online", m: g3, target: state.recovery.group3Hours }
  ].forEach(function (row) {
    var status = row.m.exceedsTarget ? '<span class="pr-badge exceeds">Exceeds target</span>' : "Within target";
    html += "<tr><td>" + row.label + "</td><td class=\"num\">" + fmtMin(row.m.wallClockCumMin) + "</td><td class=\"num\">" + row.target + " hr</td><td>" + status + "</td></tr>";
  });
  html += '<tr class="total-row"><td>Full tenant (Mass Recovery baseline)</td><td class="num">' + fmtMin(model.fullRestoreMin) + '</td><td class="num">&mdash;</td><td>&mdash;</td></tr>';
  html += "</tbody></table>";

  if (state.recovery.costPerHour > 0 && model.fullRestoreMin > 0) {
    html += '<div class="pr-section-title">Downtime Cost Avoided by Group</div>';
    html += '<table class="pr-table"><thead><tr><th>Milestone</th><th class="num">Time</th><th class="num">Downtime Cost</th><th class="num">Cost Avoided</th><th class="num">Reduction</th></tr></thead><tbody>';
    [
      { label: "Group 1 online", m: g1 },
      { label: "Groups 1-2 online", m: g2 },
      { label: "Groups 1-3 online", m: g3 }
    ].forEach(function (row) {
      var cost = fmtHours(row.m.wallClockCumMin) * state.recovery.costPerHour;
      var avoided = Math.max(0, fullExposureMoney - cost);
      var pct = fullExposureMoney > 0 ? Math.round((avoided / fullExposureMoney) * 100) : 0;
      html += "<tr><td>" + row.label + "</td><td class=\"num\">" + fmtMin(row.m.wallClockCumMin) + "</td><td class=\"num\">" + fmtMoney(cost) + "</td><td class=\"num\">" + fmtMoney(avoided) + "</td><td class=\"num\">" + pct + "%</td></tr>";
    });
    html += '<tr class="total-row"><td>Full tenant (Mass Recovery baseline)</td><td class="num">' + fmtMin(model.fullRestoreMin) + '</td><td class="num">' + fmtMoney(fullExposureMoney) + '</td><td class="num">&mdash;</td><td class="num">&mdash;</td></tr>';
    html += "</tbody></table>";
  }

  html += '<div class="pr-section-title">Group Overview by Workload</div>';
  html += buildGroupOverviewTableHtml();

  html += '<div class="pr-footer">Recovery window: ' + state.recovery.windowDays + " days &middot; SP/OD throughput tier: " + model.spodTierBucket + " &middot; Downtime cost: " + (state.recovery.costPerHour > 0 ? fmtMoney(state.recovery.costPerHour) + "/hour" : "not set") + ". Full per-group breakdown, Group 4 detail, and every assumption behind these numbers: see the Full Report PDF export.</div>";

  return html;
}

// Full Report: everything from the Report/Recovery/Methodology tabs
// unabridged (full Recovery Timeline narrative, per-group workload
// breakdown, full Group 4 detail), plus the Assumptions section above -
// group-level detail only, per feedback 2026-07-23 (no full per-object
// tables - the live HTML report stays the source of truth for row-level
// detail).
// NEW: Sizing section for the Full Report PDF export, added per feedback
// 2026-08-11. Reuses buildSizingSummary() - the exact same numbers as the
// live Sizing tab - rendered with the print-friendly .pr-table classes
// instead of .exec-cost-table. NOT added to the One Page Summary export -
// that export is deliberately terse (see buildPrintSummaryHtml's own
// header comment) and sizing is a distinct data domain from the recovery-
// time/cost story it tells.
function buildSizingPdfHtml() {
  var s = buildSizingSummary();
  var detailed = !!(DATA.meta && DATA.meta.detailedSizingRequested);

  var html = '<div class="pr-section-title">M365 Sizing</div>';
  html += '<div class="pr-subnote">Tenant-wide capacity and object counts across Exchange, OneDrive, and SharePoint - independent of the criticality groups above.</div>';

  var archiveStorageCell, archiveItemsCell, rifRow, totalStorageForAvg = s.ex.totalStorageBytes;
  if (detailed && DATA.meta.sizing) {
    var archStorage = DATA.meta.sizing.archiveStorageBytes || 0;
    var archItems = DATA.meta.sizing.archiveItems || 0;
    archiveStorageCell = fmtGB(archStorage);
    archiveItemsCell = fmtNum(archItems);
    var rifStorage = DATA.meta.sizing.recoverableItemsStorageBytes || 0;
    var rifItems = DATA.meta.sizing.recoverableItemsItems || 0;
    var rifCount = DATA.meta.sizing.recoverableItemsCount || 0;
    rifRow = "<tr><td>Recoverable Items</td><td class=\"num\">" + fmtNum(rifCount) + "</td><td class=\"num\">" + fmtGB(rifStorage) + "</td><td class=\"num\">" + fmtNum(rifItems) + "</td></tr>";
    totalStorageForAvg += archStorage + rifStorage;
  } else {
    // NEW: simplified to a bare "*" per skipped cell, per feedback
    // 2026-08-11 - a single footnote below the table explains the asterisk,
    // rather than repeating an inline explanation in every cell.
    archiveStorageCell = "*";
    archiveItemsCell = "*";
    rifRow = "<tr><td>Recoverable Items</td><td class=\"num\">*</td><td class=\"num\">*</td><td class=\"num\">*</td></tr>";
  }

  html += '<table class="pr-table"><thead><tr><th>Mailbox Type</th><th class="num">Count</th><th class="num">Storage (GB)</th><th class="num">Items</th></tr></thead><tbody>' +
    "<tr><td>User Mailboxes</td><td class=\"num\">" + fmtNum(s.ex.userCount) + "</td><td class=\"num\">" + fmtGB(s.ex.userStorageBytes) + "</td><td class=\"num\">" + fmtNum(s.ex.userItems) + "</td></tr>" +
    "<tr><td>Shared Mailboxes</td><td class=\"num\">" + fmtNum(s.ex.sharedCount) + "</td><td class=\"num\">" + fmtGB(s.ex.sharedStorageBytes) + "</td><td class=\"num\">" + fmtNum(s.ex.sharedItems) + "</td></tr>" +
    "<tr><td>Archive Mailboxes</td><td class=\"num\">" + fmtNum(s.ex.archiveCount) + "</td><td class=\"num\">" + archiveStorageCell + "</td><td class=\"num\">" + archiveItemsCell + "</td></tr>" +
    rifRow +
    '<tr class="total-row"><td>Total</td><td class="num">' + fmtNum(s.ex.totalCount) + "</td><td class=\"num\">" + fmtGB(totalStorageForAvg) + "</td><td class=\"num\">" + fmtNum(s.ex.totalItems) + "</td></tr>" +
    "</tbody></table>";

  if (!detailed) {
    html += '<div class="pr-note">*Note: Not collected - run script with the -DetailedSizing switch to capture Recoverable Items and In Place Archive details. Capturing In Place Archive and Recoverable Items can take time, depending on the size of the M365 subscription.</div>';
  }

  html += '<table class="pr-table"><tbody>' +
    "<tr><td>OneDrive accounts</td><td class=\"num\">" + fmtNum(s.od.count) + "</td></tr>" +
    "<tr><td>OneDrive storage (GB)</td><td class=\"num\">" + fmtGB(s.od.storageBytes) + "</td></tr>" +
    "<tr><td>OneDrive files</td><td class=\"num\">" + fmtNum(s.od.files) + "</td></tr>" +
    "<tr><td>SharePoint sites</td><td class=\"num\">" + fmtNum(s.sp.count) + "</td></tr>" +
    "<tr><td>SharePoint storage (GB)</td><td class=\"num\">" + fmtGB(s.sp.storageBytes) + "</td></tr>" +
    "<tr><td>SharePoint files</td><td class=\"num\">" + fmtNum(s.sp.files) + "</td></tr>" +
    "</tbody></table>";

  html += '<div class="pr-note">Discovery Summary &ndash; Total Users/Accounts: ' + fmtNum(s.licenseEstimate) + ', Total Storage: ' + fmtGB(s.totalStorageBytes) + ' GB, Total Items &amp; Files: ' + fmtNum(s.totalItemsFiles) + '.</div>';

  return html;
}

function buildPrintFullHtml() {
  var model = computeRecoveryModel();
  var g1 = model.milestones["Critical Group 1"];
  var g2 = model.milestones["Critical Group 2"];
  var g3 = model.milestones["Critical Group 3"];
  var lastTier = TIER_ORDER[TIER_ORDER.length - 1];
  var totalM = model.milestones[lastTier];
  var fullExposureMoney = fmtHours(model.fullRestoreMin) * state.recovery.costPerHour;
  var abrCostG1 = fmtHours(g1.wallClockCumMin) * state.recovery.costPerHour;
  var savingsMoney = Math.max(0, fullExposureMoney - abrCostG1);
  var pctReduction = fullExposureMoney > 0 ? Math.round((savingsMoney / fullExposureMoney) * 100) : 0;
  var dormant = computeDormantSummary(model);

  var html = buildPrintHeaderHtml("Full Report");

  // ---- Executive headline ----
  // NEW v3.7.0: dropped the "Dormant Data" hero tile here too, per feedback
  // 2026-07-30 - Group 4 is no longer a headline number; it's covered as
  // detail further down in this same report (see the Group 4 section).
  html += '<div class="pr-tiles">' +
    '<div class="pr-tile"><div class="pr-tile-label">Time to Critical Data</div><div class="pr-tile-value">' + fmtMin(g1.wallClockCumMin) + '</div><div class="pr-tile-sub">instead of ' + fmtMin(model.fullRestoreMin) + " with a traditional, random-order restore</div></div>" +
    '<div class="pr-tile"><div class="pr-tile-label">Downtime Cost Avoided</div><div class="pr-tile-value">' + (state.recovery.costPerHour > 0 ? fmtMoney(savingsMoney) : "n/a") + '</div><div class="pr-tile-sub">' + (state.recovery.costPerHour > 0 ? (pctReduction + "% reduction vs. a fully random-order restore") : "set $/hour on the Recovery tab for a dollar figure") + "</div></div>" +
  "</div>";
  html += '<div class="pr-mechanism">ABR restores recently accessed, modified, and created data first &ndash; the data people were actually working on &ndash; so the business is operational in hours, not weeks, while Mass Recovery continues restoring everything else in the background, in whatever order it happens to land.</div>';

  html += '<div class="pr-section-title">Mass Recovery vs. ABR: Same Timescale, Different Order</div>';
  html += '<div class="pr-subnote">Mass Recovery &ndash; the industry standard, Rubrik included &ndash; restores pieces in random order: like dumping out a puzzle and gluing down whatever you grab first, nothing forms a complete, usable picture until the whole box is done, ' + fmtMin(model.fullRestoreMin) + ' here. ABR does what any puzzle solver does first &ndash; corners and edges, the pieces that actually give you something to work with &ndash; prioritizing recently accessed, modified, and created data so the business is operational in ' + fmtMin(g1.wallClockCumMin) + ".</div>";
  if (state.recovery.costPerHour > 0) {
    html += '<table class="pr-table"><thead><tr><th></th><th class="num">Time</th><th class="num">Downtime Cost</th></tr></thead><tbody>' +
      '<tr><td>Mass Recovery (no prioritization)</td><td class="num">' + fmtMin(model.fullRestoreMin) + '</td><td class="num">' + fmtMoney(fullExposureMoney) + "</td></tr>" +
      '<tr><td>ABR (Group 1 online)</td><td class="num">' + fmtMin(g1.wallClockCumMin) + '</td><td class="num">' + fmtMoney(abrCostG1) + "</td></tr>" +
      "</tbody></table>";
  }

  // ---- Recovery Times, per-group detail ----
  html += '<div class="pr-page-break"></div>';
  html += '<div class="pr-section-title">Recovery Times - Per-Group Detail</div>';
  html += '<div class="pr-subnote">ABR (sequenced by group) vs. Mass Recovery (undifferentiated, no prioritization). Mass Recovery for a given group means restoring that SAME cumulative set of objects (Groups 1 through this one) as a single undifferentiated batch - it converges with ABR only once you reach the full tenant, because at that point there is no batch-vs-sequence difference left.</div>';

  [
    { label: "Group 1", tier: "Critical Group 1", subtitle: "Recover-first tier (target: " + state.recovery.group1Hours + " hr)", m: g1 },
    { label: "Group 2", tier: "Critical Group 2", subtitle: "Cumulative through Group 2 (target: " + state.recovery.group2Hours + " hr)", m: g2 },
    { label: "Group 3", tier: "Critical Group 3", subtitle: "Cumulative through Group 3 (target: " + state.recovery.group3Hours + " hr)", m: g3 }
  ].forEach(function (g, idx) {
    var objCount = g.m.sp.objectCount + g.m.od.objectCount + g.m.ex.objectCount;
    var abrCost = fmtHours(g.m.wallClockCumMin) * state.recovery.costPerHour;
    var massCost = fmtHours(g.m.massRecoveryCumMin) * state.recovery.costPerHour;
    var savingsHrs = Math.max(0, (g.m.massRecoveryCumMin - g.m.wallClockCumMin) / 60);
    var groupSavings = savingsHrs * state.recovery.costPerHour;
    var exceedsBadge = g.m.exceedsTarget ? '<span class="pr-badge exceeds">Exceeds target</span>' : "";
    var emptyBadge = objCount === 0 ? '<span class="pr-badge empty">Empty</span>' : "";
    html += '<div class="pr-avoid-break">';
    html += "<h4 style=\"margin:.7rem 0 .1rem;font-size:.85rem;color:var(--navy);\">" + g.label + emptyBadge + exceedsBadge + " - " + fmtNum(objCount) + " objects</h4>";
    html += '<div class="pr-subnote" style="margin-top:0;">' + g.subtitle + "</div>";
    html += '<table class="pr-table"><thead><tr><th></th><th class="num">Time</th><th class="num">Downtime Cost</th></tr></thead><tbody>' +
      '<tr><td>ABR - ' + g.label + ' online in</td><td class="num">' + fmtMin(g.m.wallClockCumMin) + '</td><td class="num">' + fmtMoney(abrCost) + "</td></tr>" +
      '<tr><td>Mass Recovery - expected wait</td><td class="num">~' + fmtMin(g.m.massRecoveryCumMin) + '</td><td class="num">' + fmtMoney(massCost) + "</td></tr>" +
      "</tbody></table>";
    html += idx === 0
      ? '<div class="pr-note">Group 1 is the first tier - nothing earlier to sequence against, so its ABR time and Mass Recovery time are the same computation by definition. ABR\'s actual value shows in the Group 1 vs. full-tenant comparison above.</div>'
      : ('<div class="pr-note">Downtime cost avoided with ABR: ' + fmtMoney(groupSavings) + " (" + savingsHrs.toFixed(1) + " hr sooner).</div>");
    html += buildStaticBreakdownTableHtml(model, g.tier);
    html += "</div>";
  });

  var totalObjCount = totalM.sp.objectCount + totalM.od.objectCount + totalM.ex.objectCount;
  html += '<div class="pr-avoid-break">';
  html += "<h4 style=\"margin:.7rem 0 .1rem;font-size:.85rem;color:var(--navy);\">Total (whole tenant, incl. Group 4) - " + fmtNum(totalObjCount) + " objects</h4>";
  html += '<table class="pr-table"><thead><tr><th></th><th class="num">Time</th><th class="num">Downtime Cost</th></tr></thead><tbody>' +
    '<tr><td>ABR - everything online in</td><td class="num">~' + fmtMin(totalM.wallClockCumMin) + '</td><td class="num">' + fmtMoney(fmtHours(totalM.wallClockCumMin) * state.recovery.costPerHour) + "</td></tr>" +
    '<tr><td>Mass Recovery - everything online in</td><td class="num">~' + fmtMin(totalM.massRecoveryCumMin) + '</td><td class="num">' + fmtMoney(fmtHours(totalM.massRecoveryCumMin) * state.recovery.costPerHour) + "</td></tr>" +
    "</tbody></table>";
  html += '<div class="pr-note">These two converge here on purpose - recovering everything takes about the same total time either way (same throughput capacity, same total data). ABR\'s value is entirely in WHEN each group comes back, not the full-job duration.</div>';
  html += "</div>";

  if (state.recovery.costPerHour > 0 && model.fullRestoreMin > 0) {
    html += '<div class="pr-section-title">Downtime Cost Avoided by Group</div>';
    html += '<table class="pr-table"><thead><tr><th>Milestone</th><th class="num">Time</th><th class="num">Downtime Cost</th><th class="num">Cost Avoided</th><th class="num">Reduction</th></tr></thead><tbody>';
    [
      { label: "Group 1 online", m: g1 },
      { label: "Groups 1-2 online", m: g2 },
      { label: "Groups 1-3 online", m: g3 }
    ].forEach(function (row) {
      var cost = fmtHours(row.m.wallClockCumMin) * state.recovery.costPerHour;
      var avoided = Math.max(0, fullExposureMoney - cost);
      var pct = fullExposureMoney > 0 ? Math.round((avoided / fullExposureMoney) * 100) : 0;
      html += "<tr><td>" + row.label + "</td><td class=\"num\">" + fmtMin(row.m.wallClockCumMin) + "</td><td class=\"num\">" + fmtMoney(cost) + "</td><td class=\"num\">" + fmtMoney(avoided) + "</td><td class=\"num\">" + pct + "%</td></tr>";
    });
    html += '<tr class="total-row"><td>Full tenant (Mass Recovery baseline)</td><td class="num">' + fmtMin(model.fullRestoreMin) + '</td><td class="num">' + fmtMoney(fullExposureMoney) + '</td><td class="num">&mdash;</td><td class="num">&mdash;</td></tr>';
    html += "</tbody></table>";
  }

  // ---- Group 4 (full detail) + Group Overview ----
  html += '<div class="pr-page-break"></div>';
  html += '<div class="pr-section-title">Group 4 Detail</div>';
  if (dormant.totalObjectsAll > 0) {
    html += '<div class="pr-subnote"><b>' + dormant.overallPct + "%</b> of this tenant (" + fmtNum(dormant.totalInactiveAll) + " of " + fmtNum(dormant.totalObjectsAll) + ") falls into Group 4 - limited activity across every metric in the reporting window. Group 4 gets no ABR priority and is recovered entirely by Mass Recovery, alongside whatever else hasn't come back yet. Still protected; just not on the critical path to getting the business running again.</div>";
    html += '<table class="pr-table"><thead><tr><th>Workload</th><th class="num">Group 4</th><th class="num">Total</th><th class="num">Group 4 %</th><th class="num">Mass Recovery (whole workload)</th></tr></thead><tbody>';
    dormant.byWorkload.slice().sort(function (a, b) { return b.pct - a.pct; }).forEach(function (d) {
      var massCell = d.massRecoveryMin !== null ? fmtMin(d.massRecoveryMin) : "N/A - no independent model";
      html += "<tr><td>" + esc(d.label) + "</td><td class=\"num\">" + fmtNum(d.inactiveCount) + "</td><td class=\"num\">" + fmtNum(d.total) + "</td><td class=\"num\">" + d.pct + "%</td><td class=\"num\">" + massCell + "</td></tr>";
    });
    html += "</tbody></table>";
  }

  html += '<div class="pr-section-title">Group Overview by Workload</div>';
  html += buildGroupOverviewTableHtml();

  // ---- Assumptions & Methodology ----
  html += '<div class="pr-page-break"></div>';
  html += buildAssumptionsHtml();

  // ---- Sizing (new) ----
  html += '<div class="pr-page-break"></div>';
  html += buildSizingPdfHtml();

  html += '<div class="pr-footer">Generated by the Recovery Assessment - M365 script. Internal Rubrik SE tooling - verify before sharing externally. Every figure in this report is computed live from the embedded raw metrics; nothing is sent anywhere.</div>';

  return html;
}

function exportPdf(mode) {
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
  // Fallback: some browsers/"Save as PDF" flows don't reliably fire
  // afterprint - clear the print-mode class after a generous timeout
  // regardless, so the live report can never get stuck hidden behind it.
  setTimeout(cleanup, 20000);
  window.print();
}

function renderCompareTab() {
  if (!DATA.priorRun) { return; }
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
  }).join("") || '<tr><td colspan="5" style="text-align:center;color:var(--dark-gray);padding:2rem;">No tier changes since the prior run.</td></tr>';
  document.getElementById("panel-compare").innerHTML = '<h2>Changes Since ' + esc(DATA.priorRun.meta.generatedAt || "prior run") + "</h2>" +
    '<div class="table-wrap"><table><thead><tr><th>Workload</th><th>Object</th><th>Identifier</th><th>Previously</th><th>Now</th></tr></thead><tbody>' + rows + "</tbody></table></div>";
}
'@

#endregion

#region ---------- HTML report JS: overrides export/import, tabs, bootstrap ----------

$script:ReportJsBootstrap = @'
function recomputeAll() {
  WORKLOAD_DEFS.forEach(function (wd) { computeScoresAndTiers(wd.key); });
  renderExecLean();
  renderExecSummary();
  renderGroupsTab();
  renderRecoveryTab();
  renderMethodologyTab();
  renderSizingTab();
  renderCompareTab();
  saveOverridesToStorage();
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
        [Parameter(Mandatory)] [array]    $Data,
        [Parameter(Mandatory)] [string[]] $MetricFields
    )
    $optionalPassthrough = @('JobTitle','Department','EmployeeType','Manager','ManagerChain','Groups','GroupIds','OfficeLocation','AccountEnabled','MailboxTypeHeuristic','RecipientType','HasArchive','HubSiteCandidate','HubSiteKeywordMatch','SiteId','RootWebTemplate')
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
        [PSCustomObject]$obj
    }
    return @($rows)
}

#endregion

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
<style>__CSS__</style>
</head>
<body>
<div class="rainbow-bar"></div>
<div class="header">
  <div class="logo">__LOGO__</div>
  <div class="eyebrow">RECOVERY SEQUENCING ASSESSMENT - LIVE, ADJUSTABLE</div>
  <h1>Recovery Assessment - M365 - __CUSTOMER__</h1>
  <div class="meta">
    <span>Usage window: <b>__PERIOD__</b></span>
    <span>Generated: <b>__GENERATED__</b></span>
    <span>Permission mode: <b>__MODE__</b></span>
  </div>
</div>
<div class="tabbar">
  <button class="tab-btn active" data-tab="exec">Executive Summary</button>
  <button class="tab-btn" data-tab="report">Report</button>
  <button class="tab-btn" data-tab="groups">Criticality Groups</button>
  <button class="tab-btn" data-tab="recovery">Recovery</button>
  <button class="tab-btn" data-tab="methodology">Methodology &amp; Glossary</button>
  <button class="tab-btn" data-tab="sizing">Sizing</button>
  <button class="tab-btn" data-tab="compare" id="compare-tab-btn" style="display:none;">Changes Since Last Run</button>
  <!-- NEW v3.6.2: icon-only action toolbar, per feedback 2026-07-23 - moved
       out of the full-width text-button export-bar (previously its own row
       under the tabbar) and docked to the far right of the tabbar itself,
       via margin-left:auto on .tabbar-actions. title/aria-label carry the
       full label for hover tooltips + accessibility since the text is gone
       from the button face. -->
  <div class="tabbar-actions">
    <button class="icon-btn" onclick="exportOverrides()" title="Export overrides (for next run)" aria-label="Export overrides (for next run)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v10"/><path d="M8 9l4 4 4-4"/><path d="M4 19h16"/></svg>
    </button>
    <label class="icon-btn" style="cursor:pointer;" title="Import overrides" aria-label="Import overrides">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17V7"/><path d="M8 11l4-4 4 4"/><path d="M4 19h16"/></svg>
      <input type="file" accept=".json" style="display:none;" onchange="importOverridesFile(this)">
    </label>
    <button class="icon-btn" onclick="exportPdf('summary')" title="Export PDF: One Page Summary" aria-label="Export PDF: One Page Summary">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 2h7l4 4v16H7z"/><path d="M14 2v4h4"/><path d="M9.5 13h5"/><path d="M9.5 16.5h5"/></svg>
    </button>
    <button class="icon-btn" onclick="exportPdf('full')" title="Export PDF: Full Report" aria-label="Export PDF: Full Report">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 2h6l4 4v13H9z"/><path d="M15 2v4h4"/><path d="M5 6v16h11"/></svg>
    </button>
  </div>
</div>
<main>
  <section class="tab-panel active" data-tab-panel="exec" id="panel-exec">
    <h2>Executive Summary</h2>
    <!-- NEW v3.5.0: split out of the (now much longer) detailed content per
         feedback 2026-07-17 - the original single Executive Summary tab had
         grown too long for an exec skim. This tab is now deliberately just
         three numbers (time to critical data, downtime cost avoided, dormant
         data %) plus one sentence on the mechanism - everything else that
         used to live here (financial compare cards, recovery timeline,
         per-group recovery times, per-workload cards, totals) moved to the
         new Report tab, see panel-report below. -->
    <div id="exec-lean"></div>
  </section>
  <section class="tab-panel" data-tab-panel="report" id="panel-report">
    <h2>Report</h2>
    <p style="color:var(--dark-gray);font-size:.9rem;max-width:70ch;margin:-1rem 0 1.5rem;">Full detail behind the Executive Summary headline figures - financial comparison, recovery timeline, per-group breakdown, and per-workload totals.</p>
    <!-- NEW: reordered per the point of this whole exercise - break critical
         objects into groups to reduce recovery time. Lead with financial
         impact, then recovery times, THEN the per-workload group breakdown
         (previously the only thing on this tab). -->
    <div id="exec-financial"></div>
    <div id="exec-recovery-times"></div>
    <div id="exec-cost-table"></div>
    <h2 style="margin-top:2rem;">Group Overview</h2>
    <div class="summary-grid" id="exec-summary-cards"></div>
    <div id="exec-totals"></div>
    <!-- NEW v3.6.0: Dormant Data moved to the very bottom of the Report tab
         and collapsed by default, per feedback 2026-07-22 - see
         renderExecFinancialAndRecoveryTop's dormantHtml block. -->
    <div id="exec-dormant"></div>
  </section>
  <section class="tab-panel" data-tab-panel="groups" id="panel-groups"></section>
  <section class="tab-panel" data-tab-panel="recovery" id="panel-recovery"></section>
  <section class="tab-panel" data-tab-panel="methodology" id="panel-methodology"></section>
  <section class="tab-panel" data-tab-panel="sizing" id="panel-sizing"></section>
  <section class="tab-panel" data-tab-panel="compare" id="panel-compare"></section>
</main>
<footer>
  <p>Tiers, totals, and recovery/cost figures are a data-driven starting point computed LIVE in this page from the embedded raw metrics - adjust weights, title/hub-site keywords, or manual overrides above and everything recomputes instantly. Nothing you change here is sent anywhere; use "Export overrides" to save your adjustments and pass the file back in via -OverridesFile on the next run so they persist.</p>
  <p>Generated by the Recovery Assessment - M365 script (v3.0.0). Internal Rubrik SE tooling - verify before sharing externally.</p>
</footer>
<!-- NEW v3.6.0: PDF export target. Hidden on screen always; only shown
     during an actual print (see @media print rules) when body carries
     printing-summary/printing-full, populated on demand by exportPdf(). -->
<div id="print-root"></div>
<script type="application/json" id="report-data">__DATA_JSON__</script>
<script>__JS__</script>
</body>
</html>
'@

function New-M365HtmlReport {
    param(
        [Parameter(Mandatory)] [array]  $Mailboxes,
        [Parameter(Mandatory)] [array]  $OneDrive,
        [Parameter(Mandatory)] [array]  $SharePoint,
        [Parameter(Mandatory)] [array]  $Teams,
        [Parameter(Mandatory)] [string] $CustomerLabel,
        [Parameter(Mandatory)] [string] $Period,
        [Parameter(Mandatory)] [string] $OutFile,
        [Parameter(Mandatory)] [string] $RunId,
        [switch]    $Full,
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
        # NEW: -DetailedSizing result (Archive/Recoverable Items sizing) -
        # $null/false when not requested, in which case the Sizing tab shows
        # its "not collected" note instead of these numbers.
        [switch]    $DetailedSizingRequested,
        $Sizing = $null,
        $PriorRunData = $null
    )

    $dataObject = [ordered]@{
        meta = [ordered]@{
            runId                        = $RunId
            customerLabel                = $CustomerLabel
            period                       = $Period
            generatedAt                  = (Get-Date).ToString('dddd, MMMM d, yyyy - h:mm tt')
            mode                         = if ($Full) { if ($Groups) { 'FULL + GROUPS' } else { 'FULL' } } else { 'PREVIEW (default)' }
            groupsRequested              = [bool]$Groups
            recoveryWindowDays           = $RecoveryWindowDays
            recoveryLicenseTierRequested = $RecoveryLicenseTier
            downtimeCostPerHour          = $DowntimeCostPerHour
            spodTierTable                = $script:SPODTierTable
            exBenchmark                  = $script:EXBenchmark
            # NEW v3.10.0: M365 MVC Recovery Time Estimator constants - single
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
            # connection and a per-mailbox loop - see -DetailedSizing/
            # Get-DetailedSizingInfo. $Sizing is $null when not requested, in
            # which case the JS shows its "not collected" note instead.
            detailedSizingRequested      = [bool]$DetailedSizingRequested
            sizing                       = if ($Sizing) {
                [ordered]@{
                    archiveStorageBytes          = $Sizing.archiveStorageBytes
                    archiveItems                 = $Sizing.archiveItems
                    recoverableItemsCount        = $Sizing.recoverableItemsCount
                    recoverableItemsStorageBytes = $Sizing.recoverableItemsStorageBytes
                    recoverableItemsItems        = $Sizing.recoverableItemsItems
                }
            } else { $null }
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
        workloads = [ordered]@{
            mailboxes  = ConvertTo-ReportRows -Data $Mailboxes      -MetricFields @('SendRecvActivity','ReadActivity','Size','TotalActivity','ItemCount','StorageUsedMB','StorageBytes','SendRecvActivity7d')
            onedrive   = ConvertTo-ReportRows -Data $OneDrive       -MetricFields @('FileActivity','Storage','TotalActivity','FileCount','StorageUsedGB','StorageBytes','ViewedOrEditedCount','ViewedOrEditedCount7d')
            sharepoint = ConvertTo-ReportRows -Data $SharePoint     -MetricFields @('PageViews','ActiveFiles','Storage','TotalActivity','FileCount','StorageUsedGB','StorageBytes','ActiveFiles7d')
            teams      = ConvertTo-ReportRows -Data $Teams          -MetricFields @('ActiveUsers','ChannelMsgs','Meetings','TotalActivity','ActiveUsersCount')
        }
        priorRun = $PriorRunData
    }

    $reportDataJson = $dataObject | ConvertTo-Json -Depth 12 -Compress
    $faviconB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:RubrikBrandmarkSvg))
    $allJs = @($script:ReportJsEngine, $script:ReportJsRecovery, $script:ReportJsRenderA, $script:ReportJsRenderB, $script:ReportJsRenderC, $script:ReportJsBootstrap) -join "`n"

    $html = $script:ReportHtmlTemplate
    $html = $html.Replace('__TITLE__', (ConvertTo-SafeHtml "Recovery Assessment - M365 - $CustomerLabel"))
    $html = $html.Replace('__LOGO__', $script:RubrikLogoSvg)
    $html = $html.Replace('__CUSTOMER__', (ConvertTo-SafeHtml $CustomerLabel))
    $html = $html.Replace('__PERIOD__', (ConvertTo-SafeHtml $Period))
    $html = $html.Replace('__GENERATED__', $dataObject.meta.generatedAt)
    $html = $html.Replace('__MODE__', $dataObject.meta.mode)
    $html = $html.Replace('__FAVICON__', $faviconB64)
    $html = $html.Replace('__CSS__', $script:ReportCss)
    $html = $html.Replace('__JS__', $allJs)
    $html = $html.Replace('__DATA_JSON__', $reportDataJson)

    Set-Content -Path $OutFile -Value $html -Encoding UTF8
    return $OutFile
}

#endregion

#region ---------- Main ----------

Write-Host "=== Recovery Assessment - M365 (v3.0.0) ===" -ForegroundColor Cyan

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

# -Groups rides the SAME bulk Get-MgUser directory pull -Full already makes
# (see Get-UserEnrichmentIndex) - there is nothing to expand group membership
# onto without it, so it's a no-op (not a silent scope request) if -Full
# wasn't also passed.
if ($Groups -and -not $Full) {
    Write-Warning "-Groups requires -Full (Entra ID group membership is resolved as part of the same directory pull as manager enrichment). Ignoring -Groups this run - re-run with both -Full -Groups."
    $Groups = $false
}

if ($DetailedSizing -and -not $Full) {
    Write-Warning "-DetailedSizing requires -Full. Ignoring -DetailedSizing this run - re-run with both -Full -DetailedSizing."
    $DetailedSizing = $false
}

Assert-GraphModules -Full:$Full -Groups:$Groups -DetailedSizing:$DetailedSizing
Connect-Assessment -Full:$Full -Groups:$Groups -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint

if ($Full) {
    $groupsNote = if ($Groups) { " Entra ID group membership (Group.Read.All) is also being resolved for bulk group-based selection." } else { "" }
    $sizingNote = if ($DetailedSizing) { " -DetailedSizing is on: Archive Mailbox and Recoverable Items sizing will run last, via a separate Exchange Online connection." } else { "" }
    Write-Host "`nRunning in FULL mode - User.Read.All/Sites.Read.All requested; enrichment, title-weight scoring, mailbox-type heuristic, and exact Team-site dedupe are active.$groupsNote$sizingNote" -ForegroundColor Magenta
} else {
    Write-Host "`nRunning in PREVIEW mode (default) - Reports.Read.All only. Pass -Full for enrichment." -ForegroundColor DarkGray
}

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

$userEnrichment = @{}
if ($Full) {
    Write-Host "`n--- User profile enrichment (Full) ---" -ForegroundColor Yellow
    $userEnrichment = Get-UserEnrichmentIndex -IncludeGroups:$Groups
}

$results = @{}

# ---------------------------------------------------------------------------
# RAW COLLECTION PHASE: Mailboxes/OneDrive/Teams/SharePoint are pulled before
# any scoring/tiering, because -RTOPreset Auto needs an early, whole-tenant
# recovery-time estimate from their RAW totals to pick Standard-vs-Enterprise
# targets. Teams is still collected before SharePoint so exact Team-site
# exclusion (Full) works exactly as before.
# ---------------------------------------------------------------------------
Write-Host "`n--- Collecting raw usage data ---" -ForegroundColor Yellow
$mailboxesRaw = @(Get-MailboxCriticality -Period $Period -WorkDir $rawDir)
Write-Host ("{0,-24} {1,5} rows" -f 'Mailboxes', $mailboxesRaw.Count) -ForegroundColor Gray
$onedriveRaw = @(Get-OneDriveCriticality -Period $Period -WorkDir $rawDir)
Write-Host ("{0,-24} {1,5} rows" -f 'OneDrive', $onedriveRaw.Count) -ForegroundColor Gray

$teams = @(Get-TeamsCriticality -Period $Period -WorkDir $rawDir)
Write-Host ("{0,-24} {1,5} rows" -f 'Teams', $teams.Count) -ForegroundColor Gray

$exactTeamSiteUrls = $null
if ($Full) {
    Write-Host "Resolving exact Team SharePoint sites (Full)..." -ForegroundColor Gray
    $exactTeamSiteUrls = Get-ExactTeamSiteUrls -Teams $teams
}

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
# throughput tier and 0-7 day window scaling. See RECOVERY-MODEL-METHODOLOGY.md.
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
# (-TierSplit). See RECOVERY-MODEL-METHODOLOGY.md.
# ---------------------------------------------------------------------------

Write-Host "`n--- Mailboxes ---" -ForegroundColor Yellow
$mailboxes = $mailboxesRaw
if ($Full) {
    $mailboxes = @(Add-UserEnrichment -Data $mailboxes -EnrichmentIndex $userEnrichment -UpnField 'Identifier')
    $mailboxes = @(Add-TitleWeightScore -Data $mailboxes -TitleWeights $TitleWeights)
    $MailboxWeights = $MailboxWeights + @{ TitleWeight = $TitleWeightContribution }
}
# Recipient Type (authoritative, from the mailbox usage report) runs
# regardless of -Full; the AccountEnabled fallback inside only has data
# to fall back to when -Full enrichment ran above.
$mailboxes = @(Add-MailboxTypeHeuristic -Data $mailboxes)
$mailboxes = @(Add-RecentDataEstimate -Data $mailboxes -TotalItemField 'ItemCount' -TotalStorageField 'StorageUsedMB' -RecentItemField 'SendRecvActivity7d')
$mailboxes = @(Add-CompositeScore -Data $mailboxes -MetricWeights $MailboxWeights)
$mailboxes = @(Add-CriteriaTags -Data $mailboxes -MetricWeights $MailboxWeights)
$mailboxItemTotal = Get-FieldSum $mailboxes 'ItemCount'
$mailboxAvgItemSize = if ($mailboxItemTotal -gt 0) { (Get-FieldSum $mailboxes 'StorageUsedMB') / $mailboxItemTotal } else { 0 }
$mailboxes = @(Add-BudgetTier -Data $mailboxes -InactiveCheckField 'TotalActivity' -AvgItemSize $mailboxAvgItemSize -SPODTier $null -WorkloadType 'EX' -TargetsMin $targetsMin -WindowFactor $tierWindowFactor)
$mailboxes = @(Add-Overrides -Data $mailboxes -OverridesIndex $overridesIndex -Workload 'mailboxes')
$results['Mailboxes'] = Export-WorkloadResult -Data $mailboxes -Name 'Mailboxes' -OutDir $OutputPath

Write-Host "`n--- OneDrive ---" -ForegroundColor Yellow
$onedrive = $onedriveRaw
if ($Full) {
    $onedrive = @(Add-UserEnrichment -Data $onedrive -EnrichmentIndex $userEnrichment -UpnField 'OwnerUpn')
    $onedrive = @(Add-TitleWeightScore -Data $onedrive -TitleWeights $TitleWeights)
    $OneDriveWeights = $OneDriveWeights + @{ TitleWeight = $TitleWeightContribution }
}
$onedrive = @(Add-RecentDataEstimate -Data $onedrive -TotalItemField 'FileCount' -TotalStorageField 'StorageBytes' -RecentItemField 'ViewedOrEditedCount7d')
$onedrive = @(Add-CompositeScore -Data $onedrive -MetricWeights $OneDriveWeights)
$onedrive = @(Add-CriteriaTags -Data $onedrive -MetricWeights $OneDriveWeights)
$onedriveItemTotal = Get-FieldSum $onedrive 'FileCount'
$onedriveAvgItemSize = if ($onedriveItemTotal -gt 0) { (Get-FieldSum $onedrive 'StorageBytes') / $onedriveItemTotal } else { 0 }
$onedrive = @(Add-BudgetTier -Data $onedrive -InactiveCheckField 'TotalActivity' -AvgItemSize $onedriveAvgItemSize -SPODTier $tierSpodTier -WorkloadType 'OD' -TargetsMin $targetsMin -WindowFactor $tierWindowFactor)
$onedrive = @(Add-Overrides -Data $onedrive -OverridesIndex $overridesIndex -Workload 'onedrive')
$results['OneDrive'] = Export-WorkloadResult -Data $onedrive -Name 'OneDrive' -OutDir $OutputPath

Write-Host "`n--- Teams ---" -ForegroundColor Yellow
$teams = @(Add-CompositeScore -Data $teams -MetricWeights $TeamsWeights)
$teams = @(Add-CriteriaTags -Data $teams -MetricWeights $TeamsWeights)
$teams = @(Add-Tier -Data $teams -TierSplit $TierSplit -InactiveCheckField 'TotalActivity')
$teams = @(Add-Overrides -Data $teams -OverridesIndex $overridesIndex -Workload 'teams')
$results['Teams'] = Export-WorkloadResult -Data $teams -Name 'Teams' -OutDir $OutputPath

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
$results['SharePoint'] = Export-WorkloadResult -Data $sharepoint -Name 'SharePointSites' -OutDir $OutputPath
if ($sharepointExcluded.Count -gt 0) {
    $excludedPath = Join-Path $OutputPath 'SharePointSites_Excluded.csv'
    $sharepointExcluded | Export-Csv -Path $excludedPath -NoTypeInformation -Encoding UTF8
    Write-Host ("{0,-24} {1,5} objects  ->  {2}" -f 'SharePoint (excluded)', $sharepointExcluded.Count, $excludedPath) -ForegroundColor DarkGray
}

# Master rollup
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

# Recovery model - computed here too (console/manifest visibility); the HTML report
# recomputes its own copy live in JS so it stays in sync with any weight/override changes.
Write-Host "`n--- Recovery time modeling ---" -ForegroundColor Yellow
$recoveryModel = Build-RecoveryModel -SharePoint $sharepoint -OneDrive $onedrive -Mailboxes $mailboxes -RecoveryLicenseTier $RecoveryLicenseTier -TargetsMin $targetsMin -RecoveryWindowDays $RecoveryWindowDays
$group1CumMin = $recoveryModel.Milestones['Critical Group 1'].WallClockCumulativeMin
Write-Host ("SP/OD throughput tier: {0}" -f $recoveryModel.Meta.SPODTierBucket) -ForegroundColor Gray
Write-Host ("Group 1 online in:     {0:N1} min ({1:N1} hr)  [ABR, recent/active data]" -f $group1CumMin, ($group1CumMin/60)) -ForegroundColor Gray
Write-Host ("Full restore (all):    {0:N1} min ({1:N1} hr)  [Mass Recovery, full data]" -f $recoveryModel.FullRestoreUnprioritizedMin, ($recoveryModel.FullRestoreUnprioritizedMin/60)) -ForegroundColor Gray
foreach ($tn in @('Critical Group 1','Critical Group 2','Critical Group 3')) {
    $m = $recoveryModel.Milestones[$tn]
    if ($m.ExceedsTarget) {
        Write-Host ("$tn exceeds its RTO target by: {0:N1} hr ({1:N1} days)" -f ($m.TargetGapMin/60), ($m.TargetGapMin/1440)) -ForegroundColor Yellow
    }
}
if ($DowntimeCostPerHour -gt 0) {
    $savedHrs = [math]::Max(0, ($recoveryModel.FullRestoreUnprioritizedMin - $group1CumMin) / 60)
    Write-Host ("Downtime cost avoided (Group 1 online early): {0:C0}" -f ($savedHrs * $DowntimeCostPerHour)) -ForegroundColor Gray
}

$runId = [guid]::NewGuid().ToString('N').Substring(0,12)

# NEW: -DetailedSizing runs LAST, after every Graph-based collection/export
# above has already succeeded and been written to disk - this is the
# slowest, most timeout-prone part of the whole run (a separate Exchange
# Online connection plus a per-mailbox loop over every active mailbox), so
# it never puts the core recovery assessment at risk if it fails or times
# out partway through.
$detailedSizingResult = $null
if ($DetailedSizing) {
    try {
        $detailedSizingResult = Get-DetailedSizingInfo -Mailboxes $mailboxes -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint
    } catch {
        Write-Warning "-DetailedSizing failed: $($_.Exception.Message). Continuing without Archive/Recoverable Items sizing - the rest of the report is unaffected."
        $detailedSizingResult = $null
    }
}

$htmlReportPath = $null
if (-not $SkipHtmlReport) {
    Write-Host "`n--- HTML report ---" -ForegroundColor Yellow
    $resolvedCustomerLabel = if ($CustomerName) {
        $CustomerName
    } else {
        $acct = (Get-MgContext).Account
        if ($acct -and $acct.Contains('@')) { $acct.Split('@')[1] } else { 'Customer Tenant' }
    }
    $htmlReportPath = New-M365HtmlReport -Mailboxes $mailboxes -OneDrive $onedrive -SharePoint $sharepoint -Teams $teams `
        -CustomerLabel $resolvedCustomerLabel -Period $Period -RunId $runId -Full:$Full -Groups:$Groups `
        -MailboxWeights $MailboxWeights -OneDriveWeights $OneDriveWeights -SharePointWeights $SharePointWeights -TeamsWeights $TeamsWeights `
        -TierSplit $TierSplit -TitleWeights $TitleWeights -TitleWeightContribution $TitleWeightContribution -HubSiteKeywords $HubSiteKeywords -HubSiteBonus $HubSiteBonus `
        -RecoveryWindowDays $RecoveryWindowDays -RecoveryLicenseTier $RecoveryLicenseTier -DowntimeCostPerHour $DowntimeCostPerHour -PriorRunData $priorRunData `
        -Group1TargetHours $Group1TargetHours -Group2TargetHours $Group2TargetHours -Group3TargetHours $Group3TargetHours -RTOPresetResolved $resolvedPresetLabel -RTOPresetReason $presetReason `
        -DetailedSizingRequested:$DetailedSizing -Sizing $detailedSizingResult `
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
    $reportDataForCompare | ConvertTo-Json -Depth 12 -Compress | Set-Content -Path (Join-Path $OutputPath '_ReportData.json') -Encoding UTF8
    Write-Host "HTML report              ->  $htmlReportPath" -ForegroundColor Gray
}

$manifest = @"
Recovery Assessment - M365 - Run Manifest (v3.0.0)
Run time (UTC):        $((Get-Date).ToUniversalTime())
Usage report period:   $Period
Tier split (Teams only): $($TierSplit -join ' / ')
Permission mode:       $(if ($Full) { if ($Groups) { 'FULL + GROUPS' } else { 'FULL' } } else { 'PREVIEW (default)' })
Graph scopes used:     $(if ($Full) { if ($Groups) { 'Reports.Read.All, User.Read.All, Sites.Read.All, Group.Read.All' } else { 'Reports.Read.All, User.Read.All, Sites.Read.All' } } else { 'Reports.Read.All' })
Detailed sizing:       $(if ($DetailedSizing) { 'Requested (Exchange Online - Archive/Recoverable Items sizing included)' } else { 'Not requested (Sizing tab shows Exchange/OneDrive/SharePoint totals + Archive count only)' })
Signed in as:          $((Get-MgContext).Account)
Overrides file used:   $(if ($OverridesFile) { $OverridesFile } else { '(none)' })
Compared against:      $(if ($CompareTo) { $CompareTo } else { '(none)' })

Tiering: all four workloads ranked by composite score and split by -TierSplit
($($TierSplit -join ' / ')) - Group 1 = top tier = recover first.

RTO targets (compliance check against ABR recovery time - Mailboxes/OneDrive/SharePoint only):
  Preset resolved:       $resolvedPresetLabel
  Reason:                $presetReason
  Group 1 target:        $Group1TargetHours hr
  Group 2 target:        $Group2TargetHours hr (cumulative)
  Group 3 target:        $Group3TargetHours hr (cumulative)
$(( @('Critical Group 1','Critical Group 2','Critical Group 3') | ForEach-Object { $m = $recoveryModel.Milestones[$_]; if ($m.ExceedsTarget) { "  $_ exceeds its target by: $([math]::Round($m.TargetGapMin/60,1)) hr" } } ) -join "`n")
Row counts by workload:
  Mailboxes:               $($mailboxes.Count)
  OneDrive accounts:       $($onedrive.Count)
  SharePoint sites:        $($sharepoint.Count)  (excluded as OneDrive/Team: $($sharepointExcluded.Count))
  Teams:                   $($teams.Count)
$(if ($Full) { "`nFull-mode enrichment:`n  Users profile-enriched: $($userEnrichment.Count)`n  Team sites exactly resolved: $($exactTeamSiteUrls.Count) of $($teams.Count)$(if ($Groups) { "`n  Users with >=1 Entra ID group resolved: $((@($userEnrichment.Values) | Where-Object { $_.Groups -and $_.Groups.Count -gt 0 }).Count) of $($userEnrichment.Count)" })" })

Recovery model (Preview weights/tiers as computed at run time - the HTML report recomputes live):
  SP/OD throughput tier:  $($recoveryModel.Meta.SPODTierBucket)
  Group 1 online in:      $([math]::Round($group1CumMin,1)) min ($([math]::Round($group1CumMin/60,1)) hr)  [ABR, recent/active data]
  Full restore (all):     $([math]::Round($recoveryModel.FullRestoreUnprioritizedMin,1)) min ($([math]::Round($recoveryModel.FullRestoreUnprioritizedMin/60,1)) hr)  [Mass Recovery, full data]

Reminder: tiers are a starting point. The HTML report's tier dropdowns, mass-reassignment,
weight/keyword controls, and RTO target inputs exist specifically so the customer can
correct anything the data can't see - export overrides and pass them back in via
-OverridesFile next time.
"@
Set-Content -Path (Join-Path $OutputPath '_RunManifest.txt') -Value $manifest -Encoding UTF8

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host "Per-workload CSVs, _MasterSummary.csv, _ReportData.json, and _RunManifest.txt written to: $OutputPath" -ForegroundColor Green
if ($htmlReportPath) { Write-Host "Open the HTML report:      $htmlReportPath" -ForegroundColor Green }
Write-Host "Enterprise App setup guide: $(Join-Path $OutputPath 'EnterpriseApp-Setup-Guide.md')" -ForegroundColor Green

$masterRows | Group-Object Workload, Tier | Sort-Object Name | Format-Table @{L='Workload / Tier';E={$_.Name}}, Count -AutoSize

Disconnect-MgGraph | Out-Null

#endregion

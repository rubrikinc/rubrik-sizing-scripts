param (
    [Parameter(Mandatory=$true)]
    [string] $personalAccessToken
)

$base64AuthInfo = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($personalAccessToken)"))
$headers = @{Authorization = ("Basic {0}" -f $base64AuthInfo)}

function Get-OrgSizing {
    param (
        [string] $organisation,
        [hashtable] $headers
    )

    $result = @{
        Organisation  = $organisation
        GitRepoCount  = 0
        TfvcRepoCount = 0
        TotalSizeMB   = 0
        HasAdminAccess = $false
        AdminCheckNote = $null
        Error         = $null
    }

    # Probe an admin-only endpoint (audit log) to detect whether this PAT
    # has Project Collection Admin-equivalent visibility. A 403 means the
    # ACL-filtered list endpoints below are likely undercounting.
    try {
        Invoke-RestMethod -Uri "https://auditservice.dev.azure.com/$organisation/_apis/audit/auditlog?api-version=6.0-preview.1" -Method Get -Headers $headers | Out-Null
        $result.HasAdminAccess = $true
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -eq 401 -or $statusCode -eq 403) {
            $result.AdminCheckNote = "Audit log access denied (HTTP $statusCode) — PAT lacks collection-admin visibility; totals likely undercounted."
        }
        else {
            $result.AdminCheckNote = "Admin probe inconclusive: $($_.Exception.Message)"
        }
    }

    try {
        $projects = (Invoke-RestMethod -Uri "https://dev.azure.com/$organisation/_apis/projects?api-version=6.0" -Method Get -Headers $headers).value
        $projectNames = $projects.name

        $AllSourceRepos = (Invoke-RestMethod -Uri "https://dev.azure.com/$organisation/_apis/git/repositories?api-version=6.0" -Method Get -Headers $headers).value
        $result.GitRepoCount = $AllSourceRepos.Count

        [int]$incre = 0
        $projectNames | ForEach-Object {
            $project = $_
            try {
                $tfvc = Invoke-RestMethod -Uri "https://dev.azure.com/$organisation/$project/_apis/tfvc/items?api-version=6.0" -Method Get -Headers $headers
                if ($tfvc.value[0].Path -like "*$/*") {
                    $incre++
                }
            }
            catch {
                # No TFVC items for this project
            }
        }
        $result.TfvcRepoCount = $incre

        $totalMB = 0
        $AllSourceRepos | ForEach-Object {
            $repoName = $_.name
            try {
                $repo = Invoke-RestMethod -Uri "$($_.url)?api-version=4.1" -Method Get -Headers $headers
                $totalMB += $repo.size / 1MB
            }
            catch {
                Write-Host "  Could not add in size for repo $repoName in org $organisation"
            }
        }
        $result.TotalSizeMB = $totalMB
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# Discover all orgs the PAT has access to
Write-Host "Discovering organisations accessible by this PAT..."
$profile = Invoke-RestMethod -Uri "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=6.0" -Method Get -Headers $headers
$memberId = $profile.publicAlias

$accounts = (Invoke-RestMethod -Uri "https://app.vssps.visualstudio.com/_apis/accounts?memberId=$memberId&api-version=6.0" -Method Get -Headers $headers).value
$orgNames = $accounts.accountName | Sort-Object

Write-Host "Found $($orgNames.Count) organisation(s): $($orgNames -join ', ')"
Write-Host ""

$allResults = @()
foreach ($org in $orgNames) {
    Write-Host "Processing organisation: $org"
    $orgResult = Get-OrgSizing -organisation $org -headers $headers
    $allResults += $orgResult

    if ($orgResult.Error) {
        Write-Host "  ERROR: $($orgResult.Error)"
    }
    else {
        Write-Host "  GIT repos: $($orgResult.GitRepoCount), TFVC repos: $($orgResult.TfvcRepoCount), Size: $([math]::Round($orgResult.TotalSizeMB, 2)) MB"
    }
    if ($orgResult.HasAdminAccess) {
        Write-Host "  Admin visibility: OK"
    }
    else {
        Write-Host "  WARNING: $($orgResult.AdminCheckNote)"
    }
}

Write-Host ""
Write-Host "===================== Per-Organisation Summary ====================="
$allResults | ForEach-Object {
    $adminFlag = if ($_.HasAdminAccess) { "[admin]" } else { "[LIMITED]" }
    if ($_.Error) {
        Write-Host ("{0,-40} {1,-9} ERROR: {2}" -f $_.Organisation, $adminFlag, $_.Error)
    }
    else {
        Write-Host ("{0,-40} {1,-9} GIT: {2,-6} TFVC: {3,-6} Size: {4,10:N2} MB" -f $_.Organisation, $adminFlag, $_.GitRepoCount, $_.TfvcRepoCount, $_.TotalSizeMB)
    }
}

$limitedOrgs = $allResults | Where-Object { -not $_.HasAdminAccess }
if ($limitedOrgs.Count -gt 0) {
    Write-Host ""
    Write-Host "WARNING: $($limitedOrgs.Count) organisation(s) lack collection-admin visibility."
    Write-Host "         The list APIs (projects, repositories) are ACL-filtered server-side,"
    Write-Host "         so totals for these orgs may be undercounted:"
    $limitedOrgs | ForEach-Object {
        Write-Host "           - $($_.Organisation): $($_.AdminCheckNote)"
    }
}

$totalGit  = ($allResults | Measure-Object -Property GitRepoCount  -Sum).Sum
$totalTfvc = ($allResults | Measure-Object -Property TfvcRepoCount -Sum).Sum
$totalMB   = ($allResults | Measure-Object -Property TotalSizeMB   -Sum).Sum

Write-Host ""
Write-Host "============================== TOTAL =============================="
Write-Host "Organisations: $($allResults.Count)"
Write-Host "Total GIT repos:  $totalGit"
Write-Host "Total TFVC repos: $totalTfvc"
Write-Host "Total git size:   $([math]::Round($totalMB, 2)) MB"

<#
.SYNOPSIS
    This script is a Rubrik utility for counting human identities in a customer's Active Directory (AD) environment. The data collected is used for licensing Rubrik's products. The script identifies and categorizes all user and service accounts to determine the number of unique human users.

.DESCRIPTION
    The Get-AdHumanIdentity.ps1 script is a specialized tool for Rubrik's customers to generate a report of their Active Directory identities for licensing purposes. The script connects to the customer's AD environment to query for user and service accounts, and then categorizes them to accurately count the number of human identities.

    The primary goal of this script is to provide an accurate count of human users to ensure fair and accurate licensing of Rubrik's products. The script distinguishes between human users and non-human accounts (e.g., service accounts) to avoid over-licensing.

    The script gathers the following information to assist in the identity counting process:
    - **Account Activity**: Determines if accounts are active, inactive, or have never been used, based on their last logon timestamp. This helps in excluding dormant accounts from the count of active users.
    - **Service Account Types**: Identifies various types of non-human accounts, including:
        - Managed Service Accounts (MSAs)
        - Group Managed Service Accounts (gMSAs)
        - Accounts with passwords set to never expire.
        - Accounts matching specific naming patterns (e.g., "svc_*").
    - **Reporting Granularity**: Offers two levels of reporting to provide flexibility in how the data is presented:
        - **UserPerOU**: A detailed report with counts broken down by each Organizational Unit (OU).
        - **Summary**: A high-level report with aggregated counts for each domain.

    The script generates a CSV report that can be shared with Rubrik for licensing purposes.

.PARAMETER SpecificDomains
    This is an optional parameter that allows you to specify which Active Directory domains to audit. If you do not use this parameter, the script will automatically discover and audit all domains in the current AD forest.

    To use this parameter, provide a list of fully qualified domain names (FQDNs).
    Example: -SpecificDomains "corp.example.com", "dev.example.com"

.PARAMETER UserServiceAccountNamesLike
    This is an optional parameter that allows you to identify service accounts based on their names. You can provide a list of wildcard patterns, and any user account with a name matching one of these patterns will be flagged as a service account in the report.

    This is useful for identifying service accounts that are not formally registered as MSAs or gMSAs.
    Example: -UserServiceAccountNamesLike "*svc*", "*_bot", "testuser*"

.PARAMETER Mode
    This is a required parameter that controls the level of detail in the final report. You must choose one of the following two modes:
    - 'UserPerOU': This mode provides a very detailed report, with a separate entry for each Organizational Unit (OU). This is the recommended mode for a granular analysis.
    - 'Summary': This mode provides a high-level overview, with a single entry for each domain, showing the total counts for all account types.

    The default value is 'UserPerOU'.

.EXAMPLE
    Example 1: Perform a detailed audit of the entire forest and identify service accounts by name.

    .\Get-AdHumanIdentity.ps1 -UserServiceAccountNamesLike "*svc*", "*_app" -Mode UserPerOU

    This command will:
    - Scan all domains in the current AD forest.
    - Flag any user account with a name containing "svc" or "_app" as a service account.
    - Generate a detailed report with account counts for each OU.
    - Save the report to a CSV file in the .\ADReports directory.

.EXAMPLE
    Example 2: Perform a summary audit of a single, specific domain.

    .\Get-AdHumanIdentity.ps1 -SpecificDomains "corp.example.com" -Mode Summary

    This command will:
    - Connect only to the "corp.example.com" domain.
    - Generate a high-level summary report for that domain.
    - Save the report to a CSV file in the .\ADReports directory.

.NOTES
    - **Prerequisites**: The computer running this script must have the Active Directory module for PowerShell installed. This is part of the Remote Server Administration Tools (RSAT).
    - **Permissions**: The user account running this script must have read permissions for user and service account objects in the target Active Directory domains.
    - **Execution Policy**: You may need to adjust the PowerShell execution policy to run this script. You can do this by running "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process".
    - **Culture Settings**: The script temporarily sets the culture to 'en-US' to ensure that dates and times are parsed correctly. This change is reverted at the end of the script.
#>


param (
    [string[]]$UserServiceAccountNamesLike = @(),
    [string[]]$SpecificDomains,
    [ValidateSet("UserPerOU", "Summary")]
    [string]$Mode = "UserPerOU"
)

# === Logging Setup ===
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = ".\ADReports"
if (-not (Test-Path $outputPath)) { New-Item -Path $outputPath -ItemType Directory | Out-Null }

$logPath = Join-Path $outputPath "AD_Audit_$timestamp.log"
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $formatted = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logPath -Value $formatted
    Write-Host $Message
}

function Initialize-Prerequisites {
    $requiredPSVersion = [Version]"5.1"
    $moduleName = "ActiveDirectory"

    if ($PSVersionTable.PSVersion -lt $requiredPSVersion) {
        Write-Log "PowerShell $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)"
        exit
    }

    try {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Log "Required module '$moduleName' not found. Please install RSAT: Active Directory Tools."
            exit
        }
        Import-Module $moduleName -ErrorAction Stop
    } catch {
        Write-Log "Failed to import '$moduleName'. Ensure it's installed and accessible. $_"
        exit
    }

    # Culture preservation
    $script:OriginalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $script:OriginalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture

    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Write-Log "Prerequisites validated. Environment initialized." -ForegroundColor Green
}

Initialize-Prerequisites

# =====================
# Helper Functions
# =====================

function Get-OUFromDN {
    param ([string]$dn)
    ($dn -split '(?<!\\),')[1..($dn.Count - 1)] -join ','
}

function Test-ManagedServiceAccount {
    param ([string]$SamAccountName, [string[]]$MSASet)
    return $MSASet -contains $SamAccountName
}

function Test-GroupManagedServiceAccount {
    param ([string]$SamAccountName, [string[]]$GMSASet)
    return $GMSASet -contains $SamAccountName
}

function Test-NonExpiringUser {
    param ([string]$SamAccountName, [string[]]$NoExpireSet)
    return $NoExpireSet -contains $SamAccountName
}

function Test-PatternMatchedUser {
    param ([string]$SamAccountName, [string[]]$PatternSet)
    return $PatternSet -contains $SamAccountName
}

function Get-UsersAsServiceAccount {
    param (
        [string[]]$NamePatterns,
        [string]$Domain
    )

    if (-not $NamePatterns -or $NamePatterns.Count -eq 0) {
        return @()  # nothing to do
    }

    $subs = @()
    foreach ($pattern in $NamePatterns) {
        Write-Log "[$Domain] Searching for users like '$pattern'..." -ForegroundColor Yellow
        try {
            $usersFound = Get-ADUser -Server $Domain -Filter "Name -like '$($pattern.Trim())'" `
                -Properties Name, SamAccountName, DistinguishedName, Enabled, LastLogonTimestamp, PasswordNeverExpires, ServicePrincipalName |
                Select-Object Name, SamAccountName, DistinguishedName, Enabled,
                              @{Name="LastLogonDate";Expression={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},
                              PasswordNeverExpires,
                              @{Name="ServicePrincipalNames";Expression={($_.ServicePrincipalName -join ";")}}

            $subs += $usersFound
        } catch {
            Write-Warning "[$Domain] Error searching pattern '$pattern': $_"
        }
    }
    return $subs
}

# =====================
# Main Logic
# =====================

$logonThreshold = (Get-Date).AddDays(-180)
$summary = @()

$domainsToAudit = if ($SpecificDomains) {
    $SpecificDomains
} else {
    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains | ForEach-Object { $_.Name }
}

foreach ($domain in $domainsToAudit) {
    Write-Log "Auditing domain: $domain" -ForegroundColor Cyan

    try {
        # Preload reference data
        $MSASet = Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-ManagedServiceAccount' } |
                  Select-Object -ExpandProperty SamAccountName
        $GMSASet = Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' } |
                   Select-Object -ExpandProperty SamAccountName
        $NoExpireSet = Get-ADUser -Server $domain -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } |
                       Select-Object -ExpandProperty SamAccountName

        # 🔍 Get pattern-matched service accounts
        $PatternMatches = Get-UsersAsServiceAccount -NamePatterns $UserServiceAccountNamesLike -Domain $domain
        $PatternSet = $PatternMatches.SamAccountName | Sort-Object -Unique

        # 🧾 Get users
        $userAccounts = Get-ADUser -Server $domain -Filter { Enabled -eq $true } `
            -Properties SamAccountName, DistinguishedName, LastLogonTimestamp

        $msaObjects  = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-ManagedServiceAccount' })
        $gmsaObjects = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' })

        $serviceAccounts = $msaObjects + $gmsaObjects | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName     = $_.SamAccountName
                DistinguishedName  = $_.DistinguishedName
                LastLogonTimestamp = $_.LastLogonTimestamp
            }
        }

        $users = $userAccounts + $serviceAccounts

        foreach ($user in $users) {
            $sam = $user.SamAccountName
            $ou  = Get-OUFromDN $user.DistinguishedName

            $entry = $summary | Where-Object { $_.Domain -eq $domain -and $_.OU -eq $ou }
            if (-not $entry) {
                $entry = [PSCustomObject]@{
                    Domain                              = $domain
                    OU                                  = $ou
                    TotalUsers                          = 0
                    ActiveUsers                         = 0
                    InactiveUsers                       = 0
                    NeverLoggedInUsers                  = 0
                    ServiceAccountsManaged              = 0
                    ServiceAccountsGroupManaged         = 0
                    ServiceAccountsPasswordNeverExpires = 0
                    ServiceAccountsPatternMatched       = 0
                }
                $summary += $entry
            }

            $entry.TotalUsers++
            if ($user.LastLogonTimestamp) {
                if ($user.LastLogonTimestamp -ge $logonThreshold.ToFileTime()) {
                    $entry.ActiveUsers++
                } else {
                    $entry.InactiveUsers++
                }
            } else {
                $entry.NeverLoggedInUsers++
            }

            if (Test-ManagedServiceAccount      $sam $MSASet)      { $entry.ServiceAccountsManaged++ }
            elseif (Test-GroupManagedServiceAccount $sam $GMSASet)     { $entry.ServiceAccountsGroupManaged++ }
            if (Test-NonExpiringUser            $sam $NoExpireSet) { $entry.ServiceAccountsPasswordNeverExpires++ }
            if (Test-PatternMatchedUser         $sam $PatternSet)  { $entry.ServiceAccountsPatternMatched++ }
        }
    } catch {
        Write-Warning "Failed processing domain $domain : $_"
    }
}
# =====================
# Report Output
# =====================

# Create unique filename with timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$fileName = "UserAudit_${Mode}_$timestamp.csv"
$fullExportPath = Join-Path -Path $outputPath -ChildPath $fileName

switch ($Mode) {

    "UserPerOU" {
        Write-Log "OU Summary Report" -ForegroundColor Green
        $summary | Sort-Object Domain, OU | Format-Table -AutoSize
        $summary | Sort-Object Domain, OU | Export-Csv -Path $fullExportPath -NoTypeInformation -Encoding UTF8
    }
    "Summary" {
        $summaryGrouped = $summary |
            Group-Object Domain |
            ForEach-Object {
                [PSCustomObject]@{
                    Domain                              = $_.Name
                    TotalUsers                          = ($_.Group | Measure-Object TotalUsers -Sum).Sum
                    ActiveUsers                         = ($_.Group | Measure-Object ActiveUsers -Sum).Sum
                    InactiveUsers                       = ($_.Group | Measure-Object InactiveUsers -Sum).Sum
                    NeverLoggedInUsers                  = ($_.Group | Measure-Object NeverLoggedInUsers -Sum).Sum
                    ServiceAccountsManaged              = ($_.Group | Measure-Object ServiceAccountsManaged -Sum).Sum
                    ServiceAccountsGroupManaged         = ($_.Group | Measure-Object ServiceAccountsGroupManaged -Sum).Sum
                    ServiceAccountsPasswordNeverExpires = ($_.Group | Measure-Object ServiceAccountsPasswordNeverExpires -Sum).Sum
                    ServiceAccountsPatternMatched       = ($_.Group | Measure-Object ServiceAccountsPatternMatched -Sum).Sum
                }
            }

        Write-Log "Domain Summary Report" -ForegroundColor Green
        $summaryGrouped | Sort-Object Domain | Format-Table -AutoSize
        $summaryGrouped | Export-Csv -Path $fullExportPath -NoTypeInformation -Encoding UTF8
    }
}

Write-Log "Results have been saved into $fullExportPath. Please send all the files within the directory to your Rubrik Sales representative." -ForegroundColor Green

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture

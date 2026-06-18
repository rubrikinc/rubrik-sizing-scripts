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
        - **Full**: A detailed report with counts broken down by each Organizational Unit (OU).
        - **Summary**: A high-level report with aggregated counts for each domain.

    The script generates CSV and HTML reports that can be shared with Rubrik for licensing purposes.

    ## Report Columns

    ### Per-OU Report (ByOU)
    - **Domain**: The Active Directory domain name.
    - **OU**: The Organizational Unit distinguished name.
    - **Total Users**: Total number of user accounts in this OU (includes enabled user accounts plus MSA/gMSA service accounts).
    - **Active Users**: Number of accounts that have logged in within the last 180 days.
    - **Inactive Users**: Number of accounts that have not logged in within the last 180 days.
    - **Never Logged In Users**: Number of accounts with no recorded logon event.
    - **Managed Service Accounts**: Number of Managed Service Accounts (MSA).
    - **Group Managed Service Accounts**: Number of Group Managed Service Accounts (gMSA).
    - **Password Never Expires**: Number of enabled accounts with the PasswordNeverExpires flag set.
    - **Pattern Matched Service Accounts**: Number of accounts matching the -UserServiceAccountNamesLike patterns.
    - **Licensed Identities**: Number of users qualifying for Rubrik licensing (Active + not MSA + not gMSA + not pattern-matched service account).

    ### Per-Domain Report (ByDomain)
    Same columns as ByOU, minus the OU column. Values are aggregated across all OUs for each domain.

    ### Licensing Report
    - **Domain**: The Active Directory domain name.
    - **Licensed Identities**: Number of users qualifying for Rubrik licensing. Formula: Active + not MSA + not gMSA + not pattern-matched.

.PARAMETER SpecificDomains
    This is an optional parameter that allows you to specify which Active Directory domains to audit. If you do not use this parameter, the script will automatically discover and audit all domains in the current AD forest.

    To use this parameter, provide a list of fully qualified domain names (FQDNs).
    Example: -SpecificDomains "corp.example.com", "dev.example.com"

.PARAMETER UserServiceAccountNamesLike
    This is an optional parameter that allows you to identify service accounts based on their names. You can provide a list of wildcard patterns, and any user account with a name matching one of these patterns will be flagged as a service account in the report.

    This is useful for identifying service accounts that are not formally registered as MSAs or gMSAs.
    Example: -UserServiceAccountNamesLike "*svc*", "*_bot", "testuser*"

.PARAMETER ExcludeOUs
    This is an optional parameter that allows you to exclude specific Organizational Units (OUs) from the audit. Any user account located in one of the specified OUs will be completely ignored and not counted in any report column.

    The match is exact on the OU distinguished name (the part of the user's DN after the first comma). You can find the OU DN by running: Get-ADUser -Identity "someuser" | Select-Object DistinguishedName

    Example: -ExcludeOUs "OU=Servers,DC=corp,DC=local", "OU=Equipment,OU=Resources,DC=corp,DC=local"

.PARAMETER Mode
    This is a required parameter that controls the level of detail in the final report. You must choose one of the following two modes:
    - 'Full': This mode provides a very detailed report, with a separate entry for each Organizational Unit (OU). This is the recommended mode for a granular analysis.
    - 'Summary': This mode provides a high-level overview, with a single entry for each domain, showing the total counts for all account types.

    The default value is 'Full'.

.EXAMPLE
    Example 1: Perform a detailed audit of the entire forest and identify service accounts by name.

    .\Get-AdHumanIdentity.ps1 -UserServiceAccountNamesLike "*svc*", "*_app" -Mode Full

    This command will:
    - Scan all domains in the current AD forest.
    - Flag any user account with a name containing "svc" or "_app" as a service account.
    - Generate a detailed report with account counts for each OU.
    - Save the reports in CSV and HTML format in the .\ADReports directory.

.EXAMPLE
    Example 2: Perform a summary audit of a single, specific domain.

    .\Get-AdHumanIdentity.ps1 -SpecificDomains "corp.example.com" -Mode Summary

    This command will:
    - Connect only to the "corp.example.com" domain.
    - Generate a high-level summary report for that domain.
    - Save the reports in CSV and HTML format in the .\ADReports directory.

.NOTES
    Author: Aymeric Jaouen

    - **Prerequisites**: The computer running this script must have the Active Directory module for PowerShell installed. This is part of the Remote Server Administration Tools (RSAT).
    - **Permissions**: The user account running this script must have read permissions for user and service account objects in the target Active Directory domains.
    - **Execution Policy**: You may need to adjust the PowerShell execution policy to run this script. You can do this by running "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process".
    - **Culture Settings**: The script temporarily sets the culture to 'en-US' to ensure that dates and times are parsed correctly. This change is reverted at the end of the script.
#>


param (
    [string[]]$UserServiceAccountNamesLike = @(),
    [string[]]$SpecificDomains,
    [string[]]$ExcludeOUs = @(),
    [ValidateSet("Full", "Summary")]
    [string]$Mode = "Full",
    [int]$DaysInactive = 180
)

# === Logging Setup ===
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = ".\ADReports"
if (-not (Test-Path $outputPath)) { New-Item -Path $outputPath -ItemType Directory | Out-Null }

$logPath = Join-Path $outputPath "AD_Audit_$timestamp.log"
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [System.ConsoleColor]$Color = "White"
    )
    $formatted = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logPath -Value $formatted
    Write-Host $Message -ForegroundColor $Color
}

# === Log the command that started the script ===
try {
    $commandString = $MyInvocation.MyCommand.Name
    foreach ($param in $MyInvocation.BoundParameters.GetEnumerator()) {
        $paramName = $param.Key
        $paramValue = $param.Value

        $formattedValue = ""
        if ($paramValue -is [System.Array]) {
            $formattedValue = '"' + ($paramValue -join '", "') + '"'
        } elseif ($paramValue -is [string] -and $paramValue.Contains(" ")) {
            $formattedValue = """$paramValue"""
        } else {
            $formattedValue = $paramValue.ToString()
        }
        $commandString += " -$paramName $formattedValue"
    }
    $script:commandLine = $commandString
    Write-Log "Script started with command: $commandString" "INFO" "Magenta"
}
catch {
    $script:commandLine = "N/A"
    Write-Log "Could not log the command line. Error: $_" "WARNING" "Yellow"
}

function Initialize-Prerequisites {
    $requiredPSVersion = [Version]"5.1"
    $moduleName = "ActiveDirectory"

    if ($PSVersionTable.PSVersion -lt $requiredPSVersion) {
        Write-Log "PowerShell $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)" "ERROR" "Red"
        exit
    }

    try {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Log "Required module '$moduleName' not found. Please install RSAT: Active Directory Tools." "ERROR" "Red"
            exit
        }
        Import-Module $moduleName -ErrorAction Stop
    } catch {
        Write-Log "Failed to import '$moduleName'. Ensure it's installed and accessible. $_" "ERROR" "Red"
        exit
    }

    # Culture preservation
    $script:OriginalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $script:OriginalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture

    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Write-Log "Prerequisites validated. Environment initialized." "INFO" "Green"
}

Initialize-Prerequisites

#==================================================================================================
# 1. HEADERS
#==================================================================================================
function Get-ReportHeaders {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ByOU', 'ByDomain', 'Licensing')]
        [string] $Type
    )

    switch ($Type) {
        'ByOU' {
            return [PSCustomObject][ordered]@{
                Domain                              = 'Domain'
                OU                                  = 'Organizational Unit'
                TotalUsers                          = 'Total Users'
                ActiveUsers                         = 'Active Users'
                InactiveUsers                       = 'Inactive Users'
                NeverLoggedInUsers                  = 'Never Logged In'
                ServiceAccountsManaged              = 'Managed Service Accounts'
                ServiceAccountsGroupManaged         = 'Group Managed Service Accounts'
                ServiceAccountsPasswordNeverExpires = 'Password Never Expires'
                ServiceAccountsPatternMatched       = 'Pattern Matched Service Accounts'
                LicensedIdentities                  = 'Licensed Identities'
            }
        }

        'ByDomain' {
            return [PSCustomObject][ordered]@{
                Domain                              = 'Domain'
                TotalUsers                          = 'Total Users'
                ActiveUsers                         = 'Active Users'
                InactiveUsers                       = 'Inactive Users'
                NeverLoggedInUsers                  = 'Never Logged In'
                ServiceAccountsManaged              = 'Managed Service Accounts'
                ServiceAccountsGroupManaged         = 'Group Managed Service Accounts'
                ServiceAccountsPasswordNeverExpires = 'Password Never Expires'
                ServiceAccountsPatternMatched       = 'Pattern Matched Service Accounts'
                LicensedIdentities                  = 'Licensed Identities'
            }
        }

        'Licensing' {
            return [PSCustomObject][ordered]@{
                Domain             = 'Domain'
                LicensedIdentities = 'Licensed Identities'
            }
        }
    }
}

#==================================================================================================
# 2. HELPERS
#==================================================================================================
function Get-OUFromDN {
    param ([string]$dn)
    $parts = ($dn -split '(?<!\\),')
    $parts[1..($parts.Count - 1)] -join ','
}

function Get-UsersAsServiceAccount {
    param (
        [string[]]$NamePatterns,
        [string]$Domain
    )

    if (-not $NamePatterns -or $NamePatterns.Count -eq 0) {
        return @()
    }

    $subs = @()
    foreach ($pattern in $NamePatterns) {
        $safePattern = $pattern.Trim().Replace("'", "''")
        Write-Log "[$Domain] Searching for users like '$safePattern'..." "INFO" "Cyan"
        try {
            $usersFound = Get-ADUser -Server $Domain -Filter "Name -like '$safePattern'" `
                -Properties Name, SamAccountName, DistinguishedName, Enabled, LastLogonTimestamp, PasswordNeverExpires, ServicePrincipalName |
                Select-Object Name, SamAccountName, DistinguishedName, Enabled,
                              @{Name="LastLogonDate";Expression={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},
                              PasswordNeverExpires,
                              @{Name="ServicePrincipalNames";Expression={($_.ServicePrincipalName -join ";")}}

            $subs += $usersFound
        } catch {
            Write-Log "[$Domain] Error searching pattern '$safePattern': $_" "WARNING" "Yellow"
        }
    }
    return $subs
}

#==================================================================================================
# 3. DETAIL: Build ByOU data
#==================================================================================================
function Get-ByOUData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $DomainsToAudit,

        [Parameter()]
        [string[]] $ServicePattern = @(),

        [Parameter()]
        [string[]] $ExcludeOUs = @(),

        [Parameter(Mandatory)]
        [datetime] $LogonThreshold
    )

    $summaryMap = @{}

    foreach ($domain in $DomainsToAudit) {
        Write-Log "Auditing domain: $domain" "INFO" "Cyan"

        try {
            $msaObjects  = @(Get-ADServiceAccount -Server $domain -Filter "ObjectClass -eq 'msDS-ManagedServiceAccount'" -Properties SamAccountName, DistinguishedName, LastLogonTimestamp)
            $gmsaObjects = @(Get-ADServiceAccount -Server $domain -Filter "ObjectClass -eq 'msDS-GroupManagedServiceAccount'" -Properties SamAccountName, DistinguishedName, LastLogonTimestamp)

            $msaNames     = @($msaObjects | Select-Object -ExpandProperty SamAccountName)
            $gmsaNames    = @($gmsaObjects | Select-Object -ExpandProperty SamAccountName)
            $noExpireNames = @(Get-ADUser -Server $domain -Filter "PasswordNeverExpires -eq `$true -and Enabled -eq `$true" | Select-Object -ExpandProperty SamAccountName)

            $MSASet      = [System.Collections.Generic.HashSet[string]]::new([string[]]$msaNames, [System.StringComparer]::OrdinalIgnoreCase)
            $GMSASet     = [System.Collections.Generic.HashSet[string]]::new([string[]]$gmsaNames, [System.StringComparer]::OrdinalIgnoreCase)
            $NoExpireSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$noExpireNames, [System.StringComparer]::OrdinalIgnoreCase)

            $PatternMatches = Get-UsersAsServiceAccount -NamePatterns $ServicePattern -Domain $domain
            $patternNames = @($PatternMatches | Select-Object -ExpandProperty SamAccountName)
            $PatternSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$patternNames, [System.StringComparer]::OrdinalIgnoreCase)

            $userAccounts = Get-ADUser -Server $domain -Filter "Enabled -eq `$true" `
                -Properties SamAccountName, DistinguishedName, LastLogonTimestamp

            $serviceAccounts = ($msaObjects + $gmsaObjects) | ForEach-Object {
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

                if ($ExcludeOUs -contains $ou) { continue }

                $key = "$domain|$ou"
                if (-not $summaryMap.ContainsKey($key)) {
                    $summaryMap[$key] = [PSCustomObject]@{
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
                        LicensedIdentities                  = 0
                    }
                }
                $entry = $summaryMap[$key]

                $entry.TotalUsers++

                $isActive = $false
                if ($user.LastLogonTimestamp) {
                    if ($user.LastLogonTimestamp -ge $LogonThreshold.ToFileTime()) {
                        $entry.ActiveUsers++
                        $isActive = $true
                    } else {
                        $entry.InactiveUsers++
                    }
                } else {
                    $entry.NeverLoggedInUsers++
                }

                $isMSA     = $MSASet.Contains($sam)
                $isGMSA    = $GMSASet.Contains($sam)
                $isPattern = $PatternSet.Contains($sam)

                if ($isMSA)      { $entry.ServiceAccountsManaged++ }
                elseif ($isGMSA) { $entry.ServiceAccountsGroupManaged++ }
                if ($NoExpireSet.Contains($sam)) { $entry.ServiceAccountsPasswordNeverExpires++ }
                if ($isPattern)  { $entry.ServiceAccountsPatternMatched++ }

                if ($isActive -and -not $isMSA -and -not $isGMSA -and -not $isPattern) {
                    $entry.LicensedIdentities++
                }
            }

            Write-Log "Successfully processed domain '$domain'. Found $($users.Count) accounts." "INFO" "Green"
        } catch {
            Write-Log "Failed processing domain $domain : $_" "ERROR" "Red"
        }
    }

    $summary = @($summaryMap.Values | Sort-Object Domain, OU)

    # Build a grand-total row
    $totals = [ordered]@{ Domain = 'TOTAL'; OU = '' }
    foreach ($col in $summary | Get-Member -MemberType NoteProperty | Select-Object -Expand Name | Where-Object { $_ -notin @('Domain','OU') }) {
        $totals[$col] = ($summary | Measure-Object -Property $col -Sum).Sum
    }

    Write-Log "Successfully built $($summary.Count) OU records across all domains." "INFO" "Green"
    return $summary + [PSCustomObject]$totals
}

#==================================================================================================
# 4. SUMMARY: Group Into ByDomain
#==================================================================================================
function Get-ByDomainData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $OUData
    )

    $rows = $OUData |
        Group-Object Domain |
        ForEach-Object {
            [PSCustomObject][ordered]@{
                Domain                              = $_.Name
                TotalUsers                          = ($_.Group | Measure-Object TotalUsers -Sum).Sum
                ActiveUsers                         = ($_.Group | Measure-Object ActiveUsers -Sum).Sum
                InactiveUsers                       = ($_.Group | Measure-Object InactiveUsers -Sum).Sum
                NeverLoggedInUsers                  = ($_.Group | Measure-Object NeverLoggedInUsers -Sum).Sum
                ServiceAccountsManaged              = ($_.Group | Measure-Object ServiceAccountsManaged -Sum).Sum
                ServiceAccountsGroupManaged         = ($_.Group | Measure-Object ServiceAccountsGroupManaged -Sum).Sum
                ServiceAccountsPasswordNeverExpires = ($_.Group | Measure-Object ServiceAccountsPasswordNeverExpires -Sum).Sum
                ServiceAccountsPatternMatched       = ($_.Group | Measure-Object ServiceAccountsPatternMatched -Sum).Sum
                LicensedIdentities                  = ($_.Group | Measure-Object LicensedIdentities -Sum).Sum
            }
        }

    # Build a grand-total row
    $totals = [ordered]@{ Domain = 'TOTAL' }
    foreach ($col in $rows | Get-Member -MemberType NoteProperty | Select-Object -Expand Name | Where-Object { $_ -ne 'Domain' }) {
        $totals[$col] = ($rows | Measure-Object -Property $col -Sum).Sum
    }

    Write-Log "Successfully aggregated $($rows.Count) domain(s)." "INFO" "Green"
    return @($rows) + [PSCustomObject]$totals
}

#==================================================================================================
# 5. EXPORTERS (CSV + HTML)
#==================================================================================================
function Export-CsvReport {
    param(
        [Parameter(Mandatory)]
        [string]   $FileName,

        [Parameter(Mandatory)]
        [object[]] $Data,

        [Parameter(Mandatory)]
        [PSCustomObject] $Columns
    )

    $fullPath = Join-Path -Path $outputPath -ChildPath $FileName
    $calculatedProperties = @()

    try {
        foreach ($name in $Columns.PSObject.Properties.Name) {
            $header = $Columns."$name"
            $calculatedProperties += @{
                Name       = $header
                Expression = [scriptblock]::Create("`$_.`"$name`"")
            }
        }

        $Data | Select-Object -Property $calculatedProperties | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Log "Successfully exported CSV report to $fullPath" "INFO" "Green"
    }
    catch {
        Write-Log "Could not export to CSV file $fullPath. Error: $_" "ERROR" "Red"
    }
}

function Export-HtmlReport {
    param(
        [Parameter(Mandatory)]
        [string]   $FileName,

        [Parameter(Mandatory)]
        [string]   $Title,

        [Parameter(Mandatory)]
        [object[]] $Data,

        [Parameter(Mandatory)]
        [PSCustomObject] $Columns,

        [Parameter()]
        [string] $MiddleReportTitle,

        [Parameter()]
        [object[]] $MiddleReportData,

        [Parameter()]
        [PSCustomObject] $MiddleReportColumns,

        [Parameter()]
        [string] $SecondReportTitle,

        [Parameter()]
        [object[]] $SecondReportData,

        [Parameter()]
        [PSCustomObject] $SecondReportColumns,

        [Parameter(Mandatory)]
        [string] $OutputPath
    )

    $fullPath = Join-Path -Path $OutputPath -ChildPath $FileName

    try {
        function New-HtmlTable {
            param(
                [Parameter(Mandatory)]
                [string] $TableTitle,

                [Parameter(Mandatory)]
                [object[]] $TableData,

                [Parameter(Mandatory)]
                [PSCustomObject] $TableColumns
            )
           $svgContent = @"
<svg xmlns="http://www.w3.org/2000/svg" height="72" width="72" viewBox="-8 -35000 278050 403334" shape-rendering="geometricPrecision" text-rendering="geometricPrecision" image-rendering="optimizeQuality" fill-rule="evenodd" clip-rule="evenodd">
    <path fill="#ea3e23" d="M278050 305556l-29-16V28627L178807 0 448 66971l-448 87 22 200227 60865-23821V80555l117920-28193-17 239519L122 267285l178668 65976v73l99231-27462v-316z"/>
</svg>
"@

            $html = "<div class='table-header'>"
            $html += "<div class='table-header-logo'>$svgContent</div>"
            $html += "<h2>$TableTitle</h2>"
            $html += "</div>"
            $html += "<div class='table-scroll'><table>"

            $html += '<thead><tr>'
            foreach ($header in $TableColumns.PSObject.Properties.Value) {
                $safeHeader = [System.Net.WebUtility]::HtmlEncode($header)
                $html += "<th>$safeHeader</th>"
            }
            $html += '</tr></thead>'
            $html += '<tbody>'

            foreach ($row in $TableData) {
                $isTotalRow = ($row.Domain -eq 'TOTAL')

                $rowClass = ""
                if ($isTotalRow) {
                    $rowClass = ' class="total"'
                }
                $html += "<tr$rowClass>"

                foreach ($colName in $TableColumns.PSObject.Properties.Name) {
                    $value = [System.Net.WebUtility]::HtmlEncode("$($row."$colName")")
                    $html += "<td>$value</td>"
                }
                $html += '</tr>'
            }

            $html += '</tbody></table></div>'
            return $html
        }

        $base64DataUri = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIwIiBoZWlnaHQ9IjM4IiB2aWV3Qm94PSIwIDAgMTIwIDM4IiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTk1LjczMzMgMTIuNjkyMkM5NC4zMzE1IDEyLjY5MjIgOTMuNjk5NCAxMy4wOTcxIDkyLjQwMTggMTQuNzE3VjE0LjAxNzZDOTIuNDAxOCAxMy4xNzA2IDkyLjI5NjQgMTMuMDYwNiA5MS40ODk3IDEzLjA2MDZIOTAuODI0MkM5MC4wMTc2IDEzLjA2MDYgODkuOTEyMSAxMy4xNzA2IDg5LjkxMjEgMTQuMDE3NlYyNy4zNzc3Qzg5LjkxMjEgMjguMjI0NyA5MC4wMTc2IDI4LjMzNDcgOTAuODI0MiAyOC4zMzQ3SDkxLjQ4OTdDOTIuMjk2NCAyOC4zMzQ3IDkyLjQwMTggMjguMjI0NyA5Mi40MDE4IDI3LjM3NzdWMjAuMjc0MkM5Mi40MDE4IDE4LjQzMzggOTIuNTc3NiAxNy4zMzAzIDkyLjk2MyAxNi41OTQzQzkzLjQ5NTggMTUuNTc4IDk0LjY1NTggMTUuMDY4NyA5NS43Mjg1IDE1LjIyNTlDOTUuOTc4OCAxNS4yNjE5IDk2LjIgMTUuMzUwNCA5Ni40MzgyIDE1LjQzNDVDOTYuNTI2NyAxNS40NjUzIDk2LjYyODUgMTUuNDg4NiA5Ni43MTY0IDE1LjQ0ODVDOTYuODA2MSAxNS40MDcyIDk2Ljg3NjQgMTUuMzMyOCA5Ni45MzUyIDE1LjI1MjdDOTcuMDc3NiAxNS4wNjEyIDk3LjE2OTcgMTQuODMwMSA5Ny4yNzgyIDE0LjYxNjZDOTcuMzQ3MyAxNC40NzkzIDk3LjQxNjQgMTQuMzQyIDk3LjQ4NjcgMTQuMjAxMUM5Ny42Mjg1IDEzLjkwNjYgOTcuNzMzMyAxMy42ODYxIDk3LjczMzMgMTMuNTc2Qzk3Ljc2NzMgMTMuMDk3MSA5Ni44MjEyIDEyLjY5MjIgOTUuNzMzMyAxMi42OTIyWiIgZmlsbD0iIzA3MEY1MiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTUxLjQxNzIgMTIuNjkyMkM1MC4wMTUyIDEyLjY5MjIgNDkuMzgzMSAxMy4wOTcxIDQ4LjA4NTggMTQuNzE3VjE0LjAxNzZDNDguMDg1OCAxMy4xNzA2IDQ3Ljk4MDYgMTMuMDYwNiA0Ny4xNzM2IDEzLjA2MDZINDYuNTA3NUM0NS43MDA2IDEzLjA2MDYgNDUuNTk1NyAxMy4xNzA2IDQ1LjU5NTcgMTQuMDE3NlYyNy4zNzc3QzQ1LjU5NTcgMjguMjI0NyA0NS43MDA2IDI4LjMzNDcgNDYuNTA3NSAyOC4zMzQ3SDQ3LjE3MzZDNDcuOTgwNiAyOC4zMzQ3IDQ4LjA4NTggMjguMjI0NyA0OC4wODU4IDI3LjM3NzdWMjAuMjc0MkM0OC4wODU4IDE4LjQzMzggNDguMjYwNyAxNy4zMzAzIDQ4LjY0NjYgMTYuNTk0M0M0OS4xNzg4IDE1LjU3OCA1MC4zMzkzIDE1LjA2ODcgNTEuNDExOCAxNS4yMjU5QzUxLjY2MTggMTUuMjYxOSA1MS44ODM2IDE1LjM1MDQgNTIuMTIxNSAxNS40MzQ1QzUyLjIwOTUgMTUuNDY1MyA1Mi4zMTE1IDE1LjQ4ODYgNTIuMzk5NSAxNS40NDg1QzUyLjQ4ODkgMTUuNDA3MiA1Mi41NTk4IDE1LjMzMjggNTIuNjE4NSAxNS4yNTI3QzUyLjc2MSAxNS4wNjEyIDUyLjg1MzMgMTQuODMwMSA1Mi45NjEyIDE0LjYxNjZDNTMuMDMwMyAxNC40NzkzIDUzLjA5OTkgMTQuMzQyIDUzLjE3MDQgMTQuMjAxMUM1My4zMTEzIDEzLjkwNjYgNTMuNDE2MiAxMy42ODYxIDUzLjQxNjIgMTMuNTc2QzUzLjQ1MTQgMTMuMDk3MSA1Mi41MDQ0IDEyLjY5MjIgNTEuNDE3MiAxMi42OTIyWiIgZmlsbD0iIzA3MEY1MiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTU4LjYzMDIgMjEuOTY2OUM1OC42MzAyIDIzLjQwMTkgNTguNzcwNyAyNC4xNzU3IDU5LjA4NTcgMjQuODM4MkM1OS41NzY0IDI1Ljc5NTUgNjAuNjYzOCAyNi4zODQxIDYxLjkyNjMgMjYuMzg0MUM2My4xNTM1IDI2LjM4NDEgNjQuMjQwOCAyNS43OTU1IDY0LjczMjMgMjQuODM4MkM2NS4wNDc1IDI0LjE3NTcgNjUuMTg4MSAyMy40MDE5IDY1LjE4ODEgMjEuOTY2OVYxNC4wMTczQzY1LjE4ODEgMTMuMTcwNCA2NS4yOTM1IDEzLjA2MDQgNjYuMTAwMiAxMy4wNjA0SDY2Ljc2NjNDNjcuNTcyOSAxMy4wNjA0IDY3LjY3NzggMTMuMTcwNCA2Ny42Nzc4IDE0LjAxNzNWMjIuMjYxNEM2Ny42Nzc4IDI0LjUwNzIgNjcuMzI3NSAyNS43MjE2IDY2LjM0NTcgMjYuODYyMUM2NS4yOTM1IDI4LjExMzkgNjMuNzE0OCAyOC43NzU1IDYxLjkyNjMgMjguNzc1NUM2MC4xMDI0IDI4Ljc3NTUgNTguNTI1NCAyOC4xMTM5IDU3LjQ3MyAyNi44NjIxQzU2LjQ5MDcgMjUuNzIxNiA1Ni4xNDAxIDI0LjUwNzIgNTYuMTQwMSAyMi4yNjE0VjE0LjAxNzNDNTYuMTQwMSAxMy4xNzA0IDU2LjI0NSAxMy4wNjA0IDU3LjA1MiAxMy4wNjA0SDU3LjcxOEM1OC41MjU0IDEzLjA2MDQgNTguNjMwMiAxMy4xNzA0IDU4LjYzMDIgMTQuMDE3M1YyMS45NjY5WiIgZmlsbD0iIzA3MEY1MiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTc0LjA3NiAyMC42NzkxQzc0LjA3NiAyNC4wNjU4IDc2LjA3NiAyNi4zODQ3IDc4Ljk1MTggMjYuMzg0N0M4MS43MjIxIDI2LjM4NDcgODMuNzIwOSAyMy45NTQ5IDgzLjcyMDkgMjAuNjA1NkM4My43MjA5IDE3LjUxNDIgODEuNjUxOCAxNS4xMjE0IDc4LjkxNjYgMTUuMTIxNEM3Ni4wNzYgMTUuMTIxNCA3NC4wNzYgMTcuNDAzNyA3NC4wNzYgMjAuNjc5MVpNNzQuMjUyNCAxNS4yMzI0Qzc1LjY4OTQgMTMuNTAyNCA3Ny4yMzMgMTIuNzI5MSA3OS4zMzcyIDEyLjcyOTFDODMuMzM0OCAxMi43MjkxIDg2LjI4MDkgMTYuMDc4NCA4Ni4yODA5IDIwLjY3OTFDODYuMjgwOSAyNS4zNTM3IDgzLjI5OTcgMjguNzc2MSA3OS4yNjY5IDI4Ljc3NjFDNzcuMjMzIDI4Ljc3NjEgNzUuNjE5NyAyNy45NjYyIDc0LjI1MjQgMjYuMjM3NlYyNy4zNzc2Qzc0LjI1MjQgMjguMjI0NiA3NC4xNDY5IDI4LjMzNDYgNzMuMzM5NyAyOC4zMzQ2SDcyLjY3NDJDNzEuODY2OSAyOC4zMzQ2IDcxLjc2MTUgMjguMjI0NiA3MS43NjE1IDI3LjM3NzZWMi40NTk3OUM3MS43NjE1IDEuNjEzNzcgNzEuODY2OSAxLjUwMzcyIDcyLjY3NDIgMS41MDM3Mkg3My4zMzk3Qzc0LjE0NjkgMS41MDM3MiA3NC4yNTI0IDEuNjEzNzcgNzQuMjUyNCAyLjQ1OTc5VjE1LjIzMjRaIiBmaWxsPSIjMDcwRjUyIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTAzLjQ3MyAyNy4zNzc3QzEwMy40NzMgMjguMjI0NyAxMDMuMzY3IDI4LjMzNDcgMTAyLjU2MSAyOC4zMzQ3SDEwMS44OTRDMTAxLjA4NyAyOC4zMzQ3IDEwMC45ODMgMjguMjI0NyAxMDAuOTgzIDI3LjM3NzdWMTQuMDE3MUMxMDAuOTgzIDEzLjE3MTEgMTAxLjA4NyAxMy4wNjAxIDEwMS44OTQgMTMuMDYwMUgxMDIuNTYxQzEwMy4zNjcgMTMuMDYwMSAxMDMuNDczIDEzLjE3MTEgMTAzLjQ3MyAxNC4wMTcxVjI3LjM3NzdaTTEwNC4wMzQgNy4yODQwNkMxMDQuMDM0IDguMzE2MSAxMDMuMjI3IDkuMTYzMDUgMTAyLjI0NSA5LjE2MzA1QzEwMS4yNjMgOS4xNjMwNSAxMDAuNDU3IDguMzE2MSAxMDAuNDU3IDcuMjQ3MDdDMTAwLjQ1NyA2LjI1MjQ4IDEwMS4yNjMgNS40MDUwOSAxMDIuMjQ1IDUuNDA1MDlDMTAzLjIyNyA1LjQwNTA5IDEwNC4wMzQgNi4yNTI0OCAxMDQuMDM0IDcuMjg0MDZaIiBmaWxsPSIjMDcwRjUyIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTE1LjQ0OCAxMy41MDI1QzExNS44NjggMTMuMDYwNSAxMTUuODY4IDEzLjA2MDUgMTE2LjQ2NSAxMy4wNjA1SDExNy41NTJDMTE4LjE4MyAxMy4wNjA1IDExOC40MjkgMTMuMjQ0OSAxMTguNDI5IDEzLjY0OTVDMTE4LjQyOSAxMy43OTY1IDExOC4yODggMTQuMDE3NSAxMTguMDA4IDE0LjMxMkwxMTIuOTkyIDE5LjU3NTZMMTE5LjM0IDI3LjA4MzZDMTE5LjU4NiAyNy40MTQ3IDExOS43MjcgMjcuNjM2IDExOS43MjcgMjcuNzgzMUMxMTkuNzI3IDI4LjE1MTEgMTE5LjQ0NiAyOC4zMzUxIDExOC44MTQgMjguMzM1MUgxMTcuNzI3QzExNy4wOTYgMjguMzM1MSAxMTcuMDk2IDI4LjMzNTEgMTE2LjcxIDI3Ljg1NjZMMTExLjIzOSAyMS4zNzg1TDExMC42MDcgMjIuMDQxVjI3LjM3ODFDMTEwLjYwNyAyOC4yMjQ2IDExMC41MDIgMjguMzM1MSAxMDkuNjk2IDI4LjMzNTFIMTA5LjAzQzEwOC4yMjMgMjguMzM1MSAxMDguMTE4IDI4LjIyNDYgMTA4LjExOCAyNy4zNzgxVjIuNDYwMjJDMTA4LjExOCAxLjYxMzc2IDEwOC4yMjMgMS41MDM3MiAxMDkuMDMgMS41MDM3MkgxMDkuNjk2QzExMC41MDIgMS41MDM3MiAxMTAuNjA3IDEuNjEzNzYgMTEwLjYwNyAyLjQ2MDIyVjE4LjY5MjFMMTE1LjQ0OCAxMy41MDI1WiIgZmlsbD0iIzA3MEY1MiIvPgo8L3N2Zz4K"
        $logoHtml = "<img src='$base64DataUri' class='header-svg' alt='Rubrik Logo' />"

        $css = @"
<style>
    body {
        font-family: Arial, sans-serif;
        background-color: #f0f2f5;
        color: #333;
        margin: 0;
        padding: 0;
    }
    .report-container {
        width: 98%;
        max-width: none;
        margin: 20px auto;
        padding: 20px;
        background-color: #fff;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        box-sizing: border-box;
    }
    .header {
        background-color: #0d47a1;
        color: #fff;
        padding: 20px;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: flex-start;
    }
    .table-header {
    display: flex;
    align-items: center;
    gap: 15px;
    border-bottom: 2px solid #e0e6ed;
    padding-bottom: 10px;
    margin-bottom: 20px;
    }
    .header h1 {
        margin: 0;
        font-size: 24px;
        margin-left: 20px;
    }
    .header-logo {
        height: 40px;
    }
    .header svg {
        height: 45px;
        width: auto;
    }
    h2 {
        color: #0d47a1;
        font-size: 20px;
        padding-bottom: 10px;
        margin-top: 30px;
    }
    .table-scroll {
        width: 100%;
        margin-bottom: 20px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        table-layout: auto;
    }
    th, td {
        padding: 12px;
        text-align: center;
        border: 1px solid #ddd;
    }
    td:first-child, th:first-child {
        white-space: normal;
    }
    thead th {
        background-color: #2c3e50;
        color: white;
        font-weight: bold;
        text-transform: uppercase;
        font-size: 13px;
        border: 1px solid #2c3e50;
    }
    tbody tr:nth-child(odd) {
        background-color: #f9f9f9;
    }
    tbody tr:nth-child(even) {
        background-color: #fff;
    }
    tbody tr:hover {
        background-color: #e8f4fd;
    }
    tr.total {
        font-weight: bold;
        background-color: #2c3e50 !important;
        color: #fff;
    }
    .footer {
        text-align: center;
        padding: 15px;
        font-size: 12px;
        color: #888;
        border-top: 1px solid #ddd;
        margin-top: 20px;
    }
</style>
"@

        $htmlBody = @"
<html>
<head>
    <title>AD Report</title>
    $css
</head>
<body>
    <div class="report-container">
        <div class="header">
            $logoHtml
            <h1>AD Report</h1>
        </div>
        <br>
"@

        # Add the first table
        $htmlBody += New-HtmlTable -TableTitle $Title -TableData $Data -TableColumns $Columns

        # If a middle report (licensing) is provided, add it
        if ($MiddleReportData) {
            $htmlBody += "<br>"
            $htmlBody += New-HtmlTable -TableTitle $MiddleReportTitle -TableData $MiddleReportData -TableColumns $MiddleReportColumns
        }

        # If a second report is provided, add it
        if ($SecondReportData) {
            $htmlBody += "<br>"
            $htmlBody += New-HtmlTable -TableTitle $SecondReportTitle -TableData $SecondReportData -TableColumns $SecondReportColumns
        }

        $htmlBody += @"
        <div class="footer">
            Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br/>
            Command: $([System.Net.WebUtility]::HtmlEncode($script:commandLine))
        </div>
    </div>
</body>
</html>
"@

        $htmlBody | Out-File -FilePath $fullPath -Encoding UTF8
        Write-Log "Successfully exported HTML report to $fullPath" "INFO" "Green"
    }
    catch {
        Write-Log "Could not export to HTML file $fullPath. Error: $_" "ERROR" "Red"
    }
}

#==================================================================================================
# 6. MAIN
#==================================================================================================

try {

#— 1) Discover domains
$logonThreshold = (Get-Date).AddDays(-$DaysInactive)
if ($SpecificDomains) {
    $domainsToAudit = $SpecificDomains
} else {
    try {
        $domainsToAudit = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains | ForEach-Object { $_.Name }
    } catch {
        Write-Log "Failed to discover AD forest. Ensure this machine is domain-joined and can reach a domain controller. Error: $_" "ERROR" "Red"
        exit 1
    }
}

#— 2) Build per-OU dataset
Write-Log "Building per-OU dataset..." "INFO" "Cyan"
$byOU = Get-ByOUData `
    -DomainsToAudit $domainsToAudit `
    -ServicePattern $UserServiceAccountNamesLike `
    -ExcludeOUs $ExcludeOUs `
    -LogonThreshold $logonThreshold

# Filter out the TOTAL row before passing to Get-ByDomainData
$ouDataInput = $byOU | Select-Object -SkipLast 1

#— 3) Aggregate by domain
Write-Log "Building aggregated report by Domain..." "INFO" "Cyan"
$byDomain = Get-ByDomainData -OUData $ouDataInput

#— 3b) Licensing data
Write-Log "Preparing Rubrik licensing data..." "INFO" "Cyan"
$licensingData = $byDomain | Select-Object Domain, LicensedIdentities

#— 4) Report headers
$ouCols        = Get-ReportHeaders -Type ByOU
$domainCols    = Get-ReportHeaders -Type ByDomain
$licensingCols = Get-ReportHeaders -Type Licensing

#— 5) Export CSV & HTML
if ($Mode -eq 'Full') {
    Write-Log "Exporting Full reports in CSV and HTML format..." "INFO" "Cyan"

    Export-CsvReport -FileName "Full_ByOU_$timestamp.csv"      -Data $byOU          -Columns $ouCols
    Export-CsvReport -FileName "Full_ByDomain_$timestamp.csv"  -Data $byDomain      -Columns $domainCols
    Export-CsvReport -FileName "Full_Licensing_$timestamp.csv" -Data $licensingData  -Columns $licensingCols
    Export-HtmlReport -FileName "Full_Report_$timestamp.html" `
                   -Title 'Domain Summary' `
                   -Data  $byDomain `
                   -Columns $domainCols `
                   -MiddleReportTitle 'Rubrik Licensing' `
                   -MiddleReportData $licensingData `
                   -MiddleReportColumns $licensingCols `
                   -SecondReportTitle 'OU Details' `
                   -SecondReportData $byOU `
                   -SecondReportColumns $ouCols `
                   -OutputPath $OutputPath
}
else {
    Write-Log "Exporting Summary reports in CSV and HTML format..." "INFO" "Cyan"

    Export-CsvReport -FileName "Summary_ByDomain_$timestamp.csv"  -Data $byDomain      -Columns $domainCols
    Export-CsvReport -FileName "Summary_Licensing_$timestamp.csv" -Data $licensingData  -Columns $licensingCols
    Export-HtmlReport -FileName "Summary_Report_$timestamp.html" -Title 'Domain Summary' `
                   -Data $byDomain -Columns $domainCols `
                   -MiddleReportTitle 'Rubrik Licensing' `
                   -MiddleReportData $licensingData `
                   -MiddleReportColumns $licensingCols `
                   -OutputPath $OutputPath
}

Write-Log "AD reports generation completed." "INFO" "Green"

} finally {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:OriginalCulture
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = $script:OriginalUICulture
}

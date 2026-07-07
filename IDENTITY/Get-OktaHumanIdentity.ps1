<#
.SYNOPSIS
    This script is a Rubrik utility for counting human identities in a customer's Okta tenant. The data collected is used for licensing Rubrik's products. The script identifies and categorizes all user accounts and applications to determine the number of unique human users.

.DESCRIPTION
    The Get-OktaHumanIdentity.ps1 script is a specialized tool for Rubrik's customers to generate a report of their Okta identities for licensing purposes. The script connects to the customer's Okta tenant via the Okta Management API to query for users and applications, and then categorizes them to accurately count the number of human identities.

    The primary goal of this script is to provide an accurate count of human users to ensure fair and accurate licensing of Rubrik's products. The script distinguishes between human users and non-human accounts (e.g., service accounts) to avoid over-licensing.

    The script gathers the following information to assist in the identity counting process:
    - **User Account Activity**: Determines if user accounts are active, inactive, or have never been used, based on their last login date. This helps in excluding dormant accounts from the count of active users.
    - **Service Account Identification**: Identifies user accounts that may be service accounts based on naming conventions.
    - **Internal vs External Users**: Distinguishes between internal users (managed by Okta or synced from AD/LDAP) and external users (federated, social, or imported) to help differentiate between owned and external identities.
    - **Application Inventory**: Provides a count of applications registered in the Okta tenant.
    - **Reporting Modes**:
        - **Full**: A detailed report with information about each user account, as well as a summary by domain.
        - **Summary**: A high-level report with aggregated counts for each domain.

    The script generates both CSV and HTML reports that can be shared with Rubrik for licensing purposes.

    ## Report Columns

    ### Per-User Report (ByUser)
    - **Directory**: The domain associated with the user (extracted from the login/email after the @ symbol).
    - **User**: The user's login name (the part before @ in the login).
    - **External User**: 1 if the user is from an external identity provider (Federation, Social, or Import), 0 otherwise.
    - **Internal User**: 1 if the user is managed internally (Okta, Active Directory, or LDAP provider), 0 otherwise.
    - **Account Enabled**: 1 if the account status is ACTIVE, 0 otherwise.
    - **Account Disabled**: 1 if the account is not ACTIVE (suspended, deprovisioned, locked out, etc.), 0 otherwise.
    - **Active Identity**: 1 if the user has logged in within the inactivity period and the account is enabled, 0 otherwise.
    - **Inactive Identity**: 1 if the user has not logged in within the inactivity period and the account is enabled, 0 otherwise.
    - **Never Logged In**: 1 if no login activity has ever been recorded for this account, 0 otherwise.
    - **Service Account Pattern**: 1 if the user's login matches one of the patterns specified in -UserServiceAccountNamesLike, 0 otherwise.
    - **Synch from AD**: 1 if the account is sourced from Active Directory (credentials provider type is ACTIVE_DIRECTORY), 0 otherwise.
    - **Cloud Only**: 1 if the account is managed directly in Okta (credentials provider type is OKTA), 0 otherwise.
    - **Licensed Identity**: 1 if the user qualifies for Rubrik licensing (Internal AND Enabled AND Active AND not a pattern-matched service account), 0 otherwise.
    - **Source AD**: The Active Directory source name for AD-synced accounts, N/A otherwise.

    ### Per-Domain Report (ByDomain)
    - **Directory**: The domain name.
    - **Total Users**: Total number of user accounts associated with this domain.
    - **External Users**: Number of external accounts (federated, social, imported).
    - **Internal Users**: Number of internal accounts (Okta-managed, AD-synced, LDAP).
    - **Account Enabled**: Number of enabled accounts (status = ACTIVE).
    - **Account Disabled**: Number of disabled accounts.
    - **Active Identity**: Number of users who logged in within the inactivity period.
    - **Inactive Identity**: Number of users who have not logged in within the inactivity period.
    - **Never Logged In Users**: Number of accounts with no recorded login.
    - **Service Account Pattern**: Number of accounts matching the service account naming patterns.
    - **Synch from AD**: Number of accounts sourced from Active Directory.
    - **Cloud Only**: Number of Okta-managed cloud-only accounts.
    - **Licensed Identities**: Number of users qualifying for Rubrik licensing (Internal + Enabled + Active + not service account).
    - **Source AD**: Number of distinct AD source domains for AD-synced accounts.
    - **Applications**: Number of Okta applications published under this domain.

    ### Licensing Report
    - **Directory**: The domain name.
    - **Licensed Identities**: Number of users qualifying for Rubrik licensing. Formula: Internal + Enabled + Active (logged in within inactivity period) + Not a service account pattern match.

.PARAMETER OktaDomain
    The fully qualified domain name of your Okta tenant (e.g., "myorg.okta.com"). This is the domain used to access the Okta admin console. Required for both authentication methods.

.PARAMETER ApiToken
    The Okta API token (SSWS) used to authenticate API requests. Generate this token in the Okta Admin Console under Security > API > Tokens. The token inherits the permissions of the admin account that created it. Use this parameter for API Token authentication (ParameterSet 'ApiToken').

.PARAMETER ClientId
    The Client ID of the Okta OIDC application used for OAuth 2.0 authentication. This triggers the interactive OAuth flow via the browser. Use this parameter for OAuth authentication (ParameterSet 'OAuth').

.PARAMETER AuthorizationServerId
    The Okta Authorization Server ID to use for the OAuth flow. Defaults to "org" which uses the Org Authorization Server (supports Okta API scopes natively). You can specify a custom authorization server ID if needed (e.g., "default" for the default custom authorization server).

.PARAMETER Scopes
    The OAuth 2.0 scopes to request during the authorization flow. Defaults to "openid", "okta.users.read", and "okta.apps.read". These scopes must be granted in the Okta application's API Scopes tab.

.PARAMETER RedirectPort
    The local port used by the HTTP listener to receive the OAuth callback from the browser. Defaults to 8443. The redirect URI will be http://localhost:{RedirectPort}/callback/.

.PARAMETER UserServiceAccountNamesLike
    This is an optional parameter that allows you to identify service accounts based on their login name. You can provide a list of wildcard patterns, and any user account with a login matching one of these patterns will be flagged as a service account in the report.

    Example: -UserServiceAccountNamesLike "*svc*", "*_app"

.PARAMETER Mode
    This parameter controls the level of detail in the final report. You can choose one of the following two modes:
    - 'Full': This mode generates a detailed report with information about each individual user, as well as a summary by domain. This is the recommended mode for a comprehensive analysis.
    - 'Summary': This mode generates a high-level summary report, with aggregated data for each domain.

    The default value is 'Full'.

.PARAMETER DaysInactive
    The number of days of inactivity used to classify users as inactive. Users who have not logged in within this period are considered inactive. The default value is 180 days.

.PARAMETER CheckAppAssignments
    When present, retrieves the list of applications assigned to each user via the Okta API (GET /api/v1/users/{id}/appLinks). This adds an "Assigned Applications" column to the ByUser report and populates the "Applications" column in the ByDomain report.
    WARNING: This makes one API call per user and can be very slow on large tenants (e.g., 10,000 users = 10,000 API calls). This information is for informational purposes only and is NOT required for Rubrik licensing.

.EXAMPLE
    Example 1: Perform a full audit using an API token.

    .\Get-OktaHumanIdentity.ps1 -OktaDomain "myorg.okta.com" -ApiToken "00abc123..." -Mode Full

    This command will:
    - Connect to the Okta tenant at myorg.okta.com using the SSWS API token.
    - Generate a detailed report for all users and a summary by domain.
    - Save the reports in both CSV and HTML format in the .\OktaReports directory.

.EXAMPLE
    Example 2: Perform a full audit using OAuth 2.0 interactive login.

    .\Get-OktaHumanIdentity.ps1 -OktaDomain "myorg.okta.com" -ClientId "0oa..." -Mode Full

    This command will:
    - Open the default browser for Okta login (Authorization Code + PKCE flow).
    - After authentication, generate a detailed report for all users and a summary by domain.
    - Save the reports in both CSV and HTML format in the .\OktaReports directory.

.EXAMPLE
    Example 3: OAuth with a custom authorization server and service account detection.

    .\Get-OktaHumanIdentity.ps1 -OktaDomain "myorg.okta.com" -ClientId "0oa..." -AuthorizationServerId "custom" -Mode Summary -UserServiceAccountNamesLike "*svc*"

    This command will:
    - Authenticate via OAuth using the "custom" authorization server.
    - Generate a high-level summary report by domain.
    - Identify service accounts with logins containing "svc".

.EXAMPLE
    Example 4: Full report with application assignment details (slow on large tenants).

    .\Get-OktaHumanIdentity.ps1 -OktaDomain "myorg.okta.com" -ApiToken "00abc123..." -Mode Full -CheckAppAssignments

    This command will:
    - Generate a detailed report with an additional "Assigned Applications" column per user.
    - Populate the "Applications" column in the domain summary.
    - WARNING: Makes one API call per user — can be very slow on large tenants.

.NOTES
    Author: Aymeric Jaouen

    - **Prerequisites**: This script requires PowerShell 7.0 or higher. No external modules are required — the script uses Invoke-RestMethod to call the Okta Management API directly.
    - **Authentication**: The script supports two authentication methods:
        1. **API Token (SSWS)**: Pass -ApiToken with a token generated in Okta Admin > Security > API > Tokens. The token inherits the permissions of the admin account that created it. A Super Admin or Read-Only Admin role is recommended.
        2. **OAuth 2.0 (PKCE)**: Pass -ClientId with the Client ID of an Okta OIDC application. The script opens the browser for interactive login using the Authorization Code + PKCE flow. No client secret is required.
    - **OAuth Setup**: To use OAuth, create an app in Okta Admin Console:
        1. Applications > Create App Integration > OIDC - OpenID Connect > Native Application
        2. Grant type: Authorization Code (PKCE is automatic for public clients)
        3. Sign-in redirect URI: http://localhost:8443/callback/
        4. Assignments: Assign to the admin user
        5. Okta API Scopes tab: Grant okta.users.read, okta.apps.read, and okta.orgs.read
        6. Copy the Client ID
    - **Execution Policy**: You may need to adjust the PowerShell execution policy to run this script. You can do this by running "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process".
    - **Culture Settings**: The script temporarily sets the culture to 'en-US' to ensure that dates and times are parsed correctly. This change is reverted at the end of the script.
    - **Rate Limits**: The script handles Okta API rate limits automatically by retrying requests when a 429 response is received.
#>

[CmdletBinding(DefaultParameterSetName = 'ApiToken')]
param (
    [Parameter(Mandatory, ParameterSetName = 'ApiToken')]
    [Parameter(Mandatory, ParameterSetName = 'OAuth')]
    [string]$OktaDomain,

    # --- API Token auth ---
    [Parameter(Mandatory, ParameterSetName = 'ApiToken')]
    [string]$ApiToken,

    # --- OAuth auth ---
    [Parameter(Mandatory, ParameterSetName = 'OAuth')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'OAuth')]
    [string]$AuthorizationServerId = "org",

    [Parameter(ParameterSetName = 'OAuth')]
    [string[]]$Scopes = @("openid", "okta.users.read", "okta.apps.read", "okta.orgs.read"),

    [Parameter(ParameterSetName = 'OAuth')]
    [int]$RedirectPort = 8443,

    # --- Common ---
    [string[]]$UserServiceAccountNamesLike = @(),
    [ValidateSet("Summary", "Full")]
    [string]$Mode = "Full",
    [int]$DaysInactive = 180,
    [switch]$CheckAppAssignments
)

# === Global Variables and Logging Setup ===
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = ".\OktaReports"
if (-not (Test-Path $outputPath)) { New-Item -Path $outputPath -ItemType Directory | Out-Null }

$logPath = Join-Path $outputPath "OktaAudit_$timestamp.log"

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

        if ($paramName -eq 'ApiToken') {
            $commandString += " -$paramName ********"
            continue
        }

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

# === Initialization and Connection ===
function Initialize-OktaPrerequisites {
    $requiredPSVersion = [Version]"7.0"

    if ($PSVersionTable.PSVersion -lt $requiredPSVersion) {
        Write-Log "PowerShell $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)" "ERROR" "Red"
        exit 1
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Culture preservation
    $script:OriginalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $script:OriginalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture

    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Write-Log "Successfully validated Okta prerequisites. Environment initialized." "INFO" "Green"
}

function Connect-OktaOAuth {
    param(
        [Parameter(Mandatory)]
        [string]$OktaDomain,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [string]$AuthorizationServerId = "org",

        [string[]]$Scopes = @("openid", "okta.users.read", "okta.apps.read", "okta.orgs.read"),

        [int]$RedirectPort = 8443
    )

    Write-Log "Starting OAuth 2.0 Authorization Code + PKCE flow..." "INFO" "Cyan"

    $redirectUri = "http://localhost:$RedirectPort/callback/"

    # Generate PKCE code_verifier and code_challenge
    $randomBytes = [byte[]]::new(64)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($randomBytes)
    $codeVerifier = [Convert]::ToBase64String($randomBytes) -replace '\+', '-' -replace '/', '_' -replace '='

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $challengeBytes = $sha256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
    $codeChallenge = [Convert]::ToBase64String($challengeBytes) -replace '\+', '-' -replace '/', '_' -replace '='

    # Generate state for CSRF protection
    $stateBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($stateBytes)
    $state = [Convert]::ToBase64String($stateBytes) -replace '\+', '-' -replace '/', '_' -replace '='

    $scopeString = $Scopes -join ' '

    if ($AuthorizationServerId -eq "org") {
        $oauthBase = "https://$OktaDomain/oauth2/v1"
    } else {
        $oauthBase = "https://$OktaDomain/oauth2/$AuthorizationServerId/v1"
    }

    $authorizeUrl = "$oauthBase/authorize?" +
        "client_id=$([System.Uri]::EscapeDataString($ClientId))" +
        "&response_type=code" +
        "&scope=$([System.Uri]::EscapeDataString($scopeString))" +
        "&redirect_uri=$([System.Uri]::EscapeDataString($redirectUri))" +
        "&state=$([System.Uri]::EscapeDataString($state))" +
        "&code_challenge=$([System.Uri]::EscapeDataString($codeChallenge))" +
        "&code_challenge_method=S256"

    # Start HTTP listener for callback
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($redirectUri)

    try {
        $listener.Start()
    } catch {
        Write-Log "Failed to start HTTP listener on port $RedirectPort. Make sure the port is not in use. Error: $_" "ERROR" "Red"
        exit 1
    }

    # Open browser for Okta login
    Write-Log "Opening browser for Okta login... Please authenticate in the browser window." "INFO" "Yellow"
    try {
        if ($IsMacOS) {
            Start-Process "open" -ArgumentList $authorizeUrl
        } elseif ($IsLinux) {
            Start-Process "xdg-open" -ArgumentList $authorizeUrl
        } else {
            Start-Process $authorizeUrl
        }
    } catch {
        Write-Log "Could not open the browser automatically. Please open this URL manually:" "WARNING" "Yellow"
        Write-Log $authorizeUrl "INFO" "White"
    }

    Write-Log "Waiting for authentication callback on $redirectUri ..." "INFO" "Cyan"

    # Wait for the callback with a 5-minute timeout
    try {
        $timeoutMs = 300000
        $asyncResult = $listener.BeginGetContext($null, $null)
        $completed = $asyncResult.AsyncWaitHandle.WaitOne($timeoutMs)

        if (-not $completed) {
            Write-Log "OAuth authentication timed out after 5 minutes. No callback received." "ERROR" "Red"
            $listener.Stop()
            $listener.Close()
            exit 1
        }

        $context = $listener.EndGetContext($asyncResult)
        $request = $context.Request
        $queryParams = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)

        $callbackCode = $queryParams["code"]
        $callbackState = $queryParams["state"]
        $callbackError = $queryParams["error"]
        $callbackErrorDescription = $queryParams["error_description"]

        # Send response page to the browser
        $responseHtml = @"
<!DOCTYPE html>
<html>
<head><title>Okta Authentication</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
.card { background: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }
.success { color: #00b388; }
h2 { margin-top: 0; }
</style>
</head>
<body>
<div class="card">
<h2 class="success">Authentication Successful</h2>
<p>You have been authenticated successfully. You can close this browser window and return to PowerShell.</p>
</div>
</body>
</html>
"@
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseHtml)
        $context.Response.ContentType = "text/html"
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.OutputStream.Close()
    } catch {
        Write-Log "Error while waiting for the OAuth callback: $_" "ERROR" "Red"
        $listener.Stop()
        $listener.Close()
        exit 1
    } finally {
        $listener.Stop()
        $listener.Close()
    }

    # Validate state
    if ($callbackState -ne $state) {
        Write-Log "OAuth state mismatch — possible CSRF attack. Aborting." "ERROR" "Red"
        exit 1
    }

    # Check for errors from Okta
    if ($callbackError) {
        Write-Log "Okta returned an error: $callbackError — $callbackErrorDescription" "ERROR" "Red"
        exit 1
    }

    if (-not $callbackCode) {
        Write-Log "No authorization code received in the callback. Aborting." "ERROR" "Red"
        exit 1
    }

    Write-Log "Authorization code received. Exchanging for access token..." "INFO" "Cyan"

    # Exchange authorization code for access token
    $tokenUrl = "$oauthBase/token"
    $tokenBody = @{
        grant_type    = "authorization_code"
        code          = $callbackCode
        redirect_uri  = $redirectUri
        client_id     = $ClientId
        code_verifier = $codeVerifier
    }

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -ContentType "application/x-www-form-urlencoded" -Body $tokenBody
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Log "Failed to exchange authorization code for token (HTTP $statusCode). Error: $_" "ERROR" "Red"
        exit 1
    }

    if (-not $tokenResponse.access_token) {
        Write-Log "No access token in the token response. Aborting." "ERROR" "Red"
        exit 1
    }

    Write-Log "OAuth 2.0 access token obtained successfully." "INFO" "Green"
    return $tokenResponse.access_token
}

function Connect-OktaApi {
    Write-Log "Connecting to Okta API at $OktaDomain..." "INFO" "Cyan"

    $script:OktaBaseUrl = "https://$OktaDomain"

    if ($ClientId) {
        $accessToken = Connect-OktaOAuth `
            -OktaDomain $OktaDomain `
            -ClientId $ClientId `
            -AuthorizationServerId $AuthorizationServerId `
            -Scopes $Scopes `
            -RedirectPort $RedirectPort

        $script:OktaAccessToken = $accessToken
        $script:OktaClientId = $ClientId
        $script:OktaAuthServerId = $AuthorizationServerId
        $script:OktaAuthMethod = 'OAuth'

        $script:OktaHeaders = @{
            'Authorization' = "Bearer $accessToken"
            'Accept'        = 'application/json'
            'Content-Type'  = 'application/json'
        }
    } else {
        $script:OktaAuthMethod = 'ApiToken'
        $script:OktaHeaders = @{
            'Authorization' = "SSWS $ApiToken"
            'Accept'        = 'application/json'
            'Content-Type'  = 'application/json'
        }
    }

    try {
        $org = Invoke-RestMethod -Uri "$($script:OktaBaseUrl)/api/v1/org" -Headers $script:OktaHeaders -Method Get
        Write-Log "Successfully connected to Okta tenant: $($org.companyName) ($($org.subdomain))" "INFO" "Green"
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 401) {
            Write-Log "Authentication failed. The token is invalid or expired." "ERROR" "Red"
        } elseif ($statusCode -eq 403) {
            Write-Log "Access denied. Insufficient permissions. A Super Admin or Read-Only Admin role is required." "ERROR" "Red"
        } else {
            Write-Log "Failed to connect to Okta API at $OktaDomain. Error: $_" "ERROR" "Red"
        }
        exit 1
    }
}

function Disconnect-OktaOAuth {
    if ($script:OktaAuthMethod -ne 'OAuth' -or -not $script:OktaAccessToken) { return }

    if ($script:OktaAuthServerId -eq "org") {
        $revokeUrl = "https://$OktaDomain/oauth2/v1/revoke"
    } else {
        $revokeUrl = "https://$OktaDomain/oauth2/$($script:OktaAuthServerId)/v1/revoke"
    }

    try {
        Invoke-RestMethod -Uri $revokeUrl -Method Post -ContentType "application/x-www-form-urlencoded" -Body @{
            token           = $script:OktaAccessToken
            token_type_hint = "access_token"
            client_id       = $script:OktaClientId
        } | Out-Null
        Write-Log "OAuth access token revoked successfully." "INFO" "Green"
    } catch {
        Write-Log "Failed to revoke OAuth access token: $_" "WARNING" "Yellow"
    }
}

# Run Initialization and Connection
Initialize-OktaPrerequisites

try {

Connect-OktaApi

#————————————————————————————————————————
# HELPERS
#————————————————————————————————————————
function Invoke-OktaPagedRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $allResults = [System.Collections.Generic.List[object]]::new()
    $nextUrl = $Uri

    while ($nextUrl) {
        try {
            $response = Invoke-WebRequest -Uri $nextUrl -Headers $script:OktaHeaders -Method Get

            $pageData = $response.Content | ConvertFrom-Json
            if ($pageData) {
                foreach ($item in $pageData) {
                    $allResults.Add($item)
                }
            }

            $nextUrl = $null
            $linkHeader = $response.Headers['Link']
            if ($linkHeader) {
                $links = if ($linkHeader -is [System.Array]) { $linkHeader } else { @($linkHeader) }
                foreach ($link in $links) {
                    if ($link -match '<([^>]+)>;\s*rel="next"') {
                        $nextUrl = $Matches[1]
                    }
                }
            }
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ($statusCode -eq 429) {
                $retryAfter = $_.Exception.Response.Headers['Retry-After']
                $waitSeconds = if ($retryAfter) { [int]$retryAfter } else { 30 }
                Write-Log "Rate limited by Okta API. Waiting $waitSeconds seconds before retrying..." "WARNING" "Yellow"
                Start-Sleep -Seconds $waitSeconds
                continue
            }
            Write-Log "Okta API request failed for $nextUrl. Error: $_" "ERROR" "Red"
            throw
        }
    }

    return $allResults
}

function Get-DomainFromLogin {
    param([string]$Login)

    if ([string]::IsNullOrWhiteSpace($Login)) { return $null }
    if ($Login -match '@(?<Domain>[^@]+)$') { return $Matches['Domain'].ToLowerInvariant() }
    return $null
}

#————————————————————————————————————————
# 1. HEADERS
#————————————————————————————————————————
function Get-ReportHeaders {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ByUser', 'ByDomain', 'Licensing')]
        [string] $Type,
        [switch] $CheckAppAssignments
    )

    switch ($Type) {
        'ByUser' {
            $baseHeaders = [ordered]@{
                Directory               = 'Directory'
                User                    = 'User'
                ExternalUser            = 'External User'
                InternalUser            = 'Internal User'
                AccountEnabled          = 'Account Enabled'
                DisabledUser            = 'Account Disabled'
                ActiveUser              = 'Active Identity'
                InactiveUser            = 'Inactive Identity'
                NeverLoggedInUser       = 'Never Logged In'
                PatternMatchedUser      = 'Service Account Pattern'
                SyncFromAD              = 'Synch from AD'
                CloudOnly               = 'Cloud Only'
                LicensedIdentity        = 'Licensed Identity'
                ADSourceDomain          = 'Source AD'
            }
            if ($CheckAppAssignments) {
                $baseHeaders['AssignedAppsCount'] = 'Assigned Applications'
            }
            return [PSCustomObject]$baseHeaders
        }

        'Licensing' {
            return [PSCustomObject][ordered]@{
                Domain             = 'Directory'
                LicensedIdentities = 'Licensed Identities'
            }
        }

        'ByDomain' {
            $baseHeaders = [ordered]@{
                Domain                        = 'Directory'
                TotalUsers                    = 'Total Users'
                ExternalUsers                 = 'External Users'
                InternalUsers                 = 'Internal Users'
                AccountEnabledCount           = 'Account Enabled'
                DisabledUsers                 = 'Account Disabled'
                ActiveUsers                   = 'Active Identity'
                InactiveUsers                 = 'Inactive Identity'
                NeverLoggedInUsers            = 'Never Logged In Users'
                PatternMatchedUsers           = 'Service Account Pattern'
                SyncFromADCount               = 'Synch from AD'
                CloudOnlyCount                = 'Cloud Only'
                LicensedIdentities            = 'Licensed Identities'
                ADSourceDomainCounts          = 'Source AD'
            }
            if ($CheckAppAssignments) {
                $baseHeaders['DomainApplicationsCount'] = 'Applications'
            }
            return [PSCustomObject]$baseHeaders
        }
    }
}

#————————————————————————————————————————
# 2. DETAIL: Build ByUser List
#————————————————————————————————————————
function Get-ByUserData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]      $DaysInactive,

        [Parameter()]
        [string[]] $ServicePattern = @(),

        [Parameter()]
        [switch]   $CheckAppAssignments
    )

    begin {
        $cutoff = (Get-Date).AddDays(-$DaysInactive)
        Write-Verbose "Inactivity cutoff date: $cutoff"

        $output = [System.Collections.Generic.List[object]]::new()
    }

    process {
        Write-Log "Retrieving users from Okta..." "INFO" "Cyan"
        $users = Invoke-OktaPagedRequest -Uri "$($script:OktaBaseUrl)/api/v1/users?limit=200"
        Write-Log "Retrieved $($users.Count) users." "INFO" "Cyan"

        if ($CheckAppAssignments) {
            Write-Log "Retrieving application assignments for $($users.Count) users (1 API call per user)..." "INFO" "Cyan"
        }

        $userIndex = 0
        foreach ($u in $users) {
            $userIndex++
            Write-Verbose "Processing user: $($u.profile.login)"

            $login = $u.profile.login
            $parts = if ($login) { $login.Split('@') } else { @('','') }
            $user = $parts[0]
            if ($parts.Count -le 1) {
                Write-Log "Warning: Login without '@' detected: '$login' (Id=$($u.id))" "WARNING" "Yellow"
            }
            $loginDomain = if ($parts.Count -gt 1) { $parts[1].ToLowerInvariant() } else { '' }
            $directory = $loginDomain

            $providerType = $null
            $providerName = $null
            if ($u.credentials -and $u.credentials.provider) {
                $providerType = $u.credentials.provider.type
                $providerName = $u.credentials.provider.name
            }

            $isExternal = $providerType -in @('FEDERATION', 'SOCIAL', 'IMPORT')
            $isInternal = $providerType -in @('OKTA', 'ACTIVE_DIRECTORY', 'LDAP')
            if (-not $isExternal -and -not $isInternal) {
                $isInternal = $true
            }

            $isEnabled = $u.status -eq 'ACTIVE'

            $lastLogin = $null
            if ($u.lastLogin) {
                try {
                    $lastLogin = [datetime]$u.lastLogin
                } catch {
                    Write-Log "Warning: could not parse lastLogin '$($u.lastLogin)' for user '$login'" "WARNING" "Yellow"
                }
            }

            $isNeverLoggedIn = [bool](-not $lastLogin)

            if ($isEnabled) {
                $isActive   = [bool]($lastLogin -and ($lastLogin -ge $cutoff))
                $isInactive = [bool](-not $isActive)
            }
            else {
                $isActive   = $false
                $isInactive = $false
            }

            $patternMatched = $false
            foreach ($p in $ServicePattern) {
                if ($login -like $p) {
                    $patternMatched = $true
                    break
                }
            }

            $syncFromAD = $providerType -eq 'ACTIVE_DIRECTORY'
            $cloudOnly  = [int]($providerType -eq 'OKTA')
            $adSourceDomain = if ($syncFromAD -and -not [string]::IsNullOrWhiteSpace($providerName)) {
                $providerName.ToLowerInvariant()
            } else {
                'N/A'
            }

            $assignedAppsCount = 0
            $assignedAppLabels = @()
            if ($CheckAppAssignments) {
                try {
                    $appLinks = Invoke-OktaPagedRequest -Uri "$($script:OktaBaseUrl)/api/v1/users/$($u.id)/appLinks"
                    $assignedAppsCount = $appLinks.Count
                    $assignedAppLabels = @($appLinks | ForEach-Object { $_.label })
                } catch {
                    Write-Log "Warning: could not retrieve appLinks for user '$login': $_" "WARNING" "Yellow"
                }
                if ($userIndex % 50 -eq 0) {
                    Write-Log "App assignments progress: $userIndex / $($users.Count) users processed..." "INFO" "Cyan"
                }
            }

            $record = [ordered]@{
                Directory               = $directory
                User                    = $user
                ExternalUser            = [int]$isExternal
                InternalUser            = [int]$isInternal
                AccountEnabled          = [int]$isEnabled
                DisabledUser            = [int](-not $isEnabled)
                ActiveUser              = [int]$isActive
                InactiveUser            = [int]$isInactive
                NeverLoggedInUser       = [int]$isNeverLoggedIn
                PatternMatchedUser      = [int]$patternMatched
                SyncFromAD              = [int]$syncFromAD
                CloudOnly               = $cloudOnly
                LicensedIdentity        = [int]($isInternal -and $isEnabled -and $isActive -and -not $patternMatched)
                ADSourceDomain          = $adSourceDomain
            }
            if ($CheckAppAssignments) {
                $record['AssignedAppsCount'] = $assignedAppsCount
                $record['_AppLinkLabels'] = $assignedAppLabels
            }
            $output.Add([PSCustomObject]$record)
        }
    }

    end {
        Write-Verbose "Built $($output.Count) user records. Calculating totals..."
        Write-Log "Successfully built $($output.Count) user records." "INFO" "Green"

        # Build a grand-total row
        $totals = [ordered]@{ Directory = "TOTAL"; User = "" }
        foreach ($col in $output | Get-Member -MemberType NoteProperty | Select-Object -Expand Name | Where-Object { $_ -notin @('Directory','User','ADSourceDomain','_AppLinkLabels') }) {
            $totals[$col] = ($output | Measure-Object -Property $col -Sum).Sum
        }
        $totals['ADSourceDomain'] = 'N/A'

        $output.Add([PSCustomObject]$totals)
        return $output
    }
}

#————————————————————————————————————————
# 3. SUMMARY: Group Into ByDomain
#————————————————————————————————————————
function Get-ByDomainData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $UserData,

        [Parameter()]
        [switch]   $CheckAppAssignments
    )

    begin {
        $rows = [System.Collections.Generic.List[object]]::new()
    }

    process {
        $UserData |
            Group-Object -Property Directory |
            ForEach-Object {
                $domain = $_.Name
                $grpUsers = $_.Group

                $record = [ordered]@{
                    Domain                        = $domain
                    TotalUsers                    = $grpUsers.Count
                    ExternalUsers                 = ($grpUsers | Where-Object { $_.ExternalUser -eq 1 }).Count
                    InternalUsers                 = ($grpUsers | Where-Object { $_.InternalUser -eq 1 }).Count
                    AccountEnabledCount           = ($grpUsers | Where-Object { $_.AccountEnabled -eq 1 }).Count
                    DisabledUsers                 = ($grpUsers | Where-Object { $_.DisabledUser -eq 1 }).Count
                    ActiveUsers                   = ($grpUsers | Where-Object { $_.ActiveUser -eq 1 }).Count
                    InactiveUsers                 = ($grpUsers | Where-Object { $_.InactiveUser -eq 1 }).Count
                    NeverLoggedInUsers            = ($grpUsers | Where-Object { $_.NeverLoggedInUser -eq 1 }).Count
                    PatternMatchedUsers           = ($grpUsers | Where-Object { $_.PatternMatchedUser -eq 1 }).Count
                    SyncFromADCount               = ($grpUsers | Where-Object { $_.SyncFromAD -eq 1 }).Count
                    CloudOnlyCount                = ($grpUsers | Where-Object { $_.CloudOnly -eq 1 }).Count
                    LicensedIdentities            = ($grpUsers | Where-Object { $_.LicensedIdentity -eq 1 }).Count
                    ADSourceDomainCounts          = @(
                        $grpUsers |
                        Where-Object { $_.SyncFromAD -eq 1 -and -not [string]::IsNullOrWhiteSpace($_.ADSourceDomain) -and $_.ADSourceDomain -ne 'N/A' } |
                        Select-Object -ExpandProperty ADSourceDomain -Unique
                    ).Count
                }
                if ($CheckAppAssignments) {
                    $uniqueAppLinks = [System.Collections.Generic.HashSet[string]]::new()
                    foreach ($usr in $grpUsers) {
                        if ($usr._AppLinkLabels) {
                            foreach ($lbl in $usr._AppLinkLabels) {
                                $uniqueAppLinks.Add($lbl) | Out-Null
                            }
                        }
                    }
                    $record['DomainApplicationsCount'] = $uniqueAppLinks.Count
                }
                $rows.Add([PSCustomObject]$record)
            }
    }

    end {
        # Build a grand-total row
        $totals = [ordered]@{ Domain = 'TOTAL' }
        foreach ($col in $rows | Get-Member -MemberType NoteProperty | Select-Object -Expand Name | Where-Object { $_ -ne 'Domain' }) {
            $totals[$col] = ($rows | Measure-Object -Property $col -Sum).Sum
        }

        Write-Log "Successfully aggregated $($rows.Count) different domain(s)." "INFO" "Green"
        return $rows + [PSCustomObject]$totals
    }
}

#————————————————————————————————————————
# 4. EXPORTERS (CSV + HTML)
#————————————————————————————————————————
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
        Write-Log "Successfully exported all objects in CSV file $fullPath" "INFO" "Green"
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
                $isTotalRow = ($row.Directory -eq 'TOTAL' -or $row.Domain -eq 'TOTAL')

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
    <title>Okta Report</title>
    $css
</head>
<body>
    <div class="report-container">
        <div class="header">
            $logoHtml
            <h1>OKTA Report</h1>
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
# 5. MAIN
#==================================================================================================

#— 0) Confirm CheckAppAssignments if enabled
if ($CheckAppAssignments) {
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Yellow
    Write-Host "  WARNING: -CheckAppAssignments is enabled." -ForegroundColor Yellow
    Write-Host "  This will make ONE API call per user to retrieve" -ForegroundColor Yellow
    Write-Host "  the applications assigned to each user." -ForegroundColor Yellow
    Write-Host "  On large tenants, this can take a very long time" -ForegroundColor Yellow
    Write-Host "  and consume significant API rate limits." -ForegroundColor Yellow
    Write-Host "  This is NOT required for Rubrik licensing." -ForegroundColor Yellow
    Write-Host "========================================================" -ForegroundColor Yellow
    Write-Host ""
    $confirmation = Read-Host "Do you want to continue with application assignment checks? (Y/N)"
    Write-Log "User response to -CheckAppAssignments prompt: '$confirmation'" "INFO" "Cyan"
    if ($confirmation -notin @('Y', 'y', 'Yes', 'yes', 'O', 'o', 'Oui', 'oui')) {
        Write-Log "User declined -CheckAppAssignments. Continuing without application assignment data." "INFO" "Cyan"
        $CheckAppAssignments = [switch]::new($false)
    } else {
        Write-Log "User confirmed -CheckAppAssignments. Proceeding with application assignment checks." "INFO" "Cyan"
    }
}

#— 1) Build detailed per-user report
Write-Log "Building per-user dataset..." "INFO" "Cyan"
$byUser = Get-ByUserData `
    -DaysInactive $DaysInactive `
    -ServicePattern $UserServiceAccountNamesLike `
    -CheckAppAssignments:$CheckAppAssignments

# Filter out the last row (the 'TOTAL' row) before passing the data to Get-ByDomainData
$domainDataInput = $byUser | Select-Object -SkipLast 1

#— 3) Aggregate by domain
Write-Log "Building aggregated report by Domain..." "INFO" "Cyan"
$byDomain = Get-ByDomainData `
    -UserData          $domainDataInput `
    -CheckAppAssignments:$CheckAppAssignments

#— 3b) Licensing: extract from domain data
Write-Log "Preparing Rubrik licensing data..." "INFO" "Cyan"
$licensingData = $byDomain | Select-Object Domain, LicensedIdentities

#— 4) Prepare report headers
$userCols      = Get-ReportHeaders -Type ByUser -CheckAppAssignments:$CheckAppAssignments
$domainCols    = Get-ReportHeaders -Type ByDomain -CheckAppAssignments:$CheckAppAssignments
$licensingCols = Get-ReportHeaders -Type Licensing

#— 5) Export CSV & HTML based on mode
if ($Mode -eq 'Full') {
    Write-Log "Exporting Full reports in CSV and HTML format..." "INFO" "Cyan"

    Export-CsvReport -FileName "Full_ByUser_$timestamp.csv"      -Data $byUser        -Columns $userCols
    Export-CsvReport -FileName "Full_ByDomain_$timestamp.csv"    -Data $byDomain      -Columns $domainCols
    Export-CsvReport -FileName "Full_Licensing_$timestamp.csv"   -Data $licensingData  -Columns $licensingCols
    Export-HtmlReport -FileName "Full_Report_$timestamp.html" `
                   -Title 'Domain Summary' `
                   -Data  $byDomain `
                   -Columns $domainCols `
                   -MiddleReportTitle 'Rubrik Licensing' `
                   -MiddleReportData $licensingData `
                   -MiddleReportColumns $licensingCols `
                   -SecondReportTitle 'User Details' `
                   -SecondReportData $byUser `
                   -SecondReportColumns $userCols `
                   -OutputPath $outputPath
}

else {
    Write-Log "Exporting Summary reports in CSV and HTML format..." "INFO" "Cyan"

    Export-CsvReport   -FileName "Summary_ByDomain_$timestamp.csv"  -Data $byDomain      -Columns $domainCols
    Export-CsvReport   -FileName "Summary_Licensing_$timestamp.csv" -Data $licensingData  -Columns $licensingCols
    Export-HtmlReport  -FileName "Summary_Report_$timestamp.html" -Title 'Okta Summary' `
                       -Data $byDomain -Columns $domainCols `
                       -MiddleReportTitle 'Rubrik Licensing' `
                       -MiddleReportData $licensingData `
                       -MiddleReportColumns $licensingCols `
                       -OutputPath $outputPath
}

Write-Log "OKTA reports generation completed." "INFO" "Green"

} finally {
    Disconnect-OktaOAuth
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:OriginalCulture
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = $script:OriginalUICulture
}

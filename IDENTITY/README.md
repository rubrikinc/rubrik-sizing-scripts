# Rubrik Identity Auditing Scripts for Licensing

## Overview

This repository contains a suite of PowerShell scripts designed specifically for Rubrik's customers to audit their user identities for licensing purposes. The scripts connect to both on-premises Active Directory (AD) and Microsoft Entra ID (formerly Azure Active Directory) to count the number of unique human identities. This data is then used to ensure fair and accurate licensing of Rubrik's products.

The primary goal of these scripts is to distinguish between human users and non-human accounts (e.g., service accounts, applications) to avoid over-licensing. The scripts generate detailed reports that can be shared with Rubrik.

## Scripts

This repository contains three main scripts:

1.  **`Get-AdHumanIdentity.ps1`**: For auditing on-premises Active Directory.
2.  **`Get-EntraHumanIdentity.ps1`**: For auditing Microsoft Entra ID.
3.  **`Get-OktaHumanIdentity.ps1`**: For auditing Okta.

---

## `Get-AdHumanIdentity.ps1`

This script is a Rubrik utility for counting human identities in a customer's Active Directory (AD) environment. The data collected is used for licensing Rubrik's products. The script identifies and categorizes all user and service accounts to determine the number of unique human users.

### Features

-   **Multi-Domain Auditing**: Scans a single domain, a list of specified domains, or all domains in the current forest.
-   **Account Classification**: Categorizes user accounts based on their activity status to help differentiate between human and non-human accounts:
    -   **Active**: Users who have logged in within the last 180 days.
    -   **Inactive**: Users who have not logged in for more than 180 days.
    -   **Never Logged In**: Accounts that have never recorded a logon event.
-   **Service Account Detection**: Identifies different types of non-human accounts to exclude them from the human identity count:
    -   Managed Service Accounts (MSA)
    -   Group Managed Service Accounts (gMSA)
    -   Accounts with the `PasswordNeverExpires` flag set.
    -   Accounts matching custom naming patterns (e.g., `*svc*`, `*_bot`).
-   **Flexible Reporting**: Generates reports in two modes:
    -   `Full`: A detailed breakdown of accounts per Organizational Unit (OU).
    -   `Summary`: A high-level summary of accounts per domain.
-   **CSV & HTML Export**: Automatically exports the audit results to timestamped CSV and HTML files that can be shared with Rubrik.
-   **Logging**: Creates a detailed log file for each execution, capturing all actions and potential errors.

### Prerequisites

-   **PowerShell Version**: 5.1 or later.
-   **Active Directory Module**: The `ActiveDirectory` PowerShell module must be installed. This is typically included with the Remote Server Administration Tools (RSAT) for Active Directory Domain Services.
-   **Permissions**: The user running the script must have sufficient permissions to read user and service account information from the target Active Directory domains.

### Parameters

| Parameter                       | Description                                                                                                                         | Required | Default Value             |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------- | ------------------------- |
| `SpecificDomains`               | An array of fully qualified domain names to audit (e.g., `"corp.domain.local"`). If omitted, all domains in the forest are audited. | No       | All domains in the forest |
| `UserServiceAccountNamesLike`   | An array of wildcard patterns to identify service accounts by name. Patterns are used as-is with `-like`, so include wildcards explicitly (e.g., `"*svc*"` for contains-match, `"svc-*"` for prefix-match). | No       | None                      |
| `ExcludeOUs`                    | An array of OU distinguished names to exclude from the audit (exact match on the full DN).                                          | No       | None                      |
| `Mode`                          | The reporting mode. `Full` for a detailed per-OU report or `Summary` for a domain-level summary.                                    | Yes      | `Full`                    |

### Usage Examples

**Example 1: Audit all domains in the forest with a detailed per-OU report.**

```powershell
.\Get-AdHumanIdentity.ps1 -Mode Full
```

**Example 2: Audit a specific domain and identify service accounts by name, with a summary report.**

```powershell
.\Get-AdHumanIdentity.ps1 -SpecificDomains "corp.domain.local" -UserServiceAccountNamesLike "*svc*", "*_bot*" -Mode Summary
```

### Report Columns

#### Per-OU Report (ByOU)

| Column | Description |
| --- | --- |
| Domain | The Active Directory domain name. |
| OU | The Organizational Unit distinguished name. |
| Total Users | Total number of user accounts in this OU (includes enabled user accounts plus MSA/gMSA service accounts). |
| Active Users | Number of accounts that have logged in within the last 180 days. |
| Inactive Users | Number of accounts that have not logged in within the last 180 days. |
| Never Logged In Users | Number of accounts with no recorded logon event. |
| Managed Service Accounts | Number of Managed Service Accounts (MSA). |
| Group Managed Service Accounts | Number of Group Managed Service Accounts (gMSA). |
| Password Never Expires | Number of enabled accounts with the PasswordNeverExpires flag set. |
| Pattern Matched Service Accounts | Number of accounts matching the `-UserServiceAccountNamesLike` patterns. |
| Licensed Identities | Number of users qualifying for Rubrik licensing (Active + not MSA + not gMSA + not pattern-matched service account). |

#### Per-Domain Report (ByDomain)

Same columns as ByOU, minus the OU column. Values are aggregated across all OUs for each domain.

#### Licensing Report

| Column | Description |
| --- | --- |
| Domain | The Active Directory domain name. |
| Licensed Identities | Number of users qualifying for Rubrik licensing. Formula: Active + not MSA + not gMSA + not pattern-matched. |

### Output

-   **CSV Reports**: CSV files are created in the `ADReports` directory (ByOU, ByDomain, Licensing in Full mode; ByDomain, Licensing in Summary mode).
-   **HTML Report**: An HTML report with Rubrik branding is created in the `ADReports` directory.
-   **Log File**: A log file named `AD_Audit_<timestamp>.log` is created in the `ADReports` directory.

---

## `Get-EntraHumanIdentity.ps1`

This script is a Rubrik utility for counting human identities in a customer's Entra ID tenant. The data collected is used for licensing Rubrik's products. The script connects to the Microsoft Graph API to identify and categorize all user accounts, service principals, and applications to determine the number of unique human users.

### Features

-   **Microsoft Graph Integration**: Connects to Microsoft Graph with the necessary permissions to read identity data.
-   **User Activity Analysis**: Identifies inactive users based on 180 days of inactivity to help differentiate between active and dormant human users.
-   **Service Account Identification**: Flags potential service accounts based on naming patterns in their User Principal Name (UPN) to exclude them from the human identity count.
-   **Identity Type Classification**: Classifies each user into one of four mutually exclusive identity types based on `UserType`, `OnPremisesSyncEnabled`, and `CreationType` properties from Microsoft Graph:

    | Identity Type | Description | Example |
    | --- | --- | --- |
    | **Hybrid Member** | Member account synchronized from an on-premises Active Directory via Entra Connect | An employee created in corp AD and synced to Entra ID |
    | **Cloud Member** | Member account created directly in Entra ID (not synced from AD) | An employee provisioned in the cloud without on-premises AD |
    | **B2B Guest** | External account invited via B2B collaboration | A partner or contractor invited by email into the tenant |
    | **CIAM** | Consumer identity from Entra External ID or Azure AD B2C | An end-customer signing up on a customer-facing portal |

    The **Source AD** column complements Hybrid Members by showing which on-premises AD domain the account originates from. In the ByDomain report, Source AD is a count of distinct AD source domains — e.g., a domain with 50 Hybrid Members and Source AD = 2 means those accounts come from 2 different AD forests.
-   **Application and Service Principal Ownership**: Optionally performs a deep scan to count the number of applications and service principals owned by each user, which helps in distinguishing human from non-human accounts.
-   **Comprehensive Reporting**: Generates reports in two modes:
    -   `Full`: A detailed per-user report.
    -   `Summary`: An aggregated report by domain.
-   **Multiple Export Formats**: Exports reports in both CSV and a user-friendly HTML format, which can be shared with Rubrik.
-   **Automated Module Installation**: Checks for and installs the required Microsoft Graph PowerShell modules if they are not already present.
-   **Logging**: Creates a detailed log file for each execution.

### Prerequisites

-   **PowerShell Version**: 7.0 or later.
-   **Microsoft Graph Modules**: The script requires the following PowerShell modules:
    -   `Microsoft.Graph.Users`
    -   `Microsoft.Graph.Applications`
    -   `Microsoft.Graph.Identity.DirectoryManagement`
    The script will attempt to install these modules automatically if they are missing.
-   **Permissions**: The user running the script must have permissions to grant consent for the required Microsoft Graph API scopes (`User.Read.All`, `Directory.Read.All`, `Application.Read.All`, `AuditLog.Read.All`). This may require an administrator account.

### Parameters

| Parameter                       | Description                                                                                                              | Required | Default Value |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------- | ------------- |
| `UserServiceAccountNamesLike`   | An array of wildcard patterns to identify service accounts by their UPN. Patterns are used as-is with `-like`, so include wildcards explicitly (e.g., `"*svc*"` for contains-match, `"svc-*"` for prefix-match). | No       | None          |
| `Mode`                          | The reporting mode. `Full` for a detailed per-user report or `Summary` for an aggregated report.                         | Yes      | `Full`        |
| `CheckOwnership`                | When present, enables the check for application and service principal ownership. This is time-consuming on large tenants. | No       | Not present   |

### Usage Examples

**Example 1: Generate a full report with ownership analysis.**

```powershell
.\Get-EntraHumanIdentity.ps1 -Mode Full -CheckOwnership
```

**Example 2: Generate a summary report, identifying service accounts with "svc-" in their UPN.**

```powershell
.\Get-EntraHumanIdentity.ps1 -Mode Summary -UserServiceAccountNamesLike "*svc*"
```

### Report Columns

#### Per-User Report (ByUser)

| Column | Description |
| --- | --- |
| Directory | The domain associated with the user (resolved from mail, identities, or UPN for guests; from on-premises domain for synced users). |
| User | The user's account name (the part before @ in the UPN). |
| Account Enabled | 1 if the account is enabled in Entra ID, 0 if disabled. |
| Account Disabled | 1 if the account is disabled, 0 otherwise. |
| Active Identity | 1 if the user has signed in within the last 180 days, 0 otherwise. Disabled accounts are never marked active. |
| Inactive Identity | 1 if the user has not signed in within the inactivity period or has never signed in. Disabled accounts are never marked inactive (they are simply disabled). |
| Never Logged In | 1 if no sign-in activity has ever been recorded for this account, 0 otherwise. |
| Service Account Pattern | 1 if the user's UPN matches one of the patterns specified in `-UserServiceAccountNamesLike`, 0 otherwise. |
| Licensed Identity | 1 if the user qualifies for Rubrik licensing (Member AND Enabled AND Active AND not a pattern-matched service account), 0 otherwise. |
| Source AD | The on-premises AD domain name for synced accounts, N/A for cloud-only accounts. |
| Hybrid Member | 1 if the user is a member synced from on-premises AD (OnPremisesSyncEnabled = true), 0 otherwise. |
| Cloud Member | 1 if the user is a cloud-only member (UserType = Member, not synced from AD, not CIAM), 0 otherwise. |
| B2B Guest | 1 if the user is an external B2B guest (UserType = Guest, not CIAM), 0 otherwise. |
| CIAM | 1 if the user is a CIAM/consumer identity (CreationType = LocalAccount), 0 otherwise. |
| App owned by User | *(only with `-CheckOwnership`)* Number of Entra ID application registrations owned by this user. |
| SP owned by User | *(only with `-CheckOwnership`)* Number of service principals (enterprise apps) owned by this user. |
| Managed Identity | *(only with `-CheckOwnership`)* Number of managed identities owned by this user. |

#### Per-Domain Report (ByDomain)

| Column | Description |
| --- | --- |
| Directory | The domain name. |
| Total Users | Total number of user accounts associated with this domain. |
| Account Enabled | Number of enabled accounts. |
| Account Disabled | Number of disabled accounts. |
| Active Identity | Number of users who signed in within the inactivity period. |
| Inactive Identity | Number of users who have not signed in within the inactivity period. |
| Never Logged In Users | Number of accounts with no recorded sign-in. |
| Service Account Pattern | Number of accounts matching the service account naming patterns. |
| Licensed Identities | Number of users qualifying for Rubrik licensing (Member + Enabled + Active + not service account). |
| Source AD | Number of distinct on-premises AD source domains for synced accounts. |
| Hybrid Members | Number of member accounts synced from on-premises AD. |
| Cloud Members | Number of cloud-only member accounts. |
| B2B Guests | Number of external B2B guest accounts. |
| CIAM Users | Number of CIAM/consumer identity accounts. |
| Applications | Number of Entra ID application registrations published under this domain. |
| Service Principals | Number of service principals (enterprise apps) associated with this domain. |
| Managed Identities | Number of managed identities associated with this domain. |

#### Licensing Report

| Column | Description |
| --- | --- |
| Directory | The domain name. |
| Licensed Identities | Total number of users qualifying for Rubrik licensing. Formula: Member + Enabled + Active (signed in within inactivity period) + Not a service account pattern match. |
| Licensed Hybrid Members | Number of licensed hybrid (AD-synced) member identities. |
| Licensed Cloud Members | Number of licensed cloud-only member identities. |
| Licensed B2B Guests | Number of licensed B2B guest identities. |
| Licensed CIAM | Number of licensed CIAM/consumer identities. |

### Output

-   **CSV Reports**: CSV files are created in the `EntraReports` directory (e.g., `Full_ByUser_<timestamp>.csv`, `Full_ByDomain_<timestamp>.csv`).
-   **HTML Report**: A single HTML file summarizing the audit is created in the `EntraReports` directory (e.g., `Full_Report_<timestamp>.html`).
-   **Log File**: A log file named `EntraAudit_<timestamp>.log` is created in the `EntraReports` directory.

---

## `Get-OktaHumanIdentity.ps1`

This script is a Rubrik utility for counting human identities in a customer's Okta tenant. The data collected is used for licensing Rubrik's products. The script connects to the Okta Management API to identify and categorize all user accounts and applications to determine the number of unique human users.

### Features

-   **Dual Authentication**: Supports two authentication methods, selectable via parameters:
    -   **API Token (SSWS)**: Pass `-ApiToken` for non-interactive authentication using an Okta API token.
    -   **OAuth 2.0 (PKCE)**: Pass `-ClientId` for interactive browser-based login using Authorization Code + PKCE flow (no client secret required). The access token is automatically revoked at the end of the script.
-   **Okta Management API Integration**: Connects to Okta to read identity data. No external PowerShell modules required.
-   **User Activity Analysis**: Identifies inactive users based on 180 days of inactivity (configurable via `-DaysInactive`) to help differentiate between active and dormant human users.
-   **Internal vs External Users**: Distinguishes between internal users (managed by Okta, synced from AD, or LDAP) and external users (federated, social, or imported identities).
-   **Service Account Identification**: Flags potential service accounts based on naming patterns in their login to exclude them from the human identity count.
-   **AD Sync Detection**: Identifies users sourced from Active Directory via the Okta AD agent.
-   **Application Assignments** (only with `-CheckAppAssignments`): Counts unique applications assigned to users in each domain, based on per-user appLinks queries.
-   **Deprovisioned Users** (only with `-IncludeDeprovisioned`): Optionally retrieves deactivated (DEPROVISIONED) users via a separate API call and adds a dedicated column to distinguish them in the report. No impact on licensing counts.
-   **Comprehensive Reporting**: Generates reports in two modes:
    -   `Full`: A detailed per-user report and a summary by domain.
    -   `Summary`: An aggregated report by domain.
-   **Multiple Export Formats**: Exports reports in both CSV and a user-friendly HTML format with Rubrik branding, which can be shared with Rubrik.
-   **Rate Limit Handling**: Automatically handles Okta API rate limits (HTTP 429) with retry logic (up to 5 retries per request).
-   **Logging**: Creates a detailed log file for each execution.

### Prerequisites

-   **PowerShell Version**: 7.0 or later.
-   **No External Modules**: The script uses `Invoke-RestMethod` and `Invoke-WebRequest` directly. No additional PowerShell modules are required.
-   **Authentication** (one of the two):
    -   **API Token**: Generate a token in the Okta Admin Console (Security > API > Tokens). The token inherits the permissions of the admin account that created it. A Super Admin or Read-Only Admin role is recommended.
    -   **OAuth 2.0 App**: Create an OIDC Native Application in Okta Admin Console:
        1. Applications > Create App Integration > OIDC - OpenID Connect > Native Application
        2. Grant type: Authorization Code (PKCE is automatic for public clients)
        3. Sign-in redirect URI: `http://localhost:8443/callback/`
        4. Assignments: Assign to the admin user
        5. Okta API Scopes tab: Grant `okta.users.read`, `okta.apps.read`, and `okta.orgs.read`
        6. Copy the **Client ID**

### Parameters

| Parameter                       | Description                                                                                                              | Required       | Default Value                                |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------- | -------------------------------------------- |
| `OktaDomain`                    | The fully qualified domain name of your Okta tenant (e.g., `"myorg.okta.com"`).                                         | Yes            | None                                         |
| `ApiToken`                      | The Okta API token (SSWS) used to authenticate API requests. Use with ParameterSet `ApiToken`.                           | Yes (ApiToken) | None                                         |
| `ClientId`                      | The Client ID of the Okta OIDC application for OAuth 2.0 login. Use with ParameterSet `OAuth`.                          | Yes (OAuth)    | None                                         |
| `AuthorizationServerId`         | The Okta Authorization Server ID for the OAuth flow.                                                                     | No (OAuth)     | `default`                                    |
| `Scopes`                        | The OAuth 2.0 scopes to request.                                                                                         | No (OAuth)     | `openid`, `okta.users.read`, `okta.apps.read`|
| `RedirectPort`                  | The local port for the OAuth callback listener.                                                                          | No (OAuth)     | `8443`                                       |
| `UserServiceAccountNamesLike`   | An array of wildcard patterns to identify service accounts by their login. Patterns are used as-is with `-like`, so include wildcards explicitly (e.g., `"*svc*"` for contains-match, `"svc-*"` for prefix-match). | No       | None          |
| `Mode`                          | The reporting mode. `Full` for a detailed per-user report or `Summary` for an aggregated report.                         | No             | `Full`                                       |
| `DaysInactive`                  | The number of days of inactivity to classify users as inactive.                                                          | No             | 180                                          |
| `CheckAppAssignments`           | When present, retrieves the apps assigned to each user (1 API call per user). Adds "Assigned Applications" to ByUser and "Applications" to ByDomain. **WARNING: Very slow on large tenants. Not required for Rubrik licensing.** | No | Not present |
| `IncludeDeprovisioned`          | When present, retrieves deprovisioned (deactivated) users via a separate API call and adds a "Deprovisioned" column to ByUser and ByDomain. Deprovisioned users do not affect the Licensed Identity count. | No | Not present |

### Usage Examples

**Example 1: Generate a full report using an API token.**

```powershell
.\Get-OktaHumanIdentity.ps1 -OktaDomain "myorg.okta.com" -ApiToken "00abc123..." -Mode Full
```

**Example 2: Generate a full report using OAuth 2.0 interactive login.**

```powershell
.\Get-OktaHumanIdentity.ps1 -OktaDomain "myorg.okta.com" -ClientId "0oa..." -Mode Full
```

**Example 3: OAuth with a custom authorization server and service account detection.**

```powershell
.\Get-OktaHumanIdentity.ps1 -OktaDomain "myorg.okta.com" -ClientId "0oa..." -AuthorizationServerId "custom" -Mode Summary -UserServiceAccountNamesLike "*svc*"
```

**Example 4: Full report with application assignment details (slow on large tenants).**

```powershell
.\Get-OktaHumanIdentity.ps1 -OktaDomain "myorg.okta.com" -ApiToken "00abc123..." -Mode Full -CheckAppAssignments
```

**Example 5: Full report including deprovisioned users.**

```powershell
.\Get-OktaHumanIdentity.ps1 -OktaDomain "myorg.okta.com" -ApiToken "00abc123..." -Mode Full -IncludeDeprovisioned
```

### Report Columns

#### Per-User Report (ByUser)

| Column | Description |
| --- | --- |
| Directory | The domain associated with the user (extracted from the login after the @ symbol). |
| User | The user's login name (the part before @ in the login). |
| External User | 1 if the user is from an external identity provider (Federation, Social, or Import), 0 otherwise. |
| Internal User | 1 if the user is managed internally (Okta, Active Directory, or LDAP provider), 0 otherwise. |
| Account Enabled | 1 if the account status is ACTIVE, 0 otherwise. |
| Account Disabled | 1 if the account is not ACTIVE (suspended, deprovisioned, locked out, password expired, staged, provisioned), 0 otherwise. |
| Active Identity | 1 if the user has logged in within the inactivity period and the account is enabled, 0 otherwise. |
| Inactive Identity | 1 if the user has not logged in within the inactivity period and the account is enabled, 0 otherwise. |
| Never Logged In | 1 if no login activity has ever been recorded for this account, 0 otherwise. |
| Service Account Pattern | 1 if the user's login matches one of the patterns specified in `-UserServiceAccountNamesLike`, 0 otherwise. |
| Synch from AD | 1 if the account is sourced from Active Directory (credentials provider type is ACTIVE_DIRECTORY), 0 otherwise. |
| Cloud Only | 1 if the account is managed directly in Okta (credentials provider type is OKTA), 0 otherwise. |
| Licensed Identity | 1 if the user qualifies for Rubrik licensing (Internal AND Enabled AND Active AND not a pattern-matched service account), 0 otherwise. |
| Source AD | The Active Directory source name for AD-synced accounts, N/A otherwise. |
| Deprovisioned | *(only with `-IncludeDeprovisioned`)* 1 if the account status is DEPROVISIONED, 0 otherwise. |
| Assigned Applications | *(only with `-CheckAppAssignments`)* Number of applications assigned to this user. |

#### Per-Domain Report (ByDomain)

| Column | Description |
| --- | --- |
| Directory | The domain name. |
| Total Users | Total number of user accounts associated with this domain. |
| External Users | Number of external accounts (federated, social, imported). |
| Internal Users | Number of internal accounts (Okta-managed, AD-synced, LDAP). |
| Account Enabled | Number of enabled accounts (status = ACTIVE). |
| Account Disabled | Number of disabled accounts. |
| Active Identity | Number of users who logged in within the inactivity period. |
| Inactive Identity | Number of users who have not logged in within the inactivity period. |
| Never Logged In Users | Number of accounts with no recorded login. |
| Service Account Pattern | Number of accounts matching the service account naming patterns. |
| Synch from AD | Number of accounts sourced from Active Directory. |
| Cloud Only | Number of Okta-managed cloud-only accounts. |
| Licensed Identities | Number of users qualifying for Rubrik licensing (Internal + Enabled + Active + not service account). |
| Source AD | Number of distinct AD source domains for AD-synced accounts. |
| Deprovisioned | *(only with `-IncludeDeprovisioned`)* Number of deprovisioned accounts in this domain. |
| Applications | *(only with `-CheckAppAssignments`)* Number of unique application labels assigned to users in this domain. |

#### Licensing Report

| Column | Description |
| --- | --- |
| Directory | The domain name. |
| Licensed Identities | Number of users qualifying for Rubrik licensing. Formula: Internal + Enabled + Active (logged in within inactivity period) + Not a service account pattern match. |

### Output

-   **CSV Reports**: CSV files are created in the `OktaReports` directory (e.g., `Full_ByUser_<timestamp>.csv`, `Full_ByDomain_<timestamp>.csv`).
-   **HTML Report**: A single HTML file summarizing the audit is created in the `OktaReports` directory (e.g., `Full_Report_<timestamp>.html`).
-   **Log File**: A log file named `OktaAudit_<timestamp>.log` is created in the `OktaReports` directory.

---

## How to Use

1.  **Download the scripts:** Download the scripts from this repository to a machine that has access to your identity systems (Active Directory or Entra ID).
2.  **Open a PowerShell terminal.**
3.  **Run the desired script with the appropriate parameters.** Make sure you meet the prerequisites for the script you are running.
4.  **Share the generated reports with your Rubrik representative.**

## Contributing

These scripts are provided by Rubrik for licensing purposes. For support, please contact your Rubrik representative.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Author

Aymeric Jaouen
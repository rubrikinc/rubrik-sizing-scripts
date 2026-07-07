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
-   **Application Inventory**: Provides a count of applications registered in the Okta tenant.
-   **Comprehensive Reporting**: Generates reports in two modes:
    -   `Full`: A detailed per-user report and a summary by domain.
    -   `Summary`: An aggregated report by domain.
-   **Multiple Export Formats**: Exports reports in both CSV and a user-friendly HTML format with Rubrik branding, which can be shared with Rubrik.
-   **Rate Limit Handling**: Automatically handles Okta API rate limits (HTTP 429) with retry logic.
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
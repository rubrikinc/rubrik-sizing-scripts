#requires -Version 7.0
#requires -Modules Az.Accounts, Az.Compute, Az.Storage, Az.Sql, Az.SqlVirtualMachine, Az.ResourceGraph, Az.Monitor, Az.Resources, Az.RecoveryServices, Az.CostManagement, Az.CosmosDB

<#
.SYNOPSIS
Gets all Azure VM Managed Disk and/or Azure SQL information in the specified subscription(s).

.DESCRIPTION
The "Get-AzureSizingInfo.ps1" script collects metadata about resources in Azure that Rubrik supports. This includes
but is not limited to: Azure VMs, Azure VMs with Microsoft SQL, Azure Managed Disks, Azure SQL, Azure Managed Instances, 
Azure Storage Accounts, Azure Blob storage and Azure Files.

There are options to restrict where and what resources are reported on. See the parameters section for more details.

To prepare to run this script from the Azure Cloud Shell (preferred) system do the following:

  1. If you are unfamiliar with Azure Cloud Shell go to this link to learn about it:
      https://docs.microsoft.com/en-us/azure/cloud-shell/overview

  2.  Verify that the Azure AD account that will be used to run this script has the "Reader" and "Reader and Data Access"
      roles on each subscription to be scanned.

  3. Login to the Azure Portal using the user that was verified above.
  
  4. Open the Azure Cloud Shell

  5. Install the Azure CostManagement module by running the following command:

      "Install-Module Az.CostManagement"
  
  6. Upload the "Get-AzureSizingInfo.ps1" script using Azure Cloud Shell.

To prepare to run this script from a local system do the following:

  1. Install Powershell 7
  
  2. Install the Azure Powershell modules that are required by this script by running the command:

      "Install-Module Az.Accounts,Az.Compute,Az.Storage,Az.Sql,Az.SqlVirtualMachine,Az.ResourceGraph,Az.Monitor,Az.Resources,Az.RecoveryServices,Az.CostManagement,Az.CosmosDB"
  
  3. Verify that the Azure AD account that will be used to run this script has the "Reader" and "Reader and Data Access"
      roles on each subscription to be scanned. 

  4. Login to Azure from Powershell by running the command:

      "Connect-AzAccount"
      

  5. Run this script with the appropriate options. Example:
  
      ".\Get-AzureSizingInfo.ps1"

To run the script in the Azure Cloud Shell or locally do the following:

  1. Run this script with the appropriate options. For example this command will collect data from all
      subscriptions that the user currently has access to:

      ".\Get-AzureSizingInfo.ps1"

A summary of the information found by this script will be sent to console.
One or more CSV files will be saved to the same directory where the script ran with the detailed information.
Please copy/paste the console output and send it along with the CSV files to the person that asked you to run
this script.

.PARAMETER AllSubscriptions
Flag (default) to find all subscriptions that the user has access to and gather data.

.PARAMETER CurrentSubscription
Flag to only gather information from the current subscription.

.PARAMETER GetContainerDetails
Performs a deep introspection of each container in blob storage and calculates various statistics. Using this parameter 
may take a long time when large blob stores are located.


.PARAMETER ManagementGroups
A comma separated list of Azure Management Groups to gather data from.

.PARAMETER GetKeyVaultAmounts
Gets number of key vaults, and amount of certificates, keys, and secrets in each key vault. One must add the 
permission 'Key Vault Reader' to each subscription in order to use the flag

.PARAMETER SkipAzureBackup
Do not collect data on Azure Backup Vaults, Policies, Items, and cost.

.PARAMETER SkipAzureFiles
Do not collect data on Azure Files.

.PARAMETER SkipAzureSQLandMI
Do not collect data on Azure SQL or Azure Managed Instances

.PARAMETER SkipAzureStorageAccounts
Do not collect data on Azure Storage Accounts. This includes not collecting data on Azure Blob storage and Azure Files.

.PARAMETER SkipAzureVMandManagedDisks
Do not collect data on Azure VMs or Managed Disks.

.PARAMETER SkipAzureCosmosDB
Do not collect data on Azure CosmosDB.

.PARAMETER Subscriptions
A comma separated list of subscriptions to gather data from.

.PARAMETER SubscriptionIds
A comma separated list of ids of the subscriptions to gather data from.

.PARAMETER Anonymize
Anonymize data collected.

.PARAMETER AnonymizeFields
  A comma separated list of fields in resulting CSVs and JSONs to anonymize. The list must be encased in
  quotes, with no spaces between fields.

.PARAMETER NotAnonymizeFields
  A comma separated list of fields in resulting CSVs and JSONs to not anonymize (only required for fields which are by default being 
  anonymized). The list must be encased in quotes, with no spaces between fields.
  Note that we currently anonymize the following fields:
  "SubscriptionId", "Subscription", "Tenant", "Name", 
  "ResourceGroup", "VirtualMachineId", "PolicyId", "ProtectionPolicyName", "Id",
  "SourceResourceId", "ContainerName", "FriendlyName", "ServerName", "ParentName",
  "ProtectedItemDataSourceId",  "StorageAccount", "Database", "Server", "ElasticPool",
  "ManagedInstance", "DatabaseID", "vmID"

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 2/19/22
Updated by stevenctong: 7/13/22
Updated by stevenctong: 10/20/22
Updated by DamaniN: 01/25/23 -  Added support for Azure Mange Groups
Updated by DamaniN: 07/18/23 -  Fixed 25 subscription limit for -AllSubscriptions options
Updated by DamaniN: 07/20/23 -  Added support for Microsoft SQL in an Azure VM.
                                Added support for Azure Files.
                                Added Support for Azure SQL Managed Instances
                                Changed default collection to AllSubscriptions.
                                Improved status reporting
Updated by DamaniN: 11/3/23 -   Updated install/deployment documentation - Damani
                                Added support for Azure Blob stores
                                Added parameters to skip the collection of various Azure services
Updated by DamaniN: 1/31/24 -   Added support for Azure Backup Vaults, Policies, and Items
                                
If you run this script and get an error message similar to this:

./Get-AzureSizingInfo.ps1: The script "Get-AzureSizingInfo.ps1" cannot be run because the following
modules that are specified by the "#requires" statements of the script are missing: Az.ResourceGraph.

Install the missing module by using the Install-Module command in the instructions for local deployment.

If you run  this script and get an error message similar to this:

  Write-Error: Error getting Azure File Storage information from: mystorageaccount storage account.

  Get-AzStorageShare: Get-AzureSizingInfo.ps1:604:20                     
  Line |                                                                                                                  
  604 |  …    $azFSs = Get-AzStorageShare -Context $azSAContext -ErrorAction Sto …                                
      | This request is not authorized to perform this operation. RequestId:12345678-90ab-cdef-1234-567890abcdef 
      | Time:2023-11-13T06:31:07.0875480Z Status: 403 (This request is not authorized to perform this operation.)
      | ErrorCode: AuthorizationFailure  Content: <?xml version="1.0"
      | encoding="utf-8"?><Error><Code>AuthorizationFailure</Code><Message>This request is not authorized to perform
      | this operation. RequestId:12345678-90ab-cdef-1234-567890abcdef Time:2023-11-13T06:31:07.0875480Z</Message></Error> 
      | Headers: Server: Microsoft-HTTPAPI/2.0 x-ms-request-id: 12345678-90ab-cdef-1234-567890abcdef x-ms-client-request-id: 
      | 12345678-90ab-cdef-fedc-ba-0987654321 x-ms-error-code: AuthorizationFailure Date: Mon, 13 Nov 2023 06:31:06 GMT 
      | Content-Length: 246 Content-Type: application/xml

It may mean that where the script is running that it cannot read from the Azure File Share due to the network ACLs. The 
Azure File Share may not have public access or may only be accessible via a private endpoint. If this error only
affects a few shares you may ignore it and report it back to the person who sent the script. If the statistics in the
Azure File share need to be collected, either re-run the script from a system that has network access to the Azure File 
Share, or enable public access to the Azure File Share.

.EXAMPLE
./Get-AzureSizingInfo.ps1
Runs the script against the all subscriptions that the user has access to.

.EXAMPLE
./Get-AzureSizingInfo.ps1 -Subscriptions "sub1,sub2"
Runs the script against subscriptions "sub1" and "sub2".

.EXAMPLE
./Get-AzureSizingInfo.ps1 -CurrentSubscription
Runs the script against the default subscription for the currently logged in user. 

.EXAMPLE
./Get-AzureSizingInfo.ps1 -ManagementGroups "Group1,Group2"
Runs the script against Azure Management Groups "Group1" and "Group2".

.EXAMPLE
./Get-AzureSizingInfo.ps1 -SkipAzureStorageAccounts
Runs the script against all subscriptions in the that the user has access to but skips the collection of Azure Storage Account data.

.EXAMPLE
./Get-AzureSizingInfo.ps1 -Subscriptions "sub1" -GetContainerDetails
Runs the script against the subscription "sub1" and does a deeper inspection of Azure blob storage

.LINK
https://build.rubrik.com
https://github.com/rubrikinc
https://github.com/stevenctong/rubrik
https://docs.microsoft.com/en-us/azure/cloud-shell/overview
#>

param (
  [CmdletBinding(DefaultParameterSetName = 'AllSubscriptions')]

  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$GetContainerDetails,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$GetKeyVaultAmounts,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureBackup,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureFiles,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureSQLandMI,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureStorageAccounts,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureVMandManagedDisks,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureCosmosDB,
  [Parameter(ParameterSetName='CurrentSubscription',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [switch]$CurrentSubscription,
  [Parameter(ParameterSetName='Subscriptions',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$Subscriptions = '',
  [Parameter(ParameterSetName='SubscriptionIds',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$SubscriptionIds = '',
  [Parameter(ParameterSetName='AllSubscriptions',
    Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$AllSubscriptions,
  [Parameter(ParameterSetName='ManagementGroups',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$ManagementGroups,
  # Option to anonymize the output files.
  [Parameter(Mandatory=$false)]
  [switch]$Anonymize,
  # Choose to anonymize additional fields
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$AnonymizeFields,
  # Choose to not anonymize certain fields
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$NotAnonymizeFields
)

# Save the current culture so it can be restored later
$CurrentCulture = [System.Globalization.CultureInfo]::CurrentCulture

# Set the culture to en-US; this is to ensure that output to CSV is formatted properly
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

$azConfig = Get-AzConfig -DisplayBreakingChangeWarning 
Update-AzConfig -DisplayBreakingChangeWarning $false | Out-Null

$date = Get-Date
$date_string = $($date.ToString("yyyy-MM-dd_HHmmss"))

$output_log = "output_azure_$date_string.log"

if (Test-Path "./$output_log") {
  Remove-Item -Path "./$output_log"
}

if($Anonymize){
  "Anonymized file; customer has original. Request customer to sanitize and provide output log if needed" > $output_log
  $log_for_anon_customers = "output_azure_not_anonymized_$date_string.log"
  Start-Transcript -Path "./$log_for_anon_customers"
} else{
  Start-Transcript -Path "./$output_log"
}


$archiveFile = "azure_sizing_results_$($date.ToString('yyyy-MM-dd_HHmm')).zip"

Import-Module Az.Accounts, Az.Compute, Az.Storage, Az.Sql, Az.SqlVirtualMachine, Az.ResourceGraph, Az.Monitor, Az.Resources, Az.RecoveryServices, Az.CostManagement

function Generate-VMKey {
  param (
      [string]$vmName,
      [string]$subName,
      [string]$tenantName,
      [string]$region
  )
  return "$vmName|$subName|$tenantName|$region"
}

function Get-AzureFileSAs {
  param (
      [Parameter(Mandatory=$true)]
      [PSObject]$StorageAccount
  )

  return ($StorageAccount.Kind -in @('StorageV2', 'Storage') -and 
            $StorageAccount.Sku.Name -notin @('Premium_LRS', 'Premium_ZRS')) -or
           ($StorageAccount.Kind -eq 'FileStorage' -and 
            $StorageAccount.Sku.Name -in @('Premium_LRS', 'Premium_ZRS'))
}

try{

# Filenames of the CSVs to output
$fileDate = $date.ToString("yyyy-MM-dd_HHmm")
$outputVmDisk = "azure_vmdisk_info-$($fileDate).csv"
$outputSQL = "azure_sql_info-$($fileDate).csv"
$outputMI = "azure_mi_sql_info-$($fileDate).csv"
$outputMiDbLtrStrJSON = "azure_mi_db_items-$($fileDate).json"
$outputAzSA = "azure_storage_account_info-$($fileDate).csv"
$outputAzCon = "azure_container_info-$($fileDate).csv"
$outputAzFS = "azure_file_share_info-$($fileDate).csv"
$outputAzVaults = "azure_backup_vault_info-$($fileDate).csv"
#$outputAzVaultVMPolicies = "azure_backup_vault_VM_policies-$($fileDate).csv"
$outputAzVaultVMPoliciesJSON = "azure_backup_vault_VM_policies-$($fileDate).json"
#$outputAzVaultVMSQLPolicies = "azure_backup_vault_VM_SQL_policies-$($fileDate).csv"
$outputAzVaultVMSQLPoliciesJSON = "azure_backup_vault_VM_SQL_policies-$($fileDate).json"
#$outputAzVaultAzureSQLDatabasePolicies = "azure_backup_vault_Azure_SQL_Database_Policies-$($fileDate).csv"
$outputAzVaultAzureSQLDatabasePoliciesJSON = "azure_backup_vault_Azure_SQL_Database_Policies-$($fileDate).json"
#$outputAzVaultAzureFilesPolicies = "azure_backup_vault_Azure_Files_Policies-$($fileDate).csv"
$outputAzVaultAzureFilesPoliciesJSON = "azure_backup_vault_Azure_Files_Policies-$($fileDate).json"
$outputAzVaultVMItems = "azure_backup_vault_VM_items-$($fileDate).csv"
$outputAzVaultVMSQLItem = "azure_backup_vault_VM_SQL_items-$($fileDate).csv"
$outputAzVaultAzureSQLDatabaseItems = "azure_backup_vault_Azure_SQL_Database_items-$($fileDate).csv"
$outputAzVaultAzureFilesItems = "azure_backup_vault_Azure_Files_items-$($fileDate).csv"
$outputAzVaultBackupCostsItems = "azure_backup_costs-$($fileDate).csv"
$outputAzCosmosDB = "azure_cosmos_db-$($fileDate).csv"
$outputAzKeyVault = "azure_key_vault-$($fileDate).csv"
$outputFiles = @()

Write-Host "Current identity:" -ForeGroundColor Green
$context = Get-AzContext
$context | Select-Object -Property Account,Environment,Tenant |  format-table

# Arrays for collecting data.
$azLabels = @()
$vmList = @{}
$sqlList = @()
$miList = @()
$miPolicies = @{}
$azSAList = @()
$azConList = @()
$azFSList = @()
$azVaultList = @()
$azVaultVMPoliciesList = @()
$azVaultVMSQLPoliciesList = @()
$azVaultAzureSQLDatabasePoliciesList = @()
$azVaultAzureFilesPoliciesList = @()
$azVaultVMItems = @()
$azVaultVMSQLItems = @()
$azVaultAzureSQLDatabaseItems = @()
$azVaultAzureFilesItems = @()
$backupCostDetails = @()
$cosmosDBs = @()
$keyVaultList = @()

switch ($PSCmdlet.ParameterSetName) {
  'Subscriptions' {
    Write-Host "Finding specified subscription(s)..." -ForegroundColor Green
    $subs = @()
    foreach ($subscription in $Subscriptions.split(',')) {
      Write-Host "Getting subscription information for: $($subscription)..."
      try {
        $subs = $subs + $(Get-AzSubscription -SubscriptionName "$subscription" -TenantId $context.Tenant.Id -ErrorAction Stop)
      } catch {
        Write-Error "Unable to get subscription information for subscription: $($subscription)"
        $_
        Continue
      }
    }
  }
  'SubscriptionIds' {
    Write-Host "Finding specified subscription(s)..." -ForegroundColor Green
    $subs = @()
    foreach ($subscription in $SubscriptionIds.split(',')) {
      Write-Host "Getting subscription information for: $($subscription)..."
      try {
        $subs = $subs + $(Get-AzSubscription -SubscriptionId "$subscription" -TenantId $context.Tenant.Id -ErrorAction Stop)
      } catch {
        Write-Error "Unable to get subscription information for subscription: $($subscription)"
        $_
        Continue
      }
    }
  }
  'AllSubscriptions' {
    Write-Host "Finding all subscription(s)..." -ForegroundColor Green
    try {
      $subs =  Get-AzSubscription -TenantId $context.Tenant.Id -ErrorAction Stop
    } catch {
      Write-Error "Unable to get subscription information."
      $_
      Write-Host "Exiting..." -ForegroundColor Green
      exit      
    }
  } 
  'CurrentSubscription' {
    # If no subscription is specified, only use the current subscription
    Write-Host "Gathering subscription information for $($context.Subscription.Name) ..." -ForegroundColor Green
    try {
      $subs = Get-AzSubscription -TenantId $context.Tenant.Id -SubscriptionName $context.Subscription.Name -ErrorAction Stop
    } catch {
      Write-Error "Unable to get subscription information from current subscription: $($context.Subscription.Name)"
      $_
      Write-Host "Exiting..." -ForegroundColor Green
      exit
    }
  }
  'ManagementGroups' {
    # If Azure Management Groups are used, look for all subscriptions in the Azure Management Group
    Write-Host "Gathering subscription information from Management Groups..." -ForegroundColor Green
    $subs = @()
    foreach ($managementGroup in $ManagementGroups) {
      try {
        $subs = $subs + $(Get-AzSubscription -TenantId $context.Tenant.Id -SubscriptionName $(Search-AzGraph -Query "ResourceContainers | where type =~ 'microsoft.resources/subscriptions'" -ManagementGroup $managementGroup).name -ErrorAction Stop)
      } catch {
        Write-Error "Unable to gather subscriptions from Management Group: $($managementGroup)"
        $_
        Continue
      }
    }
  }
}

# Get label keys from all specified subscriptions

$subNum=1
$processedSubs=0
Write-Host "Getting label information from $($subs.Count) subscription(s)..." -ForeGroundColor Green
foreach ($sub in $subs) {
  Write-Progress -Id 1 -Activity "Getting label information from subscription: $($sub.Name)" -PercentComplete $(($subNum/$subs.Count)*100) -Status "Subscription $($subNum) of $($subs.Count)"
  $subNum++

  try {
    Set-AzContext -SubscriptionName $sub.Name -TenantId $context.Tenant.Id -ErrorAction Stop | Out-Null
  } catch {
    Write-Error "Error switching to subscription: $($sub.Name)"
    Write-Error $_
    Continue
  }

  $azLabels += $(Get-AzTag).Name
} # foreach ($sub in $subs)
Write-Progress -Id 1 -Activity "Getting label information from subscription: $($sub.Name)" -Completed

$uniqueAzLabels = $azLabels | Sort-Object -Unique

# Get Azure information for all specified subscriptions
$subNum=1
$processedSubs=0
Write-Host "Processing $($subs.Count) subscription(s)..." -ForeGroundColor Green
foreach ($sub in $subs) {
  Write-Progress -Id 1 -Activity "Getting information from subscription: $($sub.Name)" -PercentComplete $(($subNum/$subs.Count)*100) -Status "Subscription $($subNum) of $($subs.Count)"
  $subNum++

  try {
    Set-AzContext -SubscriptionName $sub.Name -TenantId $context.Tenant.Id -ErrorAction Stop | Out-Null
  } catch {
    Write-Error "Error switching to subscription: $($sub.Name)"
    Write-Error $_
    Continue
  }

  #Get tenant name for subscription
  try {
    $tenant = Get-AzTenant -TenantId $($sub.TenantId) -ErrorAction Stop
  } catch {
    Write-Error "Error getting tenant information for: $($sub.TenantId))"
    Write-Error $_
    Continue
  }
  $processedSubs++

  if ($SkipAzureVMandManagedDisks -ne $true) {
    # Get a list of all VMs in the current subscription
    try {
      $vms = Get-AzVM -ErrorAction Stop
    } catch {
      Write-Error "Unable to get VMs for Subscription: $($sub.Name)"
      $_
      Continue
    }

    # Loop through each VM to get all disk info
    $vmNum=1
    foreach ($vm in $vms) {
      Write-Progress -Id 2 -Activity "Getting VM information for: $($vm.Name)" -PercentComplete $(($vmNum/$vms.Count)*100) -ParentId 1 -Status "VM $($vmNum) of $($vms.Count)"
      $vmNum++
      # Count of and size of all disks attached to the VM
      $diskNum = 0
      $diskSizeGiB = 0
      # Loop through each OS disk on the VM and add to the disk info
      foreach ($osDisk in $vm.StorageProfile.osdisk) {
        $diskNum += 1
        $diskSizeGiB += [int]$osDisk.DiskSizeGB
      }
      # Loop through each data disk on the VM and add to the disk info
      foreach ($dataDisk in $vm.StorageProfile.dataDisks) {
        $diskNum += 1
        $diskSizeGiB += [int]$dataDisk.DiskSizeGB
      }

      $vmObj = [ordered] @{}
      $vmObj.Add("Name",$vm.Name)
      $vmObj.Add("Disks",$diskNum)
      $vmObj.Add("SizeGiB",$diskSizeGiB)
      $vmObj.Add("SizeTiB",[math]::round($($diskSizeGiB / 1024), 4))
      $vmObj.Add("SizeGB",[math]::round($($diskSizeGiB * 1.073741824), 3))
      $vmObj.Add("SizeTB",[math]::round($($diskSizeGiB * 0.001073741824), 4))
      $vmObj.Add("Subscription",$sub.Name)
      $vmObj.Add("Tenant",$tenant.Name)
      $vmObj.Add("Region",$vm.Location)
      $vmObj.Add("ResourceGroup",$vm.ResourceGroupName)
      $vmObj.Add("vmID",$vm.vmID)
      $vmObj.Add("InstanceType",$vm.HardwareProfile.vmSize)
      $vmObj.Add("Status",$vm.StatusCode)
      $vmObj.Add("HasMSSQL","No")
      $vmObj.Add("BackupPolicies", "-")
      $vmObj.Add("InBackupPolicy", $false)

      # Loop through possible labels adding the property if there is one, adding it with a hyphen as it's value if it doesn't.
      if ($vm.Labels.Count -ne 0) {
        $uniqueAzLabels | Foreach-Object {
            if ($vm.Labels[$_]) {
                $vmObj.Add("Label/Tag: $_",$vm.Labels[$_])
            }
            else {
                $vmObj.Add("Label/Tag: $_","-")
            }
        }
      } else {
          $uniqueAzLabels | Foreach-Object { $vmObj.Add("Label/Tag: $_","-") }
      }
      $vmKey = Generate-VMKey -vmName $vm.Name -subName $sub.Name -tenantName $tenant.Name -region $vm.Location
      $vmList[$vmKey] = $vmObj
    }
    Write-Progress -Id 2 -Activity "Getting VM information for: $($vm.Name)" -Completed

    # Get a list of all VMs that have MSSQL in them.
    try {
      $sqlVms = Get-AzSQLVM
    } catch {
      Write-Error "Unable to collect SQL VM information for subscription: $($sub.Name) under tenant $($tenant.Name)"
      $_
      Continue
    }

    # Loop through each SQL VM to and update VM status
    $sqlVmNum=1
    foreach ($sqlVm in $sqlVms) {
      Write-Progress -Id 3 -Activity "Getting SQL VM information for: $($sqlVm.Name)" -PercentComplete $(($sqlVmNum/$sqlVms.Count)*100) -ParentId 1 -Status "SQL VM $($sqlVmNum) of $($sqlVms.Count)"
      $sqlVmNum++
      $vmKey = Generate-VMKey -vmName $sqlVm.Name -subName $sub.Name -tenantName $tenant.Name -region $sqlVm.Location
      if($vmList.containsKey($vmKey)){
        $vmList[$vmKey].HasMSSQL = "Yes"
      } else{
        Write-Host "Not reporting sizing for SQL VM: $vmKey"
      }
      # if ($vmToUpdate = $vmList.values | Where-Object { $_.Name -eq $sqlVm.Name }) {
      #   $vmToUpdate.HasMSSQL = "Yes"
      # } 
    }
    Write-Progress -Id 3 -Activity "Getting VM information for: $($vm.Name)" -Completed
  } #if ($SkipAzureVMandManagedDisks -ne $true) 
  
  if ($SkipAzureSQLandMI -ne $true) {
    # Get all Azure SQL servers
    try {
      $sqlServers = Get-AzSqlServer -ErrorAction Stop
    } catch {
      Write-Error "Unable to collect Azure SQL Server information for subscription: $($sub.Name) under tenant $($tenant.Name)"
      $_
      Continue    
    }

    # Loop through each SQL server to get size info
    $sqlServerNum=1
    foreach ($sqlServer in $sqlServers) {
      Write-Progress -Id 4 -Activity "Getting Azure SQL information for SQL Server: $($sqlServer.ServerName)" -PercentComplete $(($sqlServerNum/$sqlServers.Count)*100) -ParentId 1 -Status "Azure SQL Server $($sqlServerNum) of $($sqlServers.Count)"
      $sqlServerNum++
      # Get all SQL DBs on the current SQL server
      try {
        $sqlDBs = Get-AzSqlDatabase -serverName $sqlServer.ServerName -ResourceGroupName $sqlServer.ResourceGroupName -ErrorAction Stop
      }
      catch {
        Write-Error "Unable to collect Azure SQL Server database information for Azure SQL Database server: $($sqlServer.ServerName) in subscription $($sub.Name) under tenant $($tenant.Name)"
        $_
        Continue    
      }
      # Loop through each SQL DB on the current SQL server to gather size info
      foreach ($sqlDB in $sqlDBs) {
        # Only count SQL DBs that are not SYSTEM DBs
        if ($sqlDB.SkuName -ne 'System') {
          # If SQL DB is in an Elastic Pool, count the max capacity of Elastic Pool and not the DB
          if ($sqlDB.SkuName -eq 'ElasticPool') {
            # Get Elastic Pool information for the current DB
            try {
              $pools = Get-AzSqlElasticPool  -ServerName $sqlDB.ServerName -ResourceGroupName $sqlDB.ResourceGroupName -ErrorAction Stop
            }
            catch {
              Write-Error "Unable to collect Azure SQL Server Elastic Pool information for Azure SQL Database server: $($sqlServer.ServerName) in subscription $($sub.Name) under tenant $($tenant.Name)"
              $_
              Continue    
            }
            # Loop through the pools on the current database.
            foreach ($pool in $pools) {
              # Check if the current Elastic Pool already exists in the SQL list
              $poolName = $sqlList | Where-Object -Property 'ElasticPool' -eq $pool.ElasticPoolName
              # If Elastic Pool does not exist then add it
              if ($null -eq $poolName) {
                $sqlObj = [ordered] @{}
                $sqlObj.Add("Database","")
                $sqlObj.Add("Server","")
                $sqlObj.Add("ElasticPool",$pool.ElasticPoolName)
                $sqlObj.Add("ManagedInstance","")
                $sqlObj.Add("MaxSizeGiB",[math]::round($($pool.MaxSizeBytes / 1073741824), 0))
                $sqlObj.Add("MaxSizeTiB",[math]::round($($pool.MaxSizeBytes / 1073741824 / 1024), 4))
                $sqlObj.Add("MaxSizeGB",[math]::round($($pool.MaxSizeBytes / 1000000000), 3))
                $sqlObj.Add("MaxSizeTB",[math]::round($($pool.MaxSizeBytes / 1000000000000), 4))
                $sqlObj.Add("Subscription",$sub.Name)
                $sqlObj.Add("Tenant",$tenant.Name)
                $sqlObj.Add("Region",$pool.Location)
                $sqlObj.Add("ResourceGroup",$pool.ResourceGroupName)
                $sqlObj.Add("DatabaseID","")
                $sqlObj.Add("InstanceType",$pool.SkuName)
                $sqlObj.Add("Status",$pool.Status)

                # Loop through possible labels adding the property if there is one, adding it with a hyphen as it's value if it doesn't.
                if ($pool.Labels.Count -ne 0) {
                  $uniqueAzLabels | Foreach-Object {
                      if ($pool.Labels[$_]) {
                          $sqlObj.Add("Label/Tag: $_)",$pool.Labels[$_])
                      }
                      else {
                          $sqlObj.Add("Label/Tag: $_","-")
                      }
                  }
                } else {
                    $uniqueAzLabels | Foreach-Object { $sqlObj.Add("Label/Tag: $_","-") }
                }
                $sqlList += New-Object -TypeName PSObject -Property $sqlObj
              }
            } #foreach ($pool in $pools)
          } else {
            $sqlObj = [ordered] @{}
            $sqlObj.Add("Database",$sqlDB.DatabaseName)
            $sqlObj.Add("Server",$sqlDB.ServerName)
            $sqlObj.Add("ElasticPool","")
            $sqlObj.Add("ManagedInstance","")
            $sqlObj.Add("MaxSizeGiB",[math]::round($($sqlDB.MaxSizeBytes / 1073741824), 0))
            $sqlObj.Add("MaxSizeTiB",[math]::round($($sqlDB.MaxSizeBytes / 1073741824 / 1024), 4))
            $sqlObj.Add("MaxSizeGB",[math]::round($($sqlDB.MaxSizeBytes / 1000000000), 3))
            $sqlObj.Add("MaxSizeTB",[math]::round($($sqlDB.MaxSizeBytes / 1000000000000), 4))
            $sqlObj.Add("Subscription",$sub.Name)
            $sqlObj.Add("Tenant",$tenant.Name)
            $sqlObj.Add("Region",$sqlDB.Location)
            $sqlObj.Add("ResourceGroup",$sqlDB.ResourceGroupName)
            $sqlObj.Add("DatabaseID",$sqlDB.DatabaseId)
            $sqlObj.Add("InstanceType",$sqlDB.SkuName)
            $sqlObj.Add("Status",$sqlDB.Status)

            $sqlAllocatedBytes = (
              (Get-AzMetric -WarningAction SilentlyContinue `
              -ResourceId $sqlDB.ResourceId `
              -MetricName "allocated_data_storage" `
              -AggregationType Maximum `
              -StartTime (Get-Date).AddDays(-1))
            )
            $sqlUsedBytes = (
                (Get-AzMetric  -WarningAction SilentlyContinue `
                -ResourceId $sqlDB.ResourceId `
                -MetricName "storage" `
                -AggregationType Maximum `
                -StartTime (Get-Date).AddDays(-1))
            )
            $sqlAllocatedAvg = ($sqlAllocatedBytes.Data.Maximum | Select-Object -Last 1)
            $sqlUsedAvg = ($sqlUsedBytes.Data.Maximum | Select-Object -Last 1)

            $sqlObj.Add("Allocated_Bytes", $sqlAllocatedAvg)
            $sqlObj.Add("Utilized_Bytes", $sqlUsedAvg)

            $ltrPolicy = @{}
            try {
              if ($sqlDB.DatabaseName -eq "master"){
                $ltrPolicy = Get-AzSqlDatabaseBackupLongTermRetentionPolicy -ServerName $sqlDB.ServerName -DatabaseName $sqlDB.DatabaseName -ResourceGroupName $sqlDB.ResourceGroupName -ErrorAction SilentlyContinue
              } elseif($sqlObj.InstanceType -eq "DataWarehouse"){
                $ltrPolicy = Get-AzSqlDatabaseBackupLongTermRetentionPolicy -ServerName $sqlDB.ServerName -DatabaseName $sqlDB.DatabaseName -ResourceGroupName $sqlDB.ResourceGroupName -ErrorAction SilentlyContinue
              } else{
                $ltrPolicy = Get-AzSqlDatabaseBackupLongTermRetentionPolicy -ServerName $sqlDB.ServerName -DatabaseName $sqlDB.DatabaseName -ResourceGroupName $sqlDB.ResourceGroupName -ErrorAction Stop
              }
            } catch {
              if ($sqlDB.DatabaseName -ne "master") {
                Write-Host "Failed to get Long Term Retention Policy for DB $($sqlDB.DatabaseName), Server $($sqlDB.ServerName) in sub $($sub.Name) in tenant $($tenant.Name) in $($sqlDB.Location)" -ForeGroundColor Red
                Write-Host "Error: $_" -ForeGroundColor Red
              } 
              # else {
              #   Write-Host "Expected error: LTR for master"
              # }
            }

            $strPolicy = @{}
            try {
              if ($sqlDB.DatabaseName -eq "master"){
                $strPolicy = Get-AzSqlDatabaseBackupShortTermRetentionPolicy -ServerName $sqlDB.ServerName -DatabaseName $sqlDB.DatabaseName -ResourceGroupName $sqlDB.ResourceGroupName -ErrorAction SilentlyContinue
              } elseif($sqlObj.InstanceType -eq "DataWarehouse"){
                $strPolicy = Get-AzSqlDatabaseBackupShortTermRetentionPolicy -ServerName $sqlDB.ServerName -DatabaseName $sqlDB.DatabaseName -ResourceGroupName $sqlDB.ResourceGroupName -ErrorAction SilentlyContinue
              } else{
                $strPolicy = Get-AzSqlDatabaseBackupShortTermRetentionPolicy -ServerName $sqlDB.ServerName -DatabaseName $sqlDB.DatabaseName -ResourceGroupName $sqlDB.ResourceGroupName -ErrorAction Stop
              }
            } catch {
              if ($sqlDB.DatabaseName -ne "master") {
                Write-Host "Failed to get Short Term Retention Policy for DB $($sqlDB.DatabaseName), Server $($sqlDB.ServerName) in sub $($sub.Name) in tenant $($tenant.Name) in $($sqlDB.Location)" -ForeGroundColor Red
                Write-Host "Error: $_" -ForeGroundColor Red
              } 
              # else {
              #   Write-Host "Expected error: STR for master"
              # }
            }

            $sqlObj.Add("LTRWeeklyRetention",$ltrPolicy.WeeklyRetention)
            $sqlObj.Add("LTRMonthlyRetention",$ltrPolicy.MonthlyRetention)
            $sqlObj.Add("LTRYearlyRetention",$ltrPolicy.YearlyRetention)
            $sqlObj.Add("LTRWeekOfYear",$ltrPolicy.WeekOfYear)
            $sqlObj.Add("PITR (Days)",$strPolicy.RetentionDays)
            $sqlObj.Add("DiffBackupFrequency (Hours)",$strPolicy.DiffBackupIntervalInHours)

            # Loop through possible labels adding the property if there is one, adding it with a hyphen as it's value if it doesn't.
            if ($sqlDB.Labels.Count -ne 0) {
              $uniqueAzLabels | Foreach-Object {
                  if ($sqlDB.Labels[$_]) {
                      $sqlObj.Add("Label/Tag: $_",$sqlDB.Labels[$_])
                  }
                  else {
                      $sqlObj.Add("Label/Tag: $_","-")
                  }
              }
            } else {
                $uniqueAzLabels | Foreach-Object { $sqlObj.Add("Label/Tag: $_","-") }
            }
            $sqlList += New-Object -TypeName PSObject -Property $sqlObj
          }  # else not an Elastic Pool but normal SQL DB
        }  # if ($sqlDB.SkuName -ne 'System')
      }  # foreach ($sqlDB in $sqlDBs)
    }  # foreach ($sqlServer in $sqlServers)
    Write-Progress -Id 4 -Activity "Getting Azure SQL information for SQL Server: $($sqlServer.ServerName)" -Completed

    # Get all Azure Managed Instances
    try {
      $sqlManagedInstances = Get-AzSqlInstance -ErrorAction Stop
    } catch {
      Write-Error "Unable to collect Azure Manged Instance information for subscription: $($sub.Name) in subscription $($sub.Name) under tenant $($tenant.Name)"
      $_
      Continue    
    }

    # Loop through each SQL Managed Instances to get size info
    $managedInstanceNum=1

    # Setting up nested JSON accordingly if needed for this tenant/sub
    # JSON output is tenant -> sub -> MI -> Databases in MI
    if(-not $miPolicies.ContainsKey($tenant.Name)){
      $miPolicies[$($tenant.Name)] = @{}
    }
    if(-not $miPolicies[$tenant.Name].ContainsKey($sub.Name)){
      $miPolicies[$($tenant.Name)][$($sub.Name)] = @{}
    }
    
    foreach ($MI in $sqlManagedInstances) {
      Write-Progress -Id 5 -Activity "Getting Azure Managed Instance information for: $($MI.ManagedInstanceName)" -PercentComplete $(($managedInstanceNum/$sqlManagedInstances.Count)*100) -ParentId 1 -Status "SQL Managed Instance $($managedInstanceNum) of $($sqlManagedInstances.Count)"

      $databasesCounter = 0
      $databases = @()
      try{
        $databases = Get-AzSqlInstanceDatabase -InstanceName $($MI.ManagedInstanceName) -ResourceGroupName $($MI.ResourceGroupName) -ErrorAction Stop| ConvertTo-JSON -Depth 10 | ConvertFrom-JSON
      } catch{
        Write-Host "Issue getting SqlInstance Databases from $($MI.ManagedInstanceName) in $($MI.ResourceGroupName) in subscription $($sub.Name) under tenant $($tenant.Name)"
      }
      foreach($database in $databases){
        $databasesCounter++
        try{
        $str = Get-AzSqlInstanceDatabaseBackupShortTermRetentionPolicy -ResourceGroupName $($MI.ResourceGroupName) -InstanceName $($MI.ManagedInstanceName) -DatabaseName $($database.Name) -ErrorAction Stop
        if($str){
          $database | Add-Member -MemberType NoteProperty -Name "STR" -Value $($str | ConvertTo-JSON -Depth 10 | ConvertFrom-JSON)
        }
        $ltr = Get-AzSqlInstanceDatabaseBackupLongTermRetentionPolicy -ResourceGroupName $($MI.ResourceGroupName) -InstanceName $($MI.ManagedInstanceName) -DatabaseName $($database.Name) -ErrorAction Stop
        if($ltr){
          $database | Add-Member -MemberType NoteProperty -Name "LTR" -Value $($ltr | ConvertTo-JSON -Depth 10 | ConvertFrom-JSON)        
        }
        } catch{
          Write-Host "failed to get LTR/STR for  $($database.Name) in $($MI.ManagedInstanceName) in subscription $($sub.Name) under tenant $($tenant.Name)"
          Write-Host $_
        }
      }
      $miPolicies[$($tenant.Name)][$($sub.Name)][$($MI.ManagedInstanceName)] = $databases

      $managedInstanceNum++
      $sqlObj = [ordered] @{}
      $sqlObj.Add("Database","")
      $sqlObj.Add("Server","")
      $sqlObj.Add("ElasticPool","")
      $sqlObj.Add("ManagedInstance",$MI.ManagedInstanceName)
      $sqlObj.Add("MaxSizeGiB",$MI.StorageSizeInGB)
      $sqlObj.Add("MaxSizeTiB",[math]::round($($MI.StorageSizeInGB / 1024), 4))
      $sqlObj.Add("MaxSizeGB",[math]::round($($MI.StorageSizeInGB * 1.073741824), 3))
      $sqlObj.Add("MaxSizeTB",[math]::round($($MI.StorageSizeInGB * 0.001073741824), 4))
      $sqlObj.Add("Subscription",$sub.Name)
      $sqlObj.Add("Tenant",$tenant.Name)
      $sqlObj.Add("Region",$MI.Location)
      $sqlObj.Add("ResourceGroup",$MI.ResourceGroupName)
      $sqlObj.Add("DatabaseID","")
      $sqlObj.Add("InstanceType",$MI.Sku.Name)
      $sqlObj.Add("Status",$MI.Status)
      $sqlObj.Add("Databases", $databasesCounter)

      $sqlUsedBytes = (
          (Get-AzMetric  -WarningAction SilentlyContinue `
          -ResourceId $MI.Id `
          -MetricName "storage_space_used_mb" `
          -AggregationType Maximum `
          -StartTime (Get-Date).AddDays(-1))
      )
      $sqlUsedAvg = ($sqlUsedBytes.Data.Maximum | Select-Object -Last 1)
      $sqlObj.Add("storage_space_used_mb", $sqlUsedAvg)

      # Loop through possible labels adding the property if there is one, adding it with a hyphen as it's value if it doesn't.
      if ($MI.Labels.Count -ne 0) {
        $uniqueAzLabels | Foreach-Object {
            if ($MI.Labels[$_]) {
                $sqlObj.Add("Label/Tag: $_",$MI.Labels[$_])
            }
            else {
                $sqlObj.Add("Label/Tag: $_","-")
            }
        }
      } else {
          $uniqueAzLabels | Foreach-Object { $sqlObj.Add("Label/Tag: $_","-") }
      }
      $miList += New-Object -TypeName PSObject -Property $sqlObj
    } # foreach ($MI in $sqlManagedInstances)
    Write-Progress -Id 5 -Activity "Getting Azure Managed Instance information for: $($MI.ManagedInstanceName)" -Completed
  } #if ($SkipAzureSQLandMI -ne $true)

  if($SkipAzureCosmosDB -ne $true) {
    try {
    $resourceGroups = Get-AzResourceGroup
    } catch {
      Write-Error "Unable to collect Resource Group information for CosmosDBs in subscription: $($sub.Name) in subscription $($sub.Name) under tenant $($tenant.Name)"
      $_
      Continue    
    }
    $rgCounter = 0
    foreach ($rg in $resourceGroups) {
      $rgCounter++
      Write-Progress -Id 6 -Activity "Getting Azure CosmosDB information for: $($rg.ResourceGroupName)" -PercentComplete $(($rgCounter/$resourceGroups.Count)*100) -ParentId 1 -Status "Resource Group $($rgCounter) of $($resourceGroups.Count)"
      try {
      $cosmosDBAccounts = Get-AzCosmosDBAccount -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
      } catch {
        Write-Error "Unable to collect CosmosDB information for Resource Group $($rg.ResoruceGroupName) in subscription: $($sub.Name) in subscription $($sub.Name) under tenant $($tenant.Name)"
        $_
        Continue    
      }

      foreach ($account in $cosmosDBAccounts) {

        $dbAccountObj = [ordered] @{}
        $dbAccountObj.Add("Subscription",$sub.Name)
        $dbAccountObj.Add("Tenant",$tenant.Name)
        $dbAccountObj.Add("Name",$account.Name)
        $dbAccountObj.Add("Location",$account.Location)
        $dbAccountObj.Add("Id",$account.Id)
        $dbAccountObj.Add("Kind",$account.Kind)
        $dbAccountObj.Add("InstanceId",$account.InstanceId)
        $dbAccountObj.Add("BackupPolicyBackupIntervalInMinutes",$account.BackupPolicy.BackupIntervalInMinutes)
        $dbAccountObj.Add("BackupPolicyBackupRetentionIntervalInHours",$account.BackupPolicy.BackupRetentionIntervalInHours)
        $dbAccountObj.Add("BackupPolicyBackupType",$account.BackupPolicy.BackupType)
        $dbAccountObj.Add("BackupPolicyBackupStorageRedundancy",$account.BackupPolicy.BackupStorageRedundancy)
        $dbAccountObj.Add("BackupPolicyTier",$account.BackupPolicy.Tier)
        $dbAccountObj.Add("MinimalTlsVersion",$account.MinimalTlsVersion)
        $dbAccountObj.Add("NameDatabaseAccountOfferType",$account.NameDatabaseAccountOfferType)


        $id = $account.Id
        $azSAUsedCapacity = (Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId $id `
        -MetricName DocumentCount `
        -AggregationType Maximum `
        -StartTime (Get-Date).AddDays(-1)).Data.Maximum | Select-Object -Last 1
        $dbAccountObj.Add("DocumentCount",$azSAUsedCapacity)
        $azSAUsedCapacity = (Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId $id `
        -MetricName DataUsage `
        -AggregationType Maximum `
        -StartTime (Get-Date).AddDays(-1)).Data.Maximum | Select-Object -Last 1
        $dbAccountObj.Add("DataUsage",$azSAUsedCapacity)
        $azSAUsedCapacity = (Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId $id `
        -MetricName PhysicalPartitionSizeInfo `
        -AggregationType Maximum `
        -StartTime (Get-Date).AddDays(-1)).Data.Maximum | Select-Object -Last 1
        $dbAccountObj.Add("PhysicalPartitionSizeInfo",$azSAUsedCapacity)
        $azSAUsedCapacity = (Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId $id `
        -MetricName PhysicalPartitionCount `
        -AggregationType Maximum `
        -StartTime (Get-Date).AddDays(-1)).Data.Maximum | Select-Object -Last 1
        $dbAccountObj.Add("PhysicalPartitionCount",$azSAUsedCapacity)
        $azSAUsedCapacity = (Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId $id `
        -MetricName IndexUsage `
        -AggregationType Maximum `
        -StartTime (Get-Date).AddDays(-1)).Data.Maximum | Select-Object -Last 1
        $dbAccountObj.Add("IndexUsage",$azSAUsedCapacity)

      # Loop through possible tags adding the property if there is one, adding it with a hyphen as it's value if it doesn't.
      if ($account.Tags.Count -ne 0) {
        $uniqueAzTags | Foreach-Object {
            if ($account.Tags[$_]) {
                $dbAccountObj.Add("Tag: $_",$account.Tags[$_])
            }
            else {
                $dbAccountObj.Add("Tag: $_","-")
            }
        }
      } else {
          $uniqueAzTags | Foreach-Object { $dbAccountObj.Add("Tag: $_","-") }
      }
        $cosmosDBs += New-Object -TypeName PSObject -Property $dbAccountObj
      }
    }
    Write-Progress -Id 6 -Activity "Getting Azure CosmosDB information for: $($rg.ResourceGroupName)" -Completed
  } # if($SkipAzureCosmosDB -ne $true)

  if ($SkipAzureStorageAccounts -ne $true) {
    Write-Host "Getting Storage Account information in $($sub.Name)" -ForeGroundColor Green
    # Get a list of all Azure Storage Accounts.
    try {
      $azSAs = Get-AzStorageAccount -ErrorAction Stop
    } catch {
      Write-Error "Unable to collect Azure Storage Account information for subscription: $($sub.Name)"
      $_
      Continue    
    }

    # Loop through each Azure Storage Account and gather statistics
    $azSANum=1
    foreach ($azSA in $azSAs) {
      Write-Progress -Id 7 -Activity "Getting Storage Account information for: $($azSA.StorageAccountName)" -PercentComplete $(($azSANum/$azSAs.Count)*100) -ParentId 1 -Status "Azure Storage Account $($azSANum) of $($azSAs.Count)"
      $azSANum++
      try{
        $azSAContext = (Get-AzStorageAccount  -Name $azSA.StorageAccountName -ResourceGroupName $azSA.ResourceGroupName).Context
      } catch {
        Write-Host "Failed to get Storage Account Context for Storage Account $($azSA.StorageAccountName) in Resource Group $($azSA.ResourceGroupName) in sub $($sub.Name) in tenant $($tenant.Name)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      try{
        $azSAPSObjects = Get-AzStorageAccount -ResourceGroupName $azSA.ResourceGroupName -Name $azSA.StorageAccountName
      } catch {
        Write-Host "Failed to get Storage Account Objects for Storage Account $($azSA.StorageAccountName) in Resource Group $($azSA.ResourceGroupName) in sub $($sub.Name) in tenant $($tenant.Name)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $azSAResourceId = "/subscriptions/$($sub.Id)/resourceGroups/$($azSA.ResourceGroupName)/providers/Microsoft.Storage/storageAccounts/$($azSA.StorageAccountName)"
      $azSAUsedCapacity = (Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId $azSAResourceId `
        -MetricName UsedCapacity `
        -AggregationType Maximum `
        -StartTime (Get-Date).AddDays(-1)).Data.Maximum
      $metrics = @("BlobCapacity", "ContainerCount", "BlobCount")
      $azSABlob = (Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId "$($azSAResourceId)/blobServices/default" `
        -MetricNames $metrics `
        -AggregationType Maximum `
        -StartTime (Get-Date).AddDays(-1))
      $metrics = @("FileCapacity", "FileShareCount", "FileCount")
      $azSAFile = Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId "$($azSAResourceId)/fileServices/default" `
        -MetricNames $metrics `
        -AggregationType Maximum `
        -StartTime (Get-Date).AddDays(-1)
      $UsedCapacityBytes = ($azSAUsedCapacity | Select-Object -Last 1)
      $UsedBlobCapacityBytes = (($azSABlob | where-object {$_.id -like "*BlobCapacity"}).Data.Maximum | Select-Object -Last 1)
      $UsedFileShareCapacityBytes = (($azSAFile | where-object {$_.id -like "*FileCapacity"}).Data.Maximum | Select-Object -Last 1)

      $azSAObj = [ordered] @{}
      $azSAObj.Add("StorageAccount",$azSA.StorageAccountName)
      $azSAObj.Add("StorageAccountType",$azSA.Kind)
      $azSAObj.Add("HNSEnabled(ADLSGen2)",$azSA.EnableHierarchicalNamespace)
      $azSAObj.Add("StorageAccountSkuName",$azSA.Sku.Name)
      $azSAObj.Add("StorageAccountAccessTier",$azSA.AccessTier)
      $azSAObj.Add("Tenant",$tenant.Name)
      $azSAObj.Add("Subscription",$sub.Name)
      $azSAObj.Add("Region",$azSA.PrimaryLocation)
      $azSAObj.Add("ResourceGroup",$azSA.ResourceGroupName)
      $azSAObj.Add("UsedCapacityBytes",$UsedCapacityBytes)
      $azSAObj.Add("UsedCapacityGiB",[math]::round($($UsedCapacityBytes / 1073741824), 0))
      $azSAObj.Add("UsedCapacityTiB",[math]::round($($UsedCapacityBytes / 1073741824 / 1024), 4))
      $azSAObj.Add("UsedCapacityGB",[math]::round($($UsedCapacityBytes / 1000000000), 3))
      $azSAObj.Add("UsedCapacityTB",[math]::round($($UsedCapacityBytes / 1000000000000), 4))
      $azSAObj.Add("UsedBlobCapacityBytes",$UsedBlobCapacityBytes)
      $azSAObj.Add("UsedBlobCapacityGiB",[math]::round($($UsedBlobCapacityBytes / 1073741824), 0))
      $azSAObj.Add("UsedBlobCapacityTiB",[math]::round($($UsedBlobCapacityBytes / 1073741824 / 1024), 4))
      $azSAObj.Add("UsedBlobCapacityGB",[math]::round($($UsedBlobCapacityBytes / 1000000000), 3))
      $azSAObj.Add("UsedBlobCapacityTB",[math]::round($($UsedBlobCapacityBytes / 1000000000000), 4))
      $azSAObj.Add("BlobContainerCount",(($azSABlob | where-object {$_.id -like "*ContainerCount"}).Data.Maximum | Select-Object -Last 1))
      $azSAObj.Add("BlobCount",(($azSABlob | where-object {$_.id -like "*BlobCount"}).Data.Maximum | Select-Object -Last 1))
      $azSAObj.Add("UsedFileShareCapacityBytes",$UsedFileShareCapacityBytes)
      $azSAObj.Add("UsedFileShareCapacityGiB",[math]::round($($UsedFileShareCapacityBytes / 1073741824), 0))
      $azSAObj.Add("UsedFileShareCapacityTiB",[math]::round($($UsedFileShareCapacityBytes / 1073741824 / 1024), 4))
      $azSAObj.Add("UsedFileShareCapacityGB",[math]::round($($UsedFileShareCapacityBytes / 1000000000), 3))
      $azSAObj.Add("UsedFileShareCapacityTB",[math]::round($($UsedFileShareCapacityBytes / 1000000000000), 4))
      $azSAObj.Add("FileShareCount",(($azSAFile | where-object {$_.id -like "*FileShareCount"}).Data.Maximum | Select-Object -Last 1))
      $azSAObj.Add("FileCountInFileShares",(($azSAFile | where-object {$_.id -like "*FileCount"}).Data.Maximum | Select-Object -Last 1))
      # Loop through possible labels adding the property if there is one, adding it with a hyphen as it's value if it doesn't.
      if ($azSA.Labels.Count -ne 0) {
        $uniqueAzLabels | Foreach-Object {
            if ($azSA.Labels[$_]) {
                $azSAObj.Add("Label/Tag: $_",$azSA.Labels[$_])
            }
            else {
                $azSAObj.Add("Label/Tag: $_","-")
            }
        }
      } else {
          $uniqueAzLabels | Foreach-Object { $azSAObj.Add("Label/Tag: $_","-") }
      }
      $azSAList += New-Object -TypeName PSObject -Property $azSAObj
      
      if ($GetContainerDetails -eq $true) {
        # Loop through each Azure Container and record capacities    
        try {
          $azCons = Get-AzStorageContainer -Context $azSAContext -ErrorAction Stop
        }
        catch {
          Write-Error "Error getting Azure Container information from: $($azSA.StorageAccountName) storage account in subscription $($sub.Name) under tenant $($tenant.Name)."
          $_
          $azCons = @()
        }
        $azConNum = 1
        foreach ($azCon in $azCons) {
          Write-Progress -Id 8 -Activity "Getting Azure Container information for: $($azCon.Name)" -PercentComplete $(($azConNum/$azCons.Count)*100) -ParentId 6 -Status "Azure Container $($azConNum) of $($azCons.Count)"
          $azConNum++
          try{
            $azConBlobs = Get-AzStorageBlob -Container $($azCon.Name) -Context $azSAContext
          } catch {
            Write-Host "Failed to get Azure Container Information for container $($azCon.Name) in Storage Account Storage Account $($azSA.StorageAccountName) in Resource Group $($azSA.ResourceGroupName) in sub $($sub.Name) in tenant $($tenant.Name)" -ForeGroundColor Red
            Write-Host "Error: $_" -ForeGroundColor Red
          }
          $lengthHotTier = 0
          $lengthCoolTier = 0
          $lengthArchiveTier = 0
          $lengthUnknownTier = 0
          $lengthAllTiers = 0
          $azConBlobs | ForEach-Object {if ($_.AccessTier -Eq "Hot" -and $_.SnapshotTime -eq $null) {$lengthHotTier = $lengthHotTier + $_.Length}}
          $azConBlobs | ForEach-Object {if ($_.AccessTier -eq "Cool" -and $_.SnapshotTime -eq $null) {$lengthCoolTier = $lengthCoolTier + $_.Length}}
          $azConBlobs | ForEach-Object {if ($_.AccessTier -eq "Archive" -and $_.SnapshotTime -eq $null) {$lengthArchiveTier = $lengthArchiveTier + $_.Length}}
          $azConBlobs | ForEach-Object {if ($_.AccessTier -ne "Hot" -and `
                                              $_.AccessTier -ne "Cool" -and `
                                              $_.AccessTier -ne "Archive" -and `
                                              $_.SnapshotTime -eq $null) 
                                            {$lengthUnknownTier = $lengthUnknownTier + $_.Length}}
          $azConBlobs | ForEach-Object {if ($_.SnapshotTime -eq $null) {$lengthAllTiers = $lengthAllTiers + $_.Length}}
          $azConObj = [PSCustomObject] @{}        
          $azConObj.Add("Name",$azCon.Name)
          $azConObj.Add("StorageAccount",$azSA.StorageAccountName)
          $azConObj.Add("StorageAccountType",$azSA.Kind)
          $azConObj.Add("HNSEnabled(ADLSGen2)",$azSA.EnableHierarchicalNamespace)
          $azConObj.Add("StorageAccountSkuName",$azSA.Sku.Name)
          $azConObj.Add("StorageAccountAccessTier",$azSA.AccessTier)
          $azConObj.Add("Tenant",$tenant.Name)
          $azConObj.Add("Subscription",$sub.Name)
          $azConObj.Add("Region",$azSA.PrimaryLocation)
          $azConObj.Add("ResourceGroup",$azSA.ResourceGroupName)
          $azConObj.Add("UsedCapacityHotTierBytes",$lengthHotTier)
          $azConObj.Add("UsedCapacityHotTierGiB",[math]::round($($lengthHotTier / 1073741824), 0))
          $azConObj.Add("UsedCapacityHotTierTiB",[math]::round($($lengthHotTier / 1073741824 / 1024), 4))
          $azConObj.Add("UsedCapacityHotTierGB",[math]::round($($lengthHotTier / 1000000000), 3))
          $azConObj.Add("UsedCapacityHotTierTB",[math]::round($($lengthHotTier / 1000000000000), 4))
          $azConObj.Add("HotTierBlobCount",@($azConBlobs | Where-Object {$_.AccessTier -eq "Hot" -and $_.SnapshotTime -eq $null}).Count)
          $azConObj.Add("UsedCapacityCoolTierBytes",$lengthCoolTier)
          $azConObj.Add("UsedCapacityCoolTierGiB",[math]::round($($lengthCoolTier / 1073741824), 0))
          $azConObj.Add("UsedCapacityCoolTierTiB",[math]::round($($lengthCoolTier / 1073741824 / 1024), 4))
          $azConObj.Add("UsedCapacityCoolTierGB",[math]::round($($lengthCoolTier / 1000000000), 3)) 
          $azConObj.Add("UsedCapacityCoolTierTB",[math]::round($($lengthCoolTier / 1000000000000), 4))
          $azConObj.Add("CoolTierBlobCount",@($azConBlobs | Where-Object {$_.AccessTier -eq "Cool" -and $_.SnapshotTime -eq $null}).Count)
          $azConObj.Add("UsedCapacityArchiveTierBytes",$lengthArchiveTier)
          $azConObj.Add("UsedCapacityArchiveTierGiB",[math]::round($($lengthArchiveTier / 1073741824), 0))
          $azConObj.Add("UsedCapacityArchiveTierTiB",[math]::round($($lengthArchiveTier / 1073741824 / 1024), 4))
          $azConObj.Add("UsedCapacityArchiveTierGB",[math]::round($($lengthArchiveTier / 1000000000), 3)) 
          $azConObj.Add("UsedCapacityArchiveTierTB",[math]::round($($lengthArchiveTier / 1000000000000), 4))
          $azConObj.Add("ArchiveTierBlobCount",@($azConBlobs | Where-Object {$_.AccessTier -eq "Archive" -and $_.SnapshotTime -eq $null}).Count)
          $azConObj.Add("UsedCapacityUnknownTierBytes",$lengthUnknownTier)
          $azConObj.Add("UsedCapacityUnknownTierGiB",[math]::round($($lengthUnknownTier / 1073741824), 0))
          $azConObj.Add("UsedCapacityUnknownTierTiB",[math]::round($($lengthUnknownTier / 1073741824 / 1024), 4))
          $azConObj.Add("UsedCapacityUnknownTierGB",[math]::round($($lengthUnknownTier / 1000000000), 3))
          $azConObj.Add("UsedCapacityUnknownTierTB",[math]::round($($lengthUnknownTier / 1000000000000), 4))
          $azConObj.Add("UnknownTierBlobCount",($azConBlobs| Where-Object {$_.SnapshotTime -eq $null}).Count)
          $azConObj.Add("UsedCapacityAllTiersBytes",$lengthAllTiers)
          $azConObj.Add("UsedCapacityAllTiersGiB",[math]::round($($lengthAllTiers / 1073741824), 0))
          $azConObj.Add("UsedCapacityAllTiersTiB",[math]::round($($lengthAllTiers / 1073741824 / 1024), 4))
          $azConObj.Add("UsedCapacityAllTiersGB",[math]::round($($lengthAllTiers / 1000000000), 3))
          $azConObj.Add("UsedCapacityAllTiersTB",[math]::round($($lengthAllTiers / 1000000000000), 4))
          # Loop through possible labels adding the property if there is one, adding it with a hyphen as it's value if it doesn't.
          if ($azCon.Labels.Count -ne 0) {
            $uniqueAzLabels | Foreach-Object {
                if ($azCon.Labels[$_]) {
                    $azConObj.Add("Label/Tag: $_",$azCon.Labels[$_])
                }
                else {
                    $azConObj.Add("Label/Tag: $_","-")
                }
            }
          } else {
              $uniqueAzLabels | Foreach-Object { $azConObj.Add("Label/Tag: $_","-") }
          }
          $azConList += New-Object -TypeName PSObject -Property $azConObj
        } #foreach ($azCon in $azCons)
        Write-Progress -Id 8 -Activity "Getting Azure Container information for: $($azCon.Name)" -Completed
      } #if ($GetContainerDetails -eq $true)

      if ($SkipAzureFiles -ne $true) {
        # Loop through each Azure File Share and record quotas and capacities
        try {
          # Select only those Storage Accounts that support Azure Files to query.
          foreach ($azSAPSObject in $azSAPSObjects) {
            if (Get-AzureFileSAs -StorageAccount $azSAPSObject) {
              $azFSs = Get-AzRmStorageShare -StorageAccount $azSAPSObject
              $azFSDetails = foreach ($azFS in $azFSs) {
                $stgAcctName = $azFS.StorageAccountName
                $rgName = $azFS.ResourceGroupName
                $shareName = $azFS.Name
                Get-AzRmStorageShare -ResourceGroupName $rgName -StorageAccountName $stgAcctName -Name $shareName -GetShareUsage
              }
            }
            else {
              Write-Verbose "Skipping File Share query for $($azSAPSObject.StorageAccountName) because it does not support Azure Files."
            }            
          }
        }
        catch {
          Write-Error "Error getting Azure File Storage information from: $($azSA.StorageAccountName) storage account in subscription $($sub.Name) under tenant $($tenant.Name)."
          $_
          $azFSDetails = @()
        }    
        $azFSNum = 1
        foreach ($azFSi in $azFSDetails) {
          Write-Progress -Id 9 -Activity "Getting Azure File Share information for: $($azFSi.Name)" -PercentComplete $(($azFSNum/$azFSs.Count)*100) -ParentId 6 -Status "Azure File Share $($azFSNum) of $($azFSs.Count)"
          $azFSNum++
          $azFSObj = [ordered] @{}
          $azFSObj.Add("Name",$azFSi.Name)
          $azFSObj.Add("StorageAccount",$azSA.StorageAccountName)
          $azFSObj.Add("StorageAccountType",$azSA.Kind)
          $azFSObj.Add("StorageAccountSkuName",$azSA.Sku.Name)
          $azFSObj.Add("StorageAccountAccessTier",$azSA.AccessTier)
          $azFSObj.Add("Tenant",$tenant.Name)
          $azFSObj.Add("Subscription",$sub.Name)
          $azFSObj.Add("Region",$azSA.PrimaryLocation)
          $azFSObj.Add("ResourceGroup",$azSA.ResourceGroupName)
          $azFSObj.Add("QuotaGiB",$azFSi.QuotaGiB)
          $azFSObj.Add("QuotaTiB",[math]::round($($azFSi.QuotaGiB / 1024), 3))
          $azFSObj.Add("UsedCapacityBytes",$azFSi.ShareUsageBytes)
          $azFSObj.Add("UsedCapacityGiB",[math]::round($($azFSi.ShareUsageBytes / 1073741824), 0))
          $azFSObj.Add("UsedCapacityTiB",[math]::round($($azFSi.ShareUsageBytes / 1073741824 / 1024), 4))
          $azFSObj.Add("UsedCapacityGB",[math]::round($($azFSi.ShareUsageBytes / 1000000000), 3))
          $azFSObj.Add("UsedCapacityTB",[math]::round($($azFSi.ShareUsageBytes / 1000000000000), 4))

          $azFSList += New-Object -TypeName PSObject -Property $azFSObj
        } #foreach ($azFS in $azFSs)
        Write-Progress -Id 9 -Activity "Getting Azure File Share information for: $($azFSi.Name)" -Completed
      } #if ($SkipAzureFiles -ne $true)
    } # foreach ($azSA in $azSAs)
    Write-Progress -Id 7 -Activity "Getting Storage Account information for: $($azSA.StorageAccountName)" -Completed
  } # if ($SkipAzureStorageAccounts -ne $true)

  if ($SkipAzureBackup -ne $true) {
    # Get a list of all Azure Storage Accounts.
    try {
      $azVaults = Get-AzRecoveryServicesVault -ErrorAction Stop
    } catch {
      Write-Error "Unable to collect Azure Backup information for subscription: $($sub.Name) under tenant $($tenant.Name)"
      $_
      Continue    
    }

    #Loop over all vaults in the subscription and get Azure Backup Details
    $azVaultNum=1
    foreach ($azVault in $azVaults) {
      Write-Progress -Id 8 -Activity "Getting Azure Backup Vault information for: $($azVault.Name)" -PercentComplete $(($azVaultNum/$azVaults.Count)*100) -ParentId 1 -Status "Azure Vault $($azVaultNum) of $($azVaults.Count)"
      $azVaultNum++
      $azVaultVMPolicies = @()
      $azVaultVMSQLPolicies = @()
      $azVaultAzureSQLDatabasePolicies = @()
      $azVaultAzureFilesPolicies = @()
      $azVaultVMPolicyObj = [ordered] @{}
      $azVaultVMPolicyObj.Add("Name",$azVault.Name)
      $azVaultVMPolicyObj.Add("Type",$azVault.Type)
      $azVaultVMPolicyObj.Add("Tenant",$tenant.Name)
      $azVaultVMPolicyObj.Add("Subscription",$sub.Name)
      $azVaultVMPolicyObj.Add("Region",$azVault.Location)
      $azVaultVMPolicyObj.Add("ResourceGroup",$azVault.ResourceGroupName)
      $azVaultVMPolicyObj.Add("ProvisioningState",$azVault.Properties.ProvisioningState)
      $azVaultVMPolicyObj.Add("CrossSubscriptionRestoreState",$azVault.Properties.RestoreSettings.CrossSubscriptionRestoreSettings.CrossSubscriptionRestoreState)
      $azVaultVMPolicyObj.Add("ImmutabilitySettings",$azVault.Properties.ImmutabilitySettings)
      $azVaultList += New-Object -TypeName PSObject -Property $azVaultVMPolicyObj

      Set-AzRecoveryServicesVaultContext  -Vault $azVault
      #Get Azure Backup policies for VMs and SQL in a VM
      try {
        $azVaultVMPolicies += Get-AzRecoveryServicesBackupProtectionPolicy -WorkloadType AzureVM
        $azVaultVMPoliciesList += $azVaultVMPolicies | Select-Object -Property `
          @{Name = "Tenant"; Expression = {$tenant.Name}}, `
          @{Name = "Subscription"; Expression = {$sub.Name}}, `
          @{Name = "Region"; Expression = {$azVault.Location}}, `
          @{Name = "ResourceGroup"; Expression = {$azVault.ResourceGroupName}}, `
          *

        $azVaultVMSQLPolicies += Get-AzRecoveryServicesBackupProtectionPolicy -WorkloadType MSSQL
        $azVaultVMSQLPoliciesList += $azVaultVMSQLPolicies | Select-Object -Property `
        @{Name = "Tenant"; Expression = {$tenant.Name}}, `
        @{Name = "Subscription"; Expression = {$sub.Name}}, `
        @{Name = "Region"; Expression = {$azVault.Location}}, `
        @{Name = "ResourceGroup"; Expression = {$azVault.ResourceGroupName}}, `
        *

        $azVaultAzureSQLDatabasePolicies += Get-AzRecoveryServicesBackupProtectionPolicy -WorkloadType AzureSQLDatabase
        $azVaultAzureSQLDatabasePoliciesList += $azVaultAzureSQLDatabasePolicies | Select-Object -Property `
        @{Name = "Tenant"; Expression = {$tenant.Name}}, `
        @{Name = "Subscription"; Expression = {$sub.Name}}, `
        @{Name = "Region"; Expression = {$azVault.Location}}, `
        @{Name = "ResourceGroup"; Expression = {$azVault.ResourceGroupName}}, `
        *

        $azVaultAzureFilesPolicies += Get-AzRecoveryServicesBackupProtectionPolicy -WorkloadType AzureFiles
        $azVaultAzureFilesPoliciesList += $azVaultAzureFilesPolicies | Select-Object -Property `
        @{Name = "Tenant"; Expression = {$tenant.Name}}, `
        @{Name = "Subscription"; Expression = {$sub.Name}}, `
        @{Name = "Region"; Expression = {$azVault.Location}}, `
        @{Name = "ResourceGroup"; Expression = {$azVault.ResourceGroupName}}, `
        *
      } catch {
        Write-Host "Failed to get Azure Recovery Services Backup Protection Policies for vault $($azVault.Name) in Resource Group $($azSA.ResourceGroupName) in sub $($sub.Name) in tenant $($tenant.Name) in Region $($azVault.Location)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      try{
        #For each policy, get the items currently protected by the policy
        foreach ($policy in $azVaultVMPolicies) {
            $azVaultVMItem = Get-AzRecoveryServicesBackupItem -Policy $policy | Select-Object -Property `
            @{Name = "Tenant"; Expression = {$tenant.Name}}, `
            @{Name = "Subscription"; Expression = {$sub.Name}}, `
            @{Name = "Region"; Expression = {$azVault.Location}}, `
            @{Name = "ResourceGroup"; Expression = {$azVault.ResourceGroupName}}, `
            *
            $azVaultVMItems += $azVaultVMItem
            foreach($item in $azVaultVMItem){
              $vmName = ($item.VirtualMachineId -split '/')[ -1 ]
              $vmKey = Generate-VMKey -vmName $vmName -subName $sub.Name -tenantName $tenant.Name -region $vm.Location
              if ($vmList.ContainsKey($vmKey)) {
                if ($vmList[$vmKey].BackupPolicies -eq "-") {
                  $vmList[$vmKey].BackupPolicies = "$($policy.Name)"
                  $vmList[$vmKey].InBackupPolicy = $true
                }
                else {
                  $vmList[$vmKey].BackupPolicies += ", $($policy.Name)"
                }
              } else {
                  Write-Host "Found VM $($vmName) in VM backup policy $($policy.Name), however, the VM is not registered in Azure."
              }
            }
        }
        foreach ($policy in $azVaultVMSQLPolicies) {
            $azVaultVMSQLItem = Get-AzRecoveryServicesBackupItem -Policy $policy | Select-Object -Property `
            @{Name = "Tenant"; Expression = {$tenant.Name}}, `
            @{Name = "Subscription"; Expression = {$sub.Name}}, `
            @{Name = "Region"; Expression = {$azVault.Location}}, `
            @{Name = "ResourceGroup"; Expression = {$azVault.ResourceGroupName}}, `
            *
            $azVaultVMSQLItems += $azVaultVMSQLItem
            foreach($item in $azVaultVMSQLItem){
              $vmName = $item.ServerName
              $vmKey = Generate-VMKey -vmName $vmName -subName $sub.Name -tenantName $tenant.Name -region $vm.Location
              if ($vmList.ContainsKey($vmKey)) {
                if ($vmList[$vmKey].BackupPolicies -eq "-") {
                  $vmList[$vmKey].BackupPolicies = "$($policy.Name)"
                  $vmList[$vmKey].InBackupPolicy = $true
                }
                else {
                  $vmList[$vmKey].BackupPolicies += ", $($policy.Name)"
                }
              } else {
                  Write-Host "SQL VM: Found VM $($vmName) in SQL backup policy $($policy.Name), however, the VM is not registered in Azure."
              }
            }
        }
        foreach ($policy in $azVaultAzureSQLDatabasePolicies) {
            $azVaultAzureSQLDatabaseItems += Get-AzRecoveryServicesBackupItem -Policy $policy | Select-Object -Property `
            @{Name = "Tenant"; Expression = {$tenant.Name}}, `
            @{Name = "Subscription"; Expression = {$sub.Name}}, `
            @{Name = "Region"; Expression = {$azVault.Location}}, `
            @{Name = "ResourceGroup"; Expression = {$azVault.ResourceGroupName}}, `
            *
        }
        foreach ($policy in $azVaultAzureFilesPolicies) {
            $azVaultAzureFilesItems += Get-AzRecoveryServicesBackupItem -Policy $policy | Select-Object -Property `
            @{Name = "Tenant"; Expression = {$tenant.Name}}, `
            @{Name = "Subscription"; Expression = {$sub.Name}}, `
            @{Name = "Region"; Expression = {$azVault.Location}}, `
            @{Name = "ResourceGroup"; Expression = {$azVault.ResourceGroupName}}, `
            *
        }
      }catch {
        Write-Host "Failed to get Azure Recovery Services Backup Items for policies in vault $($azVault.Name) in Resource Group $($azSA.ResourceGroupName) in sub $($sub.Name) in tenant $($tenant.Name) in Region $($azVault.Location)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }

    } # foreach ($azVault in $azVaults)
    Write-Progress -Id 8 -Activity "Getting Azure Backup Vault information for: $($azVault.Name)" -Completed

    # Limit for this API call is 12 months before current date
    $costManagementQuery = $null
    $startDate = (Get-Date).AddMonths(-11)
    $endDate = (Get-Date)
    $TimePeriodFrom = [datetime]::Parse($startDate)
    $TimePeriodTo = [datetime]::Parse($endDate)
    try{
      $dimensions = New-AzCostManagementQueryComparisonExpressionObject -Name 'ServiceName' -Value 'Backup' -Operator ""
      $filter = New-AzCostManagementQueryFilterObject -Dimensions $dimensions
    
      $aggregation = @{                                                                                                                                                             
        totalCostUSD = @{
            name = "CostUSD"
            function = "Sum"
        }
        totalPreTaxCostUSD = @{
            name = "PreTaxCostUSD"
            function = "Sum"
      }
      } # max 2 in a query, possible values: 'UsageQuantity','PreTaxCost','Cost','CostUSD','PreTaxCostUSD'
      $costManagementQuery = Invoke-AzCostManagementQuery -Type Usage -Scope "subscriptions/$($sub.SubscriptionId)" -DatasetGranularity 'Monthly' -DatasetFilter $filter -Timeframe Custom -TimePeriodFrom $TimePeriodFrom -TimePeriodTo $TimePeriodTo -DatasetAggregation $aggregation | ConvertTo-JSON -Depth 10 | ConvertFrom-Json
      

      foreach ($row in $costManagementQuery.Row) {
          $costDetail = [PSCustomObject]@{
              SubscriptionId = $sub.SubscriptionId
              Subscription = $sub.Name
              Tenant = $tenant.Name
              BillingMonth  = [datetime]$row[2]
              PreTaxCostUSD =  "$" + "$([math]::round([double]$row[0], 2))"
              CostUSD =  "$" + "$([math]::round([double]$row[1], 2))"
          }

          $backupCostDetails += $costDetail
      }
    } catch{
      Write-Host "Failed to get Azure Backup Costs in sub $($sub.Name) in tenant $($tenant.Name)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

  } # if ($SkipAzureBackup -ne $true)

  # Intentionally skipping this by default; one must pass in the flag to collect this information
  # Can be changed to be collected by default later
  # Note the difference between null values and 0 values for num items as documented below
  if($GetKeyVaultAmounts -eq $true){
    Write-Host "Getting Key Vault information in $($sub.Name)" -ForeGroundColor Green
    $keyVaults = $null
    try{
      $keyVaults = Get-AzKeyVault -ErrorAction Stop
    } catch {
      Write-Error "Unable to collect Azure Key Vault information for subscription: $($sub.Name) under tenant $($tenant.Name)"
      $_
      Continue    
    }
    foreach($keyVault in $keyVaults){
      $vaultDetails = [PSCustomObject]@{
        VaultName = $keyVault.VaultName
        Location = $keyVault.Location
        Tenant = $tenant.Name
        Subscription  = $sub.Name
        NumCertificates =  $null
        NumSecrets =  $null
        NumKeys = $null
      }
      $certificates = $null
      try{
        $certificates = Get-AzKeyVaultCertificate -VaultName $keyVault.VaultName -ErrorAction Stop
        $vaultDetails.NumCertificates = $certificates.count
      } catch{
        # Could not collect certificate info. Will not throw errors as often the same error will repeat
        # One can see in CSV file whether it is 0 or null to see whether we were unable to grab number of 
        # certificates
      }
      $secrets = $null
      try{
        $secrets = Get-AzKeyVaultSecret -VaultName $keyVault.VaultName -ErrorAction Stop
        $vaultDetails.NumSecrets = $secrets.count
      } catch{
        # Could not collect secrets info. Will not throw errors as often the same error will repeat
        # One can see in CSV file whether it is 0 or null to see whether we were unable to grab number of 
        # secrets
      }
      $keys = $null
      try{
        $keys = Get-AzKeyVaultKey -VaultName $keyVault.VaultName -ErrorAction Stop
        $vaultDetails.NumKeys = $keys.count
      } catch{
        # Could not collect key info. Will not throw errors as often the same error will repeat
        # One can see in CSV file whether it is 0 or null to see whether we were unable to grab number of 
        # key
      }
      $keyVaultList += $vaultDetails
    }
  } # if($GetKeyVaultAmounts -eq $true){
} # foreach ($sub in $subs)
Write-Progress -Id 1 -Activity "Getting information from subscription: $($sub.Name)" -Completed

Write-Host "Calculating results and saving data..." -ForegroundColor Green

if ($Anonymize) {
  $global:anonymizeProperties = @("SubscriptionId", "Subscription", "Tenant", "Name", "AzureBackupRGName", "ResourceGroupName", "DatabaseName", "ManagedInstanceName", "InstanceName",
                                  "ResourceGroup", "VirtualMachineId", "PolicyId", "ProtectionPolicyName", "Id",
                                  "SourceResourceId", "ContainerName", "FriendlyName", "ServerName", "ParentName",
                                  "ProtectedItemDataSourceId",  "StorageAccount", "Database", "Server", "ElasticPool",
                                  "ManagedInstance", "DatabaseID", "vmID"
                                  )

  if($AnonymizeFields){
    [string[]]$anonFieldsList = $AnonymizeFields.split(',')
    foreach($field in $anonFieldsList){
      if (-not $global:anonymizeProperties.Contains($field)) {
        $global:anonymizeProperties += $field
      }
    }
  }
  if($NotAnonymizeFields){
    [string[]]$notAnonFieldsList = $NotAnonymizeFields.split(',')
    $global:anonymizeProperties = $global:anonymizeProperties | Where-Object { $_ -notin $notAnonFieldsList }
  }

  $global:anonymizeDict = @{}
  $global:anonymizeCounter = @{}

  function Get-NextAnonymizedValue ($anonField) {
      $charSet = "0123456789"
      $base = $charSet.Length
      $newValue = ""
      if (-not $global:anonymizeCounter.ContainsKey($anonField)) {
        $global:anonymizeCounter[$anonField] = 0
      }
      $global:anonymizeCounter[$anonField]++

      $counter = $global:anonymizeCounter[$anonField]
      while ($counter -gt 0) {
          $counter--
          $newValue = $charSet[$counter % $base] + $newValue
          $counter = [math]::Floor($counter / $base)
      }
      
      $paddedValue = $newValue.PadLeft(5, '0')

      return "$($anonField)-$($paddedValue)"
  }

  function Anonymize-Data {
      param (
          [PSObject]$DataObject
      )

      foreach ($property in $DataObject.PSObject.Properties) {
          $propertyName = $property.Name
          $shouldAnonymize = $global:anonymizeProperties -contains $propertyName

          if ($shouldAnonymize) {
              $originalValue = $DataObject.$propertyName

              if ($null -ne $originalValue) {
                if(($originalValue -is [System.Collections.IEnumerable] -and -not ($originalValue -is [string])) ){
                  # This is to handle the anonymization of list objects
                  $anonymizedCollection = @()
                  foreach ($item in $originalValue) {
                      if (-not $global:anonymizeDict.ContainsKey("$item")) {
                          $global:anonymizeDict["$item"] = Get-NextAnonymizedValue($propertyName)
                      }
                      $anonymizedCollection += $global:anonymizeDict["$item"]
                  }
                  $DataObject.$propertyName = $anonymizedCollection
                } else{
                  if (-not $global:anonymizeDict.ContainsKey("$($originalValue)")) {
                      $global:anonymizeDict[$originalValue] = Get-NextAnonymizedValue($propertyName)
                  }
                  $DataObject.$propertyName = $global:anonymizeDict[$originalValue]
                }
              }
          } 
          elseif ($propertyName -like "Label/Tag:*") {
            # Must anonymize both the tag name and value

            $tagValue = $DataObject.$propertyName
            $anonymizedTagKey = ""
            
            $tagName = $propertyName.Substring(10)
            
            if (-not $global:anonymizeDict.ContainsKey("$tagName")) {
                $global:anonymizeDict["$tagName"] = Get-NextAnonymizedValue("Label/TagName")
            }
            $anonymizedTagKey = 'Label/Tag:' + $global:anonymizeDict["$tagName"]
            
            $anonymizedTagValue = $null
            if ($null -ne $tagValue) {
                if (-not $global:anonymizeDict.ContainsKey("$($tagValue)")) {
                  $global:anonymizeDict[$tagValue] = Get-NextAnonymizedValue("Label/TagValue")#$anonymizedTagKey
                }
                $anonymizedTagValue = $global:anonymizeDict[$tagValue]
            }
            $DataObject.PSObject.Properties.Remove($propertyName)
            $DataObject | Add-Member -MemberType NoteProperty -Name $anonymizedTagKey -Value $anonymizedTagValue -Force
        }
          elseif ($property.Value -is [PSObject]) {
              $DataObject.$propertyName = Anonymize-Data -DataObject $property.Value
          }
          elseif ($property.Value -is [System.Collections.IEnumerable] -and -not ($property.Value -is [string])) {
              $anonymizedCollection = @()
              foreach ($item in $property.Value) {
                  if ($item -is [PSObject]) {
                      $anonymizedItem = Anonymize-Data -DataObject $item
                      $anonymizedCollection += $anonymizedItem
                  } else {
                      $anonymizedCollection += $item
                  }
              }
              $DataObject.$propertyName = $anonymizedCollection
          }
      }

      return $DataObject
  }

  function Anonymize-Collection {
      param (
          [System.Collections.IEnumerable]$Collection
      )

      $anonymizedCollection = @()
      foreach ($item in $Collection) {
          if ($item -is [PSObject]) {
              $anonymizedItem = Anonymize-Data -DataObject $item
              $anonymizedCollection += $anonymizedItem
          } else {
              $anonymizedCollection += $item
          }
      }

      return $anonymizedCollection
  }
}
if ($SkipAzureVMandManagedDisks -ne $true) {

  $VMtotalGiB = ($vmList.values.SizeGiB | Measure-Object -Sum).sum
  $VMtotalTiB = ($vmList.values.SizeTiB | Measure-Object -Sum).sum 
  $VMtotalGB = ($vmList.values.SizeGB | Measure-Object -Sum).sum
  $VMtotalTB = ($vmList.values.SizeTB | Measure-Object -Sum).sum 


  Write-Host
  Write-Host "Successfully collected data from $($processedSubs) out of $($subs.count) found subscriptions"  -ForeGroundColor Green
  Write-Host
  Write-Host "Total # of Azure VMs: $('{0:N0}' -f $vmList.values.count)" -ForeGroundColor Green
  Write-Host "Total # of Managed Disks: $('{0:N0}' -f ($vmList.values.Disks | Measure-Object -Sum).sum)" -ForeGroundColor Green
  Write-Host "Total capacity of all disks: $('{0:N0}' -f $VMtotalGiB) GiB or $('{0:N0}' -f $VMtotalGB) GB or $VMtotalTiB TiB or $VMtotalTB TB" -ForeGroundColor Green

  $vmListToCsv = $vmList.values

  if ($Anonymize) {
    $vmListToCsv = Anonymize-Collection -Collection $vmListToCsv
  }

  $outputFiles += New-Object -TypeName pscustomobject -Property @{Files="$outputVmDisk - Azure VM and Managed Disk CSV file."}
  $vmListToCsv | Export-CSV -path $outputVmDisk -NoTypeInformation

} #if ($SkipAzureVMandManagedDisks -ne $true)

if ($SkipAzureSQLandMI -ne $true) {
  $DBtotalGiB = (($sqlList | Where-Object -Property 'Database' -ne '').MaxSizeGiB | Measure-Object -Sum).sum
  $DBtotalTiB = (($sqlList | Where-Object -Property 'Database' -ne '').MaxSizeTiB | Measure-Object -Sum).sum
  $DBtotalGB = (($sqlList | Where-Object -Property 'Database' -ne '').MaxSizeGB | Measure-Object -Sum).sum
  $DBtotalTB = (($sqlList | Where-Object -Property 'Database' -ne '').MaxSizeTB | Measure-Object -Sum).sum
  $elasticTotalGiB = (($sqlList | Where-Object -Property 'ElasticPool' -ne '').MaxSizeGiB | Measure-Object -Sum).sum
  $elasticTotalTiB = (($sqlList | Where-Object -Property 'ElasticPool' -ne '').MaxSizeTiB | Measure-Object -Sum).sum
  $elasticTotalGB = (($sqlList | Where-Object -Property 'ElasticPool' -ne '').MaxSizeGB | Measure-Object -Sum).sum
  $elasticTotalTB = (($sqlList | Where-Object -Property 'ElasticPool' -ne '').MaxSizeTB | Measure-Object -Sum).sum

  $MITotalGiB = (($miList | Where-Object -Property 'ManagedInstance' -ne '').MaxSizeGiB | Measure-Object -Sum).sum
  $MITotalTiB = (($miList | Where-Object -Property 'ManagedInstance' -ne '').MaxSizeTiB | Measure-Object -Sum).sum 
  $MITotalGB = (($miList | Where-Object -Property 'ManagedInstance' -ne '').MaxSizeGB | Measure-Object -Sum).sum
  $MITotalTB = (($miList | Where-Object -Property 'ManagedInstance' -ne '').MaxSizeTB | Measure-Object -Sum).sum

  $sqlTotalGiB = $MITotalGiB + ($sqlList.MaxSizeGiB | Measure-Object -Sum).sum
  $sqlTotalTiB = $MITotalTiB + ($sqlList.MaxSizeTiB | Measure-Object -Sum).sum
  $sqlTotalGB = $MITotalGB + ($sqlList.MaxSizeGB | Measure-Object -Sum).sum
  $sqlTotalTB = $MITotalTB + ($sqlList.MaxSizeTB | Measure-Object -Sum).sum

  Write-Host
  Write-Host "Total # of SQL DBs (independent): $('{0:N0}' -f ($sqlList | Where-Object -Property 'Database' -ne '').Count)" -ForeGroundColor Green
  Write-Host "Total # of SQL Elastic Pools: $('{0:N0}' -f ($sqlList | Where-Object -Property 'ElasticPool' -ne '').Count)" -ForeGroundColor Green
  Write-Host "Total # of SQL Managed Instances: $('{0:N0}' -f ($miList | Where-Object -Property 'ManagedInstance' -ne '').Count)" -ForeGroundColor Green
  Write-Host "Total capacity of all SQL DBs (independent): $('{0:N0}' -f $DBtotalGiB) GiB or $('{0:N0}' -f $DBtotalGB) GB or $DBtotalTiB TiB or $DBtotalTB TB" -ForeGroundColor Green
  Write-Host "Total capacity of all SQL Elastic Pools: $('{0:N0}' -f $elasticTotalGiB) GiB or $('{0:N0}' -f $elasticTotalGB) GB or $elasticTotalTiB TiB or $elasticTotalTB TB" -ForeGroundColor Green
  Write-Host "Total capacity of all SQL Managed Instances: $('{0:N0}' -f $MITotalGiB) GiB or $('{0:N0}' -f $MITotalGB) GB or $MITotalTiB TiB or $MITotalTB TB" -ForeGroundColor Green
  Write-Host
  Write-Host "Total # of SQL DBs, Elastic Pools & Managed Instances: $('{0:N0}' -f ($sqlList.count + $miList.count))" -ForeGroundColor Green
  Write-Host "Total capacity of all SQL: $('{0:N0}' -f $sqlTotalGiB) GiB or $('{0:N0}' -f $sqlTotalGB) GB or $sqlTotalTiB TiB or $sqlTotalTB TB" -ForeGroundColor Green

  if ($Anonymize) {
    $sqlList = Anonymize-Collection -Collection $sqlList
    $miList = Anonymize-Collection -Collection $miList
    $miPolicies = Anonymize-Collection -Collection $miPolicies
  }
  
  $outputFiles += New-Object -TypeName pscustomobject -Property @{Files="$outputSQL - Azure SQL CSV file."}
  $outputFiles += New-Object -TypeName pscustomobject -Property @{Files="$outputMI - Azure MI SQL CSV file."}
  $outputFiles += New-Object -TypeName pscustomobject -Property @{Files="$outputMiDbLtrStrJSON - Azure MI SQL DBs and their LTRs and STR JSON file."}

  $sqlList | Export-CSV -path $outputSQL
  $miList | Export-CSV -path $outputMI
  $miPolicies | ConvertTo-Json -Depth 10 > $outputMiDbLtrStrJSON
} #if ($SkipAzureSQLandMI -ne $true)

if ($SkipAzureStorageAccounts -ne $true) {
  $azSATotalGiB = ($azSAList.UsedCapacityGiB | Measure-Object -Sum).sum
  $azSATotalTiB = ($azSAList.UsedCapacityTiB | Measure-Object -Sum).sum
  $azSATotalGB = ($azSAList.UsedCapacityGB | Measure-Object -Sum).sum
  $azSATotalTB = ($azSAList.UsedCapacityTB | Measure-Object -Sum).sum
  $azSATotalBlobGiB = ($azSAList.UsedBlobCapacityGiB | Measure-Object -Sum).sum
  $azSATotalBlobTiB = ($azSAList.UsedBlobCapacityTiB | Measure-Object -Sum).sum
  $azSATotalBlobGB = ($azSAList.UsedBlobCapacityGB | Measure-Object -Sum).sum
  $azSATotalBlobTB = ($azSAList.UsedBlobCapacityTB | Measure-Object -Sum).sum
  $azSATotalBlobObjects = ($azSAList.BlobCount | Measure-Object -Sum).sum
  $azSATotalBlobContainers = ($azSAList.BlobContainerCount | Measure-Object -Sum).sum
  $azSATotalFileGiB = ($azSAList.UsedFileShareCapacityGiB | Measure-Object -Sum).sum
  $azSATotalFileTiB = ($azSAList.UsedFileShareCapacityTiB | Measure-Object -Sum).sum
  $azSATotalFileGB = ($azSAList.UsedFileShareCapacityGB | Measure-Object -Sum).sum
  $azSATotalFileTB = ($azSAList.UsedFileShareCapacityTB | Measure-Object -Sum).sum
  $azSATotalFileObjects = ($azSAList.FileCountInFileShares | Measure-Object -Sum).sum
  $azSATotalFileShares = ($azSAList.FileShareCount | Measure-Object -Sum).sum
  Write-Host
  Write-Host "Totals based on querying storage account metrics:"
  Write-Host "Total # of Azure Storage Accounts: $('{0:N0}' -f $azSAList.count)" -ForeGroundColor Green
  Write-Host "Total capacity of all Azure Storage Accounts: $('{0:N0}' -f $azSATotalGiB) GiB or $('{0:N0}' -f $azSATotalGB) GB or $azSATotalTiB TiB or $azSATotalTB TB" -ForeGroundColor Green
  Write-Host "Total capacity of all Azure Blob storage in Azure Storage Accounts: $('{0:N0}' -f $azSATotalBlobGiB) GiB or $('{0:N0}' -f $azSATotalBlobGB) GB or $azSATotalBlobTiB TiB or $azSATotalBlobTB TB" -ForeGroundColor Green
  Write-Host "Total number blobs is $('{0:N0}' -f $azSATotalBlobObjects) in $('{0:N0}' -f $azSATotalBlobContainers) containers." -ForeGroundColor Green
  Write-Host "Total capacity of all Azure File storage in Azure Storage Accounts: $('{0:N0}' -f $azSATotalFileGiB) GiB or $('{0:N0}' -f $azSATotalFileGB) GB or $azSATotalFileTiB or $azSATotalFileTB TB" -ForeGroundColor Green
  Write-Host "Total number files is $('{0:N0}' -f $azSATotalFileObjects) in $('{0:N0}' -f $azSATotalFileShares) Azure File Shares." -ForeGroundColor Green


  if ($Anonymize) {
    $azSAList = Anonymize-Collection -Collection $azSAList
  }

  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzSA - Azure Storage Account CSV file."}
  $azSAList | Export-CSV -path $outputAzSA

  if ($GetContainerDetails -eq $true) {
    $azConTotalGiB = ($azConList.UsedCapacityAllTiersGiB | Measure-Object -Sum).sum
    $azConTotalTiB = ($azConList.UsedCapacityAllTiersTiB | Measure-Object -Sum).sum
    $azConTotalGB = ($azConList.UsedCapacityAllTiersGB | Measure-Object -Sum).sum
    $azConTotalTB = ($azConList.UsedCapacityAllTiersTB | Measure-Object -Sum).sum
    $azConTotalGiB = ($azConList.UsedCapacityGiB | Measure-Object -Sum).sum
    $azConTotalTiB = ($azConList.UsedCapacityTiB | Measure-Object -Sum).sum
    $azConTotalGB = ($azConList.UsedCapacityGB | Measure-Object -Sum).sum
    $azConTotalTB = ($azConList.UsedCapacityTB | Measure-Object -Sum).sum
    Write-Host
    Write-Host "Totals based on traversing each blob store container and calculating statistics:" -ForeGroundColor Green
    Write-Host "NOTE: The totals may be different than those gathered from Storage Account metrics if" -ForeGroundColor Green
    Write-Host "some containers could not be accessed. There are also differences in the way these two metrics" -ForeGroundColor Green
    Write-Host "are calculated by Azure." -ForeGroundColor Green
    Write-Host "Total # of Azure Containers: $('{0:N0}' -f $azConList.count)" -ForeGroundColor Green
    Write-Host "Total capacity of all Azure Containers: $('{0:N0}' -f $azConTotalGiB) GiB or $('{0:N0}' -f $azConTotalGB) GB or $azConTotalTiB TiB or $azConTotalTB TB" -ForeGroundColor Green

    if ($Anonymize) {
      $azConList = Anonymize-Collection -Collection $azConList
    }
    
    $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzCon - Azure Container CSV file."}
    $azConList | Export-CSV -path $outputAzCon
  }

  if ($SkipAzureFiles -ne $true) {
    $azFSTotalGiB = ($azFSList.UsedCapacityGiB | Measure-Object -Sum).sum
    $azFSTotalTiB = ($azFSList.UsedCapacityTiB | Measure-Object -Sum).sum
    $azFSTotalGB = ($azFSList.UsedCapacityGB | Measure-Object -Sum).sum
    $azFSTotalTB = ($azFSList.UsedCapacityTB | Measure-Object -Sum).sum
    Write-Host
    Write-Host "Totals based on traversing each Azure File Share and calculating statistics:"
    Write-Host "Note: The totals may be different than those gathered from Storage Account metrics if"
    Write-Host "the Azure File Share could not be accessed. There are also differences in the way these two metrics"
    Write-Host "are calculated by Azure."
    Write-Host "Total # of Azure File Shares: $('{0:N0}' -f $azFSList.count)" -ForeGroundColor Green
    Write-Host "Total capacity of all Azure File Shares: $('{0:N0}' -f $azFSTotalGiB) GiB or $('{0:N0}' -f $azFSTotalGB) GB or $azFSTotalTiB TiB or $azFSTotalTB TB" -ForeGroundColor Green

    if ($Anonymize) {
      $azFSList = Anonymize-Collection -Collection $azFSList
    }
    
    $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzFS - Azure File Share CSV file."}
    $azFSList | Export-CSV -path $outputAzFS
  }
} #if ($SkipAzureStorageAccounts -ne $true)

if ($SkipAzureBackup -ne $true) {
  

  if ($Anonymize) {
    $azVaultList = Anonymize-Collection -Collection $azVaultList
    $azVaultVMPoliciesList = Anonymize-Collection -Collection $azVaultVMPoliciesList
    $azVaultVMSQLPoliciesList = Anonymize-Collection -Collection $azVaultVMSQLPoliciesList
    $azVaultAzureSQLDatabasePoliciesList = Anonymize-Collection -Collection $azVaultAzureSQLDatabasePoliciesList
    $azVaultAzureFilesPoliciesList = Anonymize-Collection -Collection $azVaultAzureFilesPoliciesList
    $azVaultVMItems = Anonymize-Collection -Collection $azVaultVMItems
    $azVaultVMSQLItems = Anonymize-Collection -Collection $azVaultVMSQLItems
    $azVaultAzureSQLDatabaseItems = Anonymize-Collection -Collection $azVaultAzureSQLDatabaseItems
    $azVaultAzureFilesItems = Anonymize-Collection -Collection $azVaultAzureFilesItems
    $backupCostDetails = Anonymize-Collection -Collection $backupCostDetails
  }
  
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaults - Azure Backup Vault CSV file."}
  # $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultVMPolicies - Azure Backup Vault VM policies CSV file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultVMPoliciesJSON - Azure Backup Vault VM policies JSON file."}
  # $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultVMSQLPolicies - Azure Backup Vault VM SQL policies CSV file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultVMSQLPoliciesJSON - Azure Backup Vault VM SQL policies JSON file."}
  # $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultAzureSQLDatabasePolicies - Azure Backup Vault Azure SQL Database policies CSV file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultAzureSQLDatabasePoliciesJSON - Azure Backup Vault Azure SQL Database policies JSON file."}
  # $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultAzureFilesPolicies - Azure Backup Vault Azure Files CSV file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultAzureFilesPoliciesJSON - Azure Backup Vault Azure Files JSON file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultVMItems - Azure Backup Vault VM items CSV file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultVMItems - Azure Backup Vault VM SQL items CSV file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultAzureSQLDatabaseItems - Azure Backup Vault Azure SQL Database items CSV file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultAzureFilesItems - Azure Backup Vault Azure Files items CSV file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultVMSQLItem - Azure Vault VMSQL items CSV file."}
  $outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$outputAzVaultBackupCostsItems - Azure Backup Costs CSV file."}

  Write-Host "Total # of Azure Backup Vaults: $('{0:N0}' -f $azVaultList.count)" -ForeGroundColor Green
  Write-Host "Total # of Azure Backup Vault policies for Virtual Machines: $('{0:N0}' -f $azVaultVMPoliciesList.Count)" -ForeGroundColor Green
  Write-Host "Total # of Azure Backup Vault policies for Virtual Machines with SQL databases: $('{0:N0}' -f $azVaultVMSQLPoliciesList.Count)" -ForeGroundColor Green
  Write-Host "Total # of Azure Backup Vault policies for Azure SQL databases: $('{0:N0}' -f $azVaultAzureSQLDatabasePoliciesList.Count)" -ForeGroundColor Green
  Write-Host "Total # of Azure Backup Vault policies for Azure Files: $('{0:N0}' -f $azVaultAzureFilesPoliciesList.Count)" -ForeGroundColor Green
  Write-Host "Total # of Azure VMs protected by Azure Backup : $('{0:N0}' -f $azVaultVMItems.Count)" -ForeGroundColor Green
  Write-Host "Total # of Azure VMs with MS SQL protected by Azure Backup : $('{0:N0}' -f $azVaultVMSQLItems.Count)" -ForeGroundColor Green
  Write-Host "Total # of Azure SQL databases protected by Azure Backup : $('{0:N0}' -f $azVaultAzureSQLDatabaseItems.Count)" -ForeGroundColor Green
  Write-Host "Total # of Azure Files shares protected by Azure Backup : $('{0:N0}' -f $azVaultAzureFilesItems.Count)" -ForeGroundColor Green


  $azVaultList | Export-Csv -Path $outputAzVaults
  #$azVaultVMPoliciesList | Export-Csv -Path $outputAzVaultVMPolicies
  $azVaultVMPoliciesList  | ConvertTo-Json -Depth 10 > $outputAzVaultVMPoliciesJSON
  #$azVaultVMSQLPoliciesList | Export-Csv -Path $outputAzVaultVMSQLPolicies
  $azVaultVMSQLPoliciesList | ConvertTo-Json -Depth 10 > $outputAzVaultVMSQLPoliciesJSON
  #$azVaultAzureSQLDatabasePoliciesList | Export-Csv -Path $outputAzVaultAzureSQLDatabasePolicies
  $azVaultAzureSQLDatabasePoliciesList | ConvertTo-Json -Depth 10 > $outputAzVaultAzureSQLDatabasePoliciesJSON
  #$azVaultAzureFilesPoliciesList | Export-Csv -Path $outputAzVaultAzureFilesPolicies
  $azVaultAzureFilesPoliciesList | ConvertTo-Json -Depth 10 > $outputAzVaultAzureFilesPoliciesJSON
  $azVaultVMItems | Export-Csv -Path $outputAzVaultVMItems
  $azVaultVMSQLItems | Export-Csv -Path $outputAzVaultVMSQLItem
  $azVaultAzureSQLDatabaseItems | Export-Csv -Path $outputAzVaultAzureSQLDatabaseItems
  $azVaultAzureFilesItems | Export-Csv -Path $outputAzVaultAzureFilesItems
  $backupCostDetails | Export-Csv -Path $outputAzVaultBackupCostsItems

} # if ($SkipAzureBackup -ne $true)

if ($SkipAzureCosmosDB -ne $true) {
  Write-Host "Total # of Azure Cosmos DB Accounts: $('{0:N0}' -f $cosmosDBs.values.count)" -ForeGroundColor Green

  $cosmosDBsToCsv = $cosmosDBs

  if ($Anonymize) {
    $cosmosDBsToCsv = Anonymize-Collection -Collection $cosmosDBs
  }

  $outputFiles += New-Object -TypeName pscustomobject -Property @{Files="$outputAzCosmosDB - Azure Cosmos DB CSV file."}
  $cosmosDBsToCsv | Export-CSV -path $outputAzCosmosDB -NoTypeInformation

} #if ($SkipAzureCosmosDB -ne $true)

if($GetKeyVaultAmounts -eq $true){
  Write-Host "Total # of Azure Key Vaults: $('{0:N0}' -f $keyVaultList.values.count)" -ForeGroundColor Green

  $keyVaultListToCsv = $keyVaultList

  if ($Anonymize) {
    $keyVaultListToCsv = Anonymize-Collection -Collection $keyVaultList
  }

  $outputFiles += New-Object -TypeName pscustomobject -Property @{Files="$outputAzKeyVault - Azure Key Vault CSV file."}
  $keyVaultListToCsv | Export-CSV -path $outputAzKeyVault -NoTypeInformation
}


Write-Host
Write-Host "Output files are:" -ForeGroundColor Green
$outputFiles.Files
if ($SkipAzureBackup -ne $true) {
  Write-Host "This backup cost gives the cost for 95% of the cost of the vault, capacity, instance cost, etc, but does not include cost snapshots and the storage of those snapshots, restore point collections"
}
Write-Host

Write-Host
Write-Host "Results will be compressed into $archiveFile and original files will be removed." -ForegroundColor Green

if($Anonymize){
  # Exporting as rows as new value - old value
  $transformedDict = $global:anonymizeDict.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{
      AnonymizedValue = $_.Value
      ActualValue   = $_.Key
    } 
  } | Sort-Object -Property AnonymizedValue

  $anonKeyValuesFileName = "azure_anonymized_keys_to_actual_values-$date_string.csv"

  $transformedDict | Export-CSV -Path $anonKeyValuesFileName
  Write-Host
  Write-Host "Provided anonymized keys to actual values in the CSV: $anonKeyValuesFileName" -ForeGroundColor Cyan
  Write-Host "Provided log file here: $log_for_anon_customers" -ForegroundColor Cyan
  Write-Host "These files are not part of the zip file generated" -ForegroundColor Cyan
  Write-Host
}

} catch{
  Write-Error "An error occurred and the script has exited prematurely:"
  Write-Error $_
  Write-Error $_.ScriptStackTrace
} finally{
  Stop-Transcript
}

$outputFiles += New-Object -TypeName PSCustomObject -Property @{Files="$output_log - Log file"}

# Extract only the unique file names from the array of objects for compression
$filePaths = $outputFiles | ForEach-Object { $_.Files.Split(' - ')[0] }  | Sort-Object -Unique

# In the case of an early exit/error, this filters only the files which exist
$existingFiles = $filePaths | Where-Object { Test-Path $_ }

# Compress the files into a zip archive
Compress-Archive -Path $existingFiles -DestinationPath $archiveFile

# Remove the original files
foreach ($file in $filePaths) {
    Remove-Item -Path $file -ErrorAction SilentlyContinue
}

Write-Host
Write-Host
Write-Host "Results have been compressed into $archiveFile and original files have been removed." -ForegroundColor Green

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $CurrentCulture

Write-Host
Write-Host
Write-Host "Please send $archiveFile to your Rubrik representative" -ForegroundColor Cyan
Write-Host

# Reset subscription context back to original.
try {
  Set-AzContext -SubscriptionName $context.subscription.Name -TenantId $context.Tenant.Id -ErrorAction Stop | Out-Null
} catch {
  Write-Error "Unable to reset AzContext back to original context."
  $_
}

if ($azConfig.Value -eq $true) {
  try {
    Update-AzConfig -DisplayBreakingChangeWarning $true  -ErrorAction Stop | Out-Null
  } catch {
    Write-Error "Unable to rest display of breaking changes."
    $_
  }
}


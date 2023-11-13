#requires -Modules Az.Accounts, Az.Compute, Az.Storage, Az.Sql, Az.SqlVirtualMachine, Az.ResourceGraph, Az.Monitor

<#
.SYNOPSIS
Gets all Azure VM Managed Disk and/or Azure SQL information in the specified subscription(s).

.DESCRIPTION
The 'Get-AzureVMSQLInfo.ps1' script gets all VM Managed Disk and/or Azure SQL information in the specified subscription(s).
You can specify one or more subscription to run the script against. 
You can also specify to discover and report on all subscriptions with in the tenant that Powershell is logged into.
If no subscription is specified then it will gather information against the current subscription context.

This script requires the Azure Powershell module. That module can be installed by running  `Install-Module Az`
If not already done use the `Connect-AzAccount` command to connect to a specific Azure Tenant to report on.
This script works on one Azure Tenant per run.

The script gathers all Azure VMs and associated Managed Disk information.
The script will try to determine if MS SQL is running in the Azure VMs. This depends on the Azure SQL Server
IaaS Agent being installed and running in the VM. 
The script also gathers all Azure SQL DB (independent), Elastic Pool, and Managed Instance size information.

For SQL, the script will gather the Max Size for each SQL DB that is provisioned on an Azure SQL server.
If a SQL DB is in an Elastic Pool, then the script will gather the Elastic Pool Max Size.
If a SQL DB is on a Managed Instance, then the script will gather the Managed Instance Max Size.

A summary of the total # of VMs, Disks, and SQL capacity information will be output to console.
A CSV file will be exported with the details.
You should copy/paste the console output to send along with the CSV.

Update the subscription list ($subscriptions) as needed or pass it in as an argument.

Run in Azure CloudShell or Azure PowerShell connected to your subscription.
See: https://docs.microsoft.com/en-us/azure/cloud-shell/overview

.PARAMETER Subscriptions
A comma separated list of subscriptions to gather data from.

.PARAMETER AllSubscriptions
Flag to find all subscriptions in the tenant and download data.

.PARAMETER ManagementGroups
A comme separated list of Azure Management Groups to gather data from.

.PARAMETER CurrentSubscription
.PARAMETER GetContainerDetails
Performs a deep introspection of each container in blob storage and calculates various statistics. Using this parameter 
may take a long time when large blob stores are located.

.PARAMETER SkipAzureVMandManagedDisks
Do not collect data on Azure VMs or Managed Disks.

.PARAMETER SkipAzureSQLandMI
Do not collect data on Azure SQL or Azure Managed Instances

.PARAMETER SkipAzureStorageAccounts
Do not collect data on Azure Storage Accounts. This includes not collecting data on Azure Blob storage and Azure Files.

.PARAMETER SkipAzureFiles
Do not collect data on Azure Files.

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 2/19/22
Updated: 7/13/22
Updated: 10/20/22
Updated: 01/25/23 - Added support for Azure Mange Groups - Damani
Updated: 07/18/23 - Fixed 25 subscription limit for -AllSubscriptions options - Damani
Updated: 07/20/23 - Added support for Microsoft SQL in an Azure VM.
                    Added support for Azure Files.
                    Added Support for Azure SQL Managed Instances
                    Changed default collection to AllSubscriptions.
                    Improved status reporting

If you run this script and get an error message similar to this:

./Get-AzureVMSQLInfo.ps1: The script 'Get-AzureVMSQLInfo.ps1' cannot be run because the following
modules that are specified by the "#requires" statements of the script are missing: Az.ResourceGraph.

Install the missing module by using the Install-Module command similar to this:

Install-Module -Name Az.ResourceGraph

.EXAMPLE
./Get-AzureVMSQLInfo.ps1
Runs the script against the current subscription context.

.EXAMPLE
./Get-AzureVMSQLInfo.ps1 -Subscriptions "sub1,sub2"
Runs the script against subscriptions 'sub1' and 'sub2'.

.EXAMPLE
./Get-AzureVMSQLInfo.ps1 -AllSubscriptions
Runs the script against all subscriptions in the tenant. 

.EXAMPLE
./Get-AzureVMSQLInfo.ps1 -ManagementGroups "Group1,Group2"
Runs the script against Azure Management Groups 'Group1' and 'Group2'.

.EXAMPLE
./Get-AzureVMSQLInfo.ps1 -SkipAzureStorageAccounts
Runs the script against all subscriptions in the that the user has access to but skips the collection of Azure Storage Account data.

.EXAMPLE
./Get-AzureVMSQLInfo.ps1 -Subscriptions "sub1" -GetContainerDetails
Runs the script against the subscription "sub1" and does a deeper inspection of Azure blob storage

.LINK
https://build.rubrik.com
https://github.com/rubrikinc
https://github.com/stevenctong/rubrik


#>

param (
  [CmdletBinding(DefaultParameterSetName = 'AllSubscriptions')]

  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$GetContainerDetails,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureVMandManagedDisks,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureSQLandMI,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureStorageAccounts,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipAzureFiles,
  [Parameter(ParameterSetName='CurrentSubscription',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [switch]$CurrentSubscription,
  [Parameter(ParameterSetName='Subscriptions',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$Subscriptions = '',
  # Choose to get information for all Azure VMs and/or SQL
  [Parameter(ParameterSetName='AllSubscriptions',
    Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$AllSubscriptions,
  [Parameter(ParameterSetName='ManagementGroups',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$ManagementGroups

)

Import-Module Az.Accounts, Az.Compute, Az.Sql

$azConfig = Get-AzConfig -DisplayBreakingChangeWarning 
Update-AzConfig -DisplayBreakingChangeWarning $false | Out-Null

$date = Get-Date

# Filenames of the CSVs to output
$outputVmDisk = "azure_vmdisk_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputSQL = "azure_sql_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputAzSA = "azure_storage_account_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputAzCon = "azure_container_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputAzFS = "azure_file_share_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputFiles = @()

Write-Host "Current identity:" -ForeGroundColor Green
$context = Get-AzContext
$context | Select-Object -Property Account,Environment,Tenant |  format-table

# Contains list of VMs and SQL DBs with capacity info
$vmList = @()
$sqlList = @()
$azSAList = @()
$azConList = @()
$azFSList = @()

switch ($PSCmdlet.ParameterSetName) {
  'Subscriptions' {
    Write-Host "Gathering subscription information..." -ForegroundColor Green
    $subs = @()
    foreach ($subscription in $Subscriptions.split(',')) {
      write-host "Getting for subscription information for: $($subscription)..."
      try {
        $subs = $subs + $(Get-AzSubscription -SubscriptionName "$subscription" -ErrorAction Stop)
      } catch {
        Write-Error "Unable to get subscription information for subscription: $($subscription)"
        $_
        Continue
      }
    }
  }
  'AllSubscriptions' {
    Write-Host "Gathering subscription information..." -ForegroundColor Green
    try {
      $subs =  Get-AzSubscription -ErrorAction Stop
    } catch {
      Write-Error "Unable to get subscription information from Tenant: $($context.Tenant.Id)"
      $_
      Write-Host "Exiting..." -ForegroundColor Green
      exit      
    }
  } 
  'CurrentSubscription' {
    # If no subscription is specified, only use the current subscription
    Write-Host "Gathering subscription information..." -ForegroundColor Green
    try {
      $subs = Get-AzSubscription -SubscriptionName $context.Subscription.Name -ErrorAction Stop
    } catch {
      Write-Error "Unable to get subscription information from current subscription: $($context.Subscription.Name)"
      $_
      Write-Host "Exiting..." -ForegroundColor Green
      exit
    }
  }
  'ManagementGroups' {
    # If Azure Management Groups are used, look for all subscriptions in the Azure Management Group
    Write-Host "Gathering subscription information..." -ForegroundColor Green
    $subs = @()
    foreach ($managementGroup in $ManagementGroups) {
      try {
        $subs = $subs + $(Get-AzSubscription -SubscriptionName $(Search-AzGraph -Query "ResourceContainers | where type =~ 'microsoft.resources/subscriptions'" -ManagementGroup $managementGroup).name -ErrorAction Stop)
      } catch {
        Write-Error "Unable to gather subscriptions from Management Group: $($managementGroup)"
        $_
        Continue
      }
    }
  }
}


# Get Azure information for all specified subscriptions
$subNum=1
$processedSubs=0
Write-Host "Found $($subs.Count) subscriptions to process." -ForeGroundColor Green
foreach ($sub in $subs) {
  Write-Progress -Id 1 -Activity "Getting information from subscription: $($sub.Name)" -PercentComplete $(($subNum/$subs.Count)*100) -Status "Subscription $($subNum) of $($subs.Count)"
  $subNum++

  try {
    Set-AzContext -SubscriptionName $sub.Name -ErrorAction Stop | Out-Null
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
    $vmObj = [PSCustomObject] @{
      "Name" = $vm.name
      "Disks" = $diskNum
      "SizeGiB" = $diskSizeGiB
      "SizeGB" = [math]::round($($diskSizeGiB * 1.073741824), 3)
      "Subscription" = $sub.Name
      "Tenant" = $tenant.Name
      "Region" = $vm.Location
      "ResourceGroup" = $vm.ResourceGroupName
      "vmID" = $vm.vmID
      "InstanceType" = $vm.HardwareProfile.vmSize
      "Status" = $vm.StatusCode
      "HasMSSQL" = "No"
    }
    $vmList += $vmObj
  }
  Write-Progress -Id 2 -Activity "Getting VM information for: $($vm.Name)" -Completed

  # Get a list of all VMs that have MSSQL in them.
  try {
    $sqlVms = Get-AzSQLVM
  } catch {
    Write-Error "Unable to collect SQL VM information for subscription: $($sub.Name)"
    $_
    Continue
  }

  # Loop through each SQL VM to and update VM status
  $sqlVmNum=1
  foreach ($sqlVm in $sqlVms) {
    Write-Progress -Id 3 -Activity "Getting SQL VM information for: $($sqlVm.Name)" -PercentComplete $(($sqlVmNum/$sqlVms.Count)*100) -ParentId 1 -Status "SQL VM $($sqlVmNum) of $($sqlVms.Count)"
    $sqlVmNum++
    if ($vmToUpdate = $vmList | Where-Object { $_.Name -eq $sqlVm.Name }) {
      $vmToUpdate.HasMSSQL = "Yes"
    } 
  }
  Write-Progress -Id 3 -Activity "Getting VM information for: $($vm.Name)" -Completed
  } #if ($SkipAzureVMandManagedDisks -ne $true) 
  
  if ($SkipAzureSQLandMI -ne $true) {
  # Get all Azure SQL servers
  try {
    $sqlServers = Get-AzSqlServer -ErrorAction Stop
  } catch {
    Write-Error "Unable to collect Azure SQL Server information for subscription: $($sub.Name)"
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
      Write-Error "Unable to collect Azure SQL Server database information for Azure SQL Database server: $($sqlServer.ServerName)"
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
            Write-Error "Unable to collect Azure SQL Server Elastic Pool information for Azure SQL Database server: $($sqlServer.ServerName)"
            $_
            Continue    
          }
          # Loop through the pools on the current database.
          foreach ($pool in $pools) {
            # Check if the current Elastic Pool already exists in the SQL list
            $poolName = $sqlList | Where-Object -Property 'ElasticPool' -eq $pool.ElasticPoolName
            # If Elastic Pool does not exist then add it
            if ($null -eq $poolName) {
              $sqlObj = [PSCustomObject] @{
                "Database" = ""
                "Server" = ""
                "ElasticPool" = $pool.ElasticPoolName
                "ManagedInstance" = ""
                "MaxSizeGiB" = [math]::round($($pool.MaxSizeBytes / 1073741824), 0)
                "MaxSizeGB" = [math]::round($($pool.MaxSizeBytes / 1000000000), 3)
                "Subscription" = $sub.Name
                "Tenant" = $tenant.Name
                "Region" = $pool.Location
                "ResourceGroup" = $pool.ResourceGroupName
                "DatabaseID" = ""
                "InstanceType" = $pool.SkuName
                "Status" = $pool.Status
              }
              $sqlList += $sqlObj
            }
          } #foreach ($pool in $pools)
        } else {
          $sqlObj = [PSCustomObject] @{
            "Database" = $sqlDB.DatabaseName
            "Server" = $sqlDB.ServerName
            "ElasticPool" = ""
            "ManagedInstance" = ""
            "MaxSizeGiB" = [math]::round($($sqlDB.MaxSizeBytes / 1073741824), 0)
            "MaxSizeGB" = [math]::round($($sqlDB.MaxSizeBytes / 1000000000), 3)
            "Subscription" = $sub.Name
            "Tenant" = $tenant.Name
            "Region" = $sqlDB.Location
            "ResourceGroup" = $sqlDB.ResourceGroupName
            "DatabaseID" = $sqlDB.DatabaseId
            "InstanceType" = $sqlDB.SkuName
            "Status" = $sqlDB.Status
          }
          $sqlList += $sqlObj
        }  # else not an Elastic Pool but normal SQL DB
      }  # if ($sqlDB.SkuName -ne 'System')
    }  # foreach ($sqlDB in $sqlDBs)
  }  # foreach ($sqlServer in $sqlServers)
  Write-Progress -Id 4 -Activity "Getting Azure SQL information for SQL Server: $($sqlServer.ServerName)" -Completed

  # Get all Azure Managed Instances
  try {
    $sqlManagedInstances = Get-AzSqlInstance -ErrorAction Stop
  } catch {
    Write-Error "Unable to collect Azure Manged Instance information for subscription: $($sub.Name)"
    $_
    Continue    
  }

  # Loop through each SQL Managed Instances to get size info
  $managedInstanceNum=1
  foreach ($MI in $sqlManagedInstances) {
    Write-Progress -Id 5 -Activity "Getting Azure Managed Instance information for: $($MI.ManagedInstanceName)" -PercentComplete $(($managedInstanceNum/$sqlManagedInstances.Count)*100) -ParentId 1 -Status "SQL Managed Instance $($managedInstanceNum) of $($sqlManagedInstances.Count)"
    $managedInstanceNum++
    $sqlObj = [PSCustomObject] @{
      "Database" = ""
      "Server" = ""
      "ElasticPool" = ""
      "ManagedInstance" = $MI.ManagedInstanceName
      "MaxSizeGiB" = $MI.StorageSizeInGB
      "MaxSizeGB" = [math]::round($($MI.StorageSizeInGB * 1.073741824), 3)
      "Subscription" = $sub.Name
      "Tenant" = $tenant.Name
      "Region" = $MI.Location
      "ResourceGroup" = $MI.ResourceGroupName
      "DatabaseID" = ""
      "InstanceType" = $MI.Sku.Name
      "Status" = $MI.Status
    }
    $sqlList += $sqlObj
  } # foreach ($MI in $sqlManagedInstances)
  Write-Progress -Id 5 -Activity "Getting Azure Managed Instance information for: $($MI.ManagedInstanceName)" -Completed
  } #if ($SkipAzureSQLandMI -ne $true)

  if ($SkipAzureStorageAccounts -ne $true) {
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
    Write-Progress -Id 6 -Activity "Getting Storage Account information for: $($azSA.StorageAccountName)" -PercentComplete $(($azSANum/$azSAs.Count)*100) -ParentId 1 -Status "Azure Storage Account $($azSANum) of $($azSAs.Count)"
    $azSANum++
    $azSAContext = (Get-AzStorageAccount  -Name $azSA.StorageAccountName -ResourceGroupName $azSA.ResourceGroupName).Context
      $azSAResourceId = "/subscriptions/$($sub.Id)/resourceGroups/$($azSA.ResourceGroupName)/providers/Microsoft.Storage/storageAccounts/$($azSA.StorageAccountName)"
      $azSAUsedCapacity = (Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId $azSAResourceId `
        -MetricName UsedCapacity `
        -AggregationType Average `
        -StartTime (Get-Date).AddDays(-1)).Data.Average
      $metrics = @("BlobCapacity", "ContainerCount", "BlobCount")
      $azSABlob = (Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId "$($azSAResourceId)/blobServices/default" `
        -MetricNames $metrics `
        -AggregationType Average `
        -StartTime (Get-Date).AddDays(-1))
      $metrics = @("FileCapacity", "FileShareCount", "FileCount")
      $azSAFile = Get-AzMetric -WarningAction SilentlyContinue `
        -ResourceId "$($azSAResourceId)/fileServices/default" `
        -MetricNames $metrics `
        -AggregationType Average `
        -StartTime (Get-Date).AddDays(-1)

      $azSAObj = [PSCustomObject] @{
        "StorageAccount" = $azSA.StorageAccountName
        "StorageAccountType" = $azSA.Kind
        "StorageAccountSkuName" = $azSA.Sku.Name
        "StorageAccountAccessTier" = $azSA.AccessTier
        "Tenant" = $tenant.Name
        "Subscription" = $sub.Name
        "Region" = $azSA.PrimaryLocation
        "ResourceGroup" = $azSA.ResourceGroupName
        "UsedCapacityBytes" = $azSAUsedCapacity | Select-Object -Last 1
        "UsedCapacityGiB" = [math]::round($([double](($azSAUsedCapacity | Select-Object -Last 1)) / 1073741824), 0)
        "UsedCapacityGB" = [math]::round($([double](($azSAUsedCapacity | Select-Object -Last 1)) / 1000000000), 3)      
        "UsedBlobCapacityBytes" = ($azSABlob | where-object {$_.id -like "*BlobCapacity"}).Data.Average | Select-Object -Last 1
        "UsedBlobCapacityGiB" = [math]::round($([double]((($azSABlob | where-object {$_.id -like "*BlobCapacity"}).Data.Average | Select-Object -Last 1)) / 1073741824), 0)
        "UsedBlobCapacityGB" = [math]::round($([double]((($azSABlob | where-object {$_.id -like "*BlobCapacity"}).Data.Average | Select-Object -Last 1)) / 1000000000), 3)      
        "BlobContainerCount" = ($azSABlob | where-object {$_.id -like "*ContainerCount"}).Data.Average | Select-Object -Last 1
        "BlobCount" = ($azSABlob | where-object {$_.id -like "*BlobCount"}).Data.Average | Select-Object -Last 1
        "UsedFileShareCapacityBytes" = ($azSAFile | where-object {$_.id -like "*FileCapacity"}).Data.Average | Select-Object -Last 1
        "UsedFileShareCapacityGiB" = [math]::round($([double]((($azSAFile | where-object {$_.id -like "*FileCapacity"}).Data.Average | Select-Object -Last 1)) / 1073741824), 0)
        "UsedFileShareCapacityGB" = [math]::round($([double]((($azSAFile | where-object {$_.id -like "*FileCapacity"}).Data.Average | Select-Object -Last 1)) / 1000000000), 3)      
        "FileShareCount" = ($azSAFile | where-object {$_.id -like "*FileShareCount"}).Data.Average | Select-Object -Last 1
        "FileCountInFileShares" = ($azSAFile | where-object {$_.id -like "*FileCount"}).Data.Average | Select-Object -Last 1
      }
      $azSAList += $azSAObj
      
      if ($GetContainerDetails -eq $true) {
        # Loop through each Azure Container and record capacities    
        try {
          $azCons = Get-AzStorageContainer -Context $azSAContext -ErrorAction Stop
        }
        catch {
          Write-Error "Error getting Azure Container information from: $($azSA.StorageAccountName) storage account."
          $_
          $azCons = @()
        }
        $azConNum = 1
        foreach ($azCon in $azCons) {
          Write-Progress -Id 7 -Activity "Getting Azure Container information for: $($azCon.Name)" -PercentComplete $(($azConNum/$azCons.Count)*100) -ParentId 6 -Status "Azure Container $($azConNum) of $($azCons.Count)"
          $azConNum++
          $azConBlobs = Get-AzStorageBlob -Container $($azCon.Name) -Context $azSAContext
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
          $azConObj = [PSCustomObject] @{
            "Name" = $azCon.Name
            "StorageAccount" = $azSA.StorageAccountName
            "StorageAccountType" = $azSA.Kind
            "StorageAccountSkuName" = $azSA.Sku.Name
            "StorageAccountAccessTier" = $azSA.AccessTier
            "Tenant" = $tenant.Name
            "Subscription" = $sub.Name
            "Region" = $azSA.PrimaryLocation
            "ResourceGroup" = $azSA.ResourceGroupName
            "UsedCapacityHotTierBytes" = $lengthHotTier
            "UsedCapacityHotTierGiB" = [math]::round($($lengthHotTier / 1073741824), 0)
            "UsedCapacityHotTierGB" = [math]::round($($lengthHotTier / 1000000000), 3)        
            "HotTierBlobCount" = @($azConBlobs | Where-Object {$_.AccessTier -eq "Hot" -and $_.SnapshotTime -eq $null}).Count
            "UsedCapacityCoolTierBytes" = $lengthCoolTier
            "UsedCapacityCoolTierGiB" = [math]::round($($lengthCoolTier / 1073741824), 0)
            "UsedCapacityCoolTierGB" = [math]::round($($lengthCoolTier / 1000000000), 3)        
            "CoolTierBlobCount" = @($azConBlobs | Where-Object {$_.AccessTier -eq "Cool" -and $_.SnapshotTime -eq $null}).Count
            "UsedCapacityArchiveTierBytes" = $lengthArchiveTier
            "UsedCapacityArchiveTierGiB" = [math]::round($($lengthArchiveTier / 1073741824), 0)
            "UsedCapacityArchiveTierGB" = [math]::round($($lengthArchiveTier / 1000000000), 3)        
            "ArchiveTierBlobCount" = @($azConBlobs | Where-Object {$_.AccessTier -eq "Archive" -and $_.SnapshotTime -eq $null}).Count
            "UsedCapacityUnknownTierBytes" = $lengthUnknownTier
            "UsedCapacityUnknownTierGiB" = [math]::round($($lengthUnknownTier / 1073741824), 0)
            "UsedCapacityUnknownTierGB" = [math]::round($($lengthUnknownTier / 1000000000), 3)
            "UnknownTierBlobCount" = ($azConBlobs| Where-Object {$_.SnapshotTime -eq $null}).Count
            "UsedCapacityAllTiersBytes" = $lengthAllTiers
            "UsedCapacityAllTiersGiB" = [math]::round($($lengthAllTiers / 1073741824), 0)
            "UsedCapacityAllTiersGB" = [math]::round($($lengthAllTiers / 1000000000), 3)
            "AllTiersBlobCount" = ($azConBlobs | Where-Object {$_.SnapshotTime -eq $null}).Count
        }      
        $azConList += $azConObj
        } #foreach ($azCon in $azCons)
        Write-Progress -Id 7 -Activity "Getting Azure Container information for: $($azCon.Name)" -Completed
      } #if ($GetContainerDetails -eq $true)
      
      if ($SkipAzureFiles -ne $true) {
        # Loop through each Azure File Share and record capacities    
        try {
          $azFSs = Get-AzStorageShare -Context $azSAContext -ErrorAction Stop | Where-Object -Property IsSnapshot -eq $false
    }
    catch {
          Write-Error "Error getting Azure File Storage information from: $($azSA.StorageAccountName) storage account."
      $_
          $azFSs = @()
    }
    $azFSNum = 1
    # Loop through each Azure File Share and record capacities    
    foreach ($azFS in $azFSs) {
      Write-Progress -Id 7 -Activity "Getting Azure File Share information for: $($azFS.Name)" -PercentComplete $(($azFSNum/$azFSs.Count)*100) -ParentId 6 -Status "Azure File Share $($azFSNum) of $($azFSs.Count)"
          $azFSNum++
      $azFSClient = $azFS.ShareClient
      $azFSStats = $azFSClient.GetStatistics()
      $azFSObj = [PSCustomObject] @{
        "Name" = $azFS.Name
        "StorageAccount" = $azSA.StorageAccountName
            "StorageAccountType" = $azSA.Kind
            "StorageAccountSkuName" = $azSA.Sku.Name
            "StorageAccountAccessTier" = $azSA.AccessTier
        "Tenant" = $tenant.Name
        "Subscription" = $sub.Name
        "Region" = $azSA.PrimaryLocation
        "ResourceGroup" = $azSA.ResourceGroupName
        "QuotaGiB" = $azFS.Quota
        "UsedCapacityBytes" = $azFSStats.Value.ShareUsageInBytes
        "UsedCapacityGiB" = [math]::round($($azFSStats.Value.ShareUsageInBytes / 1073741824), 0)
        "UsedCapacityGB" = [math]::round($($azFSStats.Value.ShareUsageInBytes / 1000000000), 3)        
      }
    $azFSList += $azFSObj
    } #foreach ($azFS in $azFSs)
    Write-Progress -Id 7 -Activity "Getting Azure File Share information for: $($azFS.Name)" -Completed
      } #if ($SkipAzureFiles -ne $true)
  } # foreach ($azSA in $azSAs)
  Write-Progress -Id 6 -Activity "Getting Storage Account information for: $($azSA.StorageAccountName)" -Completed
  } # if ($SkipAzureStorageAccounts -ne $true)
} # foreach ($sub in $subs)
Write-Progress -Id 1 -Activity "Getting information from subscription: $($sub.Name)" -Completed

Write-Host "Calculating results and saving data..." -ForegroundColor Green

if ($SkipAzureVMandManagedDisks -ne $true) {

  $VMtotalGiB = ($vmList.SizeGiB | Measure-Object -Sum).sum
  $VMtotalGB = ($vmList.SizeGB | Measure-Object -Sum).sum

  $sqlTotalGiB = ($sqlList.MaxSizeGiB | Measure-Object -Sum).sum
  $sqlTotalGB = ($sqlList.MaxSizeGB | Measure-Object -Sum).sum

  Write-Host
  Write-Host "Successfully collected data from $($processedSubs) out of $($subs.count) found subscriptions"  -ForeGroundColor Green
  Write-Host
  Write-Host "Total # of Azure VMs: $('{0:N0}' -f $vmList.count)" -ForeGroundColor Green
  Write-Host "Total # of Managed Disks: $('{0:N0}' -f ($vmList.Disks | Measure-Object -Sum).sum)" -ForeGroundColor Green
  Write-Host "Total capacity of all disks: $('{0:N0}' -f $VMtotalGiB) GiB or $('{0:N0}' -f $VMtotalGB) GB" -ForeGroundColor Green
  $outputFileObj = [PSCustomObject] @{ 
    "Files" = "Azure VM and Managed Disk CSV file output saved to: $outputVmDisk"
  }
  $outputFiles += $outputFileObj
  $vmList | Export-CSV -path $outputVmDisk

} #if ($SkipAzureVMandManagedDisks -ne $true)

if ($SkipAzureSQLandMI -ne $true) {
  $DBtotalGiB = (($sqlList | Where-Object -Property 'Database' -ne '').MaxSizeGiB | Measure-Object -Sum).sum
  $DBtotalGB = (($sqlList | Where-Object -Property 'Database' -ne '').MaxSizeGB | Measure-Object -Sum).sum
  $elasticTotalGiB = (($sqlList | Where-Object -Property 'ElasticPool' -ne '').MaxSizeGiB | Measure-Object -Sum).sum
  $elasticTotalGB = (($sqlList | Where-Object -Property 'ElasticPool' -ne '').MaxSizeGB | Measure-Object -Sum).sum
  $MITotalGiB = (($sqlList | Where-Object -Property 'ManagedInstance' -ne '').MaxSizeGiB | Measure-Object -Sum).sum
  $MITotalGB = (($sqlList | Where-Object -Property 'ManagedInstance' -ne '').MaxSizeGB | Measure-Object -Sum).sum
  Write-Host
  Write-Host "Total # of SQL DBs (independent): $('{0:N0}' -f ($sqlList | Where-Object -Property 'Database' -ne '').Count)" -ForeGroundColor Green
  Write-Host "Total # of SQL Elastic Pools: $('{0:N0}' -f ($sqlList | Where-Object -Property 'ElasticPool' -ne '').Count)" -ForeGroundColor Green
  Write-Host "Total # of SQL Managed Instances: $('{0:N0}' -f ($sqlList | Where-Object -Property 'ManagedInstance' -ne '').Count)" -ForeGroundColor Green
  Write-Host "Total capacity of all SQL DBs (independent): $('{0:N0}' -f $DBtotalGiB) GiB or $('{0:N0}' -f $DBtotalGB) GB" -ForeGroundColor Green
  Write-Host "Total capacity of all SQL Elastic Pools: $('{0:N0}' -f $elasticTotalGiB) GiB or $('{0:N0}' -f $elasticTotalGB) GB" -ForeGroundColor Green
  Write-Host "Total capacity of all SQL Managed Instances: $('{0:N0}' -f $MITotalGiB) GiB or $('{0:N0}' -f $MITotalGB) GB" -ForeGroundColor Green
  Write-Host
  Write-Host "Total # of SQL DBs, Elastic Pools & Managed Instances: $('{0:N0}' -f $sqlList.count)" -ForeGroundColor Green
  Write-Host "Total capacity of all SQL: $('{0:N0}' -f $sqlTotalGiB) GiB or $('{0:N0}' -f $sqlTotalGB) GB" -ForeGroundColor Green
  $outputFileObj = [PSCustomObject] @{ 
    "Files" = "Azure SQL/MI CSV file output saved to: $outputSQL"
  }
  $outputFiles += $outputFileObj
  $sqlList | Export-CSV -path $outputSQL
} #if ($SkipAzureSQLandMI -ne $true)

if ($SkipAzureStorageAccounts -ne $true) {
  $azSATotalGiB = ($azSAList.UsedCapacityGiB | Measure-Object -Sum).sum
  $azSATotalGB = ($azSAList.UsedCapacityGB | Measure-Object -Sum).sum
  $azSATotalBlobGiB = ($azSAList.UsedBlobCapacityGiB | Measure-Object -Sum).sum
  $azSATotalBlobGB = ($azSAList.UsedBlobCapacityGB | Measure-Object -Sum).sum
  $azSATotalBlobObjects = ($azSAList.BlobCount | Measure-Object -Sum).sum
  $azSATotalBlobContainers = ($azSAList.BlobContainerCount | Measure-Object -Sum).sum
  $azSATotalFileGiB = ($azSAList.UsedFileShareCapacityGiB | Measure-Object -Sum).sum
  $azSATotalFileGB = ($azSAList.UsedFileShareCapacityGB | Measure-Object -Sum).sum
  $azSATotalFileObjects = ($azSAList.FileCountInFileShares | Measure-Object -Sum).sum
  $azSATotalFileShares = ($azSAList.FileShareCount | Measure-Object -Sum).sum
  Write-Host
  Write-Host "Totals based on querying storage account metrics:"
  Write-Host "Total # of Azure Storage Accounts: $('{0:N0}' -f $azSAList.count)" -ForeGroundColor Green
  Write-Host "Total capacity of all Azure Storage Accounts: $('{0:N0}' -f $azSATotalGiB) GiB or $('{0:N0}' -f $azSATotalGB) GB" -ForeGroundColor Green
  Write-Host "Total capacity of all Azure Blob storage in Azure Storage Accounts: $('{0:N0}' -f $azSATotalBlobGiB) GiB or $('{0:N0}' -f $azSATotalBlobGB) GB" -ForeGroundColor Green
  Write-Host "Total number blobs is $('{0:N0}' -f $azSATotalBlobObjects) in $('{0:N0}' -f $azSATotalBlobContainers) containers." -ForeGroundColor Green
  Write-Host "Total capacity of all Azure File storage in Azure Storage Accounts: $('{0:N0}' -f $azSATotalFileGiB) GiB or $('{0:N0}' -f $azSATotalFileGB) GB" -ForeGroundColor Green
  Write-Host "Total number files is $('{0:N0}' -f $azSATotalFileObjects) in $('{0:N0}' -f $azSATotalFileShares) Azure File Shares." -ForeGroundColor Green

  $outputFileObj = [PSCustomObject] @{ 
    "Files" = "Azure Storage Account CSV file output saved to: $outputAzSA"
  }
  $outputFiles += $outputFileObj
  $azSAList | Export-CSV -path $outputAzSA

  if ($GetContainerDetails -eq $true) {
    $azConTotalGiB = ($azConList.UsedCapacityAllTiersGiB | Measure-Object -Sum).sum
    $azConTotalGB = ($azConList.UsedCapacityAllTiersGB | Measure-Object -Sum).sum
    $azConTotalGiB = ($azConList.UsedCapacityGiB | Measure-Object -Sum).sum
    $azConTotalGB = ($azConList.UsedCapacityGB | Measure-Object -Sum).sum
    Write-Host
    Write-Host "Totals based on traversing each blob store container and calculating statistics:"
    Write-Host "NOTE: The totals may be different than those gathered from Storage Account metrics if"
    Write-Host "some containers could not be accessed. There are also differences in the way these two metrics"
    Write-Host "are calculated by Azure."
    Write-Host "Total # of Azure Containers: $('{0:N0}' -f $azConList.count)" -ForeGroundColor Green
    Write-Host "Total capacity of all Azure Containers: $('{0:N0}' -f $azConTotalGiB) GiB or $('{0:N0}' -f $azConTotalGB) GB" -ForeGroundColor Green
    $outputFileObj = [PSCustomObject] @{ 
      "Files" = "Azure Container CSV file output saved to: $outputAzCon"
    }
    $outputFiles += $outputFileObj
    $azConList | Export-CSV -path $outputAzCon
  }

  if ($SkipAzureFiles -ne $true) {
    $azFSTotalGiB = ($azFSList.UsedCapacityGiB | Measure-Object -Sum).sum
    $azFSTotalGB = ($azFSList.UsedCapacityGB | Measure-Object -Sum).sum
    Write-Host
    Write-Host "Totals based on traversing each Azure File Share adn calculating statistics:"
    Write-Host "Note: The totals may be different than those gathered from Storage Account metrics if"
    Write-Host "the Azure File Share could not be accessed. There are also differences in the way these two metrics"
    Write-Host "are calculated by Azure."
    Write-Host "Total # of Azure File Shares: $('{0:N0}' -f $azFSList.count)" -ForeGroundColor Green
    Write-Host "Total capacity of all Azure File Shares: $('{0:N0}' -f $azFSTotalGiB) GiB or $('{0:N0}' -f $azFSTotalGB) GB" -ForeGroundColor Green
    $outputFileObj = [PSCustomObject] @{ 
      "Files" = "Azure File Share CSV file output saved to: $outputAzFS"
    }
    $outputFiles += $outputFileObj
    $azFSList | Export-CSV -path $outputAzFS
  }
} #if ($SkipAzureStorageAccounts -ne $true)

Write-Host
Write-Host "Output files are:"
$outputFiles.Files
Write-Host

# Reset subscription context back to original.
try {
  Set-AzContext -SubscriptionName $context.subscription.Name -ErrorAction Stop | Out-Null
} catch {
  Write-Error "Unable to reset AzContext back to original context."
  $_
}

$VMtotalGiB = ($vmList.SizeGiB | Measure-Object -Sum).sum
$VMtotalGB = ($vmList.SizeGB | Measure-Object -Sum).sum

$sqlTotalGiB = ($sqlList.MaxSizeGiB | Measure-Object -Sum).sum
$sqlTotalGB = ($sqlList.MaxSizeGB | Measure-Object -Sum).sum
$DBtotalGiB = (($sqlList | Where-Object -Property 'Database' -ne '').MaxSizeGiB | Measure-Object -Sum).sum
$DBtotalGB = (($sqlList | Where-Object -Property 'Database' -ne '').MaxSizeGB | Measure-Object -Sum).sum
$elasticTotalGiB = (($sqlList | Where-Object -Property 'ElasticPool' -ne '').MaxSizeGiB | Measure-Object -Sum).sum
$elasticTotalGB = (($sqlList | Where-Object -Property 'ElasticPool' -ne '').MaxSizeGB | Measure-Object -Sum).sum
$MITotalGiB = (($sqlList | Where-Object -Property 'ManagedInstance' -ne '').MaxSizeGiB | Measure-Object -Sum).sum
$MITotalGB = (($sqlList | Where-Object -Property 'ManagedInstance' -ne '').MaxSizeGB | Measure-Object -Sum).sum
$azFSTotalGiB = ($azFSList.UsedCapacityGiB | Measure-Object -Sum).sum
$azFSTotalGB = ($azFSList.UsedCapacityGB | Measure-Object -Sum).sum

Write-Host
Write-Host "Successfully collected data from $($processedSubs) out of $($subs.count) found subscriptions"  -ForeGroundColor Green
Write-Host
Write-Host "Total # of Azure VMs: $($vmList.count)" -ForeGroundColor Green
Write-Host "Total # of Managed Disks: $(($vmList.Disks | Measure-Object -Sum).sum)" -ForeGroundColor Green
Write-Host "Total capacity of all disks: $VMtotalGiB GiB or $VMtotalGB GB" -ForeGroundColor Green

Write-Host
Write-Host "Total # of Azure File Shares: $($azFSList.count)" -ForeGroundColor Green
Write-Host "Total capacity of all Azure File shares: $azFSTotalGiB GiB or $azFSTotalGB GB" -ForeGroundColor Green

Write-Host
Write-Host "Total # of SQL DBs (independent): $(($sqlList.Database -ne '').count)" -ForeGroundColor Green
Write-Host "Total # of SQL Elastic Pools: $(($sqlList.ElasticPool -ne '').count)" -ForeGroundColor Green
Write-Host "Total # of SQL Managed Instances: $(($sqlList.ManagedInstance -ne '').count)" -ForeGroundColor Green
Write-Host "Total capacity of all SQL DBs (independent): $DBtotalGiB GiB or $DBtotalGB GB" -ForeGroundColor Green
Write-Host "Total capacity of all SQL Elastic Pools: $elasticTotalGiB GiB or $elasticTotalGB GB" -ForeGroundColor Green
Write-Host "Total capacity of all SQL Managed Instances: $MITotalGiB GiB or $MITotalGB GB" -ForeGroundColor Green

Write-Host
Write-Host "Total # of SQL DBs, Elastic Pools & Managed Instances: $($sqlList.count)" -ForeGroundColor Green
Write-Host "Total capacity of all SQL: $sqlTotalGiB GiB or $sqlTotalGB GB" -ForeGroundColor Green

# Export to CSV
Write-Host ""
Write-Host "VM CSV file output to: $outputVmDisk" -ForeGroundColor Green
$vmList | Export-CSV -path $outputVmDisk
Write-Host "Azure SQL/MI CSV file output to: $outputSQL" -ForeGroundColor Green
$sqlList | Export-CSV -path $outputSQL
Write-Host "Azure File Share CSV file output to: $outputAzFS" -ForeGroundColor Green
$azFSList | Export-CSV -path $outputAzFS

if ($azConfig.Value -eq $true) {
  try {
    Update-AzConfig -DisplayBreakingChangeWarning $true  -ErrorAction Stop | Out-Null
  } catch {
    Write-Error "Unable to rest display of breaking changes."
    $_
  }
}
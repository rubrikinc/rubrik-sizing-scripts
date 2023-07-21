#requires -Modules Az.Accounts, Az.Compute, Az.Sql, Az.ResourceGraph

<#
.SYNOPSIS
Gets all Azure VM Managed Disk and/or Azure SQL info in the specified subscription(s).

.DESCRIPTION
The 'Get-AzureVMSQLInfo.ps1' script gets all VM Managed Disk and/or Azure SQL info in the specified subscription(s).
You can specify one or more subscription to run the script against. 
You can also specify to discover and report on all subscriptions with in the tenant that Powershell is logged into.
If no subscription is specified then it will gather info against the current subscription context.

This script requires the Azure Powershell module. That module can be installed by running  `Install-Module Az`
If not already done use the `Connect-AzAccount` command to connect to a specific Azure Tenant to report on.

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
Flog to only gather information from the current subscription.

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


.LINK
https://build.rubrik.com
https://github.com/rubrikinc
https://github.com/stevenctong/rubrik


#>

param (
  [CmdletBinding(DefaultParameterSetName = 'CurrentSubscription')]

  # Choose to get info for only Azure VMs and/or SQL
  [Parameter(ParameterSetName='UserSubscriptions',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$Subscriptions = '',
  # Choose to get info for all Azure VMs and/or SQL
  [Parameter(ParameterSetName='AllSubscriptions',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [switch]$AllSubscriptions,
  [Parameter(ParameterSetName='CurrentSubscription',
    Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$CurrentSubscription,
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
$outputAzFS = "azure_file_share_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"

Write-Host "Current identity:" -foregroundcolor green
$context = Get-AzContext
$context | Select-Object -Property Account,Environment,Tenant |  format-table

# Contains list of VMs and SQL DBs with capacity info
$vmList = @()
$sqlList = @()
$azFSList = @()

switch ($PSCmdlet.ParameterSetName) {
    Write-Host "Gathering subscription information..." -ForegroundColor Green
    $subs = @()
    foreach ($subscription in $Subscriptions.split(',')) {
      write-host "Getting for sub: $($subscription)"
      $subs = $subs + $(Get-AzSubscription -SubscriptionName "$subscription")
    }
  }
  'AllSubscriptions' {
    Write-Host "Gathering subscription information..." -ForegroundColor Green
    $subs =  Get-AzSubscription
  } 
  'CurrentSubscription' {
    # If no subscription is specified, only use the current subscription
    Write-Host "Gathering subscription information..." -ForegroundColor Green
    $subs = Get-AzSubscription -SubscriptionName $context.subscription.name
  }
  'ManagementGroups' {
    # If Azure Management Groups are used, look for all subscriptions in the Azure Management Group
    Write-Host "Gathering subscription information..." -ForegroundColor Green
    $subs = @()
    foreach ($managementGroup in $ManagementGroups) {
      $subs = $subs + $(Get-AzSubscription -SubscriptionName $(Search-AzGraph -Query "ResourceContainers | where type =~ 'microsoft.resources/subscriptions'" -ManagementGroup $managementGroup).name)
    }
  }
}


# Get Azure info for all specified subscriptions
$subNum=1
$processedSubs=0
Write-Host "Found $($subs.Count) subscriptions to process." -ForeGroundColor Green
foreach ($sub in $subs) {
  Write-Progress -Id 1 -Activity "Getting info from subscription: $($sub.Name)" -PercentComplete $(($subNum/$subs.Count)*100) -Status "Subscription $($subNum) of $($subs.Count)"
  $subNum++

  try {
    Set-AzContext -SubscriptionName $sub.Name | Out-Null
  } catch {
    Write-Error "Error switching to subscription: $($sub.Name)"
    Write-Error $_
    break
  }

  #Get tenant name for subscription
  try {
    $tenant = Get-AzTenant -TenantId $($sub.TenantId)
  } catch {
    Write-Error "Error getting tenant information for: $($sub.TenantId))"
    Write-Error $_
    break
  }
  $processedSubs++

  # Get a list of all VMs in the current subscription
  $vms = Get-AzVM

  # Loop through each VM to get all disk info
  $vmNum=1
  foreach ($vm in $vms) {
    Write-Progress -Id 2 -Activity "Getting VM info for: $($vm.Name)" -PercentComplete $(($vmNum/$vms.Count)*100) -ParentId 1 -Status "VM $($vmNum) of $($vms.Count)"
    $vmNum++
    # Count of and size of all disks attached to the VM
    $diskNum = 0
    $diskSizeGiB = 0
    # Loop through each OS disk on the VM and add to the disk info
    foreach ($osDisk in $vm.StorageProfile.osdisk)
    {
      $diskNum += 1
      $diskSizeGiB += [int]$osDisk.DiskSizeGB
    }
    # Loop through each data disk on the VM and add to the disk info
    foreach ($dataDisk in $vm.StorageProfile.dataDisks)
    {
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
  Write-Progress -Id 2 -Activity "Getting VM info for: $($vm.Name)" -Completed

  # Get a list of all VMs that have MSSQL in them.
  $sqlVms = Get-AzSQLVM

  # Loop through each SQL VM to and update VM status
  $sqlVmNum=1
  foreach ($sqlVm in $sqlVms) {
    Write-Progress -Id 3 -Activity "Getting SQL VM info for: $($sqlVm.Name)" -PercentComplete $(($sqlVmNum/$sqlVms.Count)*100) -ParentId 1 -Status "SQL VM $($sqlVmNum) of $($sqlVms.Count)"
    $sqlVmNum++
    if ($vmToUpdate = $vmList | Where-Object { $_.Name -eq $sqlVm.Name }) {
      $vmToUpdate.HasMSSQL = "Yes"
    } 
  }
  Write-Progress -Id 3 -Activity "Getting VM info for: $($vm.Name)" -Completed

  # Get all Azure SQL servers
  $sqlServers = Get-AzSqlServer

  # Loop through each SQL server to get size info
  $sqlServerNum=1
  foreach ($sqlServer in $sqlServers) {
    Write-Progress -Id 4 -Activity "Getting Azure SQL info for SQL Server: $($sqlServer.ServerName)" -PercentComplete $(($sqlServerNum/$sqlServers.Count)*100) -ParentId 1 -Status "Azure SQL Server $($sqlServerNum) of $($sqlServers.Count)"
    $sqlServerNum++
    # Get all SQL DBs on the current SQL server
    $sqlDBs = Get-AzSqlDatabase -serverName $sqlServer.ServerName -ResourceGroupName $sqlServer.ResourceGroupName
    # Loop through each SQL DB on the current SQL server to gather size info
    foreach ($sqlDB in $sqlDBs)
    {
      # Only count SQL DBs that are not SYSTEM DBs
      if ($sqlDB.SkuName -ne 'System')
      {
        # If SQL DB is in an Elastic Pool, count the max capacity of Elastic Pool and not the DB
        if ($sqlDB.SkuName -eq 'ElasticPool')
        {
          # Get Elastic Pool info for the current DB
          $pool = Get-AzSqlElasticPool -servername $sqlDB.ServerName -ResourceGroupName $sqlDB.ResourceGroupName
          # Check if the current Elastic Pool already exists in the SQL list
          $poolName = $sqlList | Where-Object -Property 'ElasticPool' -eq $pool.ElasticPoolName
          # If Elastic Pool does not exist then add it
          if ($null -eq $poolName)
          {
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
  Write-Progress -Id 4 -Activity "Getting Azure SQL info for SQL Server: $($sqlServer.ServerName)" -Completed

  # Get all Azure Managed Instances
  $sqlManagedInstances = Get-AzSqlInstance

  # Loop through each SQL Managed Instances to get size info
  $managedInstanceNum=1
  foreach ($MI in $sqlManagedInstances) {
    Write-Progress -Id 5 -Activity "Getting Azure Managed Instance info for: $($MI.ManagedInstanceName)" -PercentComplete $(($managedInstanceNum/$sqlManagedInstances.Count)*100) -ParentId 1 -Status "SQL Managed Instance $($managedInstanceNum) of $($sqlManagedInstances.Count)"
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
  Write-Progress -Id 5 -Activity "Getting Azure Managed Instance info for: $($MI.ManagedInstanceName)" -Completed

  # Get a list of all Azure Storage Accounts.
  $azSAs = Get-AzStorageAccount

  # Loop through each Azure Storage Account and gather statistics
  $azSANum=1
  foreach ($azSA in $azSAs) {
    Write-Progress -Id 6 -Activity "Getting Storage Account info for: $($azSA.StorageAccountName)" -PercentComplete $(($azSANum/$azSAs.Count)*100) -ParentId 1 -Status "Azure Storage Account $($azSANum) of $($azSAs.Count)"
    $azSANum++
    $azSAContext = (Get-AzStorageAccount  -Name $azSA.StorageAccountName -ResourceGroupName $azSA.ResourceGroupName).Context
    $azFSs = Get-AzStorageShare -Context $azSAContext
    $azFSNum = 1
    # Loop through each Azure File Share and record capacities    
    foreach ($azFS in $azFSs) {
      Write-Progress -Id 7 -Activity "Getting Azure File Share info for: $($azFS.Name)" -PercentComplete $(($azFSNum/$azFSs.Count)*100) -ParentId 6 -Status "Azure File Share $($azFSNum) of $($azFSs.Count)"
      $azFSClient = $azFS.ShareClient
      $azFSStats = $azFSClient.GetStatistics()
      $azFSObj = [PSCustomObject] @{
        "Name" = $azFS.Name
        "Tenant" = $tenant.Name
        "Region" = $azSA.PrimaryLocation
        "ResourceGroup" = $azSA.ResourceGroupName
        "QuotaGiB" = $azFS.Quota
        "UsedCapacityBytes" = $azFSStats.Value.ShareUsageInBytes
        "UsedCapacityGiB" = [math]::round($($azFSStats.Value.ShareUsageInBytes / 1073741824), 0)
        "UsedCapacityGB" = [math]::round($($azFSStats.Value.ShareUsageInBytes / 1000000000), 3)        
      }
    $azFSList += $azFSObj
    } #foreach ($azFS in $azFSs)
  Write-Progress -Id 6 -Activity "Getting Storage Account info for: $($azSA.StorageAccountName)" -Completed
  } # foreach ($azSA in $azSAs)
} # foreach ($sub in $subs)
Write-Progress -Id 1 -Activity "Getting info from subscription: $($sub.Name)" -Completed

# Reset subscription context back to original.
$setContext = Set-AzContext -SubscriptionName $context.subscription.Name | Out-Null

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

Write-Host
Write-Host "Total # of Azure File Shares: $($azFSList.count)" -ForeGroundColor Green
Write-Host "Total capacity of all Azure File shares: $azFSTotalGiB GiB or $azFSTotalGB GB" -ForeGroundColor Green

Write-Host
Write-Host "Total # of SQL DBs (independent): $(($sqlList.Database -ne '').count)" -foregroundcolor green
Write-Host "Total # of SQL Elastic Pools: $(($sqlList.ElasticPool -ne '').count)" -foregroundcolor green
Write-Host "Total # of SQL Managed Instances: $(($sqlList.ManagedInstance -ne '').count)" -foregroundcolor green
Write-Host "Total capacity of all SQL DBs (independent): $DBtotalGiB GiB or $DBtotalGB GB" -foregroundcolor green
Write-Host "Total capacity of all SQL Elastic Pools: $elasticTotalGiB GiB or $elasticTotalGB GB" -foregroundcolor green
Write-Host "Total capacity of all SQL Managed Instances: $MITotalGiB GiB or $MITotalGB GB" -foregroundcolor green

Write-Host
Write-Host "Total # of SQL DBs, Elastic Pools & Managed Instances: $($sqlList.count)" -foregroundcolor green
Write-Host "Total capacity of all SQL: $sqlTotalGiB GiB or $sqlTotalGB GB" -foregroundcolor green

# Export to CSV
Write-Host ""
Write-Host "VM CSV file output to: $outputVmDisk" -foregroundcolor green
$vmList | Export-CSV -path $outputVmDisk
Write-Host "SQL CSV file output to: $outputSQL" -foregroundcolor green
$sqlList | Export-CSV -path $outputSQL
Write-Host "Azure File Share CSV file output to: $outputAzFS" -ForeGroundColor Green
$azFSList | Export-CSV -path $outputAzFS

if ($azConfig.Value -eq $true) {
  Update-AzConfig -DisplayBreakingChangeWarning $true  | Out-Null
}
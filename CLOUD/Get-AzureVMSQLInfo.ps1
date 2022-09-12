# https://build.rubrik.com

<#
.SYNOPSIS
Gets all Azure VM Managed Disk and/or Azure SQL info in the specified subscription(s).

.DESCRIPTION
The 'Get-AzureVMSQLInfo.ps1' script gets all VM Managed Disk and/or Azure SQL info in the specified subscription(s).
You can specify one or more subscription to run the script against.
If no subscription is specified then it will gather info against the current subscription context.

The script gathers all Azure VMs and associated Managed Disk information.
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

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 2/19/22

.EXAMPLE
./Get-AzureVMSQLInfo.ps1
Runs the script against the current subscription context.

./Get-AzureVMSQLInfo.ps1 -subscriptions "sub1,sub2"
Runs the script against subscriptions 'sub1' and 'sub2'.

#>

param (
  [CmdletBinding()]

  # Choose to get info for only Azure VMs and/or SQL
  [Parameter(Mandatory=$false)]
  [string]$subscriptions = ''
)

$date = Get-Date

# Filenames of the CSVs to output
$outputVmDisk = "azure_vmdisk_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputSQL = "azure_sql_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"

Write-Host "Current identity:" -foregroundcolor green
$context = Get-AzureRmContext
$context | format-table

# Contains list of VMs and SQL DBs with capacity info
$vmList = @()
$sqlList = @()

# If no subscription is specified, only use the current subscription
if ( $subscriptions -eq '' ) {
  $subscriptions = $context.subscription.name
} else {
  $subscriptions = $subscriptions.split(',')
}

# Get Azure info for all specified subscriptions
foreach ($subscription in $subscriptions) {
  Write-Host "Getting VM info for subscription: $subscription" -foregroundcolor green

  $setContext = Set-AzContext -SubscriptionName $subscription
  if ($setContext -eq $null)
  {
    Write-Error "Error switching to subscription: $subscription"
    break
  }

  # Get a list of all VMs in the current subscription
  $vms = Get-AzVM

  # Loop through each VM to get all disk info
  foreach ($vm in $vms)
  {
    # Count of and size of all disks attahched to the VM
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
      "Subscription" = $subscription
      "Region" = $vm.Location
      "ResourceGroup" = $vm.ResourceGroupName
      "vmID" = $vm.vmID
      "InstanceType" = $vm.HardwareProfile.vmSize
      "Status" = $vm.StatusCode
    }
    $vmList += $vmObj
  }

  # Get all Azure SQL servers
  $sqlServers = Get-AzSqlServer

  # Loop through each SQL server to get size info
  foreach ($sqlServer in $sqlServers)
  {
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
          if ($poolName -eq $null)
          {
            $sqlObj = [PSCustomObject] @{
              "Database" = ""
              "Server" = ""
              "ElasticPool" = $pool.ElasticPoolName
              "ManagedInstance" = ""
              "MaxSizeGiB" = [math]::round($($pool.MaxSizeBytes / 1073741824), 0)
              "MaxSizeGB" = [math]::round($($pool.MaxSizeBytes / 1000000000), 3)
              "Subscription" = $subscription
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
            "Subscription" = $subscription
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

  # Get all Azure Managed Instances
  $sqlManagedInstances = Get-AzSqlInstance

  # Loop through each SQL Managed Instances to get size info
  foreach ($MI in $sqlManagedInstances)
  {
    $sqlObj = [PSCustomObject] @{
      "Database" = ""
      "Server" = ""
      "ElasticPool" = ""
      "ManagedInstance" = $MI.ManagedInstanceName
      "MaxSizeGiB" = $MI.StorageSizeInGB
      "MaxSizeGB" = [math]::round($($MI.StorageSizeInGB * 1.073741824), 3)
      "Subscription" = $subscription
      "Region" = $MI.Location
      "ResourceGroup" = $MI.ResourceGroupName
      "DatabaseID" = ""
      "InstanceType" = $MI.Sku.Name
      "Status" = $MI.Status
    }
    $sqlList += $sqlObj
  }  # foreach ($MI in $sqlManagedInstances)
}  # foreach ($subscription in $subscriptions) {

$VMtotalGiB = ($vmList.SizeGiB | Measure -Sum).sum
$VMtotalGB = ($vmList.SizeGB | Measure -Sum).sum

$sqlTotalGiB = ($sqlList.MaxSizeGiB | Measure -Sum).sum
$sqlTotalGB = ($sqlList.MaxSizeGB | Measure -Sum).sum
$DBtotalGiB = (($sqlList | Where -Property 'Database' -ne '').MaxSizeGiB | Measure -Sum).sum
$DBtotalGB = (($sqlList | Where -Property 'Database' -ne '').MaxSizeGB | Measure -Sum).sum
$elasticTotalGiB = (($sqlList | Where -Property 'ElasticPool' -ne '').MaxSizeGiB | Measure -Sum).sum
$elasticTotalGB = (($sqlList | Where -Property 'ElasticPool' -ne '').MaxSizeGB | Measure -Sum).sum
$MITotalGiB = (($sqlList | Where -Property 'ManagedInstance' -ne '').MaxSizeGiB | Measure -Sum).sum
$MITotalGB = (($sqlList | Where -Property 'ManagedInstance' -ne '').MaxSizeGB | Measure -Sum).sum

Write-Host
Write-Host "Total # of Azure VMs: $($vmList.count)" -foregroundcolor green
Write-Host "Total # of Managed Disks: $(($vmList.Disks | Measure -Sum).sum)" -foregroundcolor green
Write-Host "Total capacity of all disks: $VMtotalGiB GiB or $VMtotalGB GB" -foregroundcolor green

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

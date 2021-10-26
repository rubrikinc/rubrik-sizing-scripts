#requires -module VMware.PowerCLI
# https://build.rubrik.com

<#
.SYNOPSIS
Pulls VMware VM and VMDK write throughput disk stats for Rubrik sizing.

.DESCRIPTION
The Get-VMwareDiskStats.ps1 script pulls VM and VMDK write throughput disk stats for Rubrik sizing.
Requires PowerCLI and a vCenter read-only user.

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 10/20/21

vCenter stats collection should be configured for at least Level 2, duration 5 min, saved for 5 days.
If there is not enough space in vCenter to save it for 5 days then run this script multiple times to collect the data.
Make sure that the data gathering covers the busiest days for the VMs.
To configure stats collection, click on your vCenter -> Configure -> General -> Edit

$highKBps and $lowKBps are set to highlight any VMDKs that we need to take a closer look at for sizing.

This script will attempt to gather 5 min stats for a list of VMs.
Three different results files may be created:
1) VM level stats - for each 5 min time period, contains the sum of all VM write throughput
2) VMDK level stats - a list of any VMDK that has a write throughput greater than $lowKBps
3) Raw stats that are gathered - if the # of rows are too large, the output will be split by each day

By default, the script will gather stats for all VMs listed in vCenter.
You can also pass in a CSV with a list of VMs to gather stats for.
The list of VMs should have a column "Name" with a list of VMs to gather stats for.

A list of VMs in vCenter can also be generated with this script which can be edited and then passed back in.

If you are using Windows Powershell (not Core) you can also store vCenter credentials using:
- New-VICredentialStoreItem

.EXAMPLE
./Get-VMwareDiskStats.ps1
Prompts for vCenter server & login and gets stats for all VMs.

./Get-VMwareDiskStats.ps1 -server <vcenter_server>
Prompts for vCenter username & password and gets stats on all VMs.

./Get-VMwareDiskStats.ps1 -server <vcenter_server> -username <username> -password <password>
Pass your vCenter credentials as parameters and get stats on all VMs.

./Get-VMwareDiskStats.ps1 -outputVMfile <vmlist.csv>
Outputs a list of VMs from vCenter and exits script. Prompts for vCenter info.

./Get-VMwareDiskStats.ps1 -importVMfile <vmlist.csv>
Imports a list of VMs to gather stats on. VMs should be under a "Name" column. Prompts for vCenter info.

#>

param (
  [CmdletBinding()]

  # vCenter server hostname or IP address
  [Parameter(Mandatory=$false)]
  [string]$server = '',

  # vCenter username
  [Parameter(Mandatory=$false)]
  [string]$user = '',

  # vCenter password
  [Parameter(Mandatory=$false)]
  [string]$password = '',

  # Specify a filename just to output a list of VMs to a CSV file
  [Parameter(Mandatory=$false)]
  [string]$outputVMfile = '',

  # Specify a filename with a list of VMs to gather stats on using the "Name" column
  [Parameter(Mandatory=$false)]
  [string]$importVMfile = $null
)

Import-Module VMware.PowerCLI

# Base filename to output the stats to
$vmCSVoutput = "./vm_level_disk_stats-"
$vmdkCSVoutput = "./vmdk_level_disk_stats-"
$rawCSVoutput = "./vm_raw_disk_stats-"

# List of stats to gather
$statList = @('virtualDisk.write.average')
# Max sustained KBps to highlight for a VMDK
$highKBps = 50000
# Warning sustained KBps to highlight for a VMDK
$lowKBps = 40000

### Begin - PowerCLI authentication ###
if (!$server) { $server = Read-Host "vCenter hostname or IP" }

if (!$user) {
  Connect-VIServer -server $server
} else {
  Connect-VIServer -server $server -user $user -password $password
}
### End - PowerCLI authentication

$date = Get-Date

# Get a list of VMs, output to the specified CSV file, and exit script
if ($outputVMfile -ne '')
{
  Get-VM | Export-Csv -NoTypeInformation -Path $outVMFile
  exit
}

# If a CSV with a list of VMs is specified, import it.
# Otherwise, get a list of all VMs from vCenter to run the stats collection against.
if ($importVMfile -ne '')
{
  Write-Host "`nImporting VM list CSV file: $importVMfile`n" -foregroundcolor Green
  $vmList = Import-CSV $importVMfile | Sort-Object
} else {
  $vmList = Get-VM | Sort-Object
}

# Initialize arrays to hold the gathered data in
$vmDataArray = @()
$vmdkDataArray = @()

# For each VM, gather status
foreach ($vm in $vmList)
{
  Write-Host "Getting stats for VM: $($vm.Name)"
  # Loop through each stat we want to gather
  foreach ($stat in $statList)
  {
    $data = Get-Stat -entity $vm.Name -stat $stat -interval 5

    # If there is no "Instance" (disk) value then add it to the VM level array
    $vmDataArray += $data | Where Instance -eq ''

    # If there is "Instance" (disk) value then add it to the VMDK level array
    $vmdkDataArray += $data | Where Instance -ne ''
  } # foreach ($stat in $statList)
} # foreach ($vm in $vmList)

# Initialize array to hold calculated results in
$vmResults = @()

# For VM level stats, group everything by Timestamp
$vmGroup = $vmDataArray | Group-Object -Property Timestamp

# For VM level stats, sum up the values for each Timestamp
foreach ($i in $vmGroup)
{
  $KBpsPerTimestamp = [PSCustomObject] @{
    KBps = ($i.group | Measure-Object -Property Value -Sum).Sum
    Timestamp = $i.name
    MetricId = $i.group[0].MetricId
  }
  $vmResults += $KBpsPerTimestamp
} # foreach ($i in $vmGroup)

# For each VMDK level stat, build a list of VMDKs whose Value are greater than $highKBps
$highVMDKs = $vmdkDataArray | Where Value -ge $highKBps | Sort-Object -Property Value -Descending |
  Select @{n='KBps'; e={$_.Value}}, @{n='VM'; e={$_.Entity}}, 'Instance', 'Timestamp', 'MetricId'

# For each VMDK level stat, build a list of VMDKs whose Value are greater than $lowKBps
$lowVMDKs = $vmdkDataArray | Where { $_.value -ge $lowKBps -and $_.value -lt $highKBps } |
  Sort-Object -Property Value -Descending | Select @{n='KBps'; e={$_.Value}}, @{n='VM'; e={$_.Entity}}, 'Instance', 'Timestamp', 'MetricId'

Write-Host ""
Write-Host "These VMDKs had sustained write throughput that crossed the low threshold of $lowKBps KBps:" -foregroundcolor green
$lowVMDKs | Format-Table

Write-Host "These VMDKs had sustained write throughput that crossed the high threshold of $highKBps KBps:" -foregroundcolor green
$highVMDKs | Format-Table

Write-Host "Top 5 time time periods that had the highest sustained write throughput:" -foregroundcolor green
$vmResults | Sort-Object KBps -Desc | Select -First 5 | Format-Table

Write-Host
Write-Host "Total times a VMDK crossed the low threshold of $lowKBps KBps: $($lowVMDKs.count)"
Write-Host "Total times a VMDK crossed the high threshold of $highKBps KBps: $($highVMDKs.count)"
Write-Host ""
Write-Host "Number of unique VMs that crossed the low threshold of $lowKBps KBps: $(($lowVMDKs.VM |
  Sort-Object | Unique).count)" -foregroundcolor green
Write-Host "Number of unique VMs that crossed the high threshold of $highKBps KBps: $(($highVMDKs.VM |
  Sort-Object | Unique).count)" -foregroundcolor green
Write-Host "Highest sustained write throughput: $(($vmResults.KBps | Measure -Maximum).maximum) KBps" -foregroundcolor green
Write-Host "Average sustained write throughput: $((($vmResults.KBps | Measure -Average).average).ToString("#.###")) KBps" -foregroundcolor green
Write-Host

if ($vmResults.count -gt 0) {
  $vmResults | Export-CSV -NoTypeInformation -Path $vmCSVoutput$($date.ToString("yyyy-MM-dd_HHmm")).csv
  Write-Host "VM level results output to: $vmCSVoutput$($date.ToString("yyyy-MM-dd_HHmm")).csv" -foregroundcolor green
} else {
  Write-Host "No VM level results to output" -foregroundcolor green
}

# Combine VMDKs that are above $lowKBps and $highKBps into one and output to a CSV file if there are results
$highVMDKs += $lowVMDKs
if ($highVMDKs.count -gt 0) {
  $highVMDKs | Export-CSV -NoTypeInformation -Path $vmdkCSVoutput$($date.ToString("yyyy-MM-dd_HHmm")).csv
  Write-Host "VMDK level results output to: $vmdkCSVoutput$($date.ToString("yyyy-MM-dd_HHmm")).csv" -foregroundcolor green
} else {
  Write-Host "No VMDK throughput higher than low threshold to output" -foregroundcolor green
}

# Combine the raw results for the VM summary results and VMDK results
$vmDataArray += $vmdkDataArray

# Excel supports 1M rows. If the raw data is less than a large number, output raw results to a single file
# Otherwise, split up outputting the raw data by date
if ($vmDataArray.count -eq 0) {
  Write-Host "No raw data captured to output" -foregroundcolor green
} elseif ($vmDataArray.count -lt 800000)
{
  $vmDataArray | Select 'Timestamp', 'Value', 'Entity', 'Instance', 'MetricId', 'Unit', 'IntervalSecs' |
    Export-CSV -NoTypeInformation -Path $rawCSVoutput$($date.ToString("yyyy-MM-dd_HHmm")).csv
  Write-Host "Raw data captured output to: $rawCSVoutput$($date.ToString("yyyy-MM-dd_HHmm")).csv" -foregroundcolor green
} else {
  Write-Host "Splitting raw data output by date since number of rows was very large"
  for ($days = 0; $days -gt -7; $days--) {
    $dateComp = $date.date.adddays($days)

    if (($vmDataArray | Where-object { $_.timestamp.date -eq $dateComp.date }).count -gt 0) {
      $vmDataArray | Where-object { $_.timestamp.date -eq $dateComp.date } |
        Select 'Timestamp', 'Value', 'Entity', 'Instance', 'MetricId', 'Unit', 'IntervalSecs' |
        Export-CSV -NoTypeInformation -Path $rawCSVoutput$($dateComp.ToString("MM-dd"))_$($date.ToString("yyyy-MM-dd_HHmm")).csv
      Write-Host "Raw data captured output to: $rawCSVoutput$($dateComp.ToString("MM-dd"))_$($date.ToString("yyyy-MM-dd_HHmm")).csv" -foregroundcolor green
    }
  }
}

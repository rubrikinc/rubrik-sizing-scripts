#requires -module VMware.vim
# https://build.rubrik.com

<#
.SYNOPSIS
Pulls VMware VM disk stats for Rubrik sizing.

.DESCRIPTION
The Get-VMwareStats.ps1 script pulls VM disk stats for Rubrik sizing.
Requires PowerCLI and a vCenter read-only user.

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 10/20/21

vCenter stats collection should be configured for at least Level 2, duration 5 min, saved for 5 days.
If there is not enough space in vCenter to save it for 5 days then run this script multiple times to collect the data.
Make sure that the data gathering covers the busiest days for the VMs.
To configure stats collection, click on your vCenter -> Configure -> General -> Edit

This script will attempt to gather 5 min stats for the last few days for a list of VMs.
The results will be output to a separate CSV file for each day.
Any pre-existing files will be overwritten.

By default, the script will gather stats for all VMs listed in vCenter.
You can also pass in a CSV with a list of VMs to gather stats for.
A list of VMs in vCenter can be generated for editing.

If you are using Windows Powershell (not Core) you can also store your credentials using:
- New-VICredentialStoreItem

.EXAMPLE
./Get-VMwareStats.ps1
Prompts for vCenter info and gets stats for all VMs.

./Get-VMwareStats.ps1 -server <vcenter_server>
Prompts for vCenter username & password and gets stats on all VMs.

./Get-VMwareStats.ps1 -server <vcenter_server> -username <username> -password <password>
Pass your vCenter credentials as parameters.

./Get-VMwareStats.ps1 -outputVMfile <vmlist.csv>
Outputs a list of VMs from vCenter and exits script.

./Get-VMwareStats.ps1 -importVMfile <vmlist.csv>
Imports a list of VMs to gather stats on. VMs should be under a "Name" column.

./Get-VMwareStats.ps1 -days #
Specify how many days back to gather stats for, default 5 days.

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
  [string]$importVMfile = $null,

  # Number of days to gather stats for, default 5 days
  [Parameter(Mandatory=$false)]
  [int]$days = 5
)

# Base filename to output the stats to
$csvOutput = "./vmware_stats-"

# List of stats to gather
$statList = @('virtualDisk.write.average', 'virtualDisk.read.average')
# Max number samples to gather for 5 min interval
$maxSamples5min = 300

### Begin - PowerCLI authentication ###
if (!$server) { $server = Read-Host "vCenter hostname or IP" }

if (!$user) {
  Connect-VIServer -server $server
} else {
  Connect-VIServer -server $server -user $user -password $password
}
### End - PowerCLI authentication

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
  Write-Host "`nImporting CSV file: $importVMfile`n" -foregroundcolor Green
  $vmList = Import-CSV $importVMfile
} else {
  $vmList = Get-VM
}

# Go $days back and gather stats for each day
for ($i = $(1-$days); $i -lt 1; $i++)
{
  $dataList = @()
  $startDate = (Get-Date).AddDays($i).ToString("MM-dd-yyyy")
  $finishDate = (Get-Date).AddDays($i+1).ToString("MM-dd-yyyy")

  Write-Host "Getting stats for date: $startDate`n" -foregroundcolor green
  foreach ($vm in $vmList)
  {
    Write-Host "Getting stats for VM: $($vm.Name)"
    foreach ($stat in $statList)
    {
      $data = Get-Stat -entity $vm.Name -stat $stat -maxSamples $maxSamples5min -interval 5 -start $startDate -finish $finishDate

      $dataList += $data
    }
  }
  # Exports the results as a CSV for each date
  $dataList | Export-Csv -NoTypeInformation -Path ${csvOutput}${startDate}.csv
  Write-Host "`nResults output to: ${csvOutput}${startDate}.csv`n" -foregroundcolor green
}

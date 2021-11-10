#requires -modules GoogleCloud

# https://build.rubrik.com

<#
.SYNOPSIS
Gets all GCE VMs with the # of attached disks and total sizes of all disks.

.DESCRIPTION
The 'Get-GCEDiskInfo.ps1' script gets all GCE VMs in the specified projects.
For each GCE VM it grabs the total number of disks and total size (GiB) for all disks.
A summary of the total # of VMs, # of disks, and capacity will be output to console.
A CSV file will be exported with the details.

Pass in an array of project IDs ($projects) or update the value within the script.
If no project IDs are specified then it will run in the current config context.

Get a list of projects using:
- Get-gcpproject | select name,projectid

Run in GCP Cloud Shell or Cloud Tools for PowerShell.
Use 'gcloud init' to login if needed.
See: https://cloud.google.com/tools/powershell/docs/quickstart

Check your current gcloud context:
- gcloud auth list
- gcloud config list

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 11/9/21

.EXAMPLE
./Get-GCEDiskInfo.ps1
Runs the script to get all GCE VMs and associated disk info and output to a CSV file.

#>

param (
  [CmdletBinding()]

  # Pass in comma separated list of projects
  [Parameter(Mandatory=$false)]
  [string]$projects = ''
)

$date = Get-Date

# Filename of the CSV output
$output = "gce_disk_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"

Write-Host "Current glcoud context`n" -foregroundcolor green
& gcloud auth list
& gcloud config list --format 'value(core)'
$token = $(gcloud auth application-default print-access-token)
$headers = @{Authorization = "Bearer $token"}

# Holds list of all VMs and their info
$gceList = @()

# If a project list provided, loop through and gather all GCE VM info for each project
if ($projects -ne '') {
  $projectList = $projects -split ','
  foreach ($project in $projectList) {
    Write-Host "Getting GCE VM info for project: $project" -foregroundcolor green
    try {
      $vms = Get-GceInstance -project $project
    } catch {
      Write-Error "Error getting GCE VMs for project: $project"
    }
    if ($vms.count -gt 0) {
      $gceList += $vms
    }
  }
} else {  # Otherwise, just get the projects for the current config context
  Write-Host "Getting GCE VM info for current project context" -foregroundcolor green
  $gceList = Get-GceInstance
}

# Holds formatted list of VM and disk info we want to output
$vmList = @()

foreach ($vm in $gceList)
{
  $vmObj = [PSCustomObject] @{
    "VMName" = $vm.Name
    "VMid" = $vm.Id
    "Status" = $vm.Status
    "Disks" = 0
    "SizeGiB" = 0
    "SizeGB" = 0
    "Instance" = ($vm.MachineType -split '/') | Select -Last 1
    "Zone" = ($vm.Zone -split '/') | Select -Last 1
  }

  foreach ($disk in $vm.disks) {
    $vmObj.Disks += 1
    $diskInfo = (Invoke-WebRequest -Headers $headers -Uri $disk.Source).Content | ConvertFrom-Json
    $vmObj.SizeGiB += $diskInfo.sizeGb
  }

  $vmObj.SizeGB = [math]::round($($vmObj.SizeGiB * 1.073741824), 3)
  $vmList += $vmObj
}

$totalGiB = ($vmList.sizeGiB | Measure -Sum).sum
$totalGB = ($vmList.sizeGB | Measure -Sum).sum

Write-Host
Write-Host "Total # of GCE VMs: $($vmList.count)" -foregroundcolor green
Write-Host "Total # of disks: $(($vmList.disks | Measure -Sum).sum)" -foregroundcolor green
Write-Host "Total capacity of all disks: $totalGiB GiB or $totalGB GB" -foregroundcolor green

# Export to CSV
Write-Host ""
Write-Host "CSV file output to: $output" -foregroundcolor green
$vmList | Export-CSV -path $output

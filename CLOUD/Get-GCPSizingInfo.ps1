#requires -Version 7.0
#requires -Modules GoogleCloud

# https://build.rubrik.com

<#
.SYNOPSIS
Gets all GCE VMs with the # of attached disks and total sizes of all disks.

.DESCRIPTION
The 'Get-GCPSizingInfo.ps1' script gets all GCE VMs in the specified projects.
For each GCE VM it grabs the total number of disks and total size (GiB) for all disks.
A summary of the total # of VMs, # of disks, and capacity will be output to console.

A CSV file will be exported with the details.
You should copy/paste the console output to send along with the CSV.

Pass in an array of project IDs ($projects) or update the value within the script.
If no project IDs are specified then it will run in the current config context.

Run in GCP Cloud Shell or Cloud Tools for PowerShell.

If you are running using gcloud SDK then you must use the following to login:
- gcloud init
See: https://cloud.google.com/tools/powershell/docs/quickstart

Get a list of projects using:
- Get-gcpproject | select name,projectid

Check your current gcloud context:
- gcloud auth list
- gcloud config list

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 11/9/21
Updated: 2/24/22

.EXAMPLE
./Get-GCPSizingInfo.ps1
Get all GCE VMs and associated disk info and output to a CSV file.

./Get-GCPSizingInfo.ps1 -projects 'projectA,projectB'
For a provided list of projects, get all GCE VMs and associated disk info and output to a CSV file.

./Get-GCPSizingInfo.ps1 -projectFile 'projectFile.csv'
For a provided CSV list of projects, get all GCE VMs and associated disk info and output to a CSV file.
#>

param (
  [CmdletBinding()]

  # Pass in comma separated list of projects
  [Parameter(Mandatory=$false)]
  [string]$projects = '',

  # Pass pass in a file with a list of projects separated by line breaks, no header required
  [Parameter(Mandatory=$false)]
  [string]$projectFile = '',

  # Option to anonymize the output files.
  [Parameter(Mandatory=$false)]
  [switch]$Anonymize
)

if (Test-Path "./output.log") {
  Remove-Item -Path "./output.log"
}

Start-Transcript -Path "./output.log"

# Save the current culture so it can be restored later
$CurrentCulture = [System.Globalization.CultureInfo]::CurrentCulture

# Set the culture to en-US; this is to ensure that output to CSV is outputed properly
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

try{
$date = Get-Date

# Filename of the CSV output
$output = "gce_vmdisk_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$archiveFile = "gcp_sizing_results_$($date.ToString('yyyy-MM-dd_HHmm')).zip"

# List of output files
$outputFiles = @(
    $output,
    "output.log"
)


Write-Host "Current glcoud context`n" -foregroundcolor green
& gcloud auth list
& gcloud config list --format 'value(core)'

# Each GCE VM will be a key in a hash table
# Value will be hash table containing the disk details for that object
$vmHash = @{}

# Clear out variable in case it exists
$projectList = ''

# If a file is provided containing the list of files, then import the file
if ($projectFile -ne '')
{
  $projectObj = Import-CSV -path $projectFile -header "ProjectName"
  $projectList = $projectObj.ProjectName
} elseif ($projects -ne '')
{
  # Else if a comma separated list of projects was provided on the command line, use that
  $projectList = $projects -split ','
} else {
  # If no project is provided use the current project
  $projectList = @()
  try{
    $projectList += & gcloud config get-value project
  } catch {
    Write-Host "Failed to get project" -foregroundcolor Red
  }
  
  Write-Host "No project list provided, using current project: $projectList" -foregroundcolor green
}

# Loop through each project and grab the VM and disk info
foreach ($project in $projectList)
{
  Write-Host "Getting GCE VM info for current project: $project" -foregroundcolor green

  # gcloud SDK command to get each VM disk info a given project
  try{
    $projectInfo = & gcloud compute instances list --project=$project --format=json | jq '[ .[] | . as $vm | .disks[] | { vmName: $vm.name, vmID: $vm.id, status: $vm.status, diskName: .deviceName, diskSizeGb: .diskSizeGb} ]'
  } catch {
    Write-Host "Failed to get instances in project $project"
  }
  $projectInfo = $projectInfo | ConvertFrom-Json

  # Loop through each VM disk info and add it to the VM hash entry
  foreach ($vm in $projectInfo)
  {
    # If the object key doesn't exist, then create it along with initial details of the VM info
    if ($vmHash.containsKey($vm.'vmName') -eq $false)
    {
      $vmHash.($vm.'vmName') = @{}
      $vmHash.($vm.'vmName').'Project' = $project
      $vmHash.($vm.'vmName').'VM' = $vm.'vmName'
      $vmHash.($vm.'vmName').'DiskSizeGb' = [int]$vm.'diskSizeGb'
      $vmHash.($vm.'vmName').'NumDisks' = 1
      $vmHash.($vm.'vmName').'Status' = $vm.'status'
    } else
    {
      $vmHash.($vm.'vmName').'DiskSizeGb' += [int]$vm.'diskSizeGb'
      $vmHash.($vm.'vmName').'NumDisks' += 1
    }
  }
}

# Final list of VMs with the details we want
$vmList = @()

# Total number of objects to process
$vmCount = $vmHash.count
$count = 0

# Iterate through the hash table that has key for each object, along with disk details
foreach ($i in $vmHash.getEnumerator())
{
  $count += 1
  Write-Host "Processing [ $count / $vmCount ] : $($i.Value.VM)"

  # Create VM object that we want
  $vmObj = [PSCustomObject] @{
      "VM" = $i.value.VM
      "NumDisks" = $i.value.NumDisks
      "SizeGiB" = $i.value.DiskSizeGb
      "SizeTiB" = [math]::round($($i.value.DiskSizeGb / 1024), 7)
      "SizeGB" = [math]::round($($i.value.DiskSizeGb * 1.073741824), 3)
      "SizeTB" = [math]::round($($i.value.DiskSizeGb * 0.001073741824), 7)
      "Project" = $i.value.Project
      "Status" = $i.value.Status
  }

  $vmList += $vmObj
}

if ($Anonymize) {
  $global:anonymizeProperties = @("VM", "Project")

  $global:anonymizeDict = @{}
  $global:anonymizeCounter = 0

  function Get-NextAnonymizedValue {
      $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
      $base = $charSet.Length
      $newValue = ""
      $global:anonymizeCounter++

      $counter = $global:anonymizeCounter
      while ($counter -gt 0) {
          $counter--
          $newValue = $charSet[$counter % $base] + $newValue
          $counter = [math]::Floor($counter / $base)
      }

      return $newValue
  }

  function Anonymize-Data {
      param (
          [PSObject]$DataObject
      )

      foreach ($property in $DataObject.PSObject.Properties) {
          $propertyName = $property.Name
          $shouldAnonymize = $global:anonymizeProperties -contains $propertyName -or $propertyName -like "Label/Tag:*"

          if ($shouldAnonymize) {
              $originalValue = $DataObject.$propertyName

              if ($null -ne $originalValue) {
                  if (-not $global:anonymizeDict.ContainsKey($originalValue)) {
                      $global:anonymizeDict[$originalValue] = Get-NextAnonymizedValue
                  }
                  $DataObject.$propertyName = $global:anonymizeDict[$originalValue]
              }
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

  $vmList = Anonymize-Collection -Collection $vmList
}

$totalGiB = ($vmList.sizeGiB | Measure -Sum).sum
$totalGB = ($vmList.sizeGB | Measure -Sum).sum
$totalTiB = ($vmList.sizeTiB | Measure -Sum).sum
$totalTB = ($vmList.sizeTB | Measure -Sum).sum

Write-Host
Write-Host "Total # of GCE VMs: $($vmList.count)" -foregroundcolor green
Write-Host "Total # of disks: $(($vmList.numDisks | Measure -Sum).sum)" -foregroundcolor green
Write-Host "Total capacity of all disks: $totalGiB GiB or $totalGB GB or $totalTiB TiB or $totalTB TB" -foregroundcolor green

# Export to CSV
Write-Host ""
Write-Host "CSV file output to: $output" -foregroundcolor green
$vmList | Export-CSV -path $output

Write-Host
Write-Host
Write-Host "Results will be compressed into $archiveFile and original files will be removed." -ForegroundColor Green

} catch {
  Write-Error "An error occurred and the script has exited prematurely:"
  Write-Error $_
  Write-Error $_.ScriptStackTrace
} finally {
  Stop-Transcript
}

# In the case of an early exit/error, this filters only the files which exist
$existingFiles = $outputFiles | Where-Object { Test-Path $_ }

# Compress the files into a zip archive
Compress-Archive -Path $existingFiles -DestinationPath $archiveFile

# Remove the original files
foreach ($file in $outputFiles) {
    Remove-Item -Path $file -ErrorAction SilentlyContinue
}

Write-Host
Write-Host
Write-Host "Results have been compressed into $archiveFile and original files have been removed." -ForegroundColor Green

[System.Threading.Thread]::CurrentThread.CurrentCulture = $CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $CurrentCulture

Write-Host
Write-Host
Write-Host "Please send $archiveFile to your Rubrik representative" -ForegroundColor Cyan
Write-Host

if($Anonymize){
  Write-Host "NOTE: If any errors occurred, the log may not be anonymized" -ForegroundColor Cyan
}

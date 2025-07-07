#requires -Version 7.0
#requires -Modules GoogleCloud

# https://build.rubrik.com

<#
.SYNOPSIS
Gets all GCE VMs with the # of attached disks and total sizes of all disks.

.DESCRIPTION
The 'Get-GCPSizingInfo.ps1' script gets all GCE VMs and GCE Disk in the specified projects.
For each GCE VM it grabs the total number of disks and total size (GiB) for all disks.
A summary of the total # of VMs, # of disks, and capacity will be output to console.

A CSV file will be exported with the details along with a log file. Send the resulting 
zip file to Rubrik for analysis.

Pass a comma separated list of projects or a CSV file containing the project names
If no project IDs are specified then it will run in the current config context.

To run this script the following permissions are required by the user in GCP on all 
projects:

  - compute.instances.list
  - compute.disks.get
  - resourcemanager.projects.get

This script can be run in one of two ways:

1)  The first method of running the script is from the Google Cloud Shell. This is the
    easiest method, however, may not work for large numbers of projects. If there are
    more than 100 or so projects the Google Cloud shell may time out when running this
    script. In that case the second method will need to be used.

    To run this script in the Google Cloud shell do the following:

      a) Open a new Google Cloud Shell in the Google Console
      b) Test access by running the commands:
        
        - gcloud auth list
        - gcloud config list
        - gcloud projects list
        - Get-GcpProject | select name,projectid

      c) Upload this script to the Google Cloud Shell by selecting the ellipses and Upload.
      d) Run the script as described in the examples or help. 
          The script will run with the users credentials
          that logged into the Cloud Shell. This user must have the permissions that are
          discussed above.

2)  The second method of running this script is from a local laptop or a server. This method
    may be necessary if the Google Cloud Shell times out while running this script. To 
    Run this script from a local laptop or console, do the following:

      a) Install Powershell 7
      b) Install the gcloud tool (see https://cloud.google.com/sdk/docs/install for more 
          details).
      c) Install the GoogleCloud Powershell module by running the following command
          from inside Powershell 7:
          
          - Install-Module GoogleCloud
          
          See: https://cloud.google.com/tools/powershell/docs/quickstart for more details
      d) Run: gcloud init
      e) Run: gcloud auth login
          Login with a user that has the permissions that are discussed above.
      f) Test access by running the commands:
        
        - gcloud auth list
        - gcloud config list
        - gcloud projects list
        - Get-GcpProject | select name,projectid

      g) Run this script as described in the examples or help.
for more information on installing the Powershell GoogleCloud Module and the
gcloud application. 

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 11/9/21
Updated: 2/24/22
Updated: 6/25/25 for enhanced error handling

.EXAMPLE
Get all GCE VMs and associated disk info and output to a CSV file.

PS> ./Get-GCPSizingInfo.ps1

.EXAMPLE
For a provided list of projects, get all GCE VMs and associated disk info and output to a CSV file.
PS> ./Get-GCPSizingInfo.ps1 -Projects 'projectA,projectB'

.EXAMPLE
For a provided list of projects, get all GCE VMs and associated disk info and output to a CSV file.
PS> ./Get-GCPSizingInfo.ps1 -ProjectFile 'projectFile.txt'
#>

[CmdletBinding(DefaultParameterSetName = 'GetAllProjects')]
param (

  # Get all all projects
  [Parameter(ParameterSetName='GetAllProjects',
    Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$GetAllProjects,

  # Pass in comma separated list of projects
  [Parameter(ParameterSetName='Projects',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$Projects,

  # Pass pass in a file with a list of projects separated by line breaks, no header required
  [Parameter(ParameterSetName='ProjectFile',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$ProjectFile,

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

# Set the culture to en-US; this is to ensure that output to CSV is written properly
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

try{
$date = Get-Date
$date_string = $($date.ToString("yyyy-MM-dd_HHmmss"))

$output_log = "output_gcp_$date_string.log"

if (Test-Path "./$output_log") {
  Remove-Item -Path "./$output_log"
}

if($Anonymize){
  "Anonymized file; customer has original. Request customer to sanitize and provide output log if needed" > $output_log
  $log_for_anon_customers = "output_gcp_not_anonymized_$date_string.log"
  Start-Transcript -Path "./$log_for_anon_customers"
} else{
  Start-Transcript -Path "./$output_log"
}

Write-Host "Arguments passed to $($MyInvocation.MyCommand.Name):" -ForeGroundColor Green
$PSBoundParameters | Format-Table

# Filename of the CSV output
$outputVM = "gce_vm_info-$date_string.csv"
$outputAttachedDisks = "gce_attached_disk_info-$date_string.csv"
$outputUnattachedDisks = "gce_unattached_disk_info-$date_string.csv"

$archiveFile = "gcp_sizing_results_$date_string.zip"

# List of output files
$outputFiles = @(
    $outputVM,
    $outputAttachedDisks,
    $outputUnattachedDisks,
    $output_log
)

# Clear out variable in case it exists
$projectList = @()

# If a file is provided containing the list of files, then import the file
if ($projectFile -ne '')
{
  $projectFileContents = Get-Content -Path $ProjectFile
  foreach ($project in $projectFileContents)
  {
    try {
      $projectObj = Get-GcpProject -ProjectId $project
      if ($projectObj -and $projectObj.ProjectId) {
        $projectList += $projectObj
        Write-Host "Successfully retrieved project: $project" -ForegroundColor Green
      } else {
        Write-Host "No valid project data returned for $project" -ForegroundColor Yellow
      }
    } catch {
      Write-Host "Failed to get project $project" -ForegroundColor Red
      Write-Host "Error: $_" -ForegroundColor Red
    }
  }
} elseif ($projects -ne '')
{
  # Else if a comma separated list of projects was provided on the command line, use that
  foreach ($project in $projects.split(',')) {
    try {
      $projectObj = Get-GcpProject -ProjectId $project
      if ($projectObj -and $projectObj.ProjectId) {
        $projectList += $projectObj
        Write-Host "Successfully retrieved project: $project" -ForegroundColor Green
      } else {
        Write-Host "No valid project data returned for $project" -ForegroundColor Yellow
      }
    } catch {
      Write-Host "Failed to get project $project" -ForegroundColor Red
      Write-Host "Error: $_" -ForegroundColor Red
    }
  }
} else {
  Write-Host "No project list provided, discovering all GCP projects accessible to the authenticated account..." -ForegroundColor Green
  try {
    $projectList = Get-GcpProject
    if (-not $projectList -or $projectList.Count -eq 0) {
      Write-Host "No projects found. Check permissions ('resourcemanager.projects.get') or gcloud configuration." -ForegroundColor Red
      Write-Host "Run 'gcloud auth list' and 'gcloud config list' to verify setup." -ForegroundColor Yellow
    } else {
      Write-Host "Found $($projectList.Count) project(s)." -ForegroundColor Green
    }
  } catch {
    Write-Host "Failed to retrieve projects. Possible causes: insufficient permissions, authentication issues, or network problems." -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Run 'gcloud auth list' and 'gcloud config list' to verify setup." -ForegroundColor Yellow
  }
}

# Validate projectList before proceeding
if ($projectList.Count -eq 0) {
  Write-Host "No valid projects to process. Generating empty output files and exiting." -ForegroundColor Yellow
  # Create empty output files to maintain expected output structure
  @() | Export-CSV -Path $outputVM -NoTypeInformation
  @() | Export-CSV -Path $outputAttachedDisks -NoTypeInformation
  @() | Export-CSV -Path $outputUnattachedDisks -NoTypeInformation
  Write-Host "Empty CSV files generated: $outputVM, $outputAttachedDisks, $outputUnattachedDisks" -ForegroundColor Green
} else {
  Write-Host "Processing $($projectList.Count) project(s)..." -ForegroundColor Green
}

$instanceList = New-Object collections.arraylist
$attachedDiskList = New-Object collections.arraylist
$unattachedDiskList = New-Object collections.arraylist
# Loop through each project and grab the VM and disk info
$projectCounter = 1
foreach ($project in $projectList)
{
  if (-not $project -or -not $project.ProjectId) {
    Write-Host "Skipping invalid project entry (null or missing ProjectId)." -ForegroundColor Yellow
    continue
  }
  Write-Progress -ID 1 -Activity "Processing project: $($project.ProjectId)" -Status "Project: $($projectCounter) of $($projectList.Count)" -PercentComplete (($projectCounter / $projectList.Count) * 100)
  $projectCounter++
  $instanceInfo = $null
  try {
    $instanceInfo = Get-GceInstance -Project $($project.ProjectId)
    if (-not $instanceInfo) {
      Write-Host "No instances found in project $($project.ProjectId)" -ForegroundColor Yellow
    }
  } catch {
    Write-Host "Failed to get instances in project $($project.ProjectId)" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    continue
  }

  $instanceCounter = 1
  foreach ($instance in $instanceInfo) {
    if (-not $instance -or -not $instance.Name) {
      Write-Host "Skipping invalid instance in project $($project.ProjectId)" -ForegroundColor Yellow
      continue
    }
    Write-Progress -ID 2 -Activity "Processing GCE VM Instance: $($instance.Name)" -Status "Instance: $($instanceCounter) of $($instanceInfo.Count)" -PercentComplete (($instanceCounter / $instanceInfo.Count) * 100)
    $instanceCounter++

    $diskCount = 0
    $diskSizeGb = 0
    $numDiskEncryption = 0
    $sizeEncryptedDisksGb = 0

    foreach($disk in $instance.Disks) {
      if (-not $disk -or -not $disk.Source) {
        Write-Host "Skipping invalid disk for instance $($instance.Name) in project $($project.ProjectId)" -ForegroundColor Yellow
        continue
      }
      try {
        $diskInfo = Get-GceDisk -Project $($project.ProjectId) -DiskName $($disk.Source.split('/')[-1])
        if (-not $diskInfo) {
          Write-Host "No disk info returned for disk $($disk.Source.split('/')[-1]) in project $($project.ProjectId)" -ForegroundColor Yellow
          continue
        }
        $diskObj = [PSCustomObject] @{
          "Project" = $($project.ProjectId)
          "Zone" = $diskInfo.Zone.split('/')[-1]
          "VMName" = $instance.Name
          "DiskName" = $diskInfo.Name
          "Id" = $diskInfo.Id
          "SizeGb" = $diskInfo.SizeGb
          "SizeTb" = $diskInfo.SizeGb / 1000
          "DiskEncryptionKey" = $diskInfo.DiskEncryptionKey
          "SourceImageSource" = $null
          "SourceImageName" = $null
        }
        if($diskInfo.SourceImage -ne $null) {
          $diskObj.SourceImageSource = $diskInfo.SourceImage.split('/')[-4]
          $diskObj.SourceImageName = $diskInfo.SourceImage.split('/')[-1]
        }

        $tagCounter = 0
        foreach($key in $diskInfo.Labels.Keys) {
          $value = $diskInfo.Labels.Values.Split('\n')[$tagCounter]
          $key = $key -replace '[^a-zA-Z0-9]', '_'
          $diskObj | Add-Member -MemberType NoteProperty -Name "Label/Tag: $key" -Value $value -Force
          $tagCounter++
        }

        $diskCount++
        $diskSizeGb += $diskInfo.SizeGb
        if($diskInfo.DiskEncryptionKey) {
          $numDiskEncryption++
          $sizeEncryptedDisksGb += $diskInfo.SizeGb
        }

        $attachedDiskList.Add($diskObj) | Out-Null
      } catch {
        Write-Host "Failed to process disk $($disk.Source.split('/')[-1]) for instance $($instance.Name) in project $($project.ProjectId)" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        continue
      }
    }

    $instanceObj = [PSCustomObject] @{
      "Project" = $($project.ProjectId)
      "Zone" = $instance.Zone.split('/')[-1]
      "Name" = $instance.Name
      "TotalDiskCount" = $diskCount
      "TotalDiskSizeGb" = $diskSizeGb
      "TotalDiskSizeTb" = $diskSizeGb / 1000
      "EncryptedDisksCount" = $numDiskEncryption
      "EncryptedDisksSizeGb" = $sizeEncryptedDisksGb
      "EncryptedDisksSizeTb" = $sizeEncryptedDisksGb / 1000
      "Status" = $instance.Status  # Fixed: Changed $vm to $instance
    }
    $tagCounter = 0
    foreach($key in $instance.Labels.Keys) {
      $value = $instance.Labels.Values.Split('\n')[$tagCounter]
      $key = $key -replace '[^a-zA-Z0-9]', '_'
      $instanceObj | Add-Member -MemberType NoteProperty -Name "Label/Tag: $key" -Value $value -Force
      $tagCounter++
    }

    $instanceList.Add($instanceObj) | Out-Null
  }
  Write-Progress -ID 2 -Activity "Processing GCE VM Instance" -Completed

  $allDisks = $null
  try {
    $allDisks = Get-GceDisk -Project $($project.ProjectId)
    if (-not $allDisks) {
      Write-Host "No disks found in project $($project.ProjectId)" -ForegroundColor Yellow
    }
  } catch {
    Write-Host "Failed to get disks in project $($project.ProjectId)" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    continue
  }

  $diskCounter = 1
  foreach($disk in $allDisks) {
    if (-not $disk -or -not $disk.Name) {
      Write-Host "Skipping invalid disk in project $($project.ProjectId)" -ForegroundColor Yellow
      continue
    }
    Write-Progress -ID 3 -Activity "Processing disk: $($disk.Name)" -Status "Disk: $($diskCounter) of $($allDisks.Count)" -PercentComplete (($diskCounter / $allDisks.Count) * 100)
    $diskCounter++
    if ($disk.Users -eq $null) {
      $diskObj = [PSCustomObject] @{
        "Project" = $($project.ProjectId)
        "Zone" = $disk.Zone.split('/')[-1]
        "DiskName" = $disk.Name
        "Id" = $disk.Id
        "SizeGb" = $disk.SizeGb
        "SizeTb" = $disk.SizeGb / 1000
        "DiskEncryptionKey" = $disk.DiskEncryptionKey
        "SourceImageSource" = $null
        "SourceImageName" = $null
      }
      if($disk.SourceImage -ne $null) {
        $diskObj.SourceImageSource = $disk.SourceImage.split('/')[-4]
        $diskObj.SourceImageName = $disk.SourceImage.split('/')[-1]
      }
      $tagCounter = 0
      foreach($key in $disk.Labels.Keys) {
        $value = $disk.Labels.Values.Split('\n')[$tagCounter]
        $key = $key -replace '[^a-zA-Z0-9]', '_'
        $diskObj | Add-Member -MemberType NoteProperty -Name "Label/Tag: $key" -Value $value -Force
        $tagCounter++
      }
      $unattachedDiskList.Add($diskObj) | Out-Null
    }
  }
  Write-Progress -ID 3 -Activity "Processing disk" -Completed
}
Write-Progress -ID 1 -Activity "Processing project" -Completed

function addTagsToAllObjectsInList($list) {
  # Determine all unique tag keys
  $allTagKeys = @{}
  foreach ($obj in $list) {
      $properties = $obj.PSObject.Properties
      foreach ($property in $properties) {
          if (-not $allTagKeys.ContainsKey($property.Name)) {
              $allTagKeys[$property.Name] = $true
          }
      }
  }
  
  $allTagKeys = $allTagKeys.Keys
  
  # Ensure each object has all possible tag keys
  foreach ($obj in $list) {
      foreach ($key in $allTagKeys) {
          if (-not $obj.PSObject.Properties.Name.Contains($key)) {
              $obj | Add-Member -MemberType NoteProperty -Name $key -Value $null -Force
          }
      }
  }
}

if ($Anonymize) {
  $global:anonymizeProperties = @("Name", "Project", "VMName", "DiskName", "Id", "DiskEncryptionKey")

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
          $shouldAnonymize = $global:anonymizeProperties -contains $propertyName -or $propertyName -like "Tag:*"

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
                  $global:anonymizeDict[$tagValue] = Get-NextAnonymizedValue("Label/TagValue")
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

  $instanceList = Anonymize-Collection -Collection $instanceList
  $attachedDiskList = Anonymize-Collection -Collection $attachedDiskList
  $unattachedDiskList = Anonymize-Collection -Collection $unattachedDiskList
}

$totalGB = ($attachedDiskList.sizeGb | Measure -Sum).sum + ($unattachedDiskList.sizeGb | Measure -Sum).sum
$totalTB = ($attachedDiskList.sizeTb | Measure -Sum).sum + ($unattachedDiskList.sizeTb | Measure -Sum).sum

Write-Host
Write-Host "Total # of GCE VMs: $($instanceList.count)" -foregroundcolor green
Write-Host "Total # of attached disks: $($attachedDiskList.count)" -foregroundcolor green
Write-Host "Total # of unattached disks: $($unattachedDiskList.count)" -foregroundcolor green
Write-Host "Total capacity of all disks: $totalGB GB or $totalTB TB" -foregroundcolor green

# Export to CSV
Write-Host
addTagsToAllObjectsInList($instanceList)
Write-Host "CSV file output to: $outputVM" -foregroundcolor green
$instanceList | Export-CSV -path $outputVM -NoTypeInformation
Write-Host
addTagsToAllObjectsInList($attachedDiskList)
Write-Host "CSV file output to: $outputAttachedDisks" -foregroundcolor green
$attachedDiskList | Export-CSV -path $outputAttachedDisks -NoTypeInformation
Write-Host
addTagsToAllObjectsInList($unattachedDiskList)
Write-Host "CSV file output to: $outputUnattachedDisks" -foregroundcolor green
$unattachedDiskList | Export-CSV -path $outputUnattachedDisks -NoTypeInformation

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

  $anonKeyValuesFileName = "gcp_anonymized_keys_to_actual_values-$date_string.csv"

  $transformedDict | Export-CSV -Path $anonKeyValuesFileName -NoTypeInformation
  Write-Host
  Write-Host "Provided anonymized keys to actual values in the CSV: $anonKeyValuesFileName" -ForeGroundColor Cyan
  Write-Host "Provided log file here: $log_for_anon_customers" -ForegroundColor Cyan
  Write-Host "These files are not part of the zip file generated" -ForegroundColor Cyan
  Write-Host
}

} catch {
  Write-Error "An unexpected error occurred during script execution:"
  Write-Error $_
  Write-Error $_.ScriptStackTrace
} finally {
  Stop-Transcript
}

# In the case of an early exit/error, this filters only the files which exist
$existingFiles = $outputFiles | Where-Object { Test-Path $_ }

# Compress the files into a zip archive
Compress-Archive -Path $existingFiles -DestinationPath $archiveFile -ErrorAction SilentlyContinue

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
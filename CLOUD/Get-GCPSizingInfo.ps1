#requires -Version 7.0

# https://build.rubrik.com

<#
.SYNOPSIS
Gets all GCE VMs, GCE disks, Cloud SQL instances, and Spanner instances with sizing information.

.DESCRIPTION
The 'Get-GCPSizingInfo.ps1' script gets all GCE VMs, GCE Disks, Cloud SQL instances, and
Spanner instances in the specified projects. For each GCE VM it grabs the total number of
disks and total size (GiB) for all disks. For Cloud SQL instances, it collects storage size,
database count, and backup configuration. For Spanner instances, it collects node count,
processing units, and database count.

A summary of the total # of VMs, disks, Cloud SQL instances, and Spanner instances with
capacity will be output to console.

CSV files will be exported with the details along with a log file. Send the resulting
zip file to Rubrik for analysis.

Pass a comma separated list of projects or a CSV file containing the project names
If no project IDs are specified then it will run in the current config context.

To run this script the following permissions are required by the user in GCP on all
projects:

  - compute.instances.list
  - compute.disks.get
  - compute.disks.list
  - cloudsql.instances.list
  - cloudsql.databases.list
  - spanner.instances.list
  - spanner.databases.list
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
      c) Run: gcloud init
      d) Run: gcloud auth login
          Login with a user that has the permissions that are discussed above.
      e) Test access by running the commands:

        - gcloud auth list
        - gcloud config list
        - gcloud projects list

      f) Run this script as described in the examples or help.

.PARAMETER GetAllProjects
Flag (default) to find all projects that the user has access to and gather data.

.PARAMETER Projects
A comma separated list of GCP project IDs to gather data from.

.PARAMETER ProjectFile
Path to a file containing a list of GCP project IDs separated by line breaks. No header is required in the file.

.PARAMETER Anonymize
Anonymize data collected.

.PARAMETER AnonymizeFields
A comma separated list of fields in resulting CSVs and JSONs to anonymize. The list must be encased in
quotes, with no spaces between fields.

.PARAMETER NotAnonymizeFields
A comma separated list of fields in resulting CSVs and JSONs to not anonymize (only required for fields which are by default being
anonymized). The list must be encased in quotes, with no spaces between fields.
Note that we currently anonymize the following fields:
"Name", "Project", "VMName", "DiskName", "Id", "DiskEncryptionKey", "InstanceName", "DisplayName"
Additionally, you can specify "Tags" to exclude all tag/label fields (properties starting with "Tag:" or "Label/Tag:") from anonymization.

.PARAMETER SkipBigQuery
Skip BigQuery collection. BigQuery collection runs one bq command per table, so it can take a long time in projects with many tables.
The BigQuery CSV is still created, but it is empty.


.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 11/9/21
Updated: 2/24/22

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

  # Get all projects
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
  [string]$NotAnonymizeFields,

  # Skip BigQuery collection
  [Parameter(Mandatory=$false)]
  [switch]$SkipBigQuery
)

# Script version — update this with every PR that modifies this script.
$scriptVersion = "1.0.5"

# Save the current culture so it can be restored later
$CurrentCulture = [System.Globalization.CultureInfo]::CurrentCulture

# Set the culture to en-US; this is to ensure that output to CSV is written properly
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

# Disable gcloud interactive prompts for scripted execution
$env:CLOUDSDK_CORE_DISABLE_PROMPTS = 1

# Fail fast with actionable guidance if gcloud is not on PATH.
# Without this, every gcloud invocation silently no-ops (the script suppresses
# gcloud stderr for cleaner output) and the run reports "0 projects" with no
# explanation -- see GCP Troubleshooting in README.md.
if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: 'gcloud' CLI was not found on PATH." -ForegroundColor Red
    Write-Host "Install the Google Cloud SDK: https://cloud.google.com/sdk/docs/install" -ForegroundColor Red
    Write-Host "On Windows, close and reopen your PowerShell window after installing so PATH is refreshed." -ForegroundColor Red
    Write-Host "Then verify with: gcloud --version" -ForegroundColor Red
    throw "gcloud CLI not found. See guidance above."
}

# --- Function definitions ---

function Resolve-GCPProjects {
    param(
        [string]$Projects,
        [string]$ProjectFile
    )
    $projectList = @()
    if ($ProjectFile -ne '') {
        $projectFileContents = Get-Content -Path $ProjectFile
        foreach ($project in $projectFileContents) {
            try {
                $projectJson = gcloud projects describe $project --format=json 2>$null
                if ($projectJson) {
                    $projectList += ($projectJson -join '') | ConvertFrom-Json
                } else {
                    Write-Host "Project $project not found or not accessible" -foregroundcolor red
                }
            } catch {
                Write-Host "Failed to get project $project" -foregroundcolor red
                Write-Host "Error: $_" -foregroundcolor red
            }
        }
    } elseif ($Projects -ne '') {
        foreach ($project in $Projects.split(',')) {
            try {
                $projectJson = gcloud projects describe $project --format=json 2>$null
                if ($projectJson) {
                    $projectList += ($projectJson -join '') | ConvertFrom-Json
                } else {
                    Write-Host "Project $project not found or not accessible" -foregroundcolor red
                }
            } catch {
                Write-Host "Failed to get project $project" -foregroundcolor red
                Write-Host "Error: $_" -foregroundcolor red
            }
        }
    } else {
        Write-Host "No project list provided, discovering all GCP projects accessible to the authenticated account..." -ForegroundColor green
        # Capture stderr so a real error (auth, perms, disabled API) is not masked as "0 projects".
        $stderrFile = New-TemporaryFile
        $callFailed = $false
        try {
            $projectListJson = gcloud projects list --format=json 2>$stderrFile
            if ($projectListJson) {
                $projectList = ($projectListJson -join '') | ConvertFrom-Json
            }
        } catch {
            $callFailed = $true
            Write-Host "Failed to get projects" -foregroundcolor Red
            Write-Host "Error: $_" -foregroundcolor Red
        }
        $stderrText = (Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue)
        Remove-Item $stderrFile -ErrorAction SilentlyContinue
        # Only surface the discovery diagnostic when the gcloud call itself did not throw -- otherwise
        # the catch block above has already printed an error wall and a second one would just repeat it.
        if (-not $callFailed -and (-not $projectList -or $projectList.Count -eq 0)) {
            if ($stderrText) {
                Write-Host "ERROR: 'gcloud projects list' returned no projects." -ForegroundColor Red
                Write-Host "gcloud stderr:" -ForegroundColor Red
                Write-Host $stderrText -ForegroundColor Red
                Write-Host "Common causes (check in this order):" -ForegroundColor Yellow
                Write-Host "  1. Not authenticated, or active account is the wrong one. Run: gcloud auth list" -ForegroundColor Yellow
                Write-Host "     Re-authenticate with the Cloud Identity organization account if needed: gcloud auth login" -ForegroundColor Yellow
                Write-Host "  2. Caller lacks 'resourcemanager.projects.list' at org / folder scope." -ForegroundColor Yellow
                Write-Host "     Verify manually: gcloud projects list" -ForegroundColor Yellow
                Write-Host "  3. Cloud Resource Manager API disabled on the quota project. Enable with:" -ForegroundColor Yellow
                Write-Host "     gcloud services enable cloudresourcemanager.googleapis.com --project=<quota-project>" -ForegroundColor Yellow
                Write-Host "Workaround: pass project IDs explicitly with -Projects or -ProjectFile:" -ForegroundColor Yellow
                Write-Host "  .\Get-GCPSizingInfo.ps1 -Projects 'project-id-1,project-id-2'" -ForegroundColor Yellow
                Write-Host "  .\Get-GCPSizingInfo.ps1 -ProjectFile path\to\projects.txt" -ForegroundColor Yellow
                # Halt instead of returning an empty list -- otherwise Compress-SizingArchive still
                # produces a ZIP that looks like a successful run.
                throw "gcloud projects list returned no projects -- see guidance above."
            } else {
                # gcloud succeeded but the principal genuinely sees zero projects. Warn, do not halt.
                Write-Host "WARNING: 'gcloud projects list' returned no projects and gcloud reported no errors." -ForegroundColor Yellow
                Write-Host "This is expected if the authenticated principal has access to zero projects." -ForegroundColor Yellow
                Write-Host "If you expected projects, pass them explicitly with -Projects 'id1,id2' or -ProjectFile path." -ForegroundColor Yellow
            }
        }
    }
    return $projectList
}

function Get-GCPEnabledAPIs {
    param(
        [string]$ProjectId
    )
    $enabledApis = gcloud services list --enabled --project=$ProjectId `
        --filter="config.name:(compute.googleapis.com OR sqladmin.googleapis.com OR spanner.googleapis.com OR bigquery.googleapis.com)" `
        --format="value(config.name)" --quiet 2>$null

    return @{
        Compute  = $enabledApis -contains 'compute.googleapis.com'
        CloudSQL = $enabledApis -contains 'sqladmin.googleapis.com'
        Spanner  = $enabledApis -contains 'spanner.googleapis.com'
        BigQuery = $enabledApis -contains 'bigquery.googleapis.com'
    }
}

# Mirrors the ConvertTo-SizeUnits helper in Get-AWSSizingInfo.ps1 / Get-AzureSizingInfo.ps1.
# Supports two input units:
#   'GiB'   — Compute Engine sizeGb. Google defines Compute Engine "GB" as binary (1 GB = 2^30 bytes), so it is GiB.
#   'Bytes' — raw byte counts as returned by the BigQuery API (numBytes).
function ConvertTo-GCPSizeUnits {
    param(
        [double]$Value,
        [string]$Prefix,
        [ValidateSet('Bytes', 'GiB')]
        [string]$InputUnit = 'Bytes',
        [int]$GiBPrecision = 4,
        [int]$TiBPrecision = 4,
        [int]$GBPrecision  = 4,
        [int]$TBPrecision  = 4
    )
    if ($InputUnit -eq 'Bytes') {
        $gib = $Value / 1073741824
        $tib = $gib  / 1024
        $gb  = $Value / 1000000000
        $tb  = $gb   / 1000
    } else {
        $gib = $Value
        $tib = $gib  / 1024
        $gb  = $Value * 1.073741824
        $tb  = $gb   / 1000
    }
    @{
        "${Prefix}GiB" = [math]::Round($gib, $GiBPrecision)
        "${Prefix}TiB" = [math]::Round($tib, $TiBPrecision)
        "${Prefix}GB"  = [math]::Round($gb,  $GBPrecision)
        "${Prefix}TB"  = [math]::Round($tb,  $TBPrecision)
    }
}

function Get-GCEInstancesAndDisks {
    param(
        [string]$ProjectId
    )
    $instanceList = New-Object collections.arraylist
    $attachedDiskList = New-Object collections.arraylist

    $instanceInfo = $null
    try {
        $instancesJson = gcloud compute instances list --project=$ProjectId --format=json 2>$null
        if ($instancesJson) {
            $instanceInfo = ($instancesJson -join '') | ConvertFrom-Json
        }
    } catch {
        Write-Host "Failed to get instances in project $ProjectId" -ForeGroundColor Red
        Write-Host $_ -foregroundcolor red
    }

    $instanceCounter = 1
    foreach ($instance in $instanceInfo) {
        Write-Progress -ID 2 -Activity "Processing GCE VM Instance: $($instance.name)" -Status "Instance: $($instanceCounter) of $($instanceInfo.Count)"  -PercentComplete (($instanceCounter / $instanceInfo.Count) * 100)
        $instanceCounter++

        $diskCount = 0
        $diskSizeGb = 0
        $numDiskEncryption = 0
        $sizeEncryptedDisksGb = 0

        foreach($disk in $instance.disks){
            $diskName = $disk.source.split('/')[-1]
            $diskLocationType = $disk.source.split('/')[-4]  # 'zones' or 'regions'
            $diskLocation = $disk.source.split('/')[-3]      # zone name or region name
            $diskInfo = $null
            try {
                if ($diskLocationType -eq 'regions') {
                    $diskInfoJson = gcloud compute disks describe $diskName --project=$ProjectId --region=$diskLocation --format=json 2>$null
                } else {
                    $diskInfoJson = gcloud compute disks describe $diskName --project=$ProjectId --zone=$diskLocation --format=json 2>$null
                }
                if ($diskInfoJson) {
                    $diskInfo = ($diskInfoJson -join '') | ConvertFrom-Json
                }
            } catch {
                Write-Host "Failed to get disk $diskName in project $ProjectId" -ForeGroundColor Red
            }
            if (-not $diskInfo) { continue }

            $diskSizeGbCurrent = [double]$diskInfo.sizeGb
            $attachedDiskSizes = ConvertTo-GCPSizeUnits -Value $diskSizeGbCurrent -Prefix "Size" -InputUnit 'GiB'
            $diskObj = [PSCustomObject] @{
                "Project" = $ProjectId
                "Zone" = if ($diskInfo.zone) { $diskInfo.zone.split('/')[-1] } else { $diskInfo.region.split('/')[-1] }
                "VMName" = $instance.name
                "DiskName" = $diskInfo.name
                "Id" = $diskInfo.id
                "SizeGb"  = $diskSizeGbCurrent
                "SizeTb"  = $diskSizeGbCurrent / 1000
                "SizeGiB" = $attachedDiskSizes["SizeGiB"]
                "SizeTiB" = $attachedDiskSizes["SizeTiB"]
                "DiskEncryptionKey" = $diskInfo.diskEncryptionKey -ne $null
                "SourceImageSource" = $null
                "SourceImageName" = $null
            }
            if($diskInfo.sourceImage -ne $null){
                $diskObj.SourceImageSource = $diskInfo.sourceImage.split('/')[-4]
                $diskObj.SourceImageName = $diskInfo.sourceImage.split('/')[-1]
            }

            if ($diskInfo.labels) {
                foreach ($prop in $diskInfo.labels.PSObject.Properties) {
                    $labelKey = $prop.Name -replace '[^a-zA-Z0-9]', '_'
                    $diskObj | Add-Member -MemberType NoteProperty -Name "Label/Tag: $labelKey" -Value $prop.Value -Force
                }
            }

            $diskCount++
            $diskSizeGb += $diskSizeGbCurrent
            if($diskInfo.diskEncryptionKey){
                $numDiskEncryption++
                $sizeEncryptedDisksGb += $diskSizeGbCurrent
            }

            $attachedDiskList.Add($diskObj) | Out-Null
        }

        $totalDiskSizes     = ConvertTo-GCPSizeUnits -Value $diskSizeGb          -Prefix "TotalDiskSize"      -InputUnit 'GiB'
        $encryptedDiskSizes = ConvertTo-GCPSizeUnits -Value $sizeEncryptedDisksGb -Prefix "EncryptedDisksSize" -InputUnit 'GiB'
        $instanceObj = [PSCustomObject] @{
            "Project" = $ProjectId
            "Zone" = $instance.zone.split('/')[-1]
            "Name" = $instance.name
            "TotalDiskCount"         = $diskCount
            "TotalDiskSizeGb"        = $diskSizeGb
            "TotalDiskSizeTb"        = $diskSizeGb / 1000
            "TotalDiskSizeGiB"       = $totalDiskSizes["TotalDiskSizeGiB"]
            "TotalDiskSizeTiB"       = $totalDiskSizes["TotalDiskSizeTiB"]
            "EncryptedDisksCount"    = $numDiskEncryption
            "EncryptedDisksSizeGb"   = $sizeEncryptedDisksGb
            "EncryptedDisksSizeTb"   = $sizeEncryptedDisksGb / 1000
            "EncryptedDisksSizeGiB"  = $encryptedDiskSizes["EncryptedDisksSizeGiB"]
            "EncryptedDisksSizeTiB"  = $encryptedDiskSizes["EncryptedDisksSizeTiB"]
            "Status" = $instance.status
        }
        if ($instance.labels) {
            foreach ($prop in $instance.labels.PSObject.Properties) {
                $labelKey = $prop.Name -replace '[^a-zA-Z0-9]', '_'
                $instanceObj | Add-Member -MemberType NoteProperty -Name "Label/Tag: $labelKey" -Value $prop.Value -Force
            }
        }

        $instanceList.Add($instanceObj) | Out-Null

    }
    Write-Progress -ID 2 -Activity "Processing GCE VM Instance: $($instance.name)" -Completed

    return @{ Instances = $instanceList; AttachedDisks = $attachedDiskList }
}

function Get-GCEUnattachedDisks {
    param(
        [string]$ProjectId
    )
    $unattachedDiskList = New-Object collections.arraylist

    $allDisks = $null
    try {
        $allDisksJson = gcloud compute disks list --project=$ProjectId --format=json 2>$null
        if ($allDisksJson) {
            $allDisks = ($allDisksJson -join '') | ConvertFrom-Json
        }
    } catch {
        Write-Host "Failed to get disks in project $ProjectId" -foregroundcolor red
        Write-Host $_ -foregroundcolor red
    }

    $diskCounter = 1
    foreach($disk in $allDisks){
        Write-Progress -ID 3 -Activity "Processing disk: $($disk.name)" -Status "Disk: $($diskCounter) of $($allDisks.Count)"  -PercentComplete (($diskCounter / $allDisks.Count) * 100)
        $diskCounter++
        if (-not $disk.users){
            $diskSizeGbCurrent = [double]$disk.sizeGb
            $unattachedDiskSizes = ConvertTo-GCPSizeUnits -Value $diskSizeGbCurrent -Prefix "Size" -InputUnit 'GiB'
            $diskObj = [PSCustomObject] @{
                "Project" = $ProjectId
                "Zone" = if ($disk.zone) { $disk.zone.split('/')[-1] } else { $disk.region.split('/')[-1] }
                "DiskName" = $disk.name
                "Id" = $disk.id
                "SizeGb"  = $diskSizeGbCurrent
                "SizeTb"  = $diskSizeGbCurrent / 1000
                "SizeGiB" = $unattachedDiskSizes["SizeGiB"]
                "SizeTiB" = $unattachedDiskSizes["SizeTiB"]
                "DiskEncryptionKey" = $disk.diskEncryptionKey
                "SourceImageSource" = $null
                "SourceImageName" = $null
            }
            if($disk.sourceImage -ne $null){
                $diskObj.SourceImageSource = $disk.sourceImage.split('/')[-4]
                $diskObj.SourceImageName = $disk.sourceImage.split('/')[-1]
            }
            if ($disk.labels) {
                foreach ($prop in $disk.labels.PSObject.Properties) {
                    $labelKey = $prop.Name -replace '[^a-zA-Z0-9]', '_'
                    $diskObj | Add-Member -MemberType NoteProperty -Name "Label/Tag: $labelKey" -Value $prop.Value -Force
                }
            }
            $unattachedDiskList.Add($diskObj) | Out-Null
        }
    }
    Write-Progress -ID 3 -Activity "Processing disk: $($disk.name)" -Completed

    return , $unattachedDiskList
}

function Get-GCPCloudSQLInstances {
    param(
        [string]$ProjectId
    )
    $cloudSQLList = New-Object collections.arraylist

    $cloudSQLInstances = $null
    try {
        $cloudSQLInstancesJson = gcloud sql instances list --project=$ProjectId --format=json 2>$null
        if ($cloudSQLInstancesJson) {
            $cloudSQLInstances = ($cloudSQLInstancesJson -join '') | ConvertFrom-Json
        }
    } catch {
        Write-Verbose "Cloud SQL API not available in project $($ProjectId): $_"
    }

    $sqlInstanceCounter = 1
    foreach ($sqlInstance in $cloudSQLInstances) {
        Write-Progress -ID 4 -Activity "Processing Cloud SQL instance: $($sqlInstance.name)" -Status "Instance: $($sqlInstanceCounter) of $($cloudSQLInstances.Count)"  -PercentComplete (($sqlInstanceCounter / $cloudSQLInstances.Count) * 100)
        $sqlInstanceCounter++

        # Derive DatabaseEngine from databaseVersion prefix
        $databaseEngine = switch -Regex ($sqlInstance.databaseVersion) {
            '^POSTGRES' { 'PostgreSQL' }
            '^MYSQL'    { 'MySQL' }
            '^SQLSERVER' { 'SQL Server' }
            default     { $sqlInstance.databaseVersion }
        }

        # Define system databases per engine for filtering
        $systemDatabases = switch ($databaseEngine) {
            'PostgreSQL' { @('information_schema', 'postgres', 'template0', 'template1', 'cloudsqladmin') }
            'MySQL'      { @('information_schema', 'mysql', 'performance_schema', 'sys') }
            'SQL Server' { @('information_schema', 'master', 'tempdb', 'model', 'msdb') }
            default      { @() }
        }

        # Count user databases (excluding system databases)
        $numberOfDatabases = 0
        try {
            $databasesJson = gcloud sql databases list --instance=$($sqlInstance.name) --project=$ProjectId --format=json 2>$null
            if ($databasesJson) {
                $databases = ($databasesJson -join '') | ConvertFrom-Json
                $numberOfDatabases = ($databases | Where-Object { $systemDatabases -notcontains $_.name }).Count
            }
        } catch {
            Write-Host "Failed to get databases for Cloud SQL instance $($sqlInstance.name) in project $ProjectId" -ForeGroundColor Red
            # NumberOfDatabases remains 0 on failure
        }

        # Build Cloud SQL object
        $cloudSQLObj = [PSCustomObject] @{
            "Project" = $ProjectId
            "InstanceName" = $sqlInstance.name
            "InstanceType" = $sqlInstance.instanceType
            "DatabaseEngine" = $databaseEngine
            "EngineVersion" = $sqlInstance.databaseVersion
            "Region" = $sqlInstance.region
            "Tier" = $sqlInstance.settings.tier
            "StorageSizeGb" = if ($sqlInstance.settings.dataDiskSizeGb) { [double]$sqlInstance.settings.dataDiskSizeGb } else { 0 }
            "StorageSizeTb" = if ($sqlInstance.settings.dataDiskSizeGb) { [double]$sqlInstance.settings.dataDiskSizeGb / 1000 } else { 0 }
            "StorageType" = $sqlInstance.settings.dataDiskType
            "State" = $sqlInstance.state
            "NumberOfDatabases" = $numberOfDatabases
            "BackupEnabled" = if ($null -ne $sqlInstance.settings.backupConfiguration.enabled) { $sqlInstance.settings.backupConfiguration.enabled } else { $false }
            "BackupRetentionCount" = $sqlInstance.settings.backupConfiguration.backupRetentionSettings.retainedBackups
            "BackupStartTime" = $sqlInstance.settings.backupConfiguration.startTime
            "AvailabilityType" = $sqlInstance.settings.availabilityType
        }

        # Add labels as Label/Tag: columns
        if ($sqlInstance.settings.userLabels) {
            foreach ($prop in $sqlInstance.settings.userLabels.PSObject.Properties) {
                $labelKey = $prop.Name -replace '[^a-zA-Z0-9]', '_'
                $cloudSQLObj | Add-Member -MemberType NoteProperty -Name "Label/Tag: $labelKey" -Value $prop.Value -Force
            }
        }

        $cloudSQLList.Add($cloudSQLObj) | Out-Null
    }
    Write-Progress -ID 4 -Activity "Processing Cloud SQL instance: $($sqlInstance.name)" -Completed

    return , $cloudSQLList
}

function Get-GCPSpannerInstances {
    param(
        [string]$ProjectId
    )
    $spannerList = New-Object collections.arraylist

    $spannerInstances = $null
    try {
        $spannerInstancesJson = gcloud spanner instances list --project=$ProjectId --format=json 2>$null
        if ($spannerInstancesJson) {
            $spannerInstances = ($spannerInstancesJson -join '') | ConvertFrom-Json
        }
    } catch {
        Write-Verbose "Spanner API not available in project $($ProjectId): $_"
    }

    $spannerInstanceCounter = 1
    foreach ($spannerInstance in $spannerInstances) {
        Write-Progress -ID 5 -Activity "Processing Spanner instance: $($spannerInstance.name)" -Status "Instance: $($spannerInstanceCounter) of $($spannerInstances.Count)"  -PercentComplete (($spannerInstanceCounter / $spannerInstances.Count) * 100)
        $spannerInstanceCounter++

        # Extract short name from full resource path (e.g., "projects/foo/instances/bar" -> "bar")
        $instanceName = $spannerInstance.name.split('/')[-1]

        # Extract config name (last segment of config path)
        $config = $spannerInstance.config.split('/')[-1]

        # Count databases
        $numberOfDatabases = 0
        try {
            $databasesJson = gcloud spanner databases list --instance=$instanceName --project=$ProjectId --format=json 2>$null
            if ($databasesJson) {
                $databases = ($databasesJson -join '') | ConvertFrom-Json
                $numberOfDatabases = $databases.Count
            }
        } catch {
            Write-Host "Failed to get databases for Spanner instance $instanceName in project $ProjectId" -ForeGroundColor Red
            # NumberOfDatabases remains 0 on failure
        }

        # Build Spanner object
        $spannerObj = [PSCustomObject] @{
            "Project" = $ProjectId
            "InstanceName" = $instanceName
            "DisplayName" = $spannerInstance.displayName
            "Config" = $config
            "State" = $spannerInstance.state
            "NumberOfDatabases" = $numberOfDatabases
            "NodeCount" = if ($spannerInstance.nodeCount) { $spannerInstance.nodeCount } else { 0 }
            "ProcessingUnits" = if ($spannerInstance.processingUnits) { $spannerInstance.processingUnits } else { 0 }
        }

        # Add labels as Label/Tag: columns
        if ($spannerInstance.labels) {
            foreach ($prop in $spannerInstance.labels.PSObject.Properties) {
                $labelKey = $prop.Name -replace '[^a-zA-Z0-9]', '_'
                $spannerObj | Add-Member -MemberType NoteProperty -Name "Label/Tag: $labelKey" -Value $prop.Value -Force
            }
        }

        $spannerList.Add($spannerObj) | Out-Null
    }
    Write-Progress -ID 5 -Activity "Processing Spanner instance: $($spannerInstance.name)" -Completed

    return , $spannerList
}

function Add-LabelsToObject {
    param(
        $obj,
        $labels,
        [string]$prefix = "Label/Tag: ",
        [hashtable]$WarnedCollisions,
        [string]$CollisionContext
    )
    if (-not $labels) { return }
    foreach ($prop in $labels.PSObject.Properties) {
        $key = $prop.Name -replace '[^a-zA-Z0-9]', '_'
        $columnName = "$prefix$key"
        if ($null -ne $WarnedCollisions -and $obj.PSObject.Properties[$columnName]) {
            $warnKey = "$CollisionContext|$columnName"
            if (-not $WarnedCollisions.ContainsKey($warnKey)) {
                $WarnedCollisions[$warnKey] = $true
                Write-Host "WARNING: Column '$columnName' is produced by both a dataset label and a table label in $CollisionContext; the table label value overwrites the dataset label value." -ForegroundColor Yellow
            }
        }
        $obj | Add-Member -MemberType NoteProperty -Name $columnName -Value $prop.Value -Force
    }
}

function Add-TagsToAllObjectsInList($list) {
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

# bq ls returns only 50 results unless --max_results is set; bq follows page tokens up to that limit and then
# stops without printing a next-page token. 2147483647 (signed 32-bit maximum) is the largest value bq accepts.
$BQ_MAX_RESULTS = 2147483647

# bq writes some error text to stdout (unlinked datasets) and some to stderr (missing credentials), so the
# exit code is checked before parsing stdout and the failure message includes both streams
function Invoke-BqJson {
    param(
        [string[]]$BqArgs
    )
    try {
        $global:LASTEXITCODE = 0
        $merged = @(bq @BqArgs 2>&1)
        $exitCode = $global:LASTEXITCODE
        $output = @($merged | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
        $errorLines = @($merged | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
        if ($exitCode -ne 0) {
            $details = (@($output | ForEach-Object { "$_" }) + $errorLines) -join ' '
            return [PSCustomObject]@{ Success = $false; Data = @(); Error = "exit code ${exitCode}: $details" }
        }
        $data = @()
        if ($output) {
            $data = @(($output -join '') | ConvertFrom-Json)
        }
        return [PSCustomObject]@{ Success = $true; Data = $data; Error = $null }
    } catch {
        return [PSCustomObject]@{ Success = $false; Data = @(); Error = "$_" }
    }
}

# bq returns fewer items than --max_results only when the list has ended, so a count equal to the limit may be truncated
function Write-BqTruncationWarning {
    param(
        $Items,
        [string]$What
    )
    if (@($Items).Count -ge $BQ_MAX_RESULTS) {
        Write-Host "WARNING: The list of $What reached the limit of $BQ_MAX_RESULTS items and may be truncated; the BigQuery totals may be incomplete." -ForegroundColor Yellow
        $script:bqCollectionWarnings++
    }
}

function Get-GCPBigQueryInventory {
    param(
        [string]$ProjectId
    )
    $tableRowList = New-Object collections.arraylist
    $labelCollisionsWarned = @{}

    $datasetsResult = Invoke-BqJson -BqArgs @('ls', '--format=json', "--max_results=$BQ_MAX_RESULTS", "--project_id=$ProjectId")
    $datasets = $null
    if ($datasetsResult.Success) {
        $datasets = $datasetsResult.Data
        Write-BqTruncationWarning -Items $datasets -What "datasets in project $ProjectId"
    } else {
        Write-Host "ERROR: Failed to list BigQuery datasets in project $($ProjectId) (is 'bq' on PATH?): $($datasetsResult.Error)" -ForegroundColor Red
        $script:bqCollectionWarnings++
    }

    $datasetCounter = 1
    $datasetTotal = @($datasets).Count
    foreach ($dataset in $datasets) {
        $datasetId = $dataset.datasetReference.datasetId
        Write-Progress -ID 6 -Activity "Processing BigQuery dataset: $datasetId" -Status "Dataset $datasetCounter of $datasetTotal" -PercentComplete (($datasetCounter / $datasetTotal) * 100)
        $datasetCounter++
        $script:bqDatasetCount++

        # Get dataset details for location and dataset-level labels
        $location = ""
        $datasetLabels = $null
        $datasetInfoResult = Invoke-BqJson -BqArgs @('show', '--format=prettyjson', "${ProjectId}:${datasetId}")
        if ($datasetInfoResult.Success) {
            if ($datasetInfoResult.Data) {
                $location = $datasetInfoResult.Data[0].location
                $datasetLabels = $datasetInfoResult.Data[0].labels
            }
        } else {
            Write-Host "WARNING: Failed to get details for BigQuery dataset $datasetId in project ${ProjectId}: $($datasetInfoResult.Error)" -ForegroundColor Yellow
            $script:bqCollectionWarnings++
        }

        # List tables and emit one row per table/view
        $tablesResult = Invoke-BqJson -BqArgs @('ls', '--format=prettyjson', "--max_results=$BQ_MAX_RESULTS", "${ProjectId}:${datasetId}")
        if (-not $tablesResult.Success) {
            Write-Host "WARNING: Failed to list tables in BigQuery dataset ${ProjectId}:${datasetId}: $($tablesResult.Error)" -ForegroundColor Yellow
            $script:bqCollectionWarnings++
        }
        try {
            if ($tablesResult.Success -and $tablesResult.Data) {
                $tables = $tablesResult.Data
                Write-BqTruncationWarning -Items $tables -What "tables in BigQuery dataset ${ProjectId}:${datasetId}"
                foreach ($table in $tables) {
                    $tableId   = $table.tableReference.tableId
                    $tableType = $table.type  # TABLE, VIEW, MATERIALIZED_VIEW, EXTERNAL or SNAPSHOT

                    # Per-table details from bq show
                    $sizeBytes            = 0L
                    $longTermBytes        = 0L
                    $numRows              = 0L
                    $numberOfColumns      = 0
                    $creationTimeStr      = ""
                    $lastModifiedStr      = ""
                    $externalSourceFormat = ""
                    $externalSourceUri    = ""
                    $tableLabels          = $null

                    $tableInfoResult = Invoke-BqJson -BqArgs @('show', '--format=prettyjson', "${ProjectId}:${datasetId}.${tableId}")
                    if (-not $tableInfoResult.Success) {
                        Write-Host "WARNING: Failed to get details for BigQuery table ${datasetId}.${tableId} in project ${ProjectId}; its size is reported as 0: $($tableInfoResult.Error)" -ForegroundColor Yellow
                        $script:bqCollectionWarnings++
                    }
                    try {
                        if ($tableInfoResult.Success -and $tableInfoResult.Data) {
                            $tableInfo = $tableInfoResult.Data[0]
                            if ($tableInfo.numBytes)         { $sizeBytes     = [long]$tableInfo.numBytes }
                            if ($tableInfo.numLongTermBytes) { $longTermBytes  = [long]$tableInfo.numLongTermBytes }
                            if ($tableInfo.numRows)          { $numRows        = [long]$tableInfo.numRows }
                            if ($tableInfo.schema -and $tableInfo.schema.fields) {
                                $numberOfColumns = @($tableInfo.schema.fields).Count
                            }
                            if ($tableInfo.creationTime)     { $creationTimeStr = ([System.DateTimeOffset]::FromUnixTimeMilliseconds([long]$tableInfo.creationTime)).ToString("yyyy-MM-ddTHH:mm:ssZ") }
                            if ($tableInfo.lastModifiedTime) { $lastModifiedStr = ([System.DateTimeOffset]::FromUnixTimeMilliseconds([long]$tableInfo.lastModifiedTime)).ToString("yyyy-MM-ddTHH:mm:ssZ") }
                            if ($tableInfo.externalDataConfiguration) {
                                $externalSourceFormat = $tableInfo.externalDataConfiguration.sourceFormat
                                $sourceUris = @($tableInfo.externalDataConfiguration.sourceUris)
                                if ($sourceUris.Count -gt 0) {
                                    $externalSourceUri = $sourceUris -join '; '
                                }
                            }
                            $tableLabels = $tableInfo.labels
                        }
                    } catch {
                        Write-Host "WARNING: Failed to read details for BigQuery table ${datasetId}.${tableId} in project ${ProjectId}; some of its values may be reported as 0 or empty: $_" -ForegroundColor Yellow
                        $script:bqCollectionWarnings++
                    }

                    $activeBytes = [math]::Max(0L, $sizeBytes - $longTermBytes)

                    $totalLogicalSizes    = ConvertTo-GCPSizeUnits -Value $sizeBytes    -Prefix "TotalLogicalSize"    -InputUnit 'Bytes' -GBPrecision 4 -TBPrecision 6 -GiBPrecision 4 -TiBPrecision 6
                    $activeLogicalSizes   = ConvertTo-GCPSizeUnits -Value $activeBytes  -Prefix "ActiveLogicalSize"   -InputUnit 'Bytes' -GBPrecision 4 -TBPrecision 6 -GiBPrecision 4 -TiBPrecision 6
                    $longTermLogicalSizes = ConvertTo-GCPSizeUnits -Value $longTermBytes -Prefix "LongTermLogicalSize" -InputUnit 'Bytes' -GBPrecision 4 -TBPrecision 6 -GiBPrecision 4 -TiBPrecision 6

                    $totalLogicalSizeGb    = $totalLogicalSizes["TotalLogicalSizeGB"]
                    $totalLogicalSizeTb    = $totalLogicalSizes["TotalLogicalSizeTB"]
                    $activeLogicalSizeGb   = $activeLogicalSizes["ActiveLogicalSizeGB"]
                    $activeLogicalSizeTb   = $activeLogicalSizes["ActiveLogicalSizeTB"]
                    $longTermLogicalSizeGb = $longTermLogicalSizes["LongTermLogicalSizeGB"]
                    $longTermLogicalSizeTb = $longTermLogicalSizes["LongTermLogicalSizeTB"]

                    $tableObj = [PSCustomObject]@{
                        "Project"                = $ProjectId
                        "DatasetId"              = $datasetId
                        "Location"               = $location
                        "TableId"                = $tableId
                        "TableType"              = $tableType
                        "NumRows"                = $numRows
                        "NumberOfColumns"        = $numberOfColumns
                        "TotalLogicalSizeBytes"   = $sizeBytes
                        "TotalLogicalSizeGb"      = $totalLogicalSizeGb
                        "TotalLogicalSizeTb"      = $totalLogicalSizeTb
                        "TotalLogicalSizeGiB"     = $totalLogicalSizes["TotalLogicalSizeGiB"]
                        "TotalLogicalSizeTiB"     = $totalLogicalSizes["TotalLogicalSizeTiB"]
                        "ActiveLogicalSizeBytes"  = $activeBytes
                        "ActiveLogicalSizeGb"     = $activeLogicalSizeGb
                        "ActiveLogicalSizeTb"     = $activeLogicalSizeTb
                        "ActiveLogicalSizeGiB"    = $activeLogicalSizes["ActiveLogicalSizeGiB"]
                        "ActiveLogicalSizeTiB"    = $activeLogicalSizes["ActiveLogicalSizeTiB"]
                        "LongTermLogicalSizeBytes" = $longTermBytes
                        "LongTermLogicalSizeGb"   = $longTermLogicalSizeGb
                        "LongTermLogicalSizeTb"   = $longTermLogicalSizeTb
                        "LongTermLogicalSizeGiB"  = $longTermLogicalSizes["LongTermLogicalSizeGiB"]
                        "LongTermLogicalSizeTiB"  = $longTermLogicalSizes["LongTermLogicalSizeTiB"]
                        "ExternalSourceFormat"   = $externalSourceFormat
                        "ExternalSourceUri"      = $externalSourceUri
                        "CreationTime"           = $creationTimeStr
                        "LastModifiedTime"       = $lastModifiedStr
                    }

                    # Dataset-level labels (Label/Tag: prefix so -Anonymize redacts both key and value)
                    Add-LabelsToObject $tableObj $datasetLabels "Label/Tag: dataset_"
                    # Table-level labels (table wins on key collision)
                    Add-LabelsToObject $tableObj $tableLabels "Label/Tag: " -WarnedCollisions $labelCollisionsWarned -CollisionContext "BigQuery dataset ${ProjectId}:${datasetId}"

                    $tableRowList.Add($tableObj) | Out-Null
                }
            }
        } catch {
            Write-Host "ERROR: Failed to process tables for BigQuery dataset $datasetId in project ${ProjectId}: $_" -ForegroundColor Red
            $script:bqCollectionWarnings++
        }
    }
    Write-Progress -ID 6 -Activity "Processing BigQuery datasets" -Completed

    return , $tableRowList
}

function Compress-SizingArchive {
    param(
        [string[]]$OutputFiles,
        [string]$ArchiveFile
    )
    $existingFiles = $OutputFiles | Where-Object { Test-Path $_ }
    if ($existingFiles) {
        Compress-Archive -Path $existingFiles -DestinationPath $ArchiveFile
    }
    foreach ($file in $OutputFiles) {
        Remove-Item -Path $file -ErrorAction SilentlyContinue
    }
}

# --- Main script body ---

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

Write-Host "Script version: $scriptVersion" -ForeGroundColor Cyan
Write-Host "Arguments passed to $($MyInvocation.MyCommand.Name):" -ForeGroundColor Green
$PSBoundParameters | Format-Table

# Filename of the CSV output
$outputVM = "gce_vm_info-$date_string.csv"
$outputAttachedDisks = "gce_attached_disk_info-$date_string.csv"
$outputUnattachedDisks = "gce_unattached_disk_info-$date_string.csv"
$outputCloudSQL = "gce_cloudsql_info-$date_string.csv"
$outputSpanner = "gce_spanner_info-$date_string.csv"
$outputBigQuery = "gce_bigquery_info-$date_string.csv"

$archiveFile = "gcp_sizing_results_$date_string.zip"

# List of output files
$outputFiles = @(
    $outputVM,
    $outputAttachedDisks,
    $outputUnattachedDisks,
    $outputCloudSQL,
    $outputSpanner,
    $outputBigQuery,
    $output_log
)

# Clear out variable in case it exists
$projectList = ''

# Resolve the list of projects to process
$projectList = Resolve-GCPProjects -Projects $Projects -ProjectFile $ProjectFile

$instanceList = New-Object collections.arraylist
$attachedDiskList = New-Object collections.arraylist
$unattachedDiskList = New-Object collections.arraylist
$cloudSQLList = New-Object collections.arraylist
$spannerList = New-Object collections.arraylist
$bigQueryList = New-Object collections.arraylist
$script:bqCollectionWarnings = 0
$script:bqDatasetCount = 0
$bqAvailable = [bool](Get-Command bq -ErrorAction SilentlyContinue)
$bqMissingReported = $false
if ($SkipBigQuery) {
  Write-Host "BigQuery collection is skipped because -SkipBigQuery was specified." -ForegroundColor Yellow
}
# Loop through each project and grab the VM and disk info
$projectCounter = 1
foreach ($project in $projectList)
{
  Write-Progress -ID 1 -Activity "Processing project: $($project.projectId)" -Status "Project: $($projectCounter) of $($projectList.Count)"  -PercentComplete (($projectCounter / $projectList.Count) * 100)
  $projectCounter++

  # Proactive API enablement check — one call per project, filtered to the 4 APIs we need
  $apis = Get-GCPEnabledAPIs -ProjectId $project.projectId

  if (-not $apis.Compute) {
    Write-Host "WARNING: Compute Engine API is not enabled on project [$($project.projectId)]. Skipping Compute data collection." -ForegroundColor Yellow
  }
  if (-not $apis.CloudSQL) {
    Write-Host "WARNING: Cloud SQL Admin API is not enabled on project [$($project.projectId)]. Skipping Cloud SQL data collection." -ForegroundColor Yellow
  }
  if (-not $apis.Spanner) {
    Write-Host "WARNING: Cloud Spanner API is not enabled on project [$($project.projectId)]. Skipping Spanner data collection." -ForegroundColor Yellow
  }
  if (-not $apis.BigQuery) {
    Write-Host "WARNING: BigQuery API is not enabled on project [$($project.projectId)]. Skipping BigQuery data collection." -ForegroundColor Yellow
  }

  if ($apis.Compute) {
    $result = Get-GCEInstancesAndDisks -ProjectId $project.projectId
    $instanceList.AddRange($result.Instances)
    $attachedDiskList.AddRange($result.AttachedDisks)

    $unattached = Get-GCEUnattachedDisks -ProjectId $project.projectId
    $unattachedDiskList.AddRange($unattached)
  }

  if ($apis.CloudSQL) {
    $sql = Get-GCPCloudSQLInstances -ProjectId $project.projectId
    $cloudSQLList.AddRange($sql)
  }

  if ($apis.Spanner) {
    $spanner = Get-GCPSpannerInstances -ProjectId $project.projectId
    $spannerList.AddRange($spanner)
  }

  if ($apis.BigQuery -and -not $SkipBigQuery) {
    if ($bqAvailable) {
      $bigQuery = Get-GCPBigQueryInventory -ProjectId $project.projectId
      $bigQueryList.AddRange([System.Collections.ArrayList]$bigQuery)
    } elseif (-not $bqMissingReported) {
      Write-Host "ERROR: 'bq' was not found on PATH, so BigQuery collection is skipped for all projects. Install it with 'gcloud components install bq' and rerun." -ForegroundColor Red
      $bqMissingReported = $true
      $script:bqCollectionWarnings++
    }
  }
}
Write-Progress -ID 1 -Activity "Processing project: $($project.projectId)" -Completed


if ($Anonymize) {
  $global:anonymizeProperties = @("Name", "Project", "VMName", "DiskName", "Id", "DiskEncryptionKey", "InstanceName", "DisplayName", "DatasetId", "TableId", "ExternalSourceUri")

  if($AnonymizeFields){
    [string[]]$anonFieldsList = $AnonymizeFields.split(',')
    foreach($field in $anonFieldsList){
      if (-not $global:anonymizeProperties.Contains($field)) {
        $global:anonymizeProperties += $field
      }
    }
  }
  $global:anonymizeTags = $true
  if($NotAnonymizeFields){
    [string[]]$notAnonFieldsList = $NotAnonymizeFields.split(',')
    $global:anonymizeProperties = $global:anonymizeProperties | Where-Object { $_ -notin $notAnonFieldsList }
    if ($notAnonFieldsList -contains "Tags") {
      $global:anonymizeTags = $false
    }
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
          $shouldAnonymize = $global:anonymizeProperties -contains $propertyName -or ($propertyName -like "Tag:*" -and $global:anonymizeTags)

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
          elseif ($propertyName -like "Label/Tag:*" -and $global:anonymizeTags) {
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

  $instanceList = Anonymize-Collection -Collection $instanceList
  $attachedDiskList = Anonymize-Collection -Collection $attachedDiskList
  $unattachedDiskList = Anonymize-Collection -Collection $unattachedDiskList
  $cloudSQLList = Anonymize-Collection -Collection $cloudSQLList
  $spannerList = Anonymize-Collection -Collection $spannerList
  $bigQueryList = Anonymize-Collection -Collection $bigQueryList
}

$totalGB = ($attachedDiskList.sizeGb | Measure -Sum).sum + ($unattachedDiskList.sizeGb | Measure -Sum).sum
$totalTB = ($attachedDiskList.sizeTb | Measure -Sum).sum + ($unattachedDiskList.sizeTb | Measure -Sum).sum

$cloudSQLStorageGB = ($cloudSQLList.StorageSizeGb | Measure -Sum).sum
$cloudSQLStorageTB = ($cloudSQLList.StorageSizeTb | Measure -Sum).sum

Write-Host
Write-Host "Total # of GCE VMs: $($instanceList.count)" -foregroundcolor green
Write-Host "Total # of attached disks: $($attachedDiskList.count)" -foregroundcolor green
Write-Host "Total # of unattached disks: $($unattachedDiskList.count)" -foregroundcolor green
Write-Host "Total capacity of all disks: $totalGB GB or $totalTB TB" -foregroundcolor green
Write-Host "Total # of Cloud SQL instances: $($cloudSQLList.count)" -foregroundcolor green
Write-Host "Total Cloud SQL storage: $cloudSQLStorageGB GB or $cloudSQLStorageTB TB" -foregroundcolor green
Write-Host "Total # of Spanner instances: $($spannerList.count)" -foregroundcolor green
$totalBQDatasets       = $script:bqDatasetCount
$totalBQTables        = ($bigQueryList | Where-Object { $_.TableType -eq 'TABLE' }).Count
$totalBQMatViews       = ($bigQueryList | Where-Object { $_.TableType -eq 'MATERIALIZED_VIEW' }).Count
$totalBQViews          = ($bigQueryList | Where-Object { $_.TableType -eq 'VIEW' }).Count
$totalBQExternal       = ($bigQueryList | Where-Object { $_.TableType -eq 'EXTERNAL' }).Count
$totalBQSnapshots      = ($bigQueryList | Where-Object { $_.TableType -eq 'SNAPSHOT' }).Count
$totalBQLogicalBytes   = ($bigQueryList | Where-Object { $_.TableType -in @('TABLE', 'MATERIALIZED_VIEW') } | Measure-Object -Property TotalLogicalSizeBytes -Sum).Sum
$totalBQLogicalTb      = [math]::Round($totalBQLogicalBytes / 1000000000000, 4)
Write-Host "Total # of BigQuery datasets: $totalBQDatasets" -foregroundcolor green
Write-Host "Total # of BigQuery native tables: $totalBQTables" -foregroundcolor green
Write-Host "Total # of BigQuery materialized views: $totalBQMatViews" -foregroundcolor green
Write-Host "Total # of BigQuery views (not protected): $totalBQViews" -foregroundcolor green
Write-Host "Total # of BigQuery external tables (not protected — data not in BQ): $totalBQExternal" -foregroundcolor yellow
Write-Host "Total # of BigQuery table snapshots (not included in the protectable size below): $totalBQSnapshots" -foregroundcolor yellow
Write-Host "Total logical size of protectable BQ data (TABLE + MATERIALIZED_VIEW): $totalBQLogicalTb TB" -foregroundcolor green
if ($script:bqCollectionWarnings -gt 0) {
  Write-Host "WARNING: $($script:bqCollectionWarnings) BigQuery call(s) failed; the BigQuery totals above may be incomplete. See the warnings above." -foregroundcolor yellow
}

# Export to CSV
Write-Host
Add-TagsToAllObjectsInList($instanceList)
Write-Host "CSV file output to: $outputVM" -foregroundcolor green
$instanceList | Export-CSV -path $outputVM
Write-Host
Add-TagsToAllObjectsInList($attachedDiskList)
Write-Host "CSV file output to: $outputAttachedDisks" -foregroundcolor green
$attachedDiskList | Export-CSV -path $outputAttachedDisks
Write-Host
Add-TagsToAllObjectsInList($unattachedDiskList)
Write-Host "CSV file output to: $outputUnattachedDisks" -foregroundcolor green
$unattachedDiskList | Export-CSV -path $outputUnattachedDisks
Write-Host
Add-TagsToAllObjectsInList($cloudSQLList)
Write-Host "CSV file output to: $outputCloudSQL" -foregroundcolor green
$cloudSQLList | Export-CSV -path $outputCloudSQL
Write-Host
Add-TagsToAllObjectsInList($spannerList)
Write-Host "CSV file output to: $outputSpanner" -foregroundcolor green
$spannerList | Export-CSV -path $outputSpanner
Write-Host
Add-TagsToAllObjectsInList($bigQueryList)
Write-Host "CSV file output to: $outputBigQuery" -foregroundcolor green
$bigQueryList | Export-CSV -path $outputBigQuery

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

  $transformedDict | Export-CSV -Path $anonKeyValuesFileName
  Write-Host
  Write-Host "Provided anonymized keys to actual values in the CSV: $anonKeyValuesFileName" -ForeGroundColor Cyan
  Write-Host "Provided log file here: $log_for_anon_customers" -ForegroundColor Cyan
  Write-Host "These files are not part of the zip file generated" -ForegroundColor Cyan
  Write-Host
}

} catch {
  Write-Error "An error occurred and the script has exited prematurely:"
  Write-Error $_
  Write-Error $_.ScriptStackTrace
} finally {
  Stop-Transcript
}

Compress-SizingArchive -OutputFiles $outputFiles -ArchiveFile $archiveFile

Write-Host
Write-Host
Write-Host "Results have been compressed into $archiveFile and original files have been removed." -ForegroundColor Green

[System.Threading.Thread]::CurrentThread.CurrentCulture = $CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $CurrentCulture

Write-Host
Write-Host
Write-Host "Please send $archiveFile to your Rubrik representative." -ForegroundColor Cyan
Write-Host

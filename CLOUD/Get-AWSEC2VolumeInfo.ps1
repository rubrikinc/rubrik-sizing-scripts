#requires -modules AWSPowerShell.NetCore

# https://build.rubrik.com

<#
.SYNOPSIS
Gets all EC2 instances with the # of attached volumes and total sizes of all volumes.

.DESCRIPTION
The 'Get-AWSEC2VolumeInfo.ps1' script gets all EC2 instances in the specified regions.
For each EC2 instance it grabs the total number of volumes and total size (GiB) for all volumes.
A summary of the total # of instances, # of volumes, and capacity will be output to console.
A CSV file will be exported with the details.

Update the region list ($regions) as needed.

Run in AWS CloudShell or use 'Set-AWSCredential' to set the AWS credentials to run with.
See: https://docs.aws.amazon.com/powershell/latest/userguide/pstools-getting-started.html

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 11/8/21

.EXAMPLE
./Get-EC2AWSVolumeInfo.ps1
Runs the script to get all EC2 and associated volume info and output to a CSV file.

#>

$date = Get-Date

# Filename of the CSV output
$output = "aws_vol_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"

# List of AWS regions for reference, get current regions using 'Get-AWSRegion'
$regionsUS = @( 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2')
$regionsISO = @( 'us-iso-east-1', 'us-isob-east-1')
$regionsEU = @( 'eu-central-1', 'eu-north-1', 'eu-south-1', 'eu-west-1', 'eu-west-2', 'eu-west-3')
$regionsAPAC = @( 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
                  'ap-south-1', 'ap-southeast-1', 'ap-southeast-2')
$regionsCAN = @( 'ca-central-1' )
$regionsME = @( 'me-south-1' )
$regionsSA = @( 'sa-east-1' )

# Set the regions that you want to get EC2 instance and volume details for
$regions = @()
$regions += $regionsUS

Write-Host "Importing AWS Powershell module" -foregroundcolor green
Import-Module AWSPowerShell.NetCore

Write-Host "Current identity:" -foregroundcolor green
Get-STSCallerIdentity | format-table

# Contains list of EC2 instances with volume capacity info
$ec2list = @()

# For all specified regions get the EC2 instance and volume info
foreach ($region in $regions) {
  Write-Host "Getting EC2 instance info for region: $region" -foregroundcolor green
  $ec2instances = (Get-EC2Instance -region $region).instances

  foreach ($ec2 in $ec2instances) {
    $volSize = 0
    # Contains list of attached volumes to the current EC2 instance
    $volumes = $ec2.BlockDeviceMappings.ebs

    # Iterate through each volume and sum up the volume size
    foreach ($vol in $volumes) {
      $volSize += (Get-EC2Volume -VolumeId $vol.VolumeId -region $region).size
    }

    $ec2obj = [PSCustomObject] @{
      "InstanceId" = $ec2.InstanceId
      "InstanceType" = $ec2.InstanceType
      "Volumes" = $volumes.count
      "SizeGiB" = $volSize
      "SizeGB" = [math]::round($($volSize * 1.073741824), 3)
      "Region" = $region
      "Name" = $ec2.tags.name
      "Platform" = $ec2.Platform
    }

    $ec2list += $ec2obj
  }
}

$totalGiB = ($ec2list.sizeGiB | Measure -Sum).sum
$totalGB = ($ec2list.sizeGB | Measure -Sum).sum

Write-Host
Write-Host "Total # of EC2 instances: $($ec2list.count)" -foregroundcolor green
Write-Host "Total # of volumes: $(($ec2list.volumes | Measure -Sum).sum)" -foregroundcolor green
Write-Host "Total capacity of all volumes: $totalGiB GiB or $totalGB GB" -foregroundcolor green

# Export to CSV
Write-Host ""
Write-Host "CSV file output to: $output" -foregroundcolor green
$ec2list | Export-CSV -path $output

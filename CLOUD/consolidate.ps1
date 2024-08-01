<#
.SYNOPSIS
    A script to combine CSV files with the same prefix into one file, keeping only one set of headers.
.DESCRIPTION
    This PowerShell script takes in a directory path as a parameter, finds all CSV files within, and groups them by their prefix (the text before the first dash in the filename).
    Each group of files with the same prefix is combined into one CSV file. 
    If a CSV file is empty, it will be ignored during the aggregation. 
    The resulting combined files are saved in the directory from which the script is run.
    Headers from the original CSV files are included in the combined files intelligently: 
    each combined file will only include one set of headers taken from the CSV files with the same prefix.
    The script also filters out any blank lines in the original CSV files.

    This script requires Powershell 7 or later. To install Powershell 7 use one of these links:

    MacOs: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-macos?view=powershell-7.4
    Windows: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4
    
.PARAMETER directoryPath
    The path to the directory that contains the CSV files to be combined. Defaults to the current directory if not provided.
.EXAMPLE
    .\CombineCsvFiles.ps1 -directoryPath "C:\path\to\your\csv\files"
#>

param (
    # Path to the directory containing the CSV files
    [string]$directoryPath = "./"
)

function addNullValuesForFields($list) {
    # Determine all unique fields
    $allFields = @{}
    foreach ($obj in $list) {
        $properties = $obj.PSObject.Properties
        foreach ($property in $properties) {
            if (-not $allFields.ContainsKey($property.Name)) {
                $allFields[$property.Name] = $true
            }
        }
    }

    $allFields = $allFields.Keys

    # Ensure each object has all possible fields
    foreach ($obj in $list) {
        foreach ($field in $allFields) {
            if (-not $obj.PSObject.Properties.Name.Contains($field)) {
                $obj | Add-Member -MemberType NoteProperty -Name $field -Value $null -Force
            }
        }
    }
}
  

# Get all the CSV files in the directory
$csvFiles = Get-ChildItem -Path $directoryPath -Filter "*.csv" -File -Recurse

# Extract unique prefixes from filenames
$prefixes = $csvFiles | ForEach-Object { $_.BaseName -replace "-.*"} | Sort-Object -Unique

foreach ($prefix in $prefixes) {
    $combinedData = @()

    # Get the CSV files with the current prefix
    $prefixCsvFiles = $csvFiles | Where-Object { $_.BaseName -like "$prefix-*" }

    foreach ($csvFile in $prefixCsvFiles) {
        # Skip the current file if it's empty
        if ((Get-Content $csvFile.FullName) -eq $null) { continue }

        # Import the data
        $importedData = Import-Csv -Path $csvFile.FullName

        $combinedData += $importedData
    }

    # If no data to write, skip to the next prefix
    if ($combinedData.Count -eq 0) { continue }

    # Make sure every field is reported
    addNullValuesForFields($combinedData)

    # Write the combined data to a new CSV file in the directory the script is run from
    $combinedData | Export-Csv -Path "${prefix}_combined.csv" -NoTypeInformation
}

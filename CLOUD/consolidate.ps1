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

        # Import the data, excluding the column headers if there is already data in $combinedData
        # Filter out empty lines
        $importedData = Import-Csv -Path $csvFile.FullName | Where-Object { $_.PSObject.Properties.Value -ne $null }

        $combinedData += $importedData
    }

    # If no data to write, skip to the next prefix
    if ($combinedData.Count -eq 0) { continue }

    # Write the combined data to a new CSV file in the directory the script is run from
    $combinedData | Export-Csv -Path "${prefix}_combined.csv" -NoTypeInformation
}

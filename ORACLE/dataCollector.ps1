<#
.SYNOPSIS
    Rubrik Data Collection for Oracle - Windows (PowerShell) collector.

.DESCRIPTION
    PowerShell equivalent of dataCollector.sh. Reads collectionInput.lst, connects to each listed
    Oracle database as SYSTEM through SQL*Plus, runs the rbkDataCollection*.sql script that matches
    the database release, and appends the results to rbkDiscovery-v2.csv (tab-delimited).

    The SQL scripts are shared with dataCollector.sh and are not Windows specific. This script works
    for databases hosted on any OS, and can be run from any Windows machine that has SQL*Plus
    (full Oracle client or Instant Client + SQL*Plus package) and network access to the listeners.

    Input file format (space separated, one database per line - same as dataCollector.sh):
        hostname databasePort OracleSID databaseRelease
    databaseRelease is a 3 digit MAJOR+DOT release code: 11gR2 -> 112, 12cR1 -> 121, 19c -> 193.

    The SYSTEM password is read from the console as a SecureString for each database. It is passed to
    SQL*Plus over stdin (never on the command line), so it does not appear in the process list.

.PARAMETER InputFile
    Input list of databases. Default: collectionInput.lst in the script folder.

.PARAMETER OutputFile
    Output file. Default: rbkDiscovery-v2.csv in the script folder.

.PARAMETER SqlPlusPath
    Full path to sqlplus.exe, or to the folder containing it (or an ORACLE_HOME). If omitted, the
    script uses sqlplus.exe from PATH, then $env:ORACLE_HOME, and prompts if neither is found.

.EXAMPLE
    PS C:\rubrik\ORACLE> .\dataCollector.ps1

.EXAMPLE
    PS C:\rubrik\ORACLE> powershell -ExecutionPolicy Bypass -File .\dataCollector.ps1 -SqlPlusPath C:\oracle\instantclient_19_21

.NOTES
    Version: 2.0 (matches dataCollector.sh 2.0)
    Run from an interactive PowerShell session. A SYSTEM password containing a double quote (")
    or non-ASCII characters is rejected, since it cannot be passed to the CONNECT statement safely.
#>
[CmdletBinding()]
param(
    [string] $InputFile = 'collectionInput.lst',
    [string] $OutputFile = 'rbkDiscovery-v2.csv',
    [string] $SqlPlusPath
)

$ErrorActionPreference = 'Stop'

# The sql scripts are called by relative name and spool to a relative path, so run from the
# folder this script lives in regardless of where it was launched from.
Set-Location -LiteralPath $PSScriptRoot

$header = @(
    'CON_ID', 'CONNAME', 'DBSIZETB', 'ALLOCATED_DBSIZETB', 'BIGGESTBIGFILEGB', 'DAILYCHANGERATE',
    'DAILYREDOSIZETB', 'DATAFILECOUNT', 'HOSTNAME', 'INSTNAME', 'DBVERSION', 'DBEDITION',
    'PLATFORMNAME', 'DBNAME', 'DBUNIQUENAME', 'DBID', 'FLASHBACKENABLED', 'ARCHIVELOGENABLED',
    'SPFILE', 'PATCHLEVEL', 'CPUCOUNT', 'BLOCKSIZE', 'RACENABLED', 'SGAMAXSIZEGB', 'SGATARGETGB',
    'PGAAGGREGATETARGETGB', 'PHYSMEMORYGB', 'DNFSENABLED', 'GOLDENGATE', 'EXADATAENABLED',
    'BCTENABLED', 'LOGARCHIVECONFIG', 'ARCHIVELAGTARGET', 'TABLESPACECOUNT',
    'ENCRYPTEDTABLESPACECOUNT', 'ENCRYPTEDDATASIZETB', 'BIGFILETABLESPACECOUNT',
    'BIGFILEDATASIZEGB', 'LOGFILECOUNT', 'TEMPFILECOUNT'
)

#####
#
# Locate sqlplus.exe
#
#####
function Resolve-SqlPlus {
    param([string] $Hint)

    if ($Hint) {
        $candidates = @($Hint,
                        (Join-Path $Hint 'sqlplus.exe'),
                        (Join-Path $Hint 'bin\sqlplus.exe'))
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c -PathType Leaf) { return (Resolve-Path -LiteralPath $c).Path }
        }
        return $null
    }

    $cmd = Get-Command sqlplus.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    if ($env:ORACLE_HOME) { return Resolve-SqlPlus -Hint $env:ORACLE_HOME }
    return $null
}

$sqlplus = Resolve-SqlPlus -Hint $SqlPlusPath
while (-not $sqlplus) {
    Write-Host 'sqlplus.exe not found. Provide the folder containing sqlplus.exe (an ORACLE_HOME or Instant Client folder).'
    $answer = (Read-Host 'Folder').Trim().Trim('"')
    if (-not $answer) { continue }
    $sqlplus = Resolve-SqlPlus -Hint $answer
    if (-not $sqlplus) { Write-Host "sqlplus.exe not found under '$answer'." }
}
Write-Host "Using SQL*Plus: $sqlplus"

#####
#
# Verify the input file exists & has content
#
#####
Write-Host "Checking existence of $InputFile"
if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
    Write-Error "Error: $InputFile file not found." -ErrorAction Continue
    exit 2
}

$entries = @(Get-Content -LiteralPath $InputFile | Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith('#') })
if ($entries.Count -eq 0) {
    Write-Host "$InputFile is empty."
    exit 3
}

# write the header once per collection run; leaves an existing file's data untouched
if (-not (Test-Path -LiteralPath $OutputFile) -or (Get-Item -LiteralPath $OutputFile).Length -eq 0) {
    [System.IO.File]::WriteAllText((Join-Path $PWD.Path $OutputFile),
        (($header -join "`t") + [Environment]::NewLine),
        [System.Text.Encoding]::ASCII)
}

# SQL*Plus on Windows takes stdin in the console code page; limit the password to ASCII so it
# cannot be silently mangled on the way in.
function ConvertTo-PlainText {
    param([securestring] $Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

$failed = New-Object System.Collections.Generic.List[string]

foreach ($line in $entries) {
    $fields = $line.Trim() -split '\s+'
    if ($fields.Count -lt 4) {
        Write-Host "Skipping '$line': expected 'hostname port sid dbversion'."
        continue
    }
    $dbHost, $port, $sid, $dbversion = $fields[0], $fields[1], $fields[2], $fields[3]

    Write-Host "Connecting to database: $sid"
    Write-Host $dbversion

    # validate dbversion up front rather than silently defaulting to the newest sql script
    if ($dbversion -notmatch '^\d+$') {
        Write-Host "Skipping ${sid}: dbversion '$dbversion' is not a valid number. Expected a 3-digit release code (e.g. 112, 121, 193)."
        continue
    }
    # host, port and SID go straight into the connect descriptor; reject anything that is not a
    # plain name or number so they cannot alter the CONNECT statement or inject SQL*Plus commands
    if ($dbHost -notmatch '^[A-Za-z0-9._-]+$' -or $port -notmatch '^\d{1,5}$' -or $sid -notmatch '^[A-Za-z0-9_$#.-]+$') {
        Write-Host "Skipping '$line': host, port, or SID contains characters that are not allowed."
        continue
    }

    # warn if this host/SID already has a row in the output file. v$instance.host_name on Windows is
    # usually an upper-case short name, so compare the short host name case-insensitively.
    $shortHost = ($dbHost -split '\.')[0]
    $existing = @(Import-Csv -LiteralPath $OutputFile -Delimiter "`t" | Where-Object {
        (($_.HOSTNAME -split '\.')[0] -ieq $shortHost) -and ($_.INSTNAME -ieq $sid)
    })
    if ($existing.Count -gt 0) {
        Write-Host "Database $sid on host $dbHost already has a row in $OutputFile."
        $confirm = Read-Host 'Collect it again anyway? Duplicate rows will be added. [y/N]'
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "Skipping $sid."
            continue
        }
    }

    $secure = Read-Host "Enter SYSTEM password for $sid" -AsSecureString
    $passwd = ConvertTo-PlainText $secure
    if ($passwd -match '"' -or $passwd -cmatch '[^\x20-\x7E]') {
        Write-Host "Skipping ${sid}: the SYSTEM password contains a double quote or a non-ASCII character, which cannot be passed to the CONNECT command. Use a different password for the collection run."
        $failed.Add($sid)
        $passwd = $null
        continue
    }

    # determine database version from collectionInput.lst & set appropriate sql script for execution
    $v = [int]$dbversion
    if     ($v -lt 120) { $sql = 'rbkDataCollection_11g.sql' }
    elseif ($v -lt 122) { $sql = 'rbkDataCollection_121.sql' }
    elseif ($v -lt 180) { $sql = 'rbkDataCollection_12c.sql' }
    else                { $sql = 'rbkDataCollection.sql' }
    Write-Host $sql

    if (-not (Test-Path -LiteralPath $sql -PathType Leaf)) {
        Write-Host "Skipping ${sid}: $sql not found in $PSScriptRoot."
        $failed.Add($sid)
        $passwd = $null
        continue
    }

    # connect via a CONNECT statement fed through stdin instead of embedding the password in the
    # sqlplus command line: keeps it out of the process list
    $script = @"
WHENEVER SQLERROR EXIT SQL.SQLCODE
CONNECT system/"$passwd"@"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=$dbHost)(PORT=$port))(CONNECT_DATA=(SID=$sid)))"
@$sql
"@
    $script | & $sqlplus /nolog | Out-Host
    $exit = $LASTEXITCODE
    $script = $null
    $passwd = $null

    if ($exit -ne 0) {
        Write-Host "Data collection failed for database: $sid - check the SYSTEM password and connection details."
        $failed.Add($sid)
    }
}

if ($failed.Count -gt 0) {
    Write-Host ''
    Write-Host "Collection failed for: $($failed -join ', ')"
    exit 1
}
Write-Host ''
Write-Host "Done. Results are in $OutputFile"

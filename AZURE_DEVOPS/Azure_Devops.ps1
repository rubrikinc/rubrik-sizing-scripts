param(
    [string] $organisation,
    [SecureString] $personalAccessToken
)
if (-not $organisation) {
    $organisation = Read-Host "Enter Azure DevOps organisation (e.g. myorg)"
}
if (-not $personalAccessToken) {
    $personalAccessToken = Read-Host "Enter Personal Access Token" -AsSecureString
}
# convert secure string to plain text just for the auth header
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($personalAccessToken)
try { $patPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) 
}
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$patPlain"))
$headers = @{ Authorization = "Basic $base64AuthInfo" }
# projects
$projects = (Invoke-RestMethod -Uri
    "https://dev.azure.com/$organisation/_apis/projects?api-version=6.0" -Headers $headers).value
# count TFVC repos (use the TFVC repositories endpoint)
$tfvcCount = 0
foreach ($p in $projects) {
    try {
        $tfvcRepos = (Invoke-RestMethod -Uri
            "https://dev.azure.com/$organisation/$($p.name)/_apis/tfvc/repositories?api-version=6.0"
            -Headers $headers).value
        if ($tfvcRepos) { $tfvcCount += $tfvcRepos.Count }
    }
    catch { Write-Verbose "No TFVC in $($p.name): $_" }
}
# all Git repos
$allRepos = (Invoke-RestMethod -Uri
    "https://dev.azure.com/$organisation/_apis/git/repositories?api-version=6.0" -Headers
    $headers).value
# sum sizes (if size is available)
$totalMB = 0
foreach ($repo in $allRepos) {
    try {
        $repoDetails = Invoke-RestMethod -Uri "$($repo.url)?api-version=6.0" -Headers $headers
        if ($repoDetails.PSObject.Properties.Name -contains 'size') {
            $totalMB += [math]::Round(($repoDetails.size / 1MB), 2)
        }
    }
    catch {
        Write-Warning "Could not add size for repo $($repo.name): $($_.Exception.Message)"
    }
}
Write-Host "Found $($allRepos.Count) Git repos and $tfvcCount TFVC repos. Total Git size is
$totalMB MB"

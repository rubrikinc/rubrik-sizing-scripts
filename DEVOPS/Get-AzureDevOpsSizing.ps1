param (
    [string] $organisation,
    [string] $personalAccessToken
)

$base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($personalAccessToken)"))
$headers = @{Authorization=("Basic {0}" -f $base64AuthInfo)}

$result = Invoke-RestMethod -Uri "https://dev.azure.com/$organisation/_apis/projects?api-version=6.0" -Method Get -Headers $headers

$projectNames = $result.value.name

$url = "https://dev.azure.com/$organisation/_apis/git/repositories?api-version=6.0"
$AllSourceRepos = (Invoke-RestMethod $url -Headers $headers).value

[int]$incre = 0
$projectNames | ForEach-Object {
    $project = $_

    $result = Invoke-RestMethod -Uri "https://dev.azure.com/$organisation/$project/_apis/tfvc/items?api-version=6.0" -Method Get -Headers $headers

    if($result.value[0].Path -like "*$/*")
    {
        $incre++;
    }
} | Sort-Object

$totalMB = 0
$AllSourceRepos | ForEach-Object {
    $repoName = $_.name
    try
    {
        $result = Invoke-RestMethod -Uri "$($_.url)?api-version=4.1" -Method Get -Headers $headers
        $totalMB = $totalMB + $result.size/1MB
    }
    catch
    {
        # Catch any error
        Write-Host "Could not add in size for repo $repoName"
    }
} | Sort-Object

Write-Host "Found $($AllSourceRepos.Count) GIT repos and $($incre) TFVC repos. Total git size is $($totalMB)mb"

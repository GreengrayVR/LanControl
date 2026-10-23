[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ClientBundleDirectory,
    [Parameter(Mandatory=$true)][string]$ServerDataDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputDirectory) { throw 'OutputDirectory already exists. Choose a new client output directory.' }
$bundle = (Resolve-Path -LiteralPath $ClientBundleDirectory).Path
if (-not (Test-Path -LiteralPath (Join-Path $bundle 'LanClient.exe'))) { throw 'Missing LanClient.exe in the client bundle.' }
if (Get-ChildItem -LiteralPath $bundle -Recurse -File | Where-Object { $_.Name -in @('server.key', 'computers.json') }) {
    throw 'Client bundle must not contain server private keys or server configuration.'
}
$serverData = (Resolve-Path -LiteralPath $ServerDataDirectory).Path
$configPath = Join-Path $serverData 'computers.json'
$serverConfig = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$entries = @($serverConfig.computers)
if ($entries.Count -eq 0) { throw 'Server computer list is empty.' }
$names = @()
foreach ($entry in $entries) {
    $name = ([string]$entry.name).Trim().ToUpperInvariant()
    if ($name -notmatch '^[A-Z0-9][A-Z0-9-]{0,62}$' -or [string]$entry.token -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Invalid computer entry in server configuration.'
    }
    $names += $name
}
if (@($names | Select-Object -Unique).Count -ne $names.Count) { throw 'Duplicate computer names in server configuration.' }

$certificate = [IO.File]::ReadAllText((Join-Path $serverData 'server.crt'))
$pem = [regex]::Match($certificate, '\A\s*-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\r\n]+)\s*-----END CERTIFICATE-----\s*\z')
if (-not $pem.Success) { throw 'server.crt must contain a PEM certificate.' }
$der = [Convert]::FromBase64String($pem.Groups['body'].Value)
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $pin = [BitConverter]::ToString($sha.ComputeHash($der)).Replace('-','').ToLowerInvariant() }
finally { $sha.Dispose() }

$addSharedToken = $null -eq $serverConfig.PSObject.Properties['sharedClientToken']
if ($addSharedToken) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $bytes = New-Object byte[] 32; $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $token = [BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()
    $serverConfig | Add-Member -NotePropertyName 'sharedClientToken' -NotePropertyValue $token
} else {
    $token = [string]$serverConfig.sharedClientToken
    if ($token -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid existing sharedClientToken. Refusing to rotate credentials.' }
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
Copy-Item -LiteralPath $bundle -Destination $OutputDirectory -Recurse
$clientPath = (Resolve-Path -LiteralPath $OutputDirectory).Path
$clientConfig = @{ server='6kabinet'; port=47666; token=$token; certificateSha256=$pin }
[IO.File]::WriteAllText((Join-Path $clientPath 'client.json'), ($clientConfig | ConvertTo-Json), $utf8)
if ($addSharedToken) {
    # Publish only after the client package is complete. Preserve existing per-PC tokens and TLS files.
    $staged = Join-Path $serverData ('computers.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($staged, ($serverConfig | ConvertTo-Json -Depth 10), $utf8)
        [IO.File]::Replace($staged, $configPath, $configPath + '.before-shared')
    } finally {
        if (Test-Path -LiteralPath $staged) { Remove-Item -LiteralPath $staged }
    }
}
Write-Host "Shared client bundle: $clientPath. Copy this same directory to all $($entries.Count) listed PCs."
Write-Host 'Restart the updated LanServer to load shared-client authentication.'

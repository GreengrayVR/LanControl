[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BundleDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$ComputerNamesFile = '',
    [string]$OpenSslExe = 'openssl.exe'
)
$ErrorActionPreference = 'Stop'
if (-not $ComputerNamesFile) { $ComputerNamesFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'config\computers.txt' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'OutputDirectory already exists. Keep existing certificates and tokens; do not overwrite them.' }
foreach ($name in @('LanClient','LanServer')) {
    if (-not (Test-Path -LiteralPath (Join-Path $BundleDirectory "$name\$name.exe"))) { throw "Missing bundle: $name" }
}
$names = @(Get-Content -LiteralPath $ComputerNamesFile | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ -and -not $_.StartsWith('#') })
if ($names.Count -eq 0) { throw 'Computer list is empty.' }
if (@($names | Select-Object -Unique).Count -ne $names.Count) { throw 'Duplicate computer names.' }
foreach ($name in $names) { if ($name -notmatch '^[A-Z0-9][A-Z0-9-]{0,62}$') { throw "Invalid computer name: $name" } }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$deploymentPath = (Resolve-Path -LiteralPath $OutputDirectory).Path
# Restrict the deployment tree: it contains the server private key and all client tokens.
& icacls.exe $deploymentPath /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name):(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure deployment directory.' }
$serverDir = Join-Path $deploymentPath 'server'
Copy-Item -LiteralPath (Join-Path $BundleDirectory 'LanServer') -Destination $serverDir -Recurse
$serverData = Join-Path $serverDir 'server-data'
New-Item -ItemType Directory -Path $serverData | Out-Null
$certPath = Join-Path $serverData 'server.crt'
$keyPath = Join-Path $serverData 'server.key'
& $OpenSslExe req -x509 -newkey rsa:3072 -sha256 -nodes -days 1825 -subj '/CN=6kabinet' -addext 'subjectAltName=DNS:6kabinet' -addext 'extendedKeyUsage=serverAuth' -keyout $keyPath -out $certPath
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL certificate generation failed.' }
$utf8 = New-Object System.Text.UTF8Encoding($false)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$computers = @()
try {
    foreach ($name in $names) {
        $bytes = New-Object byte[] 32; $rng.GetBytes($bytes)
        $token = [BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()
        $computers += @{ name=$name; token=$token }
    }
} finally { $rng.Dispose() }
[IO.File]::WriteAllText((Join-Path $serverData 'computers.json'), (@{ computers=@($computers) } | ConvertTo-Json -Depth 5), $utf8)
New-Item -ItemType Directory -Path (Join-Path $serverData 'updates') | Out-Null
& (Join-Path $PSScriptRoot 'New-SharedClient.ps1') -ClientBundleDirectory (Join-Path $BundleDirectory 'LanClient') -ServerDataDirectory $serverData -OutputDirectory (Join-Path $deploymentPath 'client')
Write-Host "Created a server for $($names.Count) PCs and one shared client bundle."
Write-Host 'Distribute only the client directory. Keep server-data on the server.'

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ClientExe,
    [Parameter(Mandatory=$true)][ValidateRange(2,2147483647)][int]$Version,
    [Parameter(Mandatory=$true)][string]$ServerDataDirectory
)
$ErrorActionPreference = 'Stop'
# Stop LanServer through its tray menu before publishing; this avoids changing a release mid-transfer.
$updates = Join-Path (Resolve-Path -LiteralPath $ServerDataDirectory).Path 'updates'
New-Item -ItemType Directory -Path $updates -Force | Out-Null
$existing = Join-Path $updates 'manifest.json'
if (Test-Path -LiteralPath $existing) {
    $old = Get-Content -LiteralPath $existing -Raw | ConvertFrom-Json
    if ($Version -le [int]$old.version) { throw 'Version must be greater than the previously published release.' }
}
$source = Get-Item -LiteralPath $ClientExe
if ($source.Length -le 0 -or $source.Length -gt 128MB) { throw 'Update must be between 1 byte and 128 MiB.' }
$target = Join-Path $updates 'LanClient.exe'
Copy-Item -LiteralPath $source.FullName -Destination $target -Force
$manifest = @{ version=$Version; size=(Get-Item -LiteralPath $target).Length; sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() }
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $updates 'manifest.json.tmp'), ($manifest | ConvertTo-Json), $utf8)
Move-Item -LiteralPath (Join-Path $updates 'manifest.json.tmp') -Destination $existing -Force
Write-Host "Published release $Version. Start LanServer; connected clients check every 10 minutes and on reconnect."

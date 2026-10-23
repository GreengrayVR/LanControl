[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ScratchDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $thrown = $false
    try { & $Action | Out-Null } catch { $thrown = $true }
    Assert $thrown $Message
}
# Deliberately fake OpenSSL output: these tests cover packaging/tokens/manifest handling,
# not certificate generation, TLS, EXE compilation, installation or service behavior.
function Invoke-TestOpenSsl {
    $outIndex = [Array]::IndexOf($args, '-out')
    if ($outIndex -lt 0) { throw 'Test OpenSSL: missing -out' }
    $body = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('test-certificate-bytes'))
    [IO.File]::WriteAllText([string]$args[$outIndex + 1], "-----BEGIN CERTIFICATE-----`n$body`n-----END CERTIFICATE-----`n")
    $keyIndex = [Array]::IndexOf($args, '-keyout')
    if ($keyIndex -ge 0) { [IO.File]::WriteAllText([string]$args[$keyIndex + 1], 'test-key') }
    $global:LASTEXITCODE = 0
}
Assert (-not (Test-Path -LiteralPath $ScratchDirectory)) 'Choose a fresh scratch directory.'
New-Item -ItemType Directory -Path $ScratchDirectory | Out-Null
$scratch = (Resolve-Path -LiteralPath $ScratchDirectory).Path
foreach ($script in Get-ChildItem -LiteralPath (Join-Path $projectRoot 'scripts') -Filter '*.ps1') {
    $tokens = $null; $issues = $null
    [Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$issues) | Out-Null
    Assert ($issues.Count -eq 0) "Syntax error in $($script.Name)"
}
$bundle = Join-Path $scratch 'bundle'
foreach ($name in @('LanClient','LanServer')) {
    $folder = Join-Path $bundle $name; New-Item -ItemType Directory -Path $folder -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $folder "$name.exe"), [Text.Encoding]::ASCII.GetBytes('test-binary-bytes'))
}
$names = Join-Path $scratch 'names.txt'; [IO.File]::WriteAllText($names, "pc-01`npc-02`n")
$deployment = Join-Path $scratch 'deployment'
& (Join-Path $projectRoot 'scripts\New-Deployment.ps1') -BundleDirectory $bundle -OutputDirectory $deployment -ComputerNamesFile $names -OpenSslExe 'Invoke-TestOpenSsl'
$serverData = Join-Path $deployment 'server\server-data'
$computers = Get-Content -LiteralPath (Join-Path $serverData 'computers.json') -Raw | ConvertFrom-Json
Assert ($computers.computers.Count -eq 2) 'Missing computer entries.'
$tokens = @($computers.computers | ForEach-Object { $_.token })
Assert (($tokens | Select-Object -Unique).Count -eq 2) 'Tokens must be unique.'
$clientDirectory = Join-Path $deployment 'client'
$cfg = Get-Content -LiteralPath (Join-Path $clientDirectory 'client.json') -Raw | ConvertFrom-Json
Assert ($cfg.token -ceq $computers.sharedClientToken -and $cfg.token -cmatch '^[a-f0-9]{64}$') 'Shared token mismatch.'
Assert ($cfg.server -eq '6kabinet' -and $cfg.port -eq 47666) 'Wrong endpoint.'
Assert ($cfg.certificateSha256 -ceq '342ae913556a8804967bd2a4c108927ed973ad234069bbea1fcd2cf18362c2cd') 'Wrong certificate pin.'
Assert (-not (Test-Path -LiteralPath (Join-Path $deployment 'clients'))) 'Per-PC packages should not be created.'
Assert (-not (Get-ChildItem -LiteralPath $clientDirectory -Recurse -Filter 'server.key')) 'Private key leaked.'
Assert (-not (Test-Path -LiteralPath (Join-Path $clientDirectory 'computers.json'))) 'Server configuration leaked.'

$configPath = Join-Path $serverData 'computers.json'
$beforeConfig = (Get-FileHash -LiteralPath $configPath).Hash
& (Join-Path $projectRoot 'scripts\New-SharedClient.ps1') -ClientBundleDirectory (Join-Path $bundle 'LanClient') -ServerDataDirectory $serverData -OutputDirectory (Join-Path $scratch 'shared-again')
$again = Get-Content -LiteralPath (Join-Path $scratch 'shared-again\client.json') -Raw | ConvertFrom-Json
Assert ($again.token -ceq $cfg.token) 'Regenerating a package must reuse the shared token.'
Assert ((Get-FileHash -LiteralPath $configPath).Hash -ceq $beforeConfig) 'Existing shared configuration was unnecessarily rewritten.'
Assert-Throws { & (Join-Path $projectRoot 'scripts\New-SharedClient.ps1') -ClientBundleDirectory (Join-Path $bundle 'LanClient') -ServerDataDirectory $serverData -OutputDirectory $clientDirectory } 'Must not overwrite an existing client package.'
Assert ((Get-FileHash -LiteralPath $configPath).Hash -ceq $beforeConfig) 'Rejected packaging changed server configuration.'

# Migration adds shared access while preserving all existing client credentials and TLS files.
$computers.PSObject.Properties.Remove('sharedClientToken')
$computers | Add-Member -NotePropertyName 'testMetadata' -NotePropertyValue 'preserve me'
$computers | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $configPath -Encoding UTF8
$certificateHash = (Get-FileHash -LiteralPath (Join-Path $serverData 'server.crt')).Hash
$keyHash = (Get-FileHash -LiteralPath (Join-Path $serverData 'server.key')).Hash
& (Join-Path $projectRoot 'scripts\New-SharedClient.ps1') -ClientBundleDirectory (Join-Path $bundle 'LanClient') -ServerDataDirectory $serverData -OutputDirectory (Join-Path $scratch 'migrated')
$migrated = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$migratedClient = Get-Content -LiteralPath (Join-Path $scratch 'migrated\client.json') -Raw | ConvertFrom-Json
Assert ($migratedClient.token -ceq $migrated.sharedClientToken) 'Migrated shared credentials do not match.'
Assert ($migrated.testMetadata -ceq 'preserve me') 'Migration discarded server metadata.'
Assert (($migrated.computers | ConvertTo-Json -Compress) -ceq ($computers.computers | ConvertTo-Json -Compress)) 'Migration changed existing client credentials.'
Assert ((Get-FileHash -LiteralPath (Join-Path $serverData 'server.crt')).Hash -ceq $certificateHash) 'Migration changed the certificate.'
Assert ((Get-FileHash -LiteralPath (Join-Path $serverData 'server.key')).Hash -ceq $keyHash) 'Migration changed the private key.'
Assert-Throws { & (Join-Path $projectRoot 'scripts\New-Deployment.ps1') -BundleDirectory $bundle -OutputDirectory $deployment -ComputerNamesFile $names } 'Must not overwrite existing deployment.'
[IO.File]::WriteAllText($names, "PC-01`npc-01`n")
Assert-Throws { & (Join-Path $projectRoot 'scripts\New-Deployment.ps1') -BundleDirectory $bundle -OutputDirectory (Join-Path $scratch 'duplicate') -ComputerNamesFile $names } 'Duplicate names were accepted.'
$source = Join-Path $bundle 'LanClient\LanClient.exe'
& (Join-Path $projectRoot 'scripts\Publish-Update.ps1') -ClientExe $source -Version 2 -ServerDataDirectory $serverData
$manifestFile = Join-Path $serverData 'updates\manifest.json'
$m = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
Assert ($m.version -eq 2 -and $m.size -eq (Get-Item -LiteralPath $source).Length) 'Wrong update metadata.'
Assert ($m.sha256 -eq (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()) 'Wrong update hash.'
Assert-Throws { & (Join-Path $projectRoot 'scripts\Publish-Update.ps1') -ClientExe $source -Version 2 -ServerDataDirectory $serverData } 'Duplicate version accepted.'
[IO.File]::WriteAllBytes($source, [byte[]]@())
Assert-Throws { & (Join-Path $projectRoot 'scripts\Publish-Update.ps1') -ClientExe $source -Version 3 -ServerDataDirectory $serverData } 'Empty update accepted.'
$unchanged = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
Assert ($unchanged.version -eq 2) 'Rejected update modified existing manifest.'
Write-Host 'PASS: PowerShell syntax, shared client packaging, stable shared credentials, legacy migration, certificate preservation, endpoint/pin, duplicate protection, release metadata/hash, empty update rejection.'
Write-Host 'Certificate output was mocked. No C++ binaries, TLS sessions or Windows services were executed.'

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$QtRoot,
    [Parameter(Mandatory=$true)][string]$OpenSslBin,
    [ValidateRange(1,2147483647)][int]$Version = 1,
    [string]$BuildDirectory = '',
    [string]$OutputDirectory = ''
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $projectRoot "build-v$Version" }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $projectRoot "dist-v$Version" }
function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
if (-not (Test-Path -LiteralPath (Join-Path $QtRoot 'bin\windeployqt.exe'))) { throw 'QtRoot must point to the Qt MSVC x64 kit.' }
$sslDlls = @(Get-ChildItem -LiteralPath $OpenSslBin -Filter '*.dll' | Where-Object { $_.Name -match '^lib(ssl|crypto).*3.*\.dll$' })
if ($sslDlls.Count -lt 2) { throw 'OpenSslBin must contain matching x64 OpenSSL 3 libssl/libcrypto DLLs.' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose an empty OutputDirectory; existing builds are preserved.' }
if (-not $env:VCINSTALLDIR) {
    $vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $vsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsRoot) { $env:VCINSTALLDIR = Join-Path $vsRoot 'VC' }
    }
}
Invoke-Checked 'cmake' @('-S', $projectRoot, '-B', $BuildDirectory, '-G', 'Visual Studio 17 2022', '-A', 'x64', "-DCMAKE_PREFIX_PATH=$QtRoot", "-DLANCONTROL_VERSION_CODE=$Version", '-DBUILD_TESTING=ON')
Invoke-Checked 'cmake' @('--build', $BuildDirectory, '--config', 'Release', '--parallel')
$env:PATH = "$QtRoot\bin;$OpenSslBin;$env:PATH"
Invoke-Checked 'ctest' @('--test-dir', $BuildDirectory, '-C', 'Release', '--output-on-failure')
foreach ($target in @('LanClient', 'LanServer')) {
    $folder = Join-Path $OutputDirectory $target
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $BuildDirectory "bin\Release\$target.exe") -Destination $folder
    # OpenSSL DLLs are copied explicitly below; --force-openssl cannot be combined with --openssl-root.
    Invoke-Checked (Join-Path $QtRoot 'bin\windeployqt.exe') @('--release', '--compiler-runtime', '--force-openssl', (Join-Path $folder "$target.exe"))
    foreach ($dll in $sslDlls) { Copy-Item -LiteralPath $dll.FullName -Destination $folder -Force }
    if (-not (Test-Path -LiteralPath (Join-Path $folder 'tls\qopensslbackend.dll'))) { throw 'Missing Qt OpenSSL TLS plugin after deployment.' }
}
Write-Host "Build and tests passed. Deployable bundles: $OutputDirectory"

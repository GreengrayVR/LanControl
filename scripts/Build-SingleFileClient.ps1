[CmdletBinding()]
param(
    [string]$StaticQtRoot = '',
    [string]$ClientConfig = '',
    [string]$BuildDirectory = '',
    [string]$OutputDirectory = '',
    [ValidateRange(2,2147483647)][int]$Version = 2,
    [ValidateRange(1,64)][int]$Parallel = 6
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $StaticQtRoot) { $StaticQtRoot = Join-Path $projectRoot '.build-tools\qtstatic' }
if (-not $ClientConfig) { $ClientConfig = Join-Path $projectRoot 'deployment\client\client.json' }
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $projectRoot "build-standalone-v$Version" }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $projectRoot 'deployment\single-file' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new OutputDirectory; existing packages are preserved.' }
$qt = (Resolve-Path -LiteralPath $StaticQtRoot).Path
$config = (Resolve-Path -LiteralPath $ClientConfig).Path
$enrollment = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
if ($enrollment.server -cne '6kabinet' -or $enrollment.port -ne 47666 -or
    $enrollment.token -cnotmatch '^[a-f0-9]{64}$' -or $enrollment.certificateSha256 -cnotmatch '^[a-f0-9]{64}$') {
    throw 'Invalid shared client configuration.'
}
$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsRoot) { throw 'MSVC 2022 is required.' }
Import-Module (Join-Path $vsRoot 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vsRoot -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
$env:PATH = (Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja') + ';' + $env:PATH
function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
Invoke-Checked 'cmake' @('-S', $projectRoot, '-B', $BuildDirectory, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', "-DCMAKE_PREFIX_PATH=$qt", '-DLANCONTROL_BUILD_SERVER=OFF', '-DLANCONTROL_SINGLE_FILE_CLIENT=ON', "-DLANCONTROL_CLIENT_CONFIG=$config", "-DLANCONTROL_VERSION_CODE=$Version", '-DBUILD_TESTING=ON')
Invoke-Checked 'cmake' @('--build', $BuildDirectory, '--parallel', "$Parallel")
Invoke-Checked 'ctest' @('--test-dir', $BuildDirectory, '--output-on-failure')
$exe = Join-Path $BuildDirectory 'bin\LanClient.exe'
$imports = & dumpbin.exe /DEPENDENTS $exe
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the client import table.' }
$imports | Set-Content -LiteralPath (Join-Path $BuildDirectory 'LanClient-imports.txt') -Encoding UTF8
$systemDirectory = [Environment]::GetFolderPath('System')
foreach ($line in $imports) {
    if ($line -match '^\s+([A-Za-z0-9_.-]+\.dll)\s*$') {
        $dll = $Matches[1]
        # Windows API-set names are resolved by the OS loader and need not exist as physical DLL files.
        $windowsApiSet = $dll -match '^(api-ms-win-|ext-ms-win-)'
        if ($dll -match '^(Qt\d|libssl|libcrypto|msvcp|vcruntime|concrt|vccorlib)' -or
            (-not $windowsApiSet -and -not (Test-Path -LiteralPath (Join-Path $systemDirectory $dll)))) {
            throw "Non-system DLL dependency found: $dll"
        }
    }
}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
Copy-Item -LiteralPath $exe -Destination (Join-Path $OutputDirectory 'LanClient.exe')
Write-Host "Standalone client with embedded configuration, static Qt/MSVC runtime and Schannel: $OutputDirectory\LanClient.exe"

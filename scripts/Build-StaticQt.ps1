[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SourceDirectory,
    [string]$BuildDirectory = '',
    [string]$InstallDirectory = '',
    [ValidateRange(1,64)][int]$Parallel = 6
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $projectRoot '.build-tools\qtbuild' }
if (-not $InstallDirectory) { $InstallDirectory = Join-Path $projectRoot '.build-tools\qtstatic' }
$source = (Resolve-Path -LiteralPath $SourceDirectory).Path
$install = [IO.Path]::GetFullPath($InstallDirectory)
if (-not (Test-Path -LiteralPath (Join-Path $source 'configure.bat'))) { throw 'Qt base source directory is required.' }
$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsRoot) { throw 'MSVC 2022 is required.' }
Import-Module (Join-Path $vsRoot 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vsRoot -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
$ninjaDirectory = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja'
$env:PATH = "$ninjaDirectory;$env:PATH"
New-Item -ItemType Directory -Path $BuildDirectory -Force | Out-Null
Push-Location $BuildDirectory
try {
    if (-not (Test-Path -LiteralPath 'CMakeCache.txt')) {
        & (Join-Path $source 'configure.bat') -prefix $install -static -static-runtime -release -opensource -confirm-license -nomake examples -nomake tests -no-gui -no-widgets -no-dbus -no-opengl -no-openssl -schannel -no-icu -no-feature-sql -no-feature-xml -no-feature-concurrent -qt-zlib -qt-pcre -qt-doubleconversion
        if ($LASTEXITCODE -ne 0) { throw 'Static Qt configuration failed.' }
    }
    cmake --build . --parallel $Parallel
    if ($LASTEXITCODE -ne 0) { throw 'Static Qt compilation failed.' }
    cmake --install .
    if ($LASTEXITCODE -ne 0) { throw 'Static Qt installation failed.' }
} finally { Pop-Location }
Write-Host "Static Qt with static MSVC runtime and Windows Schannel: $install"

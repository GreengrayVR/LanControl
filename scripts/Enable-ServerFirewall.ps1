#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
if (-not (Get-NetFirewallRule -Name 'LanControl-Server' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'LanControl-Server' -DisplayName 'LanControl server (local subnet)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47666 -Profile Domain,Private -RemoteAddress LocalSubnet | Out-Null
}
Write-Host 'TCP 47666 allowed for local subnet on Domain/Private network profiles.'

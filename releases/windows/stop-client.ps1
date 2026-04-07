param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run as Administrator"
    }
}

Assert-Admin

$stateDir = Join-Path $env:APPDATA "AIVPN"
$pidPath = Join-Path $stateDir "client.pid"

if (Test-Path $pidPath) {
    $pidValue = (Get-Content $pidPath -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    if ($pidValue) {
        Stop-Process -Id ([int]$pidValue) -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $pidPath -Force -ErrorAction SilentlyContinue
}

Get-Process -Name "aivpn-client" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "AIVPN client stopped"
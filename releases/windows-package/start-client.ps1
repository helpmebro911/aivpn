param(
    [Parameter(Mandatory = $true)]
    [string]$ConnectionKey,

    [Parameter(Mandatory = $true)]
    [string]$InstallDir,

    [switch]$FullTunnel
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
$logPath = Join-Path $stateDir "client.log"
$pidPath = Join-Path $stateDir "client.pid"
$exe = Join-Path $InstallDir "aivpn-client.exe"

New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
if (-not (Test-Path $exe)) {
    throw "Missing client binary: $exe"
}

Get-Process -Name "aivpn-client" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$args = @("-k", $ConnectionKey)
if ($FullTunnel) {
    $args += "--full-tunnel"
}

if (Test-Path $logPath) {
    Remove-Item $logPath -Force -ErrorAction SilentlyContinue
}

$proc = Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $InstallDir -PassThru -WindowStyle Hidden -RedirectStandardOutput $logPath -RedirectStandardError $logPath
$proc.Id | Set-Content -Path $pidPath -Encoding ASCII
Write-Host "AIVPN client started (PID=$($proc.Id))"
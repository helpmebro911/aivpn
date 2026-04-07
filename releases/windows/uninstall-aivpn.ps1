param(
    [string]$InstallDir = "$env:ProgramFiles\AIVPN"
)

$ErrorActionPreference = "Stop"

function Ensure-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }

    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $PSCommandPath),
        "-InstallDir", ('"{0}"' -f $InstallDir)
    )
    Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs | Out-Null
    exit 0
}

Ensure-Admin

$stopScript = Join-Path $InstallDir "stop-client.ps1"
if (Test-Path $stopScript) {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $stopScript -InstallDir $InstallDir | Out-Null
}

$startMenuDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\AIVPN"
$startupShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup\AIVPN.lnk"
$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "AIVPN.lnk"
$stateDir = Join-Path $env:APPDATA "AIVPN"

Remove-Item $startupShortcut -Force -ErrorAction SilentlyContinue
Remove-Item $desktopShortcut -Force -ErrorAction SilentlyContinue
Remove-Item $startMenuDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $stateDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "AIVPN removed from $InstallDir"
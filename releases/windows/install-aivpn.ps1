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

function New-Shortcut {
    param(
        [string]$Path,
        [string]$TargetPath,
        [string]$Arguments,
        [string]$WorkingDirectory,
        [string]$Description
    )

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $TargetPath
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Description = $Description
    $shortcut.Save()
}

Ensure-Admin

$sourceDir = Split-Path -Parent $PSCommandPath
$files = @(
    "aivpn-client.exe",
    "wintun.dll",
    "AivpnTray.ps1",
    "Launch-AIVPN.vbs",
    "start-client.ps1",
    "stop-client.ps1",
    "smoke-test.ps1",
    "README_WINDOWS.md",
    "uninstall-aivpn.ps1",
    "uninstall-aivpn.cmd"
)

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

foreach ($file in $files) {
    $src = Join-Path $sourceDir $file
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $InstallDir $file) -Force
    }
}

$startMenuDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\AIVPN"
$startupDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup"
$desktopDir = [Environment]::GetFolderPath("Desktop")

New-Item -ItemType Directory -Path $startMenuDir -Force | Out-Null

$launcher = Join-Path $InstallDir "Launch-AIVPN.vbs"
New-Shortcut -Path (Join-Path $startMenuDir "AIVPN.lnk") -TargetPath "wscript.exe" -Arguments ('"{0}"' -f $launcher) -WorkingDirectory $InstallDir -Description "AIVPN tray app"
New-Shortcut -Path (Join-Path $startupDir "AIVPN.lnk") -TargetPath "wscript.exe" -Arguments ('"{0}"' -f $launcher) -WorkingDirectory $InstallDir -Description "Start AIVPN in tray"
New-Shortcut -Path (Join-Path $desktopDir "AIVPN.lnk") -TargetPath "wscript.exe" -Arguments ('"{0}"' -f $launcher) -WorkingDirectory $InstallDir -Description "AIVPN tray app"
New-Shortcut -Path (Join-Path $startMenuDir "Uninstall AIVPN.lnk") -TargetPath "powershell.exe" -Arguments ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $InstallDir "uninstall-aivpn.ps1")) -WorkingDirectory $InstallDir -Description "Uninstall AIVPN"

Write-Host "AIVPN installed to $InstallDir"
Write-Host "Start Menu and Startup shortcuts created."
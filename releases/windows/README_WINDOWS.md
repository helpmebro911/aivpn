# AIVPN Windows Package

This folder contains a Windows tray app, installer scripts, and smoke-test tooling.

## Package Contents

- `aivpn-client.exe` - Windows client binary
- `wintun.dll` - Wintun runtime (must be next to the exe)
- `AivpnTray.ps1` - tray app controller
- `Launch-AIVPN.vbs` - hidden launcher for the tray app
- `start-client.ps1` - elevated helper to start the VPN client
- `stop-client.ps1` - elevated helper to stop the VPN client
- `install-aivpn.ps1` / `install-aivpn.cmd` - installer entry point
- `uninstall-aivpn.ps1` / `uninstall-aivpn.cmd` - uninstaller entry point
- `aivpn-setup.iss` - Inno Setup installer project for a real Windows setup.exe
- `smoke-test.ps1` - automated test script

## Build Package On macOS/Linux

Run from repository root:

```bash
./build-windows-package.sh
```

It will generate:

- `releases/windows-package/` (unpacked files)
- `releases/aivpn-windows-package.zip`

## Install On Windows

1. Copy `releases/aivpn-windows-package.zip` to Windows.
2. Unzip it, for example to `C:\aivpn`.
3. Preferred: compile and run the Inno Setup installer.
4. Fallback: right click `install-aivpn.cmd` and run it as Administrator.

## Build A Real Installer

On a Windows machine with Inno Setup installed:

```powershell
iscc /DSourceDir="C:\aivpn" /DOutputDir="C:\aivpn\dist" C:\aivpn\aivpn-setup.iss
```

This produces a standard Windows installer executable that installs AIVPN into `C:\Program Files\AIVPN`, adds Start Menu and Startup shortcuts, and registers an uninstaller.

## Production Icon And Code Signing

The Inno Setup project supports both optional icon branding and code signing.

- Put `aivpn.ico` next to `aivpn-setup.iss`, or pass `/DIconFile="C:\path\to\aivpn.ico"`.
- Pass `/DSignToolCommand="signtool.exe sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a /n ""Your Company"" $f"` to sign the installer and uninstaller.

Example:

```powershell
iscc /DSourceDir="C:\aivpn" /DOutputDir="C:\aivpn\dist" /DIconFile="C:\aivpn\aivpn.ico" /DSignToolCommand="signtool.exe sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a /n ""Your Company"" $f" C:\aivpn\aivpn-setup.iss
```

If you build from the repo packaging script, it also honors:

- `AIVPN_WINDOWS_ICON=/path/to/aivpn.ico`
- `AIVPN_WINDOWS_SIGNTOOL='signtool.exe sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a /n "Your Company" $f'`

## Tray App

- Left click the tray icon to open the control window.
- Paste the `aivpn://...` connection key and choose full-tunnel mode if needed.
- `Connect` prompts for elevation and starts `aivpn-client.exe`.
- `Disconnect` prompts for elevation and stops the running client.
- `Open Log` opens `%APPDATA%\AIVPN\client.log`.

## Real Test In Windows VM

1. Copy `releases/aivpn-windows-package.zip` into your Windows VM.
2. Unzip to a folder, for example `C:\aivpn`.
3. Open PowerShell as Administrator.
4. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
cd C:\aivpn
.\smoke-test.ps1 -ConnectionKey "aivpn://..." -FullTunnel
```

## What The Smoke Test Checks

- Administrator privileges
- Presence and signatures of `aivpn-client.exe` and `wintun.dll`
- Client process starts correctly
- Basic connectivity check while client is running
- Graceful stop and log output summary

## Note About EXE Signature

`aivpn-client.exe` may be unsigned unless you sign it with an Authenticode certificate.
Unsigned exe can trigger SmartScreen warnings. This is expected for self-built binaries.

The tray app and installer are wrappers around the same client binary, so the same SmartScreen note applies unless you sign the resulting installer and binaries yourself.

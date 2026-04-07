#define MyAppName "AIVPN"
#define MyAppVersion "0.2.0"
#define MyAppPublisher "AIVPN Team"
#define MyAppExeName "Launch-AIVPN.vbs"

#ifndef SourceDir
  #define SourceDir "."
#endif

#ifndef OutputDir
  #define OutputDir "."
#endif

#ifndef IconFile
  #define IconFile AddBackslash(SourceDir) + "aivpn.ico"
#endif

#if FileExists(IconFile)
  #define HasInstallerIcon
#endif

#ifndef SignToolCommand
  #define SignToolCommand ""
#endif

#if SignToolCommand != ""
  #define HasSignTool
#endif

[Setup]
AppId={{8D7F5D7D-3D02-4D2C-A364-83E8D3C4CB7F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\AIVPN
DefaultGroupName=AIVPN
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
OutputDir={#OutputDir}
OutputBaseFilename=aivpn-windows-setup
UninstallDisplayIcon={app}\aivpn-client.exe
#ifdef HasInstallerIcon
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\aivpn.ico
#endif
#ifdef HasSignTool
SignTool=aivpn_sign
SignedUninstaller=yes
#endif

#ifdef HasSignTool
[SignTools]
Name: "aivpn_sign"; Command: "{#SignToolCommand}"
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SourceDir}\aivpn-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\AivpnTray.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\Launch-AIVPN.vbs"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\start-client.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\stop-client.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\install-aivpn.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\install-aivpn.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\uninstall-aivpn.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\uninstall-aivpn.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README_WINDOWS.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\smoke-test.ps1"; DestDir: "{app}"; Flags: ignoreversion
#ifdef HasInstallerIcon
Source: "{#IconFile}"; DestDir: "{app}"; DestName: "aivpn.ico"; Flags: ignoreversion
#endif

[Icons]
#ifdef HasInstallerIcon
Name: "{autoprograms}\AIVPN"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-AIVPN.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\aivpn.ico"
Name: "{autodesktop}\AIVPN"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-AIVPN.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\aivpn.ico"
Name: "{commonstartup}\AIVPN"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-AIVPN.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\aivpn.ico"
#else
Name: "{autoprograms}\AIVPN"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-AIVPN.vbs"""; WorkingDir: "{app}"
Name: "{autodesktop}\AIVPN"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-AIVPN.vbs"""; WorkingDir: "{app}"
Name: "{commonstartup}\AIVPN"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-AIVPN.vbs"""; WorkingDir: "{app}"
#endif
Name: "{autoprograms}\Uninstall AIVPN"; Filename: "{uninstallexe}"

[Run]
Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-AIVPN.vbs"""; Description: "Launch AIVPN tray app"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\stop-client.ps1"" -InstallDir ""{app}"""; Flags: runhidden
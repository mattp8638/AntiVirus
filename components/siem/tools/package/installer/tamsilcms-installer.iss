; Inno Setup script for Tamsilcms installer
; This script expects a preprocessor define /DSourceDir="C:\path\to\package_tmp"
; Example build command (ISCC):
; ISCC /DSourceDir="C:\repo\package_tmp" tamsilcms-installer.iss

[; preprocessor variable `SourceDir` is provided via ISCC /DSourceDir=... ]
[Setup]
AppName=Tamsilcms SIEM
AppVersion=0.1.0
DefaultDirName={autopf}\Tamsilcms
DefaultGroupName=Tamsilcms
DisableProgramGroupPage=yes
Compression=lzma2
SolidCompression=yes
OutputBaseFilename=tamsilcms-installer
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; UI assets
Source: "{#SourceDir}\ui\dist\*"; DestDir: "{app}\ui\dist"; Flags: recursesubdirs createallsubdirs
; Backend source and helpers
Source: "{#SourceDir}\backend\*"; DestDir: "{app}\backend"; Flags: recursesubdirs createallsubdirs
; Packaging helpers (bootstrap/run scripts)
Source: "{#SourceDir}\bootstrap.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\run-backend.bat"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Tamsilcms Console"; Filename: "{app}\run-backend.bat"
Name: "{group}\Uninstall Tamsilcms"; Filename: "{uninstallexe}"

[Run]
; Optionally run the bootstrap script after install (runs PowerShell). The installer runs elevated (PrivilegesRequired=admin)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""{app}\\bootstrap.ps1"""; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

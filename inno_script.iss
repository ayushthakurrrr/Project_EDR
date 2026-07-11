[Setup]
AppName=EdrAgent
AppVersion=1.0
DefaultDirName={autopf}\EdrAgent
DisableDirPage=yes
DefaultGroupName=EdrAgent
OutputDir=dist
OutputBaseFilename=EdrAgentInstaller
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
DisableProgramGroupPage=yes


; ----------------------------------------------------
; FILES (NO separate uninstaller EXE anymore)
; ----------------------------------------------------
[Files]
Source: "dist\EdrAgentGUI.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\EdrAgentSERVICE.exe"; DestDir: "{app}"; Flags: ignoreversion


; ----------------------------------------------------
; SHORTCUTS
; ----------------------------------------------------
[Icons]
Name: "{group}\EdrAgent GUI"; Filename: "{app}\EdrAgentGUI.exe"
Name: "{commondesktop}\EdrAgent"; Filename: "{app}\EdrAgentGUI.exe"


; ----------------------------------------------------
; INSTALL STEPS
; ----------------------------------------------------
[Run]

; Stop old service if exists
Filename: "sc.exe"; Parameters: "stop SimpleEDR 1"; Flags: runhidden waituntilterminated

; small delay to allow clean shutdown
Filename: "cmd.exe"; Parameters: "/C timeout /t 2 /nobreak >nul"; Flags: runhidden waituntilterminated

; Delete old service
Filename: "sc.exe"; Parameters: "delete SimpleEDR 1"; Flags: runhidden waituntilterminated

; Install service (your EXE handles install logic)
Filename: "{app}\EdrAgentSERVICE.exe"; Parameters: "install"; Flags: runhidden waituntilterminated

; Set auto start
Filename: "sc.exe"; Parameters: "config SimpleEDR 1 start= auto"; Flags: runhidden waituntilterminated

; Start service
Filename: "sc.exe"; Parameters: "start SimpleEDR 1"; Flags: runhidden waituntilterminated

; Launch GUI
Filename: "{app}\EdrAgentGUI.exe"; Flags: nowait postinstall skipifsilent


; ----------------------------------------------------
; UNINSTALL CLEANUP (IMPORTANT)
; ----------------------------------------------------
[UninstallRun]

Filename: "taskkill.exe"; Parameters: "/F /IM EdrAgentGUI.exe"; Flags: runhidden waituntilterminated

Filename: "taskkill.exe"; Parameters: "/F /IM EdrAgentSERVICE.exe"; Flags: runhidden waituntilterminated

Filename: "sc.exe"; Parameters: "stop SimpleEDR 1"; Flags: runhidden waituntilterminated

Filename: "cmd.exe"; Parameters: "/C timeout /t 3 /nobreak >nul"; Flags: runhidden waituntilterminated

Filename: "cmd.exe"; Parameters: "/C for /L %%i in (1,1,10) do (sc query SimpleEDR 1 | find ""STOPPED"" >nul && exit) || timeout /t 1 >nul"; Flags: runhidden waituntilterminated

Filename: "sc.exe"; Parameters: "delete SimpleEDR 1"; Flags: runhidden waituntilterminated

Filename: "reg.exe"; Parameters: "delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v EdrAgentGUI /f"; Flags: runhidden waituntilterminated


; ----------------------------------------------------
; REGISTRY (AUTO START GUI)
; ----------------------------------------------------
[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
ValueType: string; ValueName: "EdrAgentGUI"; ValueData: """{app}\EdrAgentGUI.exe"""; Flags: uninsdeletevalue



; ----------------------------------------------------
; FILE CLEANUP
; ----------------------------------------------------
[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\EdrAgent"
Type: filesandordirs; Name: "{userappdata}\EdrAgent"
Type: filesandordirs; Name: "{app}"
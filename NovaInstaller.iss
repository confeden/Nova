#define MyAppName "Nova"
#define MyAppVersion "@@APP_VERSION@@"
#define MyAppVersionInfo "@@APP_VERSION_INFO@@"
#define MyAppPublisher "Brent"
#define MyAppExeName "Nova.exe"
#define MyLicenseUrl "https://github.com/confeden/Nova/blob/main/LICENSE"
#define MySourceDir "@@SOURCE_DIR@@"
#define MyOutputDir "@@OUTPUT_DIR@@"
#define MyRepoDir "@@REPO_DIR@@"

[Setup]
AppId={{6C4A94A4-56E3-4A3A-91AF-7E0D34E3B4C2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion={#MyAppVersionInfo}
VersionInfoProductVersion={#MyAppVersionInfo}
VersionInfoTextVersion={#MyAppVersion}
VersionInfoProductTextVersion={#MyAppVersion}
VersionInfoDescription={#MyAppName} Setup
VersionInfoCompany={#MyAppPublisher}
DefaultDirName={localappdata}\Nova
DefaultGroupName={#MyAppName}
UsePreviousAppDir=yes
UsePreviousGroup=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CompressionThreads=7
LZMANumBlockThreads=7
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#MyOutputDir}
OutputBaseFilename=NovaSetup
SetupIconFile={#MyRepoDir}\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
LicenseFile={#MyRepoDir}\LICENSE
CloseApplications=yes
RestartApplications=no
ChangesAssociations=no
ChangesEnvironment=no
DirExistsWarning=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
english.CreateDesktopShortcut=Create a desktop shortcut
russian.CreateDesktopShortcut=Добавить ярлык на рабочий стол
english.LicenseLink=Open license on GitHub
russian.LicenseLink=Открыть лицензию на GitHub

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopShortcut}"; GroupDescription: "{cm:AdditionalIcons}"

[Dirs]
Name: "{app}\temp"
Name: "{app}\resources"
Name: "{app}\resources\docs"
Name: "{app}\resources\legal"
Name: "{app}\resources\NovaWFP"
Name: "{app}\resources\NovaWFP\proxy"
Name: "{app}\resources\NovaDivert"
Name: "{app}\resources\tgrelay"

[Files]
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Excludes: "list\u_ru.txt,list\u_eu.txt,ip\u_ru.txt,ip\u_eu.txt,bin\sing-box.exe,routing_settings.json,README.md,THIRD_PARTY_NOTICES.md,LICENSE,licenses,licenses\*,NovaWFP,NovaWFP\*,NovaDivert,NovaDivert\*,tgrelay,tgrelay\*"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MySourceDir}\list\u_ru.txt"; DestDir: "{app}\list"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall
Source: "{#MySourceDir}\list\u_eu.txt"; DestDir: "{app}\list"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall
Source: "{#MySourceDir}\ip\u_ru.txt"; DestDir: "{app}\ip"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall
Source: "{#MySourceDir}\ip\u_eu.txt"; DestDir: "{app}\ip"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall
Source: "{#MySourceDir}\routing_settings.json"; DestDir: "{app}\temp"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall
Source: "{#MyRepoDir}\NovaWFP\proxy\*"; DestDir: "{app}\resources\NovaWFP\proxy"; Excludes: "__pycache__\*"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyRepoDir}\NovaDivert\*.py"; DestDir: "{app}\resources\NovaDivert"; Flags: ignoreversion
Source: "{#MyRepoDir}\tgrelay\*"; DestDir: "{app}\resources\tgrelay"; Excludes: "__pycache__\*"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyRepoDir}\nova_routing_profiles.py"; DestDir: "{app}\resources"; Flags: ignoreversion
Source: "{#MySourceDir}\README.md"; DestDir: "{app}\resources\docs"; Flags: ignoreversion
Source: "{#MySourceDir}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}\resources\legal"; Flags: ignoreversion
Source: "{#MySourceDir}\LICENSE"; DestDir: "{app}\resources\legal"; Flags: ignoreversion
Source: "{#MySourceDir}\licenses\*"; DestDir: "{app}\resources\legal\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
Type: files; Name: "{app}\nova_deploy_debug.txt"
Type: files; Name: "{app}\routing_settings.json"
Type: filesandordirs; Name: "{app}\resources\fake"
Type: filesandordirs; Name: "{app}\licenses"
Type: filesandordirs; Name: "{app}\NovaWFP"
Type: filesandordirs; Name: "{app}\NovaDivert"
Type: filesandordirs; Name: "{app}\tgrelay"
; Runs before the new files are extracted. Without this, upgrades keep the old
; helper runtime forever - the pre-1.30 copy carried the whole build machine's
; site-packages and weighed ~122 MB.
Type: filesandordirs; Name: "{app}\resources\pyruntime"
Type: filesandordirs; Name: "{app}\resources\setuptools"
Type: filesandordirs; Name: "{app}\resources\*.dist-info"
Type: filesandordirs; Name: "{app}\resources\__pycache__"

[Icons]
Name: "{autoprograms}\Nova"; Filename: "{app}\Nova.exe"
Name: "{autodesktop}\Nova"; Filename: "{app}\Nova.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Nova.exe"; Parameters: "--updated"; Description: "Запустить Nova"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{autodesktop}\Nova.lnk"
Type: files; Name: "{userstartup}\Nova.lnk"
Type: filesandordirs; Name: "{app}\temp"
; The helpers compile .pyc caches next to their scripts at runtime, so the
; directory is not empty by the time Inno removes what it installed.
Type: filesandordirs; Name: "{app}\resources"

[Code]
var
  LicenseLinkLabel: TNewStaticText;

function PsQuote(const S: string): string;
begin
  Result := S;
  StringChangeEx(Result, '''', '''''', True);
end;

function ExecHiddenAndWait(const FileName, Params: string): Integer;
var
  ResultCode: Integer;
begin
  if Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := ResultCode
  else
    Result := -1;
end;

procedure ForceCloseNovaInstallBlockers;
var
  PsExe, Script, Params, ScriptPath: string;
begin
  PsExe := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if not FileExists(PsExe) then
    PsExe := 'powershell.exe';

  Script :=
    '$ErrorActionPreference=''SilentlyContinue''; ' +
    '$procs = Get-Process -Name Nova, winws, opera-proxy*, warp* -ErrorAction SilentlyContinue; ' +
    '$svc = Get-CimInstance Win32_SystemDriver -Filter "Name=''WinDivert''" -ErrorAction SilentlyContinue; ' +
    'if ($procs -or ($svc -and $svc.State -eq ''Running'')) { ' +
    '  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); ' +
    '  if (-not $isAdmin) { ' +
    '    Start-Process taskkill -ArgumentList ''/F /IM Nova.exe /IM winws.exe /IM opera-proxy* /IM warp-cli.exe /IM warp.exe'' -Verb RunAs -WindowStyle Hidden -Wait; ' +
    '    Start-Process sc.exe -ArgumentList ''stop WinDivert'' -Verb RunAs -WindowStyle Hidden -Wait; ' +
    '  } else { ' +
    '    taskkill /F /IM Nova.exe /IM winws.exe /IM opera-proxy* /IM warp-cli.exe /IM warp.exe; ' +
    '    sc.exe stop WinDivert; ' +
    '  } ' +
    '}';

  ScriptPath := ExpandConstant('{tmp}\nova_cleanup.ps1');
  SaveStringToFile(ScriptPath, Script, False);
  Params := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + ScriptPath + '"';
  ExecHiddenAndWait(PsExe, Params);
  DeleteFile(ScriptPath);
  Sleep(1500); // Give processes time to fully terminate
end;

procedure OpenLicenseLink(Sender: TObject);
var
  ErrorCode: Integer;
begin
  ShellExec('', '{#MyLicenseUrl}', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  NeedsRestart := False;
  ForceCloseNovaInstallBlockers;
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    ForceCloseNovaInstallBlockers;
end;

procedure InitializeWizard;
begin
  if Assigned(WizardForm.LicenseMemo) then
  begin
    LicenseLinkLabel := TNewStaticText.Create(WizardForm.LicenseMemo.Parent);
    LicenseLinkLabel.Parent := WizardForm.LicenseMemo.Parent;
    LicenseLinkLabel.Caption := ExpandConstant('{cm:LicenseLink}');
    LicenseLinkLabel.Cursor := crHand;
    LicenseLinkLabel.Font.Color := clBlue;
    LicenseLinkLabel.Font.Style := [fsUnderline];
    LicenseLinkLabel.Left := WizardForm.LicenseMemo.Left;
    LicenseLinkLabel.AutoSize := True;
    LicenseLinkLabel.Top := WizardForm.LicenseAcceptedRadio.Top - LicenseLinkLabel.Height - ScaleY(6);
    LicenseLinkLabel.OnClick := @OpenLicenseLink;
  end;
end;

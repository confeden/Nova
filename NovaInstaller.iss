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
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Excludes: "list\u_ru.txt,list\u_eu.txt,ip\u_ru.txt,ip\u_eu.txt,bin\sing-box.exe,README.md,THIRD_PARTY_NOTICES.md,LICENSE,licenses,licenses\*,NovaWFP,NovaWFP\*,NovaDivert,NovaDivert\*,tgrelay,tgrelay\*"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MySourceDir}\list\u_ru.txt"; DestDir: "{app}\list"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall
Source: "{#MySourceDir}\list\u_eu.txt"; DestDir: "{app}\list"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall
Source: "{#MySourceDir}\ip\u_ru.txt"; DestDir: "{app}\ip"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall
Source: "{#MySourceDir}\ip\u_eu.txt"; DestDir: "{app}\ip"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall
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
Type: filesandordirs; Name: "{app}\resources\fake"
Type: filesandordirs; Name: "{app}\licenses"
Type: filesandordirs; Name: "{app}\NovaWFP"
Type: filesandordirs; Name: "{app}\NovaDivert"
Type: filesandordirs; Name: "{app}\tgrelay"

[Icons]
Name: "{autoprograms}\Nova"; Filename: "{app}\Nova.exe"
Name: "{autodesktop}\Nova"; Filename: "{app}\Nova.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Nova.exe"; Description: "Запустить Nova"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{autodesktop}\Nova.lnk"
Type: filesandordirs; Name: "{app}\temp"

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
  AppDir, AppDirPs, PsExe, Script, Params, ScriptPath: string;
begin
  AppDir := ExpandConstant('{app}');
  if (AppDir = '') or (not DirExists(AppDir)) then
    exit;

  PsExe := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if not FileExists(PsExe) then
    PsExe := 'powershell.exe';

  AppDirPs := PsQuote(AppDir);
  Script :=
    '$ErrorActionPreference=''SilentlyContinue''; ' +
    '$app=[System.IO.Path]::GetFullPath(''' + AppDirPs + '''); ' +
    'if (-not $app.EndsWith(''\'', [System.StringComparison]::Ordinal)) { $app += ''\'' }; ' +
    '$parentPid = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID").ParentProcessId; ' +
    'function Test-AppPath([string]$path, [int]$procId = 0, [string]$procName = $null) { ' +
    '  if ($procId -eq $PID -or $procId -eq $parentPid) { return $false }; ' +
    '  if ($procName -like ''NovaSetup*'') { return $false }; ' +
    '  if ([string]::IsNullOrWhiteSpace($path)) { return $false }; ' +
    '  try { ' +
    '    $full=[System.IO.Path]::GetFullPath($path.Trim(''"'')); ' +
    '    return $full.StartsWith($app, [System.StringComparison]::OrdinalIgnoreCase) ' +
    '  } catch { return $false } ' +
    '}; ' +
    '$pids = New-Object System.Collections.Generic.HashSet[int]; ' +
    'Get-CimInstance Win32_Process | ForEach-Object { if (Test-AppPath $_.ExecutablePath $_.ProcessId $_.Name) { [void]$pids.Add([int]$_.ProcessId) } }; ' +
    'foreach ($pid in $pids) { Start-Process -FilePath taskkill.exe -ArgumentList @(''/PID'', [string]$pid, ''/T'', ''/F'') -WindowStyle Hidden -Wait | Out-Null }; ' +
    'Start-Sleep -Milliseconds 500; ' +
    '$svc = Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -eq ''WinDivert'' } | Select-Object -First 1; ' +
    '$svcPath = ''''; if ($svc) { $svcPath = [string]$svc.PathName }; ' +
    'if ($svcPath.StartsWith(''\??\'')) { $svcPath = $svcPath.Substring(4) }; ' +
    '$svcPath = $svcPath.Trim([char]34); ' +
    'if (Test-AppPath $svcPath) { sc.exe stop WinDivert | Out-Null; Start-Sleep -Milliseconds 1200 }; ' +
    'Get-CimInstance Win32_Process | ForEach-Object { if (Test-AppPath $_.ExecutablePath $_.ProcessId $_.Name) { Start-Process -FilePath taskkill.exe -ArgumentList @(''/PID'', [string]$_.ProcessId, ''/T'', ''/F'') -WindowStyle Hidden -Wait | Out-Null } };';
  ScriptPath := ExpandConstant('{tmp}\nova_preinstall_cleanup.ps1');
  SaveStringToFile(ScriptPath, Script, False);
  Params := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + ScriptPath + '"';
  ExecHiddenAndWait(PsExe, Params);
  DeleteFile(ScriptPath);
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

#define MyAppName "Nova"
#define MyAppVersion "@@APP_VERSION@@"
#define MyAppPublisher "Brent"
#define MyAppExeName "Nova.exe"
#define MySourceDir "@@SOURCE_DIR@@"
#define MyOutputDir "@@OUTPUT_DIR@@"
#define MyRepoDir "@@REPO_DIR@@"

[Setup]
AppId={{6C4A94A4-56E3-4A3A-91AF-7E0D34E3B4C2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Nova
DefaultGroupName={#MyAppName}
UsePreviousAppDir=yes
UsePreviousGroup=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
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

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительные значки:"; Flags: unchecked

[Dirs]
Name: "{app}\temp"

[Files]
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Nova"; Filename: "{app}\Nova.exe"
Name: "{autodesktop}\Nova"; Filename: "{app}\Nova.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Nova.exe"; Description: "Запустить Nova"; Flags: nowait postinstall skipifsilent

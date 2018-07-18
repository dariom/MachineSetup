$OfficeVersion = 16
$WarningPreference = "SilentlyContinue"
$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#####################################################################################################################################################################################################
#                                                   PRE-REQUISITES
#####################################################################################################################################################################################################
Clear-Host
Write-Host "Please Enter Your Desired Computer Name: "  -ForegroundColor Cyan 
$ComputerName = Read-Host 
Rename-Computer -NewName $ComputerName | Out-Null

Write-Host "Installing Pre-requisites" -ForegroundColor Green

Write-Host "    Chocolatey Script" -ForegroundColor Magenta
Invoke-Expression ((New-Object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null
Import-Module $env:chocolateyinstall\helpers\chocolateyInstaller.psm1 | Out-Null

Write-Host "    NuGet Package Provider" -ForegroundColor Magenta 
Install-PackageProvider -Name NuGet -Confirm:$false -Force | Out-Null

Write-Host "    VS Setup Script" -ForegroundColor Magenta
Install-Module VSSetup -Scope CurrentUser -Confirm:$false -Force | Out-Null

Write-Host "    Windows Update Powershell Script" -ForegroundColor Magenta
Install-Module PSWindowsUpdate -Confirm:$false -Force | Out-Null

#####################################################################################################################################################################################################
#                                                   ENVIRONMENT VARIABLES
#####################################################################################################################################################################################################
Write-Host "Setting up Environment Variables" -ForegroundColor Green

[Environment]::SetEnvironmentVariable('ChocolateyToolsLocation', ${env:ProgramFiles(x86)}, "User")
[Environment]::SetEnvironmentVariable('Path', $Env:Path + ";${env:ProgramFiles}\SourceGear\Common\DiffMerge\", "User")
Update-SessionEnvironment
  
#####################################################################################################################################################################################################
#                                                   INSTALLING APPLICATIONS
#####################################################################################################################################################################################################

# Visual Studio
Write-Host "Installing Visual Studio" -ForegroundColor Green
choco install visualstudio2017professional -y #visualstudio2017enterprise or visualstudio2017community

#Choose your workloads. More information on workloads can be found at https://chocolatey.org/search?q=visualstudio2017-workload
Write-Host "    Installing Azure" -ForegroundColor Magenta
# choco install visualstudio2017-workload-azure -y # Broken ATM - https://github.com/jberezanski/ChocolateyPackages/issues/35
Write-Host "    Installing Data Storage & Processing" -ForegroundColor Magenta
choco install visualstudio2017-workload-data -y
Write-Host "    Installing .NET Desktop" -ForegroundColor Magenta
choco install visualstudio2017-workload-manageddesktop -y
Write-Host "    Installing .NET Core" -ForegroundColor Magenta
choco install visualstudio2017-workload-netcoretools -y
Write-Host "    Installing Web Development" -ForegroundColor Magenta
choco install visualstudio2017-workload-netweb -y

#SQL Server Management Studio
Write-Host "Install SQL Server Management Studio" -ForegroundColor Green
choco install sql-server-management-studio -y

# Visual Studio Code
Write-Host "Installing Visual Studio Code" -ForegroundColor Green
choco install visualstudiocode -y --params '"/NoDesktopIcon /NoContextMenuFiles /NoContextMenuFolders"'
Update-SessionEnvironment

Write-Host "    Installing C# Extension" -ForegroundColor Magenta
code --install-extension ms-vscode.csharp | Out-Null
Write-Host "    Installing PowerShell Extension" -ForegroundColor Magenta
code --install-extension ms-vscode.PowerShell | Out-Null
Write-Host "    Installing Chrome Debugger Extension" -ForegroundColor Magenta
code --install-extension msjsdiag.debugger-for-chrome | Out-Null
Write-Host "    Installing Angular Extension" -ForegroundColor Magenta
code --install-extension johnpapa.Angular2 | Out-Null
Write-Host "    Installing Docker Extension" -ForegroundColor Magenta
code --install-extension PeterJausovec.vscode-docker | Out-Null
Write-Host "    Installing Git Lens Extension" -ForegroundColor Magenta
code --install-extension eamodio.gitlens | Out-Null
Write-Host "    Installing Spell Checker Extension" -ForegroundColor Magenta
code --install-extension streetsidesoftware.code-spell-checker | Out-Null
Write-Host "    Installing VSTS Extension" -ForegroundColor Magenta
code --install-extension ms-vsts.team | Out-Null
Write-Host "    Installing SQL Extension" -ForegroundColor Magenta
code --install-extension ms-mssql.mssql | Out-Null
Write-Host "    Installing Azure Account Extension" -ForegroundColor Magenta
code --install-extension ms-vscode.azure-account | Out-Null
Write-Host "    Installing Docker Extension" -ForegroundColor Magenta
code --install-extension PeterJausovec.vscode-docker | Out-Null
Write-Host "    Installing Angular Template" -ForegroundColor Magenta
code --install-extension Angular.ng-template | Out-Null
Write-Host "    Installing Material Icon Theme" -ForegroundColor Magenta
code --install-extension PKief.material-icon-theme | Out-Null
Write-Host "    Installing YAML Extension" -ForegroundColor Magenta
code --install-extension redhat.vscode-yaml | Out-Null
Write-Host "    Installing TSLint Extension" -ForegroundColor Magenta
code --install-extension eg2.tslint | Out-Null
Write-Host "    Installing Azure Resource Manager Tools" -ForegroundColor Magenta
code --install-extension msazurermtools.azurerm-vscode-tools | Out-Null

#Office 365
Write-Host "Installing Office 365" -ForegroundColor Green
choco install office365proplus -y

#Various Apps
Write-Host "Installing Various Apps" -ForegroundColor Green

Write-Host "    Git" -ForegroundColor Magenta
choco install git.install -y --params '/NoShellIntegration'
Write-Host "    Telnet" -ForegroundColor Magenta
choco install TelnetClient -source windowsFeatures
Write-Host "    Adobe Acrobat Reader" -ForegroundColor Magenta
choco install adobereader -y
Write-Host "    Node.js" -ForegroundColor Magenta
choco install nodejs.install -y
Write-Host "    Google Chrome" -ForegroundColor Magenta
choco install googlechrome -y
Write-Host "    Sysinternals" -ForegroundColor Magenta
choco install sysinternals -y
Write-Host "    Notepad++" -ForegroundColor Magenta
choco install notepadplusplus -y
Write-Host "    7-Zip" -ForegroundColor Magenta
choco install 7zip.install -y
Write-Host "    VLC" -ForegroundColor Magenta
choco install vlc -y
Write-Host "    Cmder Mini" -ForegroundColor Magenta
choco install cmdermini -y 
Write-Host "    CCleaner" -ForegroundColor Magenta
choco install CCleaner -y
Write-Host "    Paint.net" -ForegroundColor Magenta
choco install paint.net -y
Write-Host "    WinMerge" -ForegroundColor Magenta
choco install winmerge  -y
Write-Host "    Microsoft Teams" -ForegroundColor Magenta
choco install microsoft-teams -y
Write-Host "    Slack" -ForegroundColor Magenta
choco install slack -y
Write-Host "    Remote Desktop Manager" -ForegroundColor Magenta
choco install rdcman -y
Write-Host "    Steam" -ForegroundColor Magenta
choco install steam -y
Write-Host "    ReSharper" -ForegroundColor Magenta
choco install resharper -y
Write-Host "    DotPeek" -ForegroundColor Magenta
choco install dotpeek -y
Write-Host "    Fiddler" -ForegroundColor Magenta
choco install fiddler -y
Write-Host "    FileZilla" -ForegroundColor Magenta
choco install filezilla -y
Write-Host "    MarkdownPad2" -ForegroundColor Magenta
choco install markdownpad2 -y
Write-Host "    TeamViewer" -ForegroundColor Magenta
choco install teamviewer -y

Update-SessionEnvironment

#####################################################################################################################################################################################################
#                                                   REMOVING PREINSTALLED APPS
#####################################################################################################################################################################################################
Write-Host "Removing Preinstalled Windows Apps" -ForegroundColor Green

$ApplicationList = "Microsoft.BingFinance",
"Microsoft.BingNews",
"Microsoft.BingSports",
"Microsoft.BingWeather",
"Microsoft.FreshPaint",
"Microsoft.Getstarted",
"Microsoft.MSPaint",
"Microsoft.WindowsSoundRecorder",
"Microsoft.Microsoft3DViewer",
"Microsoft.MicrosoftOfficeHub",
"Microsoft.MicrosoftSolitaireCollection",
"Microsoft.MicrosoftStickyNotes"        ,
"Microsoft.WindowsFeedbackHub",
"Microsoft.OneConnect",
"Microsoft.SkypeApp",
"Microsoft.WindowsAlarms",
"Microsoft.WindowsCamera",
"Microsoft.WindowsMaps",
"Microsoft.WindowsPhone",
"Microsoft.ZuneVideo",
"Microsoft.MinecraftUWP",
"Microsoft.MicrosoftPowerBIForWindows",
"Microsoft.NetworkSpeedTest",
"Microsoft.CommsPhone",
"Microsoft.ConnectivityStore",
"Microsoft.Messaging",
"Microsoft.Office.Sway",
"Microsoft.OneConnect",
"Microsoft.BingFoodAndDrink",
"Microsoft.BingTravel",
"Microsoft.BingHealthAndFitness",
"Microsoft.WindowsReadingList",
"9E2F88E3.Twitter",
"PandoraMediaInc.29680B314EFC2",
"Flipboard.Flipboard",
"ShazamEntertainmentLtd.Shazam",
"king.com.CandyCrushSaga",
"king.com.CandyCrushSodaSaga",
"king.com.*",
"ClearChannelRadioDigital.iHeartRadio",
"4DF9E0F8.Netflix",
"6Wunderkinder.Wunderlist",
"Drawboard.DrawboardPDF",
"2FE3CB00.PicsArt-PhotoStudio",
"D52A8D61.FarmVille2CountryEscape",
"TuneIn.TuneInRadio",
"GAMELOFTSA.Asphalt8Airborne",
"TheNewYorkTimes.NYTCrossword",
"DB6EA5DB.CyberLinkMediaSuiteEssentials",
"Facebook.Facebook",
"flaregamesGmbH.RoyalRevolt2",
"Playtika.CaesarsSlotsFreeCasino",
"A278AB0D.MarchofEmpires",
"KeeperSecurityInc.Keeper",
"ThumbmunkeysLtd.PhototasticCollage",
"XINGAG.XING",
"89006A2E.AutodeskSketchBook",
"D5EA27B7.Duolingo-LearnLanguagesforFree",
"46928bounde.EclipseManager",
"ActiproSoftwareLLC.562882FEEB491",
"DolbyLaboratories.DolbyAccess",
"SpotifyAB.SpotifyMusic",
"A278AB0D.DisneyMagicKingdoms",
"WinZipComputing.WinZipUniversal",
"BethesdaSoftworks.FalloutShelter",
"PandoraMediaInc.29680B314EFC2",
"AdobeSystemIncorporated.AdobePhotoshop",
"Microsoft.Print3D",
"Microsoft.GetHelp",
"king.com.BubbleWitch3Saga"

ForEach ($CurrentAppName in $ApplicationList) {

    Write-Host "    Removing $CurrentAppName" -ForegroundColor Magenta
    
    $PackageFullName = (Get-AppxPackage $CurrentAppName).PackageFullName
    $ProPackageFullName = (Get-AppxProvisionedPackage -online | Where-Object {$_.Displayname -eq $CurrentAppName}).PackageName

    if ($PackageFullName) {
        Remove-AppxPackage -Package $PackageFullName | Out-Null
    }

    if ($ProPackageFullName) {        
        Remove-AppxProvisionedPackage -Online -PackageName $ProPackageFullName | Out-Null
    }
}


#####################################################################################################################################################################################################
#                                                   DOWNLOAD REMOTE FILES
#####################################################################################################################################################################################################
Write-Host "Downloading Remote Files" -ForegroundColor Green

New-Item (Join-Path -Path $env:UserProfile -ChildPath "\.gitconfig") -Type File -Value ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mauro-dasilva/MachineSetup/master/Windows/Configs/Git/.gitconfig')) -Force | Out-Null
New-Item (Join-Path -Path $env:ChocolateyToolsLocation -ChildPath "\cmdermini\vendor\conemu-maximus5\ConEmu.xml") -Type File -Value ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mauro-dasilva/MachineSetup/master/Windows/Configs/Cmder/ConEmu.xml')) -Force | Out-Null
New-Item (Join-Path -Path $env:UserProfile -ChildPath "\AppData\Roaming\Code\User\keybindings.json") -Type File -Value ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mauro-dasilva/MachineSetup/master/Windows/Configs/VSCode/keybindings.json')) -Force | Out-Null
New-Item (Join-Path -Path $env:UserProfile -ChildPath "\AppData\Roaming\Code\User\settings.json") -Type File -Value ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mauro-dasilva/MachineSetup/master/Windows/Configs/VSCode/settings.json')) -Force | Out-Null

#####################################################################################################################################################################################################
#                                                   WINDOWS PREFERENCES
#####################################################################################################################################################################################################
Write-Host "Setting Windows Preferences" -ForegroundColor Green    

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null

# Disable Outlook Notifications
New-Item "HKCU:\Software\Microsoft\Office\$OfficeVersion.0\Outlook\Preferences" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$OfficeVersion.0\Outlook\Preferences" -Name "ChangePointer" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$OfficeVersion.0\Outlook\Preferences" -Name "NewmailDesktopAlerts" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$OfficeVersion.0\Outlook\Preferences" -Name "PlaySound" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$OfficeVersion.0\Outlook\Preferences" -Name "ShowEnvelope" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Show Hidden Files
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Hide File Extensions
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Navigation Pane Shows The Current Folder
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Remove Suggested Apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Enable Do Not Track on Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Disable Ads in Windows Explorer
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications"  -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Show Cortana Circle
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Enable Lock Screen Spotlight
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Hide Task View Button
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Sticky Keys Prompt
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" "506" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" "122" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" "58" -ErrorAction SilentlyContinue

# Show All Icons in Tray
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Windows Explorer Default to My Computer
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Enable P2P Downloads over LAN only
New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -ErrorAction SilentlyContinue | Out-Null
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3 -ErrorAction SilentlyContinue

# Automatically Pick a Colour from your Background for your Theme Colour
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoColorization" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Hide Recycle Bin on Desktop
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Use Light Theme By Default
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Disable Windows Ink Workspace
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable App Suggestions & Tips
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Enable Driver Updates through Windows Update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    
# Disable Auto Play
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1 -ErrorAction SilentlyContinue

#Show Details when Copying Files
New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Use Large Taskbar Icons
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -ErrorAction SilentlyContinue

# Hiding Recent Shortcuts
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Hiding Desktop Icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue

# Hiding Downloads Icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue

# Hiding Music Icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue

# Hiding Pictures Icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue

# Hiding Videos Icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue

# Hiding 3D Objects Icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

# Disabling creation of Thumbs.db
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Hiding Titles in Taskbar
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue

# Turn off Checkboxes in Windows Explorer
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 0 -ErrorAction SilentlyContinue 

# Hide the My People Icon in the Taskbar
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer\" -Name "HidePeopleBar" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Enabling NumLock After Startup
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650 -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
    $ScriptShell = New-Object -ComObject WScript.Shell
    $ScriptShell.SendKeys('{NUMLOCK}') 
}

# Disabling Search for App in Store for Unknown Extensions
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Enabling Driver Updates through Windows Update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue

# Enable Remote Desktop
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction SilentlyContinue

# Allow Trusted Apps (Needed for Linux Subsystem)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Remove "Include in Library" From Context Menu   
Remove-Item "HKLM:\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -Recurse -ErrorAction SilentlyContinue

# Remove "Pin to Quick Access" From Context Menu   
Remove-Item "HKLM:\SOFTWARE\Classes\Folder\shell\pintohome" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Folder\shell\pintohome" -Recurse -ErrorAction SilentlyContinue

# Remove "Quick Access" from File Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Remove "New Contact" From Context Menu   
Remove-Item "HKCR:\.contact\ShellNew" -Recurse -ErrorAction SilentlyContinue

# Remove "Intel Graphics" From Context Menu   
Remove-Item "HKCR:\Directory\Background\shellex\ContextMenuHandlers\igfxcui" -Recurse -ErrorAction SilentlyContinue

# Remove "New Journal" From Context Menu   
Remove-Item "HKCR:\.jnt\jntfile\ShellNew" -Recurse -ErrorAction SilentlyContinue

# Remove "New Rich Text Document" From Context Menu   
Remove-Item "HKCR:\.rtf\ShellNew" -Recurse -ErrorAction SilentlyContinue

# Remove "New Compressed Folder" From Context Menu   
Remove-Item "HKCR:\.zip\CompressedFolder\ShellNew" -Recurse -ErrorAction SilentlyContinue

# Remove "New Bitmap Image" From Context Menu   
Remove-Item "HKCR:\.bmp\ShellNew" -Recurse -ErrorAction SilentlyContinue
    
# Remove "Modern Share" From Context Menu   
Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -Recurse -ErrorAction SilentlyContinue

# Remove "New Word Document" From Context Menu   
Remove-Item "HKCR:\.docx\Word.Document.12\ShellNew" -Recurse -ErrorAction SilentlyContinue

# Remove "New Excel Document" From Context Menu   
Remove-Item "HKCR:\.xlsx\Excel.Sheet.12\ShellNew" -Recurse -ErrorAction SilentlyContinue

# Remove "New Publisher Document" From Context Menu   
Remove-Item "HKCR:\.pub\Publisher.Document.16\ShellNew" -Recurse -ErrorAction SilentlyContinue

# Remove "New Access Document" From Context Menu   
Remove-Item "HKCR:\.accdb\Access.Application.16\ShellNew" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\.mdb\ShellNew" -Recurse -ErrorAction SilentlyContinue

# Remove "New Powerpoint Document" From Context Menu   
Remove-Item "HKCR:\.pptx\PowerPoint.Show.12\ShellNew" -Recurse -ErrorAction SilentlyContinue

# Remove "New Shortcut" From Context Menu   
Remove-Item "HKCR:\.lnk\ShellNew" -Recurse -ErrorAction SilentlyContinue
        
# Remove "Open in Visual Studio" From Context Menu   
Remove-Item "HKCR:\Directory\Background\shell\AnyCode" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\shell\AnyCode" -Recurse -ErrorAction SilentlyContinue

# Remove "Scan with Windows Defender" From Context Menu   
Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\EPP" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\shellex\ContextMenuHandlers\EPP" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Drive\shellex\ContextMenuHandlers\EPP" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780" -Recurse -ErrorAction SilentlyContinue

# Remove "Set as Backgroud Wallpaper" From Context Menu   
Remove-Item "HKCR:\SystemFileAssociations\.bmp\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.dib\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.gif\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jfif\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jpe\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jpeg\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jpg\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.png\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.tif\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.tiff\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.wdp\Shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue

# Remove "Shared Folder Synchronization" From Context Menu   
Remove-Item "HKCR:\CLSID\{6C467336-8281-4E60-8204-430CED96822D}" -Recurse -ErrorAction SilentlyContinue

# Remove "Restore Previous Versions" From Context Menu   
Remove-Item "HKCR:\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Drive\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" -Recurse -ErrorAction SilentlyContinue

# Remove "Add to VLC media player's Playlist" From Context Menu  
Get-Item -Path HKCR:\VLC.*\shell\AddToPlaylistVLC  | Remove-Item -Recurse -ErrorAction SilentlyContinue
Get-Item -Path HKCR:\VLC.*\shell\PlayWithVLC  | Remove-Item -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\shell\AddtoPlaylistVLC" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\shell\PlayWithVLC" -Recurse -ErrorAction SilentlyContinue

# Remove "Git Gui Here & Git Bash Here" From Context Menu  
Remove-Item "HKCR:\Directory\shell\git_gui" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\shell\git_shell" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\Background\shell\git_gui" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\Background\shell\git_shell" -Recurse -ErrorAction SilentlyContinue

# Remove "Open with VS Code" From Context Menu  
Remove-Item "HKCR:\Directory\shell\VSCode" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\Background\shell\VSCode" -Recurse -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "HKCR:\*\shell\VSCode" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Drive\shell\VSCode" -Recurse -ErrorAction SilentlyContinue

# Remove "Windows Media Player" From Context Menu  
Remove-Item "HKCR:\Directory\shell\VSCode" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\Background\shell\VSCode" -Recurse -ErrorAction SilentlyContinue

# Remove "Edit with Paint 3D" From Context Menu  
Remove-Item "HKCR:\SystemFileAssociations\.3mf\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.bmp\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.fbx\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.gif\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.glb\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jfif\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jpe\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jpeg\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jpg\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.obj\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.ply\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.png\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.stl\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.tif\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.tiff\shell\3D Edit" -Recurse -ErrorAction SilentlyContinue

# Remove "Set as Wallpaper" From Context Menu  
Remove-Item "HKCR:\SystemFileAssociations\.bmp\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.dib\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.gif\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jfif\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jpe\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jpeg\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.jpg\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.png\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.tif\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.tiff\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.wdp\shell\setdesktopwallpaper" -Recurse -ErrorAction SilentlyContinue

# Remove "3D Print" From Context Menu
Remove-Item "HKCR:\SystemFileAssociations\.3ds\shell\3D Print" -Recurse -ErrorAction SilentlyContinue	
Remove-Item "HKCR:\SystemFileAssociations\.3mf\shell\3D Print" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.dae\shell\3D Print" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.dxf\shell\3D Print" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.obj\shell\3D Print" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.ply\shell\3D Print" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.stl\shell\3D Print" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\SystemFileAssociations\.wrl\shell\3D Print" -Recurse -ErrorAction SilentlyContinue

# Remove "DiffMerge" From Context Menu
Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\SourceGearDiffMergeShellExtension32" -Recurse -ErrorAction SilentlyContinue 
Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\SourceGearDiffMergeShellExtension64" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\shellex\ContextMenuHandlers\SourceGearDiffMergeShellExtension32" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Directory\shellex\ContextMenuHandlers\SourceGearDiffMergeShellExtension64" -Recurse -ErrorAction SilentlyContinue
        
# Remove "Send To" Links
Remove-Item "${env:APPDATA}\Microsoft\Windows\SendTo\Bluetooth File Transfer.LNK" -ErrorAction SilentlyContinue
Remove-Item "${env:APPDATA}\Microsoft\Windows\SendTo\Desktop (create shortcut).DeskLink" -ErrorAction SilentlyContinue
Remove-Item "${env:APPDATA}\Microsoft\Windows\SendTo\Documents.mydocs" -ErrorAction SilentlyContinue
Remove-Item "${env:APPDATA}\Microsoft\Windows\SendTo\Mail Recipient.MAPIMail" -ErrorAction SilentlyContinue
Remove-Item "${env:APPDATA}\Microsoft\Windows\SendTo\Fax recipient.lnk" -ErrorAction SilentlyContinue

Remove-PSDrive -Name HKCR | Out-Null
Remove-PSDrive -Name HKU | Out-Null

#####################################################################################################################################################################################################
#                                                  ADD/REMOVE WINDOWS FEATURES
#####################################################################################################################################################################################################
Write-Host "Adding/Removing Windows Features" -ForegroundColor Green

Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName "MediaPlayback" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName "FaxServicesClientPackage" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName "Xps-Foundation-Xps-Viewer" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-InternetPrinting-Client" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -NoRestart -ErrorAction SilentlyContinue | Out-Null

#####################################################################################################################################################################################################
#                                                  KEYBOARD PREFERENCES
#####################################################################################################################################################################################################
Write-Host "Setting up Keyboard Preferences" -ForegroundColor Green

$Languages = Get-WinUserLanguageList
$Languages.Add("en-US")
Set-WinUserLanguageList $Languages -Force

#####################################################################################################################################################################################################
#                                                  MISC SETUP
#####################################################################################################################################################################################################
Write-Host "Misc Setup" -ForegroundColor Green

Write-Host "    Removing Desktop Shortcuts" -ForegroundColor Magenta
Remove-Item "$env:Public\Desktop\*.lnk"
Remove-Item "$env:UserProfile\Desktop\*.lnk"

Write-Host "    Creating Folders" -ForegroundColor Magenta

If (-Not (Test-Path "C:\Personal")) {
    New-Item "C:\Personal" -ItemType Directory | Out-Null
}

If (-Not (Test-Path "C:\Source Code")) {
    New-Item "C:\Source Code" -ItemType Directory | Out-Null
}

#####################################################################################################################################################################################################
#                                                  TASKBAR
#####################################################################################################################################################################################################

# CURRENTLY NOT WORKING IN WINDOWS 10
If ([Environment]::OSVersion.Version.Major -lt 10) {
    Write-Host "Add Shortcuts to Taskbar" -ForegroundColor Green

    $VisualStudioExe = Join-Path -Path ((Get-VSSetupInstance | Select-VSSetupInstance -Latest).InstallationPath) -ChildPath "\Common7\IDE\devenv.exe"

    Remove-Item "${env:APPDATA}\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Recurse | Out-Null
    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse | Out-Null
    Install-ChocolateyPinnedTaskBarItem "$($env:windir)\explorer.exe" | Out-Null
    Install-ChocolateyPinnedTaskBarItem "${env:ProgramFiles(x86)}\Microsoft Office\root\Office$OfficeVersion\Outlook.exe" | Out-Null
    Install-ChocolateyPinnedTaskBarItem "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe" | Out-Null
    Install-ChocolateyPinnedTaskBarItem "$VisualStudioExe" | Out-Null 
    Install-ChocolateyPinnedTaskBarItem "${env:ProgramFiles}\Microsoft VS Code\Code.exe" | Out-Null
    Install-ChocolateyPinnedTaskBarItem "${env:ProgramFiles(x86)}\Microsoft SQL Server\140\Tools\Binn\ManagementStudio\ssms.exe" | Out-Null
    Install-ChocolateyPinnedTaskBarItem "${env:ChocolateyToolsLocation}\cmdermini\cmder.exe" | Out-Null  # See https://github.com/cmderdev/cmder/issues/154#issuecomment-168455895 for workaround on pinning icon
    Install-ChocolateyPinnedTaskBarItem "${env:ProgramFiles(x86)}\Microsoft Office\root\Office$OfficeVersion\Onenote.exe" | Out-Null
    Install-ChocolateyPinnedTaskBarItem "${env:ProgramFiles}\Notepad++\Notepad++.exe" | Out-Null
    Install-ChocolateyPinnedTaskBarItem "${env:ProgramFiles(x86)}\Skype\Phone\Skype.exe" | Out-Null
    Install-ChocolateyPinnedTaskBarItem "${env:UserProfile}\AppData\Local\WhatsApp\WhatsApp.exe" | Out-Null
    Install-ChocolateyPinnedTaskBarItem "${env:UserProfile}\AppData\Local\Microsoft\Teams\current\Teams.exe" | Out-Null
}

#####################################################################################################################################################################################################
#                                                   FILE ASSOCIATION
#####################################################################################################################################################################################################

# CURRENTLY NOT WORKING IN WINDOWS 10
If ([Environment]::OSVersion.Version.Major -lt 10) {
    Write-Host "Setting Up Defaut File Associations" -ForegroundColor Green

    Install-ChocolateyFileAssociation ".txt" "${env:ProgramFiles}\Notepad++\Notepad++.exe" | Out-Null
    Install-ChocolateyFileAssociation ".log" "${env:ProgramFiles}\Notepad++\Notepad++.exe" | Out-Null
    Install-ChocolateyFileAssociation ".xml" "${env:ProgramFiles}\Microsoft VS Code\Code.exe" | Out-Null
    Install-ChocolateyFileAssociation ".cs" "${env:ProgramFiles}\Microsoft VS Code\Code.exe" | Out-Null
    Install-ChocolateyFileAssociation ".ps1" "${env:ProgramFiles}\Microsoft VS Code\Code.exe" | Out-Null
    Install-ChocolateyFileAssociation ".psm1" "${env:ProgramFiles}\Microsoft VS Code\Code.exe" | Out-Null
    Install-ChocolateyFileAssociation ".config" "${env:ProgramFiles}\Microsoft VS Code\Code.exe" | Out-Null
    Install-ChocolateyFileAssociation ".avi" "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe" | Out-Null
    Install-ChocolateyFileAssociation ".mp4" "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe" | Out-Null
    Install-ChocolateyFileAssociation ".mkv" "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe" | Out-Null
}

Stop-Process -ProcessName explorer

#####################################################################################################################################################################################################
#                                                  CONFIGURING STARTUP APPLICATIONS
#####################################################################################################################################################################################################
Write-Host "Configuring Startup Applications" -ForegroundColor Green

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Steam" -ErrorAction SilentlyContinue

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Outlook" -Value "${env:ProgramFiles(x86)}\Microsoft Office\root\Office$OfficeVersion\Outlook.exe" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Chrome" -Value "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WhatsApp" -Value "${env:UserProfile}\AppData\Local\WhatsApp\WhatsApp.exe" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Cmder" -Value "${env:ChocolateyToolsLocation}\cmdermini\cmder.exe" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Notepad++" -Value "${env:ProgramFiles}\Notepad++\Notepad++.exe" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Explorer" -Value "$($env:windir)\explorer.exe" -Force -ErrorAction SilentlyContinue

#####################################################################################################################################################################################################
#                                                   UPDATE WINDOWS
#####################################################################################################################################################################################################
Write-Host "Updating Windows" -ForegroundColor Green

Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false | Out-Null
Get-WUInstall -MicrosoftUpdate -AcceptAll | Out-Null

#####################################################################################################################################################################################################
#                                                   CLEAN UP
#####################################################################################################################################################################################################
Write-Host "Cleaning Up..." -ForegroundColor Green
    
Write-Host "    Temp Folders" -ForegroundColor Magenta
$Tempfolders = @("C:\Windows\Temp\*", "C:\Windows\Prefetch\*", "C:\Documents and Settings\*\Local Settings\Temp\*", "C:\Users\*\Appdata\Local\Temp\*")
Remove-Item $Tempfolders -Force -Recurse -ErrorAction SilentlyContinue | Out-Null

Write-Host "    Scheduling Cleanup Of WinSXS Folder on Next Startup" -ForegroundColor Magenta
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Cleanup WinSXS" -Value "Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase" | Out-Null 

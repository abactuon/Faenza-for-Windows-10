# Check PowerShell is running as Administrator
$Principal = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent())

If (-Not ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Warning "You do not have Administrator rights to run this script.  Please run PowerShell as an Administrator."
    Break
}

If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT"
}

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" 
}

$User_Profile = $env:UserProfile

$IR="C:\Windows\MyIcons"

# Icons
If (!(Test-Path "$IR")) {
	New-Item -Path "$IR" -ItemType Directory
}
Copy-Item "$PSScriptRoot\Pictures\*" -Destination "$IR" -Force


# To Turn Off Thumbnail Previews
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableThumbnails" -Type DWord -Value 1

# Default Folder View -> General
If (!(Test-Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\Shell\Bags\AllFolders\Shell")) {
	New-Item -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\Shell\Bags\AllFolders\Shell" 
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\Shell\Bags\AllFolders\Shell" -Name "FolderType" -Type String -Value "NotSpecified"

# Disable window anim. min/max
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value "0"

# Show This PC shortcut on desktop 
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" 
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" 
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

# This PC Icon
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\DefaultIcon")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\DefaultIcon" 
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\DefaultIcon" -Name "(default)" -Value "$IR\hardinfo.ico,0" -Force

# Hide Libraries in Navigation Pane
If (!(Test-Path "HKCU:\SOFTWARE\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}")) {
	New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" 
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Name "System.IsPinnedToNameSpaceTree" -Type DWORD -Value 0


# USER Icon
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\DefaultIcon")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\DefaultIcon" 
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\DefaultIcon" -Name "(default)" -Value "$IR\user-info.ico,0"

## Hide Folder From Library

# Music_library
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2112AB0A-C86A-4ffe-A368-0DE96E47012E}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2112AB0A-C86A-4ffe-A368-0DE96E47012E}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Saved_Pictures_library
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{E25B5812-BE88-4bd9-94B0-29233477B6C3}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{E25B5812-BE88-4bd9-94B0-29233477B6C3}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Camera_Roll_library
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2B20DF75-1EDA-4039-8097-38798227D5B7}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2B20DF75-1EDA-4039-8097-38798227D5B7}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Documents_library
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7b0db17d-9cd2-4a93-9733-46cc89022e7c}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7b0db17d-9cd2-4a93-9733-46cc89022e7c}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Pictures-library
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A990AE9F-A03B-4e80-94BC-9912D7504104}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A990AE9F-A03B-4e80-94BC-9912D7504104}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Videos-library
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{491E922F-5643-4af4-A7EB-4E7A138D8174}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{491E922F-5643-4af4-A7EB-4E7A138D8174}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Remove Include in library from context menu
Remove-Item -Path "HKCR:\Folder\ShellEx\Library Location" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location" -Recurse -ErrorAction SilentlyContinue

## Hide Folder From "This PC"

# 3D Objects
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" 
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
	New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" 
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"


# Desktop
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Documents
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Downloads
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Music
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Pictures
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Videos
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"

# Change default Explorer view to This PC
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWORD -Value 1


### Desktop.ini with new icon


## Windows folder
$TargetDirectory = "C:\Windows"
$DesktopIni = @"
[.ShellClassInfo]
IconResource=$IR\folder-windows.ico,0
"@

If (Test-Path "$($TargetDirectory)\desktop.ini")  {
  Write-Warning "The desktop.ini file already exists."
}
Else  {
  #Create/Add content to the desktop.ini file
  Add-Content "$($TargetDirectory)\desktop.ini" -Value $DesktopIni
  
  #Set the attributes for $DesktopIni
  (Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'

  #Finally, set the folder's attributes
  (Get-Item $TargetDirectory -Force).Attributes = 'ReadOnly, Directory'
}


## Desktop
$TargetDirectory = "$User_Profile\Desktop"
Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.dt.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'

## AppData no


## Users
$TargetDirectory = "C:\Users"
If (Test-Path "$($TargetDirectory)\desktop.ini")  {
  Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
}
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.u.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'

## Admin
$TargetDirectory = "$User_Profile"
If (Test-Path "$($TargetDirectory)\desktop.ini")  {
  Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
}
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.i.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'

## Contacts
$TargetDirectory = "$User_Profile\Contacts"
Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.c.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'
## Documents
# folder 'Documents' on Disk 'D'
$TargetDirectory = "$User_Profile\Documents"
If (Test-Path "$($TargetDirectory)\desktop.ini")  {
  Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
}
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.doc.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'
## Downloads
$TargetDirectory = "$User_Profile\Downloads"
If (Test-Path "$($TargetDirectory)\desktop.ini")  {
  Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
}
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.dl.txt" -Destination "$User_Profile\Downloads\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'
## Favorites
$TargetDirectory = "$User_Profile\Favorites"
Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.f.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'
## Links
$TargetDirectory = "$User_Profile\Links"
Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.l.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'
## Music
$TargetDirectory = "$User_Profile\Music"
Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.m.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'
## Pictures
$TargetDirectory = "$User_Profile\Pictures"
Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.p.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'
## Saved Games
$TargetDirectory = "$User_Profile\Saved Games"
Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.sg.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'
## Searches
$TargetDirectory = "$User_Profile\Searches"
Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.s.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'
## Videos
$TargetDirectory = "$User_Profile\Videos"
Remove-Item -Path "$TargetDirectory\desktop.ini" -Force
Copy-Item "$PSScriptRoot\DesktopINI\Desktop.ini.v.txt" -Destination "$TargetDirectory\desktop.ini" -Force
(Get-Item "$($TargetDirectory)\desktop.ini" -Force).Attributes = 'Hidden, System, Archive'


# Folder Icon
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /T REG_SZ  /V "3" /D "$IR\folder.ico,0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /T REG_SZ  /V "4" /D "$IR\folder-open.ico,0" /f
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /T REG_SZ  /V "3" /D "$IR\folder.ico,0" /f
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /T REG_SZ  /V "4" /D "$IR\folder-open.ico,0" /f
# Disk Icon
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /T REG_SZ  /V "107" /D "$IR\DiskWindows.ico,0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /T REG_SZ  /V "8" /D "$IR\DiskStandart1.ico,0" /f
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /T REG_SZ  /V "107" /D "$IR\DiskWindows.ico,0" /f
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /T REG_SZ  /V "8" /D "$IR\DiskStandart1.ico,0" /f

#
REG ADD "HKCR\txtfile\DefaultIcon" /ve /d "$IR\text-plain.ico,0" /f
REG ADD "HKCR\.pdf\DefaultIcon" /ve /d "$IR\pdf.ico,0" /f
REG ADD "HKCR\.xlsx\DefaultIcon" /ve /d "$IR\excel.ico,0" /f
REG ADD "HKCR\.zip\DefaultIcon" /ve /d "$IR\zip.ico,0" /f
REG ADD "HKCR\CompressedFolder\DefaultIcon" /ve /d "$IR\zip.ico,0" /f
REG ADD "HKCR\htmlfile\DefaultIcon" /ve /d "$IR\text-html.ico,0" /f
REG ADD "HKCR\Unknown\DefaultIcon" /ve /d "$IR\unknown.ico,0" /f
REG ADD "HKCR\dllfile\DefaultIcon" /ve /d "$IR\application-msdownload.ico,0" /f
REG ADD "HKCR\pngfile\DefaultIcon" /ve /d "$IR\Pictures\image-png,0" /f
REG ADD "HKCR\jpegfile\DefaultIcon" /ve /d "$IR\Pictures\image-jpeg,0" /f
REG ADD "HKCR\Microsoft.PowerShellScript.1\DefaultIcon" /ve /d "$IR\text-source.ico,0" /f
REG ADD "HKCR\MSEdgeHTM\DefaultIcon" /ve /d "$IR\Edge.ico,0" /f
REG ADD "HKCR\batfile\DefaultIcon" /ve /d "$IR\text-script.ico,0" /f
If (!(Test-Path "HKCR:\.torrent")) {
	New-Item -Path "HKCR:\.torrent" -Force
}
REG ADD "HKCR\.torrent\DefaultIcon" /ve /d "$IR\torrent.ico,0" /f

ie4uinit.exe -show

# Restart Explorer
Stop-Process -ProcessName explorer

# Install Theme
Invoke-Expression $PSScriptRoot\Theme2020.deskthemepack

Read-Host -Prompt 'You may need to restart your computer.'
Read-Host -Prompt 'Press any key...'

#restart-computer

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$clsid = '{6E2B7F4A-9C1D-4E8B-9A7F-3D5C1E2B4A60}'
$installDir = Join-Path $env:ProgramFiles 'FamiliarSmartcard'
$dllSource = Join-Path $PSScriptRoot '..\target\release\cred_provider.dll'
$dllDest = Join-Path $installDir 'familiar_cred_provider.dll'

if (-not (Test-Path $dllSource)) {
    throw "Build the DLL first: cargo build --release -p cred-provider"
}

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -Force $dllSource $dllDest

$cpKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
New-Item -Path $cpKey -Force | Out-Null
Set-Item -Path $cpKey -Value 'FamiliarSmartcard'

$inprocKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
New-Item -Path $inprocKey -Force | Out-Null
Set-Item -Path $inprocKey -Value $dllDest
Set-ItemProperty -Path $inprocKey -Name 'ThreadingModel' -Value 'Apartment'

# Restrict the install directory to SYSTEM and Administrators.
$acl = Get-Acl $installDir
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
$system = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$admins = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($system)
$acl.AddAccessRule($admins)
Set-Acl -Path $installDir -AclObject $acl

Write-Host "Registered FamiliarSmartcard Credential Provider:"
Write-Host "  CLSID: $clsid"
Write-Host "  DLL:   $dllDest"
Write-Host "Keep the native password provider enabled as the recovery path."

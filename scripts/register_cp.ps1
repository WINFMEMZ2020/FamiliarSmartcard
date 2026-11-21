#Requires -RunAsAdministrator
param(
    [string]$DllPath = '',
    [string]$HelperPath = ''
)

$ErrorActionPreference = 'Stop'

$clsid = '{6E2B7F4A-9C1D-4E8B-9A7F-3D5C1E2B4A60}'
$installDir = Join-Path $env:ProgramFiles 'FamiliarSmartcard'
$dllDest = Join-Path $installDir 'familiar_cred_provider.dll'
$helperDest = Join-Path $installDir 'familiar-auth-helper.exe'

if ([string]::IsNullOrWhiteSpace($DllPath)) {
    $candidates = @(
        (Join-Path $PSScriptRoot 'cred_provider.dll'),
        (Join-Path $PSScriptRoot '..\target\release\cred_provider.dll')
    )
    $DllPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if ([string]::IsNullOrWhiteSpace($DllPath) -or -not (Test-Path $DllPath)) {
    throw "cred_provider.dll not found. Pass -DllPath or build with: cargo build --release --workspace"
}

if ([string]::IsNullOrWhiteSpace($HelperPath)) {
    $helperCandidates = @(
        (Join-Path $PSScriptRoot 'familiar-auth-helper.exe'),
        (Join-Path $PSScriptRoot '..\target\release\familiar-auth-helper.exe')
    )
    $HelperPath = $helperCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if ([string]::IsNullOrWhiteSpace($HelperPath) -or -not (Test-Path $HelperPath)) {
    throw "familiar-auth-helper.exe not found. Pass -HelperPath or build with: cargo build --release --workspace"
}

$dllSource = (Resolve-Path $DllPath).Path
$helperSource = (Resolve-Path $HelperPath).Path

New-Item -ItemType Directory -Force -Path $installDir | Out-Null

# Restrict the install directory: SYSTEM/Administrators FullControl,
# Users/AppPackages/LocalService ReadAndExecute (matching pure-Rust installer.rs).
$acl = Get-Acl $installDir
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
$system = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$admins = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$users = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'Users', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$localSvc = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'LOCAL SERVICE', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$allAppPkgSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-15-2-1')
$allAppPkg = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $allAppPkgSid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($system)
$acl.AddAccessRule($admins)
$acl.AddAccessRule($users)
$acl.AddAccessRule($localSvc)
$acl.AddAccessRule($allAppPkg)
Set-Acl -Path $installDir -AclObject $acl

function Install-BinaryLive([string]$src, [string]$dst) {
    if ((Test-Path $dst) -and ((Get-FileHash $src).Hash -eq (Get-FileHash $dst).Hash)) {
        return
    }
    try {
        Copy-Item -Force $src $dst -ErrorAction Stop
    } catch {
        $stamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $oldName = "$([System.IO.Path]::GetFileNameWithoutExtension($dst)).old.$stamp"
        Rename-Item -Path $dst -NewName $oldName -Force
        Copy-Item -Force $src $dst -ErrorAction Stop
    }
}

Install-BinaryLive $dllSource $dllDest
Install-BinaryLive $helperSource $helperDest

$cpKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
New-Item -Path $cpKey -Force | Out-Null
Set-Item -Path $cpKey -Value 'FamiliarSmartcard'

$inprocKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
New-Item -Path $inprocKey -Force | Out-Null
Set-Item -Path $inprocKey -Value $dllDest
Set-ItemProperty -Path $inprocKey -Name 'ThreadingModel' -Value 'Apartment'

$vaultRoot = 'HKLM:\SOFTWARE\FamiliarSmartcard'
foreach ($sub in @($vaultRoot, "$vaultRoot\Users", "$vaultRoot\Attestation", "$vaultRoot\Cooldowns")) {
    New-Item -Path $sub -Force | Out-Null
}
$regAcl = Get-Acl $vaultRoot
$regAcl.SetAccessRuleProtection($true, $false)
$regAcl.Access | ForEach-Object { $regAcl.RemoveAccessRule($_) | Out-Null }
$regSys = New-Object System.Security.AccessControl.RegistryAccessRule(
    'SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$regAdm = New-Object System.Security.AccessControl.RegistryAccessRule(
    'Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$regAcl.AddAccessRule($regSys)
$regAcl.AddAccessRule($regAdm)
Set-Acl -Path $vaultRoot -AclObject $regAcl

Write-Host "Familiar Smartcard Credential Provider installed and registered."
Write-Host "  DLL:    $dllDest"
Write-Host "  Helper: $helperDest"
Write-Host "  CLSID:  $clsid"

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$clsid = '{6E2B7F4A-9C1D-4E8B-9A7F-3D5C1E2B4A60}'
$cpKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
$inprocKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"

if (Test-Path $cpKey) {
    Remove-Item -Path $cpKey -Recurse -Force
    Write-Host "Removed Credential Provider registration."
} else {
    Write-Host "Credential Provider registration was not present."
}

# The DLL may still be loaded by LogonUI. Leave InprocServer32 in place unless
# the caller explicitly wants a full cleanup; deleting the provider key is the
# safe rescue path.
if (Test-Path $inprocKey) {
    Write-Host "Left CLSID/InprocServer32 in place to avoid a loaded-DLL delete."
}

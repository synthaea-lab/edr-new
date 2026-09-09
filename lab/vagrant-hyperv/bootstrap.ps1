<#
  One-time host setup for the Hyper-V lab. RUN IN AN ELEVATED PowerShell
  ("Run as Administrator"). Safe to re-run.

    1. Enables the Hyper-V platform + PowerShell module (may need a reboot)
    2. Adds you to "Hyper-V Administrators" (so later `vagrant` runs need only
       elevation, not a group change — log out/in once for it to take effect)
    3. Installs Vagrant if missing
    4. Checks the "Default Switch" (NAT) Vagrant uses for guest networking
#>
$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this from an elevated PowerShell (Run as Administrator)."
}

Write-Host "== 1. Hyper-V feature ==" -ForegroundColor Cyan
$hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($hv.State -ne "Enabled") {
  $r = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
  if ($r.RestartNeeded) { Write-Host "REBOOT REQUIRED, then re-run this script." -ForegroundColor Red; exit 1 }
} else { Write-Host "Already enabled." }

Write-Host "== 2. Hyper-V Administrators group ==" -ForegroundColor Cyan
$grp = (Get-LocalGroup -SID "S-1-5-32-578").Name   # localized-safe
$me  = "$env:USERDOMAIN\$env:USERNAME"
if (-not (Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue | Where-Object Name -eq $me)) {
  Add-LocalGroupMember -Group $grp -Member $env:USERNAME
  Write-Host "Added $me to '$grp'. LOG OUT and back in for it to take effect." -ForegroundColor Yellow
} else { Write-Host "$me already in '$grp'." }

Write-Host "== 3. Vagrant ==" -ForegroundColor Cyan
if (Get-Command vagrant -ErrorAction SilentlyContinue) {
  Write-Host (vagrant --version)
} else {
  winget install --id Hashicorp.Vagrant -e --accept-source-agreements --accept-package-agreements
  Write-Host "Open a new shell so PATH picks up vagrant." -ForegroundColor Yellow
}

Write-Host "== 4. Default Switch ==" -ForegroundColor Cyan
if (Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object Name -eq "Default Switch") {
  Write-Host "'Default Switch' present (NAT)."
} else {
  Write-Host "No 'Default Switch' — normally auto-created by Hyper-V; a reboot after step 1 restores it." -ForegroundColor Yellow
}

Write-Host "`nNext: new elevated shell -> cd here ->" -ForegroundColor Green
Write-Host '  $env:VAGRANT_HYPERV_SWITCH = "Default Switch"' -ForegroundColor Green
Write-Host "  vagrant up ubuntu2204 --provider hyperv" -ForegroundColor Green

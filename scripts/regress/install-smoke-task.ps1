<#
.SYNOPSIS
  One-time setup for tier 4: lets regress.ps1 -Level release run the packaged-EXE smoke test elevated without a UAC
  prompt each time. Run it ONCE from an administrator PowerShell 7. Run it again after smoke.ps1 changes.

.DESCRIPTION
  What it changes on this PC:
  - Creates C:\PCPorterCI, writable only by SYSTEM and Administrators (readable by users), and copies smoke.ps1 into it.
    (The repo is user-writable and synced; the task never runs the repo copy.)
  - Registers the scheduled task "PCPorterSmoke": runs as YOU with highest privileges, only when started on demand
    (no schedule), and only runs C:\PCPorterCI\smoke.ps1.

  Trade-off: any program running as you can start this task, and the task runs the PCPorter build in
  C:\PCPorter-dist (copied into C:\PCPorterCI\run first, with its SHA-256 recorded). On a one-person PC where you are
  already an administrator this adds little risk (UAC is not a security boundary), but remove it if that ever changes:
    .\install-smoke-task.ps1 -Uninstall
#>
#Requires -Version 7
#Requires -RunAsAdministrator
param([switch] $Uninstall)
$ErrorActionPreference = 'Stop'
$TaskName = 'PCPorterSmoke'
$Ci = 'C:\PCPorterCI'

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
    if (Test-Path $Ci) { Remove-Item -LiteralPath $Ci -Recurse -Force }
    Write-Host "Removed the $TaskName task and $Ci."
    return
}

# Administrators-only folder (no inherited permissions, so a normal process cannot change what runs elevated).
New-Item -ItemType Directory -Force $Ci | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
# Users may READ (regress.ps1 checks the installed copy matches the repo) but never change what runs elevated.
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
Set-Acl -LiteralPath $Ci -AclObject $acl
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'smoke.ps1') -Destination (Join-Path $Ci 'smoke.ps1') -Force

$pwsh = (Get-Command pwsh).Source
$action = New-ScheduledTaskAction -Execute $pwsh -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Ci\smoke.ps1`""
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force `
    -Description 'PCPorter tier-4 smoke test (on demand only). Remove with scripts\regress\install-smoke-task.ps1 -Uninstall.' | Out-Null

Write-Host "Installed: task $TaskName (on demand, elevated, runs only $Ci\smoke.ps1)."
Write-Host "smoke.ps1 SHA-256: $((Get-FileHash (Join-Path $Ci 'smoke.ps1')).Hash)"
Write-Host 'Now run (no admin needed):  .\scripts\regress.ps1 -Level release'

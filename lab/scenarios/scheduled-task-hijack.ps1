<#
.SYNOPSIS
    Scheduled-task hijack detection fidelity scenario for T1053.005 (event 4702).

.DESCRIPTION
    Assertion for "an existing scheduled task repointed at a suspicious action
    (event 4702) is detected end-to-end via the eventlog sensor, and a benign
    rewrite is not": `check_scheduled_task_update_persistence` fires iff
    `sensor-windows-eventlog` captured the 4702 and its new action matches the
    rule's hijack patterns.

    Shape, per iteration:
      1. `schtasks.exe /Create` a task pointed at `notepad.exe` -- the legitimate
         task an attacker would later hijack. Fires the 4698 creation rule.
         `/Create` also emits a 4702 of its own (lab, 2026-09-22); its action is
         still `notepad.exe`, so the hijack rule must stay silent on it.
      2. Rewrite the action to another benign System32 binary -- the negative
         control: routine churn, no hijack alert expected.
      3. Rewrite the action to `cmd.exe /c ...` -- the hijack. Expected: one
         hijack alert.
    The rewrites use `Set-ScheduledTask`, not `schtasks /Change /TR`: the
    latter asks for the run-as password even with /IT or /RU, which a scripted
    run cannot answer (lab, fr-FR, 2026-09-25). Both go through the same Task
    Scheduler update, and 4702 is written by the service whichever client
    asks.
    Tasks are set to run at a far-future time and deleted at the end, so no
    action ever executes. No destructive action, no outbound network --
    benign by construction, for detection validation only.

.NOTES
    Usage:
        1) terminal A (as Administrator):
             target\release\agent.exe run
        2) terminal B (as Administrator):
             powershell -ExecutionPolicy Bypass -File lab\scenarios\scheduled-task-hijack.ps1
        3) expected, per iteration, exactly two T1053.005 alerts (the agent
           prints an em dash where this ASCII-only file writes `--`):
             task=SynthaeaHijackTask<N> pid=<id>: scheduled task persistence
               created -- action path: C:\Windows\System32\notepad.exe
             task=SynthaeaHijackTask<N> pid=<id>: existing scheduled task
               repointed (cmd.exe) -- new action path: cmd.exe /c echo synthaea-hijack
           and no alert naming `calc.exe` (the negative control).

    No hijack alert means either:
        - The eventlog sensor's `scheduled-task-update` target is not polling
          (it shares `scheduled_tasks_enabled` with 4698; check the agent's
          `windows-eventlog:scheduled-task-update` heartbeat).
        - The audit subcategory is not enabled (same one as 4698, see
          `scheduled-task-persistence.ps1`).
        - The rule regressed.
    An alert naming `calc.exe` means the pattern gate regressed.

    Prerequisites: run this script AND the agent as Administrator. The
    Security log is not readable without elevation.

.LINK
    ATT&CK T1053.005 -- https://attack.mitre.org/techniques/T1053/005/
#>

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

$Iterations = 2
$TaskNamePrefix = "SynthaeaHijackTask"
$LegitAction = "C:\Windows\System32\notepad.exe"
# Negative control: a routine rewrite to another installed binary, matching
# none of the rule's hijack patterns.
$BenignRewrite = @{ Execute = "C:\Windows\System32\calc.exe" }
# The hijack: a script host, the shape `schtasks /change` produced in the lab
# capture the parser fixture comes from. The sensor renders it as
# "cmd.exe /c echo synthaea-hijack" (Command, space, Arguments).
$HijackAction = @{ Execute = "cmd.exe"; Argument = "/c echo synthaea-hijack" }

function Set-TaskAction {
    param([string]$TaskName, [hashtable]$Action)
    $newAction = New-ScheduledTaskAction @Action
    Set-ScheduledTask -TaskName $TaskName -Action $newAction | Out-Null
}

Write-Host "Creating and hijacking $Iterations scheduled tasks..."
$CreatedTaskNames = @()
try {
    for ($i = 1; $i -le $Iterations; $i++) {
        $taskName = "${TaskNamePrefix}${i}"
        # /SC ONCE /ST 23:59 /SD <far future> : one-shot, never fires in practice.
        # /RL LIMITED : runs under the invoking user, no privilege escalation.
        # /F : overwrite if a stale task from a previous run remains.
        Invoke-Native schtasks.exe @("/Create", "/TN", $taskName, "/TR", $LegitAction,
            "/SC", "ONCE", "/ST", "23:59", "/SD", (Get-FarFutureDate), "/RL", "LIMITED", "/F")
        $CreatedTaskNames += $taskName
        # Spaced out so each 4702 lands in its own poll and the alert order in
        # the agent terminal follows the steps above.
        Start-Sleep -Seconds 3
        Set-TaskAction $taskName $BenignRewrite
        Start-Sleep -Seconds 3
        Set-TaskAction $taskName $HijackAction
        Write-Host "  iteration $i done ($taskName)"
        Start-Sleep -Seconds 3
    }

    Write-Host ""
    Write-Host "Done. Per task, the agent should have logged one creation alert"
    Write-Host "and one hijack alert naming cmd.exe, and nothing for calc.exe."
}
finally {
    Write-Host ""
    Write-Host "Cleanup: deleting scheduled tasks..."
    foreach ($taskName in $CreatedTaskNames) {
        Invoke-NativeCleanup $taskName schtasks.exe @("/Delete", "/TN", $taskName, "/F")
    }
}

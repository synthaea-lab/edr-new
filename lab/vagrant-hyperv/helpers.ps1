<#
  Dot-source this for short forms of the repetitive Hyper-V lab commands
  (the ones spelled out in README.md). RUN FROM AN ELEVATED PowerShell --
  the Hyper-V provider needs elevation for every command that touches a VM.

    cd lab\vagrant-hyperv
    . .\helpers.ps1              # dot-source (note the leading dot + space)
    vprep                        # wsl --shutdown + check rsync + set the switch
    vup                          # up + provision the primary box (ubuntu2204)
    vbuild                       # cargo build --release -p agent, in the VM
    vscen beacon T1071           # run agent + a scenario, grep the alert
    vreset                       # destroy -f + up  (clean rollback)

  First-run host setup is still .\bootstrap.ps1 (Hyper-V feature, group,
  Vagrant, Default Switch) -- run that once, not every session.

  Every function takes an optional machine name; it defaults to $LabMachine
  ("ubuntu2204"). Set $LabMachine = "debian12" to switch the default.
#>

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Warning "Not elevated -- vagrant up/ssh/halt/destroy will fail. Re-open PowerShell as Administrator."
}

# Meant to skip the interactive switch prompt on `vagrant up`. Note: with two
# switches present ("Default Switch" + "WSL (Hyper-V firewall)") Vagrant 2.4.9
# still prints the menu -- just answer 1. Setting it does no harm.
$env:VAGRANT_HYPERV_SWITCH = "Default Switch"

# Default target machine for every helper below.
$LabMachine = "ubuntu2204"

function Get-LabMachine([string]$Name) {
  if ($Name) { return $Name }
  return $LabMachine
}

function vprep {
  <#
    Per-session prep before `vup`, in order:
      1. wsl --shutdown  -- the boxes ask for 4 GB; reclaim it from WSL first
      2. check an rsync is on PATH (Vagrant needs one for the synced folder --
         Git for Windows ships one, or `choco install rsync` / `winget install cwRsync`)
      3. (re)assert the switch env var
  #>
  Write-Host "wsl --shutdown" -ForegroundColor Cyan
  wsl --shutdown
  $rsync = (Get-Command rsync -ErrorAction SilentlyContinue).Source
  if ($rsync) {
    Write-Host "rsync: $rsync" -ForegroundColor Green
  } else {
    Write-Warning "no rsync on PATH -- `vagrant up` will fail to sync the repo. Install cwRsync or Git-for-Windows rsync."
  }
  $env:VAGRANT_HYPERV_SWITCH = "Default Switch"
  Write-Host "VAGRANT_HYPERV_SWITCH = $env:VAGRANT_HYPERV_SWITCH" -ForegroundColor Green

  # The VM boots at 1 GB (Dynamic Memory, see Vagrantfile). Under ~1.5 GB free,
  # `vagrant up` dies with 0x800705AA -- warn before the 30 s import + failure.
  $freeMB = [int]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)
  if ($freeMB -lt 1536) {
    Write-Warning "only ${freeMB} MB RAM free -- close a browser/IDE before `vup` (Hyper-V needs ~1 GB to start the VM)."
  } else {
    Write-Host "RAM free: ${freeMB} MB" -ForegroundColor Green
  }
}

function vup {
  <# Bring the machine up (creates + provisions on first run). #>
  param([string]$Machine)
  $m = Get-LabMachine $Machine
  Write-Host "vagrant up $m --provider hyperv" -ForegroundColor Cyan
  vagrant up $m --provider hyperv
}

function vsync {
  <# Re-push the repo root to /synthaea after host-side edits (one-way rsync). #>
  param([string]$Machine)
  $m = Get-LabMachine $Machine
  vagrant rsync $m
}

function Invoke-LabRemote {
  <#
    Run a bash snippet in the guest. The snippet is base64'd and decoded inside
    the VM so it survives untouched through PowerShell's native-arg parser,
    vagrant, and ssh -- otherwise embedded quotes / `$(...)` / leading-dash
    tokens (`curl -fSL ...`) get mangled and vagrant rejects them as options.
    ~/.cargo/env is sourced first; the snippet sets its own `set -e` if it wants
    fail-fast (vbuild does, vscen deliberately does not).
  #>
  param([string]$Machine, [string]$Script)
  $m = Get-LabMachine $Machine
  $full = "source ~/.cargo/env 2>/dev/null || true`n" + $Script
  $b64  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($full))
  vagrant ssh $m -c "echo $b64 | base64 -d | bash"
}

function vssh {
  <# Interactive shell, or `vssh ubuntu2204 'cmd; cmd'` to run a bash snippet. #>
  param([string]$Machine, [string]$Command)
  $m = Get-LabMachine $Machine
  if ($Command) { Invoke-LabRemote $m $Command } else { vagrant ssh $m }
}

function vhalt {
  param([string]$Machine)
  vagrant halt (Get-LabMachine $Machine)
}

function vreset {
  <# Clean rollback: destroy the VM and bring a fresh one up + provisioned. #>
  param([string]$Machine)
  $m = Get-LabMachine $Machine
  Write-Host "vagrant destroy -f $m  &&  vagrant up $m" -ForegroundColor Yellow
  vagrant destroy -f $m
  vagrant up $m --provider hyperv
}

function vbuild {
  <#
    Release build of the agent inside the VM. Fails fast if bpf-linker is not on
    PATH -- without it the build silently omits the eBPF probes and the agent
    errors at runtime ("built without embedded eBPF probes").
  #>
  param([string]$Machine)
  Invoke-LabRemote (Get-LabMachine $Machine) @'
set -e
command -v bpf-linker >/dev/null || { echo "bpf-linker NOT on PATH -- run: vagrant provision" >&2; exit 1; }
cd /synthaea && cargo build --release -p agent
'@
}

function vstatus {
  <# Verifier check: loads all sensor programs and reports (needs a prior vbuild). #>
  param([string]$Machine)
  Invoke-LabRemote (Get-LabMachine $Machine) 'cd /synthaea && sudo ./target/release/agent status'
}

function vscen {
  <#
    Run the agent, fire one scenario, grep the alert file, then stop the agent.
      vscen beacon T1071
      vscen dns-exfil T1048 debian12
    Scenario name maps to lab/scenarios/<name>.sh.
  #>
  param(
    [Parameter(Mandatory)][string]$Scenario,
    [string]$Grep = "",
    [string]$Machine
  )
  $m = Get-LabMachine $Machine
  $grepStep = if ($Grep) { "grep $Grep /tmp/a || echo '(no match for $Grep)'" } else { "cat /tmp/a" }
  Invoke-LabRemote $m @"
cd /synthaea
sudo env RUST_LOG=sensor_linux=info ./target/release/agent run --alerts /tmp/a --events /tmp/e &
sleep 4
bash lab/scenarios/$Scenario.sh
sleep 2
sudo pkill -f 'agent run' || true
$grepStep
"@
}

Write-Host "lab helpers loaded: vprep vup vsync vssh vhalt vreset vbuild vstatus vscen  (default machine: $LabMachine)" -ForegroundColor Green

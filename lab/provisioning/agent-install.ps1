<#
.SYNOPSIS
    Installs an already-built agent (+ watchdog, + rules content) into a lab
    Windows VM for scenario runs (#22) — the Windows counterpart of just
    `cargo build`-ing in place on the Linux side (see ../vagrant/README.md):
    a Windows lab machine can receive a binary built elsewhere (another VM,
    or a host with the toolchain already set up) instead of provisioning the
    full MSVC/Windows SDK toolchain on every machine that only needs to RUN a
    scenario, not build one.

.DESCRIPTION
    Provider-neutral: takes no harness-specific assumptions about how the
    build output got onto this machine (winrm file copy, a synced folder, a
    manually copied zip) — just a source to copy from. Idempotent: re-running
    with the same arguments overwrites in place; -InstallService safely
    replaces an already-installed service rather than erroring on it.

.PARAMETER SourceDir
    A directory containing the build output: agent.exe, watchdog.exe, and
    optionally the rules/sigma and rules/yara content directories (as
    produced by `cargo build --release` — i.e. a target/release/ directory,
    or a staging directory assembled from one).

.PARAMETER AgentZip
    Alternative to -SourceDir: a zip archive with the same contents, expanded
    into a temporary directory before installing. Exactly one of -SourceDir /
    -AgentZip must be given.

.PARAMETER InstallDir
    Where the agent is installed on this machine. Default: C:\Synthaea.

.PARAMETER InstallService
    Also registers the watchdog as a Windows service (`watchdog.exe install`)
    so the agent runs under supervision and survives a reboot — the same
    kill-resistance setup a production endpoint gets. Without this switch,
    the binaries are staged but nothing is started: useful when a scenario
    script drives `agent.exe run` directly and wants to read its own
    alerts/events files without a background service also writing to them.

.EXAMPLE
    .\agent-install.ps1 -SourceDir \\build-host\out\release -InstallService
#>

[CmdletBinding()]
param(
    # Plain optional params rather than two parameter sets: PowerShell's own
    # parameter-set-resolution error for "neither given" is opaque ("cannot
    # be resolved using the specified named parameters"); the explicit check
    # below gives a clearer message instead.
    [string]$SourceDir,

    [string]$AgentZip,

    [string]$InstallDir = "C:\Synthaea",

    [switch]$InstallService
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

if ([bool]$SourceDir -eq [bool]$AgentZip) {
    throw "Specify exactly one of -SourceDir or -AgentZip"
}

# ── Resolve the source ──────────────────────────────────────────────────────
Write-Section "Resolving build output"

if ($AgentZip) {
    if (-not (Test-Path $AgentZip)) {
        throw "AgentZip not found: $AgentZip"
    }
    $extractDir = Join-Path $env:TEMP ("synthaea-agent-install-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $extractDir | Out-Null
    Write-Host "[info] expanding $AgentZip -> $extractDir"
    Expand-Archive -Path $AgentZip -DestinationPath $extractDir -Force
    $SourceDir = $extractDir
}

$SourceDir = (Resolve-Path $SourceDir).Path
Write-Host "[ok] source: $SourceDir"

$agentSrc = Join-Path $SourceDir "agent.exe"
$watchdogSrc = Join-Path $SourceDir "watchdog.exe"
foreach ($required in @($agentSrc, $watchdogSrc)) {
    if (-not (Test-Path $required)) {
        throw "missing $required — SourceDir must contain a release build of both agent and watchdog"
    }
}

# ── Stop any previous install first ─────────────────────────────────────────
# Overwriting a running agent.exe/watchdog.exe in place fails (the file is
# locked) — idempotent re-installs must tear the old one down first, exactly
# what a fresh install also needs to be safe to run twice.
Write-Section "Stopping any existing install"

$watchdogDst = Join-Path $InstallDir "watchdog.exe"
if (Test-Path $watchdogDst) {
    # Best-effort: fine if no service was ever installed (plain binary-only
    # staging from a previous run without -InstallService).
    & $watchdogDst uninstall 2>$null | Out-Null
    Write-Host "[ok] removed any previously installed service"
}
Get-Process -Name "agent", "watchdog" -ErrorAction SilentlyContinue | Stop-Process -Force

# ── Copy binaries + content ─────────────────────────────────────────────────
Write-Section "Installing into $InstallDir"

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $agentSrc (Join-Path $InstallDir "agent.exe") -Force
Copy-Item $watchdogSrc (Join-Path $InstallDir "watchdog.exe") -Force
Write-Host "[ok] agent.exe, watchdog.exe"

# rules/sigma and rules/yara are optional (DetectionSink runs fine without
# either — see agent/src/sink.rs's content_dir doc) — only copied when present
# next to the binaries, mirroring the executable-relative lookup the agent
# itself does at runtime.
foreach ($contentDir in @("rules\sigma", "rules\yara")) {
    $src = Join-Path $SourceDir $contentDir
    if (Test-Path $src) {
        $dst = Join-Path $InstallDir $contentDir
        # Remove any previous copy first: Copy-Item -Recurse onto an
        # already-existing destination directory nests $src *inside* it
        # (…\rules\sigma\sigma\…) instead of replacing it — silently
        # duplicating content on every re-run otherwise.
        if (Test-Path $dst) {
            Remove-Item -Path $dst -Recurse -Force
        }
        New-Item -ItemType Directory -Path (Split-Path $dst -Parent) -Force | Out-Null
        Copy-Item $src $dst -Recurse -Force
        Write-Host "[ok] $contentDir"
    } else {
        Write-Host "[info] $contentDir not present in source — skipped (agent runs without it)"
    }
}

if ($AgentZip) {
    Remove-Item -Path $SourceDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ── Optionally install the watchdog service ─────────────────────────────────
# Computed unconditionally: used below in the final instructions either way
# (as the -InstallService target, or as the direct-run example).
$agentDst = Join-Path $InstallDir "agent.exe"
$alertsPath = Join-Path $InstallDir "alerts.ndjson"
$eventsPath = Join-Path $InstallDir "events.jsonl"

if ($InstallService) {
    Write-Section "Installing the watchdog service"
    & (Join-Path $InstallDir "watchdog.exe") install --alerts $alertsPath
    if ($LASTEXITCODE -ne 0) {
        throw "watchdog.exe install failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host ""
    Write-Host "[info] -InstallService not given — binaries staged, nothing started"
}

Write-Host ""
Write-Host "== Done ==" -ForegroundColor Cyan
Write-Host "Installed into: $InstallDir"
if ($InstallService) {
    Write-Host "Watchdog service running — check: sc query SynthaEDR"
} else {
    Write-Host "Run a scenario directly, e.g.:"
    Write-Host "  $agentDst run --alerts $alertsPath --events $eventsPath"
}

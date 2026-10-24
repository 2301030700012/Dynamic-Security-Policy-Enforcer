param(
    # How often (seconds) the CIM polling query samples firewall profile
    # state. 1-300; default 2 keeps the original responsiveness.
    [int]$PollSeconds = 2
)
if ($PollSeconds -lt 1 -or $PollSeconds -gt 300) { $PollSeconds = 2 }

# Path resolution that also works inside a ps2exe-compiled exe, where
# $PSScriptRoot and $MyInvocation.MyCommand.Path are both empty - fall back
# to the location of the running process (the exe itself).
function Get-DSPEHome {
    if ($PSScriptRoot) { return $PSScriptRoot }
    if ($MyInvocation.MyCommand.Path) { return Split-Path -Parent $MyInvocation.MyCommand.Path }
    $procPath = (Get-Process -Id $PID -ErrorAction SilentlyContinue).Path
    if ($procPath) { return Split-Path -Parent $procPath }
    return (Get-Location).Path
}
$here = Get-DSPEHome
Import-Module (Join-Path $here "Common.psm1") -Force -DisableNameChecking

Ensure-DSPEFolders

if (-not (Test-IsElevated)) {
    Write-Log "Firewall monitoring requires elevation to receive CIM events - some changes may be missed." -Level WARN
}

Write-Log "Dynamic Monitoring Started - Watching Windows Firewall profiles..." -Level INFO
Write-Host "Leave this window open. Press Ctrl+C to stop." -ForegroundColor Cyan

# The CIM action block below runs in its own scope where $PSScriptRoot is
# empty, so capture the module location up front in a global variable the
# action block can always reliably read.
$global:DSPE_CimCommonModule = Join-Path $here "Common.psm1"

Register-CimIndicationEvent -Namespace "root\StandardCimv2" -Query "SELECT * FROM __InstanceModificationEvent WITHIN $PollSeconds WHERE TargetInstance ISA 'MSFT_NetFirewallProfile'" -SourceIdentifier "FirewallProfileWatch" -Action {
    # The action block runs in its own scope where $PSScriptRoot is empty,
    # so re-import the framework using the path captured at registration
    # time ($global:DSPE_CimCommonModule) - the old expression dereferenced
    # $PSScriptRoot inside the action, which is always empty there, so the
    # import failed silently and alerts were never logged.
    $commonPath = $global:DSPE_CimCommonModule
    if ($commonPath -and (Test-Path $commonPath)) {
        Import-Module $commonPath -Force -DisableNameChecking -ErrorAction SilentlyContinue
    }
    $profile = $Event.SourceEventArgs.NewEvent.TargetInstance
    $time = Get-Date -Format "HH:mm:ss"
    if ($profile.Enabled -eq 0) {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ALERT: Firewall profile '$($profile.Name)' was DISABLED" -Level ERROR }
        Write-Host "[$time] ALERT: Firewall profile '$($profile.Name)' was DISABLED!" -ForegroundColor Red
    } else {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "Firewall profile '$($profile.Name)' is back ENABLED" -Level SUCCESS }
        Write-Host "[$time] INFO: Firewall profile '$($profile.Name)' is back ENABLED" -ForegroundColor Green
    }
} | Out-Null

try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
} finally {
    # Ctrl+C or console close: drop the event subscription so the process exits clean.
    Unregister-Event -SourceIdentifier "FirewallProfileWatch" -ErrorAction SilentlyContinue
    Write-Log "Firewall monitoring stopped." -Level INFO
}

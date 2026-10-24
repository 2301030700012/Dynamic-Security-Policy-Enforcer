# Collector: Firewall Check
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
Import-Module (Join-Path $here "..\Common.psm1") -Force -DisableNameChecking

if (-not (Test-IsElevated)) {
    Write-Log "Firewall profile enumeration requires elevation - results may be unreliable." -Level WARN
}

try {
    $firewallStatus = Get-NetFirewallProfile -Profile Domain,Public,Private -ErrorAction Stop
} catch {
    Write-Log "Could not read firewall profiles: $($_.Exception.Message)" -Level ERROR
    exit 2
}

$allEnabled = -not ($firewallStatus.Enabled -contains $false)

if ($allEnabled) {
    Write-Log "All firewall profiles are enabled" -Level SUCCESS
} else {
    $disabled = ($firewallStatus | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name }) -join ", "
    Write-Log "One or more firewall profiles are disabled: $disabled" -Level ERROR
}

$firewallStatus | Format-Table -AutoSize

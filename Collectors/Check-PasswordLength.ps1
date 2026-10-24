# Collector: Minimum Password Length Check
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
    Write-Log "secedit export requires elevation - results may be unreliable." -Level WARN
}

$secpolContent = $null
try {
    $seceditPath = Get-DSPEPath -Which SecpolFile
    secedit /export /cfg $seceditPath | Out-Null
    $secpolContent = Get-Content $seceditPath
} catch {
    Write-Log "secedit export failed: $($_.Exception.Message)" -Level ERROR
    exit 2
}

$minPwdLine = $secpolContent | Select-String "MinimumPasswordLength"
if (-not $minPwdLine) {
    Write-Log "MinimumPasswordLength not found in secedit export." -Level ERROR
    exit 2
}
$minPwdLength = [int](($minPwdLine -split "=", 2)[1].Trim())

Write-Log "Current Minimum Password Length: $minPwdLength" -Level INFO

if ($minPwdLength -ge 14) {
    Write-Log "PASS: Minimum password length meets the 14-character requirement" -Level SUCCESS
    exit 0
} else {
    Write-Log "FAIL: Minimum password length is below 14 characters (currently $minPwdLength)" -Level ERROR
    exit 1
}

param(
    # The dashboard opens in the browser automatically by default; scheduled
    # runs pass -NoOpen so they don't pop a browser window.
    [switch]$NoOpen
)

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
function ConvertTo-HtmlSafe([string]$text) {
    return [System.Net.WebUtility]::HtmlEncode($text)
}
$reportsDir = Get-DSPEPath -Which Reports

# Sort by last write time, not filename, so ordering stays correct even if
# report files are copied in or renamed.
$reportFiles = Get-ChildItem -Path $reportsDir -Filter "ScanReport_*.csv" |
    Sort-Object LastWriteTime

if ($reportFiles.Count -eq 0) {
    Write-Log "No ScanReport_*.csv files found in $reportsDir - run Run-PolicyCheck.ps1 -Scan first." -Level WARN
    exit 1
}

$scanSummary = @()

foreach ($file in $reportFiles) {
    try {
        $data = Import-Csv $file.FullName
    } catch {
        Write-Log "Skipping unreadable report $($file.Name): $($_.Exception.Message)" -Level WARN
        continue
    }
    $total = @($data).Count
    if ($total -eq 0) {
        Write-Log "Skipping empty report $($file.Name)." -Level WARN
        continue
    }
    $passed = ($data | Where-Object { $_.Status -eq "PASS" }).Count
    $percent = [math]::Round(($passed / $total) * 100, 1)

    $scanSummary += [pscustomobject]@{
        ScanFile   = $file.Name
        Total      = $total
        Passed     = $passed
        Compliance = $percent
    }
}

if ($scanSummary.Count -eq 0) {
    Write-Log "Every report file was unreadable or empty - nothing to chart." -Level ERROR
    exit 1
}

# Build bar chart HTML (one bar per scan)
$bars = ""
foreach ($row in $scanSummary) {
    $color = if ($row.Compliance -ge 90) { "#2ecc71" } elseif ($row.Compliance -ge 60) { "#f39c12" } else { "#e74c3c" }
    $bars += "<div class='bar-wrap'><div class='bar' style='height:$($row.Compliance)%; background:$color;' title='$(ConvertTo-HtmlSafe $row.ScanFile)'></div><span class='label'>$($row.Compliance)%</span></div>`n"
}

# Build table rows
$rows = ""
foreach ($row in $scanSummary) {
    $rows += "<tr><td>$(ConvertTo-HtmlSafe $row.ScanFile)</td><td>$($row.Total)</td><td>$($row.Passed)</td><td>$($row.Compliance)%</td></tr>`n"
}

$html = @"
<!DOCTYPE html>
<html>
<head>
<title>DSPE Compliance Dashboard</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; background: #f4f4f4; padding: 30px; }
h1 { color: #7A2330; }
.chart { display: flex; align-items: flex-end; height: 220px; gap: 10px; background: white; padding: 20px; border-radius: 8px; }
.bar-wrap { display: flex; flex-direction: column; align-items: center; justify-content: flex-end; height: 100%; }
.bar { width: 30px; border-radius: 4px 4px 0 0; }
.label { font-size: 11px; margin-top: 4px; }
table { border-collapse: collapse; width: 100%; margin-top: 30px; background: white; }
th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 13px; }
th { background: #7A2330; color: white; }
</style>
</head>
<body>
<h1>Dynamic Security Policy Enforcer — Compliance Dashboard</h1>
<p>Compliance percentage across all scans performed so far.</p>
<div class="chart">
$bars
</div>
<table>
<tr><th>Scan File</th><th>Total Rules</th><th>Passed</th><th>Compliance</th></tr>
$rows
</table>
</body>
</html>
"@

$dashboardPath = Join-Path $reportsDir "Dashboard.html"
$html | Out-File -FilePath $dashboardPath -Encoding UTF8

$latest = $scanSummary | Select-Object -Last 1
Write-Log "Dashboard generated at: $dashboardPath (latest scan: $($latest.Compliance)% compliance, $($latest.Passed)/$($latest.Total) rules)" -Level SUCCESS
if (-not $NoOpen) {
    Start-Process $dashboardPath
}

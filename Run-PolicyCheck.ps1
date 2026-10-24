param(
    [switch]$Scan,
    [switch]$Remediate
)

# ================== Shared framework (paths, logging, elevation, validation) ==================
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

Initialize-EventLogSource
Ensure-DSPEFolders

if (-not $Scan) {
    Write-Log "Usage: Run-PolicyCheck.ps1 -Scan [-Remediate]" -Level WARN
    Write-Log "No action specified. Exiting." -Level WARN
    exit 1
}

# Checks and remediation (secedit, auditpol, net accounts, firewall) all need admin.
if (-not (Assert-Elevated -ScriptPath $PSCommandPath)) {
    Write-Log "Continuing without elevation - checks that require admin will report as failing." -Level WARN
}

try {
    $policy = Import-D_SPEPolicy
} catch {
    Write-Log $_.Exception.Message -Level ERROR
    exit 2
}

$seceditPath = Get-DSPEPath -Which SecpolFile
function Export-Secedit {
    secedit /export /cfg $seceditPath | Out-Null
    return Get-Content $seceditPath
}
$script:seceditLines = Export-Secedit

function Get-SeceditValue($key) {
    $line = $script:seceditLines | Select-String ("^\s*" + [regex]::Escape($key) + "\s*=")
    if ($line) { return ($line -split "=", 2)[1].Trim() }
    return $null
}

function Compare-Value($actual, $expected, $operator, $rule) {
    if ($null -eq $actual -or $actual -eq "NotSet" -or $actual -eq "NotFound" -or $actual -eq "Error") {
        return $false
    }
    try {
        switch ($operator) {
            "eq"       { return ($actual -eq $expected) }
            "gte"      { return ([double]$actual -ge [double]$expected) }
            "lte"      { return ([double]$actual -le [double]$expected) }
            "range"    { return ([double]$actual -ge [double]$rule.min -and [double]$actual -le [double]$rule.max) }
            "contains" {
                $exp = $expected.ToLower()
                $act = $actual.ToLower()
                if ($exp -eq "success and failure") { return ($act -match "success") -and ($act -match "failure") }
                return $act -match [regex]::Escape($exp)
            }
            default    { return ($actual -eq $expected) }
        }
    } catch { return $false }
}

# ---- Single source of truth for "what is the current state of this rule?" ----
# Used both for the initial scan AND to re-verify a rule immediately after a fix.
function Test-Rule($rule) {
    $actualValue = "NotSet"
    $passed = $false

    switch ($rule.check_type) {
        "secedit" {
            $raw = Get-SeceditValue($rule.key)
            if ($null -ne $raw) {
                try { $actualValue = [double]$raw } catch { $actualValue = $raw }
            }
            $passed = Compare-Value $actualValue $rule.expected $rule.operator $rule
        }
        "registry" {
            try {
                $actualValue = (Get-ItemProperty -Path $rule.path -Name $rule.name -ErrorAction Stop).$($rule.name)
                # REG_MULTI_SZ values (e.g. NullSessionPipes) come back as a
                # string[] - join so an empty array compares equal to an
                # "expected": "" rule instead of silently failing the
                # array-vs-string comparison.
                if ($actualValue -is [array]) { $actualValue = $actualValue -join ',' }
            } catch { $actualValue = "NotSet" }
            $passed = Compare-Value $actualValue $rule.expected $rule.operator $rule
        }
        "firewall" {
            $fw = Get-NetFirewallProfile -Profile Domain,Public,Private
            $actualValue = -not ($fw.Enabled -contains $false)
            $passed = ($actualValue -eq $rule.expected)
        }
        "firewall_property" {
            try {
                $prof = Get-NetFirewallProfile -Profile $rule.profile
                $actualValue = $prof.$($rule.property)
                $passed = Compare-Value $actualValue $rule.expected $rule.operator $rule
            } catch { $actualValue = "Error"; $passed = $false }
        }
        "service" {
            $svc = Get-Service -Name $rule.service_name -ErrorAction SilentlyContinue
            if ($svc) {
                $actualValue = $svc.StartType.ToString()
                $passed = ($actualValue -eq $rule.expected)
            } else {
                $actualValue = "NotInstalled"
                $passed = $true
            }
        }
        "auditpol" {
            try {
                $auditResult = & auditpol /get /subcategory:"$($rule.subcategory)" 2>$null
                $line = $auditResult | Where-Object { $_ -match $rule.subcategory }
                if ($line) {
                    $parts = $line -split '\s{2,}'
                    $actualValue = ($parts | Select-Object -Last 1).Trim()
                } else { $actualValue = "NotFound" }
                $passed = Compare-Value $actualValue $rule.expected $rule.operator $rule
            } catch { $actualValue = "Error"; $passed = $false }
        }
    }
    return @{ Actual = $actualValue; Passed = $passed }
}

# ---- Initial scan ----
Write-Log "Starting compliance scan of $($policy.rules.Count) rules." -Level INFO
$results = @()
foreach ($rule in $policy.rules) {
    try {
        $r = Test-Rule $rule
    } catch {
        Write-Log "Rule $($rule.id): check threw an exception - reported as FAIL. $($_.Exception.Message)" -Level WARN
        $r = @{ Actual = "Error"; Passed = $false }
    }
    $results += [pscustomobject]@{
        ID = $rule.id; Description = $rule.description; Category = $rule.category
        CIS_Ref = $rule.cis_ref; Severity = $rule.severity; Expected = $rule.expected
        Actual = $r.Actual; Status = if ($r.Passed) { "PASS" } else { "FAIL" }
    }
}

function Show-Summary($resultSet) {
    $total = @($resultSet).Count
    if ($total -eq 0) {
        Write-Log "No rules to display - policy is empty or the scan produced no results." -Level WARN
        return
    }
    $p = ($resultSet | Where-Object { $_.Status -eq "PASS" }).Count
    $f = $total - $p
    $pct = [math]::Round(($p / $total) * 100, 1)
    Write-Host "`n=== CIS Windows 11 Benchmark v5.0.0 — Compliance Scan ===" -ForegroundColor Cyan
    Write-Host "Total Rules : $total  |  Passed : $p  |  Failed : $f  |  Score : $pct%" -ForegroundColor Cyan
    Write-Host ""
    $categories = $resultSet | Select-Object -ExpandProperty Category -Unique
    foreach ($cat in $categories) {
        Write-Host "--- $cat ---" -ForegroundColor White
        $resultSet | Where-Object { $_.Category -eq $cat } | ForEach-Object {
            $color = if ($_.Status -eq "PASS") { "Green" } else { "Red" }
            Write-Host ("  [{0}] {1,-10} {2,-60} {3}" -f $_.Status, $_.ID, ($_.Description.Substring(0, [Math]::Min(60, $_.Description.Length))), $_.CIS_Ref) -ForegroundColor $color
        }
        Write-Host ""
    }
}

Show-Summary $results

# ---- Remediation ----
$failures = $results | Where-Object { $_.Status -eq "FAIL" }
if ($failures.Count -gt 0) {
    Write-Host "=== Remediation Guidance for Failed Checks ===" -ForegroundColor Yellow
    if ($Remediate) {
        # Snapshot the pre-fix state of every rule that may be touched, so any
        # fix can be rolled back per-rule afterwards.
        try {
            $rulesToFix = $failures | ForEach-Object {
                $failId = $_.ID
                $policy.rules | Where-Object { $_.id -eq $failId }
            }
            Import-Module (Join-Path $here "Backup-Restore.psm1") -Force -DisableNameChecking
            $backupPath = New-DSPESnapshot -Rules $rulesToFix
            if ($backupPath) {
                Write-Log "Pre-remediation backup saved to $backupPath" -Level INFO
                Write-Host "Backup saved to: $backupPath (restore with Restore-DSPESnapshot)" -ForegroundColor Cyan
                Remove-OldDSPESnapshots -Keep 20
            }
        } catch {
            Write-Log "Backup failed: $($_.Exception.Message)" -Level ERROR
            Write-Host "Backup failed - continuing, but rollback will not be available for this run." -ForegroundColor Red
        }
    }
    foreach ($r in $failures) {
        $matchingRule = $policy.rules | Where-Object { $_.id -eq $r.ID }
        Write-Host "`n[$($r.ID)] $($r.Description)" -ForegroundColor Yellow
        Write-Host "  CIS: $($r.CIS_Ref)  |  Severity: $($r.Severity)" -ForegroundColor DarkYellow
        Write-Host "  Fix: $($matchingRule.remediation)" -ForegroundColor DarkYellow

        if ($Remediate) {
            $confirm = Read-Host "  Apply this fix? (Y/N)"
            if ($confirm -eq "Y") {
                # The fix dispatch lives in Common.psm1 (Invoke-DSPESettingFix),
                # shared with the GUI and the restore path - the CLI only
                # applies the fix and re-verifies with its own Test-Rule.
                $fixResult = Invoke-DSPESettingFix -Rule $matchingRule
                if ($matchingRule.check_type -eq "secedit") {
                    # Refresh secedit export so the re-check below sees the new value
                    $script:seceditLines = Export-Secedit
                }
                if ($fixResult.Success) {
                    # Re-verify against the live system — don't just trust the command exited cleanly
                    Start-Sleep -Milliseconds 300
                    try { $recheck = Test-Rule $matchingRule } catch { $recheck = @{ Actual = "Error"; Passed = $false } }
                    if ($recheck.Passed) {
                        Write-Log "Remediation for $($r.ID) applied and verified - now PASS." -Level SUCCESS
                        Write-Host "  Applied and verified — now PASS." -ForegroundColor Green
                        $row = $results | Where-Object { $_.ID -eq $r.ID }
                        $row.Actual = $recheck.Actual
                        $row.Status = "PASS"
                    } else {
                        Write-Host "  Command ran, but the setting still does not match after re-checking (actual: $($recheck.Actual))." -ForegroundColor Red
                    }
                } else {
                    Write-Log "Remediation for $($r.ID) failed: $($fixResult.Reason)" -Level ERROR
                    Write-Host "  Fix failed: $($fixResult.Reason)" -ForegroundColor Red
                }
            } else {
                Write-Host "  Skipped." -ForegroundColor Gray
            }
        }
    }

    if ($Remediate) {
        Write-Host "`n--- Updated results after remediation ---" -ForegroundColor Cyan
        Show-Summary $results
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportsDir = Get-DSPEPath -Which Reports
$reportPath = Join-Path $reportsDir "ScanReport_$timestamp.csv"
$results | Export-Csv -Path $reportPath -NoTypeInformation
Write-Log "Report saved to: $reportPath" -Level SUCCESS

# Machine-readable JSON alongside the CSV, for CI/CD consumption.
$failedCountJson = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
$jsonPath = Join-Path $reportsDir "ScanReport_$timestamp.json"
[pscustomobject]@{
    GeneratedAt       = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    TotalRules        = $results.Count
    Passed            = ($results | Where-Object { $_.Status -eq "PASS" }).Count
    Failed            = $failedCountJson
    CompliancePercent = [math]::Round((($results.Count - $failedCountJson) / $results.Count) * 100, 1)
    Rules             = $results
} | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host "Run Generate-Dashboard.ps1 to update the compliance dashboard." -ForegroundColor Cyan

# Exit code reflects compliance so scheduled tasks / CI can detect failures.
$failedCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
Write-Log "Scan complete: $failedCount of $($results.Count) rules failed." -Level INFO
exit $(if ($failedCount -gt 0) { 1 } else { 0 })
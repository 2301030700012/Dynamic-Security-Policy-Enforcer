# DSPE shared framework: paths, logging, elevation, policy validation.
# Imported by Run-PolicyCheck.ps1, DSPE-GUI.ps1, Generate-Dashboard.ps1 and the
# collectors so path resolution and logging behave identically everywhere.

Set-StrictMode -Version Latest

# ================== Dynamic path resolution ==================
# Everything lives relative to the module location, so the tool runs from any
# directory. Falls back to a legacy C:\DSPE location only if the scripts are
# deployed there without their Policies/Reports/Logs folders.
# The module lives at the root of the DSPE folder, so $PSScriptRoot IS the root.
$script:DSPE_ROOT = $PSScriptRoot
$script:POLICY_DIR = Join-Path $script:DSPE_ROOT "Policies"
$script:REPORTS_DIR = Join-Path $script:DSPE_ROOT "Reports"
$script:LOGS_DIR = Join-Path $script:DSPE_ROOT "Logs"
$script:BACKUP_DIR = Join-Path $script:DSPE_ROOT "Backups"

function Get-DSPEPath {
    param([ValidateSet("Root", "Policies", "Reports", "Logs", "PolicyFile", "SettingsFile", "SecpolFile", "LogDir", "BackupDir")][string]$Which)
    switch ($Which) {
        "Root"         { return $script:DSPE_ROOT }
        "Policies"     { return $script:POLICY_DIR }
        "Reports"      { return $script:REPORTS_DIR }
        "LogDir"       { return $script:LOGS_DIR }
        "BackupDir"    { return $script:BACKUP_DIR }
        "PolicyFile"   { return (Join-Path $script:POLICY_DIR "policy.json") }
        "SettingsFile" { return (Join-Path $script:POLICY_DIR "gui-settings.json") }
        "SecpolFile"   { return (Join-Path $script:REPORTS_DIR "secpol.cfg") }
    }
}

function Ensure-DSPEFolders {
    foreach ($dir in @($script:REPORTS_DIR, $script:LOGS_DIR)) {
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    }
}

# ================== Log retention ==================
# Daily log files would accumulate forever - trim anything older than
# $LogRetentionDays. The cleanup runs at most once per process (on the first
# Write-Log call) so it costs nothing in steady state.
$script:LogRetentionDays = 30
$script:LogCleanupDone = $false

function Remove-OldDSPELogs {
    param([int]$KeepDays = $script:LogRetentionDays)
    try {
        if (-not (Test-Path $script:LOGS_DIR)) { return }
        $cutoff = (Get-Date).AddDays(-$KeepDays)
        Get-ChildItem -Path $script:LOGS_DIR -Filter "DSPE_*.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { }
}

# ================== Structured logging ==================
# Daily log file (Logs\DSPE_YYYYMMDD.log) + optional Event Log + color-coded
# console. All scripts route output through here for a consistent audit trail.
$script:LogEventSource = "DSPE"
$script:LogEventLogReady = $false

function Initialize-EventLogSource {
    # Event log registration needs admin and only needs to succeed once per machine.
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:LogEventSource)) {
            New-EventLog -LogName Application -Source $script:LogEventSource -ErrorAction Stop
        }
        $script:LogEventLogReady = $true
    } catch { $script:LogEventLogReady = $false }
}

function Write-DSPEDisplay {
    # Console rendering only - mirrors what goes to the log file, with color.
    param([string]$Message, [string]$Level, [ConsoleColor]$Color)
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$stamp] [$Level] $Message" -ForegroundColor $Color
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")][string]$Level = "INFO"
    )
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$stamp] [$Level] $Message"

    # One-time per-process cleanup of expired daily log files.
    if (-not $script:LogCleanupDone) {
        $script:LogCleanupDone = $true
        Remove-OldDSPELogs
    }

    $logFile = Join-Path $script:LOGS_DIR ("DSPE_{0}.log" -f (Get-Date -Format "yyyyMMdd"))
    try {
        if (-not (Test-Path $script:LOGS_DIR)) { New-Item -Path $script:LOGS_DIR -ItemType Directory -Force | Out-Null }
        Add-Content -Path $logFile -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Logging must never take the tool down - fall back to console only.
        Write-Host $line
    }

    if ($script:LogEventLogReady -and ($Level -in @("ERROR", "WARN"))) {
        try {
            $type = if ($Level -eq "ERROR") { [System.Diagnostics.EventLogEntryType]::Error } else { [System.Diagnostics.EventLogEntryType]::Warning }
            Write-EventLog -LogName Application -Source $script:LogEventSource -EventId 1000 -EntryType $type -Message $line -ErrorAction Stop
        } catch { }
    }

    $colors = @{
        INFO    = [ConsoleColor]::Gray
        WARN    = [ConsoleColor]::Yellow
        ERROR   = [ConsoleColor]::Red
        SUCCESS = [ConsoleColor]::Green
        DEBUG   = [ConsoleColor]::DarkGray
    }
    Write-DSPEDisplay -Message $Message -Level $Level -Color $colors[$Level]
}

# ================== Administrator privilege validation ==================
function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Elevated {
    # Returns $true when running elevated. Otherwise offers a one-click
    # elevated restart and reports failure instead of failing silently later
    # on the first secedit/auditpol call. Pass -ScriptPath (the caller's
    # $PSCommandPath) so the restart relaunches the calling script.
    param([string]$ScriptPath)
    if (Test-IsElevated) { return $true }

    Write-Log -Message "Not running elevated - security policy checks and remediation will fail." -Level WARN
    Write-Host ""
    Write-Host "This tool requires Administrator privileges." -ForegroundColor Yellow
    $answer = Read-Host "Restart elevated now? (Y/N)"
    if ($answer -eq "Y") {
        $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $ScriptPath)
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -ErrorAction Stop
            Write-Log -Message "Elevated instance launched; exiting non-elevated instance." -Level INFO
            exit 0
        } catch {
            Write-Log -Message "Elevation declined or failed: $($_.Exception.Message)" -Level ERROR
        }
    }
    return $false
}

# ================== Policy schema validation ==================
# Validates policy.json BEFORE any scan runs so a config typo produces one
# clear error instead of N confusing per-rule failures at runtime.
$script:ValidCheckTypes = @("secedit", "registry", "firewall", "firewall_property", "service", "auditpol")
$script:ValidOperators = @("eq", "gte", "lte", "range", "contains")
$script:CheckTypeRequiredFields = @{
    secedit           = @("key")
    registry          = @("path", "name")
    firewall          = @()
    firewall_property = @("profile", "property")
    service           = @("service_name")
    auditpol          = @("subcategory")
}
# Check types whose Test-Rule path uses Compare-Value and therefore needs an
# operator. firewall/service compare directly with -eq, so operator is optional.
$script:OperatorRequiredTypes = @("secedit", "registry", "firewall_property", "auditpol")

function Test-PolicySchema {
    param([Parameter(Mandatory)]$Policy, [string]$SourcePath)
    $errors = @()

    if ($null -eq $Policy.rules -or $Policy.rules.Count -eq 0) {
        $errors += "policy.json contains no rules array (or it is empty)."
        return $errors
    }

    $seenIds = @{}
    $ruleNumber = 0
    foreach ($rule in $Policy.rules) {
        $ruleNumber++
        # Helper that reads a property without tripping StrictMode on missing members.
        $prop = {
            param($name)
            $p = $rule.PSObject.Properties[$name]
            if ($p) { return $p.Value }
            return $null
        }

        $id = & $prop "id"
        $label = if ($id) { "rule '$id'" } else { "rule #$ruleNumber" }

        if (-not $id) { $errors += "$label`: missing required field 'id'." }
        elseif ($seenIds.ContainsKey($id)) { $errors += "$label`: duplicate rule id." }
        else { $seenIds[$id] = $true }

        if (-not (& $prop "description")) { $errors += "$label`: missing required field 'description'." }
        if (-not (& $prop "category"))   { $errors += "$label`: missing required field 'category'." }

        $checkType = & $prop "check_type"
        if (-not $checkType) {
            $errors += "$label`: missing required field 'check_type'."
            continue
        }
        if ($script:ValidCheckTypes -notcontains $checkType) {
            $known = $script:ValidCheckTypes -join ", "
            $errors += "$label`: unknown check_type '$checkType' (expected one of: $known)."
            continue
        }

        foreach ($field in $script:CheckTypeRequiredFields[$checkType]) {
            if (-not (& $prop $field)) { $errors += "$label`: check_type '$checkType' requires field '$field'." }
        }

        $operator = & $prop "operator"
        if (-not $operator) {
            if ($script:OperatorRequiredTypes -contains $checkType) {
                $errors += "$label`: check_type '$checkType' requires field 'operator'."
            }
        }
        elseif ($script:ValidOperators -notcontains $operator) {
            $known = $script:ValidOperators -join ", "
            $errors += "$label`: unknown operator '$operator' (expected one of: $known)."
        }
        elseif ($operator -eq "range") {
            if ($null -eq (& $prop "min") -or $null -eq (& $prop "max")) {
                $errors += "$label`: operator 'range' requires both 'min' and 'max'."
            }
        }
        elseif ($null -eq (& $prop "expected")) {
            $errors += "$label`: operator '$operator' requires field 'expected'."
        }
    }
    return $errors
}

function Import-D_SPEPolicy {
    # Loads and validates policy.json. Returns the policy object, or throws
    # with a readable error block listing every problem found.
    param([string]$Path = (Get-DSPEPath -Which PolicyFile))

    if (-not (Test-Path $Path)) {
        throw "Policy file not found: $Path"
    }
    try {
        $policy = Get-Content $Path -Raw | ConvertFrom-Json
    } catch {
        throw "Policy file is not valid JSON ($Path): $($_.Exception.Message)"
    }

    $schemaErrors = @(Test-PolicySchema -Policy $policy -SourcePath $Path)
    if ($schemaErrors.Count -gt 0) {
        $details = ($schemaErrors | ForEach-Object { "  - $_" }) -join "`n"
        throw "Policy validation failed with $($schemaErrors.Count) error(s):`n$details"
    }
    return $policy
}

# ================== Shared remediation engine ==================
# ONE source of truth for HOW each rule is fixed, used by the GUI
# (Invoke-RuleRemediation), the CLI (Run-PolicyCheck.ps1 -Remediate) and the
# restore path (Backup-Restore.psm1). Callers apply the fix here, then
# re-verify with their own Test-Rule implementation so GUI caches and CLI
# state stay consistent. It deliberately lives in Common.psm1 (imported by
# every entry script) instead of a new module file - an extra Import-Module
# chain would re-create the import-order trap fixed in v7.1.1.

function Get-DSPESeceditTargetValue {
    # Resolves the value a secedit fix should apply for a rule. Range rules
    # (ACC-002 MaximumPasswordAge, ACC-009 LockoutBadCount) carry min/max
    # instead of "expected" - the max is used (the strictest allowed value).
    param([Parameter(Mandatory)]$Rule)
    $maxProp = $Rule.PSObject.Properties["max"]
    switch ($Rule.key) {
        "MaximumPasswordAge" { if ($maxProp) { return $maxProp.Value } }
        "LockoutBadCount"    { if ($maxProp) { return $maxProp.Value } }
    }
    $expProp = $Rule.PSObject.Properties["expected"]
    if ($expProp) { return $expProp.Value }
    return $null
}

function Invoke-DSPESeceditInfFix {
    # Single-setting secedit INF template - the same mechanism secpol.msc
    # uses under the hood, for account-policy values that "net accounts"
    # does not expose (PasswordComplexity, ClearTextPassword).
    param(
        [Parameter(Mandatory)][ValidateSet("PasswordComplexity", "ClearTextPassword")][string]$Setting,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )
    $infPath = Join-Path $env:TEMP ("dspe_fix_" + [guid]::NewGuid().ToString('N') + ".inf")
    $sdbPath = Join-Path $env:TEMP ("dspe_fix_" + [guid]::NewGuid().ToString('N') + ".sdb")
    try {
        $infLines = @(
            "[Unicode]",
            "Unicode=yes",
            "[System Access]",
            "$Setting = $Value",
            "[Version]",
            'signature="$CHICAGO$"',
            "Revision=1"
        )
        Set-Content -Path $infPath -Value $infLines -Encoding Unicode
        $out = secedit /configure /db $sdbPath /cfg $infPath /areas SECURITYPOLICY 2>&1
        if ($LASTEXITCODE -ne 0 -and $out) {
            return @{ Success = $false; Reason = ($out | Out-String).Trim() }
        }
        return @{ Success = $true; Reason = "" }
    } catch {
        return @{ Success = $false; Reason = $_.Exception.Message }
    } finally {
        Remove-Item -Path $infPath, $sdbPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-DSPESeceditFix {
    # Applies ONE account-policy value. $Key is the secedit policy name as it
    # appears in the INF export; $Value is the resolved target value (callers
    # pass rule.max for range rules, the captured value for restores).
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )
    switch ($Key) {
        "MinimumPasswordLength" { $out = net accounts /minpwlen:$Value 2>&1 }
        "PasswordHistorySize"   { $out = net accounts /uniquepw:$Value 2>&1 }
        "MaximumPasswordAge"    { $out = net accounts /maxpwage:$Value 2>&1 }
        "MinimumPasswordAge"    { $out = net accounts /minpwage:$Value 2>&1 }
        "LockoutBadCount"       { $out = net accounts /lockoutthreshold:$Value 2>&1 }
        "LockoutDuration"       { $out = net accounts /lockoutduration:$Value 2>&1 }
        "ResetLockoutCount"     { $out = net accounts /lockoutwindow:$Value 2>&1 }
        "PasswordComplexity"    { return (Invoke-DSPESeceditInfFix -Setting "PasswordComplexity" -Value $Value) }
        "ClearTextPassword"     { return (Invoke-DSPESeceditInfFix -Setting "ClearTextPassword" -Value $Value) }
        default {
            return @{ Success = $false; Reason = "No automated fix for $Key - apply via secpol.msc" }
        }
    }
    if ($LASTEXITCODE -ne 0 -and $out) {
        return @{ Success = $false; Reason = ($out | Out-String).Trim() }
    }
    return @{ Success = $true; Reason = "" }
}

function Invoke-DSPESettingFix {
    # Fixes ONE rule on the live system. Returns @{ Success; Reason }.
    # No re-check here on purpose - callers verify with their own Test-Rule
    # (the GUI re-checks with fresh caches, the CLI re-exports secedit).
    param([Parameter(Mandatory)]$Rule)
    try {
        switch ($Rule.check_type) {
            "firewall" {
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
                return @{ Success = $true; Reason = "" }
            }
            "firewall_property" {
                $fwParams = @{ Profile = $Rule.profile; ErrorAction = "Stop" }
                $fwValue = $Rule.expected
                # GpoBoolean-style properties (NotifyOnListen, LogBlocked,
                # LogAllowed) parse from their string form, not a .NET bool.
                if ($fwValue -is [bool]) { $fwValue = $fwValue.ToString() }
                $fwParams[$Rule.property] = $fwValue
                Set-NetFirewallProfile @fwParams
                return @{ Success = $true; Reason = "" }
            }
            "registry" {
                if (-not (Test-Path $Rule.path)) { New-Item -Path $Rule.path -Force | Out-Null }
                # Preserve the existing value's REG_MULTI_SZ-ness (e.g.
                # NullSessionPipes/NullSessionShares) - writing "" as a plain
                # string to a multi-string value doesn't clear it; it needs an
                # empty string[] array.
                $regValue = $Rule.expected
                $regKind = $null
                try { $regKind = (Get-Item -Path $Rule.path -ErrorAction Stop).GetValueKind($Rule.name) } catch { }
                if ($regKind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) {
                    $regValue = if ([string]::IsNullOrEmpty("$($Rule.expected)")) { [string[]]@() } else { [string[]]@($Rule.expected) }
                    Set-ItemProperty -Path $Rule.path -Name $Rule.name -Value $regValue -Type MultiString -ErrorAction Stop
                } else {
                    Set-ItemProperty -Path $Rule.path -Name $Rule.name -Value $regValue -ErrorAction Stop
                }
                return @{ Success = $true; Reason = "" }
            }
            "service" {
                $startType = "Disabled"
                $expProp = $Rule.PSObject.Properties["expected"]
                if ($expProp -and $expProp.Value) { $startType = "$($expProp.Value)" }
                Set-Service -Name $Rule.service_name -StartupType $startType -ErrorAction Stop
                Stop-Service -Name $Rule.service_name -ErrorAction SilentlyContinue
                return @{ Success = $true; Reason = "" }
            }
            "secedit" {
                $target = Get-DSPESeceditTargetValue -Rule $Rule
                if ($null -eq $target) {
                    return @{ Success = $false; Reason = "Rule carries no expected/max value to apply." }
                }
                return (Invoke-DSPESeceditFix -Key $Rule.key -Value "$target")
            }
            "auditpol" {
                $exp = "$($Rule.expected)".ToLower()
                $sFlag = if ($exp -match "success") { "/success:enable" } else { "/success:disable" }
                $fFlag = if ($exp -match "failure") { "/failure:enable" } else { "/failure:disable" }
                & auditpol /set /subcategory:"$($Rule.subcategory)" $sFlag $fFlag | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    return @{ Success = $false; Reason = "auditpol returned an error" }
                }
                return @{ Success = $true; Reason = "" }
            }
            default {
                return @{ Success = $false; Reason = "No automated fix available for this check type" }
            }
        }
    } catch {
        return @{ Success = $false; Reason = $_.Exception.Message }
    }
}

Export-ModuleMember -Function @(
    "Get-DSPEPath", "Ensure-DSPEFolders", "Write-Log",
    "Initialize-EventLogSource", "Test-IsElevated", "Assert-Elevated",
    "Test-PolicySchema", "Import-D_SPEPolicy", "Remove-OldDSPELogs",
    "Get-DSPESeceditTargetValue", "Invoke-DSPESeceditInfFix",
    "Invoke-DSPESeceditFix", "Invoke-DSPESettingFix"
)

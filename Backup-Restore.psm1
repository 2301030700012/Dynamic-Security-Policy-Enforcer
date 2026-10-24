# DSPE backup & restore: snapshots the current value of every setting that is
# about to be changed, so a fix can be rolled back per-rule instead of relying
# on blanket file copies. Snapshots live in Backups\ as JSON plus raw copies of
# secedit/auditpol state for forensic reference.

Set-StrictMode -Version Latest

# Backups live INSIDE the DSPE root (next to Reports/Logs). The old layout - a
# Backups folder as a SIBLING of the tool folder - broke when DSPE was deployed
# under Program Files or any other read-only install directory. The legacy
# location is remembered so existing snapshots can be migrated automatically.
#
# NOTE: this module deliberately stays SELF-CONTAINED (no Import-Module of
# Common.psm1 here). Re-importing Common with -Force from module scope would
# yank it out of the session's global scope and cascade "command not found"
# errors through the GUI and CLI. Both modules sit in the same folder, so
# $PSScriptRoot resolves to the identical DSPE root that Common.psm1 uses for
# Get-DSPEPath -Which BackupDir - the two always agree by construction.
$script:LegacyBackupDir = Join-Path (Split-Path -Parent $PSScriptRoot) "Backups"
$script:BACKUP_DIR = Join-Path $PSScriptRoot "Backups"

function Get-DSPEBackupDir { return $script:BACKUP_DIR }

function Ensure-DSPEBackupDir {
    # One-time migration: snapshots taken before this fix lived in a Backups
    # folder NEXT TO the tool folder. Move them into the new location so
    # existing restore points survive the upgrade.
    try {
        if ($script:LegacyBackupDir -and
            (Test-Path $script:LegacyBackupDir) -and
            ($script:LegacyBackupDir -ne $script:BACKUP_DIR)) {
            $legacySnapshots = @(Get-ChildItem -Path $script:LegacyBackupDir -Filter "Backup_*" -File -ErrorAction SilentlyContinue)
            if ($legacySnapshots.Count -gt 0) {
                if (-not (Test-Path $script:BACKUP_DIR)) {
                    New-Item -Path $script:BACKUP_DIR -ItemType Directory -Force | Out-Null
                }
                foreach ($oldSnapshot in $legacySnapshots) {
                    Move-Item -Path $oldSnapshot.FullName -Destination $script:BACKUP_DIR -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch { }
    if (-not (Test-Path $script:BACKUP_DIR)) {
        New-Item -Path $script:BACKUP_DIR -ItemType Directory -Force | Out-Null
    }
}

# ---- Per-rule capture: reads the CURRENT live value the same way Test-Rule does ----
# $SeceditLines (optional) lets the caller export secpol ONCE for a whole batch
# of rules instead of once per rule - backing up 50+ account-policy rules used
# to take minutes because every single rule triggered its own secedit export.
function Get-RuleCaptureValue($rule, $SeceditLines = $null) {
    switch ($rule.check_type) {
        "secedit" {
            if ($SeceditLines) {
                $line = @($SeceditLines) | Select-String ("^\s*" + [regex]::Escape($rule.key) + "\s*=")
                if ($line) { return (($line.Line -split "=", 2)[1].Trim()) }
                return $null
            }
            $tmp = Join-Path $env:TEMP ("dspe_snap_" + [guid]::NewGuid().ToString('N') + ".cfg")
            try {
                secedit /export /cfg $tmp | Out-Null
                $line = Get-Content $tmp | Select-String ("^\s*" + [regex]::Escape($rule.key) + "\s*=")
                if ($line) { return (($line.Line -split "=", 2)[1].Trim()) }
                return $null
            } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        }
        "registry" {
            try {
                $val = (Get-ItemProperty -Path $rule.path -Name $rule.name -ErrorAction Stop).PSObject.Properties[$rule.name].Value
                if ($val -is [array]) { $val = $val -join ',' }
                return $val
            } catch { return $null }
        }
        "firewall" {
            try {
                $fw = Get-NetFirewallProfile -Profile Domain,Public,Private
                return ($fw | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ";"
            } catch { return $null }
        }
        "firewall_property" {
            try {
                $prof = Get-NetFirewallProfile -Profile $rule.profile
                return $prof.$($rule.property)
            } catch { return $null }
        }
        "service" {
            $svc = Get-Service -Name $rule.service_name -ErrorAction SilentlyContinue
            if ($svc) { return $svc.StartType.ToString() } else { return "NotInstalled" }
        }
        "auditpol" {
            try {
                $line = & auditpol /get /subcategory:"$($rule.subcategory)" 2>$null | Where-Object { $_ -match [regex]::Escape($rule.subcategory) }
                if ($line) { return (($line -split '\s{2,}') | Select-Object -Last 1).Trim() }
                return $null
            } catch { return $null }
        }
    }
    return $null
}

function New-DSPESnapshot {
    # Captures the pre-fix state of the given rules and writes
    # Backups\Backup_<timestamp>.json (+ raw exports). Returns the file path,
    # or $null if nothing needed backing up.
    param([Parameter(Mandatory)]$Rules)

    $entries = @()
    # Export secpol ONCE for all secedit-type rules (an export per rule made
    # backing up 50+ account-policy rules take minutes).
    $seceditLines = $null
    if (@($Rules | Where-Object { $_.check_type -eq "secedit" }).Count -gt 0) {
        try {
            $snapCfg = Join-Path $env:TEMP ("dspe_snap_" + [guid]::NewGuid().ToString('N') + ".cfg")
            secedit /export /cfg $snapCfg | Out-Null
            $seceditLines = Get-Content $snapCfg
            Remove-Item $snapCfg -Force -ErrorAction SilentlyContinue
        } catch { $seceditLines = $null }
    }
    foreach ($rule in $Rules) {
        $value = Get-RuleCaptureValue $rule $seceditLines
        # Read optional per-type fields without tripping StrictMode on rules
        # that don't carry them.
        function prop([string]$n) {
            $p = $rule.PSObject.Properties[$n]
            if ($p) { return $p.Value }
            return $null
        }
        $entries += [pscustomobject]@{
            ID = $rule.id
            CheckType = $rule.check_type
            Key = prop "key"
            Path = prop "path"
            Name = prop "name"
            Profile = prop "profile"
            Property = prop "property"
            ServiceName = prop "service_name"
            Subcategory = prop "subcategory"
            CapturedValue = $value
        }
    }
    if ($entries.Count -eq 0) { return $null }

    Ensure-DSPEBackupDir
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $backupPath = Join-Path $script:BACKUP_DIR "Backup_$timestamp.json"

    # Raw state copies alongside the JSON, for reference/forensics (the JSON is
    # what Restore actually uses - these are belt-and-braces).
    $secpolCopy = Join-Path $script:BACKUP_DIR "Backup_${timestamp}_secpol.cfg"
    $auditpolCopy = Join-Path $script:BACKUP_DIR "Backup_${timestamp}_auditpol.txt"
    try { secedit /export /cfg $secpolCopy | Out-Null } catch { }
    try { & auditpol /get /category:* | Out-File -FilePath $auditpolCopy -Encoding Unicode } catch { }

    $snapshot = [pscustomobject]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        RuleCount = $entries.Count
        Rules = $entries
    }
    $snapshot | ConvertTo-Json -Depth 5 | Out-File -FilePath $backupPath -Encoding UTF8
    return $backupPath
}

function Restore-DSPESnapshot {
    # Rolls back every rule in the snapshot to its captured value. Rules whose
    # captured value was $null (the setting didn't exist) are skipped rather
    # than deleted - deleting policy values is riskier than leaving a fix in
    # place, and the skip is reported.
    param([Parameter(Mandatory)][string]$SnapshotPath)

    $snapshot = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    $restored = 0
    $skipped = 0
    $failed = 0
    $details = @()

    foreach ($entry in $snapshot.Rules) {
        if ($null -eq $entry.CapturedValue) {
            $skipped++
            $details += "SKIP $($entry.ID): no prior value recorded"
            continue
        }
        try {
            switch ($entry.CheckType) {
                "secedit" {
                    # Shared fix engine in Common.psm1 - the SAME net-accounts /
                    # secedit-INF mapping the Fix path uses, so fix and restore
                    # can never drift apart again. Common.psm1 is imported by
                    # every DSPE entry script before this module loads.
                    if (-not (Get-Command Invoke-DSPESeceditFix -ErrorAction SilentlyContinue)) {
                        throw "Invoke-DSPESeceditFix not available - import Common.psm1 before Backup-Restore.psm1"
                    }
                    $fixResult = Invoke-DSPESeceditFix -Key $entry.Key -Value "$($entry.CapturedValue)"
                    if (-not $fixResult.Success) { throw $fixResult.Reason }
                }
                "registry" {
                    if (-not (Test-Path $entry.Path)) { New-Item -Path $entry.Path -Force | Out-Null }
                    $kind = $null
                    try { $kind = (Get-Item -Path $entry.Path -ErrorAction Stop).GetValueKind($entry.Name) } catch { }
                    if ($kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) {
                        $mv = if ([string]::IsNullOrEmpty($entry.CapturedValue)) { [string[]]@() } else { [string[]]@($entry.CapturedValue) }
                        Set-ItemProperty -Path $entry.Path -Name $entry.Name -Value $mv -Type MultiString -ErrorAction Stop
                    } else {
                        Set-ItemProperty -Path $entry.Path -Name $entry.Name -Value $entry.CapturedValue -ErrorAction Stop
                    }
                }
                "firewall" {
                    foreach ($pair in ($entry.CapturedValue -split ";")) {
                        $parts = $pair -split "=", 2
                        if ($parts.Count -eq 2) {
                            Set-NetFirewallProfile -Profile $parts[0] -Enabled $parts[1] -ErrorAction Stop
                        }
                    }
                }
                "firewall_property" {
                    $val = $entry.CapturedValue
                    if ($val -is [bool]) { $val = $val.ToString() }
                    # Set the property by name via a splat built dynamically.
                    $p = @{ Profile = $entry.Profile; ErrorAction = "Stop" }
                    $p[$entry.Property] = $val
                    Set-NetFirewallProfile @p
                }
                "service" {
                    if ($entry.CapturedValue -eq "NotInstalled") {
                        $skipped++; $details += "SKIP $($entry.ID): service was not installed"
                        continue
                    }
                    Set-Service -Name $entry.ServiceName -StartupType $entry.CapturedValue -ErrorAction Stop
                }
                "auditpol" {
                    $exp = $entry.CapturedValue.ToLower()
                    $sFlag = if ($exp -match "success") { "/success:enable" } else { "/success:disable" }
                    $fFlag = if ($exp -match "failure") { "/failure:enable" } else { "/failure:disable" }
                    & auditpol /set /subcategory:"$($entry.Subcategory)" $sFlag $fFlag | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "auditpol returned an error" }
                }
                default { throw "unknown check_type '$($entry.CheckType)'" }
            }
            $restored++
            $details += "OK   $($entry.ID): restored to '$($entry.CapturedValue)'"
        } catch {
            $failed++
            $details += "FAIL $($entry.ID): $($_.Exception.Message)"
        }
    }
    return [pscustomobject]@{
        Restored = $restored; Skipped = $skipped; Failed = $failed; Details = $details
    }
}

function Get-DSPESnapshots {
    # Newest first, newest carrying the IsNewest flag for menu display.
    Ensure-DSPEBackupDir
    return @(Get-ChildItem -Path $script:BACKUP_DIR -Filter "Backup_*.json" |
        Sort-Object LastWriteTime -Descending)
}

function Remove-OldDSPESnapshots {
    # Keep the most recent $Keep backups; delete the rest. Called after each new
    # snapshot so the folder cannot grow without bound.
    param([int]$Keep = 20)
    $all = @(Get-DSPESnapshots)
    if ($all.Count -gt $Keep) {
        $all | Select-Object -Skip $Keep | ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            # Also remove this snapshot's raw companion files.
            $stamp = $_.BaseName -replace "^Backup_", ""
            Remove-Item (Join-Path $script:BACKUP_DIR "Backup_${stamp}_secpol.cfg") -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $script:BACKUP_DIR "Backup_${stamp}_auditpol.txt") -Force -ErrorAction SilentlyContinue
        }
    }
}

Export-ModuleMember -Function @(
    "Get-DSPEBackupDir", "Ensure-DSPEBackupDir", "Get-RuleCaptureValue",
    "New-DSPESnapshot", "Restore-DSPESnapshot", "Get-DSPESnapshots",
    "Remove-OldDSPESnapshots"
)
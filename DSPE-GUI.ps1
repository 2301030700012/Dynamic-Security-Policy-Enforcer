Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

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
Import-Module (Join-Path $here "Backup-Restore.psm1") -Force -DisableNameChecking

Initialize-EventLogSource
Ensure-DSPEFolders
Ensure-DSPEBackupDir

# Checks and remediation need admin - offer an elevated restart up front
# instead of letting every secedit/auditpol call fail silently later.
if (-not (Test-IsElevated)) {
    Write-Log "GUI started without elevation." -Level WARN
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "DSPE requires Administrator privileges to check and remediate security policy.`n`nRestart elevated now?",
        "Administrator Required",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($answer -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            Start-Process -FilePath "powershell.exe" `
                -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $MyInvocation.MyCommand.Path) `
                -Verb RunAs -ErrorAction Stop
            Write-Log "Elevated GUI instance launched; exiting non-elevated instance." -Level INFO
            exit 0
        } catch {
            Write-Log "Elevation declined or failed: $($_.Exception.Message)" -Level ERROR
        }
    }
}

# ================== Load policy ==================
try {
    $policy = Import-D_SPEPolicy
} catch {
    Write-Log $_.Exception.Message -Level ERROR
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to load policy:`n`n$($_.Exception.Message)`n`nThe application will now exit.",
        "Policy Load Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    exit 2
}

# ================== Settings persistence ==================
 $settingsPath = Get-DSPEPath -Which SettingsFile
 $exePath = Join-Path (Get-DSPEPath -Which Root) "DSPE-GUI.exe"
 $runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
 $runKeyName = "DynamicSecurityPolicyEnforcer"

function Get-DSPESettings {
    if (Test-Path $settingsPath) {
        try { return Get-Content $settingsPath -Raw | ConvertFrom-Json } catch { }
    }
    return [pscustomobject]@{
        StartWithWindows = $false
        StartMinimized   = $false
        MinimizeOnClose  = $false
        AppliedIDs       = @()
    }
}

function Save-DSPESettings {
    $obj = [pscustomobject]@{
        StartWithWindows       = $chkStartWithWindows.Checked
        StartMinimized         = $chkStartMinimized.Checked
        MinimizeOnClose        = $chkMinimizeOnClose.Checked
        AppliedIDs             = @($script:appliedIDs)
        MonitorIntervalSeconds = [int]$numMonitorInterval.Value
    }
    $obj | ConvertTo-Json | Out-File -FilePath $settingsPath -Encoding UTF8
}

function Set-StartWithWindows($enable) {
    try {
        if ($enable) {
            Set-ItemProperty -Path $runKeyPath -Name $runKeyName -Value "`"$exePath`"" -ErrorAction Stop
        } else {
            Remove-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction SilentlyContinue
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Could not update startup registry entry: $_", "Warning") | Out-Null
    }
}

 $script:trulyExit = $false

 $seceditPath = Get-DSPEPath -Which SecpolFile
function Export-Secedit {
    secedit /export /cfg $seceditPath | Out-Null
    return Get-Content $seceditPath
}
 $script:seceditLines = $null
# Tracks whether this pass already tried the expensive call, independently of
# whether it actually returned anything - without this, a failed attempt (e.g.
# secedit/auditpol without admin rights) looks identical to "never tried" and
# gets retried on every single rule instead of once per pass.
 $script:seceditAttempted = $false

function Get-SeceditValue($key) {
    if (-not $script:seceditAttempted) {
        $script:seceditAttempted = $true
        $script:seceditLines = Export-Secedit
    }
    $line = $script:seceditLines | Select-String ("^\s*" + [regex]::Escape($key) + "\s*=")
    if ($line) { return ($line -split "=", 2)[1].Trim() }
    return $null
}

# Firewall/auditpol state is expensive to fetch (a CIM call / an external process).
# Cache each one per scan pass so N rules of the same type cost one call, not N -
# this is what was driving the CPU spike on every 5-second monitor tick.
 $script:fwProfileCache = $null
 $script:fwProfileAttempted = $false
function Get-CachedFirewallProfiles {
    if (-not $script:fwProfileAttempted) {
        $script:fwProfileAttempted = $true
        try { $script:fwProfileCache = Get-NetFirewallProfile -Profile Domain,Public,Private } catch { $script:fwProfileCache = $null }
    }
    return $script:fwProfileCache
}

 $script:auditpolCache = $null
 $script:auditpolAttempted = $false
function Get-AuditSubcategoryValue($subcategory) {
    if (-not $script:auditpolAttempted) {
        $script:auditpolAttempted = $true
        $script:auditpolCache = & auditpol /get /category:* 2>$null
    }
    $line = $script:auditpolCache | Where-Object { $_.Trim() -match ("^" + [regex]::Escape($subcategory) + "\s") } | Select-Object -First 1
    if ($line) {
        $parts = $line -split '\s{2,}'
        return ($parts | Select-Object -Last 1).Trim()
    }
    return "NotFound"
}

# Clears all per-pass caches so the next Test-Rule call for each check type
# re-fetches fresh data exactly once - and not at all if that type isn't used.
function Reset-ScanCaches {
    $script:seceditLines = $null
    $script:seceditAttempted = $false
    $script:fwProfileCache = $null
    $script:fwProfileAttempted = $false
    $script:auditpolCache = $null
    $script:auditpolAttempted = $false
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

function Test-Rule($rule) {
    $actualValue = "NotSet"
    $passed = $false
    switch ($rule.check_type) {
        "secedit" {
            $raw = Get-SeceditValue($rule.key)
            if ($null -ne $raw) { try { $actualValue = [double]$raw } catch { $actualValue = $raw } }
            $passed = Compare-Value $actualValue $rule.expected $rule.operator $rule
        }
        "registry" {
            try {
                $actualValue = (Get-ItemProperty -Path $rule.path -Name $rule.name -ErrorAction Stop).$($rule.name)
                # REG_MULTI_SZ values (e.g. NullSessionPipes/NullSessionShares) come back as a
                # string[] - join so an empty array compares equal to an "expected": "" rule
                # instead of silently failing an array-vs-string comparison.
                if ($actualValue -is [array]) { $actualValue = $actualValue -join ',' }
            }
            catch { $actualValue = "NotSet" }
            $passed = Compare-Value $actualValue $rule.expected $rule.operator $rule
        }
        "firewall" {
            $fw = Get-CachedFirewallProfiles
            if ($null -eq $fw) {
                # Profile fetch failed (no admin / CIM unavailable) - report
                # Error + FAIL instead of silently computing a false PASS.
                $actualValue = "Error"
                $passed = $false
            } else {
                $actualValue = -not ($fw.Enabled -contains $false)
                $passed = ($actualValue -eq $rule.expected)
            }
        }
        "firewall_property" {
            try {
                $prof = Get-CachedFirewallProfiles | Where-Object { $_.Name -eq $rule.profile }
                if ($null -eq $prof) {
                    $actualValue = "Error"; $passed = $false
                } else {
                    $actualValue = $prof.$($rule.property)
                    $passed = Compare-Value $actualValue $rule.expected $rule.operator $rule
                }
            } catch { $actualValue = "Error"; $passed = $false }
        }
        "service" {
            $svc = Get-Service -Name $rule.service_name -ErrorAction SilentlyContinue
            if ($svc) { $actualValue = $svc.StartType.ToString(); $passed = ($actualValue -eq $rule.expected) }
            else { $actualValue = "NotInstalled"; $passed = $true }
        }
        "auditpol" {
            try {
                $actualValue = Get-AuditSubcategoryValue $rule.subcategory
                $passed = Compare-Value $actualValue $rule.expected $rule.operator $rule
            } catch { $actualValue = "Error"; $passed = $false }
        }
    }
    return @{ Actual = $actualValue; Passed = $passed }
}

# Full re-scan: refresh cached secedit export once, then test every rule.
# Updates each grid row's Status cell and color; returns a hashtable ID -> Passed.
function Invoke-FullScan {
    Reset-ScanCaches
    $passMap = @{}
    foreach ($row in $grid.Rows) {
        $id = $row.Cells["ID"].Value
        $rule = $policy.rules | Where-Object { $_.id -eq $id } | Select-Object -First 1
        if (-not $rule) { continue }
        # One broken rule must not abort the whole scan - report it as FAIL.
        try { $r = Test-Rule $rule } catch { $r = @{ Actual = "Error"; Passed = $false } }
        $passMap[$id] = $r.Passed
        $row.Cells["Status"].Value = if ($r.Passed) { "PASS" } else { "FAIL" }
        $row.DefaultCellStyle.BackColor = if ($r.Passed) { [System.Drawing.Color]::FromArgb(223, 246, 221) } else { [System.Drawing.Color]::FromArgb(252, 224, 224) }
    }
    return $passMap
}

# Compliance % over only the currently-applied (checked-at-Apply-time) rule set.
 $script:appliedIDs = @()
function Update-ComplianceLabel($passMap) {
    if ($script:appliedIDs.Count -eq 0) {
        $lblCompliance.Text = "Compliance: -- % (no rule set applied yet)"
        return
    }
    $applied = $script:appliedIDs
    $passedCount = 0
    foreach ($id in $applied) {
        if ($passMap.ContainsKey($id) -and $passMap[$id]) { $passedCount++ }
    }
    $pct = [math]::Round(($passedCount / $applied.Count) * 100, 1)
    $lblCompliance.Text = "Compliance: $pct % ($passedCount of $($applied.Count) applied rules passing)"
}


# ================== Main Form ==================
 $form = New-Object System.Windows.Forms.Form
 $form.Text = "Dynamic Security Policy Enforcer"
 $form.Size = New-Object System.Drawing.Size(1300, 820)
 $form.StartPosition = "CenterScreen"
 $form.MinimumSize = New-Object System.Drawing.Size(1000, 600)

# ================== Top panel: dashboard summary ==================
 $topPanel = New-Object System.Windows.Forms.Panel
 $topPanel.Dock = "Top"
 $topPanel.Height = 70
 $topPanel.BackColor = [System.Drawing.Color]::FromArgb(122, 35, 48)
 $form.Controls.Add($topPanel)

 $lblTitle = New-Object System.Windows.Forms.Label
 $lblTitle.Text = "Dynamic Security Policy Enforcer"
 $lblTitle.ForeColor = [System.Drawing.Color]::White
 $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
 $lblTitle.AutoSize = $true
 $lblTitle.Location = New-Object System.Drawing.Point(15, 12)
 $topPanel.Controls.Add($lblTitle)

 $lblCompliance = New-Object System.Windows.Forms.Label
 $lblCompliance.Text = "Compliance: -- % (not scanned yet)"
 $lblCompliance.ForeColor = [System.Drawing.Color]::White
 $lblCompliance.Font = New-Object System.Drawing.Font("Segoe UI", 11)
 $lblCompliance.AutoSize = $true
 $lblCompliance.Location = New-Object System.Drawing.Point(15, 42)
 $lblCompliance.Name = "lblCompliance"
 $topPanel.Controls.Add($lblCompliance)

# ================== Bottom control panel ==================
 $bottomPanel = New-Object System.Windows.Forms.Panel
 $bottomPanel.Dock = "Bottom"
 $bottomPanel.Height = 130
 $form.Controls.Add($bottomPanel)

# Preset buttons
 $btnMinimal = New-Object System.Windows.Forms.Button
 $btnMinimal.Text = "Minimal"
 $btnMinimal.Size = New-Object System.Drawing.Size(110, 32)
 $btnMinimal.Location = New-Object System.Drawing.Point(15, 10)
 $bottomPanel.Controls.Add($btnMinimal)

 $btnStandard = New-Object System.Windows.Forms.Button
 $btnStandard.Text = "Standard"
 $btnStandard.Size = New-Object System.Drawing.Size(110, 32)
 $btnStandard.Location = New-Object System.Drawing.Point(135, 10)
 $bottomPanel.Controls.Add($btnStandard)

 $btnAdvanced = New-Object System.Windows.Forms.Button
 $btnAdvanced.Text = "Advanced"
 $btnAdvanced.Size = New-Object System.Drawing.Size(110, 32)
 $btnAdvanced.Location = New-Object System.Drawing.Point(255, 10)
 $bottomPanel.Controls.Add($btnAdvanced)

 $btnApply = New-Object System.Windows.Forms.Button
 $btnApply.Text = "Apply"
 $btnApply.Size = New-Object System.Drawing.Size(110, 32)
 $btnApply.Location = New-Object System.Drawing.Point(400, 10)
 $btnApply.BackColor = [System.Drawing.Color]::FromArgb(122, 35, 48)
 $btnApply.ForeColor = [System.Drawing.Color]::White
 $bottomPanel.Controls.Add($btnApply)

 $btnRescan = New-Object System.Windows.Forms.Button
 $btnRescan.Text = "Rescan Now"
 $btnRescan.Size = New-Object System.Drawing.Size(110, 32)
 $btnRescan.Location = New-Object System.Drawing.Point(520, 10)
 $bottomPanel.Controls.Add($btnRescan)

 $btnFix = New-Object System.Windows.Forms.Button
 $btnFix.Text = "Fix"
 $btnFix.Size = New-Object System.Drawing.Size(110, 32)
 $btnFix.Location = New-Object System.Drawing.Point(640, 10)
 $btnFix.BackColor = [System.Drawing.Color]::FromArgb(192, 96, 32)
 $btnFix.ForeColor = [System.Drawing.Color]::White
 $bottomPanel.Controls.Add($btnFix)

 $btnExport = New-Object System.Windows.Forms.Button
 $btnExport.Text = "Export Report"
 $btnExport.Size = New-Object System.Drawing.Size(110, 32)
 $btnExport.Location = New-Object System.Drawing.Point(760, 10)
 $bottomPanel.Controls.Add($btnExport)

# Progress bar shown during scans and remediation
 $progressBar = New-Object System.Windows.Forms.ProgressBar
 $progressBar.Size = New-Object System.Drawing.Size(360, 18)
 $progressBar.Location = New-Object System.Drawing.Point(900, 17)
 $progressBar.Style = "Continuous"
 $progressBar.Visible = $false
 $bottomPanel.Controls.Add($progressBar)

 $lblSelectedCount = New-Object System.Windows.Forms.Label
 $lblSelectedCount.Text = "No rules loaded yet"
 $lblSelectedCount.AutoSize = $true
# Sits on the checkbox row after "Minimize on close" - the button row is full
# now that Fix and Export were added.
 $lblSelectedCount.Location = New-Object System.Drawing.Point(470, 58)
 $lblSelectedCount.Name = "lblSelectedCount"
 $bottomPanel.Controls.Add($lblSelectedCount)

# Tray/startup checkboxes
 $chkStartWithWindows = New-Object System.Windows.Forms.CheckBox
 $chkStartWithWindows.Text = "Start with Windows"
 $chkStartWithWindows.AutoSize = $true
 $chkStartWithWindows.Location = New-Object System.Drawing.Point(15, 55)
 $bottomPanel.Controls.Add($chkStartWithWindows)

 $chkStartMinimized = New-Object System.Windows.Forms.CheckBox
 $chkStartMinimized.Text = "Start minimized"
 $chkStartMinimized.AutoSize = $true
 $chkStartMinimized.Location = New-Object System.Drawing.Point(180, 55)
 $bottomPanel.Controls.Add($chkStartMinimized)

 $chkMinimizeOnClose = New-Object System.Windows.Forms.CheckBox
 $chkMinimizeOnClose.Text = "Minimize on close"
 $chkMinimizeOnClose.AutoSize = $true
 $chkMinimizeOnClose.Location = New-Object System.Drawing.Point(320, 55)
 $bottomPanel.Controls.Add($chkMinimizeOnClose)

# Monitor interval selector (settings-persisted, 5-3600 seconds)
 $lblMonitorInterval = New-Object System.Windows.Forms.Label
 $lblMonitorInterval.Text = "Monitor every"
 $lblMonitorInterval.AutoSize = $true
 $lblMonitorInterval.Location = New-Object System.Drawing.Point(640, 58)
 $bottomPanel.Controls.Add($lblMonitorInterval)

 $numMonitorInterval = New-Object System.Windows.Forms.NumericUpDown
 $numMonitorInterval.Minimum = 5
 $numMonitorInterval.Maximum = 3600
 $numMonitorInterval.Increment = 5
 $numMonitorInterval.Size = New-Object System.Drawing.Size(55, 23)
 $numMonitorInterval.Location = New-Object System.Drawing.Point(725, 55)
 $bottomPanel.Controls.Add($numMonitorInterval)

 $lblMonitorSec = New-Object System.Windows.Forms.Label
 $lblMonitorSec.Text = "sec"
 $lblMonitorSec.AutoSize = $true
 $lblMonitorSec.Location = New-Object System.Drawing.Point(783, 58)
 $bottomPanel.Controls.Add($lblMonitorSec)

# ================== Load saved settings into checkboxes ==================
 $script:settings = Get-DSPESettings
 $chkStartWithWindows.Checked = [bool]$script:settings.StartWithWindows
 $chkStartMinimized.Checked   = [bool]$script:settings.StartMinimized
 $chkMinimizeOnClose.Checked  = [bool]$script:settings.MinimizeOnClose
 $script:appliedIDs = @($script:settings.AppliedIDs)

# Saved monitor interval - fall back to 5 s when missing or out of range.
 $monSec = 5
 try {
     $monProp = $script:settings.PSObject.Properties["MonitorIntervalSeconds"]
     if ($monProp -and [int]$monProp.Value -ge 5 -and [int]$monProp.Value -le 3600) { $monSec = [int]$monProp.Value }
 } catch { }
 $numMonitorInterval.Value = $monSec

# ================== Start-hidden setup ==================
# These have to be set BEFORE Application.Run shows the form - setting them
# only in the Load/Shown handlers still lets the window flash on screen for a
# frame first. WindowState/ShowInTaskbar keep it off the taskbar and out of
# Alt-Tab; Opacity 0 makes sure nothing is ever actually painted on screen.
if ($chkStartMinimized.Checked) {
    $form.WindowState = "Minimized"
    $form.ShowInTaskbar = $false
    $form.Opacity = 0
}

# ================== System tray icon ==================
 $notifyIcon = New-Object System.Windows.Forms.NotifyIcon
 $notifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
 $notifyIcon.Text = "Dynamic Security Policy Enforcer"
 $notifyIcon.Visible = $true

 $trayMenu = New-Object System.Windows.Forms.ContextMenuStrip
 $menuShow = $trayMenu.Items.Add("Show")
 $menuRestore = $trayMenu.Items.Add("Restore from backup...")
 $menuExit = $trayMenu.Items.Add("Exit")
 $notifyIcon.ContextMenuStrip = $trayMenu

# ================== Restore from backup ==================
function Show-RestoreDialog {
    $snapshots = Get-DSPESnapshots
    if ($snapshots.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No backups exist yet. Backups are created automatically before each remediation.", "Restore") | Out-Null
        return
    }
    $picker = New-Object System.Windows.Forms.Form
    $picker.Text = "Restore from backup"
    $picker.Size = New-Object System.Drawing.Size(520, 220)
    $picker.StartPosition = "CenterParent"
    $picker.FormBorderStyle = "FixedDialog"
    $lblPick = New-Object System.Windows.Forms.Label
    $lblPick.Text = "Select the backup to restore (newest first):"
    $lblPick.Location = New-Object System.Drawing.Point(15, 12)
    $lblPick.AutoSize = $true
    $picker.Controls.Add($lblPick)
    $combo = New-Object System.Windows.Forms.ComboBox
    $combo.DropDownStyle = "DropDownList"
    $combo.Size = New-Object System.Drawing.Size(470, 23)
    $combo.Location = New-Object System.Drawing.Point(15, 38)
    foreach ($s in $snapshots) { [void]$combo.Items.Add($s.Name) }
    $combo.SelectedIndex = 0
    $picker.Controls.Add($combo)
    $btnGo = New-Object System.Windows.Forms.Button
    $btnGo.Text = "Restore"
    $btnGo.Size = New-Object System.Drawing.Size(90, 30)
    $btnGo.Location = New-Object System.Drawing.Point(15, 75)
    $picker.Controls.Add($btnGo)
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Size = New-Object System.Drawing.Size(90, 30)
    $btnCancel.Location = New-Object System.Drawing.Point(115, 75)
    $picker.Controls.Add($btnCancel)
    $btnCancel.Add_Click({ $picker.Close() })
    $btnGo.Add_Click({
        $choice = [System.Windows.Forms.MessageBox]::Show(
            "Restore will revert every rule in this backup to its recorded pre-fix state.`n`nFile: $($combo.SelectedItem)`n`nContinue?",
            "Confirm Restore", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $lblStatus.Text = "Restoring backup, please wait..."
        $lblStatus.Refresh()
        try {
            $result = Restore-DSPESnapshot -SnapshotPath (Join-Path (Get-DSPEBackupDir) $combo.SelectedItem)
            Write-Log "Restore from $($combo.SelectedItem): $($result.Restored) restored, $($result.Skipped) skipped, $($result.Failed) failed." -Level $(if ($result.Failed -eq 0) { "SUCCESS" } else { "WARN" })
            $detail = ($result.Details | Select-Object -First 15) -join "`n"
            [System.Windows.Forms.MessageBox]::Show(
                "Restored: $($result.Restored)  |  Skipped: $($result.Skipped)  |  Failed: $($result.Failed)`n`n$detail",
                "Restore Complete") | Out-Null
            $picker.Close()
            # Re-scan so the grid reflects the restored state.
            $passMap = Invoke-FullScan
            Update-ComplianceLabel $passMap
        } catch {
            Write-Log "Restore failed: $($_.Exception.Message)" -Level ERROR
            [System.Windows.Forms.MessageBox]::Show("Restore failed: $($_.Exception.Message)", "Restore Error") | Out-Null
        }
    })
    [void]$picker.ShowDialog($form)
}
 $menuRestore.Add_Click({ Show-RestoreDialog })

 $showFromTray = {
    $form.Opacity = 1
    $form.ShowInTaskbar = $true
    $form.Show()
    $form.WindowState = "Normal"
    $form.Activate()
}
 $notifyIcon.Add_DoubleClick($showFromTray)
 $menuShow.Add_Click($showFromTray)
 $menuExit.Add_Click({
    $script:trulyExit = $true
    $monitorTimer.Stop()
    $notifyIcon.Visible = $false
    $form.Close()
})

# ================== Checkbox change wiring ==================
 $chkStartWithWindows.Add_CheckedChanged({
    Set-StartWithWindows $chkStartWithWindows.Checked
    Save-DSPESettings
})
 $chkStartMinimized.Add_CheckedChanged({ Save-DSPESettings })
 $chkMinimizeOnClose.Add_CheckedChanged({ Save-DSPESettings })
 $numMonitorInterval.Add_ValueChanged({
    $monitorTimer.Interval = [int]$numMonitorInterval.Value * 1000
    Save-DSPESettings
})

# ================== Close behavior (minimize to tray vs real exit) ==================
 $form.Add_FormClosing({
    param($s, $e)
    if (-not $script:trulyExit -and $chkMinimizeOnClose.Checked) {
        $e.Cancel = $true
        $form.Hide()
        $notifyIcon.ShowBalloonTip(1500, "Dynamic Security Policy Enforcer", "Still running in the system tray.", [System.Windows.Forms.ToolTipIcon]::Info)
    } else {
        $monitorTimer.Stop()
        $notifyIcon.Visible = $false
    }
})

 $lblStatus = New-Object System.Windows.Forms.Label
 $lblStatus.Text = "Ready."
 $lblStatus.AutoSize = $true
 $lblStatus.ForeColor = [System.Drawing.Color]::DimGray
 $lblStatus.Location = New-Object System.Drawing.Point(15, 90)
 $lblStatus.Name = "lblStatus"
 $bottomPanel.Controls.Add($lblStatus)

# ================== Rule grid ==================
 $grid = New-Object System.Windows.Forms.DataGridView
 $grid.Dock = "Fill"
 $grid.AllowUserToAddRows = $false
 $grid.AllowUserToDeleteRows = $false
 $grid.ReadOnly = $false
 $grid.RowHeadersVisible = $false
 $grid.SelectionMode = "FullRowSelect"
 $grid.AutoSizeColumnsMode = "Fill"
 $grid.Name = "grid"
 $form.Controls.Add($grid)
 $grid.BringToFront()

 $colSelected = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
 $colSelected.Name = "Selected"
 $colSelected.HeaderText = "On"
 $colSelected.Width = 40
 $colSelected.FillWeight = 8
 $grid.Columns.Add($colSelected) | Out-Null

 $colID = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
 $colID.Name = "ID"
 $colID.HeaderText = "ID"
 $colID.ReadOnly = $true
 $colID.FillWeight = 10
 $grid.Columns.Add($colID) | Out-Null

 $colCategory = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
 $colCategory.Name = "Category"
 $colCategory.HeaderText = "Category"
 $colCategory.ReadOnly = $true
 $colCategory.FillWeight = 16
 $grid.Columns.Add($colCategory) | Out-Null

 $colSeverity = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
 $colSeverity.Name = "Severity"
 $colSeverity.HeaderText = "Severity"
 $colSeverity.ReadOnly = $true
 $colSeverity.FillWeight = 12
 $grid.Columns.Add($colSeverity) | Out-Null

 $colCIS = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
 $colCIS.Name = "CIS_Ref"
 $colCIS.HeaderText = "CIS Ref"
 $colCIS.ReadOnly = $true
 $colCIS.FillWeight = 16
 $grid.Columns.Add($colCIS) | Out-Null

 $colDescription = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
 $colDescription.Name = "Description"
 $colDescription.HeaderText = "Description"
 $colDescription.ReadOnly = $true
 $colDescription.FillWeight = 40
 $grid.Columns.Add($colDescription) | Out-Null

 $colStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
 $colStatus.Name = "Status"
 $colStatus.HeaderText = "Status"
 $colStatus.ReadOnly = $true
 $colStatus.FillWeight = 12
 $grid.Columns.Add($colStatus) | Out-Null

# ================== Populate grid from policy.json ==================
foreach ($rule in $policy.rules) {
    $rowIndex = $grid.Rows.Add()
    $row = $grid.Rows[$rowIndex]
    $row.Cells["Selected"].Value = $false
    $row.Cells["ID"].Value = $rule.id
    $row.Cells["Category"].Value = $rule.category
    $row.Cells["Severity"].Value = $rule.severity
    $row.Cells["CIS_Ref"].Value = $rule.cis_ref
    $row.Cells["Description"].Value = $rule.description
    $row.Cells["Status"].Value = "Not scanned"
}

# ================== Helper: apply a severity-based preset ==================
function Set-Preset($severities) {
    foreach ($row in $grid.Rows) {
        $sev = $row.Cells["Severity"].Value
        $row.Cells["Selected"].Value = ($severities -contains $sev)
    }
    Update-SelectedCount
}

function Update-SelectedCount {
    $count = 0
    foreach ($row in $grid.Rows) {
        if ($row.Cells["Selected"].Value -eq $true) { $count++ }
    }
    $lblSelectedCount.Text = "$count of $($grid.Rows.Count) rules selected"
}

# Initial count once the grid has been populated.
Update-SelectedCount

# ================== Button wiring ==================
# Progress helpers - Show/Hide on the UI thread; Set sets 0..100.
function Show-Progress { $progressBar.Visible = $true; $progressBar.Value = 0; $progressBar.Refresh() }
function Hide-Progress { $progressBar.Value = 0; $progressBar.Visible = $false; $progressBar.Refresh() }
function Set-Progress([int]$Percent) {
    if ($Percent -lt 0) { $Percent = 0 } elseif ($Percent -gt 100) { $Percent = 100 }
    $progressBar.Value = $Percent
    $progressBar.Refresh()
    [System.Windows.Forms.Application]::DoEvents()
}

 $btnMinimal.Add_Click({ Set-Preset @("Critical") })
 $btnStandard.Add_Click({ Set-Preset @("Critical", "High") })
 $btnAdvanced.Add_Click({ Set-Preset @("Critical", "High", "Medium", "Low") })

 $btnApply.Add_Click({
    $lblStatus.Text = "Applying   scanning selected rules, please wait..."
    $lblStatus.Refresh()
    [System.Windows.Forms.Application]::DoEvents()

    $script:appliedIDs = @()
    foreach ($row in $grid.Rows) {
        if ($row.Cells["Selected"].Value -eq $true) { $script:appliedIDs += $row.Cells["ID"].Value }
    }
    $passMap = Invoke-FullScan
    Update-ComplianceLabel $passMap
    $script:lastPassState = @{} + $passMap
    Update-SelectedCount
    Save-DSPESettings
    $lblStatus.Text = "Applied at $(Get-Date -Format 'HH:mm:ss')   now monitoring $($script:appliedIDs.Count) rule(s)."
    Write-Log "Applied rule set: $($script:appliedIDs.Count) of $($grid.Rows.Count) rules now monitored." -Level INFO
})

 $btnRescan.Add_Click({
    $lblStatus.Text = "Rescanning all $($grid.Rows.Count) rules, please wait..."
    $lblStatus.Refresh()
    [System.Windows.Forms.Application]::DoEvents()
    Show-Progress
    try {
        $passMap = Invoke-FullScan
        Update-ComplianceLabel $passMap
        $lblStatus.Text = "Rescanned at $(Get-Date -Format 'HH:mm:ss')."
    } finally {
        Hide-Progress
    }
})

# ================== Fix selected rules ==================
# Fixes only the rules whose "On" checkbox is ticked (directly or via the
# preset buttons). Selected rules that are already passing are re-checked
# live and skipped; the rest are backed up, confirmed, then remediated one
# at a time. Critical rules ARE included since you selected them
# deliberately, but the confirmation dialog calls them out because
# account-policy changes can lock users out.
 $btnFix.Add_Click({
    # 1. Gather the selected rules.
    $selected = @()
    foreach ($row in $grid.Rows) {
        if ($row.Cells["Selected"].Value -eq $true) {
            $rule = $policy.rules | Where-Object { $_.id -eq $row.Cells["ID"].Value } | Select-Object -First 1
            if ($rule) { $selected += @{ Row = $row; Rule = $rule } }
        }
    }
    if ($selected.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No rules are selected.`n`nTick the 'On' checkbox next to the rules you want to fix (or use a preset), then click Fix.",
            "Fix") | Out-Null
        return
    }

    # 2. Re-check the selected rules live, so we only fix what is actually
    #    failing right now (and the grid shows fresh statuses).
    $lblStatus.Text = "Checking $($selected.Count) selected rule(s)..."
    $lblStatus.Refresh()
    [System.Windows.Forms.Application]::DoEvents()
    Reset-ScanCaches

    $toFix = @()
    $alreadyPassing = 0
    foreach ($item in $selected) {
        $r = Test-Rule $item.Rule
        $item.Row.Cells["Status"].Value = if ($r.Passed) { "PASS" } else { "FAIL" }
        $item.Row.DefaultCellStyle.BackColor = if ($r.Passed) { [System.Drawing.Color]::FromArgb(223, 246, 221) } else { [System.Drawing.Color]::FromArgb(252, 224, 224) }
        if ($null -ne $script:lastPassState) { $script:lastPassState[$item.Rule.id] = $r.Passed }
        if ($r.Passed) { $alreadyPassing++ } else { $toFix += $item }
    }

    if ($toFix.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "All $($selected.Count) selected rule(s) are already passing - nothing to fix.",
            "Fix") | Out-Null
        $lblStatus.Text = "Fix: all $($selected.Count) selected rule(s) already passing at $(Get-Date -Format 'HH:mm:ss')."
        return
    }

    # 3. Confirm exactly what will change.
    $critical = @($toFix | Where-Object { $_.Rule.severity -eq "Critical" })
    $listText = ($toFix | ForEach-Object { "  $($_.Rule.id) - $($_.Rule.description)" }) -join "`n"
    if ($listText.Length -gt 1800) { $listText = $listText.Substring(0, 1800) + "..." }
    $confirmText = "About to fix $($toFix.Count) selected rule(s). A backup will be taken first.`n`n$listText"
    if ($alreadyPassing -gt 0) { $confirmText += "`n`n($alreadyPassing selected rule(s) are already passing and will be skipped.)" }
    if ($critical.Count -gt 0) {
        $confirmText += "`n`nWARNING: $($critical.Count) Critical rule(s) included - account-policy changes can lock users out if unsuitable."
    }
    $confirmText += "`n`nContinue?"
    $confirm = [System.Windows.Forms.MessageBox]::Show($confirmText, "Fix Selected Rules",
        [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    # 4. Backup before touching anything.
    try {
        $backupPath = New-DSPESnapshot -Rules ($toFix | ForEach-Object { $_.Rule })
        if ($backupPath) {
            Write-Log "Pre-fix backup saved to $backupPath" -Level INFO
            Remove-OldDSPESnapshots -Keep 20
        } else {
            Write-Log "Fix backup captured no values (nothing restorable)." -Level WARN
        }
    } catch {
        Write-Log "Fix backup failed: $($_.Exception.Message)" -Level ERROR
        $abort = [System.Windows.Forms.MessageBox]::Show(
            "Backup failed - rollback will not be available for this run.`n`nContinue anyway?",
            "Backup Failed", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Error)
        if ($abort -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    # 5. Fix them one by one. Suppress the 5-second monitor while fixing so
    #    its ticks can't interleave scans with the remediation rechecks.
    $script:isMonitoring = $true
    Show-Progress
    $fixed = 0; $failedFixes = 0; $failedItems = @()
    try {
        for ($i = 0; $i -lt $toFix.Count; $i++) {
            $item = $toFix[$i]
            Set-Progress ([int](($i / $toFix.Count) * 100))
            $lblStatus.Text = "Fixing $($item.Rule.id) ($($i + 1) of $($toFix.Count))..."
            $lblStatus.Refresh()

            $result = Invoke-RuleRemediation $item.Rule
            if ($result.Success) {
                $fixed++
                $item.Row.Cells["Status"].Value = "PASS"
                $item.Row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(223, 246, 221)
                if ($null -ne $script:lastPassState) { $script:lastPassState[$item.Rule.id] = $true }
            } else {
                $failedFixes++
                $item.FailReason = $result.Reason
                $failedItems += $item
                Write-Log "Fix $($item.Rule.id) failed: $($result.Reason)" -Level ERROR
            }
        }
    } finally {
        $script:isMonitoring = $false
        Hide-Progress
    }

    # 6. Wrap up - refresh compliance and tell the user what failed and why.
    Update-ComplianceLabel (@{} + $script:lastPassState)
    Write-Log "Fix complete: $fixed succeeded, $failedFixes failed out of $($toFix.Count) selected failing rule(s)." -Level $(if ($failedFixes -eq 0) { "SUCCESS" } else { "WARN" })
    $lblStatus.Text = "Fix done at $(Get-Date -Format 'HH:mm:ss'): $fixed fixed, $failedFixes failed."

    if ($failedItems.Count -gt 0) {
        $details = ($failedItems | ForEach-Object { "$($_.Rule.id): $($_.FailReason)" }) -join "`n"
        if ($details.Length -gt 1200) { $details = $details.Substring(0, 1200) + "..." }
        [System.Windows.Forms.MessageBox]::Show(
            "Fixed: $fixed`nFailed: $failedFixes`n`nFailed rules:`n$details`n`nFull details are in the log.",
            "Fix Complete", [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
})

# ================== Export report (HTML / JSON / CSV) ==================
 $btnExport.Add_Click({
    # Snapshot the current grid state into result objects.
    $exportRows = @()
    foreach ($row in $grid.Rows) {
        $exportRows += [pscustomobject]@{
            ID = $row.Cells["ID"].Value; Description = $row.Cells["Description"].Value
            Category = $row.Cells["Category"].Value; CIS_Ref = $row.Cells["CIS_Ref"].Value
            Severity = $row.Cells["Severity"].Value; Status = $row.Cells["Status"].Value
        }
    }
    $total = $exportRows.Count
    $passed = ($exportRows | Where-Object { $_.Status -eq "PASS" }).Count
    $pct = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }
    $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $reportsDir = Get-DSPEPath -Which Reports

    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Title = "Export compliance report"
    $dlg.InitialDirectory = $reportsDir
    $dlg.FileName = "ComplianceExport_$stamp"
    $dlg.Filter = "HTML report (*.html)|*.html|JSON export (*.json)|*.json|CSV export (*.csv)|*.csv"
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        switch ([System.IO.Path]::GetExtension($dlg.FileName).ToLower()) {
            ".json" {
                $payload = [pscustomobject]@{
                    GeneratedAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
                    CompliancePercent = $pct
                    Passed = $passed
                    Total = $total
                    Rules = $exportRows
                }
                $payload | ConvertTo-Json -Depth 4 | Out-File -FilePath $dlg.FileName -Encoding UTF8
            }
            ".csv" {
                $exportRows | Export-Csv -Path $dlg.FileName -NoTypeInformation
            }
            default {
                # HTML with a score banner and per-category color coding.
                function esc([string]$t) { [System.Net.WebUtility]::HtmlEncode($t) }
                $scoreColor = if ($pct -ge 90) { "#2ecc71" } elseif ($pct -ge 60) { "#f39c12" } else { "#e74c3c" }
                $rowsHtml = ""
                foreach ($r in $exportRows) {
                    $color = if ($r.Status -eq "PASS") { "green" } elseif ($r.Status -eq "FAIL") { "red" } else { "gray" }
                    $rowsHtml += "<tr class='$color'><td>$(esc $r.ID)</td><td>$(esc $r.Severity)</td><td>$(esc $r.Category)</td><td>$(esc $r.CIS_Ref)</td><td>$(esc $r.Description)</td><td>$(esc $r.Status)</td></tr>`n"
                }
                $html = @"
<!DOCTYPE html>
<html><head><title>DSPE Compliance Report</title><style>
body { font-family: Segoe UI, Arial; background:#f4f4f4; padding:30px; }
.score { font-size: 42px; font-weight: bold; color: $scoreColor; }
table { border-collapse: collapse; width: 100%; margin-top: 20px; background: white; }
th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 13px; }
th { background: #7A2330; color: white; }
tr.green { background: #e6f9e6; } tr.red { background: #fdeaea; } tr.gray { background: #f0f0f0; }
</style></head><body>
<h1>DSPE Compliance Report</h1>
<p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<div class='score'>$pct%</div>
<p>$passed of $total rules passing</p>
<table><tr><th>ID</th><th>Severity</th><th>Category</th><th>CIS Ref</th><th>Description</th><th>Status</th></tr>
 $rowsHtml</table></body></html>
"@
                $html | Out-File -FilePath $dlg.FileName -Encoding UTF8
            }
        }
        Write-Log "Report exported to $($dlg.FileName) ($pct% compliance)." -Level SUCCESS
        $lblStatus.Text = "Report exported: $($dlg.FileName)"
    } catch {
        Write-Log "Export failed: $($_.Exception.Message)" -Level ERROR
        [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Export Error") | Out-Null
    }
})

 $grid.Add_CellValueChanged({
    if ($_.ColumnIndex -eq 0) { Update-SelectedCount }
})
 $grid.Add_CurrentCellDirtyStateChanged({
    if ($grid.IsCurrentCellDirty) { $grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) }
})

# ================== Single-rule remediation (shared engine) ==================
# The fix dispatch itself lives in Common.psm1 (Invoke-DSPESettingFix) so the
# GUI, the CLI and the restore path share ONE implementation - no more drift.
# This wrapper adds the GUI-specific parts: cache invalidation and re-check.
function Invoke-RuleRemediation($rule) {
    $result = Invoke-DSPESettingFix -Rule $rule

    if ($rule.check_type -eq "secedit") {
        # Refresh the cached secedit export so the re-check below reads the
        # new value instead of the pre-fix one.
        $script:seceditLines = Export-Secedit
        $script:seceditAttempted = $true
    }

    if (-not $result.Success) { return @{ Success = $false; Reason = $result.Reason } }

    # Invalidate the cached firewall/auditpol state so the recheck below reads
    # LIVE values instead of the pre-fix snapshot from the last scan pass.
    # Without this, a fix command can succeed yet still verify as "still
    # failing" because the recheck compared against stale cached data.
    $script:fwProfileCache = $null
    $script:fwProfileAttempted = $false
    $script:auditpolCache = $null
    $script:auditpolAttempted = $false

    Start-Sleep -Milliseconds 300
    try { $recheck = Test-Rule $rule } catch { $recheck = @{ Actual = "Error"; Passed = $false } }
    return @{ Success = $recheck.Passed; Actual = $recheck.Actual; Reason = if (-not $recheck.Passed) { "Command ran but setting still does not match (actual: $($recheck.Actual))" } else { "" } }
}

 $rowContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
 $menuRemediate = $rowContextMenu.Items.Add("Remediate this rule")
 $menuRemediate.Add_Click({
    if ($grid.SelectedRows.Count -eq 0) { return }
    $row = $grid.SelectedRows[0]
    $id = $row.Cells["ID"].Value
    if ($row.Cells["Status"].Value -ne "FAIL") {
        [System.Windows.Forms.MessageBox]::Show("$id is already passing - nothing to remediate.", "Remediate") | Out-Null
        return
    }
    $rule = $policy.rules | Where-Object { $_.id -eq $id } | Select-Object -First 1
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Apply this fix now?`n`n$($rule.description)`n`nFix: $($rule.remediation)",
        "Confirm Remediation", [System.Windows.Forms.MessageBoxButtons]::YesNo)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $lblStatus.Text = "Remediating $id ..."
    $lblStatus.Refresh()
    [System.Windows.Forms.Application]::DoEvents()

    $result = Invoke-RuleRemediation $rule
    if ($result.Success) {
        $row.Cells["Status"].Value = "PASS"
        $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(223, 246, 221)
        $lblStatus.Text = "$id fixed and verified at $(Get-Date -Format 'HH:mm:ss')."
        Write-Log "Remediation $id applied and verified - now PASS." -Level SUCCESS
        if ($null -ne $script:lastPassState) { $script:lastPassState[$id] = $true }
    } else {
        $lblStatus.Text = "$id fix failed: $($result.Reason)"
        Write-Log "Remediation $id failed: $($result.Reason)" -Level ERROR
        [System.Windows.Forms.MessageBox]::Show("Fix failed: $($result.Reason)", "Remediation Failed") | Out-Null
    }
    if ($script:appliedIDs -contains $id) {
        Update-ComplianceLabel (@{} + $script:lastPassState)
    }
})
 $grid.Add_CellMouseDown({
    param($s, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right -and $e.RowIndex -ge 0) {
        $grid.ClearSelection()
        $grid.Rows[$e.RowIndex].Selected = $true
        $rowContextMenu.Show($grid, $e.Location)
    }
})

# ================== 5-second monitoring of the applied rule set ==================
 $script:lastPassState = @{}
 $script:isMonitoring = $false

 $monitorTimer = New-Object System.Windows.Forms.Timer
 # Interval comes from the persisted setting (5-3600 s; default 5 s).
 $monitorTimer.Interval = [int]$numMonitorInterval.Value * 1000

 $monitorTimer.Add_Tick({
    if ($script:isMonitoring -or $script:appliedIDs.Count -eq 0) { return }
    $script:isMonitoring = $true
    try {
        Reset-ScanCaches
        $changed = @()
        foreach ($row in $grid.Rows) {
            $id = $row.Cells["ID"].Value
            if ($script:appliedIDs -notcontains $id) { continue }
            $rule = $policy.rules | Where-Object { $_.id -eq $id } | Select-Object -First 1
            if (-not $rule) { continue }
            # One broken rule must not abort the monitoring tick.
            try { $r = Test-Rule $rule } catch { $r = @{ Actual = "Error"; Passed = $false } }
            $row.Cells["Status"].Value = if ($r.Passed) { "PASS" } else { "FAIL" }
            $row.DefaultCellStyle.BackColor = if ($r.Passed) { [System.Drawing.Color]::FromArgb(223, 246, 221) } else { [System.Drawing.Color]::FromArgb(252, 224, 224) }

            $prev = $script:lastPassState[$id]
            if ($null -ne $prev -and $prev -ne $r.Passed) {
                $changed += [pscustomobject]@{ ID = $id; Description = $rule.description; NowPassing = $r.Passed }
            }
            $script:lastPassState[$id] = $r.Passed
        }
        Update-ComplianceLabel $script:lastPassState

        if ($changed.Count -gt 0) {
            $worsened = $changed | Where-Object { -not $_.NowPassing }
            $improved = $changed | Where-Object { $_.NowPassing }
            if ($worsened.Count -gt 0) {
                Write-Log "Compliance drift: $($worsened.Count) rule(s) started failing: $(($worsened | ForEach-Object { $_.ID }) -join ', ')" -Level WARN
                $msg = ($worsened | ForEach-Object { "$($_.ID): $($_.Description)" }) -join "`n"
                if ($msg.Length -gt 250) { $msg = $msg.Substring(0, 250) + "..." }
                $notifyIcon.ShowBalloonTip(4000, "Compliance drift detected", $msg, [System.Windows.Forms.ToolTipIcon]::Warning)
            }
            if ($improved.Count -gt 0 -and $worsened.Count -eq 0) {
                $notifyIcon.ShowBalloonTip(3000, "Compliance improved", "$($improved.Count) rule(s) now passing.", [System.Windows.Forms.ToolTipIcon]::Info)
            }
        }
        $lblStatus.Text = "Last monitored at $(Get-Date -Format 'HH:mm:ss')   watching $($script:appliedIDs.Count) rule(s)."
    } finally {
        $script:isMonitoring = $false
    }
})

# ================== Initial scan on first run ==================
# Wired to Load (fires before the window is painted) instead of Shown (fires
# after) so a "start minimized" launch hides before anything is ever drawn on
# screen - no more visible flash of the window before it drops into the tray.
 $lblStatus.Text = "Running initial scan of all $($grid.Rows.Count) rules, please wait..."
 $form.Add_Load({
    if ($chkStartMinimized.Checked) { $form.Hide() }

    $lblStatus.Refresh()
    [System.Windows.Forms.Application]::DoEvents()

    # Restore checkbox state in the grid for whatever was applied last session
    if ($script:appliedIDs.Count -gt 0) {
        foreach ($row in $grid.Rows) {
            $row.Cells["Selected"].Value = ($script:appliedIDs -contains $row.Cells["ID"].Value)
        }
        Update-SelectedCount
    }

    $script:initialPassMap = Invoke-FullScan
    Update-ComplianceLabel $script:initialPassMap
    $script:lastPassState = @{} + $script:initialPassMap
    Write-Log "Initial scan complete: $(($script:initialPassMap.Values | Where-Object { $_ }).Count) of $($script:initialPassMap.Count) rules passing." -Level INFO
    $monitorTimer.Start()

    if ($script:appliedIDs.Count -gt 0) {
        $lblStatus.Text = "Initial scan complete at $(Get-Date -Format 'HH:mm:ss'). Resumed monitoring $($script:appliedIDs.Count) previously-applied rule(s)."
    } else {
        $lblStatus.Text = "Initial scan complete at $(Get-Date -Format 'HH:mm:ss'). Select a preset and click Apply to start monitoring."
    }

    if ($chkStartMinimized.Checked) {
        $notifyIcon.ShowBalloonTip(1500, "Dynamic Security Policy Enforcer", "Running in the system tray.", [System.Windows.Forms.ToolTipIcon]::Info)
    }
})



# ================== Show ==================
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::Run($form)
# DSPE — Dynamic Security Policy Enforcer

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011-blue)](#requirements)
[![Shell](https://img.shields.io/badge/shell-PowerShell%205.1-5391FE)](#requirements)
[![Benchmark](https://img.shields.io/badge/benchmark-CIS%20Win11%20v5.0.0-red)](#whats-checked)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**DSPE** is a Windows security hardening and compliance tool built around the [CIS Microsoft Windows 11 Benchmark v5.0.0](https://www.cisecurity.org/cis-benchmarks). It audits **247 security settings** across six policy categories, reports a per-category compliance score, can remediate failing settings one by one with your confirmation, and continuously monitors the rules you apply so you know the moment a setting drifts back.

It ships as both a **point-and-click GUI** (system-tray capable) and a **CLI** that is scriptable and CI/scheduled-task friendly, with automatic pre-remediation snapshots so every fix can be rolled back.

> ## ⚠️ Read Before Use
>
> - DSPE **modifies real system security settings** (password policy, registry, services, firewall, audit policy). An incorrect policy can lock you out or break functionality.
> - Always run with a **pre-remediation snapshot** available (DSPE creates one automatically) and know how to use **Restore** before you start fixing.
> - Test on a **VM or non-critical machine** before applying it to a production or daily-use system.
> - **Administrator privileges are required** — `secedit`, `auditpol`, `net accounts`, and firewall commands all need elevation.

---

## Features

- **247 CIS-mapped rules** across Account Policy, Security Options, Administrative Templates, Services, Firewall, and Advanced Audit Policy — each with severity, CIS reference, expected value, and a remediation hint.
- **Dual interface** — a WinForms GUI with a live compliance grid, or a CLI (`Run-PolicyCheck.ps1 -Scan [-Remediate]`).
- **Scan → Fix → Re-verify loop** — every applied fix is re-checked against the live system instead of trusting the command's exit code, so a "successful" command that didn't actually change anything is still reported as failing.
- **Severity presets** — one click selects *Minimal*, *Standard*, or *Advanced* rule sets based on rule severity.
- **Continuous monitoring** — applied rules are re-checked on a configurable interval; compliance drift triggers a system-tray balloon notification and a WARN entry in the log.
- **Automatic snapshots** — before any remediation, the pre-fix state of every affected rule is saved to `Backups/` and can be restored per snapshot from the GUI or CLI.
- **Firewall watchdog** — `Monitor-Firewall.ps1` subscribes to CIM events and alerts in real time when any firewall profile (Domain / Private / Public) is disabled.
- **HTML dashboard** — `Generate-Dashboard.ps1` turns your scan history into a local `Dashboard.html` trend view.
- **Machine-readable reports** — every scan writes a CSV (human-readable) and JSON (machine-readable) report; the CLI exit code reflects compliance so scheduled tasks and CI pipelines can react to failures.
- **Schema-validated policy** — `policy.json` is validated at load time, so a malformed custom rule fails loudly with a clear message instead of silently skipping checks.

## What's Checked

| Category | Rules | Check method |
|---|---:|---|
| Administrative Templates (registry) | 92 | `Get-ItemProperty` |
| Security Options | 59 | `secedit /export` parsing & registry |
| Services | 44 | `Get-Service` startup type |
| Advanced Audit Policy | 27 | `auditpol /get /subcategory` |
| Firewall | 15 | `Get-NetFirewallProfile` |
| Account Policy | 10 | `secedit` (password/lockout policy) |
| **Total** | **247** | |

**Severity mix:** 17 Critical · 79 High · 112 Medium · 39 Low

Supported comparison operators: `eq`, `gte`, `lte`, `range` (min/max), `contains`.

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 (the version built into Windows — no extra installs)
- Administrator privileges for checks and remediation
- No external modules or dependencies

## Getting Started

### 1. Get the code

```powershell
git clone https://github.com/<you>/DSPE.git
cd DSPE
```

…or download and extract the ZIP from **Releases**.

### 2. Unblock the files (one time)

Files downloaded from the internet carry the Windows *Mark of the Web*, which can block script execution. From an elevated PowerShell, run the bundled helper once:

```powershell
powershell -ExecutionPolicy Bypass -File .\Unblock-DSPE.ps1
```

### 3. Run it

```powershell
# GUI
powershell -ExecutionPolicy Bypass -File .\DSPE-GUI.ps1

# CLI scan only
powershell -ExecutionPolicy Bypass -File .\Run-PolicyCheck.ps1 -Scan
```

The GUI detects a non-elevated launch and offers to restart itself elevated.

## Usage

### GUI (`DSPE-GUI.ps1`)

1. On launch, DSPE scans all 247 rules and color-codes each row (green = PASS, red = FAIL).
2. Pick a preset (**Minimal / Standard / Advanced**) or tick rules individually.
3. Click **Apply** to start continuous monitoring of the selected rules — drift is flagged in the tray.
4. Use **Fix** to remediate selected failing rules, **Rescan Now** for a fresh scan, and **Export Report** to save results.
5. The restore dialog lets you browse and roll back to any previous snapshot.
6. Options: *Start with Windows*, *Start minimized*, *Minimize on close*, and the monitoring interval.

### CLI (`Run-PolicyCheck.ps1`)

```powershell
# Scan only — prints a per-category summary with PASS/FAIL per rule
.\Run-PolicyCheck.ps1 -Scan

# Scan + interactive remediation: shows each fix, asks Y/N, snapshots first,
# re-verifies after applying
.\Run-PolicyCheck.ps1 -Scan -Remediate
```

Exit codes: `0` = all rules pass, `1` = at least one failure, `2` = policy failed to load.

### Dashboard (`Generate-Dashboard.ps1`)

```powershell
.\Generate-Dashboard.ps1          # generates and opens Reports\Dashboard.html
.\Generate-Dashboard.ps1 -NoOpen  # for scheduled runs
```

### Firewall watchdog (`Monitor-Firewall.ps1`)

```powershell
.\Monitor-Firewall.ps1             # real-time CIM event watch, Ctrl+C to stop
.\Monitor-Firewall.ps1 -PollSeconds 5
```

## Backups & Rollback

Before any remediation (CLI or GUI), DSPE snapshots the pre-fix state of every rule that may be touched into `Backups\` and keeps the last 20 snapshots. Each snapshot captures the original values for the exact check types involved (secedit INF state, registry values, service startup types, firewall profile flags, auditpol subcategories). Restoring a snapshot re-applies those original values and verifies the result — so any fix can be undone.

## Reports & Logs

| Path | Contents |
|---|---|
| `Reports\ScanReport_*.csv` | Human-readable scan results (one row per rule) |
| `Reports\ScanReport_*.json` | Same data + compliance percentage, for CI/CD |
| `Reports\Dashboard.html` | Trend dashboard generated from scan history |
| `Logs\` | Daily log files (older logs auto-trimmed) |
| `Backups\` | Pre-remediation snapshots |

All folders are created automatically on first run and are safe to delete while DSPE is not running.

## Automation

The CLI is designed for scheduled tasks and CI:

```powershell
# Example: nightly scan at 03:00, log failures via the non-zero exit code
schtasks /create /tn "DSPE Nightly Scan" /sc daily /st 03:00 /rl highest ^
  /tr "powershell -NoProfile -ExecutionPolicy Bypass -File C:\DSPE\Run-PolicyCheck.ps1 -Scan"
```

Pair it with `Generate-Dashboard.ps1 -NoOpen` afterwards to refresh the dashboard unattended.

## Adding Your Own Rules

Append objects to the `rules` array in `Policies\policy.json`. The schema is validated on load, so typos surface immediately. A rule looks like this:

```json
{
    "id": "REG-999",
    "description": "Prevent users from changing network location",
    "category": "Administrative Templates",
    "severity": "Medium",
    "cis_ref": "CIS 9.3.5 (L1)",
    "check_type": "registry",
    "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
    "name": "NC_ReadOnly",
    "operator": "eq",
    "expected": 1,
    "remediation": "Set the registry value to 1"
}
```

Check types and their required fields:

| `check_type` | Fields |
|---|---|
| `secedit` | `key` |
| `registry` | `path`, `name` |
| `service` | `service_name` |
| `auditpol` | `subcategory` |
| `firewall` | — (all profiles enabled) |
| `firewall_property` | `profile`, `property` |

## Project Structure

```
DSPE/
├── DSPE-GUI.ps1              # WinForms GUI: scan grid, presets, fix, tray monitoring
├── Run-PolicyCheck.ps1       # CLI: -Scan [-Remediate], CSV/JSON reports, exit codes
├── Generate-Dashboard.ps1    # Builds Reports\Dashboard.html from scan history
├── Monitor-Firewall.ps1      # Real-time firewall profile watchdog (CIM events)
├── Unblock-DSPE.ps1          # One-time Mark-of-the-Web cleanup
├── Common.psm1               # Shared framework: paths, logging, elevation,
│                             #   policy schema validation, fix dispatch
├── Backup-Restore.psm1       # Snapshot creation, restore, retention
├── Collectors/
│   ├── Check-Firewall.ps1          # Standalone firewall check
│   └── Check-PasswordLength.ps1    # Standalone password-length check
└── Policies/
    └── policy.json           # 247 CIS-mapped rules (the policy database)
```

`Reports\`, `Logs\`, and `Backups\` are generated at runtime and intentionally not committed — see `.gitignore`.

## Contributing

Issues and pull requests are welcome. When contributing new rules, please:

1. Follow the rule schema above and keep IDs unique and prefixed by category (`ACC-`, `SO-`, `REG-`, `SVC-`, `FW-`, `AUD-`, `ADM-`).
2. Include the correct CIS reference and severity.
3. Test the rule on a clean Windows 11 VM — verify both the failing and remediated states.

## License

Released under the [MIT License](LICENSE).

## Acknowledgments

Rule definitions are based on the [CIS Microsoft Windows 11 Benchmark v5.0.0](https://www.cisecurity.org/cis-benchmarks) published by the [Center for Internet Security](https://www.cisecurity.org). DSPE is an independent tool and is not affiliated with or endorsed by CIS.

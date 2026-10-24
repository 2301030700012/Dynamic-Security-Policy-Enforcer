# Unblock-DSPE.ps1 - removes the Windows "Mark of the Web" from all DSPE files.
#
# Files extracted from a ZIP downloaded from the internet are flagged by
# Windows as downloaded content. Depending on your PowerShell execution
# policy, running or importing flagged files produces errors such as:
#   "... is not digitally signed" / "is not recognized as a name of a cmdlet"
#
# Run this ONCE after extracting the DSPE folder, from an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\Unblock-DSPE.ps1

Get-ChildItem -Path $PSScriptRoot -Recurse -File | Unblock-File
Write-Host "All DSPE files unblocked. You can now run DSPE normally." -ForegroundColor Green

# Master Script to trigger all 5 Analyzer Reports
$scriptPath = "C:\PROG\New folder"

Write-Host "Starting Automated Report Generation..." -ForegroundColor Cyan

& "$scriptPath\Hourly.ps1"
& "$scriptPath\Inlet_N2O_Cal.ps1"
& "$scriptPath\Inlet_N2O_Linearity.ps1"
& "$scriptPath\Outlet_N2O_Cal.ps1"
& "$scriptPath\Outlet_N2O_Linearity.ps1"

Write-Host "All reports processed." -ForegroundColor Green
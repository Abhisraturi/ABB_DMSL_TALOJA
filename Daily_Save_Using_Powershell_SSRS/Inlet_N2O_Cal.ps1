# Configuration
$baseUrl = "http://desktop-f4fk4gn/ReportServer/Pages/ReportViewer.aspx?%2fANALYSER_REPORT%2fN%e2%82%82O+Abator+Inlet+Calibration"
$saveDir = "C:\Users\Dell\OneDrive\Documents\Saved_Reports"

# Dates
$target = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")
$ts = (Get-Date).ToString("dd_MM_yyyy_HH-mm-ss")

# Execution
$finalUrl = "$baseUrl&TargetDate=$target&rs:Command=Render&rs:Format=PDF"
$path = Join-Path $saveDir "N2O_Abator_Inlet_Calibration_$($ts).pdf"

if (!(Test-Path $saveDir)) { New-Item -ItemType Directory -Path $saveDir }
Invoke-WebRequest -Uri $finalUrl -OutFile $path -UseDefaultCredentials
Write-Host "Saved: $path" -ForegroundColor Green
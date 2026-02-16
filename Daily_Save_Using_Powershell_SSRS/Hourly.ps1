# Configuration
$baseUrl = "http://desktop-f4fk4gn/ReportServer/Pages/ReportViewer.aspx?%2fANALYSER_REPORT%2fAnalyser+Hourly"
$saveDir = "C:\Users\Dell\OneDrive\Documents\Saved_Reports"

# Dates
$start = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")
$end = (Get-Date).ToString("yyyy-MM-dd")
$ts = (Get-Date).ToString("dd_MM_yyyy_HH-mm-ss")

# Execution
$finalUrl = "$baseUrl&StartDate=$start&EndDate=$end&rs:Command=Render&rs:Format=PDF"
$path = Join-Path $saveDir "Analyser_Hourly_$($ts).pdf"

if (!(Test-Path $saveDir)) { New-Item -ItemType Directory -Path $saveDir }
Invoke-WebRequest -Uri $finalUrl -OutFile $path -UseDefaultCredentials
Write-Host "Saved: $path" -ForegroundColor Green
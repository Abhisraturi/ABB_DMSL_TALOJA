# --- Configuration ---
# Report: N₂O Abator Outlet (Stack) Calibration
$baseUrl = "http://desktop-f4fk4gn/ReportServer/Pages/ReportViewer.aspx?%2fANALYSER_REPORT%2fN%e2%82%82O+Abator+Outlet+(Stack)+Calibration"
$saveDir = "C:\Users\Dell\OneDrive\Documents\Saved_Reports"

# --- Date Calculation ---
# TargetDate set to Yesterday
$targetDate = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")

# --- Precise Filename Generation ---
# We clean up special characters for the filename to avoid Windows errors
$ts = (Get-Date).ToString("dd_MM_yyyy_HH-mm-ss")
$cleanName = "N2O_Abator_Outlet_Stack_Calibration"
$fileName = "$($cleanName)_$($ts).pdf"
$fullPath = Join-Path $saveDir $fileName

# --- Construct the Full SSRS URL ---
$finalUrl = "$baseUrl&TargetDate=$targetDate&rs:Command=Render&rs:Format=PDF"

# --- Execution ---
try {
    # Ensure directory exists
    if (!(Test-Path $saveDir)) { 
        New-Item -ItemType Directory -Path $saveDir | Out-Null 
    }

    Write-Host "Fetching Outlet Stack Calibration Report for: $targetDate" -ForegroundColor Cyan
    
    # Download using Windows Authentication
    Invoke-WebRequest -Uri $finalUrl -OutFile $fullPath -UseDefaultCredentials
    
    if (Test-Path $fullPath) {
        Write-Host "Success! Saved to: $fullPath" -ForegroundColor Green
    }
}
catch {
    Write-Host "Error: Could not generate the Outlet Stack Calibration report." -ForegroundColor Red
    $_.Exception.Message
}
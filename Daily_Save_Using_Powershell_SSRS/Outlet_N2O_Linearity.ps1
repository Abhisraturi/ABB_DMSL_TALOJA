# --- Configuration ---
# Report: N₂O Abator Outlet (Stack) Linearity
$baseUrl = "http://desktop-f4fk4gn/ReportServer/Pages/ReportViewer.aspx?%2fANALYSER_REPORT%2fN%e2%82%82O+Abator+Outlet+(Stack)+Linearity"
$saveDir = "C:\Users\Dell\OneDrive\Documents\Saved_Reports"

# --- Date Calculation ---
# Setting the 'Date' parameter to Yesterday (YYYY-MM-DD)
$reportDate = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")

# --- Precise Filename Generation ---
# Using a "Bigger and Precise" name for the stack linearity report
$ts = (Get-Date).ToString("dd_MM_yyyy_HH-mm-ss")
$cleanName = "N2O_Abator_Outlet_Stack_Linearity"
$fileName = "$($cleanName)_$($ts).pdf"
$fullPath = Join-Path $saveDir $fileName

# --- Construct the Full SSRS URL ---
# Using your exact parameter name: Date
$finalUrl = "$baseUrl&Date=$reportDate&rs:Command=Render&rs:Format=PDF"

# --- Execution ---
try {
    # Ensure directory exists
    if (!(Test-Path $saveDir)) { 
        New-Item -ItemType Directory -Path $saveDir | Out-Null 
    }

    Write-Host "Fetching Outlet Stack Linearity Report for: $reportDate" -ForegroundColor Cyan
    
    # Download using Windows Authentication (current logged-in user)
    Invoke-WebRequest -Uri $finalUrl -OutFile $fullPath -UseDefaultCredentials
    
    if (Test-Path $fullPath) {
        Write-Host "Success! Precise report saved to: $fullPath" -ForegroundColor Green
    }
}
catch {
    Write-Host "Error: Check if the 'Date' parameter is correct in SSRS." -ForegroundColor Red
    $_.Exception.Message
}
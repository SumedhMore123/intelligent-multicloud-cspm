$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\Scripts\python.exe"
$dashboardUrl = "http://127.0.0.1:8000/code/index.html"
$apiUrl = "http://127.0.0.1:8765/api/health"
$logDirectory = Join-Path $root ".dashboard-logs"

if (-not (Test-Path $python)) {
    throw "Python virtual environment not found at $python"
}

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

try {
    Invoke-WebRequest -UseBasicParsing -Uri $apiUrl -TimeoutSec 2 | Out-Null
} catch {
    Start-Process `
        -FilePath $python `
        -ArgumentList "-m backend.server" `
        -WorkingDirectory $root `
        -WindowStyle Minimized `
        -RedirectStandardOutput (Join-Path $logDirectory "backend.log") `
        -RedirectStandardError (Join-Path $logDirectory "backend-error.log")
}

try {
    Invoke-WebRequest -UseBasicParsing -Uri $dashboardUrl -TimeoutSec 2 | Out-Null
} catch {
    Start-Process `
        -FilePath $python `
        -ArgumentList "-m http.server 8000 --directory Dashboard" `
        -WorkingDirectory $root `
        -WindowStyle Minimized `
        -RedirectStandardOutput (Join-Path $logDirectory "dashboard.log") `
        -RedirectStandardError (Join-Path $logDirectory "dashboard-error.log")
}

Start-Sleep -Milliseconds 500
Start-Process $dashboardUrl

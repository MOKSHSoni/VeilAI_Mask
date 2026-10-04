# Start VeilAI_Mask on http://127.0.0.1:8765 (local only) and open the browser.
#   powershell -ExecutionPolicy Bypass -File start.ps1
Set-Location $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"
Start-Process "http://127.0.0.1:8765"
.\.venv\Scripts\python.exe -m veilai_mask serve --port 8765

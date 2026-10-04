# One-time setup for VeilAI_Mask on Windows (PowerShell). Needs Python 3.11+ and Ollama.
#   powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "1/4  Python environment"
if (-not (Test-Path .venv)) { python -m venv .venv }
.\.venv\Scripts\python.exe -m pip install --upgrade pip -q

Write-Host "2/4  Packages (PyTorch CPU build is ~200 MB)"
.\.venv\Scripts\python.exe -m pip install -q torch --index-url https://download.pytorch.org/whl/cpu
.\.venv\Scripts\python.exe -m pip install -q -r requirements.txt
.\.venv\Scripts\python.exe -m spacy download en_core_web_sm -q

Write-Host "3/4  Base model (Qwen3 4B, ~2.5 GB, skipped if present)"
ollama pull qwen3:4b-instruct-2507-q4_K_M

Write-Host "4/4  Create the veilai_mask model from ./Modelfile"
ollama create veilai_mask -f Modelfile

Write-Host "`nDone. Start with:  powershell -ExecutionPolicy Bypass -File start.ps1"

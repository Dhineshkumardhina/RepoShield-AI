# Launch RepoShield AI Backend Server (FastAPI + Uvicorn)
Write-Host "Starting RepoShield AI FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Cyan
Write-Host "Interactive API Docs available at: http://127.0.0.1:8000/docs" -ForegroundColor Green

$env:PYTHONPATH = "backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

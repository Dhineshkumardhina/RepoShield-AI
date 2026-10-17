# Setup Script for RepoShield AI (Windows PowerShell)
# Xerova Digital Solutions

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " RepoShield AI - Local Environment Bootstrap" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Prepare .env file if missing
if (-not (Test-Path ".env")) {
    Write-Host "[1/4] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
} else {
    Write-Host "[1/4] Existing .env detected." -ForegroundColor Green
}

# 2. Install backend dependencies
Write-Host "[2/4] Installing backend dependencies..." -ForegroundColor Yellow
py -3.12 -m pip install -r backend/requirements.txt

# 3. Run database migrations
Write-Host "[3/4] Running Alembic database migrations..." -ForegroundColor Yellow
$env:PYTHONPATH = "backend"
py -3.12 -m alembic -c backend/alembic.ini upgrade head

# 4. Install frontend dependencies
Write-Host "[4/4] Installing frontend npm packages..." -ForegroundColor Yellow
npm.cmd --prefix frontend install

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " Setup complete! You can now start the services:" -ForegroundColor Green
Write-Host " Backend:  .\scripts\run_backend.ps1" -ForegroundColor Cyan
Write-Host " Frontend: .\scripts\run_frontend.ps1" -ForegroundColor Cyan
Write-Host " Tests:    .\scripts\run_tests.ps1" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green

# Run Automated Test Suites (Backend Pytest + Frontend Vitest)
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Running Backend Pytest Suite..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

python -m pytest tests/
$backendExit = $LASTEXITCODE

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Running Frontend Vitest Suite..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

npm.cmd --prefix frontend run test
$frontendExit = $LASTEXITCODE

if ($backendExit -ne 0 -or $frontendExit -ne 0) {
    Write-Host "`n[ERROR] Test suite failure detected." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n[SUCCESS] All backend and frontend test suites passed!" -ForegroundColor Green
    exit 0
}

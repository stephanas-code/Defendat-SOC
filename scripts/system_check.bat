@echo off
echo AI Anomaly IDS - System Health Check
echo =====================================
echo.

REM Check if backend is running
curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    echo [FAILED] Backend is not running at http://localhost:8000
    echo Please start the backend first using: docker-compose up backend
    exit /b 1
)

echo [OK] Backend is running
echo.

REM Check detailed status
echo Checking component status...
curl -s http://localhost:8000/status
echo.

echo.
echo =====================================
echo For detailed health check, run:
echo   python scripts\system_check.py
echo.
echo Dashboard: http://localhost:3000
echo API Status: http://localhost:8000/status
echo =====================================

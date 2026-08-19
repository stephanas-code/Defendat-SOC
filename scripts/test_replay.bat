@echo off
echo Testing artifact data replay...
echo This will replay the Global_Cybersecurity_Threats_2015-2024.csv data to the dashboard
echo.

REM Check if backend is running
curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Backend is not running at http://localhost:8000
    echo Please start the backend first using: docker-compose up backend
    exit /b 1
)

echo Backend is running. Starting data replay...
echo.

python scripts\replay_global_threats_csv.py --csv artifacts\Global_Cybersecurity_Threats_2015-2024.csv --backend http://localhost:8000 --rate 5

if %errorlevel% equ 0 (
    echo.
    echo SUCCESS: Data replay completed. Check the dashboard at http://localhost:3000
) else (
    echo.
    echo ERROR: Data replay failed. Check the error messages above.
    exit /b 1
)

@echo off
echo ========================================
echo   Fingerprint Scanner Desktop Bridge
echo ========================================
echo.

REM Check for venv
if not exist "venv\Scripts\activate.bat" (
    echo Virtual environment not found. Creating one...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo.
    echo Installing required packages...
    call "venv\Scripts\pip.exe" install -r requirements.txt
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install required packages.
        pause
        exit /b 1
    )
    echo.
)

echo Activating virtual environment...
call "venv\Scripts\activate.bat"

echo.
echo Starting Desktop Bridge App...
echo Server will run on: http://127.0.0.1:8080
echo.
python http_server_fingerprint_scanner.py

echo.
echo Deactivating virtual environment...
call "venv\Scripts\deactivate.bat"

echo.
echo Desktop Bridge stopped.
pause
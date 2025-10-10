@echo off
REM Production startup script for netops-tools (Windows)

echo ==============================================
echo Starting NetOps Tools - Production Mode
echo ==============================================
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo X Virtual environment not found!
    echo Please create it first with: python -m venv venv
    pause
    exit /b 1
)

REM Activate virtual environment
echo / Activating virtual environment...
call venv\Scripts\activate.bat

REM Check if .env exists
if not exist ".env" (
    echo Warning: .env file not found!
    echo Please create .env file with production settings
    echo See DEPLOYMENT.md for details
    pause
    exit /b 1
)

REM Load environment variables from .env
for /f "usebackq tokens=*" %%a in (".env") do (
    set "line=%%a"
    setlocal enabledelayedexpansion
    if not "!line:~0,1!"=="#" (
        set "%%a"
    )
    endlocal
)

REM Check if Gunicorn is installed
python -c "import gunicorn" 2>nul
if errorlevel 1 (
    echo X Gunicorn not installed!
    echo Installing dependencies...
    pip install -r requirements.txt
)

echo / Environment configured
echo.

REM Create logs directory if it doesn't exist
if not exist "logs" mkdir logs

REM Display configuration
echo Configuration:
echo   Workers: %GUNICORN_WORKERS%
echo   Bind: %GUNICORN_BIND%
echo   Timeout: %GUNICORN_TIMEOUT%s
echo.

REM Start Gunicorn
echo Starting Gunicorn server...
echo ==============================================
echo.

REM Use config file if it exists, otherwise use environment variables
if exist "gunicorn_config.py" (
    gunicorn -c gunicorn_config.py run:app
) else (
    gunicorn ^
        --workers %GUNICORN_WORKERS% ^
        --bind %GUNICORN_BIND% ^
        --timeout %GUNICORN_TIMEOUT% ^
        --access-logfile logs/access.log ^
        --error-logfile logs/error.log ^
        --log-level %GUNICORN_LOG_LEVEL% ^
        --capture-output ^
        run:app
)

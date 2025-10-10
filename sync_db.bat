@echo off
REM Database Synchronization Wrapper Script (Windows)

echo ==============================================
echo NetOps Tools - Database Sync
echo ==============================================
echo.

REM Check if venv exists
if not exist "venv" (
    echo X Virtual environment not found!
    echo Please create it first with: python -m venv venv
    pause
    exit /b 1
)

echo / Activating virtual environment...
call venv\Scripts\activate.bat

REM Check if Flask is installed
python -c "import flask" 2>nul
if errorlevel 1 (
    echo X Flask not installed in virtual environment!
    echo Please install dependencies with: pip install -r requirements.txt
    call deactivate
    pause
    exit /b 1
)

echo / Dependencies installed
echo.

REM Run sync script
python sync_database.py

set exit_code=%errorlevel%

call deactivate

pause
exit /b %exit_code%

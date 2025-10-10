@echo off
REM Script to run database migration for saved device lists, commands, and BGP Looking Glass features
REM This script activates the virtual environment and runs the migration

echo ==============================================
echo Database Migration - Latest Features
echo ==============================================
echo.

REM Check if venv exists
if not exist "..\venv" (
    echo X Virtual environment not found!
    echo Please create it first with: python -m venv venv
    pause
    exit /b 1
)

echo / Virtual environment found
echo.

REM Activate virtual environment
echo Activating virtual environment...
call ..\venv\Scripts\activate.bat

REM Check if Flask is installed
python -c "import flask" 2>nul
if errorlevel 1 (
    echo X Flask not installed in virtual environment!
    echo Please install dependencies with: pip install -r requirements.txt
    call deactivate
    pause
    exit /b 1
)

echo / Flask installed
echo.

REM Run migration
echo Running database migration...
echo.
flask db upgrade

if errorlevel 1 (
    echo.
    echo ==============================================
    echo X Migration failed!
    echo ==============================================
    echo.
    echo Please check the error messages above
    call deactivate
    pause
    exit /b 1
)

echo.
echo ==============================================
echo / Migration completed successfully!
echo ==============================================
echo.
echo New tables created/updated:
echo   - saved_device_lists
echo   - saved_commands
echo   - bgp_looking_glass_devices
echo.
echo You can now access the features at:
echo   - /saved-items/device-lists
echo   - /saved-items/commands
echo   - BGP Looking Glass tab on main page
echo   - Configure BGP devices in Settings
echo.

call deactivate
pause

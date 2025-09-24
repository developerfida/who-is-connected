@echo off
REM Windows Remote Connection Monitor - Installation and Run Script

echo Installing Python dependencies...
pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo Error: Failed to install Python dependencies
    pause
    exit /b 1
)

echo.
echo Python dependencies installed successfully!
echo.
echo Starting Remote Connection Monitor...
echo Press Ctrl+C to stop monitoring
echo.

python connection_monitor.py --api-url http://localhost:3001/api --interval 5 --log-level INFO

echo.
echo Monitor stopped.
pause
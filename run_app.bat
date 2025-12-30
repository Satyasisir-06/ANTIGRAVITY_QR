@echo off
echo Starting QR Attendance System...
cd QR_Attendance
if %errorlevel% neq 0 (
    echo Error: Could not find 'QR_Attendance' folder.
    pause
    exit /b
)
python app.py
pause

@echo off
cd /d "%~dp0"

echo ====================================
echo  TCPView with WinDivert (NEED ADMIN!)
echo ====================================
echo.

REM Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Need administrator rights!
    echo [!] Right-click run.bat -^> "Run as administrator"
    pause
    exit /b 1
)

REM Stop any running instance
taskkill /F /IM TCPView.exe 2>nul

echo Building...
cd build
cmake --build . --config Release --target TCPView

if %errorlevel% equ 0 (
    echo.
    echo Build OK! Starting TCPView...
    echo.
    .\bin\Release\TCPView.exe
) else (
    echo.
    echo ERROR: Build failed!
    pause
)

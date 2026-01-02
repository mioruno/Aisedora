@echo off
cd /d "%~dp0"

echo ====================================
echo  TCPView with WinDivert (FIXED)
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
echo.

REM --- SMART BUILD SYSTEM ---
if not exist build (
    echo [i] Creating build directory...
    mkdir build
)
cd build

echo [i] Checking project configuration (CMake)...
REM Using CALL to ensure control returns to this script
call cmake .. -DCMAKE_BUILD_TYPE=Release

if %errorlevel% neq 0 (
    echo.
    echo [!] Configuration mismatch or error detected.
    echo [i] Cleaning up and re-initializing...
    cd ..
    rmdir /s /q build
    mkdir build
    cd build
    
    echo [i] Configuring project from scratch...
    call cmake .. -DCMAKE_BUILD_TYPE=Release
    if %errorlevel% neq 0 (
        echo [!] Fatal: CMake Configuration Failed!
        pause
        exit /b 1
    )
)

echo.
echo [DEBUG] Configuration finished. Moving to build step...
REM Force pause here to ensure user sees the success above
timeout /t 2 >nul

echo [i] Building...
call cmake --build . --config Release --target TCPView -j %NUMBER_OF_PROCESSORS%

if %errorlevel% equ 0 (
    echo.
    echo [OK] Build Successful! 
    echo [i] Launching TCPView...
    echo.
    if exist "bin\Release\TCPView.exe" (
        .\bin\Release\TCPView.exe
    ) else (
        echo [!] Critical Error: executable not found in bin\Release\TCPView.exe
        pause
    )
) else (
    echo.
    echo [!] ERROR: Build failed!
    pause
)

echo.
echo [i] Script finished.
pause

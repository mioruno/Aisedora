@echo off
cd /d "%~dp0"

echo ====================================
echo  TCPView with WinDivert (FAST MODE)
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

REM --- FAST BUILD SYSTEM ---
if not exist build (
    echo [i] Build directory not found. Creating...
    mkdir build
    set RECONFIG=1
) else (
    if not exist build\CMakeCache.txt (
         set RECONFIG=1
    ) else (
         set RECONFIG=0
    )
)

cd build

if %RECONFIG%==1 (
    echo [i] First time setup / Reconfiguration...
    call cmake .. -DCMAKE_BUILD_TYPE=Release
    if %errorlevel% neq 0 goto :config_failed
)

echo [i] Building...
REM Try to build directly. If it fails, we assume config is broken and retry hard.
call cmake --build . --config Release --target TCPView -j %NUMBER_OF_PROCESSORS%

if %errorlevel% neq 0 (
     echo.
     echo [!] Build failed. Assuming stale configuration.
     echo [i] Cleaning and retrying from scratch...
     
     cd ..
     rmdir /s /q build
     mkdir build
     cd build
     
     call cmake .. -DCMAKE_BUILD_TYPE=Release
     if %errorlevel% neq 0 goto :config_failed
     
     call cmake --build . --config Release --target TCPView -j %NUMBER_OF_PROCESSORS%
     if %errorlevel% neq 0 goto :build_failed
)

echo.
echo [OK] Launching...
echo.
if exist "bin\Release\TCPView.exe" (
    .\bin\Release\TCPView.exe
) else (
    echo [!] Critical Error: executable not found!
    pause
)

goto :end

:config_failed
echo [!] CMake Configuration Failed!
pause
goto :end

:build_failed
echo [!] Build Failed even after full reconfiguration!
pause
goto :end

:end
REM Optional: pause only if you want to see the output every time.
REM pause

@echo off
REM ============================================================
REM  Build Kiosk_Launcher.exe
REM  Requirements: Windows 11 x64 + Python 3.10-3.12 (64-bit)
REM  Usage: double-click this file, or run it in cmd
REM ============================================================
cd /d "%~dp0"

echo [1/3] Installing dependencies...
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
if errorlevel 1 goto :err

echo [2/3] Building EXE with PyInstaller...
py -m PyInstaller --clean --noconfirm Kiosk_Launcher.spec
if errorlevel 1 goto :err

echo [3/3] Build complete!
echo.
echo Output: %~dp0dist\Kiosk_Launcher.exe
echo.
pause
goto :eof

:err
echo.
echo *** BUILD FAILED ***
pause
exit /b 1

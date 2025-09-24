@echo off
REM Quick launcher for Nexus Security Reports
REM Opens the latest comprehensive report in default browser

echo.
echo ========================================
echo   Nexus Security Scanner Report Viewer
echo ========================================
echo.

cd /d "%~dp0"

REM Find the most recent comprehensive HTML report
for /f "delims=" %%i in ('dir /b /od "vulnerability_reports\comprehensive_scan_report_*.html" 2^>nul') do set "latest=%%i"

if defined latest (
    echo Opening latest comprehensive report...
    echo File: %latest%
    start "" "vulnerability_reports\%latest%"
    echo.
    echo Report opened in your default web browser.
) else (
    echo No comprehensive reports found in vulnerability_reports folder.
    echo Please run the scanner first: python clean_nexus_scanner.py
)

echo.
echo Available report files:
dir /b vulnerability_reports\*.html 2>nul
if errorlevel 1 echo No HTML reports found.

echo.
echo Press any key to exit...
pause >nul
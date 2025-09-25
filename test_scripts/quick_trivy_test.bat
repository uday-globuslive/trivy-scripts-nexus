@echo off
echo === Quick Trivy Node.js Package Test ===

REM Change to vulnerability_reports directory where the file likely is
cd vulnerability_reports 2>nul || cd .

REM Check if the test file exists
if not exist "client-personalization-5.35.0.tgz" (
    echo Error: client-personalization-5.35.0.tgz not found
    echo Please copy it to the current directory
    pause
    exit /b 1
)

echo 1. Extracting package...
if exist "test_extraction" rmdir /s /q test_extraction
mkdir test_extraction
tar -xzf client-personalization-5.35.0.tgz -C test_extraction

echo 2. Finding package.json...
for /r test_extraction %%f in (package.json) do (
    set PACKAGE_DIR=%%~dpf
    echo Found: %%f
)

echo 3. Creating package-lock.json for Trivy detection...
cd "%PACKAGE_DIR%"
echo { > package-lock.json
echo   "name": "@algolia/client-personalization", >> package-lock.json
echo   "version": "5.35.0", >> package-lock.json
echo   "lockfileVersion": 3, >> package-lock.json
echo   "requires": true, >> package-lock.json
echo   "packages": { "": { "name": "@algolia/client-personalization", "version": "5.35.0" } }, >> package-lock.json
echo   "dependencies": {} >> package-lock.json
echo } >> package-lock.json

echo 4. Running Trivy scan...
"%~dp0trivy\trivy.exe" fs --scanners vuln --format json --output trivy_results.json .

echo 5. Checking results...
if exist "trivy_results.json" (
    echo ✅ Trivy scan completed successfully
    findstr /c:"VulnerabilityID" trivy_results.json >nul && (
        echo 🚨 Vulnerabilities found - check trivy_results.json
    ) || (
        echo ✅ No vulnerabilities found - package is secure
    )
    echo Results saved to: trivy_results.json
) else (
    echo ❌ Trivy scan failed - no results file generated
)

echo 6. Cleanup...
cd "%~dp0"
rmdir /s /q test_extraction

echo === Test Complete ===
pause
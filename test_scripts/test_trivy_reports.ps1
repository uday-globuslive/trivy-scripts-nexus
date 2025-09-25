# Enhanced Trivy Test Script with JSON and HTML Report Generation
# PowerShell version for Windows

param(
    [string]$TestFile = "client-personalization-5.35.0.tgz",
    [string]$TrivyPath = ".\trivy\trivy.exe"
)

Write-Host "=== Enhanced Trivy Node.js Package Test with Reports ===" -ForegroundColor Cyan

# Check Trivy executable
if (-not (Test-Path $TrivyPath)) {
    Write-Host "❌ Trivy not found at: $TrivyPath" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Using Trivy: $TrivyPath" -ForegroundColor Green

# Check for test file
if (-not (Test-Path $TestFile)) {
    Write-Host "❌ Test file not found: $TestFile" -ForegroundColor Red
    Write-Host "Please ensure the file is in the current directory" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Testing file: $TestFile" -ForegroundColor Green

# Create unique test directory
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$TestDir = "trivy_reports_test_$Timestamp"
New-Item -ItemType Directory -Path $TestDir | Out-Null

Write-Host "📁 Test directory: $TestDir" -ForegroundColor Blue

# Extract package using tar (available in Windows 10+)
Write-Host "📦 Extracting package..." -ForegroundColor Yellow
tar -xzf $TestFile -C "$TestDir\"

# Find package.json
$PackageJsonFile = Get-ChildItem -Path $TestDir -Name "package.json" -Recurse | Select-Object -First 1
if (-not $PackageJsonFile) {
    Write-Host "❌ No package.json found in extracted files" -ForegroundColor Red
    exit 1
}

$PackageDir = Join-Path $TestDir (Split-Path $PackageJsonFile)
Write-Host "✅ Found package directory: $PackageDir" -ForegroundColor Green

# Read original package.json for metadata
$PackageJsonContent = Get-Content (Join-Path $PackageDir "package.json") -Raw
$PackageName = ($PackageJsonContent | Select-String '"name"\s*:\s*"([^"]*)"').Matches[0].Groups[1].Value
$PackageVersion = ($PackageJsonContent | Select-String '"version"\s*:\s*"([^"]*)"').Matches[0].Groups[1].Value

Write-Host "📋 Package: $PackageName@$PackageVersion" -ForegroundColor Blue

# Create comprehensive package-lock.json
Write-Host "🔧 Creating enhanced package-lock.json..." -ForegroundColor Yellow
Push-Location $PackageDir

# Extract dependencies from package.json
$DependenciesSection = ($PackageJsonContent | Select-String '"dependencies"\s*:\s*{([^}]*)}' -AllMatches).Matches[0].Groups[1].Value
$Dependencies = @()
if ($DependenciesSection) {
    $Dependencies = ($DependenciesSection | Select-String '"([^"]*)"\s*:\s*"([^"]*)"' -AllMatches).Matches
}

# Create enhanced package-lock.json
$LockFileContent = @"
{
  "name": "$PackageName",
  "version": "$PackageVersion",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "$PackageName",
      "version": "$PackageVersion",
      "license": "MIT"
"@

if ($Dependencies.Count -gt 0) {
    $LockFileContent += ",`n      `"dependencies`": {`n"
    for ($i = 0; $i -lt $Dependencies.Count; $i++) {
        $DepName = $Dependencies[$i].Groups[1].Value
        $DepVersion = $Dependencies[$i].Groups[2].Value
        $LockFileContent += "        `"$DepName`": `"$DepVersion`""
        if ($i -lt ($Dependencies.Count - 1)) { $LockFileContent += "," }
        $LockFileContent += "`n"
    }
    $LockFileContent += "      }`n"
}

$LockFileContent += @"
    }
  },
  "dependencies": {
"@

if ($Dependencies.Count -gt 0) {
    for ($i = 0; $i -lt $Dependencies.Count; $i++) {
        $DepName = $Dependencies[$i].Groups[1].Value
        $DepVersion = $Dependencies[$i].Groups[2].Value
        $LockFileContent += @"
    "$DepName": {
      "version": "$DepVersion",
      "resolved": "https://registry.npmjs.org/$DepName/-/$DepName-$DepVersion.tgz",
      "integrity": "sha512-placeholder"
    }
"@
        if ($i -lt ($Dependencies.Count - 1)) { $LockFileContent += "," }
        $LockFileContent += "`n"
    }
}

$LockFileContent += @"
  }
}
"@

$LockFileContent | Out-File -FilePath "package-lock.json" -Encoding UTF8
$LockSize = (Get-Item "package-lock.json").Length
Write-Host "✅ Created enhanced lock file ($LockSize bytes)" -ForegroundColor Green

# Set up report file names
$TimestampFull = Get-Date -Format "yyyyMMdd_HHMMss"
$BaseName = ($PackageName -replace '[^a-zA-Z0-9]', '_') + "_" + ($PackageVersion -replace '[^a-zA-Z0-9]', '_')
$JsonReport = "..\$BaseName" + "_trivy_$TimestampFull.json"
$HtmlReport = "..\$BaseName" + "_trivy_$TimestampFull.html"

Write-Host "📊 Report files:" -ForegroundColor Blue
Write-Host "   JSON: $JsonReport" -ForegroundColor Gray
Write-Host "   HTML: $HtmlReport" -ForegroundColor Gray

# Run JSON scan
Write-Host "🔍 Running JSON vulnerability scan..." -ForegroundColor Yellow
$JsonArgs = @("fs", "--scanners", "vuln", "--format", "json", "--output", $JsonReport, ".")
& $TrivyPath $JsonArgs
$JsonExitCode = $LASTEXITCODE
Write-Host "JSON scan exit code: $JsonExitCode" -ForegroundColor $(if ($JsonExitCode -eq 0) { "Green" } else { "Red" })

# Run HTML scan
Write-Host "🌐 Running HTML report scan..." -ForegroundColor Yellow
$TrivyDir = Split-Path $TrivyPath -Parent
$HtmlTemplate = Join-Path $TrivyDir "contrib\html.tpl"

if (Test-Path $HtmlTemplate) {
    Write-Host "✅ Using HTML template: $HtmlTemplate" -ForegroundColor Green
    $HtmlArgs = @("fs", "--scanners", "vuln", "--format", "template", "--template", "@$HtmlTemplate", "--output", $HtmlReport, ".")
} else {
    Write-Host "⚠️  HTML template not found, using table format" -ForegroundColor Yellow
    $HtmlArgs = @("fs", "--scanners", "vuln", "--format", "table", "--output", $HtmlReport, ".")
}

& $TrivyPath $HtmlArgs
$HtmlExitCode = $LASTEXITCODE
Write-Host "HTML scan exit code: $HtmlExitCode" -ForegroundColor $(if ($HtmlExitCode -eq 0) { "Green" } else { "Red" })

# Check results
Pop-Location
Write-Host ""
Write-Host "📋 Scan Results Summary:" -ForegroundColor Cyan

if (Test-Path $JsonReport) {
    $JsonSize = (Get-Item $JsonReport).Length
    $JsonContent = Get-Content $JsonReport -Raw
    $VulnCount = ([regex]::Matches($JsonContent, '"VulnerabilityID"')).Count
    Write-Host "✅ JSON Report: $JsonSize bytes, $VulnCount vulnerabilities" -ForegroundColor Green
    
    # Check detection
    if ($JsonContent -match '"Class": "lang-pkgs"') {
        Write-Host "✅ Package detection: SUCCESS (language packages detected)" -ForegroundColor Green
    } else {
        Write-Host "❌ Package detection: FAILED (no language packages found)" -ForegroundColor Red
    }
} else {
    Write-Host "❌ JSON Report: FAILED to generate" -ForegroundColor Red
}

if (Test-Path $HtmlReport) {
    $HtmlSize = (Get-Item $HtmlReport).Length
    Write-Host "✅ HTML Report: $HtmlSize bytes" -ForegroundColor Green
    
    # Try to detect if it's actually HTML
    $HtmlHeader = Get-Content $HtmlReport -TotalCount 5 -Raw
    if ($HtmlHeader -match "<html|<!DOCTYPE") {
        Write-Host "✅ HTML Format: Valid HTML document" -ForegroundColor Green
    } else {
        Write-Host "ℹ️  HTML Format: Plain text format (template may not be available)" -ForegroundColor Blue
    }
} else {
    Write-Host "❌ HTML Report: FAILED to generate" -ForegroundColor Red
}

# Create summary report
$SummaryFile = "scan_summary_$TimestampFull.md"
$SummaryContent = @"
# Trivy Scan Summary Report

**Package:** $PackageName@$PackageVersion  
**Scan Date:** $(Get-Date)  
**Test Directory:** $TestDir

## Scan Results

### JSON Report
- **File:** ``$JsonReport``
- **Size:** $JsonSize bytes
- **Vulnerabilities:** $VulnCount
- **Exit Code:** $JsonExitCode

### HTML Report  
- **File:** ``$HtmlReport``
- **Size:** $HtmlSize bytes
- **Exit Code:** $HtmlExitCode

## Package Detection
$(if ($JsonContent -match '"Class": "lang-pkgs"') { "✅ **SUCCESS** - Node.js package properly detected" } else { "❌ **FAILED** - Package not detected as Node.js" })

## Files Generated
- JSON Report: ``$JsonReport``
- HTML Report: ``$HtmlReport``
- Summary: ``$SummaryFile``
- Test Data: ``$TestDir\``

"@

$SummaryContent | Out-File -FilePath $SummaryFile -Encoding UTF8
Write-Host ""
Write-Host "📄 Summary report created: $SummaryFile" -ForegroundColor Blue

# List all generated files
Write-Host ""
Write-Host "📁 Generated Files:" -ForegroundColor Blue
Get-ChildItem -Path "." -Name "*.json", "*.html", "*.md" | Where-Object { $_ -match $TimestampFull -or $_ -match $BaseName }

Write-Host ""
Write-Host "🏁 Enhanced test complete!" -ForegroundColor Green
Write-Host "   Check the HTML report in a browser for detailed vulnerability information" -ForegroundColor Yellow

# Offer to open HTML report
if (Test-Path $HtmlReport) {
    $Response = Read-Host "Would you like to open the HTML report in your default browser? (y/n)"
    if ($Response -eq 'y' -or $Response -eq 'Y') {
        Start-Process $HtmlReport
    }
}
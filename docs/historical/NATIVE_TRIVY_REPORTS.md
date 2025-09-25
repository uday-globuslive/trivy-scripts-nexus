# Native Trivy JSON and HTML Report Generation

This document explains the enhanced scanner's native Trivy report generation capabilities.

## Overview

The scanner now generates **authentic Trivy reports** in both JSON and HTML formats, not custom interpretations of Trivy data.

## Report Types Generated

### 1. Native Trivy JSON Reports
- **Format**: Standard Trivy JSON schema
- **Contains**: Raw vulnerability data as output by Trivy
- **Usage**: Compatible with all Trivy-aware tools and parsers
- **File naming**: `{filename}_trivy_{timestamp}.json`
- **Location**: `individual_files_reports/` directory

### 2. Native Trivy HTML Reports  
- **Format**: Generated using Trivy's `contrib/html.tpl` template
- **Contains**: Formatted HTML with Trivy's built-in styling
- **Usage**: View directly in web browser
- **File naming**: `{filename}_trivy_{timestamp}.html`
- **Location**: `individual_files_reports/` directory

## Key Enhancements

### Main Scanner (`clean_nexus_scanner.py`)
```python
# Now saves actual Trivy outputs, not custom JSON structures
json_report_path = os.path.join(self.individual_files_dir, 
                              f"{base_name}_trivy_{timestamp}.json")
# Save the raw Trivy JSON output (not our custom structure)
with open(json_report_path, 'w', encoding='utf-8') as f:
    f.write(json_content)  # This is raw Trivy JSON
```

### Test Script (`test_native_trivy.sh`)
```bash
# Generates native Trivy JSON
"$TRIVY_BINARY" fs --scanners vuln --format json --output "$JSON_OUTPUT" "$SCAN_DIR"

# Generates native Trivy HTML using official template
"$TRIVY_BINARY" fs --scanners vuln --format template --template "@$HTML_TEMPLATE" --output "$HTML_OUTPUT" "$SCAN_DIR"
```

## Usage Examples

### Testing Individual TGZ Files
```bash
# Place script in same directory as your TGZ file
./test_native_trivy.sh client-personalization-5.35.0.tgz

# Or auto-detect first TGZ file in directory
./test_native_trivy.sh
```

### Running Full Scanner
```bash
# Scanner automatically generates both JSON and HTML for all scanned files
python3 clean_nexus_scanner.py
```

## Trivy Binary Configuration

### Linux Deployment
- **Trivy Binary**: `/tmp/tools/trivy/trivy`
- **HTML Template**: `/tmp/tools/trivy/contrib/html.tpl`
- **Auto-detected**: Scanner checks this path first

### Local Development
- **Windows**: `./trivy/trivy.exe`
- **Linux/Mac**: `./trivy/trivy`
- **Fallback**: System PATH

## Report Content

### JSON Report Structure
```json
{
  "SchemaVersion": 2,
  "CreatedAt": "2025-09-25T10:34:51.220300595-04:00",
  "ArtifactName": ".",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-12345",
          "PkgName": "example-package",
          "Severity": "HIGH",
          "Description": "Example vulnerability",
          // ... full Trivy vulnerability data
        }
      ]
    }
  ]
}
```

### HTML Report Features
- **Trivy Branding**: Official Trivy styling and layout
- **Severity Colors**: Color-coded vulnerability levels
- **CVSS Scores**: Detailed scoring information
- **Links**: Direct links to vulnerability databases
- **Filtering**: Interactive filtering by severity
- **Responsive**: Mobile-friendly design

## Node.js Package Enhancement

### Detection Process
1. **Extract TGZ**: Decompress archive to temporary directory
2. **Find package.json**: Locate Node.js package metadata
3. **Enhance Detection**: Create comprehensive `package-lock.json` if missing
4. **Scan**: Run Trivy with enhanced package manager detection
5. **Generate Reports**: Save both native JSON and HTML outputs

### Enhancement Details
```bash
# Before enhancement: Trivy shows "num=0" 
2025-09-25T10:34:51-04:00 INFO Number of language-specific files num=0

# After enhancement: Trivy shows "num=1"
2025-09-25T10:34:51-04:00 INFO Number of language-specific files num=1
```

## Verification

### Check JSON Report Authenticity
```bash
# Verify it's authentic Trivy JSON
jq '.SchemaVersion' your_report.json  # Should show: 2
jq '.Results[].Class' your_report.json  # Should show: "lang-pkgs" for Node.js
```

### Check HTML Report Authenticity  
```bash
# Verify it uses Trivy template
grep -i "trivy" your_report.html  # Should contain Trivy branding
head -5 your_report.html | grep "<!DOCTYPE html>"  # Should be valid HTML
```

## File Locations

```
project_root/
├── individual_files_reports/
│   ├── client-personalization-5_35_0_tgz_trivy_20250925_103451.json  ← Native Trivy JSON
│   ├── client-personalization-5_35_0_tgz_trivy_20250925_103451.html  ← Native Trivy HTML
│   └── ... (other scanned files)
└── test_native_trivy.sh  ← Test script for individual files
```

## Benefits

1. **Compatibility**: Reports work with existing Trivy toolchains
2. **Standardization**: Uses official Trivy formats and schemas  
3. **Professional**: HTML reports have official Trivy branding and styling
4. **Integration**: JSON reports can be consumed by CI/CD pipelines
5. **Accuracy**: No custom interpretation or data transformation
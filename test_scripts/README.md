# Test Scripts for Nexus Vulnerability Scanner

This directory contains various test scripts designed to validate and troubleshoot the Nexus vulnerability scanner, particularly for Node.js package scanning with Trivy integration.

## 📁 Test Scripts Overview

### 🎯 `test_trivy_fixed.sh` ⭐ **[RECOMMENDED]**
**Purpose:** The most advanced test script that successfully resolves Node.js package detection issues with Trivy.

**What it does:**
- ✅ **Fixed Node.js Detection:** Creates comprehensive package-lock.json with proper structure
- ✅ **Native Trivy Reports:** Generates both JSON and HTML reports using Trivy's native formats
- ✅ **Enhanced Package Structure:** Creates node_modules directory with individual package metadata
- ✅ **Proven Success:** Achieves `num=1` detection instead of `num=0` for Node.js packages

**Usage:**
```bash
# Test specific TGZ file
./test_trivy_fixed.sh your_nodejs_package.tgz

# Auto-detect first TGZ in current directory
./test_trivy_fixed.sh
```

**Expected Output:**
- JSON Report: ~506+ bytes (with actual vulnerability data)
- HTML Report: ~3000+ bytes (with proper Trivy styling)
- Detection Success: "Node.js Detection: SUCCESS"

---

### 🔧 `test_native_trivy.sh`
**Purpose:** Basic native Trivy testing without enhancement logic.

**What it does:**
- Basic TGZ extraction and Trivy scanning
- Native JSON and HTML report generation
- No package enhancement (may show `num=0` for Node.js)

**Usage:**
```bash
./test_native_trivy.sh package.tgz
```

**When to use:** Testing baseline Trivy functionality without enhancements

---

### 📦 `test_nodejs_package.sh`
**Purpose:** Comprehensive Node.js package analysis and testing.

**What it does:**
- Detailed Node.js package structure analysis
- Dependency mapping and validation
- Enhanced package-lock.json creation
- Colorized output for better readability

**Usage:**
```bash
./test_nodejs_package.sh nodejs_package.tgz
```

**When to use:** Deep analysis of Node.js package structure and dependencies

---

### 🧪 `test_nodejs_scanning.sh`
**Purpose:** Simple Node.js scanning test focused on client-personalization package.

**What it does:**
- Tests specific problematic Node.js package
- Basic package extraction and analysis
- Dependency listing and structure examination

**Usage:**
```bash
# Copy client-personalization-5.35.0.tgz to /tmp/trivy_nodejs_test first
./test_nodejs_scanning.sh
```

**When to use:** Quick test for the specific client-personalization package issue

---

### 📊 `test_trivy_reports.sh`
**Purpose:** Enhanced reporting with comprehensive JSON and HTML generation.

**What it does:**
- Focuses on report generation quality
- Tests both JSON and HTML output formats
- Validates report content and structure

**Usage:**
```bash
# Requires client-personalization-5.35.0.tgz in current directory
./test_trivy_reports.sh
```

**When to use:** Testing report generation capabilities

---

### 🔧 `verify_trivy_setup.sh`
**Purpose:** Verify Trivy installation and enhanced reporting functionality for Linux systems.

**What it does:**
- Checks Trivy installation and paths
- Validates HTML template availability
- Tests enhanced functionality setup
- Verifies Trivy version and capabilities

**Usage:**
```bash
./verify_trivy_setup.sh
```

**When to use:** Initial setup verification and troubleshooting

---

### ⚡ `quick_lock_test.sh`
**Purpose:** Quick test for Node.js package-lock.json format generation and validation.

**What it does:**
- Creates test package.json with dependencies
- Generates comprehensive package-lock.json
- Tests Trivy detection with different lock file formats
- Validates lockfile structure

**Usage:**
```bash
./quick_lock_test.sh
```

**When to use:** Rapid package-lock.json format testing and validation

---

### 🪟 `quick_trivy_test.bat`
**Purpose:** Windows batch script for quick Node.js package testing.

**What it does:**
- Windows-compatible TGZ extraction
- Creates basic package-lock.json
- Runs Trivy scan with Windows Trivy binary
- Checks for vulnerabilities and results

**Usage:**
```cmd
quick_trivy_test.bat
```

**When to use:** Windows environment testing

---

### 🪟 `test_nodejs_scanning.ps1`
**Purpose:** PowerShell script for Node.js package scanning tests on Windows.

**What it does:**
- PowerShell-based testing framework
- Enhanced scanner configuration testing
- Windows-compatible Node.js package analysis

**Usage:**
```powershell
.\test_nodejs_scanning.ps1
```

**When to use:** Advanced Windows testing with PowerShell

---

### 🪟 `test_trivy_reports.ps1`
**Purpose:** PowerShell version of comprehensive report testing for Windows.

**What it does:**
- Windows PowerShell report generation testing
- JSON and HTML format validation
- Windows Trivy binary compatibility testing

**Usage:**
```powershell
.\test_trivy_reports.ps1 -TestFile "package.tgz" -TrivyPath ".\trivy\trivy.exe"
```

**When to use:** Windows report generation testing

## 🚀 Quick Start Guide

### Prerequisites
- **Linux Environment** (these scripts are designed for Linux/Unix systems)
- **Trivy Installation** at `/tmp/tools/trivy/trivy`
- **HTML Template** at `/tmp/tools/trivy/contrib/html.tpl`
- **Node.js TGZ files** to test with

### Recommended Testing Workflow

1. **Start with the proven solution:**
   ```bash
   cd test_scripts
   chmod +x test_trivy_fixed.sh
   ./test_trivy_fixed.sh your_nodejs_package.tgz
   ```

2. **Compare with baseline:**
   ```bash
   chmod +x test_native_trivy.sh
   ./test_native_trivy.sh your_nodejs_package.tgz
   ```

3. **Deep analysis if needed:**
   ```bash
   chmod +x test_nodejs_package.sh
   ./test_nodejs_package.sh your_nodejs_package.tgz
   ```

### Success Indicators

When tests are working correctly, you should see:

✅ **Proper Detection:**
```
✅ Node.js Detection: SUCCESS (1 npm results found)
Number of language-specific files num=1
```

✅ **Substantial Reports:**
```
✅ JSON Report: 506 bytes, 2 vulnerabilities, 1 result sections
✅ HTML Report: 3161 bytes
✅ HTML Report: Contains substantial data
```

✅ **Native Trivy Output:**
```json
{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm"
    }
  ]
}
```

## 🐛 Troubleshooting

### Problem: "num=0" or Empty Reports

**Solution:** Use `test_trivy_fixed.sh` which creates comprehensive package structure:
- Proper package-lock.json with lockfileVersion 3
- Physical node_modules directories
- Individual package.json files for dependencies

### Problem: "Trivy binary not found"

**Solution:** Install Trivy at the expected location:
```bash
sudo mkdir -p /tmp/tools/trivy
# Download and install Trivy to /tmp/tools/trivy/trivy
```

### Problem: "HTML template not found"

**Solution:** Ensure HTML template exists:
```bash
# Template should be at: /tmp/tools/trivy/contrib/html.tpl
ls -la /tmp/tools/trivy/contrib/html.tpl
```

### Problem: Scripts not executable

**Solution:** Make scripts executable:
```bash
chmod +x test_scripts/*.sh
```

## 📈 Performance Comparison

| Script | Platform | Detection Rate | Report Quality | Use Case |
|--------|----------|---------------|----------------|----------|
| `test_trivy_fixed.sh` ⭐ | Linux | ✅ High (`num=1`) | ✅ Rich Content | **Production Use** |
| `test_native_trivy.sh` | Linux | ❌ Low (`num=0`) | ❌ Empty Reports | Baseline Testing |
| `test_nodejs_package.sh` | Linux | ✅ High | ✅ Detailed Analysis | Deep Debugging |
| `test_nodejs_scanning.sh` | Linux | ⚠️ Variable | ⚠️ Basic | Quick Testing |
| `test_trivy_reports.sh` | Linux | ⚠️ Variable | ✅ Good Formatting | Report Validation |
| `verify_trivy_setup.sh` | Linux | ✅ Setup Check | ✅ System Validation | Setup Verification |
| `quick_lock_test.sh` | Linux | ✅ High | ✅ Format Testing | Lock File Testing |
| `quick_trivy_test.bat` | Windows | ⚠️ Basic | ⚠️ Basic | Windows Quick Test |
| `test_nodejs_scanning.ps1` | Windows | ✅ Good | ✅ Good | Windows Advanced |
| `test_trivy_reports.ps1` | Windows | ✅ Good | ✅ Rich Content | Windows Reports |

## 🔄 Integration with Main Scanner

The logic from `test_trivy_fixed.sh` has been integrated into the main scanner:
- **File:** `clean_nexus_scanner.py`
- **Method:** `enhance_nodejs_package_for_scanning()`
- **Result:** Production scanner now uses same proven methodology

## 📝 Development Notes

### Key Learning: Package Structure Requirements

Trivy requires specific Node.js package structure for proper detection:

1. **Complete package-lock.json** with:
   - `lockfileVersion: 3`
   - `packages` section with root and node_modules entries
   - `dependencies` section with resolved URLs

2. **Physical node_modules directory** with:
   - Individual directories for each dependency
   - package.json file in each dependency directory

3. **Proper dependency metadata** with:
   - Clean version numbers (no ^ ~ prefixes)
   - Resolved URLs and integrity hashes
   - License information

### Evolution of Scripts

1. **test_native_trivy.sh** - Initial baseline (failed: `num=0`)
2. **test_nodejs_scanning.sh** - Basic Node.js focus
3. **test_nodejs_package.sh** - Enhanced analysis
4. **test_trivy_reports.sh** - Report quality focus
5. **test_trivy_fixed.sh** - **Final working solution** ⭐

## 🎯 Conclusion

For production testing and validation, use `test_trivy_fixed.sh` as it represents the current working solution that successfully resolves Node.js package detection issues and generates proper vulnerability reports.

The other scripts serve as historical references and alternative approaches for specific debugging scenarios.
# Nexus Repository Vulnerability Scanner

A comprehensive security scanning solution for Nexus Repository Manager that uses Trivy to detect vulnerabilities in all repositories, components, and artifacts.

## 🎯 Overview

This scanner provides complete vulnerability assessment of your Nexus Repository Manager by:
- Scanning **ALL hosted repositories** (Maven, NuGet, Raw, Docker)
- Processing **ALL components** with proper pagination
- Analyzing **ALL assets** in each component
- Generating professional reports in multiple formats

## 📁 Project Structure

```
nexus-vulnerability-scanner/
├── clean_nexus_scanner.py          # Main scanner application
├── config_loader.py                # Configuration management
├── monitor_progress.py             # Scanning progress monitor
├── monitor_scanner.sh              # Linux progress monitor wrapper
├── .env                            # Nexus credentials & settings
├── config.example                  # Example configuration
├── open_latest_report.bat          # Quick report viewer
├── trivy/                          # Trivy scanner binaries
├── vulnerability_reports/          # Generated scan reports
│   ├── README.md                   # Report documentation
│   ├── *.json                      # Detailed scan data
│   └── *.html                      # Professional web reports
├── test_scripts/                   # Test & validation scripts
│   ├── README.md                   # Test scripts documentation
│   ├── test_trivy_fixed.sh        # ⭐ Proven Node.js scanning fix
│   ├── test_native_trivy.sh       # Basic Trivy testing
│   ├── test_nodejs_package.sh     # Comprehensive Node.js analysis
│   ├── test_nodejs_scanning.sh    # Quick Node.js testing
│   ├── test_trivy_reports.sh      # Report generation testing
│   ├── verify_trivy_setup.sh      # Setup verification
│   ├── quick_lock_test.sh         # Lock file format testing
│   ├── quick_trivy_test.bat       # Windows quick testing
│   ├── test_nodejs_scanning.ps1   # Windows PowerShell testing
│   ├── test_trivy_reports.ps1     # Windows report testing
│   └── setup_permissions.sh       # Make scripts executable
├── docs/                           # Documentation
│   ├── README.md                   # Documentation index
│   ├── NODEJS_INTEGRATION_COMPLETE.md    # Integration status
│   ├── TEST_SCRIPTS_ORGANIZATION_COMPLETE.md  # Organization status
│   ├── trivy_nodejs_scan_guide.md         # Technical reference
│   └── historical/                 # Historical documentation
│       ├── BUG_FIX_REPOSITORY_NAME.md    # Bug fix records
│       ├── NATIVE_TRIVY_REPORTS.md       # Report implementation
│       ├── NODEJS_ENHANCEMENT_COMPLETE.md # Enhancement records
│       └── PERFORMANCE_OPTIMIZATION.md    # Optimization records
├── QUICK_START_GUIDE.md            # Getting started guide
└── README.md                       # This file
```

## 🚀 Quick Start

### 1. Configure Scanner
Your `.env` file is already configured with:
```bash
NEXUS_URL=http://10.11.53.12:8081
NEXUS_USERNAME=sv-sbom
NEXUS_PASSWORD=sbom@sbom
```

### 2. Run Scanner
```bash
python clean_nexus_scanner.py
```

### 3. View Reports
```bash
open_latest_report.bat
```

## 📊 Generated Reports

Each scan produces multiple report formats:

### Standard Reports
- **JSON**: Raw vulnerability data for tool integration
- **CSV**: Spreadsheet-friendly format for analysis  
- **HTML**: Professional web report with styling

### Comprehensive Reports
- **Enhanced JSON**: Complete analytics with metadata
- **Executive HTML**: Dashboard with charts and metrics

## ✅ Features

- **Complete Coverage**: Scans every repository, component, and asset
- **Multiple Formats**: JSON, CSV, HTML reports
- **Professional Styling**: Executive-ready HTML dashboards
- **Pagination Support**: Handles large repositories efficiently
- **Windows Compatible**: Clean logging without Unicode issues
- **Configuration Management**: Centralized settings via .env
- **Report History**: Timestamped files for tracking
- **Zero Dependencies Issues**: All required tools included

## 🧪 Testing & Validation

The scanner includes comprehensive test scripts for validation and troubleshooting across different platforms:

### Quick Test (Linux/Unix)
```bash
cd test_scripts
chmod +x setup_permissions.sh
./setup_permissions.sh
./test_trivy_fixed.sh your_nodejs_package.tgz
```

### Quick Test (Windows)
```cmd
cd test_scripts
quick_trivy_test.bat
```

### Test Scripts Available
- **`test_trivy_fixed.sh`** ⭐ **Recommended** - Proven Node.js scanning solution (Linux)
- **`test_native_trivy.sh`** - Basic Trivy functionality testing (Linux)
- **`test_nodejs_package.sh`** - Comprehensive Node.js package analysis (Linux)
- **`verify_trivy_setup.sh`** - Setup verification and troubleshooting (Linux)
- **`quick_lock_test.sh`** - Package-lock.json format testing (Linux)
- **`test_trivy_reports.ps1`** - Comprehensive report testing (Windows PowerShell)
- **`test_nodejs_scanning.ps1`** - Advanced Node.js testing (Windows PowerShell)
- **`quick_trivy_test.bat`** - Quick testing (Windows batch)

📖 **See `test_scripts/README.md` for detailed testing documentation**
📚 **See `docs/README.md` for additional documentation and guides**

## 🔧 Requirements

- Python 3.7+
- Windows/Linux/Mac compatible
- Network access to Nexus Repository Manager
- Trivy scanner (✅ included in `./trivy/` folder)

## 📈 Current Configuration

Your Nexus server setup:
- **Server**: `http://10.11.53.12:8081`
- **Username**: `sv-sbom` 
- **Repositories Available**: 
  - `mccamishsbom` (raw format, 2 components)
  - `mccamish_sbom` (maven2 format, 9 components)
  - Plus additional empty repositories

## 🛡️ Enterprise Features

- **Audit Trail**: Complete scan history and metadata
- **Compliance Ready**: Professional reporting for audits
- **CI/CD Integration**: JSON output for automated workflows
- **Executive Dashboards**: Visual reports for management
- **Risk Assessment**: Severity-based vulnerability grouping

## 📞 Usage

For detailed usage instructions, see `QUICK_START_GUIDE.md`.

For report documentation, see `vulnerability_reports/README.md`.

---

*Powered by Trivy vulnerability scanning engine*
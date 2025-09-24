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
├── .env                            # Nexus credentials & settings
├── config.example                  # Example configuration
├── open_latest_report.bat          # Quick report viewer
├── trivy/                          # Trivy scanner binaries
├── vulnerability_reports/          # Generated scan reports
│   ├── README.md                   # Report documentation
│   ├── *.json                      # Detailed scan data
│   └── *.html                      # Professional web reports
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
# Monitor Progress Integration with Main Scanner

## 🎯 **How `monitor_progress.py` Works with Main Scanner**

The `monitor_progress.py` is a **standalone monitoring utility** that provides real-time progress tracking for the Nexus vulnerability scanner by monitoring the debug log files created by the main scanner.

## 🏗️ **Integration Architecture**

```
Main Scanner (clean_nexus_scanner.py)
    ↓ Creates debug log files
vulnerability_reports/nexus_scanner_debug_YYYYMMDD_HHMMSS.log
    ↑ Monitors log files
Monitor Progress (monitor_progress.py)
    ↓ Displays progress
Terminal/Console Output
```

## 🔧 **Integration Points**

### **1. Debug Logging Configuration**

**Main Scanner Configuration (`.env`):**
```properties
# Debug Configuration
DEBUG_MODE=true                    # Show console output + file logging
DEBUG_LOG_LEVEL=DEBUG             # Detailed logging level  
DEBUG_LOG_FILE=true               # Create debug log files ← KEY FOR MONITORING
DEBUG_TRIVY_COMMANDS=true         # Log Trivy commands
DEBUG_HTTP_REQUESTS=true          # Log HTTP requests
```

**Main Scanner Logging Setup:**
```python
# In clean_nexus_scanner.py lines 74-115
if self.debug_log_file:
    log_filename = f"nexus_scanner_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_filepath = os.path.join(self.output_dir, log_filename)  # vulnerability_reports/
    
    # Creates file handler with detailed formatting
    file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
    self.logger.addHandler(file_handler)
```

### **2. Log File Structure Monitored**

**Monitor Progress reads these log patterns:**
```python
# Repository scanning detection
repo_pattern = re.compile(r'=== SCANNING REPOSITORY: (.+?) \(format: (.+?), type: (.+?)\) ===')

# Component retrieval tracking  
component_retrieval_pattern = re.compile(r'Retrieved (\d+) components \(total: (\d+)\)')

# Component processing progress
component_processing_pattern = re.compile(r'Processing component (\d+)/(\d+): (.+?)$')

# Asset scanning tracking
scanning_pattern = re.compile(r'SCANNING: (.+?) \(Type: (.+?)\)')

# Vulnerability detection
vulnerability_pattern = re.compile(r'Found (\d+) vulnerabilities')

# Report generation tracking
report_pattern = re.compile(r'Individual HTML report retained:')
```

### **3. Usage Workflow**

**Step 1:** Start the main scanner (creates debug log)
```bash
python clean_nexus_scanner.py
```

**Step 2:** In a separate terminal, start the monitor
```bash
# Linux/Unix
./monitor_scanner.sh
# OR directly
python3 monitor_progress.py

# Windows  
python monitor_progress.py
```

## 📊 **What the Monitor Shows**

### **Real-time Progress Display:**
```
🔍 NEXUS SCANNER PROGRESS MONITOR
==================================================
⏱️  Runtime: 15m 32s
📅 Started: 2025-09-25 10:30:15

🎯 Current Phase: 🛡️ Scanning Assets for Vulnerabilities  
📂 Repository: mccamish_sbom

📊 PROGRESS STATISTICS:
   🔍 Components Found: 9
   ⚡ Components Processed: 7  
   🛡️ Assets Scanned: 23
   🚨 Vulnerabilities Found: 15
   📄 Reports Generated: 18
   🔧 Current Component: client-personalization-5.35.0.tgz

📁 INDIVIDUAL REPORTS:
   📂 Reports Location: ./vulnerability_reports/individual_files_reports/
   📊 Total Reports: 18
   📁 Organization: Separated by vulnerability status and repository

💡 WHAT'S HAPPENING:
   • Scanner is downloading and scanning individual assets
   • Individual HTML reports are being generated and organized  
   • Reports separated into 'with_vulnerabilities' and 'empty_reports' folders
```

### **Phase Tracking:**
1. **🔍 Discovering Components** - Finding all components in repositories
2. **🛡️ Scanning Assets** - Downloading and scanning individual files  
3. **📄 Generating Reports** - Creating final comprehensive reports
4. **✅ Completed** - Scan finished

## 🎯 **Key Benefits**

### **✅ Independent Operation**
- **No code changes needed** in main scanner
- **Standalone utility** - can be started/stopped independently
- **Non-intrusive** - only reads log files, doesn't affect scanner performance

### **✅ Real-time Visibility**
- **Live progress tracking** - updates every 10 seconds
- **Phase awareness** - knows what the scanner is currently doing
- **Detailed statistics** - components, assets, vulnerabilities, reports
- **ETA estimation** - shows runtime and progress

### **✅ Enterprise Monitoring**
- **Progress reporting** for long-running scans
- **Status visibility** for managers/stakeholders  
- **Troubleshooting aid** - see where scanner might be stuck
- **Resource planning** - understand scan duration patterns

## 🔧 **Technical Implementation**

### **Log File Detection:**
```python
def get_latest_log_file():
    """Find the most recent scanner debug log file."""
    log_dir = "./vulnerability_reports"
    log_files = [f for f in os.listdir(log_dir) 
                if f.startswith("nexus_scanner_debug_") and f.endswith(".log")]
    return max(log_files, key=os.path.getctime)  # Most recent by creation time
```

### **Progress Parsing:**
```python  
def parse_log_progress(log_file):
    """Parse the log file to extract current progress."""
    # Reads log file and extracts:
    # - Current repository being scanned
    # - Number of components found/processed
    # - Assets scanned count
    # - Vulnerabilities detected
    # - Reports generated
    # - Current phase (discovery/scanning/reporting)
```

### **Display Updates:**
```python
def monitor_progress():
    """Main monitoring loop."""
    while True:
        progress = parse_log_progress(log_file)
        display_progress(progress, start_time)
        time.sleep(10)  # Update every 10 seconds
```

## 🚀 **Usage Scenarios**

### **🏢 Enterprise Scanning**
- **Long-running scans** (30+ minutes) - see progress instead of waiting
- **Stakeholder updates** - show management scan is progressing
- **Resource planning** - understand how long scans typically take

### **🐛 Troubleshooting**
- **Stuck scans** - identify which component/repository is causing issues
- **Performance analysis** - see which phases take longest
- **Validation** - confirm scanner is processing expected number of components

### **🔍 Development & Testing**
- **Integration testing** - monitor test scans for expected behavior
- **Performance optimization** - identify bottlenecks in scan process
- **Feature validation** - confirm new features are working as expected

## 📝 **Summary**

`monitor_progress.py` provides **enterprise-grade monitoring** for the Nexus vulnerability scanner by:

1. **Reading debug logs** created by main scanner (`DEBUG_LOG_FILE=true`)
2. **Parsing progress patterns** to extract current status
3. **Displaying real-time updates** in a user-friendly format
4. **Operating independently** without affecting scanner performance

This creates a **professional scanning experience** where users can track progress, estimate completion times, and identify any issues during long-running vulnerability scans.
#!/usr/bin/env python3
"""
Real-time Progress Monitor for Nexus Scanner
Monitors the scanner log file and shows current progress and phase transitions.
"""

import os
import time
import re
from datetime import datetime
from collections import defaultdict

def get_latest_log_file():
    """Find the most recent scanner debug log file."""
    log_dir = "./vulnerability_reports"
    if not os.path.exists(log_dir):
        return None
    
    log_files = []
    for file in os.listdir(log_dir):
        if file.startswith("nexus_scanner_debug_") and file.endswith(".log"):
            log_files.append(os.path.join(log_dir, file))
    
    if not log_files:
        return None
    
    # Get the most recent log file
    latest_log = max(log_files, key=os.path.getctime)
    return latest_log

def parse_log_progress(log_file):
    """Parse the log file to extract current progress."""
    if not os.path.exists(log_file):
        return None
    
    progress = {
        'phase': 'unknown',
        'current_repository': 'unknown',
        'components_found': 0,
        'components_processed': 0,
        'assets_scanned': 0,
        'vulnerabilities_found': 0,
        'reports_generated': 0,
        'last_activity': 'unknown',
        'repositories_completed': [],
        'current_component': 'unknown'
    }
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Process lines from most recent to oldest for current state
        repo_pattern = re.compile(r'=== SCANNING REPOSITORY: (.+?) \(format: (.+?), type: (.+?)\) ===')
        component_retrieval_pattern = re.compile(r'Retrieved (\d+) components \(total: (\d+)\)')
        component_processing_pattern = re.compile(r'Processing component (\d+)/(\d+): (.+?)$')
        scanning_pattern = re.compile(r'SCANNING: (.+?) \(Type: (.+?)\)')
        vulnerability_pattern = re.compile(r'Found (\d+) vulnerabilities')
        report_pattern = re.compile(r'Individual HTML report retained:')
        
        current_repo = 'unknown'
        
        for line in reversed(lines[-500:]):  # Check last 500 lines for efficiency
            line = line.strip()
            
            # Check for repository scanning
            repo_match = repo_pattern.search(line)
            if repo_match:
                current_repo = repo_match.group(1)
                progress['current_repository'] = current_repo
                progress['phase'] = 'scanning_assets'
                break
                
            # Check for component retrieval (still in discovery phase)
            comp_retrieval_match = component_retrieval_pattern.search(line)
            if comp_retrieval_match and current_repo == 'unknown':
                progress['components_found'] = int(comp_retrieval_match.group(2))
                progress['phase'] = 'discovering_components'
                progress['last_activity'] = f"Retrieving components (found {comp_retrieval_match.group(2)})"
                break
        
        # Count totals from entire log
        for line in lines:
            # Count processing progress
            comp_proc_match = component_processing_pattern.search(line)
            if comp_proc_match:
                progress['components_processed'] = int(comp_proc_match.group(1))
                progress['current_component'] = comp_proc_match.group(3)
                progress['last_activity'] = f"Processing {comp_proc_match.group(3)}"
            
            # Count scanned assets
            if 'SCANNING:' in line:
                progress['assets_scanned'] += 1
            
            # Count vulnerabilities
            vuln_match = vulnerability_pattern.search(line)
            if vuln_match:
                progress['vulnerabilities_found'] += int(vuln_match.group(1))
            
            # Count reports generated
            if 'Individual HTML report retained:' in line:
                progress['reports_generated'] += 1
        
        return progress
        
    except Exception as e:
        print(f"Error parsing log: {e}")
        return None

def format_time_elapsed(start_time):
    """Format elapsed time in a readable format."""
    elapsed = time.time() - start_time
    hours = int(elapsed // 3600)
    minutes = int((elapsed % 3600) // 60)
    seconds = int(elapsed % 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"

def display_progress(progress, start_time):
    """Display the current progress in a nice format."""
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen
    
    print("🔍 NEXUS SCANNER PROGRESS MONITOR")
    print("=" * 50)
    print(f"⏱️  Runtime: {format_time_elapsed(start_time)}")
    print(f"📅 Started: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    if progress:
        # Phase indicator
        phase_emoji = {
            'discovering_components': '🔍',
            'scanning_assets': '🛡️',
            'generating_reports': '📄',
            'completed': '✅'
        }
        
        phase_name = {
            'discovering_components': 'Discovering Components',
            'scanning_assets': 'Scanning Assets for Vulnerabilities', 
            'generating_reports': 'Generating Reports',
            'completed': 'Scan Complete'
        }
        
        emoji = phase_emoji.get(progress['phase'], '❓')
        name = phase_name.get(progress['phase'], progress['phase'].title())
        
        print(f"🎯 Current Phase: {emoji} {name}")
        print(f"📂 Repository: {progress['current_repository']}")
        print()
        
        # Progress statistics
        print("📊 PROGRESS STATISTICS:")
        if progress['phase'] == 'discovering_components':
            print(f"   🔍 Components Found: {progress['components_found']:,}")
            print(f"   📝 Last Activity: {progress['last_activity']}")
        else:
            print(f"   🔍 Components Found: {progress['components_found']:,}")
            print(f"   ⚡ Components Processed: {progress['components_processed']:,}")
            print(f"   🛡️ Assets Scanned: {progress['assets_scanned']:,}")
            print(f"   🚨 Vulnerabilities Found: {progress['vulnerabilities_found']:,}")
            print(f"   📄 Reports Generated: {progress['reports_generated']:,}")
            
            if progress['current_component'] != 'unknown':
                print(f"   🔧 Current Component: {progress['current_component']}")
        
        print()
        
        # Individual reports status
        if progress['reports_generated'] > 0:
            print("📁 INDIVIDUAL REPORTS:")
            print(f"   📂 Reports Location: ./vulnerability_reports/individual_files_reports/")
            print(f"   📊 Total Reports: {progress['reports_generated']}")
            print("   📁 Organization: Separated by vulnerability status and repository")
        elif progress['phase'] == 'scanning_assets':
            print("📁 INDIVIDUAL REPORTS:")
            print("   ⏳ Reports will appear once asset scanning completes...")
        else:
            print("📁 INDIVIDUAL REPORTS:")
            print("   ⏳ Reports will be generated after component discovery completes...")
        
        print()
        
        # Helpful tips based on phase
        if progress['phase'] == 'discovering_components':
            print("💡 WHAT'S HAPPENING:")
            print("   • Scanner is retrieving all components from repositories")
            print("   • This can take time for large npm repositories (10-30 minutes)")
            print("   • Individual reports will be created during asset scanning phase")
        elif progress['phase'] == 'scanning_assets':
            print("💡 WHAT'S HAPPENING:")
            print("   • Scanner is downloading and scanning individual assets")
            print("   • Individual HTML reports are being generated and organized")
            print("   • Reports separated into 'with_vulnerabilities' and 'empty_reports' folders")
        
    else:
        print("❌ Could not parse progress from log file")
    
    print()
    print("Press Ctrl+C to exit monitor")

def monitor_progress():
    """Main monitoring loop."""
    print("🔍 Nexus Scanner Progress Monitor")
    print("Searching for active scanner log file...")
    
    log_file = get_latest_log_file()
    if not log_file:
        print("❌ No scanner log file found!")
        print("Make sure the scanner is running with DEBUG_LOG_FILE=true")
        return
    
    print(f"📋 Monitoring: {log_file}")
    print("Starting progress monitor...\n")
    
    start_time = os.path.getctime(log_file)
    
    try:
        while True:
            progress = parse_log_progress(log_file)
            display_progress(progress, start_time)
            time.sleep(10)  # Update every 10 seconds
            
    except KeyboardInterrupt:
        print("\n\n👋 Progress monitor stopped.")
        print("Scanner continues running in the background.")

if __name__ == "__main__":
    monitor_progress()
#!/usr/bin/env python3
"""
Clean Nexus Repository Scanner - No Unicode Characters
Scans all repositories and all components for vulnerabilities using Trivy.
"""

import os
import sys
import json
import csv
import glob
import shutil
import logging
import subprocess
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import Counter
import requests
from requests.auth import HTTPBasicAuth
from config_loader import get_config

# Configure logging without Unicode
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

class CleanNexusScanner:
    def __init__(self):
        """Initialize the intelligent scanner with configuration."""
        config = get_config()
        
        self.nexus_url = config['nexus_url']
        self.username = config['nexus_username']  
        self.password = config['nexus_password']
        self.trivy_path = config['trivy_path']
        self.output_dir = config.get('output_dir', './vulnerability_reports')
        
        # Debug configuration from .env
        self.debug_mode = config.get('debug_mode', False)
        self.debug_log_level = config.get('debug_log_level', 'INFO')
        self.debug_log_file = config.get('debug_log_file', False)
        self.debug_trivy_commands = config.get('debug_trivy_commands', False)
        self.debug_http_requests = config.get('debug_http_requests', False)
        
        # Report retention configuration
        self.retain_individual_reports = config.get('retain_individual_reports', False)
        
        # Create separate error and skip tracking
        self.scan_issues = {
            'errors': [],
            'skipped_files': [],
            'warnings': [],
            'successful_scans': []  # Track successfully scanned artifacts with details
        }
        
        # Setup authentication
        self.auth = HTTPBasicAuth(self.username, self.password)
        
        # Setup logging with debug configuration
        if self.debug_log_file:
            # Ensure output directory exists before creating log file
            os.makedirs(self.output_dir, exist_ok=True)
            
            log_filename = f"nexus_scanner_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            log_filepath = os.path.join(self.output_dir, log_filename)
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            
            # Set log level based on configuration
            if self.debug_log_level == 'DEBUG':
                log_level = logging.DEBUG
            elif self.debug_log_level == 'INFO':
                log_level = logging.INFO
            elif self.debug_log_level == 'WARNING':
                log_level = logging.WARNING
            else:
                log_level = logging.INFO
                
            # Create file handler
            file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            
            # Get or create logger
            self.logger = logging.getLogger('CleanNexusScanner')
            self.logger.setLevel(log_level)
            self.logger.addHandler(file_handler)
            
            # Also add console handler if in debug mode
            if self.debug_mode:
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setLevel(log_level)
                console_handler.setFormatter(formatter)
                self.logger.addHandler(console_handler)
            
            self.logger.info(f"Debug logging enabled - Log file: {log_filepath}")
            self.logger.info(f"Debug settings: mode={self.debug_mode}, trivy_commands={self.debug_trivy_commands}, http_requests={self.debug_http_requests}")
        else:
            self.logger = logging.getLogger('CleanNexusScanner')
        
        self.logger.info("Scanner initialization starting...")
        self.logger.debug(f"Python version: {sys.version}")
        self.logger.debug(f"Working directory: {os.getcwd()}")
        
        self.logger.info(f"Initialized intelligent scanner with Nexus: {self.nexus_url}")
        self.logger.info(f"Using Trivy: {self.trivy_path}")
        
        # Debug Trivy version
        try:
            trivy_version_cmd = [self.trivy_path, "--version"]
            result = subprocess.run(trivy_version_cmd, capture_output=True, text=True, timeout=30)
            self.logger.debug(f"Trivy version check: {result.stdout.strip()}")
            if result.stderr:
                self.logger.debug(f"Trivy version stderr: {result.stderr.strip()}")
        except Exception as e:
            self.logger.error(f"Failed to get Trivy version: {e}")
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Enhanced statistics with artifact type tracking
        self.stats = {
            'repositories_scanned': 0,
            'components_found': 0,
            'assets_scanned': 0,
            'vulnerabilities_found': 0,
            'scan_errors': 0
        }
        
        # Intelligent detection statistics using Counter for easy incrementation
        self.statistics = {
            'repository_types': Counter(),
            'artifact_types': Counter()
        }
        
        # Artifact type detection patterns
        self.artifact_patterns = {
            'java_jar': ['.jar', '.war', '.ear'],
            'java_source': ['.java', '.class'],
            'maven_pom': ['pom.xml', '.pom'],
            'container_image': ['.tar', '.tar.gz', '.tgz'],
            'docker_manifest': ['manifest.json', 'config.json'],
            'python_package': ['.whl', '.egg', '.tar.gz'],
            'node_package': ['package.json', '.tgz', '.npm'],
            'nuget_package': ['.nupkg', '.nuspec'],
            'archive': ['.zip', '.7z', '.rar'],
            'source_code': ['.zip', '.tar.gz', '.git'],
            'binary_executable': ['.exe', '.dll', '.so', '.dylib'],
            'script': ['.sh', '.bat', '.ps1', '.py', '.js'],
            'configuration': ['.xml', '.json', '.yaml', '.yml', '.properties', '.conf'],
            'sbom': ['.json', '.xml', '.spdx'],
            'security_report': ['trivy-report', 'scan-report', '.sarif']
        }
    
    def log_scan_issue(self, issue_type: str, asset_info: dict, reason: str, details: str = ""):
        """Log scan issues (errors, skips, warnings) to tracking system."""
        timestamp = datetime.now().isoformat()
        issue_record = {
            'timestamp': timestamp,
            'type': issue_type,
            'repository': asset_info.get('repository', 'Unknown'),
            'component': asset_info.get('component', 'Unknown'),
            'asset': asset_info.get('asset', 'Unknown'),
            'artifact_type': asset_info.get('artifact_type', 'Unknown'),
            'reason': reason,
            'details': details
        }
        
        if issue_type == 'error':
            self.scan_issues['errors'].append(issue_record)
            self.logger.error(f"Scan error - {reason}: {asset_info.get('asset', 'Unknown')}")
        elif issue_type == 'skip':
            self.scan_issues['skipped_files'].append(issue_record)
            self.logger.info(f"Skipping {asset_info.get('asset', 'Unknown')} - {reason}")
        elif issue_type == 'warning':
            self.scan_issues['warnings'].append(issue_record)
            self.logger.warning(f"Scan warning - {reason}: {asset_info.get('asset', 'Unknown')}")
        
        # Also add to debug log if enabled
        if self.debug_mode:
            self.logger.debug(f"Issue logged: {issue_record}")
    
    def log_successful_scan(self, asset_info: dict, scan_details: dict):
        """Log successfully scanned artifacts with details."""
        timestamp = datetime.now().isoformat()
        scan_record = {
            'timestamp': timestamp,
            'repository': asset_info.get('repository', 'Unknown'),
            'component': asset_info.get('component', 'Unknown'),
            'asset': asset_info.get('asset', 'Unknown'),
            'artifact_type': asset_info.get('artifact_type', 'Unknown'),
            'scan_strategy': scan_details.get('scan_strategy', 'Unknown'),
            'vulnerabilities_found': scan_details.get('vulnerabilities_found', 0),
            'scan_type': scan_details.get('scan_type', 'Unknown'),
            'file_size': scan_details.get('file_size', 'Unknown'),
            'scan_duration': scan_details.get('scan_duration', 'Unknown'),
            'trivy_command': scan_details.get('trivy_command', 'Unknown')
        }
        
        self.scan_issues['successful_scans'].append(scan_record)
        
        if scan_details.get('vulnerabilities_found', 0) > 0:
            self.logger.info(f"Successfully scanned {asset_info.get('asset', 'Unknown')} - Found {scan_details.get('vulnerabilities_found', 0)} vulnerabilities")
        else:
            self.logger.info(f"Successfully scanned {asset_info.get('asset', 'Unknown')} - No vulnerabilities found")
        
        # Also add to debug log if enabled
        if self.debug_mode:
            self.logger.debug(f"Successful scan logged: {scan_record}")
    
    def save_scan_issues_report(self, scan_timestamp: str):
        """Save scan issues to a separate report file."""
        try:
            # Create issues report filename
            issues_filename = f"scan_issues_report_{scan_timestamp.replace(':', '-')}.json"
            issues_filepath = os.path.join(self.output_dir, issues_filename)
            
            # Prepare comprehensive issues report
            issues_report = {
                'scan_metadata': {
                    'timestamp': scan_timestamp,
                    'nexus_url': self.nexus_url,
                    'total_errors': len(self.scan_issues['errors']),
                    'total_skipped': len(self.scan_issues['skipped_files']),
                    'total_warnings': len(self.scan_issues['warnings']),
                    'total_successful_scans': len(self.scan_issues['successful_scans'])
                },
                'summary': {
                    'errors_by_reason': self._group_issues_by_reason(self.scan_issues['errors']),
                    'skips_by_reason': self._group_issues_by_reason(self.scan_issues['skipped_files']),
                    'warnings_by_reason': self._group_issues_by_reason(self.scan_issues['warnings']),
                    'successful_scans_by_type': self._group_successful_scans_by_type(self.scan_issues['successful_scans'])
                },
                'detailed_issues': {
                    'errors': self.scan_issues['errors'],
                    'skipped_files': self.scan_issues['skipped_files'],
                    'warnings': self.scan_issues['warnings']
                },
                'successful_scans': self.scan_issues['successful_scans']
            }
            
            # Save to JSON file
            with open(issues_filepath, 'w', encoding='utf-8') as f:
                json.dump(issues_report, f, indent=2, ensure_ascii=False)
            
            # Also create a human-readable CSV for skipped files
            csv_filename = f"skipped_files_report_{scan_timestamp.replace(':', '-')}.csv"
            csv_filepath = os.path.join(self.output_dir, csv_filename)
            
            if self.scan_issues['skipped_files']:
                with open(csv_filepath, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = ['timestamp', 'repository', 'component', 'asset', 'artifact_type', 'reason', 'details']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    # Filter out 'type' field from each record
                    for issue in self.scan_issues['skipped_files']:
                        row_data = {k: v for k, v in issue.items() if k in fieldnames}
                        writer.writerow(row_data)
            
            # Create a CSV report for successful scans
            success_csv_filename = f"successful_scans_report_{scan_timestamp.replace(':', '-')}.csv"
            success_csv_filepath = os.path.join(self.output_dir, success_csv_filename)
            
            if self.scan_issues['successful_scans']:
                with open(success_csv_filepath, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = ['timestamp', 'repository', 'component', 'asset', 'artifact_type', 
                                'scan_strategy', 'vulnerabilities_found', 'scan_type', 'file_size', 'scan_duration']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for scan in self.scan_issues['successful_scans']:
                        row_data = {k: v for k, v in scan.items() if k in fieldnames}
                        writer.writerow(row_data)
            
            self.logger.info(f"Scan issues report saved to: {issues_filepath}")
            if self.scan_issues['skipped_files']:
                self.logger.info(f"Skipped files CSV saved to: {csv_filepath}")
            if self.scan_issues['successful_scans']:
                self.logger.info(f"Successful scans CSV saved to: {success_csv_filepath}")
            
            # Create a CSV report for error/failed scans
            error_csv_filename = f"error_scans_report_{scan_timestamp.replace(':', '-')}.csv"
            error_csv_filepath = os.path.join(self.output_dir, error_csv_filename)
            
            if self.scan_issues['errors']:
                with open(error_csv_filepath, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = ['timestamp', 'repository', 'component', 'asset', 'artifact_type', 
                                'reason', 'details']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    # Filter out 'type' field from each record
                    for error in self.scan_issues['errors']:
                        row_data = {k: v for k, v in error.items() if k in fieldnames}
                        writer.writerow(row_data)
                        
                self.logger.info(f"Error scans CSV saved to: {error_csv_filepath}")
                
        except Exception as e:
            self.logger.error(f"Error saving scan issues report: {e}")
    
    def _group_issues_by_reason(self, issues_list: list) -> dict:
        """Group issues by reason for summary statistics."""
        reason_counts = {}
        for issue in issues_list:
            reason = issue.get('reason', 'Unknown')
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        return reason_counts
    
    def _group_successful_scans_by_type(self, successful_scans_list: list) -> dict:
        """Group successful scans by artifact type for summary statistics."""
        type_stats = {}
        for scan in successful_scans_list:
            artifact_type = scan.get('artifact_type', 'Unknown')
            if artifact_type not in type_stats:
                type_stats[artifact_type] = {
                    'count': 0,
                    'total_vulnerabilities': 0,
                    'clean_scans': 0
                }
            type_stats[artifact_type]['count'] += 1
            type_stats[artifact_type]['total_vulnerabilities'] += scan.get('vulnerabilities_found', 0)
            if scan.get('vulnerabilities_found', 0) == 0:
                type_stats[artifact_type]['clean_scans'] += 1
        return type_stats
    
    def test_connection(self) -> bool:
        """Test connection to Nexus server."""
        try:
            response = requests.get(
                f"{self.nexus_url}/service/rest/v1/status",
                auth=self.auth,
                timeout=30
            )
            if response.status_code == 200:
                self.logger.info("Successfully connected to Nexus server")
                return True
            else:
                self.logger.error(f"Failed to connect: HTTP {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def get_repositories(self) -> List[Dict[str, Any]]:
        """Get all repositories from Nexus."""
        try:
            response = requests.get(
                f"{self.nexus_url}/service/rest/v1/repositories",
                auth=self.auth,
                timeout=30
            )
            response.raise_for_status()
            repositories = response.json()
            
            # Filter for hosted repositories (all formats including Docker)
            hosted_repos = [repo for repo in repositories if repo.get('type') == 'hosted']
            
            # Log repository types found
            repo_types = {}
            for repo in hosted_repos:
                format_type = repo.get('format', 'unknown')
                repo_types[format_type] = repo_types.get(format_type, 0) + 1
            
            self.logger.info(f"Found {len(hosted_repos)} hosted repositories: {dict(repo_types)}")
            return hosted_repos
            
        except Exception as e:
            self.logger.error(f"Error getting repositories: {e}")
            return []
    
    def get_repository_components(self, repository_name: str) -> List[Dict[str, Any]]:
        """Get all components from a specific repository using pagination."""
        components = []
        continuation_token = None
        
        try:
            while True:
                # Build URL with pagination
                url = f"{self.nexus_url}/service/rest/v1/components"
                params = {'repository': repository_name}
                
                if continuation_token:
                    params['continuationToken'] = continuation_token
                
                response = requests.get(url, auth=self.auth, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                batch_components = data.get('items', [])
                components.extend(batch_components)
                
                # Check for more pages
                continuation_token = data.get('continuationToken')
                if not continuation_token:
                    break
                    
                self.logger.info(f"Retrieved {len(batch_components)} components (total: {len(components)})")
            
            self.logger.info(f"Found {len(components)} components in '{repository_name}'")
            return components
            
        except Exception as e:
            self.logger.error(f"Error getting components from {repository_name}: {e}")
            return []
    
    def download_asset(self, asset_url: str, local_path: str) -> bool:
        """Download an asset from Nexus."""
        try:
            self.logger.debug(f"=== Starting asset download ===")
            self.logger.debug(f"Asset URL: {asset_url}")
            self.logger.debug(f"Local path: {local_path}")
            
            response = requests.get(asset_url, auth=self.auth, stream=True, timeout=60)
            self.logger.debug(f"HTTP status code: {response.status_code}")
            self.logger.debug(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
            self.logger.debug(f"Content-Length: {response.headers.get('Content-Length', 'Unknown')}")
            
            response.raise_for_status()
            
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            downloaded_size = 0
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded_size += len(chunk)
            
            self.logger.debug(f"Downloaded {downloaded_size} bytes")
            self.logger.debug(f"File exists after download: {os.path.exists(local_path)}")
            if os.path.exists(local_path):
                actual_size = os.path.getsize(local_path)
                self.logger.debug(f"Actual file size: {actual_size} bytes")
            
            self.logger.debug(f"=== Asset download completed ===")
            return True
            
        except Exception as e:
            self.logger.error(f"Error downloading {asset_url}: {e}")
            self.logger.debug(f"Download exception details: ", exc_info=True)
            return False
    
    def scan_with_trivy(self, file_path: str, scan_type: str = "fs") -> Optional[tuple]:
        """Scan a file or directory with Trivy. Returns (json_results, html_output)."""
        try:
            self.logger.debug(f"=== Starting Trivy scan ===")
            self.logger.debug(f"File path: {file_path}")
            self.logger.debug(f"Scan type: {scan_type}")
            self.logger.debug(f"File exists: {os.path.exists(file_path)}")
            if os.path.exists(file_path):
                self.logger.debug(f"File size: {os.path.getsize(file_path)} bytes")
            
            # Create output files for Trivy results
            json_output_file = f"{file_path}.trivy.json"
            html_output_file = f"{file_path}.trivy.html"
            
            self.logger.debug(f"JSON output: {json_output_file}")
            self.logger.debug(f"HTML output: {html_output_file}")
            
            # JSON scan for programmatic processing
            json_cmd = [
                self.trivy_path,
                scan_type,
                "--format", "json",
                "--output", json_output_file,
                file_path
            ]
            
            # HTML scan using Trivy's built-in template
            html_template_path = os.path.join(os.path.dirname(self.trivy_path), 'contrib', 'html.tpl')
            html_cmd = [
                self.trivy_path,
                scan_type,
                "--format", "template",
                "--template", f"@{html_template_path}",
                "--output", html_output_file,
                file_path
            ]
            
            # Add --quiet flag only if not in debug mode
            if not self.debug_mode:
                json_cmd.insert(-1, "--quiet")
                html_cmd.insert(-1, "--quiet")
            
            self.logger.debug(f"JSON command: {' '.join(json_cmd)}")
            
            # Run JSON scan
            json_result = subprocess.run(json_cmd, capture_output=True, text=True, timeout=300)
            
            self.logger.debug(f"JSON scan return code: {json_result.returncode}")
            if json_result.stdout:
                self.logger.debug(f"JSON scan stdout: {json_result.stdout}")
            if json_result.stderr:
                self.logger.debug(f"JSON scan stderr: {json_result.stderr}")
                
            if json_result.returncode != 0:
                self.logger.error(f"Trivy JSON scan failed for {file_path}")
                self.logger.error(f"Return code: {json_result.returncode}")
                self.logger.error(f"STDERR: {json_result.stderr}")
                return None
            
            self.logger.debug(f"HTML command: {' '.join(html_cmd)}")
            
            # Run HTML scan
            html_result = subprocess.run(html_cmd, capture_output=True, text=True, timeout=300)
            
            self.logger.debug(f"HTML scan return code: {html_result.returncode}")
            if html_result.stdout:
                self.logger.debug(f"HTML scan stdout: {html_result.stdout}")
            if html_result.stderr:
                self.logger.debug(f"HTML scan stderr: {html_result.stderr}")
            
            json_data = None
            html_content = None
            
            # Read JSON results
            if os.path.exists(json_output_file):
                try:
                    with open(json_output_file, 'r', encoding='utf-8') as f:
                        json_content = f.read()
                        self.logger.debug(f"JSON file size: {len(json_content)} characters")
                        if json_content.strip():
                            json_data = json.loads(json_content)
                            self.logger.debug(f"JSON parsed successfully, type: {type(json_data)}")
                        else:
                            self.logger.debug("JSON file is empty")
                    os.remove(json_output_file)
                    self.logger.debug("JSON output file cleaned up")
                except Exception as e:
                    self.logger.error(f"Error parsing JSON results: {e}")
            else:
                self.logger.warning(f"JSON output file not found: {json_output_file}")
            
            # Read HTML results
            if os.path.exists(html_output_file):
                try:
                    with open(html_output_file, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                        self.logger.debug(f"HTML file size: {len(html_content)} characters")
                    os.remove(html_output_file)
                    self.logger.debug("HTML output file cleaned up")
                except Exception as e:
                    self.logger.error(f"Error reading HTML results: {e}")
            else:
                self.logger.warning(f"HTML output file not found: {html_output_file}")
                
            self.logger.debug(f"=== Trivy scan completed ===")
            return (json_data, html_content)
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Trivy scan timed out for {file_path}")
            return None
        except Exception as e:
            self.logger.error(f"Error scanning {file_path} with Trivy: {e}")
            self.logger.debug(f"Exception details: ", exc_info=True)
            return None
    
    def extract_vulnerabilities(self, trivy_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerability information from Trivy results."""
        vulnerabilities = []
        
        if not trivy_results:
            return vulnerabilities
            
        results = trivy_results.get('Results', [])
        for result in results:
            target = result.get('Target', 'Unknown')
            vulns = result.get('Vulnerabilities', [])
            
            for vuln in vulns:
                vulnerability = {
                    'target': target,
                    'vulnerability_id': vuln.get('VulnerabilityID', ''),
                    'pkg_name': vuln.get('PkgName', ''),
                    'pkg_version': vuln.get('InstalledVersion', ''),
                    'severity': vuln.get('Severity', 'UNKNOWN'),
                    'title': vuln.get('Title', ''),
                    'description': vuln.get('Description', ''),
                    'fixed_version': vuln.get('FixedVersion', ''),
                    'references': vuln.get('References', [])
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def scan_with_strategy(self, file_path: str, strategy: dict, artifact_type: str) -> Optional[tuple]:
        """Scan a file using the intelligent strategy. Returns (json_results, html_output)."""
        try:
            # Handle file extraction if needed
            actual_scan_path = file_path
            temp_extract_dir = None
            
            if strategy.get('extract_before_scan'):
                temp_extract_dir = f"{file_path}_extracted"
                if self.extract_archive(file_path, temp_extract_dir):
                    actual_scan_path = temp_extract_dir
                    self.logger.info(f"Extracted {artifact_type} archive for deeper scanning")
                else:
                    self.logger.warning(f"Could not extract {file_path}, scanning as-is")
            
            # Perform the scan
            scan_type = strategy.get('scan_type', 'fs')
            results = self.scan_with_trivy(actual_scan_path, scan_type)
            
            # Clean up extracted files
            if temp_extract_dir and os.path.exists(temp_extract_dir):
                try:
                    import shutil
                    shutil.rmtree(temp_extract_dir)
                except Exception as e:
                    self.logger.warning(f"Could not clean up extracted directory {temp_extract_dir}: {e}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in strategic scan of {file_path}: {e}")
            return None
    
    def extract_archive(self, archive_path: str, extract_dir: str) -> bool:
        """Extract archive files for scanning."""
        try:
            import zipfile
            import tarfile
            
            os.makedirs(extract_dir, exist_ok=True)
            archive_lower = archive_path.lower()
            
            if archive_lower.endswith('.zip') or archive_lower.endswith('.jar') or archive_lower.endswith('.war'):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                return True
            
            elif archive_lower.endswith(('.tar.gz', '.tgz')):
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_dir)
                return True
            
            elif archive_lower.endswith('.tar'):
                with tarfile.open(archive_path, 'r') as tar_ref:
                    tar_ref.extractall(extract_dir)
                return True
            
            else:
                self.logger.warning(f"Unsupported archive format: {archive_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error extracting {archive_path}: {e}")
            return False
    
    def scan_content_repositories(self):
        """Scan all content repositories for vulnerabilities."""
        if not self.test_connection():
            self.logger.error("Cannot connect to Nexus server")
            return
        
        repositories = self.get_repositories()
        if not repositories:
            self.logger.error("No repositories found to scan")
            return
        
        all_vulnerabilities = []
        scan_timestamp = datetime.now().isoformat()
        
        self.logger.info(f"Starting scan of {len(repositories)} repositories")
        
        for repo in repositories:
            repo_name = repo['name']
            self.logger.info(f"Scanning repository: {repo_name}")
            self.stats['repositories_scanned'] += 1
            
            components = self.get_repository_components(repo_name)
            self.stats['components_found'] += len(components)
            
            for component in components:
                component_name = component.get('name', 'unknown')
                component_version = component.get('version', 'unknown')
                
                self.logger.info(f"Processing component: {component_name}:{component_version}")
                
                assets = component.get('assets', [])
                # Handle different repository formats
                repo_format = repo.get('format', 'unknown')
                
                if repo_format == 'docker':
                    # For Docker repositories, scan container images
                    vulnerabilities = self.scan_docker_components(component, repo_name, scan_timestamp)
                    all_vulnerabilities.extend(vulnerabilities)
                else:
                    # For other formats, scan individual assets
                    assets = component.get('assets', [])
                    for asset in assets:
                        asset_name = asset.get('path', asset.get('name', 'unknown'))
                        download_url = asset.get('downloadUrl', '')
                        
                        if not download_url:
                            continue
                        
                        # Detect artifact type and determine scanning strategy
                        artifact_type = self.detect_artifact_type(asset_name, repo_format)
                        self.statistics['artifact_types'][artifact_type] += 1
                        self.logger.debug(f"Detected artifact type: {artifact_type}")
                        
                        strategy = self.determine_scan_strategy(artifact_type, asset_name, repo_format)
                        self.logger.debug(f"Scan strategy: {strategy}")
                        
                        if strategy['skip_scan']:
                            # Log skip with detailed asset information
                            asset_info = {
                                'repository': repo_name,
                                'component': component_name,
                                'asset': asset_name,
                                'artifact_type': artifact_type
                            }
                            self.log_scan_issue('skip', asset_info, strategy['reason'], f"Download URL: {download_url}")
                            continue
                        
                        self.logger.info(f"Scanning asset: {asset_name} (Type: {artifact_type})")
                        self.logger.info(f"Strategy: {strategy['reason']}")
                        self.stats['assets_scanned'] += 1
                        
                        # Create local filename for download
                        safe_filename = asset_name.replace('/', '_').replace('\\', '_')
                        local_path = os.path.join(self.output_dir, 'temp', safe_filename)
                        
                        self.logger.debug(f"Download URL: {download_url}")
                        self.logger.debug(f"Local path: {local_path}")
                        
                        # Download and scan
                        if self.download_asset(download_url, local_path):
                            self.logger.debug(f"Asset downloaded successfully")
                            
                            # Use intelligent scanning strategy
                            scan_start_time = datetime.now()
                            scan_results = self.scan_with_strategy(local_path, strategy, artifact_type)
                            scan_end_time = datetime.now()
                            scan_duration = str(scan_end_time - scan_start_time)
                            
                            if scan_results and scan_results[0]:  # Check JSON results
                                json_data, html_content = scan_results
                                vulnerabilities = self.extract_vulnerabilities(json_data)
                                self.stats['vulnerabilities_found'] += len(vulnerabilities)
                                
                                # Log successful scan with details
                                file_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
                                asset_info = {
                                    'repository': repo_name,
                                    'component': component_name,
                                    'asset': asset_name,
                                    'artifact_type': artifact_type
                                }
                                scan_details = {
                                    'scan_strategy': strategy['reason'],
                                    'vulnerabilities_found': len(vulnerabilities),
                                    'scan_type': strategy['scan_type'],
                                    'file_size': f"{file_size:,} bytes",
                                    'scan_duration': scan_duration,
                                    'trivy_command': f"trivy {strategy['scan_type']}"
                                }
                                self.log_successful_scan(asset_info, scan_details)
                                
                                # Add metadata to each vulnerability
                                for vuln in vulnerabilities:
                                    vuln.update({
                                        'repository': repo_name,
                                        'repository_format': repo_format,
                                        'component': component_name,
                                        'component_version': component_version,
                                        'asset': asset_name,
                                        'artifact_type': artifact_type,
                                        'scan_strategy': strategy['reason'],
                                        'scan_timestamp': scan_timestamp
                                    })
                                
                                all_vulnerabilities.extend(vulnerabilities)
                                
                                # Save individual HTML report for all successful scans
                                if html_content:
                                    self.save_individual_html_report(html_content, component_name, asset_name, scan_timestamp)
                                
                                if vulnerabilities:
                                    self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities in {asset_name}")
                            else:
                                # Log scan error with detailed information
                                asset_info = {
                                    'repository': repo_name,
                                    'component': component_name,
                                    'asset': asset_name,
                                    'artifact_type': artifact_type
                                }
                                self.log_scan_issue('error', asset_info, 'Trivy scan failed', f"Strategy: {strategy['reason']}, Path: {local_path}")
                                self.stats['scan_errors'] += 1
                        else:
                            # Log download error
                            asset_info = {
                                'repository': repo_name,
                                'component': component_name,
                                'asset': asset_name,
                                'artifact_type': artifact_type
                            }
                            self.log_scan_issue('error', asset_info, 'Asset download failed', f"URL: {download_url}")
                            
                            # Clean up downloaded file
                            try:
                                os.remove(local_path)
                            except:
                                pass
        
        # Save results
        self.save_results(all_vulnerabilities, scan_timestamp)
        self.generate_combined_report(all_vulnerabilities, scan_timestamp)
        self.save_scan_issues_report(scan_timestamp)  # Save separate issues report
        
        # Clean up temporary individual reports if retention is disabled
        if not self.retain_individual_reports:
            self.cleanup_temporary_reports()
        
        # Always clean up downloaded temp files (but preserve individual reports if configured)
        self.cleanup_downloaded_files()
            
        self.print_summary()
        
        # Move all reports to timestamped folder
        self.move_reports_to_timestamped_folder(scan_timestamp)
    
    def save_results(self, vulnerabilities: List[Dict[str, Any]], timestamp: str):
        """Save scan results to files."""
        # JSON output
        json_file = os.path.join(self.output_dir, f'nexus_scan_results_{timestamp.replace(":", "-")}.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'scan_timestamp': timestamp,
                'statistics': self.stats,
                'vulnerabilities': vulnerabilities
            }, f, indent=2, ensure_ascii=False)
        
        # CSV output
        csv_file = os.path.join(self.output_dir, f'nexus_scan_results_{timestamp.replace(":", "-")}.csv')
        if vulnerabilities:
            fieldnames = vulnerabilities[0].keys()
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(vulnerabilities)
        
        self.logger.info(f"Results saved to:")
        self.logger.info(f"  JSON: {json_file}")
        self.logger.info(f"  CSV: {csv_file}")
    
    def detect_artifact_type(self, asset_name: str, repo_format: str) -> str:
        """Intelligently detect artifact type based on file extension and repository format."""
        asset_lower = asset_name.lower()
        
        # Repository format-based detection for Docker repositories
        if repo_format == 'docker':
            return 'container_image'
        
        # Hash/checksum files should be detected first
        if any(asset_lower.endswith(ext) for ext in ['.md5', '.sha1', '.sha256', '.sha512']):
            return 'script'  # These are treated as script files for consistency
        
        # Specific file extension patterns (in priority order)
        # Java artifacts
        if any(asset_lower.endswith(ext) for ext in ['.jar', '.war', '.ear']):
            return 'java_jar'
        elif any(asset_lower.endswith(ext) for ext in ['.java', '.class']):
            return 'java_source'
        elif 'pom.xml' in asset_lower or asset_lower.endswith('.pom'):
            return 'maven_pom'
        
        # Python packages (check before generic archives)
        if any(asset_lower.endswith(ext) for ext in ['.whl', '.egg']) or (asset_lower.endswith('.tar.gz') and 'python' in asset_lower):
            return 'python_package'
        
        # NuGet packages
        if any(asset_lower.endswith(ext) for ext in ['.nupkg', '.nuspec']):
            return 'nuget_package'
        
        # Node packages
        if 'package.json' in asset_lower or asset_lower.endswith('.npm') or (asset_lower.endswith('.tgz') and 'node' in asset_lower):
            return 'node_package'
        
        # Container images (only for actual Docker layers/manifests, not in Maven repos)
        if repo_format != 'docker' and any(filename in asset_lower for filename in ['manifest.json', 'config.json']):
            return 'docker_manifest'
        
        # Archives (generic)
        if any(asset_lower.endswith(ext) for ext in ['.zip', '.7z', '.rar']):
            return 'archive'
        elif any(asset_lower.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz']) and repo_format != 'docker':
            return 'archive'  # Treat .tar.gz as archives unless in Docker repo
        
        # Binary executables
        if any(asset_lower.endswith(ext) for ext in ['.exe', '.dll', '.so', '.dylib']):
            return 'binary_executable'
        
        # Scripts
        if any(asset_lower.endswith(ext) for ext in ['.sh', '.bat', '.ps1', '.py', '.js']):
            return 'script'
        
        # Configuration files
        if any(asset_lower.endswith(ext) for ext in ['.xml', '.json', '.yaml', '.yml', '.properties', '.conf']):
            return 'configuration'
        
        # SBOM files
        if any(filename in asset_lower for filename in ['.spdx']) or (asset_lower.endswith('.json') and 'sbom' in asset_lower):
            return 'sbom'
        
        # Security reports
        if any(filename in asset_lower for filename in ['trivy-report', 'scan-report', '.sarif']):
            return 'security_report'
        
        # Repository format-based fallback
        if repo_format == 'maven2':
            return 'maven_artifact'
        elif repo_format == 'nuget':
            return 'nuget_package'
        elif repo_format == 'raw':
            return 'raw_file'
        
        return 'unknown'
    
    def determine_scan_strategy(self, artifact_type: str, file_path: str, repo_format: str) -> dict:
        """Determine the best scanning strategy based on artifact type."""
        strategy = {
            'scan_type': 'fs',
            'extract_before_scan': False,
            'scan_as_archive': False,
            'skip_scan': False,
            'reason': ''
        }
        
        # Java artifacts
        if artifact_type in ['java_jar', 'maven_artifact']:
            strategy.update({
                'scan_type': 'fs',
                'scan_as_archive': True,
                'reason': 'Java archive - scan for dependencies and vulnerabilities'
            })
        
        # Container images
        elif artifact_type == 'container_image' or repo_format == 'docker':
            strategy.update({
                'scan_type': 'image',  # Use Trivy's image scanning for container images
                'extract_before_scan': False,  # Trivy handles container layers automatically
                'reason': 'Container image - scan with Trivy image scanner'
            })
        
        # Python packages
        elif artifact_type == 'python_package':
            strategy.update({
                'scan_type': 'fs',
                'scan_as_archive': True,
                'reason': 'Python package - scan for dependencies'
            })
        
        # Archives that might contain source code
        elif artifact_type in ['archive', 'source_code']:
            strategy.update({
                'scan_type': 'fs',
                'extract_before_scan': True,
                'reason': 'Archive/source code - extract and scan contents'
            })
        
        # Configuration and SBOM files
        elif artifact_type in ['configuration', 'sbom']:
            strategy.update({
                'scan_type': 'config',
                'reason': 'Configuration/SBOM file - scan for misconfigurations'
            })
        
        # Hash/checksum files - skip scanning
        elif any(ext in file_path.lower() for ext in ['.md5', '.sha1', '.sha256', '.sha512']):
            strategy.update({
                'skip_scan': True,
                'reason': 'Hash/checksum file - not scannable'
            })
        
        # Security reports - skip to avoid recursion
        elif artifact_type == 'security_report':
            strategy.update({
                'skip_scan': True,
                'reason': 'Existing security report - skip to avoid recursion'
            })
        
        return strategy
    
    def scan_docker_components(self, component: Dict[str, Any], repo_name: str, scan_timestamp: str) -> List[Dict[str, Any]]:
        """Scan Docker components (container images) using Trivy's native image scanning."""
        vulnerabilities = []
        component_name = component.get('name', 'unknown')
        component_version = component.get('version', 'unknown')
        
        try:
            # Construct the image reference for Docker registry scanning
            # Format: nexus-server:port/repository-name/image-name:version
            nexus_host = self.nexus_url.replace('http://', '').replace('https://', '')
            if nexus_host.endswith('/'):
                nexus_host = nexus_host[:-1]
            
            # For Docker repositories, the image reference format varies
            # Try different common patterns
            image_references = [
                f"{nexus_host}/{repo_name}/{component_name}:{component_version}",
                f"{nexus_host}/{component_name}:{component_version}",
                f"{component_name}:{component_version}"  # For pulled/local images
            ]
            
            self.logger.info(f"Attempting to scan Docker image: {component_name}:{component_version}")
            
            # Try scanning with different image reference formats
            scan_successful = False
            for image_ref in image_references:
                self.logger.info(f"Trying image reference: {image_ref}")
                
                # Try direct image scanning first
                results = self.scan_docker_image_direct(image_ref, component_name, component_version)
                if results:
                    # Process results and add metadata
                    for vuln in results:
                        vuln.update({
                            'repository': repo_name,
                            'repository_format': 'docker',
                            'component': component_name,
                            'component_version': component_version,
                            'artifact_type': 'container_image',
                            'scan_strategy': 'Direct Docker image scan',
                            'scan_timestamp': scan_timestamp,
                            'image_reference': image_ref
                        })
                    
                    vulnerabilities.extend(results)
                    scan_successful = True
                    self.logger.info(f"Successfully scanned Docker image with reference: {image_ref}")
                    break
            
            if not scan_successful:
                self.logger.warning(f"Could not scan Docker image {component_name}:{component_version} - image may not be accessible or Docker not available")
                # Fall back to asset-based scanning if available
                assets = component.get('assets', [])
                if assets:
                    self.logger.info("Falling back to asset-based scanning for Docker component")
                    # This will be handled by the normal asset scanning logic
            
        except Exception as e:
            # Log Docker component processing error
            asset_info = {
                'repository': repo_name,
                'component': component_name,
                'asset': f"docker_image_{component_version}",
                'artifact_type': 'container_image'
            }
            self.log_scan_issue('error', asset_info, 'Docker component processing failed', f"Error: {str(e)}")
            self.stats['scan_errors'] += 1
        
        return vulnerabilities
    
    def scan_docker_image_direct(self, image_reference: str, component_name: str, component_version: str) -> List[Dict[str, Any]]:
        """Scan Docker image directly using Trivy's image scanning capability."""
        try:
            self.logger.debug(f"=== Starting Docker image scan ===")
            self.logger.debug(f"Image reference: {image_reference}")
            self.logger.debug(f"Component: {component_name}:{component_version}")
            
            # Create output files
            safe_name = image_reference.replace('/', '_').replace(':', '_')
            json_output_file = os.path.join(self.output_dir, 'temp', f"{safe_name}_docker.json")
            html_output_file = os.path.join(self.output_dir, 'temp', f"{safe_name}_docker.html")
            
            os.makedirs(os.path.dirname(json_output_file), exist_ok=True)
            self.logger.debug(f"Docker JSON output: {json_output_file}")
            self.logger.debug(f"Docker HTML output: {html_output_file}")
            
            # JSON scan command
            json_cmd = [
                self.trivy_path, "image",
                "--format", "json",
                "--output", json_output_file,
                image_reference
            ]
            
            # HTML scan command  
            html_template_path = os.path.join(os.path.dirname(self.trivy_path), 'contrib', 'html.tpl')
            html_cmd = [
                self.trivy_path, "image",
                "--format", "template", 
                "--template", f"@{html_template_path}",
                "--output", html_output_file,
                image_reference
            ]
            
            # Add --quiet flag only if not in debug mode
            if not self.debug_mode:
                json_cmd.insert(-1, "--quiet")
                html_cmd.insert(-1, "--quiet")
            
            self.logger.debug(f"Docker JSON command: {' '.join(json_cmd)}")
            
            # Run JSON scan
            json_result = subprocess.run(json_cmd, capture_output=True, text=True, timeout=300)
            
            self.logger.debug(f"Docker JSON scan return code: {json_result.returncode}")
            if json_result.stdout:
                self.logger.debug(f"Docker JSON scan stdout: {json_result.stdout}")
            if json_result.stderr:
                self.logger.debug(f"Docker JSON scan stderr: {json_result.stderr}")
                
            if json_result.returncode != 0:
                self.logger.debug(f"Docker image scan failed for {image_reference}: {json_result.stderr}")
                return []
            
            self.logger.debug(f"Docker HTML command: {' '.join(html_cmd)}")
            
            # Run HTML scan
            html_result = subprocess.run(html_cmd, capture_output=True, text=True, timeout=300)
            
            self.logger.debug(f"Docker HTML scan return code: {html_result.returncode}")
            if html_result.stdout:
                self.logger.debug(f"Docker HTML scan stdout: {html_result.stdout}")
            if html_result.stderr:
                self.logger.debug(f"Docker HTML scan stderr: {html_result.stderr}")
            
            # Parse JSON results
            vulnerabilities = []
            if os.path.exists(json_output_file):
                try:
                    with open(json_output_file, 'r', encoding='utf-8') as f:
                        json_content = f.read()
                        self.logger.debug(f"Docker JSON file size: {len(json_content)} characters")
                        if json_content.strip():
                            json_data = json.loads(json_content)
                            vulnerabilities = self.extract_vulnerabilities(json_data)
                            self.logger.debug(f"Docker scan found {len(vulnerabilities)} vulnerabilities")
                        else:
                            self.logger.debug("Docker JSON file is empty")
                except Exception as e:
                    self.logger.error(f"Error parsing Docker JSON results: {e}")
                
                # Save individual HTML report if vulnerabilities found and HTML exists
                if vulnerabilities and os.path.exists(html_output_file):
                    try:
                        with open(html_output_file, 'r', encoding='utf-8') as f:
                            html_content = f.read()
                        self.save_individual_html_report(html_content, component_name, f"docker_image_{component_version}", "docker_scan")
                        self.logger.debug("Docker HTML report saved")
                    except Exception as e:
                        self.logger.error(f"Error saving Docker HTML report: {e}")
                
                # Clean up temp files
                for temp_file in [json_output_file, html_output_file]:
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                            self.logger.debug(f"Cleaned up temp file: {temp_file}")
                        except Exception as e:
                            self.logger.debug(f"Could not clean up temp file {temp_file}: {e}")
                            
            self.logger.debug(f"=== Docker image scan completed ===")
            return vulnerabilities
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Docker image scan timed out for {image_reference}")
            return []
        except Exception as e:
            self.logger.debug(f"Error in direct Docker scan for {image_reference}: {e}")
            self.logger.debug(f"Docker scan exception details: ", exc_info=True)
            return []
    
    def save_individual_html_report(self, html_content: str, component_name: str, asset_name: str, timestamp: str):
        """Save individual HTML report for assets with vulnerabilities."""
        try:
            # Create safe filename
            safe_component = component_name.replace('/', '_').replace(':', '_')
            safe_asset = asset_name.replace('/', '_').replace('\\', '_')
            
            if self.retain_individual_reports:
                # Create individual_files_reports directory if it doesn't exist
                individual_reports_dir = os.path.join(self.output_dir, 'individual_files_reports')
                os.makedirs(individual_reports_dir, exist_ok=True)
                
                # Use structured filename: component_name_asset_name_report.html
                filename = f"{safe_component}_{safe_asset}_report.html"
                html_file = os.path.join(individual_reports_dir, filename)
                
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                self.logger.info(f"Individual HTML report retained: {html_file}")
                
            else:
                # Original behavior - save to main directory temporarily (will be cleaned up)
                html_file = os.path.join(
                    self.output_dir, 
                    f'individual_report_{safe_component}_{safe_asset}_{timestamp.replace(":", "-")}.html'
                )
                
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                self.logger.debug(f"Temporary individual HTML report saved: {html_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving individual HTML report: {e}")
    
    def cleanup_temporary_reports(self):
        """Clean up temporary individual HTML reports when retention is disabled."""
        try:
            report_pattern = os.path.join(self.output_dir, 'individual_report_*.html')
            temp_reports = glob.glob(report_pattern)
            
            if temp_reports:
                self.logger.info(f"Cleaning up {len(temp_reports)} temporary individual reports")
                for report_file in temp_reports:
                    try:
                        os.remove(report_file)
                        self.logger.debug(f"Removed temporary report: {os.path.basename(report_file)}")
                    except Exception as e:
                        self.logger.debug(f"Could not remove {report_file}: {e}")
            else:
                self.logger.debug("No temporary individual reports to clean up")
                
        except Exception as e:
            self.logger.error(f"Error during temporary report cleanup: {e}")
    
    def cleanup_downloaded_files(self):
        """Clean up downloaded files from temp directory while preserving individual reports if configured."""
        try:
            temp_dir = os.path.join(self.output_dir, 'temp')
            if os.path.exists(temp_dir):
                # Count files before cleanup
                file_count = 0
                for root, dirs, files in os.walk(temp_dir):
                    file_count += len(files)
                
                if file_count > 0:
                    self.logger.info(f"Cleaning up {file_count} downloaded files from temp directory")
                    
                    # Remove the entire temp directory and its contents
                    shutil.rmtree(temp_dir)
                    self.logger.debug(f"Removed temp directory: {temp_dir}")
                else:
                    self.logger.debug("No downloaded files to clean up")
            else:
                self.logger.debug("Temp directory does not exist - no files to clean up")
                
        except Exception as e:
            self.logger.error(f"Error during downloaded files cleanup: {e}")
    
    def generate_html_reports(self, vulnerabilities: List[Dict[str, Any]], timestamp: str):
        """Generate HTML reports for vulnerabilities."""
        html_file = os.path.join(self.output_dir, f'nexus_scan_report_{timestamp.replace(":", "-")}.html')
        
        # Group vulnerabilities by repository and component
        repo_data = {}
        for vuln in vulnerabilities:
            repo = vuln.get('repository', 'Unknown')
            component = vuln.get('component', 'Unknown')
            
            if repo not in repo_data:
                repo_data[repo] = {}
            if component not in repo_data[repo]:
                repo_data[repo][component] = []
            
            repo_data[repo][component].append(vuln)
        
        # Generate HTML content
        html_content = self._generate_html_content(repo_data, timestamp)
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"  HTML: {html_file}")
    
    def _generate_html_content(self, repo_data: Dict, timestamp: str) -> str:
        """Generate HTML content for the vulnerability report."""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Vulnerability Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .repository {{
            border: 1px solid #bdc3c7;
            border-radius: 5px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .repo-header {{
            background-color: #3498db;
            color: white;
            padding: 15px;
            font-weight: bold;
            font-size: 18px;
        }}
        .component {{
            border-bottom: 1px solid #ecf0f1;
            padding: 10px;
        }}
        .component-name {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        .vulnerability {{
            background-color: #fff;
            border-left: 4px solid #e74c3c;
            padding: 10px;
            margin: 5px 0;
        }}
        .vulnerability.HIGH {{
            border-left-color: #e74c3c;
        }}
        .vulnerability.MEDIUM {{
            border-left-color: #f39c12;
        }}
        .vulnerability.LOW {{
            border-left-color: #f1c40f;
        }}
        .vulnerability.CRITICAL {{
            border-left-color: #8e44ad;
        }}
        .vuln-id {{
            font-weight: bold;
            color: #e74c3c;
        }}
        .severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }}
        .severity.CRITICAL {{
            background-color: #8e44ad;
        }}
        .severity.HIGH {{
            background-color: #e74c3c;
        }}
        .severity.MEDIUM {{
            background-color: #f39c12;
        }}
        .severity.LOW {{
            background-color: #f1c40f;
            color: #333;
        }}
        .severity.UNKNOWN {{
            background-color: #95a5a6;
        }}
        .no-vulnerabilities {{
            background-color: #d5f4e6;
            color: #27ae60;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            margin: 20px 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-box {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border: 1px solid #dee2e6;
        }}
        .stat-number {{
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }}
        .stat-label {{
            color: #6c757d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Nexus Repository Vulnerability Scan Report</h1>
            <p>Generated on: {timestamp}</p>
            <p>Nexus Server: {self.nexus_url}</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">{self.stats['repositories_scanned']}</div>
                    <div class="stat-label">Repositories Scanned</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{self.stats['components_found']}</div>
                    <div class="stat-label">Components Found</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{self.stats['assets_scanned']}</div>
                    <div class="stat-label">Assets Scanned</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{self.stats['vulnerabilities_found']}</div>
                    <div class="stat-label">Vulnerabilities Found</div>
                </div>
            </div>
        </div>
"""

        if not repo_data or self.stats['vulnerabilities_found'] == 0:
            html += """
        <div class="no-vulnerabilities">
            <h2>No Vulnerabilities Found</h2>
            <p>Great news! No security vulnerabilities were detected in any of the scanned repositories.</p>
        </div>
"""
        else:
            html += "<h2>Vulnerability Details</h2>"
            
            for repo_name, components in repo_data.items():
                html += f"""
        <div class="repository">
            <div class="repo-header">Repository: {repo_name}</div>
"""
                
                for component_name, vulns in components.items():
                    html += f"""
            <div class="component">
                <div class="component-name">Component: {component_name}</div>
"""
                    
                    for vuln in vulns:
                        severity = vuln.get('severity', 'UNKNOWN')
                        html += f"""
                <div class="vulnerability {severity}">
                    <div class="vuln-id">{vuln.get('vulnerability_id', 'N/A')}</div>
                    <span class="severity {severity}">{severity}</span>
                    <h4>{vuln.get('title', 'No title available')}</h4>
                    <p><strong>Package:</strong> {vuln.get('pkg_name', 'N/A')} ({vuln.get('pkg_version', 'N/A')})</p>
                    <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                    <p><strong>Fixed Version:</strong> {vuln.get('fixed_version', 'Not available')}</p>
                    <p><strong>Asset:</strong> {vuln.get('asset', 'N/A')}</p>
                </div>
"""
                    
                    html += "            </div>"
                
                html += "        </div>"

        html += """
    </div>
</body>
</html>
"""
        return html
    
    def generate_combined_report(self, vulnerabilities: List[Dict[str, Any]], timestamp: str):
        """Generate comprehensive combined reports in JSON and HTML."""
        # Enhanced JSON report with additional metadata
        combined_json_file = os.path.join(self.output_dir, f'comprehensive_scan_report_{timestamp.replace(":", "-")}.json')
        
        # Group vulnerabilities by severity
        severity_counts = {}
        repo_summary = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            repo = vuln.get('repository', 'Unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if repo not in repo_summary:
                repo_summary[repo] = {
                    'total_vulnerabilities': 0,
                    'components_with_vulnerabilities': set(),
                    'severity_breakdown': {}
                }
            
            repo_summary[repo]['total_vulnerabilities'] += 1
            repo_summary[repo]['components_with_vulnerabilities'].add(vuln.get('component', 'Unknown'))
            repo_summary[repo]['severity_breakdown'][severity] = repo_summary[repo]['severity_breakdown'].get(severity, 0) + 1
        
        # Convert sets to lists for JSON serialization
        for repo in repo_summary:
            repo_summary[repo]['components_with_vulnerabilities'] = list(repo_summary[repo]['components_with_vulnerabilities'])
            repo_summary[repo]['unique_components_with_vulns'] = len(repo_summary[repo]['components_with_vulnerabilities'])
        
        comprehensive_data = {
            'scan_metadata': {
                'timestamp': timestamp,
                'nexus_url': self.nexus_url,
                'trivy_path': self.trivy_path,
                'scan_duration': 'N/A'  # Could add timing if needed
            },
            'statistics': {
                'overall': self.stats,
                'intelligent_detection': dict(self.statistics['repository_types']),
                'artifact_types_detected': dict(self.statistics['artifact_types']),
                'severity_breakdown': severity_counts,
                'repository_summary': repo_summary
            },
            'detailed_vulnerabilities': vulnerabilities,
            'scan_configuration': {
                'repositories_scanned': self.stats['repositories_scanned'],
                'scan_types': ['filesystem', 'archive'],
                'output_formats': ['JSON', 'CSV', 'HTML']
            }
        }
        
        with open(combined_json_file, 'w', encoding='utf-8') as f:
            json.dump(comprehensive_data, f, indent=2, ensure_ascii=False)
        
        # Enhanced HTML report
        combined_html_file = os.path.join(self.output_dir, f'comprehensive_scan_report_{timestamp.replace(":", "-")}.html')
        comprehensive_html = self._generate_comprehensive_html(comprehensive_data, timestamp)
        
        with open(combined_html_file, 'w', encoding='utf-8') as f:
            f.write(comprehensive_html)
        
        self.logger.info(f"Comprehensive reports generated:")
        self.logger.info(f"  JSON: {combined_json_file}")
        self.logger.info(f"  HTML: {combined_html_file}")
    
    def _generate_comprehensive_html(self, data: Dict, timestamp: str) -> str:
        """Generate comprehensive HTML report with enhanced analytics."""
        stats = data['statistics']
        vulns = data['detailed_vulnerabilities']
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive Nexus Security Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }}
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background-color: #f8f9fa;
        }}
        .metric-card {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }}
        .metric-card:hover {{
            transform: translateY(-5px);
        }}
        .metric-number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .metric-label {{
            color: #6c757d;
            font-size: 1.1em;
        }}
        .severity-chart {{
            padding: 30px;
        }}
        .severity-bar {{
            margin: 10px 0;
        }}
        .severity-bar-fill {{
            height: 30px;
            border-radius: 15px;
            display: flex;
            align-items: center;
            padding: 0 15px;
            color: white;
            font-weight: bold;
        }}
        .critical {{ background-color: #8e44ad; }}
        .high {{ background-color: #e74c3c; }}
        .medium {{ background-color: #f39c12; }}
        .low {{ background-color: #f1c40f; color: #333; }}
        .unknown {{ background-color: #95a5a6; }}
        .repo-section {{
            padding: 20px 30px;
        }}
        .repo-card {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 10px;
            margin: 15px 0;
            overflow: hidden;
        }}
        .repo-header {{
            background-color: #007bff;
            color: white;
            padding: 20px;
            font-size: 1.2em;
            font-weight: bold;
        }}
        .repo-content {{
            padding: 20px;
        }}
        .vulnerability-list {{
            margin-top: 20px;
        }}
        .vuln-item {{
            background-color: #f8f9fa;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin: 10px 0;
            border-radius: 0 5px 5px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Comprehensive Security Analysis Report</h1>
            <p>Nexus Repository Vulnerability Assessment</p>
            <p>Generated: {timestamp} | Server: {data['scan_metadata']['nexus_url']}</p>
        </div>
        
        <div class="dashboard">
            <div class="metric-card">
                <div class="metric-number" style="color: #007bff;">{stats['overall']['repositories_scanned']}</div>
                <div class="metric-label">Repositories</div>
            </div>
            <div class="metric-card">
                <div class="metric-number" style="color: #28a745;">{stats['overall']['components_found']}</div>
                <div class="metric-label">Components</div>
            </div>
            <div class="metric-card">
                <div class="metric-number" style="color: #17a2b8;">{stats['overall']['assets_scanned']}</div>
                <div class="metric-label">Assets Scanned</div>
            </div>
            <div class="metric-card">
                <div class="metric-number" style="color: #dc3545;">{stats['overall']['vulnerabilities_found']}</div>
                <div class="metric-label">Vulnerabilities</div>
            </div>
        </div>
"""

        # Severity breakdown
        if stats['severity_breakdown']:
            html += """
        <div class="severity-chart">
            <h2>Vulnerability Severity Distribution</h2>
"""
            total_vulns = sum(stats['severity_breakdown'].values())
            for severity, count in stats['severity_breakdown'].items():
                if count > 0:
                    percentage = (count / total_vulns) * 100
                    html += f"""
            <div class="severity-bar">
                <div class="severity-bar-fill {severity.lower()}" style="width: {percentage}%;">
                    {severity}: {count} ({percentage:.1f}%)
                </div>
            </div>
"""
            html += "        </div>"

        # Repository details
        if stats['repository_summary']:
            html += """
        <div class="repo-section">
            <h2>Repository Analysis</h2>
"""
            for repo_name, repo_data in stats['repository_summary'].items():
                html += f"""
            <div class="repo-card">
                <div class="repo-header">{repo_name}</div>
                <div class="repo-content">
                    <p><strong>Total Vulnerabilities:</strong> {repo_data['total_vulnerabilities']}</p>
                    <p><strong>Affected Components:</strong> {repo_data['unique_components_with_vulns']}</p>
                    <div class="vulnerability-list">
                        <h4>Components with vulnerabilities:</h4>
                        <ul>
"""
                for component in repo_data['components_with_vulnerabilities']:
                    html += f"                            <li>{component}</li>"
                
                html += """
                        </ul>
                    </div>
                </div>
            </div>
"""
            html += "        </div>"

        if not vulns:
            html += """
        <div style="padding: 40px; text-align: center; background-color: #d4edda; color: #155724; margin: 20px;">
            <h2>🎉 Security Status: CLEAN</h2>
            <p>No security vulnerabilities were detected in any scanned repositories!</p>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""
        return html
    
    def print_summary(self):
        """Print scan summary."""
        self.logger.info("=" * 50)
        self.logger.info("SCAN SUMMARY")
        self.logger.info("=" * 50)
        self.logger.info(f"Repositories scanned: {self.stats['repositories_scanned']}")
        self.logger.info(f"Components found: {self.stats['components_found']}")
        self.logger.info(f"Assets scanned: {self.stats['assets_scanned']}")
        self.logger.info(f"Vulnerabilities found: {self.stats['vulnerabilities_found']}")
        self.logger.info(f"Scan errors: {self.stats['scan_errors']}")
        
        # Issue summary
        total_issues = len(self.scan_issues['errors']) + len(self.scan_issues['skipped_files']) + len(self.scan_issues['warnings'])
        total_successful = len(self.scan_issues['successful_scans'])
        self.logger.info(f"Total issues logged: {total_issues}")
        self.logger.info(f"  - Errors: {len(self.scan_issues['errors'])}")
        self.logger.info(f"  - Skipped files: {len(self.scan_issues['skipped_files'])}")
        self.logger.info(f"  - Warnings: {len(self.scan_issues['warnings'])}")
        self.logger.info(f"Successful scans: {total_successful}")
        
        # Successful scan breakdown
        if total_successful > 0:
            clean_scans = sum(1 for scan in self.scan_issues['successful_scans'] if scan.get('vulnerabilities_found', 0) == 0)
            vuln_scans = total_successful - clean_scans
            self.logger.info(f"  - Clean scans (0 vulnerabilities): {clean_scans}")
            self.logger.info(f"  - Scans with vulnerabilities: {vuln_scans}")
        
        # Repository types detected
        self.logger.info("")
        self.logger.info("Repository Types Detected:")
        for repo_type, count in self.statistics['repository_types'].items():
            if count > 0:
                self.logger.info(f"  {repo_type}: {count}")
        
        # Artifact types detected
        self.logger.info("")
        self.logger.info("Artifact Types Detected:")
        for artifact_type, count in self.statistics['artifact_types'].items():
            if count > 0:
                self.logger.info(f"  {artifact_type}: {count}")
        
        # Report retention status
        self.logger.info("")
        self.logger.info("Report Configuration:")
        if self.retain_individual_reports:
            self.logger.info("  Individual reports: RETAINED in 'individual_files_reports' folder")
        else:
            self.logger.info("  Individual reports: TEMPORARY (cleaned up after scan)")
        
        self.logger.info("=" * 50)
    
    def move_reports_to_timestamped_folder(self, scan_timestamp: str):
        """Create a timestamped folder and move all generated reports into it."""
        try:
            # Create timestamped folder name
            folder_timestamp = scan_timestamp.replace(":", "-").replace(".", "-")
            timestamped_folder = os.path.join(self.output_dir, f"scan_reports_{folder_timestamp}")
            
            # Create the timestamped folder
            os.makedirs(timestamped_folder, exist_ok=True)
            self.logger.info(f"Created timestamped report folder: {timestamped_folder}")
            
            # Collect all report files that match the timestamp
            timestamp_pattern = scan_timestamp.replace(":", "-")
            report_files = []
            subfolders_to_move = []
            
            # Find all files in output directory that match this timestamp
            for item in os.listdir(self.output_dir):
                item_path = os.path.join(self.output_dir, item)
                
                if os.path.isfile(item_path):
                    # Check if file matches our timestamp pattern
                    if timestamp_pattern in item:
                        report_files.append(item)
                elif os.path.isdir(item_path) and item == 'individual_files_reports' and self.retain_individual_reports:
                    # Only move individual_files_reports folder if retention is enabled
                    subfolders_to_move.append(item)
            
            # Move report files to timestamped folder
            files_moved = 0
            for report_file in report_files:
                source_path = os.path.join(self.output_dir, report_file)
                dest_path = os.path.join(timestamped_folder, report_file)
                try:
                    shutil.move(source_path, dest_path)
                    files_moved += 1
                    self.logger.debug(f"Moved report: {report_file}")
                except Exception as e:
                    self.logger.error(f"Failed to move {report_file}: {e}")
            
            # Move subfolders to timestamped folder
            folders_moved = 0
            for subfolder in subfolders_to_move:
                source_path = os.path.join(self.output_dir, subfolder)
                dest_path = os.path.join(timestamped_folder, subfolder)
                try:
                    if os.path.exists(source_path):
                        shutil.move(source_path, dest_path)
                        folders_moved += 1
                        self.logger.debug(f"Moved folder: {subfolder}")
                except Exception as e:
                    self.logger.error(f"Failed to move folder {subfolder}: {e}")
            
            self.logger.info(f"Report organization complete:")
            self.logger.info(f"  - {files_moved} report files moved")
            self.logger.info(f"  - {folders_moved} folders moved")
            self.logger.info(f"  - All reports organized in: {timestamped_folder}")
            
            return timestamped_folder
            
        except Exception as e:
            self.logger.error(f"Error organizing reports into timestamped folder: {e}")
            return None

def main():
    """Main function."""
    scanner = CleanNexusScanner()
    scanner.scan_content_repositories()

if __name__ == "__main__":
    main()
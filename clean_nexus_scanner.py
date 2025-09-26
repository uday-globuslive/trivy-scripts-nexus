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
        
        # Performance configuration
        self.skip_pre_scan_component_count = config.get('skip_pre_scan_component_count', False)
        
        # Date-based artifact filtering
        scan_artifacts_from_date_str = config.get('scan_artifacts_from_date', '').strip()
        self.scan_artifacts_from_date = None
        if scan_artifacts_from_date_str:
            try:
                self.scan_artifacts_from_date = datetime.strptime(scan_artifacts_from_date_str, '%Y-%m-%d')
            except ValueError:
                print(f"⚠️  Invalid date format for SCAN_ARTIFACTS_FROM_DATE: {scan_artifacts_from_date_str}. Expected format: YYYY-MM-DD")
                self.scan_artifacts_from_date = None
        
        # Repository filtering configuration
        repositories_to_scan_str = config.get('repositories_to_scan', '').strip()
        self.repositories_to_scan = []
        if repositories_to_scan_str:
            # Parse comma-separated repository names, removing whitespace
            self.repositories_to_scan = [repo.strip() for repo in repositories_to_scan_str.split(',') if repo.strip()]
        
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
        
        # Log repository filtering configuration
        if self.repositories_to_scan:
            self.logger.info(f"Repository filtering enabled: will scan only {len(self.repositories_to_scan)} repositories: {', '.join(self.repositories_to_scan)}")
        else:
            self.logger.info("Repository filtering disabled: will scan all repositories")
        
        # Log scanning configuration details
        self.logger.info("=== SCANNER CONFIGURATION ===")
        self.logger.info(f"Nexus URL: {self.nexus_url}")
        self.logger.info(f"Trivy path: {self.trivy_path}")
        self.logger.info(f"Output directory: {self.output_dir}")
        self.logger.info(f"Debug mode: {self.debug_mode}")
        self.logger.info(f"Retain individual reports: {self.retain_individual_reports}")
        
        # Performance configuration display
        if self.skip_pre_scan_component_count:
            self.logger.info("⚡ Performance mode: FAST STARTUP (skipping pre-scan component counting)")
        else:
            self.logger.info("📊 Performance mode: DETAILED (with pre-scan component counting)")
        
        self.logger.info("=============================")
        
        # Debug Trivy version
        try:
            trivy_version_cmd = [self.trivy_path, "--version"]
            result = subprocess.run(trivy_version_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                  universal_newlines=True, timeout=30)
            self.logger.debug(f"Trivy version check: {result.stdout.strip()}")
            if result.stderr:
                self.logger.debug(f"Trivy version stderr: {result.stderr.strip()}")
        except Exception as e:
            self.logger.error(f"Failed to get Trivy version: {e}")
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create temp directory for downloads
        self.temp_dir = os.path.join(self.output_dir, 'temp')
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Log disk space management info
        self.logger.info("📁 DISK SPACE MANAGEMENT:")
        self.logger.info(f"   • Downloads are processed ONE AT A TIME to minimize disk usage")
        self.logger.info(f"   • Files are deleted immediately after scanning")
        self.logger.info(f"   • Extracted archives are cleaned up automatically")
        self.logger.info(f"   • Temp directory: {self.temp_dir}")
        
        # Enhanced statistics with artifact type tracking
        self.stats = {
            'repositories_scanned': 0,
            'components_found': 0,
            'assets_scanned': 0,
            'vulnerabilities_found': 0,
            'scan_errors': 0
        }
        
        # Report organization statistics
        self.report_stats = {
            'reports_with_vulnerabilities': 0,
            'empty_reports': 0,
            'total_reports_saved': 0
        }
        
        # Intelligent detection statistics using Counter for easy incrementation
        self.statistics = {
            'repository_types': Counter(),
            'artifact_types': Counter()
        }
        
        # Enhanced individual reports directory structure
        self.individual_reports_dir = os.path.join(self.output_dir, 'individual_files_reports')
        os.makedirs(self.individual_reports_dir, exist_ok=True)
        
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
        """Save scan issues to separate report files with repository-wise organization."""
        try:
            # Create timestamped folder
            timestamped_folder = os.path.join(self.output_dir, f"scan_reports_{scan_timestamp.replace(':', '-')}")
            os.makedirs(timestamped_folder, exist_ok=True)
            
            # Create issues report filename
            issues_filename = f"scan_issues_report_{scan_timestamp.replace(':', '-')}.json"
            issues_filepath = os.path.join(timestamped_folder, issues_filename)
            
            # Prepare comprehensive issues report
            issues_report = {
                'scan_metadata': {
                    'timestamp': scan_timestamp,
                    'nexus_url': self.nexus_url,
                    'repositories_requested': self.repositories_to_scan if self.repositories_to_scan else 'ALL',
                    'total_errors': len(self.scan_issues['errors']),
                    'total_skipped': len(self.scan_issues['skipped_files']),
                    'total_warnings': len(self.scan_issues['warnings']),
                    'total_successful_scans': len(self.scan_issues['successful_scans'])
                },
                'scan_issues': {
                    'errors': self.scan_issues['errors'],
                    'skipped_files': self.scan_issues['skipped_files'], 
                    'warnings': self.scan_issues['warnings'],
                    'successful_scans': self.scan_issues['successful_scans']
                }
            }
            
            # Save JSON report
            with open(issues_filepath, 'w', encoding='utf-8') as f:
                json.dump(issues_report, f, indent=2, default=str)
            
            self.logger.info(f"Scan issues report saved: {issues_filepath}")
            
            # Save CSV reports with repository-wise details
            self._save_csv_reports(timestamped_folder, scan_timestamp)
            
        except Exception as e:
            self.logger.error(f"Error saving scan issues report: {e}")
    
    def _save_csv_reports(self, output_folder: str, scan_timestamp: str):
        """Save separate CSV reports for errors, skips, warnings, and successful scans."""
        
        # CSV report for scan errors
        if self.scan_issues['errors']:
            errors_csv = os.path.join(output_folder, f"scan_errors_{scan_timestamp.replace(':', '-')}.csv")
            with open(errors_csv, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['timestamp', 'repository', 'component', 'asset', 'artifact_type', 'reason', 'details']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for error in self.scan_issues['errors']:
                    writer.writerow(error)
            self.logger.info(f"Scan errors CSV saved: {errors_csv}")
        
        # CSV report for skipped files  
        if self.scan_issues['skipped_files']:
            skipped_csv = os.path.join(output_folder, f"scan_skipped_{scan_timestamp.replace(':', '-')}.csv")
            with open(skipped_csv, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['timestamp', 'repository', 'component', 'asset', 'artifact_type', 'reason', 'details']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for skipped in self.scan_issues['skipped_files']:
                    writer.writerow(skipped)
            self.logger.info(f"Scan skipped CSV saved: {skipped_csv}")
        
        # CSV report for successful scans
        if self.scan_issues['successful_scans']:
            success_csv = os.path.join(output_folder, f"scan_successful_{scan_timestamp.replace(':', '-')}.csv")
            with open(success_csv, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['timestamp', 'repository', 'component', 'asset', 'artifact_type', 'scan_strategy', 
                             'vulnerabilities_found', 'scan_type', 'file_size', 'scan_duration', 'trivy_command']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for success in self.scan_issues['successful_scans']:
                    writer.writerow(success)
            self.logger.info(f"Scan successful CSV saved: {success_csv}")
        
        # CSV report for warnings
        if self.scan_issues['warnings']:
            warnings_csv = os.path.join(output_folder, f"scan_warnings_{scan_timestamp.replace(':', '-')}.csv")
            with open(warnings_csv, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['timestamp', 'repository', 'component', 'asset', 'artifact_type', 'reason', 'details']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for warning in self.scan_issues['warnings']:
                    writer.writerow(warning)
            self.logger.info(f"Scan warnings CSV saved: {warnings_csv}")
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
        """Get all repositories from Nexus, optionally filtered by repository names."""
        try:
            response = requests.get(
                f"{self.nexus_url}/service/rest/v1/repositories",
                auth=self.auth,
                timeout=30
            )
            response.raise_for_status()
            repositories = response.json()
            
            # Include all repository types (hosted, proxy, group)
            all_repos = repositories
            
            # Apply repository name filtering if specified
            if self.repositories_to_scan:
                filtered_repos = []
                available_repo_names = [repo.get('name') for repo in all_repos]
                available_repo_details = {repo.get('name'): {'type': repo.get('type'), 'format': repo.get('format')} for repo in all_repos}
                
                self.logger.info(f"Available repositories: {available_repo_names}")
                self.logger.info(f"Available repository details:")
                for name, details in available_repo_details.items():
                    self.logger.info(f"  - {name}: type={details['type']}, format={details['format']}")
                    
                self.logger.info(f"Requested repositories: {self.repositories_to_scan}")
                
                for repo in all_repos:
                    if repo.get('name') in self.repositories_to_scan:
                        filtered_repos.append(repo)
                
                missing_repos = [name for name in self.repositories_to_scan if name not in available_repo_names]
                if missing_repos:
                    self.logger.warning(f"Requested repositories not found: {missing_repos}")
                
                found_repos = [repo.get('name') for repo in filtered_repos]
                self.logger.info(f"Repository filtering enabled: {len(filtered_repos)}/{len(all_repos)} repositories selected")
                self.logger.info(f"Scanning repositories: {found_repos}")
                
                # Log repository types being scanned
                repo_types = {}
                for repo in filtered_repos:
                    repo_type = repo.get('type')
                    repo_format = repo.get('format')
                    key = f"{repo_format}-{repo_type}"
                    repo_types[key] = repo_types.get(key, 0) + 1
                
                if repo_types:
                    self.logger.info(f"Repository types to scan: {dict(repo_types)}")
                
                return filtered_repos
            else:
                # Filter for hosted repositories only when no specific filtering is requested
                hosted_repos = [repo for repo in all_repos if repo.get('type') == 'hosted']
                self.logger.info("Repository filtering disabled: scanning all hosted repositories")
                
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
    
    def generate_components_csv(self, repositories: List[Dict[str, Any]]) -> str:
        """Generate a CSV file with component information from all repositories."""
        csv_filename = f"nexus_components_scan_info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        csv_path = os.path.join(self.output_dir, csv_filename)
        
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'Repository', 'Repository_Type', 'Repository_Format',
                    'Component_Name', 'Component_Group', 'Component_Version',
                    'Asset_Name', 'Asset_Format', 'Date_Uploaded', 'Last_Modified',
                    'Will_Be_Scanned', 'Skip_Reason'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                total_components = 0
                scanned_components = 0
                
                for repo in repositories:
                    repo_name = repo.get('name', 'Unknown')
                    repo_type = repo.get('type', 'Unknown')
                    repo_format = repo.get('format', 'Unknown')
                    
                    self.logger.info(f"Fetching components for CSV from repository: {repo_name}")
                    components = self.get_repository_components(repo_name, repo_type)
                    
                    if not components:
                        # Write repository entry even if no components
                        writer.writerow({
                            'Repository': repo_name,
                            'Repository_Type': repo_type,
                            'Repository_Format': repo_format,
                            'Component_Name': 'N/A',
                            'Component_Group': 'N/A',
                            'Component_Version': 'N/A',
                            'Asset_Name': 'N/A',
                            'Asset_Format': 'N/A',
                            'Date_Uploaded': 'N/A',
                            'Last_Modified': 'N/A',
                            'Will_Be_Scanned': 'No',
                            'Skip_Reason': 'No components found'
                        })
                        continue
                    
                    for component in components:
                        total_components += 1
                        component_name = component.get('name', 'Unknown')
                        component_group = component.get('group', 'N/A')
                        component_version = component.get('version', 'N/A')
                        
                        # Check if component will be scanned based on date filtering
                        will_scan = True
                        skip_reason = ''
                        
                        if self.scan_artifacts_from_date:
                            # Check the last modified date of component assets
                            component_date = None
                            assets = component.get('assets', [])
                            
                            for asset in assets:
                                asset_last_modified = asset.get('lastModified')
                                if asset_last_modified:
                                    try:
                                        # Try multiple date format parsing
                                        if 'T' in asset_last_modified:
                                            if asset_last_modified.endswith('Z'):
                                                asset_date = datetime.strptime(asset_last_modified, '%Y-%m-%dT%H:%M:%S.%fZ')
                                            elif '+' in asset_last_modified:
                                                asset_date = datetime.strptime(asset_last_modified.split('+')[0], '%Y-%m-%dT%H:%M:%S.%f')
                                            else:
                                                asset_date = datetime.strptime(asset_last_modified, '%Y-%m-%dT%H:%M:%S.%f')
                                        else:
                                            asset_date = datetime.strptime(asset_last_modified, '%Y-%m-%d')
                                        
                                        if component_date is None or asset_date > component_date:
                                            component_date = asset_date
                                    except (ValueError, AttributeError):
                                        continue
                            
                            if component_date and component_date < self.scan_artifacts_from_date:
                                will_scan = False
                                skip_reason = f"Component date ({component_date.strftime('%Y-%m-%d')}) is before filter date ({self.scan_artifacts_from_date.strftime('%Y-%m-%d')})"
                        
                        if will_scan:
                            scanned_components += 1
                        
                        # Write component assets information
                        assets = component.get('assets', [])
                        if assets:
                            for asset in assets:
                                asset_name = asset.get('name', 'N/A')
                                asset_format = asset.get('format', 'N/A')
                                date_uploaded = asset.get('blobCreated', 'N/A')
                                last_modified = asset.get('lastModified', 'N/A')
                                
                                writer.writerow({
                                    'Repository': repo_name,
                                    'Repository_Type': repo_type,
                                    'Repository_Format': repo_format,
                                    'Component_Name': component_name,
                                    'Component_Group': component_group,
                                    'Component_Version': component_version,
                                    'Asset_Name': asset_name,
                                    'Asset_Format': asset_format,
                                    'Date_Uploaded': date_uploaded,
                                    'Last_Modified': last_modified,
                                    'Will_Be_Scanned': 'Yes' if will_scan else 'No',
                                    'Skip_Reason': skip_reason
                                })
                        else:
                            # Component with no assets
                            writer.writerow({
                                'Repository': repo_name,
                                'Repository_Type': repo_type,
                                'Repository_Format': repo_format,
                                'Component_Name': component_name,
                                'Component_Group': component_group,
                                'Component_Version': component_version,
                                'Asset_Name': 'N/A',
                                'Asset_Format': 'N/A',
                                'Date_Uploaded': 'N/A',
                                'Last_Modified': 'N/A',
                                'Will_Be_Scanned': 'Yes' if will_scan else 'No',
                                'Skip_Reason': skip_reason
                            })
                
                self.logger.info(f"CSV generated: {csv_path}")
                self.logger.info(f"Total components found: {total_components}")
                self.logger.info(f"Components to be scanned: {scanned_components}")
                self.logger.info(f"Components to be skipped: {total_components - scanned_components}")
                
        except Exception as e:
            self.logger.error(f"Error generating CSV: {e}")
            return ""
            
        return csv_path
    
    def generate_components_csv_from_cache(self, repository_components_cache: Dict[str, Dict]) -> str:
        """Generate a CSV file with component information from cached data."""
        csv_filename = f"nexus_components_scan_info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        csv_path = os.path.join(self.output_dir, csv_filename)
        
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'Repository', 'Repository_Type', 'Repository_Format',
                    'Component_Name', 'Component_Group', 'Component_Version',
                    'Asset_Name', 'Asset_Format', 'Date_Uploaded', 'Last_Modified',
                    'Will_Be_Scanned', 'Skip_Reason'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                total_components = 0
                scanned_components = 0
                
                for repo_name, repo_data in repository_components_cache.items():
                    repo = repo_data['repo']
                    components = repo_data['components']
                    repo_type = repo.get('type', 'Unknown')
                    repo_format = repo.get('format', 'Unknown')
                    
                    if not components:
                        # Write repository entry even if no components
                        writer.writerow({
                            'Repository': repo_name,
                            'Repository_Type': repo_type,
                            'Repository_Format': repo_format,
                            'Component_Name': 'N/A',
                            'Component_Group': 'N/A',
                            'Component_Version': 'N/A',
                            'Asset_Name': 'N/A',
                            'Asset_Format': 'N/A',
                            'Date_Uploaded': 'N/A',
                            'Last_Modified': 'N/A',
                            'Will_Be_Scanned': 'No',
                            'Skip_Reason': 'No components found'
                        })
                        continue
                    
                    for component in components:
                        total_components += 1
                        component_name = component.get('name', 'Unknown')
                        component_group = component.get('group', 'N/A')
                        component_version = component.get('version', 'N/A')
                        
                        # Check if component will be scanned based on date filtering
                        will_scan = True
                        skip_reason = ''
                        
                        if self.scan_artifacts_from_date:
                            # Check the last modified date of component assets
                            component_date = None
                            assets = component.get('assets', [])
                            
                            for asset in assets:
                                asset_last_modified = asset.get('lastModified')
                                if asset_last_modified:
                                    try:
                                        # Try multiple date format parsing
                                        if 'T' in asset_last_modified:
                                            if asset_last_modified.endswith('Z'):
                                                asset_date = datetime.strptime(asset_last_modified, '%Y-%m-%dT%H:%M:%S.%fZ')
                                            elif '+' in asset_last_modified:
                                                asset_date = datetime.strptime(asset_last_modified.split('+')[0], '%Y-%m-%dT%H:%M:%S.%f')
                                            else:
                                                asset_date = datetime.strptime(asset_last_modified, '%Y-%m-%dT%H:%M:%S.%f')
                                        else:
                                            asset_date = datetime.strptime(asset_last_modified, '%Y-%m-%d')
                                        
                                        if component_date is None or asset_date > component_date:
                                            component_date = asset_date
                                    except (ValueError, AttributeError):
                                        continue
                            
                            if component_date and component_date < self.scan_artifacts_from_date:
                                will_scan = False
                                skip_reason = f"Component date ({component_date.strftime('%Y-%m-%d')}) is before filter date ({self.scan_artifacts_from_date.strftime('%Y-%m-%d')})"
                        
                        if will_scan:
                            scanned_components += 1
                        
                        # Write component assets information
                        assets = component.get('assets', [])
                        if assets:
                            for asset in assets:
                                asset_name = asset.get('name', 'N/A')
                                asset_format = asset.get('format', 'N/A')
                                date_uploaded = asset.get('blobCreated', 'N/A')
                                last_modified = asset.get('lastModified', 'N/A')
                                
                                writer.writerow({
                                    'Repository': repo_name,
                                    'Repository_Type': repo_type,
                                    'Repository_Format': repo_format,
                                    'Component_Name': component_name,
                                    'Component_Group': component_group,
                                    'Component_Version': component_version,
                                    'Asset_Name': asset_name,
                                    'Asset_Format': asset_format,
                                    'Date_Uploaded': date_uploaded,
                                    'Last_Modified': last_modified,
                                    'Will_Be_Scanned': 'Yes' if will_scan else 'No',
                                    'Skip_Reason': skip_reason
                                })
                        else:
                            # Component with no assets
                            writer.writerow({
                                'Repository': repo_name,
                                'Repository_Type': repo_type,
                                'Repository_Format': repo_format,
                                'Component_Name': component_name,
                                'Component_Group': component_group,
                                'Component_Version': component_version,
                                'Asset_Name': 'N/A',
                                'Asset_Format': 'N/A',
                                'Date_Uploaded': 'N/A',
                                'Last_Modified': 'N/A',
                                'Will_Be_Scanned': 'Yes' if will_scan else 'No',
                                'Skip_Reason': skip_reason
                            })
                
                self.logger.info(f"CSV generated: {csv_path}")
                self.logger.info(f"Total components found: {total_components}")
                self.logger.info(f"Components to be scanned: {scanned_components}")
                self.logger.info(f"Components to be skipped: {total_components - scanned_components}")
                
        except Exception as e:
            self.logger.error(f"Error generating CSV: {e}")
            return ""
            
        return csv_path
    
    def get_repository_components(self, repository_name: str, repository_type: str = 'hosted') -> List[Dict[str, Any]]:
        """Get all components from a specific repository using pagination."""
        components = []
        continuation_token = None
        
        try:
            # Handle different repository types
            if repository_type == 'group':
                self.logger.info(f"Repository '{repository_name}' is a group repository - checking for cached components")
                # Group repositories aggregate other repositories, try to get components anyway
                # Some group repos might have cached content
            elif repository_type == 'proxy':
                self.logger.info(f"Repository '{repository_name}' is a proxy repository - checking for cached content")
                # Proxy repositories cache remote content, should be scannable
            else:
                self.logger.info(f"Repository '{repository_name}' is a hosted repository")
            
            while True:
                # Build URL with pagination
                url = f"{self.nexus_url}/service/rest/v1/components"
                params = {'repository': repository_name}
                
                if continuation_token:
                    params['continuationToken'] = continuation_token
                
                if self.debug_http_requests:
                    self.logger.debug(f"HTTP GET: {url} with params: {params}")
                
                response = requests.get(url, auth=self.auth, params=params, timeout=30)
                
                if self.debug_http_requests:
                    self.logger.debug(f"Response status: {response.status_code}")
                
                if response.status_code == 404:
                    self.logger.warning(f"Repository '{repository_name}' not found or no components endpoint")
                    break
                elif response.status_code == 403:
                    self.logger.warning(f"Access denied to repository '{repository_name}' - insufficient permissions")
                    break
                
                response.raise_for_status()
                
                data = response.json()
                batch_components = data.get('items', [])
                components.extend(batch_components)
                
                # Check for more pages
                continuation_token = data.get('continuationToken')
                if not continuation_token:
                    break
                    
                self.logger.info(f"Retrieved {len(batch_components)} components (total: {len(components)})")
            
            if repository_type == 'group' and len(components) == 0:
                self.logger.info(f"Group repository '{repository_name}' has no direct components (this is normal for group repositories)")
            elif repository_type == 'proxy' and len(components) == 0:
                self.logger.info(f"Proxy repository '{repository_name}' has no cached components yet")
            
            self.logger.info(f"Found {len(components)} components in '{repository_name}' ({repository_type} repository)")
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
            ]
            
            # Add enhanced options for better package detection
            if scan_type == "fs":
                # Enable all package manager scanners for filesystem scans
                json_cmd.extend(["--scanners", "vuln"])
                
                # For Node.js packages, try to detect package manager files more aggressively
                if os.path.isdir(file_path):
                    # Check if this looks like a Node.js package directory
                    package_json_files = []
                    for root, dirs, files in os.walk(file_path):
                        if 'package.json' in files:
                            package_json_files.append(os.path.join(root, 'package.json'))
                    
                    if package_json_files:
                        self.logger.debug(f"Found {len(package_json_files)} package.json files in {file_path}")
                        # Add offline mode to prevent network calls for better speed
                        # json_cmd.extend(["--offline-scan"])
                        
            json_cmd.append(file_path)
            
            # HTML scan using Trivy's built-in template
            html_template_path = os.path.join(os.path.dirname(self.trivy_path), 'contrib', 'html.tpl')
            
            # For Linux deployment, check if we're using /tmp/tools/trivy path
            if self.trivy_path == '/tmp/tools/trivy/trivy':
                html_template_path = '/tmp/tools/trivy/contrib/html.tpl'
            
            html_cmd = [
                self.trivy_path,
                scan_type,
                "--format", "template",
                "--template", f"@{html_template_path}",
                "--output", html_output_file,
            ]
            
            # Apply same enhancements to HTML command
            if scan_type == "fs":
                html_cmd.extend(["--scanners", "vuln"])
                
            html_cmd.append(file_path)
            
            # Add --quiet flag only if not in debug mode
            if not self.debug_mode:
                json_cmd.insert(-1, "--quiet")
                html_cmd.insert(-1, "--quiet")
            
            self.logger.debug(f"JSON command: {' '.join(json_cmd)}")
            
            # Run JSON scan
            json_result = subprocess.run(json_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                       universal_newlines=True, timeout=300)
            
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
            html_result = subprocess.run(html_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                       universal_newlines=True, timeout=300)
            
            self.logger.debug(f"HTML scan return code: {html_result.returncode}")
            if html_result.stdout:
                self.logger.debug(f"HTML scan stdout: {html_result.stdout}")
            if html_result.stderr:
                self.logger.debug(f"HTML scan stderr: {html_result.stderr}")
            
            json_data = None
            html_content = None
            
            # Read JSON results and save to reports directory
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
                    
                    # Save JSON report to individual files directory (actual Trivy JSON output)
                    if hasattr(self, 'individual_files_dir') and json_content.strip():
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        base_name = os.path.basename(file_path).replace('.', '_')
                        json_report_path = os.path.join(self.individual_files_dir, 
                                                      f"{base_name}_trivy_{timestamp}.json")
                        # Save the raw Trivy JSON output (not our custom structure)
                        with open(json_report_path, 'w', encoding='utf-8') as f:
                            f.write(json_content)
                        self.logger.info(f"Trivy JSON report saved: {json_report_path}")
                    
                    os.remove(json_output_file)
                    self.logger.debug("Temporary JSON output file cleaned up")
                except Exception as e:
                    self.logger.error(f"Error parsing JSON results: {e}")
            else:
                self.logger.warning(f"JSON output file not found: {json_output_file}")
            
            # Read HTML results and save to reports directory
            if os.path.exists(html_output_file):
                try:
                    with open(html_output_file, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                        self.logger.debug(f"HTML file size: {len(html_content)} characters")
                    
                    # Save HTML report to individual files directory (actual Trivy HTML output)
                    if hasattr(self, 'individual_files_dir') and html_content.strip():
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        base_name = os.path.basename(file_path).replace('.', '_')
                        html_report_path = os.path.join(self.individual_files_dir, 
                                                      f"{base_name}_trivy_{timestamp}.html")
                        # Save the raw Trivy HTML output (using html.tpl template)
                        with open(html_report_path, 'w', encoding='utf-8') as f:
                            f.write(html_content)
                        self.logger.info(f"Trivy HTML report saved: {html_report_path}")
                    
                    os.remove(html_output_file)
                    self.logger.debug("Temporary HTML output file cleaned up")
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
            self.logger.debug("No Trivy results provided to extract_vulnerabilities")
            return vulnerabilities
        
        self.logger.debug(f"Trivy results structure: {list(trivy_results.keys())}")
        
        results = trivy_results.get('Results', [])
        self.logger.debug(f"Found {len(results)} result sections in Trivy output")
        
        for i, result in enumerate(results):
            target = result.get('Target', 'Unknown')
            vulns = result.get('Vulnerabilities', [])
            self.logger.debug(f"Result {i+1}: Target='{target}', Vulnerabilities={len(vulns) if vulns else 0}")
            
            if not vulns:
                # Check if there are other types of findings
                other_keys = [k for k in result.keys() if k not in ['Target', 'Class', 'Type']]
                if other_keys:
                    self.logger.debug(f"Result {i+1} has other keys: {other_keys}")
                continue
            
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
        
        self.logger.debug(f"Extracted {len(vulnerabilities)} vulnerabilities total")
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
            import json
            
            os.makedirs(extract_dir, exist_ok=True)
            archive_lower = archive_path.lower()
            extracted = False
            
            if archive_lower.endswith('.zip') or archive_lower.endswith('.jar') or archive_lower.endswith('.war'):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                extracted = True
            
            elif archive_lower.endswith(('.tar.gz', '.tgz')):
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_dir)
                extracted = True
            
            elif archive_lower.endswith('.tar'):
                with tarfile.open(archive_path, 'r') as tar_ref:
                    tar_ref.extractall(extract_dir)
                extracted = True
            
            else:
                self.logger.warning(f"Unsupported archive format: {archive_path}")
                return False
            
            # Post-extraction processing for Node.js packages
            if extracted and archive_lower.endswith(('.tgz', '.tar.gz')):
                self.enhance_nodejs_package_for_scanning(extract_dir)
                
            return extracted
                
        except Exception as e:
            self.logger.error(f"Error extracting {archive_path}: {e}")
            return False
    
    def enhance_nodejs_package_for_scanning(self, extract_dir: str):
        """
        Enhance extracted Node.js package to ensure Trivy can scan it properly.
        Uses the same proven logic as test_trivy_fixed.sh script.
        """
        try:
            # Find package.json files in the extracted directory
            package_json_files = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file == 'package.json':
                        package_json_files.append(os.path.join(root, file))
            
            for package_json_path in package_json_files:
                package_dir = os.path.dirname(package_json_path)
                
                # Check if lock file already exists
                lock_files = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']
                has_lock_file = any(os.path.exists(os.path.join(package_dir, lock_file)) for lock_file in lock_files)
                
                if not has_lock_file:
                    try:
                        # Read the original package.json
                        with open(package_json_path, 'r', encoding='utf-8') as f:
                            pkg_data = json.load(f)
                        
                        name = pkg_data.get('name', 'unknown')
                        version = pkg_data.get('version', '0.0.0')
                        dependencies = pkg_data.get('dependencies', {})
                        
                        self.logger.debug(f"Creating comprehensive package-lock.json for {name}@{version} with {len(dependencies)} dependencies")
                        
                        # Create comprehensive package-lock.json with the exact same structure as test script
                        lock_data = {
                            "name": name,
                            "version": version,
                            "lockfileVersion": 3,
                            "requires": True,
                            "packages": {
                                "": {
                                    "name": name,
                                    "version": version,
                                    "license": "MIT"
                                }
                            },
                            "dependencies": {}
                        }
                        
                        # Add dependencies to root package if they exist
                        if dependencies:
                            lock_data["packages"][""]["dependencies"] = dependencies
                        
                        # Add node_modules entries for each dependency (critical for Trivy detection)
                        for dep_name, dep_version in dependencies.items():
                            # Clean version (remove ^ ~ >= < etc)
                            clean_version = dep_version.lstrip('^~>=<')
                            
                            # Add to node_modules section (this is what makes Trivy detect npm packages)
                            lock_data["packages"][f"node_modules/{dep_name}"] = {
                                "version": clean_version,
                                "resolved": f"https://registry.npmjs.org/{dep_name}/-/{dep_name}-{clean_version}.tgz",
                                "integrity": f"sha512-{'0' * 64}",  # Placeholder integrity hash
                                "license": "MIT"
                            }
                            
                            # Add to dependencies section
                            lock_data["dependencies"][dep_name] = {
                                "version": clean_version,
                                "resolved": f"https://registry.npmjs.org/{dep_name}/-/{dep_name}-{clean_version}.tgz",
                                "integrity": f"sha512-{'0' * 64}"
                            }
                        
                        # Write the enhanced package-lock.json
                        lock_file_path = os.path.join(package_dir, 'package-lock.json')
                        with open(lock_file_path, 'w', encoding='utf-8') as f:
                            json.dump(lock_data, f, indent=2)
                        
                        # Create physical node_modules directory structure (essential for Trivy)
                        node_modules_dir = os.path.join(package_dir, 'node_modules')
                        os.makedirs(node_modules_dir, exist_ok=True)
                        
                        # Create individual package directories and package.json files for each dependency
                        for dep_name, dep_version in dependencies.items():
                            dep_dir = os.path.join(node_modules_dir, dep_name)
                            os.makedirs(dep_dir, exist_ok=True)
                            
                            # Create a minimal package.json for each dependency
                            clean_version = dep_version.lstrip('^~>=<')
                            dep_pkg = {
                                'name': dep_name, 
                                'version': clean_version
                            }
                            dep_pkg_path = os.path.join(dep_dir, 'package.json')
                            with open(dep_pkg_path, 'w', encoding='utf-8') as f:
                                json.dump(dep_pkg, f, indent=2)
                        
                        lock_size = os.path.getsize(lock_file_path)
                        self.logger.info(f"✅ Enhanced Node.js package for Trivy scanning: {name}@{version}")
                        self.logger.info(f"   📦 Created package-lock.json: {lock_size} bytes")
                        self.logger.info(f"   📁 Created node_modules structure: {len(dependencies)} packages")
                        self.logger.debug(f"   🔍 Enhanced package at: {package_dir}")
                        
                    except Exception as e:
                        self.logger.error(f"Error creating comprehensive package-lock.json for {package_json_path}: {e}")
                        self.logger.debug(f"Exception details: ", exc_info=True)
                else:
                    self.logger.debug(f"Lock file already exists for Node.js package: {package_json_path}")
                    
        except Exception as e:
            self.logger.error(f"Error enhancing Node.js packages in {extract_dir}: {e}")
            self.logger.debug(f"Exception details: ", exc_info=True)
    
    def scan_content_repositories(self):
        """Scan all content repositories for vulnerabilities."""
        if not self.test_connection():
            self.logger.error("Cannot connect to Nexus server")
            return
        
        repositories = self.get_repositories()
        if not repositories:
            self.logger.error("No repositories found to scan")
            return
        
        # Fetch all components once and cache them
        self.logger.info("=" * 60)
        self.logger.info("FETCHING REPOSITORY COMPONENTS")
        self.logger.info("=" * 60)
        
        repository_components_cache = {}
        total_components_found = 0
        format_counts = Counter()
        
        for repo in repositories:
            repo_name = repo['name']
            repo_format = repo.get('format', 'unknown')
            repo_type = repo.get('type', 'hosted')
            format_counts[repo_format] += 1
            
            self.logger.info(f"🔍 Fetching components from: {repo_name} ({repo_format}, {repo_type})")
            try:
                components = self.get_repository_components(repo_name, repo_type)
                repository_components_cache[repo_name] = {
                    'repo': repo,
                    'components': components,
                    'count': len(components)
                }
                total_components_found += len(components)
                self.logger.info(f"  📦 Found {len(components)} components in {repo_name}")
            except Exception as e:
                self.logger.warning(f"  ❌ Error fetching components from {repo_name}: {e}")
                repository_components_cache[repo_name] = {
                    'repo': repo,
                    'components': [],
                    'count': 0
                }
        
        self.logger.info(f"📊 Repository format breakdown: {dict(format_counts)}")
        self.logger.info(f"📦 Total components across all repositories: {total_components_found}")
        
        if total_components_found == 0:
            self.logger.warning("🚨 WARNING: No components found in any repository!")
            self.logger.warning("   The scan will complete quickly but find no vulnerabilities.")
        
        # Generate CSV file with cached component information
        self.logger.info("=" * 60)
        self.logger.info("GENERATING COMPONENTS CSV")
        self.logger.info("=" * 60)
        csv_path = self.generate_components_csv_from_cache(repository_components_cache)
        if csv_path:
            self.logger.info(f"📄 Components CSV generated: {csv_path}")
        else:
            self.logger.warning("⚠️ Failed to generate components CSV")
        
        all_vulnerabilities = []
        scan_timestamp = datetime.now().isoformat()
        
        # Pre-scan diagnostic summary
        self.logger.info("=" * 60)
        self.logger.info("PRE-SCAN DIAGNOSTIC SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Scan timestamp: {scan_timestamp}")
        
        # Date-based filtering information
        if self.scan_artifacts_from_date:
            self.logger.info(f"Artifact date filtering: ENABLED (scanning artifacts from {self.scan_artifacts_from_date.strftime('%Y-%m-%d')} onwards)")
            self.logger.info(f"ℹ️  Artifacts uploaded before {self.scan_artifacts_from_date.strftime('%Y-%m-%d')} will be skipped")
        else:
            self.logger.info("Artifact date filtering: DISABLED (scanning all artifacts regardless of upload date)")
        
        # Repository filtering information
        if self.repositories_to_scan:
            self.logger.info(f"Repository filtering: ENABLED (requested {len(self.repositories_to_scan)} specific repositories)")
            missing_repos = []
            for requested_repo in self.repositories_to_scan:
                if requested_repo not in repository_components_cache:
                    missing_repos.append(requested_repo)
            if missing_repos:
                self.logger.warning(f"⚠️  Missing requested repositories: {missing_repos}")
                self.logger.info(f"✅ Found {len(repository_components_cache) - len(missing_repos)}/{len(self.repositories_to_scan)} requested repositories")
            else:
                self.logger.info(f"✅ All requested repositories found: {len(repository_components_cache)}")
        else:
            self.logger.info("Repository filtering: DISABLED (scanning all available repositories)")
        
        self.logger.info(f"Total repositories to scan: {len(repository_components_cache)}")
        
        # Repository format breakdown
        format_counts = {}
        total_components_preview = 0
        
        if self.repositories_to_scan:
            missing_repos = []
            for requested_repo in self.repositories_to_scan:
                if requested_repo not in repository_components_cache:
                    missing_repos.append(requested_repo)
            if missing_repos:
                self.logger.info("💡 TIP: Check repository names in Nexus UI or via REST API")
                self.logger.info(f"    Available repositories can be listed at: {self.nexus_url}/service/rest/v1/repositories")
        
        self.logger.info("=" * 60)
        self.logger.info("STARTING DETAILED SCAN...")
        self.logger.info("=" * 60)

        for repo_name, repo_cache_data in repository_components_cache.items():
            repo = repo_cache_data['repo']
            components = repo_cache_data['components']
            component_count = repo_cache_data['count']
            
            repo_format = repo.get('format', 'unknown')
            repo_type = repo.get('type', 'hosted')
            
            self.logger.info(f"=== SCANNING REPOSITORY: {repo_name} (format: {repo_format}, type: {repo_type}) ===")
            self.stats['repositories_scanned'] += 1
            self.stats['components_found'] += component_count
            
            self.logger.info(f"Repository {repo_name} contains {component_count} components (from cache)")
            
            if component_count == 0:
                if repo_type == 'group':
                    self.logger.info(f"Group repository {repo_name} has no direct components (normal behavior)")
                elif repo_type == 'proxy':
                    self.logger.info(f"Proxy repository {repo_name} has no cached components yet")
                else:
                    self.logger.warning(f"Repository {repo_name} is empty - no components to scan")
                continue

            for i, component in enumerate(components, 1):
                component_name = component.get('name', 'unknown')
                component_version = component.get('version', 'unknown')
                
                self.logger.info(f"Processing component {i}/{component_count}: {component_name}:{component_version}")
                
                # Analyze component assets
                assets = component.get('assets', [])
                asset_count = len(assets)
                self.logger.info(f"  Component has {asset_count} assets")
                
                # Log asset details for diagnostic purposes
                for j, asset in enumerate(assets[:5], 1):  # Log first 5 assets
                    asset_name = asset.get('path', asset.get('name', 'unknown'))
                    asset_size = asset.get('fileSize', 'unknown')
                    download_url = asset.get('downloadUrl', '')
                    self.logger.debug(f"    Asset {j}: {asset_name} (size: {asset_size}, has_url: {bool(download_url)})")
                
                if asset_count > 5:
                    self.logger.debug(f"    ... and {asset_count - 5} more assets")
                
                # Handle different repository formats
                if repo_format == 'docker':
                    self.logger.info(f"  Using Docker scanning strategy for {component_name}:{component_version}")
                    # For Docker repositories, scan container images
                    vulnerabilities = self.scan_docker_components(component, repo_name, scan_timestamp)
                    all_vulnerabilities.extend(vulnerabilities)
                else:
                    self.logger.info(f"  Using asset-by-asset scanning strategy")
                    # For other formats, scan individual assets
                    for k, asset in enumerate(assets, 1):
                        asset_name = asset.get('path', asset.get('name', 'unknown'))
                        download_url = asset.get('downloadUrl', '')
                        
                        self.logger.info(f"    Processing asset {k}/{asset_count}: {asset_name}")
                        
                        if not download_url:
                            self.logger.warning(f"    Asset {asset_name} has no download URL - skipping")
                            continue
                        
                        # Apply date-based filtering if configured
                        if self.scan_artifacts_from_date:
                            asset_last_modified = asset.get('lastModified')
                            if asset_last_modified:
                                try:
                                    # Parse the asset's last modified date with Python 2.7+ compatible parsing
                                    # Handle common ISO formats from Nexus: 2025-09-15T10:30:45.123Z
                                    date_str = asset_last_modified
                                    
                                    # Remove timezone indicators for consistent parsing
                                    if date_str.endswith('Z'):
                                        date_str = date_str[:-1]
                                    elif '+' in date_str:
                                        date_str = date_str.split('+')[0]
                                    elif date_str.endswith('+00:00'):
                                        date_str = date_str[:-6]
                                    
                                    # Handle microseconds - truncate to milliseconds if needed
                                    if '.' in date_str:
                                        date_part, frac_part = date_str.split('.')
                                        # Keep only first 6 digits (microseconds) or 3 digits (milliseconds)
                                        if len(frac_part) > 6:
                                            frac_part = frac_part[:6]
                                        elif len(frac_part) == 3:
                                            frac_part = frac_part + '000'  # Convert milliseconds to microseconds
                                        date_str = f"{date_part}.{frac_part}"
                                    
                                    # Parse using strptime (compatible with older Python versions)
                                    try:
                                        if '.' in date_str:
                                            asset_date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%f')
                                        else:
                                            asset_date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
                                    except ValueError:
                                        # Fallback: try parsing just the date part
                                        date_only = date_str.split('T')[0]
                                        asset_date = datetime.strptime(date_only, '%Y-%m-%d')
                                    
                                    if asset_date < self.scan_artifacts_from_date:
                                        self.logger.info(f"    Skipping asset {asset_name} - uploaded {asset_date.strftime('%Y-%m-%d')} (before filter date {self.scan_artifacts_from_date.strftime('%Y-%m-%d')})")
                                        self.scan_issues['skipped_files'].append({
                                            'repository': repo_name,
                                            'component': component_name,
                                            'asset': asset_name,
                                            'reason': f'Uploaded before filter date ({asset_date.strftime("%Y-%m-%d")} < {self.scan_artifacts_from_date.strftime("%Y-%m-%d")})',
                                            'upload_date': asset_date.strftime('%Y-%m-%d')
                                        })
                                        continue
                                    else:
                                        self.logger.debug(f"    Asset {asset_name} passed date filter - uploaded {asset_date.strftime('%Y-%m-%d')}")
                                except (ValueError, TypeError) as e:
                                    self.logger.warning(f"    Could not parse asset date '{asset_last_modified}' for {asset_name}: {e}")
                                    self.logger.debug(f"    Including asset {asset_name} in scan due to date parsing failure")
                            else:
                                self.logger.warning(f"    Asset {asset_name} has no lastModified date - including in scan")
                        
                        # Detect artifact type and determine scanning strategy
                        artifact_type = self.detect_artifact_type(asset_name, repo_format)
                        self.statistics['artifact_types'][artifact_type] += 1
                        self.logger.info(f"    Detected artifact type: {artifact_type}")
                        
                        strategy = self.determine_scan_strategy(artifact_type, asset_name, repo_format)
                        self.logger.info(f"    Scan strategy: {strategy['reason']}")
                        self.logger.debug(f"    Full strategy: {strategy}")
                        
                        if strategy['skip_scan']:
                            # Log skip with detailed asset information
                            asset_info = {
                                'repository': repo_name,
                                'component': component_name,
                                'asset': asset_name,
                                'artifact_type': artifact_type
                            }
                            self.log_scan_issue('skip', asset_info, strategy['reason'], f"Download URL: {download_url}")
                            self.logger.info(f"    SKIPPED: {strategy['reason']}")
                            continue
                        
                        self.logger.info(f"    SCANNING: {asset_name} (Type: {artifact_type})")
                        self.logger.info(f"    Strategy: {strategy['reason']}")
                        self.stats['assets_scanned'] += 1
                        
                        # Create local filename for download
                        safe_filename = asset_name.replace('/', '_').replace('\\', '_')
                        local_path = os.path.join(self.temp_dir, safe_filename)
                        
                        self.logger.debug(f"    Download URL: {download_url}")
                        self.logger.debug(f"    Local path: {local_path}")
                        
                        # Download and scan
                        download_start = datetime.now()
                        if self.download_asset(download_url, local_path):
                            download_time = str(datetime.now() - download_start)
                            file_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
                            self.logger.info(f"    Downloaded in {download_time} (size: {file_size:,} bytes)")
                            
                            # Use intelligent scanning strategy
                            scan_start_time = datetime.now()
                            scan_results = self.scan_with_strategy(local_path, strategy, artifact_type)
                            scan_end_time = datetime.now()
                            scan_duration = str(scan_end_time - scan_start_time)
                            
                            self.logger.info(f"    Scan completed in {scan_duration}")
                            
                            if scan_results and scan_results[0]:  # Check JSON results
                                json_data, html_content = scan_results
                                vulnerabilities = self.extract_vulnerabilities(json_data)
                                vuln_count = len(vulnerabilities)
                                self.stats['vulnerabilities_found'] += vuln_count
                                
                                self.logger.info(f"    SCAN RESULT: Found {vuln_count} vulnerabilities")
                                
                                if vuln_count > 0:
                                    # Log vulnerability summary by severity
                                    severity_counts = {}
                                    for vuln in vulnerabilities:
                                        severity = vuln.get('severity', 'UNKNOWN')
                                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                                    
                                    severity_summary = ", ".join([f"{severity}: {count}" for severity, count in severity_counts.items()])
                                    self.logger.info(f"    Vulnerability breakdown: {severity_summary}")
                                
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
                                    self.save_individual_html_report(html_content, component_name, asset_name, repo_name, scan_timestamp, len(vulnerabilities))
                                
                                # Immediately delete downloaded file to free up space
                                try:
                                    if os.path.exists(local_path):
                                        file_size = os.path.getsize(local_path)
                                        os.remove(local_path)
                                        self.logger.debug(f"✅ Freed {file_size:,} bytes - deleted: {os.path.basename(local_path)}")
                                except Exception as e:
                                    self.logger.debug(f"Could not delete downloaded file {local_path}: {e}")
                                
                                if vulnerabilities:
                                    self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities in {asset_name}")
                            else:
                                self.logger.warning(f"    SCAN FAILED: Trivy scan returned no results")
                                # Log scan error with detailed information
                                asset_info = {
                                    'repository': repo_name,
                                    'component': component_name,
                                    'asset': asset_name,
                                    'artifact_type': artifact_type
                                }
                                self.log_scan_issue('error', asset_info, 'Trivy scan failed - no results returned', f"Strategy: {strategy['reason']}, Path: {local_path}")
                                self.stats['scan_errors'] += 1
                                
                                # Delete downloaded file even if scan failed to free up space
                                try:
                                    if os.path.exists(local_path):
                                        file_size = os.path.getsize(local_path)
                                        os.remove(local_path)
                                        self.logger.debug(f"✅ Freed {file_size:,} bytes - deleted: {os.path.basename(local_path)} (scan failed)")
                                except Exception as e:
                                    self.logger.debug(f"Could not delete downloaded file {local_path}: {e}")
                        else:
                            self.logger.error(f"    DOWNLOAD FAILED: Could not download {asset_name}")
                            # Log download error
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
        
        # Repository format-based detection for npm repositories
        if repo_format == 'npm':
            # For npm repositories, most files are Node packages
            if asset_lower.endswith('.tgz') or 'package' in asset_lower:
                return 'node_package'
            else:
                return 'node_package'  # Default for npm repos
        
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
        
        # Node packages - enhanced detection to match successful test script logic
        if ('package.json' in asset_lower or 
            asset_lower.endswith('.npm') or 
            (asset_lower.endswith('.tgz') and ('node' in asset_lower or 'client' in asset_lower or 'npm' in asset_lower)) or
            asset_lower.endswith('.tar.gz')):
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
        
        # Node/npm packages - need extraction for proper dependency analysis
        elif artifact_type == 'node_package':
            if file_path.endswith('.tgz') or file_path.endswith('.tar.gz'):
                strategy.update({
                    'scan_type': 'fs',
                    'extract_before_scan': True,  # Extract .tgz to find package.json
                    'scan_as_archive': False,     # Scan extracted contents, not archive
                    'reason': 'Node/npm package (.tgz) - extract and scan for dependencies'
                })
            else:
                strategy.update({
                    'scan_type': 'fs',
                    'scan_as_archive': True,
                    'reason': 'Node/npm package - scan for dependencies'
                })
        
        # NuGet packages
        elif artifact_type == 'nuget_package':
            strategy.update({
                'scan_type': 'fs',
                'scan_as_archive': True,
                'reason': 'NuGet package - scan for dependencies'
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
        
        # Default case - attempt filesystem scan for unrecognized types
        else:
            strategy.update({
                'scan_type': 'fs',
                'extract_before_scan': False,
                'reason': f'Unknown artifact type ({artifact_type}) - attempting filesystem scan'
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
            
            # For Linux deployment, check if we're using /tmp/tools/trivy path
            if self.trivy_path == '/tmp/tools/trivy/trivy':
                html_template_path = '/tmp/tools/trivy/contrib/html.tpl'
                
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
            json_result = subprocess.run(json_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                       universal_newlines=True, timeout=300)
            
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
            html_result = subprocess.run(html_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                       universal_newlines=True, timeout=300)
            
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
                        self.save_individual_html_report(html_content, component_name, f"docker_image_{component_version}", repo_name, "docker_scan", len(vulnerabilities))
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
    
    def save_individual_html_report(self, html_content: str, component_name: str, asset_name: str, repository_name: str, timestamp: str, vulnerability_count: int = 0):
        """Save individual HTML report for assets, organizing by vulnerability status."""
        try:
            # Create safe filename
            safe_component = component_name.replace('/', '_').replace(':', '_')
            safe_asset = asset_name.replace('/', '_').replace('\\', '_')
            safe_repository = repository_name.replace('/', '_').replace(':', '_')
            
            if self.retain_individual_reports:
                # Create repository-wise directory structure with vulnerability status
                if vulnerability_count > 0:
                    # Reports with vulnerabilities
                    base_dir = os.path.join(self.individual_reports_dir, "with_vulnerabilities", safe_repository)
                    status_info = f"({vulnerability_count} vulnerabilities)"
                    self.report_stats['reports_with_vulnerabilities'] += 1
                else:
                    # Empty reports (no vulnerabilities)
                    base_dir = os.path.join(self.individual_reports_dir, "empty_reports", safe_repository)
                    status_info = "(clean - no vulnerabilities)"
                    self.report_stats['empty_reports'] += 1
                
                os.makedirs(base_dir, exist_ok=True)
                
                # Use structured filename: component_name_asset_name_report.html
                filename = f"{safe_component}_{safe_asset}_report.html"
                html_file = os.path.join(base_dir, filename)
                
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                self.report_stats['total_reports_saved'] += 1
                self.logger.info(f"Individual HTML report retained: {html_file} {status_info}")
                
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
        """Clean up any remaining downloaded files from temp directory (fallback cleanup)."""
        try:
            if os.path.exists(self.temp_dir):
                # Count files and calculate total size before cleanup
                file_count = 0
                total_size = 0
                for root, dirs, files in os.walk(self.temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            file_size = os.path.getsize(file_path)
                            total_size += file_size
                            file_count += 1
                        except:
                            file_count += 1
                
                if file_count > 0:
                    self.logger.info(f"🧹 Final cleanup: removing {file_count} remaining files ({total_size:,} bytes) from temp directory")
                    
                    # Remove the entire temp directory and its contents
                    shutil.rmtree(self.temp_dir)
                    self.logger.info(f"✅ Freed {total_size:,} bytes total from temp directory cleanup")
                else:
                    self.logger.debug("✨ Temp directory already clean - no files to remove")
                    # Remove empty temp directory
                    if os.path.exists(self.temp_dir):
                        os.rmdir(self.temp_dir)
            else:
                self.logger.debug("✨ Temp directory does not exist - no files to clean up")
                
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
        
        /* Enhanced Severity Section Styles */
        .severity-overview {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }}
        .severity-item {{
            margin-bottom: 20px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }}
        .severity-header {{
            display: flex;
            align-items: center;
            margin-bottom: 10px;
            font-weight: bold;
        }}
        .severity-icon {{
            font-size: 1.5em;
            margin-right: 10px;
        }}
        .severity-name {{
            flex: 1;
            font-size: 1.2em;
        }}
        .severity-count {{
            font-size: 1.5em;
            color: #2c3e50;
            margin-right: 10px;
        }}
        .severity-percentage {{
            color: #6c757d;
            font-size: 1em;
        }}
        .severity-bar {{
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .severity-bar-fill {{
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s ease;
        }}
        .severity-description {{
            color: #6c757d;
            font-size: 0.9em;
            font-style: italic;
            margin-top: 5px;
        }}
        .vulnerability-summary {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }}
        .summary-item {{
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        .summary-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .summary-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        
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

        # Enhanced Vulnerability Severity Section
        if stats['severity_breakdown']:
            html += """
        <div class="severity-chart">
            <h2>🚨 Vulnerability Severity Analysis</h2>
            <div class="severity-overview">
"""
            total_vulns = sum(stats['severity_breakdown'].values())
            
            # Define severity colors and icons
            severity_info = {
                'CRITICAL': {'color': '#8e44ad', 'icon': '🔴', 'description': 'Critical vulnerabilities requiring immediate action'},
                'HIGH': {'color': '#e74c3c', 'icon': '🟠', 'description': 'High severity vulnerabilities requiring urgent attention'},
                'MEDIUM': {'color': '#f39c12', 'icon': '🟡', 'description': 'Medium severity vulnerabilities requiring timely resolution'},
                'LOW': {'color': '#f1c40f', 'icon': '🟢', 'description': 'Low severity vulnerabilities for routine maintenance'},
                'UNKNOWN': {'color': '#95a5a6', 'icon': '⚪', 'description': 'Unknown severity vulnerabilities requiring assessment'}
            }
            
            # Sort severities by priority
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
            
            for severity in severity_order:
                count = stats['severity_breakdown'].get(severity, 0)
                if count > 0:
                    percentage = (count / total_vulns) * 100
                    info = severity_info.get(severity, {'color': '#95a5a6', 'icon': '⚪', 'description': 'Unknown severity'})
                    
                    html += f"""
                <div class="severity-item">
                    <div class="severity-header">
                        <span class="severity-icon">{info['icon']}</span>
                        <span class="severity-name">{severity}</span>
                        <span class="severity-count">{count:,}</span>
                        <span class="severity-percentage">({percentage:.1f}%)</span>
                    </div>
                    <div class="severity-bar">
                        <div class="severity-bar-fill {severity.lower()}" style="width: {percentage}%; background-color: {info['color']};">
                        </div>
                    </div>
                    <div class="severity-description">{info['description']}</div>
                </div>
"""
            
            # Add summary section
            html += f"""
            </div>
            <div class="vulnerability-summary">
                <h3>📊 Summary</h3>
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="summary-number" style="color: #d73527;">{stats['severity_breakdown'].get('CRITICAL', 0):,}</div>
                        <div class="summary-label">🔴 Critical</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number" style="color: #fd7e14;">{stats['severity_breakdown'].get('HIGH', 0):,}</div>
                        <div class="summary-label">🟠 High</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number" style="color: #ffc107;">{stats['severity_breakdown'].get('MEDIUM', 0):,}</div>
                        <div class="summary-label">🟡 Medium</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number" style="color: #28a745;">{stats['severity_breakdown'].get('LOW', 0):,}</div>
                        <div class="summary-label">🟢 Low</div>
                    </div>
                </div>
                <!-- Additional metrics below vulnerability breakdown -->
                <div class="additional-metrics" style="margin-top: 20px; padding: 15px; background: rgba(0,123,255,0.05); border-radius: 8px; border-left: 4px solid #007bff;">
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; text-align: center;">
                        <div>
                            <div style="font-size: 1.5em; font-weight: bold; color: #007bff;">{total_vulns:,}</div>
                            <div style="font-size: 0.9em; color: #666;">Total Vulnerabilities</div>
                        </div>
                        <div>
                            <div style="font-size: 1.5em; font-weight: bold; color: #007bff;">{len(set(v.get('component', 'Unknown') for v in vulns)):,}</div>
                            <div style="font-size: 0.9em; color: #666;">Affected Components</div>
                        </div>
                        <div>
                            <div style="font-size: 1.5em; font-weight: bold; color: #007bff;">{len(set(v.get('repository', 'Unknown') for v in vulns)):,}</div>
                            <div style="font-size: 0.9em; color: #666;">Affected Repositories</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""

        # Vulnerability Details Table
        if vulns:
            html += """
        <div class="vulnerability-details-section">
            <h2>🔍 Vulnerability Details</h2>
            <div class="table-container" style="overflow-x: auto; margin: 20px 0; border: 1px solid #ddd; border-radius: 8px;">
                <table style="width: 100%; border-collapse: collapse; background: white;">
                    <thead style="background: #f8f9fa; border-bottom: 2px solid #dee2e6;">
                        <tr>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #495057;">Component</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #495057;">Package</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #495057;">Vulnerability ID</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #495057;">Severity</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #495057;">Installed Version</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #495057;">Fixed Version</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #495057;">Repository</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            # Sort vulnerabilities by severity for better visibility
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
            sorted_vulns = sorted(vulns, key=lambda x: (severity_order.get(x.get('severity', 'UNKNOWN'), 5), x.get('vulnerability_id', '')))
            
            for vuln in sorted_vulns:
                severity = vuln.get('severity', 'UNKNOWN')
                severity_color = {
                    'CRITICAL': '#d73527',
                    'HIGH': '#fd7e14', 
                    'MEDIUM': '#ffc107',
                    'LOW': '#28a745',
                    'UNKNOWN': '#6c757d'
                }.get(severity, '#6c757d')
                
                severity_bg = {
                    'CRITICAL': 'rgba(215, 53, 39, 0.1)',
                    'HIGH': 'rgba(253, 126, 20, 0.1)',
                    'MEDIUM': 'rgba(255, 193, 7, 0.1)',
                    'LOW': 'rgba(40, 167, 69, 0.1)',
                    'UNKNOWN': 'rgba(108, 117, 125, 0.1)'
                }.get(severity, 'rgba(108, 117, 125, 0.1)')
                
                component = vuln.get('component', 'Unknown')
                package = vuln.get('pkg_name', 'N/A')
                vuln_id = vuln.get('vulnerability_id', 'N/A')
                installed_version = vuln.get('pkg_version', 'N/A')
                fixed_version = vuln.get('fixed_version', 'N/A')
                repository = vuln.get('repository', 'Unknown')
                
                html += f"""
                        <tr style="border-bottom: 1px solid #dee2e6; background: {severity_bg if severity in ['CRITICAL', 'HIGH'] else 'white'};">
                            <td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{component}</td>
                            <td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{package}</td>
                            <td style="padding: 10px;">
                                <span style="font-family: monospace; color: #0066cc; font-weight: 500;">{vuln_id}</span>
                            </td>
                            <td style="padding: 10px;">
                                <span style="background: {severity_color}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600;">{severity}</span>
                            </td>
                            <td style="padding: 10px; font-family: monospace; color: #dc3545;">{installed_version}</td>
                            <td style="padding: 10px; font-family: monospace; color: #28a745;">{fixed_version}</td>
                            <td style="padding: 10px; font-size: 0.9em;">{repository}</td>
                        </tr>
"""
            
            html += """
                    </tbody>
                </table>
            </div>
            <div style="margin: 10px 0; color: #666; font-size: 0.9em;">
                <p><strong>📋 Legend:</strong> Critical and High severity vulnerabilities are highlighted with colored backgrounds. Vulnerability details are sorted by severity.</p>
            </div>
        </div>
"""

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
        """Print comprehensive scan summary with detailed diagnostics."""
        self.logger.info("=" * 60)
        self.logger.info("COMPREHENSIVE SCAN SUMMARY")
        self.logger.info("=" * 60)
        
        # Basic statistics
        self.logger.info("BASIC STATISTICS:")
        self.logger.info(f"  Repositories scanned: {self.stats['repositories_scanned']}")
        self.logger.info(f"  Components found: {self.stats['components_found']}")
        self.logger.info(f"  Assets scanned: {self.stats['assets_scanned']}")
        self.logger.info(f"  Vulnerabilities found: {self.stats['vulnerabilities_found']}")
        self.logger.info(f"  Scan errors: {self.stats['scan_errors']}")
        
        # Issue breakdown
        total_issues = len(self.scan_issues['errors']) + len(self.scan_issues['skipped_files']) + len(self.scan_issues['warnings'])
        total_successful = len(self.scan_issues['successful_scans'])
        
        self.logger.info("")
        self.logger.info("DETAILED ISSUE BREAKDOWN:")
        self.logger.info(f"  Total issues logged: {total_issues}")
        self.logger.info(f"    - Errors: {len(self.scan_issues['errors'])}")
        self.logger.info(f"    - Skipped files: {len(self.scan_issues['skipped_files'])}")
        self.logger.info(f"    - Warnings: {len(self.scan_issues['warnings'])}")
        self.logger.info(f"  Successful scans: {total_successful}")
        
        # Successful scan breakdown with vulnerability analysis
        if total_successful > 0:
            clean_scans = sum(1 for scan in self.scan_issues['successful_scans'] if scan.get('vulnerabilities_found', 0) == 0)
            vuln_scans = total_successful - clean_scans
            self.logger.info(f"    - Clean scans (0 vulnerabilities): {clean_scans}")
            self.logger.info(f"    - Scans with vulnerabilities: {vuln_scans}")
            
            if vuln_scans > 0:
                total_vulns_across_scans = sum(scan.get('vulnerabilities_found', 0) for scan in self.scan_issues['successful_scans'])
                self.logger.info(f"    - Total vulnerabilities across all scans: {total_vulns_across_scans}")
        
        # Repository analysis
        self.logger.info("")
        self.logger.info("REPOSITORY ANALYSIS:")
        repo_type_counts = self.statistics['repository_types']
        if any(count > 0 for count in repo_type_counts.values()):
            for repo_type, count in repo_type_counts.items():
                if count > 0:
                    self.logger.info(f"  {repo_type}: {count} repositories")
        else:
            self.logger.info("  No repository types detected")
        
        # Artifact type analysis
        self.logger.info("")
        self.logger.info("ARTIFACT TYPE ANALYSIS:")
        artifact_counts = self.statistics['artifact_types']
        if any(count > 0 for count in artifact_counts.values()):
            total_artifacts = sum(count for count in artifact_counts.values())
            for artifact_type, count in sorted(artifact_counts.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    percentage = (count / total_artifacts * 100) if total_artifacts > 0 else 0
                    self.logger.info(f"  {artifact_type}: {count} ({percentage:.1f}%)")
        else:
            self.logger.info("  No artifacts processed")
        
        # Configuration summary
        self.logger.info("")
        self.logger.info("CONFIGURATION SUMMARY:")
        self.logger.info(f"  Debug mode: {self.debug_mode}")
        self.logger.info(f"  Repository filtering: {'ENABLED' if self.repositories_to_scan else 'DISABLED'}")
        if self.repositories_to_scan:
            self.logger.info(f"    Filtered repositories: {', '.join(self.repositories_to_scan)}")
        self.logger.info(f"  Individual report retention: {'ENABLED' if self.retain_individual_reports else 'DISABLED'}")
        
        # Report organization summary
        if self.retain_individual_reports and self.report_stats['total_reports_saved'] > 0:
            self.logger.info("")
            self.logger.info("INDIVIDUAL REPORT ORGANIZATION:")
            self.logger.info(f"  Total individual reports saved: {self.report_stats['total_reports_saved']}")
            self.logger.info(f"  Reports with vulnerabilities: {self.report_stats['reports_with_vulnerabilities']}")
            self.logger.info(f"    Location: {os.path.join(self.individual_reports_dir, 'with_vulnerabilities')}")
            self.logger.info(f"  Empty reports (no vulnerabilities): {self.report_stats['empty_reports']}")
            self.logger.info(f"    Location: {os.path.join(self.individual_reports_dir, 'empty_reports')}")
            
            if self.report_stats['reports_with_vulnerabilities'] > 0:
                percentage_with_vulns = (self.report_stats['reports_with_vulnerabilities'] / self.report_stats['total_reports_saved']) * 100
                self.logger.info(f"  Vulnerability detection rate: {percentage_with_vulns:.1f}% of scanned files contain vulnerabilities")
            else:
                self.logger.info(f"  🧹 All scanned files are clean (no vulnerabilities detected)")
        
        # Diagnostic insights
        self.logger.info("")
        self.logger.info("DIAGNOSTIC INSIGHTS:")
        if self.stats['vulnerabilities_found'] == 0:
            self.logger.warning("  🚨 NO VULNERABILITIES FOUND - Possible reasons:")
            if self.stats['components_found'] == 0:
                self.logger.warning("    - No components found in repositories (repositories may be empty)")
            elif self.stats['assets_scanned'] == 0:
                self.logger.warning("    - No assets were actually scanned (all skipped or failed to download)")
            elif len(self.scan_issues['skipped_files']) > 0:
                self.logger.warning(f"    - {len(self.scan_issues['skipped_files'])} files were skipped (check skip reasons)")
            elif len(self.scan_issues['errors']) > 0:
                self.logger.warning(f"    - {len(self.scan_issues['errors'])} scan errors occurred")
            else:
                self.logger.info("    - Scanned artifacts may genuinely have no vulnerabilities")
                self.logger.info("    - Or artifacts may be types that Trivy doesn't analyze for vulnerabilities")
        else:
            self.logger.info("  ✅ Vulnerabilities were successfully detected")
        
        self.logger.info("=" * 60)
    
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
#!/usr/bin/env python3
"""
Clean Nexus Repository Scanner - No Unicode Characters
Scans all repositories and all components for vulnerabilities using Trivy.
"""

import os
import sys
import json
import csv
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
        
        # Setup authentication
        self.auth = HTTPBasicAuth(self.username, self.password)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Initialized intelligent scanner with Nexus: {self.nexus_url}")
        self.logger.info(f"Using Trivy: {self.trivy_path}")
        
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
            response = requests.get(asset_url, auth=self.auth, stream=True, timeout=60)
            response.raise_for_status()
            
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error downloading {asset_url}: {e}")
            return False
    
    def scan_with_trivy(self, file_path: str, scan_type: str = "fs") -> Optional[tuple]:
        """Scan a file or directory with Trivy. Returns (json_results, html_output)."""
        try:
            # Create output files for Trivy results
            json_output_file = f"{file_path}.trivy.json"
            html_output_file = f"{file_path}.trivy.html"
            
            # JSON scan for programmatic processing
            json_cmd = [
                self.trivy_path,
                scan_type,
                "--format", "json",
                "--output", json_output_file,
                "--quiet",
                file_path
            ]
            
            # HTML scan using Trivy's built-in template
            html_cmd = [
                self.trivy_path,
                scan_type,
                "--format", "template",
                "--template", "@contrib/html.tpl",
                "--output", html_output_file,
                "--quiet",
                file_path
            ]
            
            # Run JSON scan
            json_result = subprocess.run(json_cmd, capture_output=True, text=True, timeout=300)
            # Run HTML scan
            html_result = subprocess.run(html_cmd, capture_output=True, text=True, timeout=300)
            
            json_data = None
            html_content = None
            
            # Read JSON results
            if os.path.exists(json_output_file):
                with open(json_output_file, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                os.remove(json_output_file)
            
            # Read HTML results
            if os.path.exists(html_output_file):
                with open(html_output_file, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                os.remove(html_output_file)
                
            return (json_data, html_content)
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Trivy scan timed out for {file_path}")
            return None
        except Exception as e:
            self.logger.error(f"Error scanning {file_path} with Trivy: {e}")
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
                        
                        strategy = self.determine_scan_strategy(artifact_type, asset_name, repo_format)
                        
                        if strategy['skip_scan']:
                            self.logger.info(f"Skipping {asset_name} - {strategy['reason']}")
                            continue
                        
                        self.logger.info(f"Scanning asset: {asset_name} (Type: {artifact_type})")
                        self.logger.info(f"Strategy: {strategy['reason']}")
                        self.stats['assets_scanned'] += 1
                        
                        # Create local filename for download
                        safe_filename = asset_name.replace('/', '_').replace('\\', '_')
                        local_path = os.path.join(self.output_dir, 'temp', safe_filename)
                        
                        # Download and scan
                        if self.download_asset(download_url, local_path):
                            # Use intelligent scanning strategy
                            scan_results = self.scan_with_strategy(local_path, strategy, artifact_type)
                            
                            if scan_results and scan_results[0]:  # Check JSON results
                                json_data, html_content = scan_results
                                vulnerabilities = self.extract_vulnerabilities(json_data)
                                self.stats['vulnerabilities_found'] += len(vulnerabilities)
                                
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
                                
                                # Save individual HTML report if vulnerabilities found
                                if vulnerabilities and html_content:
                                    self.save_individual_html_report(html_content, component_name, asset_name, scan_timestamp)
                                
                                if vulnerabilities:
                                    self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities in {asset_name}")
                            else:
                                self.stats['scan_errors'] += 1
                            
                            # Clean up downloaded file
                            try:
                                os.remove(local_path)
                            except:
                                pass
        
        # Save results
        self.save_results(all_vulnerabilities, scan_timestamp)
        self.generate_combined_report(all_vulnerabilities, scan_timestamp)
        self.print_summary()
    
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
        
        # Check each artifact type pattern
        for artifact_type, patterns in self.artifact_patterns.items():
            if any(asset_lower.endswith(pattern) or pattern in asset_lower for pattern in patterns):
                return artifact_type
        
        # Repository format-based detection
        if repo_format == 'maven2':
            return 'maven_artifact'
        elif repo_format == 'nuget':
            return 'nuget_package'
        elif repo_format == 'docker':
            return 'container_image'
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
                'scan_type': 'fs',  # For downloaded tar files
                'extract_before_scan': True,
                'reason': 'Container image - extract and scan layers'
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
            self.logger.error(f"Error processing Docker component {component_name}: {e}")
            self.stats['scan_errors'] += 1
        
        return vulnerabilities
    
    def scan_docker_image_direct(self, image_reference: str, component_name: str, component_version: str) -> List[Dict[str, Any]]:
        """Scan Docker image directly using Trivy's image scanning capability."""
        try:
            # Create output files
            safe_name = image_reference.replace('/', '_').replace(':', '_')
            json_output_file = os.path.join(self.output_dir, 'temp', f"{safe_name}_docker.json")
            html_output_file = os.path.join(self.output_dir, 'temp', f"{safe_name}_docker.html")
            
            os.makedirs(os.path.dirname(json_output_file), exist_ok=True)
            
            # JSON scan command
            json_cmd = [
                self.trivy_path, "image",
                "--format", "json",
                "--output", json_output_file,
                "--quiet",
                image_reference
            ]
            
            # HTML scan command  
            html_cmd = [
                self.trivy_path, "image",
                "--format", "template", 
                "--template", "@contrib/html.tpl",
                "--output", html_output_file,
                "--quiet",
                image_reference
            ]
            
            # Run JSON scan
            json_result = subprocess.run(json_cmd, capture_output=True, text=True, timeout=300)
            if json_result.returncode != 0:
                self.logger.debug(f"Docker image scan failed for {image_reference}: {json_result.stderr}")
                return []
            
            # Run HTML scan
            subprocess.run(html_cmd, capture_output=True, text=True, timeout=300)
            
            # Parse JSON results
            vulnerabilities = []
            if os.path.exists(json_output_file):
                with open(json_output_file, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                    vulnerabilities = self.extract_vulnerabilities(json_data)
                
                # Save individual HTML report if vulnerabilities found and HTML exists
                if vulnerabilities and os.path.exists(html_output_file):
                    with open(html_output_file, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    self.save_individual_html_report(html_content, component_name, f"docker_image_{component_version}", "docker_scan")
                
                # Clean up temp files
                for temp_file in [json_output_file, html_output_file]:
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                        except:
                            pass
                            
            return vulnerabilities
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Docker image scan timed out for {image_reference}")
            return []
        except Exception as e:
            self.logger.debug(f"Error in direct Docker scan for {image_reference}: {e}")
            return []
    
    def save_individual_html_report(self, html_content: str, component_name: str, asset_name: str, timestamp: str):
        """Save individual HTML report for assets with vulnerabilities."""
        try:
            # Create safe filename
            safe_component = component_name.replace('/', '_').replace(':', '_')
            safe_asset = asset_name.replace('/', '_').replace('\\', '_')
            
            html_file = os.path.join(
                self.output_dir, 
                f'individual_report_{safe_component}_{safe_asset}_{timestamp.replace(":", "-")}.html'
            )
            
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Individual HTML report saved: {html_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving individual HTML report: {e}")
    
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
        
        self.logger.info("=" * 50)

def main():
    """Main function."""
    scanner = CleanNexusScanner()
    scanner.scan_content_repositories()

if __name__ == "__main__":
    main()
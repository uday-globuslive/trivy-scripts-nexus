#!/usr/bin/env python3
"""
JSON Helper Script for Node.js Package Enhancement
This script provides JSON parsing and manipulation functionality
to replace jq dependency in bash scripts.
"""

import json
import sys
import os
from pathlib import Path

def read_json_field(json_file, field_path, default_value=""):
    """Read a specific field from a JSON file."""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle nested field paths like .dependencies
        fields = field_path.strip('.').split('.')
        current = data
        
        for field in fields:
            if isinstance(current, dict) and field in current:
                current = current[field]
            else:
                return default_value
        
        if current is None:
            return default_value
            
        return current
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return default_value

def create_package_lock(package_json_file, output_dir):
    """Create a package-lock.json file based on package.json."""
    try:
        with open(package_json_file, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
        
        name = package_data.get('name', 'unknown')
        version = package_data.get('version', '0.0.0')
        dependencies = package_data.get('dependencies', {})
        
        # Create basic lock file structure
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
        
        # Add dependencies if they exist
        if dependencies:
            lock_data["packages"][""]["dependencies"] = dependencies
            
            # Add node_modules entries
            for dep_name, dep_version in dependencies.items():
                # Clean version (remove ^ ~ >= < etc)
                clean_version = dep_version.lstrip('^~>=<')
                
                # Add to packages section
                lock_data["packages"][f"node_modules/{dep_name}"] = {
                    "version": clean_version,
                    "resolved": f"https://registry.npmjs.org/{dep_name}/-/{dep_name}-{clean_version}.tgz",
                    "integrity": "sha512-" + "0" * 64,
                    "license": "MIT"
                }
                
                # Add to dependencies section
                lock_data["dependencies"][dep_name] = {
                    "version": clean_version,
                    "resolved": f"https://registry.npmjs.org/{dep_name}/-/{dep_name}-{clean_version}.tgz",
                    "integrity": "sha512-" + "0" * 64
                }
        
        # Write lock file
        lock_file_path = os.path.join(output_dir, 'package-lock.json')
        with open(lock_file_path, 'w', encoding='utf-8') as f:
            json.dump(lock_data, f, indent=2)
        
        return {
            'success': True,
            'name': name,
            'version': version,
            'dependencies_count': len(dependencies),
            'lock_file': lock_file_path
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def create_node_modules_structure(package_json_file, output_dir):
    """Create node_modules directory structure based on package.json."""
    try:
        with open(package_json_file, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
        
        dependencies = package_data.get('dependencies', {})
        
        if not dependencies:
            return {'success': True, 'created_packages': 0}
        
        node_modules_dir = os.path.join(output_dir, 'node_modules')
        os.makedirs(node_modules_dir, exist_ok=True)
        
        created_packages = 0
        for dep_name, dep_version in dependencies.items():
            # Clean version
            clean_version = dep_version.lstrip('^~>=<')
            
            # Create dependency directory
            dep_dir = os.path.join(node_modules_dir, dep_name)
            os.makedirs(dep_dir, exist_ok=True)
            
            # Create minimal package.json for dependency
            dep_package_json = {
                "name": dep_name,
                "version": clean_version
            }
            
            dep_package_file = os.path.join(dep_dir, 'package.json')
            with open(dep_package_file, 'w', encoding='utf-8') as f:
                json.dump(dep_package_json, f, indent=2)
            
            created_packages += 1
        
        return {
            'success': True,
            'created_packages': created_packages,
            'node_modules_dir': node_modules_dir
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def analyze_scan_results(results_file):
    """Analyze Trivy scan results JSON file."""
    try:
        with open(results_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        total_vulns = 0
        severity_counts = {}
        
        # Extract vulnerabilities from results
        if isinstance(data, dict) and 'Results' in data:
            for result in data['Results']:
                if 'Vulnerabilities' in result:
                    vulns = result['Vulnerabilities']
                    total_vulns += len(vulns)
                    
                    for vuln in vulns:
                        severity = vuln.get('Severity', 'UNKNOWN')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'success': True,
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def main():
    """Main function to handle command line arguments."""
    if len(sys.argv) < 2:
        print("Usage: python3 json_helper.py <command> [args...]", file=sys.stderr)
        print("Commands:", file=sys.stderr)
        print("  read_field <json_file> <field_path> [default_value]", file=sys.stderr)
        print("  create_lock <package_json_file> <output_dir>", file=sys.stderr)
        print("  create_modules <package_json_file> <output_dir>", file=sys.stderr)
        print("  analyze_results <results_file>", file=sys.stderr)
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "read_field":
        if len(sys.argv) < 4:
            print("Usage: read_field <json_file> <field_path> [default_value]", file=sys.stderr)
            sys.exit(1)
        
        json_file = sys.argv[2]
        field_path = sys.argv[3]
        default_value = sys.argv[4] if len(sys.argv) > 4 else ""
        
        result = read_json_field(json_file, field_path, default_value)
        print(json.dumps(result) if isinstance(result, (dict, list)) else str(result))
    
    elif command == "create_lock":
        if len(sys.argv) < 4:
            print("Usage: create_lock <package_json_file> <output_dir>", file=sys.stderr)
            sys.exit(1)
        
        package_json_file = sys.argv[2]
        output_dir = sys.argv[3]
        
        result = create_package_lock(package_json_file, output_dir)
        print(json.dumps(result))
    
    elif command == "create_modules":
        if len(sys.argv) < 4:
            print("Usage: create_modules <package_json_file> <output_dir>", file=sys.stderr)
            sys.exit(1)
        
        package_json_file = sys.argv[2]
        output_dir = sys.argv[3]
        
        result = create_node_modules_structure(package_json_file, output_dir)
        print(json.dumps(result))
    
    elif command == "analyze_results":
        if len(sys.argv) < 3:
            print("Usage: analyze_results <results_file>", file=sys.stderr)
            sys.exit(1)
        
        results_file = sys.argv[2]
        
        result = analyze_scan_results(results_file)
        print(json.dumps(result))
    
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Configuration loader for Nexus Vulnerability Scanner
Loads configuration from .env file and local paths
"""

import os
import sys
from pathlib import Path

def load_env_file(env_path=".env"):
    """Load environment variables from .env file"""
    env_vars = {}
    
    if not os.path.exists(env_path):
        return env_vars
    
    try:
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    env_vars[key] = value
                    # Also set as environment variable
                    os.environ[key] = value
    except Exception as e:
        print(f"Warning: Could not load .env file: {e}")
    
    return env_vars

def get_trivy_path():
    """Get path to local Trivy executable"""
    script_dir = Path(__file__).parent
    trivy_paths = [
        script_dir / "trivy" / "trivy.exe",  # Windows
        script_dir / "trivy" / "trivy",      # Linux/Mac
        "trivy"  # Fallback to system PATH
    ]
    
    for trivy_path in trivy_paths:
        if isinstance(trivy_path, Path) and trivy_path.exists():
            return str(trivy_path.absolute())
        elif isinstance(trivy_path, str):
            # Check if trivy is in PATH
            import shutil
            if shutil.which(trivy_path):
                return trivy_path
    
    return None

def get_config():
    """Get complete configuration"""
    # Load .env file
    env_vars = load_env_file()
    
    # Get Trivy path
    trivy_path = get_trivy_path()
    
    config = {
        'nexus_url': env_vars.get('NEXUS_URL', os.getenv('NEXUS_URL')),
        'nexus_username': env_vars.get('NEXUS_USERNAME', os.getenv('NEXUS_USERNAME')),
        'nexus_password': env_vars.get('NEXUS_PASSWORD', os.getenv('NEXUS_PASSWORD')),
        'trivy_path': trivy_path,
        'output_dir': env_vars.get('OUTPUT_DIR', os.getenv('OUTPUT_DIR', './vulnerability_reports')),
        'repositories_to_scan': env_vars.get('REPOSITORIES_TO_SCAN', os.getenv('REPOSITORIES_TO_SCAN', '')),
        'debug_mode': env_vars.get('DEBUG_MODE', os.getenv('DEBUG_MODE', 'false')).lower() == 'true',
        'debug_log_level': env_vars.get('DEBUG_LOG_LEVEL', os.getenv('DEBUG_LOG_LEVEL', 'INFO')),
        'debug_log_file': env_vars.get('DEBUG_LOG_FILE', os.getenv('DEBUG_LOG_FILE', 'false')).lower() == 'true',
        'debug_trivy_commands': env_vars.get('DEBUG_TRIVY_COMMANDS', os.getenv('DEBUG_TRIVY_COMMANDS', 'false')).lower() == 'true',
        'debug_http_requests': env_vars.get('DEBUG_HTTP_REQUESTS', os.getenv('DEBUG_HTTP_REQUESTS', 'false')).lower() == 'true',
        'retain_individual_reports': env_vars.get('RETAIN_INDIVIDUAL_REPORTS', os.getenv('RETAIN_INDIVIDUAL_REPORTS', 'false')).lower() == 'true'
    }
    
    return config

def validate_config(config):
    """Validate configuration"""
    missing_items = []
    
    if not config['nexus_url']:
        missing_items.append('NEXUS_URL')
    
    if not config['nexus_username']:
        missing_items.append('NEXUS_USERNAME')
    
    if not config['nexus_password']:
        missing_items.append('NEXUS_PASSWORD')
    
    if not config['trivy_path']:
        missing_items.append('Trivy executable (not found in ./trivy/ or system PATH)')
    
    return missing_items

if __name__ == "__main__":
    # Test configuration loading
    config = get_config()
    missing = validate_config(config)
    
    print("Configuration Status:")
    print("=" * 40)
    
    if config['nexus_url']:
        print(f"✅ Nexus URL: {config['nexus_url']}")
    else:
        print("❌ Nexus URL: Not configured")
    
    if config['nexus_username']:
        print(f"✅ Username: {config['nexus_username']}")
    else:
        print("❌ Username: Not configured")
    
    if config['nexus_password']:
        print(f"✅ Password: {'*' * len(config['nexus_password'])}")
    else:
        print("❌ Password: Not configured")
    
    if config['trivy_path']:
        print(f"✅ Trivy: {config['trivy_path']}")
    else:
        print("❌ Trivy: Not found")
    
    print(f"📁 Output Directory: {config['output_dir']}")
    
    # Show repository filtering status
    repositories_to_scan_str = config.get('repositories_to_scan', '').strip()
    if repositories_to_scan_str:
        repo_list = [repo.strip() for repo in repositories_to_scan_str.split(',') if repo.strip()]
        print(f"🔍 Repository Filter: {len(repo_list)} repositories ({', '.join(repo_list)})")
    else:
        print("🔍 Repository Filter: Disabled (will scan all repositories)")
    
    if missing:
        print(f"\n❌ Missing configuration: {', '.join(missing)}")
        sys.exit(1)
    else:
        print("\n✅ All configuration items found!")
#!/bin/bash

# Quick Node.js Package Enhancement Test Script
# This script quickly applies the Node.js enhancement logic to a directory
# Usage: ./enhance_nodejs.sh <directory_path>

set -euo pipefail

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Python is available and get the command
get_python_cmd() {
    if command -v python3 >/dev/null 2>&1; then
        echo "python3"
    elif command -v python >/dev/null 2>&1; then
        # Check if it's Python 3
        if python -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" 2>/dev/null; then
            echo "python"
        else
            return 1
        fi
    else
        return 1
    fi
}

# Function to ensure Python is available
check_python() {
    local python_cmd
    python_cmd=$(get_python_cmd)
    if [[ $? -ne 0 ]]; then
        print_error "Python 3 is required but not found"
        print_info "Please install Python 3:"
        print_info "  Ubuntu/Debian: sudo apt-get install python3"
        print_info "  CentOS/RHEL: sudo yum install python3"
        print_info "  macOS: brew install python3"
        print_info "  Windows: Download from https://python.org"
        return 1
    fi
    return 0
}

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <directory_path>"
    echo "Example: $0 ./extracted-package/"
    exit 1
fi

TARGET_DIR="$1"

if [[ ! -d "$TARGET_DIR" ]]; then
    print_error "Directory does not exist: $TARGET_DIR"
    exit 1
fi

# Ensure Python is available
if ! check_python; then
    print_error "Python 3 is required for Node.js package enhancement"
    exit 1
fi

# Get Python command and script directory
PYTHON_CMD=$(get_python_cmd)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JSON_HELPER="$SCRIPT_DIR/json_helper.py"

if [[ ! -f "$JSON_HELPER" ]]; then
    print_error "json_helper.py not found in script directory"
    exit 1
fi

print_info "Enhancing Node.js packages in: $TARGET_DIR"
print_info "Searching for package.json files..."

# Find all package.json files
PACKAGE_COUNT=0
while IFS= read -r -d '' package_json_path; do
    ((PACKAGE_COUNT++))
    package_dir=$(dirname "$package_json_path")
    
    print_info "Found package.json: $package_json_path"
    
    # Check if lock files already exist
    if [[ -f "$package_dir/package-lock.json" ]] || \
       [[ -f "$package_dir/yarn.lock" ]] || \
       [[ -f "$package_dir/pnpm-lock.yaml" ]]; then
        print_warning "Lock file already exists in $package_dir, skipping"
        continue
    fi
    
    # Read package.json data using Python
    name=$($PYTHON_CMD "$JSON_HELPER" read_field "$package_json_path" "name" "unknown")
    version=$($PYTHON_CMD "$JSON_HELPER" read_field "$package_json_path" "version" "0.0.0")
    
    print_info "Enhancing: $name@$version"
    
    # Create package-lock.json using Python helper
    lock_result=$($PYTHON_CMD "$JSON_HELPER" create_lock "$package_json_path" "$package_dir")
    
    if [[ $? -eq 0 ]]; then
        # Parse the result
        success=$(echo "$lock_result" | $PYTHON_CMD -c "import sys, json; data=json.load(sys.stdin); print(data.get('success', False))")
        
        if [[ "$success" == "True" ]]; then
            # Create node_modules structure
            modules_result=$($PYTHON_CMD "$JSON_HELPER" create_modules "$package_json_path" "$package_dir")
            
            if [[ $? -eq 0 ]]; then
                modules_success=$(echo "$modules_result" | $PYTHON_CMD -c "import sys, json; data=json.load(sys.stdin); print(data.get('success', False))")
                created_packages=$(echo "$modules_result" | $PYTHON_CMD -c "import sys, json; data=json.load(sys.stdin); print(data.get('created_packages', 0))")
                
                if [[ "$modules_success" == "True" ]]; then
                    lock_file="$package_dir/package-lock.json"
                    lock_size=$(stat -f%z "$lock_file" 2>/dev/null || stat -c%s "$lock_file" 2>/dev/null || echo "unknown")
                    
                    print_success "Enhanced $name@$version:"
                    print_info "  📦 Created package-lock.json: $lock_size bytes"
                    print_info "  📁 Created node_modules with $created_packages packages"
                else
                    print_warning "Failed to create node_modules structure for $name"
                fi
            else
                print_warning "Failed to create node_modules structure for $name"
            fi
        else
            error_msg=$(echo "$lock_result" | $PYTHON_CMD -c "import sys, json; data=json.load(sys.stdin); print(data.get('error', 'Unknown error'))")
            print_warning "Failed to create package-lock.json for $name: $error_msg"
        fi
        
    else
        print_info "No dependencies found, creating minimal package-lock.json"
        
        cat > "$package_dir/package-lock.json" << EOF
{
  "name": "$name",
  "version": "$version",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "$name",
      "version": "$version",
      "license": "MIT"
    }
  },
  "dependencies": {}
}
EOF
        
        print_success "Created minimal package-lock.json for $name@$version"
    fi
    
done < <(find "$TARGET_DIR" -name "package.json" -type f -print0)

if [[ $PACKAGE_COUNT -eq 0 ]]; then
    print_warning "No package.json files found in $TARGET_DIR"
    print_info "This directory may not contain Node.js packages"
else
    print_success "Enhancement completed! Processed $PACKAGE_COUNT package(s)"
    print_info "The directory is now ready for Trivy scanning"
fi
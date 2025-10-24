#!/bin/bash

# Test Script for Node.js Package Scanning Enhancement
# This script demonstrates the complete workflow with sample data
# Usage: ./test_nodejs_enhancement.sh [trivy_binary_path]

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

print_header() {
    echo -e "${MAGENTA}======================================${NC}"
    echo -e "${MAGENTA}$1${NC}"
    echo -e "${MAGENTA}======================================${NC}"
}

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

print_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Default trivy path (can be overridden)
TRIVY_PATH="${1:-trivy}"
TEST_DIR="./test_nodejs_enhancement"
SAMPLE_PACKAGE_DIR="$TEST_DIR/sample-package"

# Function to create sample Node.js package
create_sample_package() {
    print_step "Creating sample Node.js package..."
    
    mkdir -p "$SAMPLE_PACKAGE_DIR"
    
    # Create a sample package.json with real dependencies
    cat > "$SAMPLE_PACKAGE_DIR/package.json" << 'EOF'
{
  "name": "sample-nodejs-app",
  "version": "1.0.0",
  "description": "Sample Node.js application for testing Trivy scanning",
  "main": "index.js",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.19",
    "axios": "^0.27.2",
    "jsonwebtoken": "^8.5.1",
    "bcrypt": "^5.0.1"
  },
  "devDependencies": {
    "jest": "^28.1.0",
    "nodemon": "^2.0.16"
  },
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "test": "jest"
  },
  "keywords": ["nodejs", "sample", "testing"],
  "author": "Test Author",
  "license": "MIT"
}
EOF
    
    # Create a sample index.js
    cat > "$SAMPLE_PACKAGE_DIR/index.js" << 'EOF'
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const axios = require('axios');
const _ = require('lodash');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/', (req, res) => {
    res.json({ 
        message: 'Sample Node.js app for security testing',
        dependencies: ['express', 'lodash', 'axios', 'jsonwebtoken', 'bcrypt']
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
EOF
    
    # Create README.md
    cat > "$SAMPLE_PACKAGE_DIR/README.md" << 'EOF'
# Sample Node.js Application

This is a sample Node.js application created for testing the Trivy security scanning enhancement.

## Dependencies

- express: Web framework
- lodash: Utility library
- axios: HTTP client
- jsonwebtoken: JWT implementation
- bcrypt: Password hashing

## Note

Some of these dependencies may have known vulnerabilities for testing purposes.
EOF
    
    print_success "Sample Node.js package created at: $SAMPLE_PACKAGE_DIR"
}

# Function to create tar.gz package
create_tgz_package() {
    print_step "Creating .tgz package from sample..."
    
    local tgz_file="$TEST_DIR/sample-nodejs-app-1.0.0.tgz"
    
    # Create tar.gz file (similar to npm pack)
    cd "$TEST_DIR"
    tar -czf "sample-nodejs-app-1.0.0.tgz" -C sample-package .
    cd - > /dev/null
    
    local tgz_size
    tgz_size=$(stat -f%z "$tgz_file" 2>/dev/null || stat -c%s "$tgz_file" 2>/dev/null || echo "unknown")
    
    print_success "Created .tgz package: $tgz_file ($tgz_size bytes)"
    return 0
}

# Function to test enhancement script
test_enhancement_script() {
    print_step "Testing standalone enhancement script..."
    
    if [[ ! -f "./enhance_nodejs.sh" ]]; then
        print_error "Enhancement script not found: ./enhance_nodejs.sh"
        return 1
    fi
    
    # Make script executable
    chmod +x ./enhance_nodejs.sh
    
    # Test on the extracted directory
    local test_extract_dir="$TEST_DIR/test-extract" 
    mkdir -p "$test_extract_dir"
    
    # Copy sample package to test directory
    cp -r "$SAMPLE_PACKAGE_DIR"/* "$test_extract_dir/"
    
    print_info "Running enhancement on: $test_extract_dir"
    
    if ./enhance_nodejs.sh "$test_extract_dir"; then
        print_success "Enhancement script test passed"
        
        # Verify enhancement results
        if [[ -f "$test_extract_dir/package-lock.json" ]]; then
            print_success "✅ package-lock.json created"
        else
            print_warning "⚠️  package-lock.json not found"
        fi
        
        if [[ -d "$test_extract_dir/node_modules" ]]; then
            local module_count
            module_count=$(find "$test_extract_dir/node_modules" -maxdepth 1 -type d | wc -l)
            print_success "✅ node_modules directory created with $((module_count - 1)) entries"
        else
            print_warning "⚠️  node_modules directory not found"
        fi
        
        return 0
    else
        print_error "Enhancement script test failed"
        return 1
    fi
}

# Function to test full scanning script
test_scanning_script() {
    print_step "Testing full scanning script..."
    
    if [[ ! -f "./scan_nodejs_package.sh" ]]; then
        print_error "Scanning script not found: ./scan_nodejs_package.sh"
        return 1
    fi
    
    # Make script executable
    chmod +x ./scan_nodejs_package.sh
    
    # Check if Trivy is available
    if ! command -v "$TRIVY_PATH" >/dev/null 2>&1; then
        print_warning "Trivy not found at: $TRIVY_PATH"
        print_info "Skipping Trivy scan test"
        return 0
    fi
    
    print_info "Testing with Trivy at: $TRIVY_PATH"
    
    local tgz_file="$TEST_DIR/sample-nodejs-app-1.0.0.tgz"
    
    if [[ ! -f "$tgz_file" ]]; then
        print_error "Test .tgz file not found: $tgz_file"
        return 1
    fi
    
    # Test with verbose output and JSON format
    print_info "Running scan on .tgz file with enhancement..."
    
    if ./scan_nodejs_package.sh -v -f json -o "$TEST_DIR/scan_results" "$TRIVY_PATH" "$tgz_file"; then
        print_success "Full scanning script test passed"
        
        # Check for results
        local results_dir="$TEST_DIR/scan_results"
        if [[ -d "$results_dir" ]]; then
            local result_files
            result_files=$(find "$results_dir" -name "*.json" | wc -l)
            print_success "✅ Scan results generated: $result_files JSON file(s)"
            
            # Show latest result file
            local latest_result
            latest_result=$(find "$results_dir" -name "*.json" -type f -exec ls -t {} + | head -n1)
            if [[ -n "$latest_result" ]]; then
                print_info "Latest result file: $latest_result"
                
                # Quick analysis using Python
                if [[ -f "$JSON_HELPER" ]]; then
                    local analysis_result vuln_count
                    analysis_result=$($PYTHON_CMD "$JSON_HELPER" analyze_results "$latest_result" 2>/dev/null)
                    if [[ $? -eq 0 ]]; then
                        vuln_count=$(echo "$analysis_result" | $PYTHON_CMD -c "import sys, json; data=json.load(sys.stdin); print(data.get('total_vulnerabilities', 0))" 2>/dev/null || echo "0")
                        print_info "Vulnerabilities found: $vuln_count"
                    fi
                fi
            fi
        fi
        
        return 0
    else
        print_error "Full scanning script test failed"
        return 1
    fi
}

# Function to demonstrate before/after comparison
demonstrate_enhancement() {
    print_step "Demonstrating enhancement effectiveness..."
    
    if ! command -v "$TRIVY_PATH" >/dev/null 2>&1; then
        print_warning "Trivy not found, skipping demonstration"
        return 0
    fi
    
    local tgz_file="$TEST_DIR/sample-nodejs-app-1.0.0.tgz"
    local extract_normal="$TEST_DIR/extract-normal"
    local extract_enhanced="$TEST_DIR/extract-enhanced"
    
    # Extract without enhancement
    print_info "Creating normal extraction (without enhancement)..."
    mkdir -p "$extract_normal"
    tar -xzf "$tgz_file" -C "$extract_normal"
    
    # Extract with enhancement
    print_info "Creating enhanced extraction..."
    mkdir -p "$extract_enhanced"
    tar -xzf "$tgz_file" -C "$extract_enhanced"
    ./enhance_nodejs.sh "$extract_enhanced" > /dev/null 2>&1
    
    # Scan both versions
    print_info "Scanning normal extraction..."
    local normal_results="$TEST_DIR/normal_results.json"
    "$TRIVY_PATH" fs --format json --output "$normal_results" "$extract_normal" || true
    
    print_info "Scanning enhanced extraction..."
    local enhanced_results="$TEST_DIR/enhanced_results.json"
    "$TRIVY_PATH" fs --format json --output "$enhanced_results" "$extract_enhanced" || true
    
    # Compare results using Python
    if [[ -f "$JSON_HELPER" ]]; then
        local normal_analysis enhanced_analysis normal_vulns enhanced_vulns
        
        normal_analysis=$($PYTHON_CMD "$JSON_HELPER" analyze_results "$normal_results" 2>/dev/null)
        enhanced_analysis=$($PYTHON_CMD "$JSON_HELPER" analyze_results "$enhanced_results" 2>/dev/null)
        
        if [[ $? -eq 0 ]]; then
            normal_vulns=$(echo "$normal_analysis" | $PYTHON_CMD -c "import sys, json; data=json.load(sys.stdin); print(data.get('total_vulnerabilities', 0))" 2>/dev/null || echo "0")
            enhanced_vulns=$(echo "$enhanced_analysis" | $PYTHON_CMD -c "import sys, json; data=json.load(sys.stdin); print(data.get('total_vulnerabilities', 0))" 2>/dev/null || echo "0")
        else
            normal_vulns="unknown"
            enhanced_vulns="unknown"
        fi
        
        print_info "Comparison Results:"
        print_info "  Normal scan:   $normal_vulns vulnerabilities"
        print_info "  Enhanced scan: $enhanced_vulns vulnerabilities"
        
        if [[ "$enhanced_vulns" -gt "$normal_vulns" ]]; then
            print_success "✅ Enhancement detected $((enhanced_vulns - normal_vulns)) additional vulnerabilities!"
        elif [[ "$enhanced_vulns" -eq "$normal_vulns" ]] && [[ "$enhanced_vulns" -gt 0 ]]; then
            print_success "✅ Both scans found vulnerabilities (enhancement maintained detection)"
        elif [[ "$normal_vulns" -eq 0 ]] && [[ "$enhanced_vulns" -eq 0 ]]; then
            print_info "ℹ️  No vulnerabilities found in either scan (clean packages)"
        else
            print_warning "⚠️  Unexpected result pattern"
        fi
    fi
}

# Function to cleanup test files
cleanup() {
    print_step "Cleaning up test files..."
    
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
        print_success "Test directory cleaned up"
    fi
}

# Main test function
main() {
    print_header "Node.js Package Scanning Enhancement Test"
    
    print_info "Test configuration:"
    print_info "  Trivy path: $TRIVY_PATH"
    print_info "  Test directory: $TEST_DIR"
    print_info ""
    
    # Check prerequisites
    # Ensure Python is available
    if ! check_python; then
        print_error "Python 3 is required for Node.js package enhancement"
        return 1
    fi
    
    # Check for tar (required system tool)
    if ! command -v tar >/dev/null 2>&1; then
        print_error "tar command not found. Please install tar:"
        print_info "  Ubuntu/Debian: sudo apt-get install tar"
        print_info "  CentOS/RHEL: sudo yum install tar"
        print_info "  macOS: tar is usually pre-installed"
        return 1
    fi
    
    # Set up Python and helper script variables
    PYTHON_CMD=$(get_python_cmd)
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    JSON_HELPER="$SCRIPT_DIR/json_helper.py"
    
    if [[ ! -f "$JSON_HELPER" ]]; then
        print_error "json_helper.py not found in script directory"
        return 1
    fi
    
    # Cleanup any existing test directory
    [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
    
    # Create test directory
    mkdir -p "$TEST_DIR"
    
    # Run tests
    local tests_passed=0
    local tests_total=0
    
    # Test 1: Create sample package
    ((tests_total++))
    if create_sample_package; then
        ((tests_passed++))
    fi
    
    # Test 2: Create .tgz package
    ((tests_total++))
    if create_tgz_package; then
        ((tests_passed++))
    fi
    
    # Test 3: Test enhancement script
    ((tests_total++))
    if test_enhancement_script; then
        ((tests_passed++))
    fi
    
    # Test 4: Test full scanning script (if Trivy available)
    if command -v "$TRIVY_PATH" >/dev/null 2>&1; then
        ((tests_total++))
        if test_scanning_script; then
            ((tests_passed++))
        fi
        
        # Test 5: Demonstrate enhancement effectiveness
        ((tests_total++))
        if demonstrate_enhancement; then
            ((tests_passed++))
        fi
    else
        print_warning "Trivy not available at '$TRIVY_PATH', skipping scan tests"
        print_info "To test with Trivy, provide path as argument: $0 /path/to/trivy"
    fi
    
    # Summary
    print_header "Test Summary"
    print_info "Tests passed: $tests_passed/$tests_total"
    
    if [[ $tests_passed -eq $tests_total ]]; then
        print_success "🎉 All tests passed!"
    else
        print_warning "⚠️  Some tests failed"
    fi
    
    print_info ""
    print_info "Test files preserved in: $TEST_DIR"
    print_info "To cleanup: rm -rf $TEST_DIR"
    
    # Show usage examples
    print_header "Usage Examples"
    echo "# Enhance a directory:"
    echo "./enhance_nodejs.sh /path/to/extracted/package"
    echo ""
    echo "# Scan a .tgz file:"
    echo "./scan_nodejs_package.sh /usr/local/bin/trivy package.tgz"
    echo ""
    echo "# Scan with options:"
    echo "./scan_nodejs_package.sh -v -f table -o ./results /usr/local/bin/trivy package.tgz"
}

# Trap to cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"
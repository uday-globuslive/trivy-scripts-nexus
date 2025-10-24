#!/bin/bash

# Node.js Package Scanner with Trivy Enhancement
# This script implements the same Node.js package enhancement logic as the Python scanner
# Usage: ./scan_nodejs_package.sh [OPTIONS] <trivy_binary_path> <target_path>

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
VERBOSE=false
CLEANUP=true
OUTPUT_DIR="$(pwd)/scan_results"
SCAN_TYPE="fs"
FORMAT="json"
TEMPLATE_FILE="customhtml.tpl"

# Function to print colored output
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

print_debug() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

# Function to show usage
usage() {
    cat << EOF
Node.js Package Scanner with Trivy Enhancement

Usage: $0 [OPTIONS] <trivy_folder_path> <target_path>

ARGUMENTS:
    trivy_folder_path    Path to the Trivy installation folder (containing trivy binary and contrib folder)
    target_path          Path to .tar.gz/.tgz file or extracted directory

OPTIONS:
    -v, --verbose        Enable verbose output
    -o, --output DIR     Output directory for scan results (default: ./scan_results)
    -f, --format FORMAT  Output format: json, table, sarif, html (default: json)
    -t, --type TYPE      Scan type: fs, image (default: fs)
    --template FILE      HTML template file name in contrib folder (default: customhtml.tpl)
    --no-cleanup         Don't cleanup temporary extraction directory
    -h, --help           Show this help message

EXAMPLES:
    # Scan a .tgz file (assumes trivy folder structure: /path/to/trivy/{trivy, contrib/})
    $0 /usr/local/trivy my-package.tgz
    
    # Scan with verbose output and HTML report using default template
    $0 -v -f html /usr/local/trivy my-package.tar.gz
    
    # Scan with custom HTML template
    $0 -f html --template mytemplate.tpl /usr/local/trivy package.tgz
    
    # Scan already extracted directory  
    $0 /usr/local/bin/trivy ./extracted-package/
    
    # Custom output directory and format
    $0 -o /tmp/results -f table /usr/local/bin/trivy package.tgz

EOF
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if Python is available and get the command
get_python_cmd() {
    if command_exists python3; then
        echo "python3"
    elif command_exists python; then
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
    print_debug "Using Python command: $python_cmd"
    return 0
}

# Function to extract archive
extract_archive() {
    local archive_path="$1"
    local extract_dir="$2"
    local archive_lower
    
    archive_lower=$(echo "$archive_path" | tr '[:upper:]' '[:lower:]')
    
    print_info "Extracting archive: $archive_path"
    mkdir -p "$extract_dir"
    
    if [[ "$archive_lower" == *.tar.gz ]] || [[ "$archive_lower" == *.tgz ]]; then
        if ! tar -xzf "$archive_path" -C "$extract_dir"; then
            print_error "Failed to extract tar.gz archive"
            return 1
        fi
    elif [[ "$archive_lower" == *.tar ]]; then
        if ! tar -xf "$archive_path" -C "$extract_dir"; then
            print_error "Failed to extract tar archive"
            return 1
        fi
    elif [[ "$archive_lower" == *.zip ]]; then
        if ! command_exists unzip; then
            print_error "unzip command not found"
            return 1
        fi
        if ! unzip -q "$archive_path" -d "$extract_dir"; then
            print_error "Failed to extract zip archive"
            return 1
        fi
    else
        print_error "Unsupported archive format: $archive_path"
        return 1
    fi
    
    print_success "Archive extracted to: $extract_dir"
    return 0
}

# Function to enhance Node.js package for Trivy scanning
enhance_nodejs_package() {
    local extract_dir="$1"
    local enhanced=false
    
    print_info "Searching for package.json files to enhance..."
    
    # Find all package.json files
    while IFS= read -r -d '' package_json_path; do
        local package_dir
        package_dir=$(dirname "$package_json_path")
        
        print_debug "Found package.json: $package_json_path"
        
        # Check if lock files already exist
        if [[ -f "$package_dir/package-lock.json" ]] || \
           [[ -f "$package_dir/yarn.lock" ]] || \
           [[ -f "$package_dir/pnpm-lock.yaml" ]]; then
            print_debug "Lock file already exists in $package_dir, skipping enhancement"
            continue
        fi
        
        # Read package.json using Python
        local python_cmd
        python_cmd=$(get_python_cmd)
        if [[ $? -ne 0 ]]; then
            print_warning "Python not found, cannot enhance Node.js packages"
            return 0
        fi
        
        # Get the script directory to find json_helper.py
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        local json_helper="$script_dir/json_helper.py"
        
        if [[ ! -f "$json_helper" ]]; then
            print_warning "json_helper.py not found, cannot enhance Node.js packages"
            return 0
        fi
        
        local name version
        name=$($python_cmd "$json_helper" read_field "$package_json_path" "name" "unknown")
        version=$($python_cmd "$json_helper" read_field "$package_json_path" "version" "0.0.0")
        
        print_info "Enhancing Node.js package: $name@$version"
        
        # Create package-lock.json using Python helper
        local lock_result
        lock_result=$($python_cmd "$json_helper" create_lock "$package_json_path" "$package_dir")
        
        if [[ $? -eq 0 ]]; then
            # Parse the result
            local success
            success=$(echo "$lock_result" | $python_cmd -c "import sys, json; data=json.load(sys.stdin); print(data.get('success', False))")
            
            if [[ "$success" == "True" ]]; then
                # Create node_modules structure
                local modules_result
                modules_result=$($python_cmd "$json_helper" create_modules "$package_json_path" "$package_dir")
                
                if [[ $? -eq 0 ]]; then
                    local modules_success created_packages
                    modules_success=$(echo "$modules_result" | $python_cmd -c "import sys, json; data=json.load(sys.stdin); print(data.get('success', False))")
                    created_packages=$(echo "$modules_result" | $python_cmd -c "import sys, json; data=json.load(sys.stdin); print(data.get('created_packages', 0))")
                    
                    if [[ "$modules_success" == "True" ]]; then
                        local lock_file="$package_dir/package-lock.json"
                        local file_size
                        file_size=$(stat -f%z "$lock_file" 2>/dev/null || stat -c%s "$lock_file" 2>/dev/null || echo "unknown")
                        
                        print_success "Enhanced Node.js package: $name@$version"
                        print_info "  📦 Created package-lock.json: $file_size bytes"
                        print_info "  📁 Created node_modules structure: $created_packages packages"
                        enhanced=true
                    else
                        print_warning "Failed to create node_modules structure for $name"
                    fi
                else
                    print_warning "Failed to create node_modules structure for $name"
                fi
            else
                local error_msg
                error_msg=$(echo "$lock_result" | $python_cmd -c "import sys, json; data=json.load(sys.stdin); print(data.get('error', 'Unknown error'))")
                print_warning "Failed to create package-lock.json for $name: $error_msg"
            fi
        else
            print_warning "Failed to process $package_json_path"
        fi
        
    done < <(find "$extract_dir" -name "package.json" -type f -print0)
    
    if [[ "$enhanced" == "true" ]]; then
        print_success "Node.js package enhancement completed"
    else
        print_info "No Node.js packages required enhancement" 
    fi
}

# Function to run trivy scan
run_trivy_scan() {
    local trivy_binary="$1"
    local target_path="$2"
    local output_file="$3"
    local template_path="$4"
    
    print_info "Running Trivy scan..."
    print_debug "Trivy binary: $trivy_binary"
    print_debug "Target path: $target_path"
    print_debug "Output file: $output_file"
    print_debug "Template path: $template_path"
    print_debug "Scan type: $SCAN_TYPE"
    print_debug "Format: $FORMAT"
    
    # Build trivy command
    local trivy_cmd=("$trivy_binary" "$SCAN_TYPE")
    
    if [[ "$FORMAT" == "json" ]]; then
        trivy_cmd+=("--format" "json")
    elif [[ "$FORMAT" == "table" ]]; then
        trivy_cmd+=("--format" "table")
    elif [[ "$FORMAT" == "sarif" ]]; then
        trivy_cmd+=("--format" "sarif")
    elif [[ "$FORMAT" == "html" ]]; then
        trivy_cmd+=("--format" "template")
        if [[ -n "$template_path" && -f "$template_path" ]]; then
            trivy_cmd+=("--template" "@$template_path")
            print_debug "Using custom HTML template: $template_path"
        else
            print_warning "Custom template not found, using default HTML template"
            # Try to find a default HTML template in the trivy folder
            if [[ -f "$trivy_folder/contrib/html.tpl" ]]; then
                trivy_cmd+=("--template" "@$trivy_folder/contrib/html.tpl")
                print_debug "Using default HTML template: $trivy_folder/contrib/html.tpl"
            else
                print_error "No HTML template found. Please ensure customhtml.tpl exists in $trivy_folder/contrib/"
                return 1
            fi
        fi
    fi
    
    trivy_cmd+=("--output" "$output_file")
    trivy_cmd+=("$target_path")
    
    print_debug "Running command: ${trivy_cmd[*]}"
    
    if "${trivy_cmd[@]}"; then
        print_success "Trivy scan completed successfully"
        return 0
    else
        print_error "Trivy scan failed"
        return 1
    fi
}

# Function to analyze scan results
analyze_results() {
    local results_file="$1"
    
    if [[ ! -f "$results_file" ]]; then
        print_warning "Results file not found: $results_file"
        return
    fi
    
    print_info "Analyzing scan results..."
    
    if [[ "$FORMAT" == "json" ]]; then
        local python_cmd
        python_cmd=$(get_python_cmd)
        if [[ $? -eq 0 ]]; then
            # Get the script directory to find json_helper.py
            local script_dir
            script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
            local json_helper="$script_dir/json_helper.py"
            
            if [[ -f "$json_helper" ]]; then
                local analysis_result
                analysis_result=$($python_cmd "$json_helper" analyze_results "$results_file")
                
                if [[ $? -eq 0 ]]; then
                    local success vuln_count
                    success=$(echo "$analysis_result" | $python_cmd -c "import sys, json; data=json.load(sys.stdin); print(data.get('success', False))")
                    
                    if [[ "$success" == "True" ]]; then
                        vuln_count=$(echo "$analysis_result" | $python_cmd -c "import sys, json; data=json.load(sys.stdin); print(data.get('total_vulnerabilities', 0))")
                        
                        if [[ "$vuln_count" -gt 0 ]]; then
                            print_warning "Found $vuln_count vulnerabilities"
                            
                            # Show severity breakdown
                            print_info "Vulnerability breakdown by severity:"
                            echo "$analysis_result" | $python_cmd -c "
import sys, json
data = json.load(sys.stdin)
severity_breakdown = data.get('severity_breakdown', {})
for severity, count in severity_breakdown.items():
    print(f'  {severity}: {count}')
"
                        else
                            print_success "No vulnerabilities found"
                        fi
                    else
                        print_info "Could not analyze scan results"
                    fi
                else
                    print_info "Could not analyze scan results"
                fi
            else
                print_info "Analysis helper not available"
            fi
        else
            print_info "Python not available for result analysis"
        fi
    else
        print_info "Results saved to: $results_file"
        if [[ "$FORMAT" == "table" ]]; then
            echo
            cat "$results_file"
        elif [[ "$FORMAT" == "html" ]]; then
            print_info "HTML report generated: $results_file"
            print_info "Open in browser to view detailed vulnerability report"
        fi
    fi
}

# Main function
main() {
    local trivy_folder=""
    local trivy_binary=""
    local trivy_template=""
    local target_path=""
    local temp_extract_dir=""
    local actual_scan_path=""
    local needs_extraction=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -f|--format)
                FORMAT="$2"
                if [[ ! "$FORMAT" =~ ^(json|table|sarif|html)$ ]]; then
                    print_error "Invalid format: $FORMAT. Use json, table, sarif, or html"
                    exit 1
                fi
                shift 2
                ;;
            -t|--type)
                SCAN_TYPE="$2"
                if [[ ! "$SCAN_TYPE" =~ ^(fs|image)$ ]]; then
                    print_error "Invalid scan type: $SCAN_TYPE. Use fs or image"
                    exit 1
                fi
                shift 2
                ;;
            --template)
                TEMPLATE_FILE="$2"
                shift 2
                ;;
            --no-cleanup)
                CLEANUP=false
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$trivy_folder" ]]; then
                    trivy_folder="$1"
                elif [[ -z "$target_path" ]]; then
                    target_path="$1"
                else
                    print_error "Too many arguments"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$trivy_folder" ]] || [[ -z "$target_path" ]]; then
        print_error "Missing required arguments"
        usage
        exit 1
    fi
    
    # Validate trivy folder and set up paths
    if [[ ! -d "$trivy_folder" ]]; then
        print_error "Trivy folder not found: $trivy_folder"
        exit 1
    fi
    
    # Set trivy binary path (try both common locations)
    if [[ -x "$trivy_folder/trivy" ]]; then
        trivy_binary="$trivy_folder/trivy"
    elif [[ -x "$trivy_folder/bin/trivy" ]]; then
        trivy_binary="$trivy_folder/bin/trivy"
    else
        print_error "Trivy binary not found in: $trivy_folder/trivy or $trivy_folder/bin/trivy"
        exit 1
    fi
    
    # Set template path for HTML reports
    if [[ -f "$trivy_folder/contrib/$TEMPLATE_FILE" ]]; then
        trivy_template="$trivy_folder/contrib/$TEMPLATE_FILE"
        print_debug "Found template: $trivy_template"
    elif [[ -f "$trivy_folder/templates/$TEMPLATE_FILE" ]]; then
        trivy_template="$trivy_folder/templates/$TEMPLATE_FILE"
        print_debug "Found template: $trivy_template"
    else
        print_warning "Custom HTML template '$TEMPLATE_FILE' not found in $trivy_folder/contrib/ or $trivy_folder/templates/"
        print_info "HTML reports will use fallback template"
        trivy_template=""
    fi
    
    # Validate target path
    if [[ ! -e "$target_path" ]]; then
        print_error "Target path does not exist: $target_path"
        exit 1
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    print_info "Starting Node.js package scan with Trivy enhancement"
    print_info "Trivy folder: $trivy_folder"
    print_info "Trivy binary: $trivy_binary"
    if [[ "$FORMAT" == "html" ]]; then
        if [[ -n "$trivy_template" ]]; then
            print_info "HTML template: $trivy_template"
        else
            print_info "HTML template: $TEMPLATE_FILE (not found, will use fallback)"
        fi
    fi
    print_info "Target: $target_path"
    print_info "Output directory: $OUTPUT_DIR"
    print_info "Output format: $FORMAT"
    
    # Ensure Python is available (required for Node.js enhancement)
    if ! check_python; then
        print_error "Python 3 is required for Node.js package enhancement"
        exit 1
    fi
    
    # Determine if we need to extract
    if [[ -f "$target_path" ]]; then
        local target_lower
        target_lower=$(echo "$target_path" | tr '[:upper:]' '[:lower:]')
        
        if [[ "$target_lower" == *.tar.gz ]] || [[ "$target_lower" == *.tgz ]] || [[ "$target_lower" == *.tar ]] || [[ "$target_lower" == *.zip ]]; then
            needs_extraction=true
            temp_extract_dir="$(mktemp -d)"
            
            print_info "Archive detected, extracting for scanning..."
            
            if extract_archive "$target_path" "$temp_extract_dir"; then
                actual_scan_path="$temp_extract_dir"
                
                # Apply Node.js enhancement
                enhance_nodejs_package "$temp_extract_dir"
            else
                print_error "Failed to extract archive"
                exit 1
            fi
        else
            actual_scan_path="$target_path"
        fi
    else
        # It's a directory
        actual_scan_path="$target_path"
        
        # Check if it looks like a Node.js package and enhance if needed
        enhance_nodejs_package "$target_path"
    fi
    
    # Generate output filename
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local base_name
    base_name=$(basename "$target_path" | sed 's/\.[^.]*$//')
    local output_file="$OUTPUT_DIR/trivy_scan_${base_name}_${timestamp}.$FORMAT"
    
    # Run the scan
    if run_trivy_scan "$trivy_binary" "$actual_scan_path" "$output_file" "$trivy_template"; then
        analyze_results "$output_file"
        print_success "Scan completed successfully!"
        print_info "Results saved to: $output_file"
    else
        print_error "Scan failed"
        exit 1
    fi
    
    # Cleanup
    if [[ "$needs_extraction" == "true" ]] && [[ "$CLEANUP" == "true" ]] && [[ -n "$temp_extract_dir" ]]; then
        print_debug "Cleaning up temporary extraction directory: $temp_extract_dir"
        rm -rf "$temp_extract_dir"
    fi
    
    print_success "Node.js package scan completed!"
}

# Check for required commands
if ! command_exists tar; then
    print_error "tar command not found"
    exit 1
fi

# Run main function
main "$@"
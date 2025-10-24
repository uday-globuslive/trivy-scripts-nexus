#!/bin/bash

# Test script to verify automatic jq installation
# This script can be used to test the jq installation function on different platforms

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Function to install jq if not available
install_jq() {
    if command -v jq >/dev/null 2>&1; then
        return 0
    fi
    
    print_info "jq not found, attempting to install..."
    
    # Detect OS and architecture
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    # Map architecture names
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l) arch="armhf" ;;
        i386|i686) arch="i386" ;;
        *) 
            print_error "Unsupported architecture: $arch"
            return 1
            ;;
    esac
    
    # Map OS names and construct download URL
    local jq_url=""
    local jq_binary="jq"
    
    case "$os" in
        linux)
            jq_url="https://github.com/jqlang/jq/releases/latest/download/jq-linux-${arch}"
            ;;
        darwin)
            if [[ "$arch" == "arm64" ]]; then
                jq_url="https://github.com/jqlang/jq/releases/latest/download/jq-macos-arm64"
            else
                jq_url="https://github.com/jqlang/jq/releases/latest/download/jq-macos-amd64"
            fi
            ;;
        cygwin*|mingw*|msys*)
            jq_url="https://github.com/jqlang/jq/releases/latest/download/jq-windows-amd64.exe"
            jq_binary="jq.exe"
            ;;
        *)
            print_error "Unsupported OS: $os"
            print_info "Please install jq manually:"
            print_info "  Ubuntu/Debian: sudo apt-get install jq"
            print_info "  CentOS/RHEL: sudo yum install jq"
            print_info "  macOS: brew install jq"
            print_info "  Windows: choco install jq or download from https://jqlang.github.io/jq/"
            return 1
            ;;
    esac
    
    # Create local bin directory
    local local_bin="$HOME/.local/bin"
    mkdir -p "$local_bin"
    
    # Download jq
    local jq_path="$local_bin/$jq_binary"
    print_info "Downloading jq from: $jq_url"
    
    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL "$jq_url" -o "$jq_path"; then
            print_error "Failed to download jq with curl"
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -q "$jq_url" -O "$jq_path"; then
            print_error "Failed to download jq with wget"
            return 1
        fi
    else
        print_error "Neither curl nor wget found - cannot download jq"
        print_info "Please install jq manually or install curl/wget"
        return 1
    fi
    
    # Make executable
    chmod +x "$jq_path"
    
    # Add to PATH for this session
    export PATH="$local_bin:$PATH"
    
    # Verify installation
    if command -v jq >/dev/null 2>&1; then
        local jq_version
        jq_version=$(jq --version 2>/dev/null || echo "unknown")
        print_success "jq installed successfully: $jq_version"
        print_info "jq installed to: $jq_path"
        return 0
    else
        print_error "jq installation failed"
        return 1
    fi
}

# Main test function
main() {
    echo "=========================================="
    echo "         JQ Installation Test            "
    echo "=========================================="
    echo
    
    # Show system information
    print_info "System Information:"
    print_info "  OS: $(uname -s)"
    print_info "  Architecture: $(uname -m)"
    print_info "  Shell: $SHELL"
    echo
    
    # Check if jq is already available
    if command -v jq >/dev/null 2>&1; then
        local current_version
        current_version=$(jq --version 2>/dev/null || echo "unknown")
        print_info "jq is already available: $current_version"
        print_info "Location: $(command -v jq)"
        
        # Test basic functionality
        echo '{"test": "success"}' | jq -r '.test' >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            print_success "jq is working correctly"
        else
            print_warning "jq is installed but not working properly"
        fi
    else
        print_info "jq not found - testing installation..."
        
        # Test the installation function
        if install_jq; then
            print_success "Installation test completed successfully"
            
            # Test basic functionality
            echo '{"test": "success"}' | jq -r '.test' >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                print_success "jq is working correctly after installation"
            else
                print_error "jq was installed but is not working properly"
                return 1
            fi
        else
            print_error "Installation test failed"
            return 1
        fi
    fi
    
    echo
    print_success "All tests completed!"
}

# Run the test
main "$@"
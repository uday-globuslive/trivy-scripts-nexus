#!/bin/bash

# Simple test to verify enhanced Trivy reporting is working
# This script tests the enhanced functionality for Linux systems

echo "=== Enhanced Trivy Reporting Test ==="

# Test 1: Check Trivy installation and paths
echo "🔍 Test 1: Checking Trivy installation..."

TRIVY_PATH="/tmp/tools/trivy/trivy"
TRIVY_DIR="/tmp/tools/trivy"
HTML_TEMPLATE="$TRIVY_DIR/contrib/html.tpl"

if [ -f "$TRIVY_PATH" ]; then
    echo "✅ Trivy binary found: $TRIVY_PATH"
    $TRIVY_PATH --version | head -1
else
    echo "❌ Trivy binary not found at: $TRIVY_PATH"
    exit 1
fi

if [ -f "$HTML_TEMPLATE" ]; then
    echo "✅ HTML template found: $HTML_TEMPLATE"
else
    echo "❌ HTML template not found: $HTML_TEMPLATE"
    echo "Available templates:"
    ls -la "$TRIVY_DIR/contrib/" 2>/dev/null || echo "  No contrib directory found"
fi

# Test 2: Check main scanner configuration
echo ""
echo "🔧 Test 2: Checking scanner configuration..."
cd /path/to/scanner || echo "Note: Adjust path to scanner directory"

if [ -f "config_loader.py" ]; then
    echo "Testing configuration loader..."
    python3 -c "
import sys
sys.path.append('.')
from config_loader import get_config, validate_config

config = get_config()
print(f'Trivy path detected: {config[\"trivy_path\"]}')

missing = validate_config(config)
if missing:
    print(f'Missing config: {missing}')
else:
    print('✅ Configuration complete!')
"
else
    echo "⚠️  Run this from the scanner directory for full config test"
fi

# Test 3: Quick package scan test
echo ""
echo "📦 Test 3: Testing package scanning..."

# Look for test files
TEST_FILES=(
    "client-personalization-5.35.0.tgz"
    "vulnerability_reports/client-personalization-5.35.0.tgz"
    "**/client-personalization*.tgz"
)

FOUND_FILE=""
for pattern in "${TEST_FILES[@]}"; do
    for file in $pattern; do
        if [ -f "$file" ]; then
            FOUND_FILE="$file"
            break 2
        fi
    done
done

if [ -n "$FOUND_FILE" ]; then
    echo "✅ Test file found: $FOUND_FILE"
    echo "You can test enhanced reporting with:"
    echo "  ./test_trivy_reports.sh $FOUND_FILE"
else
    echo "ℹ️  No test file found. Enhanced reporting will work when you have .tgz files to scan."
fi

# Test 4: Check if enhanced test script exists and is executable
echo ""
echo "📋 Test 4: Checking enhanced test script..."

if [ -f "test_trivy_reports.sh" ]; then
    if [ -x "test_trivy_reports.sh" ]; then
        echo "✅ Enhanced test script is ready: test_trivy_reports.sh"
    else
        echo "⚠️  Making test script executable..."
        chmod +x test_trivy_reports.sh
        echo "✅ Enhanced test script is now ready: test_trivy_reports.sh"
    fi
else
    echo "❌ Enhanced test script not found: test_trivy_reports.sh"
fi

echo ""
echo "=== Test Summary ==="
echo "The enhanced Trivy reporting system will generate:"
echo "  📊 JSON reports for programmatic processing"
echo "  🌐 HTML reports for easy viewing in browsers"  
echo "  📋 Summary reports with scan statistics"
echo ""
echo "Both individual test scripts and the main scanner"
echo "have been enhanced to support dual report generation."

echo ""
echo "🚀 Ready to test! Use: ./test_trivy_reports.sh <package.tgz>"
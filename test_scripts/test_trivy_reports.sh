#!/bin/bash

# Enhanced Trivy Test Script with JSON and HTML Report Generation
# This script tests Node.js package scanning with comprehensive reporting

set -e

echo "=== Enhanced Trivy Node.js Package Test with Reports ==="

# Configuration
TRIVY_PATH="/tmp/tools/trivy/trivy"
TRIVY_DIR="/tmp/tools/trivy"

if [ ! -f "$TRIVY_PATH" ]; then
    echo "❌ Trivy not found at: $TRIVY_PATH"
    exit 1
fi

if [ ! -d "$TRIVY_DIR" ]; then
    echo "❌ Trivy directory not found at: $TRIVY_DIR"
    exit 1
fi

echo "✅ Using Trivy: $TRIVY_PATH"

# Check for test file
TEST_FILE="client-personalization-5.35.0.tgz"
if [ ! -f "$TEST_FILE" ]; then
    echo "❌ Test file not found: $TEST_FILE"
    echo "Please ensure the file is in the current directory"
    exit 1
fi

echo "✅ Testing file: $TEST_FILE"

# Create unique test directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TEST_DIR="trivy_reports_test_$TIMESTAMP"
mkdir -p "$TEST_DIR"

echo "📁 Test directory: $TEST_DIR"

# Extract package
echo "📦 Extracting package..."
tar -xzf "$TEST_FILE" -C "$TEST_DIR/"

# Find package.json
PACKAGE_DIR=$(find "$TEST_DIR" -name "package.json" -type f | head -1 | xargs dirname)
if [ -z "$PACKAGE_DIR" ]; then
    echo "❌ No package.json found in extracted files"
    exit 1
fi

echo "✅ Found package directory: $PACKAGE_DIR"

# Read original package.json for metadata
PACKAGE_NAME=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$PACKAGE_DIR/package.json" | cut -d'"' -f4)
PACKAGE_VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$PACKAGE_DIR/package.json" | cut -d'"' -f4)

echo "📋 Package: $PACKAGE_NAME@$PACKAGE_VERSION"

# Create comprehensive package-lock.json
echo "🔧 Creating enhanced package-lock.json..."
cd "$PACKAGE_DIR"

# Extract dependencies from package.json
DEPENDENCIES=$(grep -A 20 '"dependencies"' package.json | grep -o '"[^"]*"[[:space:]]*:[[:space:]]*"[^"]*"' | head -10)

cat > package-lock.json << EOF
{
  "name": "$PACKAGE_NAME",
  "version": "$PACKAGE_VERSION",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "$PACKAGE_NAME",
      "version": "$PACKAGE_VERSION",
      "license": "MIT"
EOF

# Add dependencies if they exist
if [ -n "$DEPENDENCIES" ]; then
    echo '      ,"dependencies": {' >> package-lock.json
    echo "$DEPENDENCIES" | sed 's/^\s*//;s/\s*$//;s/$/,/' | sed '$s/,$//' | sed 's/^/        /' >> package-lock.json
    echo '      }' >> package-lock.json
fi

cat >> package-lock.json << EOF
    }
  },
  "dependencies": {
EOF

# Add dependency details
if [ -n "$DEPENDENCIES" ]; then
    echo "$DEPENDENCIES" | while IFS= read -r dep; do
        if [ -n "$dep" ]; then
            DEP_NAME=$(echo "$dep" | cut -d'"' -f2)
            DEP_VERSION=$(echo "$dep" | cut -d'"' -f4)
            cat >> package-lock.json << EOF
    "$DEP_NAME": {
      "version": "$DEP_VERSION",
      "resolved": "https://registry.npmjs.org/$DEP_NAME/-/$DEP_NAME-$DEP_VERSION.tgz",
      "integrity": "sha512-placeholder"
    },
EOF
        fi
    done
    # Remove trailing comma
    sed -i '$s/,$//' package-lock.json 2>/dev/null || sed -i '' '$s/,$//' package-lock.json
fi

cat >> package-lock.json << EOF
  }
}
EOF

LOCK_SIZE=$(wc -c < package-lock.json)
echo "✅ Created enhanced lock file ($LOCK_SIZE bytes)"

# Set up report file names
TIMESTAMP_FULL=$(date +%Y%m%d_%H%M%S)
BASE_NAME="${PACKAGE_NAME//[^a-zA-Z0-9]/_}_${PACKAGE_VERSION//[^a-zA-Z0-9]/_}"
JSON_REPORT="../${BASE_NAME}_trivy_${TIMESTAMP_FULL}.json"
HTML_REPORT="../${BASE_NAME}_trivy_${TIMESTAMP_FULL}.html"

echo "📊 Report files:"
echo "   JSON: $JSON_REPORT"
echo "   HTML: $HTML_REPORT"

# Run JSON scan
echo "🔍 Running JSON vulnerability scan..."
$TRIVY_PATH fs --scanners vuln --format json --output "$JSON_REPORT" .

JSON_EXIT_CODE=$?
echo "JSON scan exit code: $JSON_EXIT_CODE"

# Run HTML scan
echo "🌐 Running HTML report scan..."
HTML_TEMPLATE="$TRIVY_DIR/contrib/html.tpl"

if [ -f "$HTML_TEMPLATE" ]; then
    echo "✅ Using HTML template: $HTML_TEMPLATE"
    $TRIVY_PATH fs --scanners vuln --format template --template "@$HTML_TEMPLATE" --output "$HTML_REPORT" .
    HTML_EXIT_CODE=$?
    echo "HTML scan exit code: $HTML_EXIT_CODE"
else
    echo "⚠️  HTML template not found at $HTML_TEMPLATE, using table format"
    $TRIVY_PATH fs --scanners vuln --format table --output "$HTML_REPORT" .
    HTML_EXIT_CODE=$?
    echo "Table scan exit code: $HTML_EXIT_CODE"
fi

# Check results
cd ..
echo ""
echo "📋 Scan Results Summary:"

if [ -f "$JSON_REPORT" ]; then
    JSON_SIZE=$(wc -c < "$JSON_REPORT")
    VULN_COUNT=$(grep -o '"VulnerabilityID"' "$JSON_REPORT" | wc -l 2>/dev/null || echo "0")
    echo "✅ JSON Report: $JSON_SIZE bytes, $VULN_COUNT vulnerabilities"
    
    # Check detection
    if grep -q '"Class": "lang-pkgs"' "$JSON_REPORT"; then
        echo "✅ Package detection: SUCCESS (language packages detected)"
    else
        echo "❌ Package detection: FAILED (no language packages found)"
    fi
else
    echo "❌ JSON Report: FAILED to generate"
fi

if [ -f "$HTML_REPORT" ]; then
    HTML_SIZE=$(wc -c < "$HTML_REPORT")
    echo "✅ HTML Report: $HTML_SIZE bytes"
    
    # Try to detect if it's actually HTML
    if head -5 "$HTML_REPORT" | grep -q "<html\|<!DOCTYPE"; then
        echo "✅ HTML Format: Valid HTML document"
    else
        echo "ℹ️  HTML Format: Plain text format (template may not be available)"
    fi
else
    echo "❌ HTML Report: FAILED to generate"
fi

# Create summary report
SUMMARY_FILE="scan_summary_${TIMESTAMP_FULL}.md"
cat > "$SUMMARY_FILE" << EOF
# Trivy Scan Summary Report

**Package:** $PACKAGE_NAME@$PACKAGE_VERSION  
**Scan Date:** $(date)  
**Test Directory:** $TEST_DIR

## Scan Results

### JSON Report
- **File:** \`$JSON_REPORT\`
- **Size:** $JSON_SIZE bytes
- **Vulnerabilities:** $VULN_COUNT
- **Exit Code:** $JSON_EXIT_CODE

### HTML Report  
- **File:** \`$HTML_REPORT\`
- **Size:** $HTML_SIZE bytes
- **Exit Code:** $HTML_EXIT_CODE

## Package Detection
$(if grep -q '"Class": "lang-pkgs"' "$JSON_REPORT" 2>/dev/null; then echo "✅ **SUCCESS** - Node.js package properly detected"; else echo "❌ **FAILED** - Package not detected as Node.js"; fi)

## Files Generated
- JSON Report: \`$JSON_REPORT\`
- HTML Report: \`$HTML_REPORT\`
- Summary: \`$SUMMARY_FILE\`
- Test Data: \`$TEST_DIR/\`

EOF

echo ""
echo "📄 Summary report created: $SUMMARY_FILE"

# List all generated files
echo ""
echo "📁 Generated Files:"
ls -la *.json *.html *.md 2>/dev/null | grep "${TIMESTAMP_FULL}\|${BASE_NAME}" || echo "No matching files found"

echo ""
echo "🏁 Enhanced test complete!"
echo "   Check the HTML report in a browser for detailed vulnerability information"
#!/bin/bash
# Quick test for Node.js package-lock.json format

echo "=== Quick Package-Lock.json Format Test ==="

# Create test directory
mkdir -p quick_test && cd quick_test

# Create a proper package.json
cat > package.json << 'EOF'
{
  "name": "@algolia/client-personalization",
  "version": "5.35.0",
  "dependencies": {
    "@algolia/client-common": "5.35.0",
    "@algolia/requester-browser-xhr": "5.35.0",
    "@algolia/requester-fetch": "5.35.0",
    "@algolia/requester-node-http": "5.35.0"
  }
}
EOF

# Create enhanced package-lock.json 
cat > package-lock.json << 'EOF'
{
  "name": "@algolia/client-personalization",
  "version": "5.35.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "@algolia/client-personalization",
      "version": "5.35.0",
      "license": "MIT",
      "dependencies": {
        "@algolia/client-common": "5.35.0",
        "@algolia/requester-browser-xhr": "5.35.0",
        "@algolia/requester-fetch": "5.35.0",
        "@algolia/requester-node-http": "5.35.0"
      }
    },
    "node_modules/@algolia/client-common": {
      "version": "5.35.0",
      "resolved": "https://registry.npmjs.org/@algolia/client-common/-/client-common-5.35.0.tgz",
      "integrity": "sha512-placeholder",
      "license": "MIT"
    },
    "node_modules/@algolia/requester-browser-xhr": {
      "version": "5.35.0",
      "resolved": "https://registry.npmjs.org/@algolia/requester-browser-xhr/-/requester-browser-xhr-5.35.0.tgz",
      "integrity": "sha512-placeholder",
      "license": "MIT"
    },
    "node_modules/@algolia/requester-fetch": {
      "version": "5.35.0",
      "resolved": "https://registry.npmjs.org/@algolia/requester-fetch/-/requester-fetch-5.35.0.tgz",
      "integrity": "sha512-placeholder",
      "license": "MIT"
    },
    "node_modules/@algolia/requester-node-http": {
      "version": "5.35.0",
      "resolved": "https://registry.npmjs.org/@algolia/requester-node-http/-/requester-node-http-5.35.0.tgz",
      "integrity": "sha512-placeholder",
      "license": "MIT"
    }
  },
  "dependencies": {
    "@algolia/client-common": {
      "version": "5.35.0",
      "resolved": "https://registry.npmjs.org/@algolia/client-common/-/client-common-5.35.0.tgz",
      "integrity": "sha512-placeholder",
      "requires": {}
    },
    "@algolia/requester-browser-xhr": {
      "version": "5.35.0",
      "resolved": "https://registry.npmjs.org/@algolia/requester-browser-xhr/-/requester-browser-xhr-5.35.0.tgz",
      "integrity": "sha512-placeholder",
      "requires": {}
    },
    "@algolia/requester-fetch": {
      "version": "5.35.0",
      "resolved": "https://registry.npmjs.org/@algolia/requester-fetch/-/requester-fetch-5.35.0.tgz",
      "integrity": "sha512-placeholder",
      "requires": {}
    },
    "@algolia/requester-node-http": {
      "version": "5.35.0",
      "resolved": "https://registry.npmjs.org/@algolia/requester-node-http/-/requester-node-http-5.35.0.tgz",
      "integrity": "sha512-placeholder",
      "requires": {}
    }
  }
}
EOF

echo "✅ Created enhanced lock file ($(wc -c < package-lock.json) bytes)"

# Test with trivy
echo "🧪 Testing Trivy detection..."
/tmp/trivy/trivy fs --scanners vuln --format json --output results.json . 2>&1 | tee trivy_output.log

echo "📊 Detection results:"
if grep -q "language-specific" trivy_output.log; then
    grep "language-specific" trivy_output.log
    if grep -q "num=[1-9]" trivy_output.log; then
        echo "✅ SUCCESS: Trivy detected Node.js package!"
    else
        echo "❌ FAILED: Still showing num=0"
    fi
else
    echo "❌ No language-specific detection output found"
fi

echo "📁 Results file:"
if [ -f results.json ]; then
    echo "  Size: $(wc -c < results.json) bytes"
    if command -v jq &> /dev/null; then
        PKG_COUNT=$(jq -r '.Results[]?.Packages // [] | length' results.json 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
        echo "  Packages detected: $PKG_COUNT"
        if [ "$PKG_COUNT" -gt 0 ]; then
            echo "  Sample packages:"
            jq -r '.Results[]?.Packages[]? | "    - \(.Name)@\(.Version)"' results.json | head -3
        fi
    fi
else
    echo "  ❌ No results file generated"
fi

# Cleanup  
cd .. && rm -rf quick_test

echo "🏁 Quick test complete"
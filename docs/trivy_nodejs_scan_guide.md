# Trivy Node.js Package Scanning Guide

## Problem: Trivy Not Detecting package.json

When Trivy shows "Number of language-specific files num=0", it means it's not recognizing the package.json for dependency scanning.

## Root Cause
Trivy requires one of these additional files alongside package.json for Node.js scanning:
- `package-lock.json` (npm lockfile)
- `yarn.lock` (Yarn lockfile) 
- `node_modules/` directory (installed dependencies)

## Solutions

### Solution 1: Force Package Scanning (Recommended)
```bash
# Scan the package.json directly by specifying it as the target
trivy fs --format json --output results.json extracted/package/package.json

# Or scan with specific package manager detection
trivy fs --scanners vuln --format json --output results.json extracted/package/
```

### Solution 2: Create Minimal Lock File
```bash
# Create a minimal package-lock.json to trigger detection
cd extracted/package
echo '{"name": "@algolia/client-personalization", "version": "5.35.0", "lockfileVersion": 1, "requires": true, "dependencies": {}}' > package-lock.json

# Now scan will detect it
trivy fs --format json --output results.json .
```

### Solution 3: Use Different Trivy Scanner Mode
```bash
# Use config scanner mode for package files
trivy config --format json --output results.json extracted/package/package.json

# Or use repository scanner if it's a git repo
trivy repo --format json --output results.json <git-url>
```

### Solution 4: Direct Package Analysis
```bash
# Scan with explicit package manager specification
trivy fs --format json --output results.json --pkg-types npm extracted/package/
```

## Expected Output After Fix
When working correctly, you should see:
```
INFO    Number of language-specific files       num=1
INFO    Detected package files    package.json
```

## Testing Commands
```bash
# Test 1: Check if package.json is detected
trivy fs --list-all-pkgs extracted/package/

# Test 2: Scan with verbose output
trivy fs --debug --format json extracted/package/ 2>&1 | grep -i "package\|npm\|node"

# Test 3: Force package manager detection
trivy fs --scanners vuln --format json extracted/package/
```

## Integration with Scanner
The scanner should handle this automatically by:
1. Extracting .tgz files to temporary directories
2. Checking for package.json 
3. Creating minimal lock file if missing
4. Running appropriate Trivy command based on package type
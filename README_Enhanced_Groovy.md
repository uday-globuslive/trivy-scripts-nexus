# Enhanced Trivy Scan Jenkins Module

## Overview

The enhanced `runTrivyScan.groovy` Jenkins module provides comprehensive vulnerability scanning with automatic Node.js package enhancement capabilities. This module is designed to be self-contained and doesn't require external Python files, making it perfect for use across different Jenkins pipelines.

## Key Features

### 🚀 **Enhanced Node.js Support**
- **Automatic Detection**: Scans workspace for `package.json` files
- **Smart Enhancement**: Creates `package-lock.json` and `node_modules` structure for better vulnerability detection
- **Lock File Awareness**: Skips enhancement if lock files already exist (yarn.lock, pnpm-lock.yaml, package-lock.json)

### 📊 **Comprehensive Reporting**
- **Multiple Formats**: HTML, JSON, CycloneDX SBOM, SPDX SBOM, Table
- **Custom Templates**: Support for custom HTML templates
- **Result Analysis**: Automatic vulnerability analysis with severity breakdown
- **Backward Compatibility**: Creates standard `trivy_report.json` and `trivy_report.html` files

### 🔧 **Configuration Options**
- **Proxy Support**: Configurable HTTPS proxy settings
- **Flexible Paths**: Customizable Trivy installation folder
- **Enhancement Control**: Enable/disable Node.js enhancement
- **Cleanup Options**: Automatic temporary file cleanup

## Usage

### Basic Usage
```groovy
@Library('your-jenkins-library') _

pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                script {
                    def scanResults = runTrivyScan()
                    echo "Scan completed. Generated files: ${scanResults}"
                }
            }
        }
    }
}
```

### Advanced Configuration
```groovy
@Library('your-jenkins-library') _

pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                script {
                    def scanResults = runTrivyScan([
                        trivyFolder: '/opt/trivy',
                        httpsProxy: 'proxy.company.com:8080',
                        enableNodejsEnhancement: true,
                        cleanupTempFiles: true,
                        outputFormats: [
                            'html': 'custom-security-report.html',
                            'json': 'custom-security-report.json',
                            'cyclonedx': 'custom-sbom.json',
                            'spdx': 'custom-spdx.txt',
                            'table': 'custom-table.txt'
                        ]
                    ])
                    
                    // Use the results
                    archiveArtifacts artifacts: "${scanResults.html}, ${scanResults.json}"
                }
            }
        }
    }
}
```

### Disable Node.js Enhancement
```groovy
def scanResults = runTrivyScan([
    enableNodejsEnhancement: false
])
```

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `trivyFolder` | String | `/tmp/tools/trivy` | Path to Trivy installation folder |
| `httpsProxy` | String | `proxy.mccamish.com:443` | HTTPS proxy for Trivy downloads |
| `enableNodejsEnhancement` | Boolean | `true` | Enable automatic Node.js package enhancement |
| `cleanupTempFiles` | Boolean | `true` | Clean up temporary Python scripts after execution |
| `outputFormats` | Map | See defaults | Custom output file names for each format |

## Node.js Enhancement Details

### What It Does
1. **Scans Workspace**: Finds all `package.json` files in the current directory and subdirectories
2. **Checks Lock Files**: Skips enhancement if existing lock files are found
3. **Creates package-lock.json**: Generates a lock file based on dependencies in `package.json` 
4. **Builds node_modules**: Creates minimal `node_modules` structure with dependency package.json files
5. **Enhances Scanning**: Allows Trivy to detect vulnerabilities in Node.js dependencies more effectively

### Enhancement Process
```
📁 Project Root
├── 📄 package.json (detected)
├── 📄 package-lock.json (created)
└── 📁 node_modules/ (created)
    ├── 📁 dependency1/
    │   └── 📄 package.json
    ├── 📁 dependency2/
    │   └── 📄 package.json
    └── ...
```

### Enhancement Output Example
```
🔍 [INFO] Searching for Node.js packages to enhance...
📦 [DEBUG] Found package.json: ./package.json
Enhancing Node.js package: my-app@1.0.0
✓ Created package-lock.json: 2847 bytes
✓ Created node_modules structure: 15 packages
✅ Enhanced Node.js package: my-app@1.0.0
   📦 Dependencies: 15
   📁 Node modules created: 15
✅ [SUCCESS] Node.js package enhancement completed
```

## Generated Files

The module generates the following files:

### Report Files
- `{jobName}_trivy-report.html` - HTML vulnerability report
- `{jobName}_trivy-report.json` - JSON vulnerability report
- `{jobName}_trivy-report_cyclonedx.json` - CycloneDX SBOM
- `{jobName}_trivy-report_spdx.txt` - SPDX SBOM
- `{jobName}_trivy-report_table.txt` - Table format report

### Backward Compatibility Files
- `trivy_report.json` - Copy of JSON report (for existing integrations)
- `trivy_report.html` - Copy of HTML report (for existing integrations)

## Result Analysis

The module automatically analyzes JSON results and provides:

```
📊 Vulnerability Analysis Results:
   Total vulnerabilities: 23
   Breakdown by severity:
     CRITICAL: 2
     HIGH: 5
     MEDIUM: 12
     LOW: 4
```

## Error Handling

### Node.js Enhancement Failures
- Enhancement failures don't stop the scan
- Warnings are logged but execution continues
- Fallback to standard Trivy scanning

### Missing Dependencies
- Automatic Python 3 detection
- Graceful fallback if Python is unavailable
- Clear error messages for missing tools

## Troubleshooting

### Common Issues

1. **Python 3 Not Found**
   ```
   ⚠️ [WARNING] Node.js enhancement failed but continuing with scan: python3: command not found
   ```
   **Solution**: Ensure Python 3 is installed on Jenkins agents

2. **Trivy Binary Not Found**
   ```
   ❌ [ERROR] Trivy executable not found at /tmp/tools/trivy/trivy.
   ```
   **Solution**: Verify `trivyFolder` parameter points to correct Trivy installation

3. **Template Not Found**
   ```
   template file not found
   ```
   **Solution**: Ensure custom HTML template exists in `{trivyFolder}/contrib/customhtml.tpl`

### Debug Mode
Enable verbose logging by adding debug statements:
```groovy
def scanResults = runTrivyScan([
    // ... other config
])
// Check generated files
sh 'ls -la *.html *.json'
```

## Migration from Original Module

The enhanced module is **100% backward compatible**. Existing pipelines will continue to work without changes, but will gain the following benefits:

- ✅ Automatic Node.js enhancement (can be disabled)
- ✅ Enhanced vulnerability detection for Node.js projects
- ✅ Result analysis and summary
- ✅ Improved error handling and logging

### Migration Checklist
- [ ] Replace `runTrivyScan.groovy` with enhanced version
- [ ] Ensure Python 3 is available on Jenkins agents
- [ ] Test with existing Node.js projects
- [ ] Verify generated reports include Node.js vulnerabilities
- [ ] Update pipeline documentation if needed

## Best Practices

1. **Archive Reports**: Always archive the generated reports as artifacts
2. **Version Control**: Store Trivy templates in version control
3. **Agent Requirements**: Ensure Jenkins agents have Python 3 and required tools
4. **Proxy Configuration**: Configure proxy settings for corporate environments
5. **Resource Management**: Enable cleanup to avoid disk space issues

## Examples

### Multi-Project Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Scan Multiple Projects') {
            parallel {
                stage('Frontend') {
                    steps {
                        dir('frontend') {
                            script {
                                runTrivyScan([
                                    outputFormats: [
                                        'html': 'frontend-security.html',
                                        'json': 'frontend-security.json'
                                    ]
                                ])
                            }
                        }
                    }
                }
                stage('Backend') {
                    steps {
                        dir('backend') {
                            script {
                                runTrivyScan([
                                    outputFormats: [
                                        'html': 'backend-security.html', 
                                        'json': 'backend-security.json'
                                    ]
                                ])
                            }
                        }
                    }
                }
            }
        }
    }
}
```

### Conditional Enhancement
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Check if it's a Node.js project
                    def isNodeProject = fileExists('package.json')
                    
                    runTrivyScan([
                        enableNodejsEnhancement: isNodeProject
                    ])
                }
            }
        }
    }
}
```

This enhanced module provides a powerful, flexible, and self-contained solution for comprehensive security scanning with special support for Node.js projects.
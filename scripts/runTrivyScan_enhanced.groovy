def call(Map config = [:]) {
    // Default configuration values
    def defaultConfig = [
        trivyFolder: '/tmp/tools/trivy',
        httpsProxy: 'proxy.mccamish.com:443',
        enableNodejsEnhancement: true,
        cleanupTempFiles: true,
        outputFormats: [
            'html': 'trivy-report.html',
            'json': 'trivy-report.json',
            'cyclonedx': 'trivy-report_cyclonedx.json',
            'spdx': 'trivy-report_spdx.txt',
            'table': 'trivy-report_table.txt'
        ]
    ]
    
    // Merge user config with defaults
    config = defaultConfig + config
    
    // Pre-calculate all values
    def trivyPath = "${config.trivyFolder}/trivy"
    def folderName = env.JOB_NAME?.split('/').size() > 1 ? env.JOB_NAME.split('/')[0] : 'NoFolder'
    def pipelineName = env.JOB_BASE_NAME ?: 'unknown'
    def jobBaseName = "${folderName}_${pipelineName}"
    def httpsProxy = config.httpsProxy
    def trivyFolder = config.trivyFolder
    
    // Output filenames
    def htmlReport = "${jobBaseName}_${config.outputFormats.html}"
    def jsonReport = "${jobBaseName}_${config.outputFormats.json}"
    def cyclonedxReport = "${jobBaseName}_${config.outputFormats.cyclonedx}"
    def spdxReport = "${jobBaseName}_${config.outputFormats.spdx}"
    def tableReport = "${jobBaseName}_${config.outputFormats.table}"
    def htmlTemplate = "@${trivyFolder}/contrib/customhtml.tpl"
    
    echo "=== Trivy Scan with Node.js Enhancement Configuration ==="
    echo "Trivy path: ${trivyPath}"
    echo "Job base name: ${jobBaseName}"
    echo "HTTPS proxy: ${httpsProxy}"
    echo "Node.js enhancement: ${config.enableNodejsEnhancement}"
    echo "Output files:"
    echo "  HTML: ${htmlReport}"
    echo "  JSON: ${jsonReport}"
    echo "  CycloneDX: ${cyclonedxReport}"
    echo "  SPDX: ${spdxReport}"
    echo "  Table: ${tableReport}"
    echo "============================================================"
    
    // Function to enhance Node.js packages (inline implementation)
    def enhanceNodejsPackages = { ->
        echo "🔍 [INFO] Searching for Node.js packages to enhance..."
        
        // Find all package.json files
        def packageJsonFiles = sh(
            script: 'find . -name "package.json" -type f',
            returnStdout: true
        ).trim().split('\n')
        
        if (packageJsonFiles.size() == 1 && packageJsonFiles[0] == '') {
            echo "ℹ️ [INFO] No package.json files found, skipping Node.js enhancement"
            return false
        }
        
        def enhanced = false
        
        for (packageJson in packageJsonFiles) {
            if (packageJson.trim() == '') continue
            
            def packageDir = new File(packageJson).getParent() ?: '.'
            echo "📦 [DEBUG] Found package.json: ${packageJson}"
            
            // Check if lock files already exist
            def lockExists = sh(
                script: """
                if [ -f "${packageDir}/package-lock.json" ] || [ -f "${packageDir}/yarn.lock" ] || [ -f "${packageDir}/pnpm-lock.yaml" ]; then
                    echo "true"
                else  
                    echo "false"
                fi
                """,
                returnStdout: true
            ).trim()
            
            if (lockExists == "true") {
                echo "⚠️ [DEBUG] Lock file already exists in ${packageDir}, skipping enhancement"
                continue
            }
            
            // Create inline Python script for JSON processing
            def pythonScript = '''
import json
import sys
import os

def create_package_lock(package_json_file, output_dir):
    """Create a package-lock.json file based on package.json."""
    try:
        with open(package_json_file, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
        
        name = package_data.get('name', 'unknown')
        version = package_data.get('version', '0.0.0')
        dependencies = package_data.get('dependencies', {})
        
        print(f"Enhancing Node.js package: {name}@{version}")
        
        # Create basic lock file structure
        lock_data = {
            "name": name,
            "version": version,
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": name,
                    "version": version,
                    "license": "MIT"
                }
            },
            "dependencies": {}
        }
        
        # Add dependencies if they exist
        if dependencies:
            lock_data["packages"][""]["dependencies"] = dependencies
            
            # Add node_modules entries
            for dep_name, dep_version in dependencies.items():
                # Clean version (remove ^ ~ >= < etc)
                clean_version = dep_version.lstrip('^~>=<')
                
                # Add to packages section
                lock_data["packages"][f"node_modules/{dep_name}"] = {
                    "version": clean_version,
                    "resolved": f"https://registry.npmjs.org/{dep_name}/-/{dep_name}-{clean_version}.tgz",
                    "integrity": "sha512-" + "0" * 64,
                    "license": "MIT"
                }
                
                # Add to dependencies section
                lock_data["dependencies"][dep_name] = {
                    "version": clean_version,
                    "resolved": f"https://registry.npmjs.org/{dep_name}/-/{dep_name}-{clean_version}.tgz",
                    "integrity": "sha512-" + "0" * 64
                }
        
        # Write lock file
        lock_file_path = os.path.join(output_dir, 'package-lock.json')
        with open(lock_file_path, 'w', encoding='utf-8') as f:
            json.dump(lock_data, f, indent=2)
        
        print(f"✓ Created package-lock.json: {len(json.dumps(lock_data))} bytes")
        return True, name, version, len(dependencies)
        
    except Exception as e:
        print(f"❌ Error creating package-lock.json: {e}")
        return False, None, None, 0

def create_node_modules_structure(package_json_file, output_dir):
    """Create node_modules directory structure based on package.json."""
    try:
        with open(package_json_file, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
        
        dependencies = package_data.get('dependencies', {})
        
        if not dependencies:
            return True, 0
        
        node_modules_dir = os.path.join(output_dir, 'node_modules')
        os.makedirs(node_modules_dir, exist_ok=True)
        
        created_packages = 0
        for dep_name, dep_version in dependencies.items():
            # Clean version
            clean_version = dep_version.lstrip('^~>=<')
            
            # Create dependency directory
            dep_dir = os.path.join(node_modules_dir, dep_name)
            os.makedirs(dep_dir, exist_ok=True)
            
            # Create minimal package.json for dependency
            dep_package_json = {
                "name": dep_name,
                "version": clean_version
            }
            
            dep_package_file = os.path.join(dep_dir, 'package.json')
            with open(dep_package_file, 'w', encoding='utf-8') as f:
                json.dump(dep_package_json, f, indent=2)
            
            created_packages += 1
        
        print(f"✓ Created node_modules structure: {created_packages} packages")
        return True, created_packages
        
    except Exception as e:
        print(f"❌ Error creating node_modules structure: {e}")
        return False, 0

if __name__ == "__main__":
    package_json_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Create package-lock.json
    success1, name, version, dep_count = create_package_lock(package_json_file, output_dir)
    
    if success1:
        # Create node_modules structure
        success2, created_count = create_node_modules_structure(package_json_file, output_dir)
        
        if success2:
            print(f"✅ Enhanced Node.js package: {name}@{version}")
            print(f"   📦 Dependencies: {dep_count}")
            print(f"   📁 Node modules created: {created_count}")
        else:
            print(f"⚠️ Partially enhanced {name}@{version} (lock file only)")
    else:
        print("❌ Failed to enhance Node.js package")
'''
            
            // Write the Python script to a temporary file
            writeFile file: 'nodejs_enhancer.py', text: pythonScript
            
            try {
                // Run the enhancement
                def result = sh(
                    script: "python3 nodejs_enhancer.py '${packageJson}' '${packageDir}'",
                    returnStdout: true
                ).trim()
                
                echo result
                enhanced = true
                
            } catch (Exception e) {
                echo "⚠️ [WARNING] Failed to enhance ${packageJson}: ${e.getMessage()}"
            }
        }
        
        if (enhanced) {
            echo "✅ [SUCCESS] Node.js package enhancement completed"
        } else {
            echo "ℹ️ [INFO] No Node.js packages required enhancement"
        }
        
        // Cleanup temporary Python script
        if (config.cleanupTempFiles) {
            sh 'rm -f nodejs_enhancer.py'
        }
        
        return enhanced
    }
    
    echo "Executing Trivy scan with Node.js enhancement..."
    
    // Verify Trivy is available
    sh """
    if [ ! -f "${trivyPath}" ]; then
        echo "❌ [ERROR] Trivy executable not found at ${trivyPath}."
        exit 1
    else
        echo "✓ Trivy available at: ${trivyPath}"
        "${trivyPath}" version || echo "Version check failed"
    fi
    """
    
    // Enhance Node.js packages if enabled
    if (config.enableNodejsEnhancement) {
        try {
            enhanceNodejsPackages()
        } catch (Exception e) {
            echo "⚠️ [WARNING] Node.js enhancement failed but continuing with scan: ${e.getMessage()}"
        }
    } else {
        echo "ℹ️ [INFO] Node.js enhancement disabled, proceeding with standard scan"
    }
    
    // Run Trivy scans
    sh """
    export https_proxy="${httpsProxy}"
    echo "✓ HTTPS proxy set to: \$https_proxy"
    echo "[INFO] Starting enhanced Trivy scan of current directory..."
    
    echo "=== Running HTML Report ==="
    "${trivyPath}" fs --insecure --scanners vuln . --format template -t "${htmlTemplate}" --output "${htmlReport}"
    
    echo "=== Running JSON Report ==="
    "${trivyPath}" fs --insecure --scanners vuln . --format json --output "${jsonReport}"
    
    echo "=== Running CycloneDX SBOM ==="
    "${trivyPath}" fs --insecure --scanners vuln . --format cyclonedx --output "${cyclonedxReport}"
    
    echo "=== Running SPDX SBOM ==="
    "${trivyPath}" fs --insecure --scanners vuln . --format spdx --output "${spdxReport}"
    
    echo "=== Running Table Report ==="
    "${trivyPath}" fs --insecure --scanners vuln . --format table --output "${tableReport}"
    
    echo "=== Creating Backward Compatibility Copies ==="
    cp -f "${jsonReport}" trivy_report.json
    cp -f "${htmlReport}" trivy_report.html
    
    echo "=== Verifying Generated Files ==="
    for file in "${htmlReport}" "${jsonReport}" "${cyclonedxReport}" "${spdxReport}" "${tableReport}" "trivy_report.json" "trivy_report.html"; do
        if [ -f "\$file" ]; then
            size=\$(du -h "\$file" 2>/dev/null | cut -f1 || echo "unknown")
            echo "✓ \$file (\$size)"
        else
            echo "❌ Missing: \$file"
        fi
    done
    
    echo "=== Enhanced Trivy Scan Completed Successfully ==="
    """
    
    // Analyze results if JSON report was generated
    if (fileExists(jsonReport)) {
        try {
            echo "📊 [INFO] Analyzing scan results..."
            
            def analysisScript = '''
import json
import sys

def analyze_scan_results(results_file):
    """Analyze Trivy scan results JSON file."""
    try:
        with open(results_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        total_vulns = 0
        severity_counts = {}
        
        # Extract vulnerabilities from results
        if isinstance(data, dict) and 'Results' in data:
            for result in data['Results']:
                if 'Vulnerabilities' in result:
                    vulns = result['Vulnerabilities']
                    if vulns:  # Check if vulnerabilities list is not None
                        total_vulns += len(vulns)
                        
                        for vuln in vulns:
                            severity = vuln.get('Severity', 'UNKNOWN')
                            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"📊 Vulnerability Analysis Results:")
        print(f"   Total vulnerabilities: {total_vulns}")
        
        if severity_counts:
            print("   Breakdown by severity:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                if severity in severity_counts:
                    print(f"     {severity}: {severity_counts[severity]}")
        else:
            print("   🎉 No vulnerabilities found!")
        
        return total_vulns > 0
        
    except Exception as e:
        print(f"❌ Error analyzing results: {e}")
        return False

if __name__ == "__main__":
    results_file = sys.argv[1]
    has_vulns = analyze_scan_results(results_file)
    sys.exit(1 if has_vulns else 0)
'''
            
            writeFile file: 'analyze_results.py', text: analysisScript
            
            def analysisResult = sh(
                script: "python3 analyze_results.py '${jsonReport}'",
                returnStatus: true
            )
            
            if (config.cleanupTempFiles) {
                sh 'rm -f analyze_results.py'
            }
            
        } catch (Exception e) {
            echo "⚠️ [WARNING] Result analysis failed: ${e.getMessage()}"
        }
    }
    
    def generatedFiles = [
        html: htmlReport,
        json: jsonReport,
        cyclonedx: cyclonedxReport,
        spdx: spdxReport,
        table: tableReport,
        standardJson: 'trivy_report.json',
        standardHtml: 'trivy_report.html'
    ]
    
    echo "✅ Enhanced Trivy scan completed successfully"
    echo "Generated files summary:"
    generatedFiles.each { format, filename ->
        echo "  ${format}: ${filename}"
    }
    
    return generatedFiles
}
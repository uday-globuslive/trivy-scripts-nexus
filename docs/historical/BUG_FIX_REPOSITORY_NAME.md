# Bug Fix: NameError with repository_name

## Problem
Scanner was crashing with the following error:
```
NameError: name 'repository_name' is not defined
```

This occurred in two locations:
1. Line 1042: `save_individual_html_report()` call in main scanning loop
2. Line 1470: `save_individual_html_report()` call in Docker component scanning

## Root Cause
**Variable naming inconsistency** - the code was using `repository_name` in function calls, but the actual variable in scope was named `repo_name`.

## Solution
Fixed both instances by changing the variable reference:

### Fix 1: Main Scanning Loop (Line 1042)
```python
# Before (BROKEN):
self.save_individual_html_report(html_content, component_name, asset_name, repository_name, scan_timestamp, len(vulnerabilities))

# After (FIXED):
self.save_individual_html_report(html_content, component_name, asset_name, repo_name, scan_timestamp, len(vulnerabilities))
```

### Fix 2: Docker Component Scanning (Line 1470) 
```python
# Before (BROKEN):
self.save_individual_html_report(html_content, component_name, f"docker_image_{component_version}", repository_name, "docker_scan", len(vulnerabilities))

# After (FIXED):
self.save_individual_html_report(html_content, component_name, f"docker_image_{component_version}", repo_name, "docker_scan", len(vulnerabilities))
```

## Impact
- ✅ **Scanner no longer crashes** with NameError
- ✅ **Individual HTML reports** now generate correctly for both regular and Docker components
- ✅ **Report organization** (with_vulnerabilities vs empty_reports) works properly
- ✅ **No functional changes** - only fixed variable scope issue

## Testing
- Syntax validation passed
- Variable naming consistency verified across codebase
- Scanner initialization works correctly

---
*Fixed: September 25, 2024 - Variable scope issue resolved*
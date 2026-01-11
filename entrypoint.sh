#!/bin/bash
# GitHub Action entrypoint script for AWS Quick Assess
set -e

# =============================================================================
# Environment Variable Mapping
# GitHub Actions passes inputs as INPUT_* environment variables
# =============================================================================

SCAN_PATH="${INPUT_SCAN_PATH:-.}"
CONFIG_PATH="${INPUT_CONFIG_PATH:-}"
OUTPUT_FORMATS="${INPUT_OUTPUT_FORMATS:-json,sarif}"
FAIL_ON_SEVERITY="${INPUT_FAIL_ON_SEVERITY:-HIGH}"
SNYK_TOKEN="${INPUT_SNYK_TOKEN:-}"
UPLOAD_SARIF="${INPUT_UPLOAD_SARIF:-true}"
VERBOSE="${INPUT_VERBOSE:-false}"

# GitHub-specific paths
GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
REPORT_DIR="${GITHUB_WORKSPACE}/.aws-quick-assess-reports"

# Create report directory with permission handling
# GitHub Actions workspace may have restrictive permissions
create_fallback_report_dir() {
    echo "::warning::Using /tmp for reports due to workspace permission issues"
    REPORT_DIR="/tmp/.aws-quick-assess-reports"
    mkdir -p "$REPORT_DIR"
    # Copy reports to workspace at the end if possible
    FALLBACK_REPORT_DIR="true"
}

if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
    echo "::warning::Cannot create report directory in workspace, attempting to fix permissions..."
    # Try to take ownership of workspace (works when running as root)
    if chown -R "$(id -u):$(id -g)" "$GITHUB_WORKSPACE" 2>/dev/null; then
        # chown succeeded, retry mkdir (but handle failure due to set -e)
        if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
            create_fallback_report_dir
        fi
    else
        create_fallback_report_dir
    fi
fi

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo "::group::$1"
}

log_end_group() {
    echo "::endgroup::"
}

log_error() {
    echo "::error::$1"
}

log_warning() {
    echo "::warning::$1"
}

set_output() {
    local name="$1"
    local value="$2"
    echo "${name}=${value}" >> "$GITHUB_OUTPUT"
}

add_step_summary() {
    echo "$1" >> "$GITHUB_STEP_SUMMARY"
}

# =============================================================================
# Main Execution
# =============================================================================

echo "=============================================="
echo "AWS Quick Assess - GitHub Action"
echo "=============================================="
echo ""

# Resolve full scan path
if [[ "$SCAN_PATH" == "." ]]; then
    FULL_SCAN_PATH="$GITHUB_WORKSPACE"
else
    FULL_SCAN_PATH="$GITHUB_WORKSPACE/$SCAN_PATH"
fi

echo "Scan Path: $FULL_SCAN_PATH"
echo "Output Formats: $OUTPUT_FORMATS"
echo "Fail On Severity: $FAIL_ON_SEVERITY"
echo "Report Directory: $REPORT_DIR"
echo ""

# Build CLI arguments
CLI_ARGS="scan-local --repo-path $FULL_SCAN_PATH --output-dir $REPORT_DIR"

# Add output formats
IFS=',' read -ra FORMATS <<< "$OUTPUT_FORMATS"
for fmt in "${FORMATS[@]}"; do
    fmt=$(echo "$fmt" | xargs)  # Trim whitespace
    CLI_ARGS="$CLI_ARGS --format $fmt"
done

# Add config path if specified
if [[ -n "$CONFIG_PATH" && -f "$GITHUB_WORKSPACE/$CONFIG_PATH" ]]; then
    CLI_ARGS="--config $GITHUB_WORKSPACE/$CONFIG_PATH $CLI_ARGS"
fi

# Add verbose flag
if [[ "$VERBOSE" == "true" ]]; then
    CLI_ARGS="--verbose $CLI_ARGS"
fi

# Add fail-on-severity flag
if [[ -n "$FAIL_ON_SEVERITY" ]]; then
    CLI_ARGS="$CLI_ARGS --fail-on-severity $FAIL_ON_SEVERITY"
fi

# Set Snyk token if provided
if [[ -n "$SNYK_TOKEN" ]]; then
    export SNYK_AUTH="$SNYK_TOKEN"
fi

# =============================================================================
# Run the scanner
# =============================================================================

log_info "Running Security Scan"

EXIT_CODE=0
python -m src.main $CLI_ARGS || EXIT_CODE=$?

log_end_group

# =============================================================================
# Parse results and set outputs
# =============================================================================

log_info "Processing Results"

# Find the JSON report
JSON_REPORT=$(find "$REPORT_DIR" -name "*.json" -type f | head -1)
SARIF_REPORT=$(find "$REPORT_DIR" -name "*.sarif" -type f | head -1)

if [[ -f "$JSON_REPORT" ]]; then
    echo "Found JSON report: $JSON_REPORT"

    # Extract counts using Python (more reliable than jq parsing)
    COUNTS=$(python3 -c "
import json
import sys

try:
    with open('$JSON_REPORT', 'r') as f:
        data = json.load(f)

    summary = data.get('summary', {})
    by_severity = summary.get('by_severity', {})

    print(f\"total={summary.get('total_findings', 0)}\")
    print(f\"critical={by_severity.get('CRITICAL', 0)}\")
    print(f\"high={by_severity.get('HIGH', 0)}\")
    print(f\"medium={by_severity.get('MEDIUM', 0)}\")
    print(f\"low={by_severity.get('LOW', 0)}\")
except Exception as e:
    print(f'total=0', file=sys.stderr)
    print(f'critical=0', file=sys.stderr)
    print(f'high=0', file=sys.stderr)
    print(f'medium=0', file=sys.stderr)
    print(f'low=0', file=sys.stderr)
    sys.exit(0)
")

    # Parse the counts
    TOTAL=$(echo "$COUNTS" | grep "^total=" | cut -d= -f2)
    CRITICAL=$(echo "$COUNTS" | grep "^critical=" | cut -d= -f2)
    HIGH=$(echo "$COUNTS" | grep "^high=" | cut -d= -f2)
    MEDIUM=$(echo "$COUNTS" | grep "^medium=" | cut -d= -f2)
    LOW=$(echo "$COUNTS" | grep "^low=" | cut -d= -f2)
else
    echo "No JSON report found"
    TOTAL=0
    CRITICAL=0
    HIGH=0
    MEDIUM=0
    LOW=0
fi

# Set outputs
set_output "findings-count" "$TOTAL"
set_output "critical-count" "$CRITICAL"
set_output "high-count" "$HIGH"
set_output "medium-count" "$MEDIUM"
set_output "low-count" "$LOW"
set_output "report-path" "$REPORT_DIR"

if [[ -f "$SARIF_REPORT" ]]; then
    set_output "sarif-path" "$SARIF_REPORT"
fi

# Determine scan status
if [[ $EXIT_CODE -eq 0 ]]; then
    set_output "scan-status" "passed"
elif [[ $EXIT_CODE -eq 2 ]]; then
    set_output "scan-status" "failed"
else
    set_output "scan-status" "error"
fi

log_end_group

# =============================================================================
# Generate Step Summary
# =============================================================================

log_info "Generating Summary"

add_step_summary "# AWS Quick Assess Security Scan Results"
add_step_summary ""
add_step_summary "## Summary"
add_step_summary ""
add_step_summary "| Severity | Count |"
add_step_summary "|----------|-------|"
add_step_summary "| Critical | $CRITICAL |"
add_step_summary "| High | $HIGH |"
add_step_summary "| Medium | $MEDIUM |"
add_step_summary "| Low | $LOW |"
add_step_summary "| **Total** | **$TOTAL** |"
add_step_summary ""

if [[ $EXIT_CODE -eq 0 ]]; then
    add_step_summary "> **Status:** :white_check_mark: Passed - No findings at or above $FAIL_ON_SEVERITY severity"
elif [[ $EXIT_CODE -eq 2 ]]; then
    add_step_summary "> **Status:** :x: Failed - Findings detected at or above $FAIL_ON_SEVERITY severity"
else
    add_step_summary "> **Status:** :warning: Error - Scan encountered an error"
fi

add_step_summary ""
add_step_summary "## Scan Configuration"
add_step_summary ""
add_step_summary "- **Scan Path:** \`$SCAN_PATH\`"
add_step_summary "- **Output Formats:** $OUTPUT_FORMATS"
add_step_summary "- **Fail Threshold:** $FAIL_ON_SEVERITY"
add_step_summary ""

# Add top findings to summary if there are any
if [[ -f "$JSON_REPORT" && "$TOTAL" -gt 0 ]]; then
    add_step_summary "## Top Findings"
    add_step_summary ""

    python3 -c "
import json

with open('$JSON_REPORT', 'r') as f:
    data = json.load(f)

findings = data.get('findings', [])

# Sort by severity
severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
findings.sort(key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))

# Show top 10
for i, finding in enumerate(findings[:10]):
    severity = finding.get('severity', 'UNKNOWN')
    title = finding.get('title', finding.get('rule_id', 'Unknown'))
    file_path = finding.get('file_path', 'N/A')
    line = finding.get('line_number', '')
    location = f'{file_path}:{line}' if line else file_path

    # Severity emoji
    emoji = {'CRITICAL': ':red_circle:', 'HIGH': ':orange_circle:', 'MEDIUM': ':yellow_circle:', 'LOW': ':white_circle:'}.get(severity, ':white_circle:')

    print(f'{i+1}. {emoji} **{severity}** - {title}')
    print(f'   - Location: \`{location}\`')
    print()
" >> "$GITHUB_STEP_SUMMARY"

    if [[ "$TOTAL" -gt 10 ]]; then
        add_step_summary "*... and $((TOTAL - 10)) more findings. See full report for details.*"
    fi
fi

add_step_summary ""
add_step_summary "---"
add_step_summary "*Generated by [AWS Quick Assess](https://github.com/crofton-cloud/aws-quick-assess)*"

log_end_group

# =============================================================================
# Exit with appropriate code
# =============================================================================

echo ""
echo "=============================================="
echo "Scan Complete"
echo "=============================================="
echo "Total Findings: $TOTAL"
echo "Exit Code: $EXIT_CODE"
echo ""

# If we used fallback report directory, try to copy reports to workspace
if [[ "${FALLBACK_REPORT_DIR:-}" == "true" ]]; then
    WORKSPACE_REPORT_DIR="${GITHUB_WORKSPACE}/.aws-quick-assess-reports"
    if mkdir -p "$WORKSPACE_REPORT_DIR" 2>/dev/null; then
        # Attempt to copy reports and verify success
        if cp -r "$REPORT_DIR"/* "$WORKSPACE_REPORT_DIR"/ 2>/dev/null; then
            # Verify files were actually copied
            COPIED_FILES=$(find "$WORKSPACE_REPORT_DIR" -type f 2>/dev/null | wc -l)
            if [[ "$COPIED_FILES" -gt 0 ]]; then
                echo "Reports copied to workspace: $WORKSPACE_REPORT_DIR ($COPIED_FILES files)"
                # Update output to point to workspace location
                set_output "report-path" "$WORKSPACE_REPORT_DIR"
                SARIF_IN_WORKSPACE=$(find "$WORKSPACE_REPORT_DIR" -name "*.sarif" -type f | head -1)
                if [[ -f "$SARIF_IN_WORKSPACE" ]]; then
                    set_output "sarif-path" "$SARIF_IN_WORKSPACE"
                fi
            else
                echo "::warning::Copy appeared to succeed but no files found in workspace, reports available at: $REPORT_DIR"
            fi
        else
            echo "::warning::Could not copy reports to workspace, reports available at: $REPORT_DIR"
        fi
    else
        echo "::warning::Could not create workspace report directory, reports available at: $REPORT_DIR"
    fi
fi

exit $EXIT_CODE

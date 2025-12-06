"""Markdown Report Formatter"""

from typing import Dict, Any
from pathlib import Path
from datetime import datetime


class MarkdownFormatter:
    """Formats scan results as Markdown"""

    def format(self, report_data: Dict[str, Any], output_path: str) -> str:
        """
        Format report as Markdown

        Args:
            report_data: Aggregated report data
            output_path: Path to write Markdown file

        Returns:
            Path to generated file
        """
        # Generate timestamp in yyyy-mm-dd-hh-mm format
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M")
        output_file = Path(output_path) / f"{timestamp}-scan-report.md"

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(self._generate_markdown(report_data))

        return str(output_file)

    def _generate_markdown(self, report_data: Dict[str, Any]) -> str:
        """Generate markdown content"""
        md = []

        # Header
        md.append("# AWS Quick Assess - Security Scan Report\n")
        md.append(f"**Repository:** {report_data.get('repository', 'N/A')}\n")
        # Add branch if available
        if report_data.get('branch'):
            md.append(f"**Branch:** {report_data.get('branch')}\n")
        md.append(f"**Scan Date:** {report_data.get('scan_timestamp', 'N/A')}\n")
        md.append("---\n")

        # Summary
        summary = report_data.get('summary', {})
        md.append("## Summary\n")
        md.append(f"- **Total Findings:** {summary.get('total_findings', 0)}")
        md.append(f"- **Files Scanned:** {summary.get('unique_files', 0)}")
        md.append(f"- **Scanners Run:** {', '.join(report_data.get('metadata', {}).get('scanners_run', []))}\n")

        # Severity Breakdown
        md.append("### Findings by Severity\n")
        by_severity = summary.get('by_severity', {})
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = by_severity.get(severity, 0)
            if count > 0:
                md.append(f"- **{severity}:** {count}")
        md.append("")

        # Tool Breakdown
        md.append("### Findings by Tool\n")
        by_tool = summary.get('by_tool', {})
        for tool, count in sorted(by_tool.items(), key=lambda x: x[1], reverse=True):
            md.append(f"- **{tool}:** {count}")
        md.append("\n---\n")

        # Findings Details
        md.append("## Findings Details\n")
        findings = report_data.get('findings', [])

        if not findings:
            md.append("No findings detected.\n")
        else:
            # Group by severity
            by_sev = {}
            for finding in findings:
                sev = finding.get('severity', 'INFO')
                if sev not in by_sev:
                    by_sev[sev] = []
                by_sev[sev].append(finding)

            # Output by severity
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in by_sev:
                    md.append(f"### {severity} Severity ({len(by_sev[severity])} findings)\n")
                    for i, finding in enumerate(by_sev[severity], 1):
                        md.append(f"#### {i}. {finding.get('title', 'Untitled')}")
                        md.append(f"- **Severity:** {finding.get('severity', 'UNKNOWN')}")
                        md.append(f"- **Tool:** {finding.get('tool', 'Unknown')}")
                        md.append(f"- **Rule:** {finding.get('rule_id', 'N/A')}")
                        if finding.get('file_path'):
                            location = f"{finding['file_path']}"
                            if finding.get('line_number'):
                                location += f":{finding['line_number']}"
                            md.append(f"- **Location:** `{location}`")
                        if finding.get('resource'):
                            md.append(f"- **Resource:** {finding['resource']}")
                        if finding.get('description'):
                            md.append(f"- **Description:** {finding['description']}")
                        if finding.get('remediation'):
                            md.append(f"- **Remediation:** {finding['remediation']}")
                        md.append("")

        return "\n".join(md)

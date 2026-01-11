"""HTML Report Formatter"""

from typing import Dict, Any
from pathlib import Path
from html import escape
from datetime import datetime


class HTMLFormatter:
    """Formats scan results as HTML"""

    def format(self, report_data: Dict[str, Any], output_path: str) -> str:
        """
        Format report as HTML

        Args:
            report_data: Aggregated report data
            output_path: Path to write HTML file

        Returns:
            Path to generated file
        """
        # Generate timestamp in yyyy-mm-dd-hh-mm format
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M")
        output_file = Path(output_path) / f"{timestamp}-scan-report.html"

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(self._generate_html(report_data))

        return str(output_file)

    def _generate_html(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML content"""
        summary = report_data.get("summary", {})
        findings = report_data.get("findings", [])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SDLC Code Scanner - Scan Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 8px;
        }}
        .severity-CRITICAL {{ background: #dc3545; color: white; }}
        .severity-HIGH {{ background: #fd7e14; color: white; }}
        .severity-MEDIUM {{ background: #ffc107; color: #333; }}
        .severity-LOW {{ background: #17a2b8; color: white; }}
        .severity-INFO {{ background: #6c757d; color: white; }}
        .finding {{
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #ddd;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding-title {{
            font-size: 18px;
            font-weight: bold;
            margin: 0 0 10px 0;
        }}
        .finding-meta {{
            color: #666;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .finding-meta strong {{
            color: #333;
        }}
        .findings-section {{
            margin-top: 30px;
        }}
        .section-title {{
            font-size: 24px;
            margin: 30px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SDLC Code Scanner - Security Scan Report</h1>
        <p>Repository: {escape(report_data.get('repository', 'N/A'))}</p>"""

        # Add branch if available
        if report_data.get("branch"):
            html += f"""
        <p>Branch: {escape(report_data.get('branch'))}</p>"""

        html += f"""
        <p>Scan Date: {escape(report_data.get('scan_timestamp', 'N/A'))}</p>
    </div>

    <div class="summary">
        <div class="stat-card">
            <h3>Total Findings</h3>
            <div class="stat-value">{summary.get('total_findings', 0)}</div>
        </div>
        <div class="stat-card">
            <h3>Files Analyzed</h3>
            <div class="stat-value">{summary.get('unique_files', 0)}</div>
        </div>
        <div class="stat-card">
            <h3>Critical Findings</h3>
            <div class="stat-value" style="color: #dc3545;">
                {summary.get('by_severity', {}).get('CRITICAL', 0)}
            </div>
        </div>
        <div class="stat-card">
            <h3>High Findings</h3>
            <div class="stat-value" style="color: #fd7e14;">
                {summary.get('by_severity', {}).get('HIGH', 0)}
            </div>
        </div>
    </div>

    <div class="findings-section">
        <h2 class="section-title">Findings Details</h2>
"""

        if not findings:
            html += "<p>No findings detected. Great job!</p>"
        else:
            # Group by severity
            by_sev = {}
            for finding in findings:
                sev = finding.get("severity", "INFO")
                if sev not in by_sev:
                    by_sev[sev] = []
                by_sev[sev].append(finding)

            # Output by severity
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if severity in by_sev:
                    html += f'<h3 class="section-title">{severity} Severity ({len(by_sev[severity])} findings)</h3>'
                    for finding in by_sev[severity]:
                        location = ""
                        if finding.get("file_path"):
                            location = f"<code>{escape(finding['file_path'])}"
                            if finding.get("line_number"):
                                location += f":{finding['line_number']}"
                            location += "</code>"

                        html += f"""
        <div class="finding">
            <div class="finding-title">
                <span class="severity-badge severity-{severity}">{severity}</span>
                {escape(finding.get('title', 'Untitled'))}
            </div>
            <div class="finding-meta">
                <strong>Severity:</strong> {severity} |
                <strong>Tool:</strong> {escape(finding.get('tool', 'Unknown'))} |
                <strong>Rule:</strong> {escape(finding.get('rule_id', 'N/A'))}
                {f" | <strong>Location:</strong> {location}" if location else ""}
            </div>
            <p>{escape(finding.get('description', 'No description available'))}</p>
            {f"<p><strong>Remediation:</strong> {escape(finding.get('remediation', ''))}</p>"
             if finding.get('remediation') else ""}
        </div>
"""

        html += """
    </div>
</body>
</html>
"""
        return html

"""SARIF Report Formatter for GitHub Code Scanning integration"""

import json
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime


class SARIFFormatter:
    """
    Formats scan results as SARIF (Static Analysis Results Interchange Format)

    SARIF is the standard format for static analysis tools and is natively
    supported by GitHub Code Scanning.

    Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    # Map our severity levels to SARIF levels
    SEVERITY_MAP = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    # Map our severity levels to SARIF security-severity scores
    # GitHub uses these for prioritization (0.0 - 10.0 scale)
    SECURITY_SEVERITY_MAP = {
        "CRITICAL": "9.0",
        "HIGH": "7.0",
        "MEDIUM": "5.0",
        "LOW": "3.0",
        "INFO": "1.0",
    }

    def format(self, report_data: Dict[str, Any], output_path: str) -> str:
        """
        Format report as SARIF

        Args:
            report_data: Aggregated report data
            output_path: Path to write SARIF file

        Returns:
            Path to generated file
        """
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M")
        output_file = Path(output_path) / f"{timestamp}-scan-report.sarif"

        sarif_output = self._build_sarif(report_data)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sarif_output, f, indent=2)

        return str(output_file)

    def _build_sarif(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build SARIF document structure"""
        findings = report_data.get("findings", [])

        # Group findings by tool to create separate runs
        tools = self._group_by_tool(findings)

        runs = []
        for tool_name, tool_findings in tools.items():
            runs.append(self._build_run(tool_name, tool_findings, report_data))

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": runs,
        }

    def _group_by_tool(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by their source tool"""
        tools: Dict[str, List[Dict[str, Any]]] = {}
        for finding in findings:
            tool = finding.get("tool", "unknown")
            if tool not in tools:
                tools[tool] = []
            tools[tool].append(finding)
        return tools

    def _build_run(
        self,
        tool_name: str,
        findings: List[Dict[str, Any]],
        report_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a SARIF run object for a specific tool"""
        # Build rules from findings
        rules = {}
        results = []

        for finding in findings:
            rule_id = finding.get("rule_id", "unknown")

            # Add rule if not already present
            if rule_id not in rules:
                rules[rule_id] = self._build_rule(finding)

            # Add result
            results.append(self._build_result(finding))

        return {
            "tool": {
                "driver": {
                    "name": f"SDLC Code Scanner ({tool_name})",
                    "informationUri": "https://github.com/crofton-cloud/sdlc-code-scanner",
                    "version": "1.0.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                }
            ],
        }

    def _build_rule(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Build a SARIF rule object"""
        rule_id = finding.get("rule_id", "unknown")
        severity = finding.get("severity", "INFO")
        title = finding.get("title", rule_id)
        description = finding.get("description", "")
        remediation = finding.get("remediation", "")

        rule = {
            "id": rule_id,
            "name": self._sanitize_rule_name(title),
            "shortDescription": {
                "text": title[:512] if title else rule_id,
            },
            "fullDescription": {
                "text": description[:4096] if description else title,
            },
            "defaultConfiguration": {
                "level": self.SEVERITY_MAP.get(severity, "note"),
            },
            "properties": {
                "security-severity": self.SECURITY_SEVERITY_MAP.get(severity, "1.0"),
                "tags": self._get_tags(finding),
            },
        }

        if remediation:
            rule["help"] = {
                "text": remediation[:4096],
                "markdown": remediation[:4096],
            }

        return rule

    def _build_result(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Build a SARIF result object"""
        rule_id = finding.get("rule_id", "unknown")
        severity = finding.get("severity", "INFO")
        title = finding.get("title", rule_id)
        description = finding.get("description", "")
        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number")
        resource = finding.get("resource", "")

        # Build message
        message_parts = [title]
        if description and description != title:
            message_parts.append(description)
        if resource:
            message_parts.append(f"Resource: {resource}")

        result = {
            "ruleId": rule_id,
            "level": self.SEVERITY_MAP.get(severity, "note"),
            "message": {
                "text": " | ".join(message_parts)[:4096],
            },
        }

        # Add location if we have a file path
        if file_path:
            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": self._normalize_path(file_path),
                        "uriBaseId": "%SRCROOT%",
                    },
                }
            }

            # Add region if we have line number
            if line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": int(line_number) if line_number else 1,
                }

            result["locations"] = [location]

        # Add fingerprint for deduplication
        fingerprint = finding.get("fingerprint") or finding.get("metadata", {}).get(
            "hash"
        )
        if fingerprint:
            result["fingerprints"] = {
                "primaryLocationLineHash": fingerprint,
            }

        return result

    def _sanitize_rule_name(self, name: str) -> str:
        """Sanitize rule name to be a valid identifier"""
        if not name:
            return "unknown"
        # Replace invalid characters with underscores
        sanitized = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
        # Ensure it doesn't start with a number
        if sanitized and sanitized[0].isdigit():
            sanitized = "_" + sanitized
        return sanitized[:128]

    def _normalize_path(self, path: str) -> str:
        """Normalize file path for SARIF (relative paths without leading /)"""
        if not path:
            return ""
        # Remove common prefixes
        prefixes = ["/repo/", "/github/workspace/", "./"]
        for prefix in prefixes:
            if path.startswith(prefix):
                path = path[len(prefix) :]
        # Remove leading slash
        return path.lstrip("/")

    def _get_tags(self, finding: Dict[str, Any]) -> List[str]:
        """Get tags for a finding"""
        tags = ["security"]
        tool = finding.get("tool", "")

        # Add tool-specific tags
        if "terraform" in tool.lower():
            tags.append("terraform")
            tags.append("infrastructure-as-code")
        elif "cloudformation" in tool.lower() or "cfn" in tool.lower():
            tags.append("cloudformation")
            tags.append("infrastructure-as-code")
        elif "secret" in tool.lower() or "gitleaks" in tool.lower():
            tags.append("secrets")
            tags.append("credentials")
        elif "bandit" in tool.lower() or "python" in tool.lower():
            tags.append("python")
        elif "npm" in tool.lower() or "snyk" in tool.lower():
            tags.append("dependencies")
            tags.append("supply-chain")

        # Add severity tag
        severity = finding.get("severity", "").lower()
        if severity:
            tags.append(f"severity-{severity}")

        return tags

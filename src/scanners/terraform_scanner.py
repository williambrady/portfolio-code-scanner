"""
Terraform Scanner
Runs multiple security and compliance tools against Terraform code
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any
from src.scanner_base import ScannerBase, Finding, Severity


class TerraformScanner(ScannerBase):
    """Scanner for Terraform IaC files"""

    def is_applicable(self, path: str) -> bool:
        """Check if path contains Terraform files"""
        path_obj = Path(path)
        return any(path_obj.rglob("*.tf"))

    def run(self, path: str) -> List[Finding]:
        """Run all enabled Terraform scanners"""
        self.findings = []

        if not self.is_applicable(path):
            self.logger.info("No Terraform files found, skipping Terraform scanners")
            return self.findings

        self.logger.info("Running Terraform scanners...")

        # Run terraform fmt check
        if self.config.get("tools", {}).get("terraform", {}).get("terraform_fmt", True):
            self.findings.extend(self._run_terraform_fmt(path))

        # Run terraform validate
        if self.config.get("tools", {}).get("terraform", {}).get("terraform_validate", True):
            self.findings.extend(self._run_terraform_validate(path))

        # Run tflint
        if self.config.get("tools", {}).get("terraform", {}).get("tflint", True):
            self.findings.extend(self._run_tflint(path))

        # Run tfsec
        if self.config.get("tools", {}).get("terraform", {}).get("tfsec", True):
            self.findings.extend(self._run_tfsec(path))

        # Run checkov
        if self.config.get("tools", {}).get("terraform", {}).get("checkov", True):
            self.findings.extend(self._run_checkov(path))

        # Run trivy
        if self.config.get("tools", {}).get("terraform", {}).get("trivy", True):
            self.findings.extend(self._run_trivy(path))

        self.logger.info("Terraform scanners found %s findings", len(self.findings))
        return self.findings

    def _run_terraform_fmt(self, path: str) -> List[Finding]:
        """Run terraform fmt to check formatting"""
        findings = []
        self.logger.info("Running terraform fmt...")

        returncode, stdout, _ = self.execute_command(
            ["terraform", "fmt", "-check", "-recursive"],
            cwd=path
        )

        # terraform fmt returns non-zero if files need formatting
        if returncode != 0 and stdout:
            for line in stdout.strip().split('\n'):
                if line.strip():
                    file_path = line.strip()

                    # Skip excluded paths
                    if self.is_path_excluded(file_path):
                        self.logger.debug("Skipping excluded path: %s", file_path)
                        continue

                    findings.append(Finding(
                        tool="terraform-fmt",
                        severity=Severity.LOW,
                        rule_id="FMT001",
                        title="Terraform file needs formatting",
                        description=f"File {line} is not properly formatted",
                        file_path=file_path,
                        remediation="Run: terraform fmt"
                    ))

        return findings

    def _run_terraform_validate(self, path: str) -> List[Finding]:
        """Run terraform validate"""
        findings = []
        self.logger.info("Running terraform validate...")

        # First initialize (quietly)
        init_code, _, _ = self.execute_command(
            ["terraform", "init", "-backend=false"],
            cwd=path
        )

        if init_code == 0:
            returncode, stdout, _ = self.execute_command(
                ["terraform", "validate", "-json"],
                cwd=path
            )

            if returncode != 0:
                try:
                    result = json.loads(stdout)
                    if not result.get("valid", True):
                        for diag in result.get("diagnostics", []):
                            findings.append(Finding(
                                tool="terraform-validate",
                                severity=Severity.HIGH if diag.get("severity") == "error" else Severity.MEDIUM,
                                rule_id="VAL001",
                                title="Terraform validation error",
                                description=diag.get("summary", "Validation failed"),
                                file_path=diag.get("range", {}).get("filename"),
                                line_number=diag.get("range", {}).get("start", {}).get("line"),
                                metadata=diag
                            ))
                except json.JSONDecodeError:
                    pass

        return findings

    def _run_tflint(self, path: str) -> List[Finding]:
        """Run TFLint"""
        findings = []
        self.logger.info("Running TFLint...")

        returncode, stdout, stderr = self.execute_command(
            ["tflint", "--format=json", "--recursive"],
            cwd=path
        )

        findings = self.parse_output(stdout, stderr, returncode)
        return self.filter_excluded_findings(findings, "tflint", "terraform")

    def _run_tfsec(self, path: str) -> List[Finding]:
        """Run tfsec"""
        findings = []
        self.logger.info("Running tfsec...")

        # Build command with exclusions
        cmd = ["tfsec", path, "--format=json", "--no-color"]

        # Add excluded paths
        excluded_paths = self.get_excluded_paths()
        for exclude_path in excluded_paths:
            cmd.extend(["--exclude-path", exclude_path])

        _, stdout, _ = self.execute_command(cmd, cwd=path)

        try:
            if stdout:
                result = json.loads(stdout)
                for issue in result.get("results", []):
                    findings.append(Finding(
                        tool="tfsec",
                        severity=self.severity_from_string(issue.get("severity", "MEDIUM")),
                        rule_id=issue.get("rule_id", "UNKNOWN"),
                        title=issue.get("rule_description", "Security issue detected"),
                        description=issue.get("description", ""),
                        file_path=issue.get("location", {}).get("filename"),
                        line_number=issue.get("location", {}).get("start_line"),
                        resource=issue.get("resource", ""),
                        remediation=issue.get("links", [None])[0] if issue.get("links") else None,
                        metadata=issue
                    ))
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse tfsec output: %s", e)

        return self.filter_excluded_findings(findings, "tfsec", "terraform")

    def _run_checkov(self, path: str) -> List[Finding]:
        """Run Checkov"""
        findings = []
        self.logger.info("Running Checkov...")

        # Get exclusions from config
        exclude_rules = self.config.get("tools", {}).get("terraform", {}).get("exclude_rules", {}).get("checkov", [])
        if exclude_rules:
            self.logger.info("Checkov excluding rules: %s", ', '.join(exclude_rules))

        # Build command with path exclusions
        cmd = ["checkov", "-d", path, "--framework", "terraform", "--output", "json", "--quiet"]

        # Add excluded paths
        excluded_paths = self.get_excluded_paths()
        for exclude_path in excluded_paths:
            cmd.extend(["--skip-path", exclude_path])

        _, stdout, _ = self.execute_command(cmd, cwd=path)

        excluded_count = 0
        try:
            if stdout:
                result = json.loads(stdout)
                for check_type in result.get("results", {}).get("failed_checks", []):
                    rule_id = check_type.get("check_id", "UNKNOWN")

                    # Skip excluded rules
                    if rule_id in exclude_rules:
                        self.logger.debug("Skipping excluded rule %s", rule_id)
                        excluded_count += 1
                        continue

                    # Try to get severity from check metadata, fallback to intelligent mapping
                    severity = self._map_checkov_severity(check_type)

                    findings.append(Finding(
                        tool="checkov",
                        severity=severity,
                        rule_id=rule_id,
                        title=check_type.get("check_name", "Policy violation"),
                        description=check_type.get("check_result", {}).get("result", ""),
                        file_path=check_type.get("file_path"),
                        line_number=check_type.get("file_line_range", [None])[0],
                        resource=check_type.get("resource", ""),
                        remediation=check_type.get("guideline"),
                        metadata=check_type
                    ))

                if excluded_count > 0:
                    self.logger.info("Checkov excluded %s findings based on config", excluded_count)
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse Checkov output: %s", e)

        return findings

    def _map_checkov_severity(self, check: dict) -> Severity:
        """Map Checkov check to severity level based on check ID and type"""
        # First try to use severity from check if available
        if check.get("severity"):
            return self.severity_from_string(check["severity"])

        check_name = check.get("check_name", "").lower()

        # CRITICAL: Exposed secrets, public access to sensitive resources
        critical_patterns = [
            "public", "exposed", "secret", "password", "credential",
            "0.0.0.0/0", "open to internet", "publicly accessible"
        ]

        # HIGH: Missing encryption, overly permissive policies, security misconfigurations
        high_patterns = [
            "encryption", "kms", "ssl", "tls", "https",
            "iam", "policy", "permission", "wildcard",
            "mfa", "root account", "admin", "imdsv2"
        ]

        # MEDIUM: Missing logging, monitoring, best practices
        medium_patterns = [
            "logging", "log", "monitoring", "cloudtrail", "cloudwatch",
            "versioning", "backup", "retention", "audit"
        ]

        # LOW: Tags, naming, non-critical configurations
        low_patterns = [
            "tag", "name", "description", "metadata"
        ]

        # Check patterns against check name
        for pattern in critical_patterns:
            if pattern in check_name:
                return Severity.CRITICAL

        for pattern in high_patterns:
            if pattern in check_name:
                return Severity.HIGH

        for pattern in medium_patterns:
            if pattern in check_name:
                return Severity.MEDIUM

        for pattern in low_patterns:
            if pattern in check_name:
                return Severity.LOW

        # Default to MEDIUM for unknown checks
        return Severity.MEDIUM

    def _run_trivy(self, path: str) -> List[Finding]:
        """Run Trivy in config mode"""
        findings = []
        self.logger.info("Running Trivy...")

        # Build command with exclusions
        cmd = ["trivy", "config", "--format", "json", "--exit-code", "0"]

        # Add excluded paths (Trivy uses --skip-dirs with comma-separated list)
        excluded_paths = self.get_excluded_paths()
        if excluded_paths:
            cmd.extend(["--skip-dirs", ",".join(excluded_paths)])

        cmd.append(path)

        _, stdout, _ = self.execute_command(cmd, cwd=path)

        try:
            if stdout:
                result = json.loads(stdout)
                for res in result.get("Results", []):
                    for misconf in res.get("Misconfigurations", []):
                        findings.append(Finding(
                            tool="trivy",
                            severity=self.severity_from_string(misconf.get("Severity", "MEDIUM")),
                            rule_id=misconf.get("ID", "UNKNOWN"),
                            title=misconf.get("Title", "Misconfiguration detected"),
                            description=misconf.get("Description", ""),
                            file_path=res.get("Target"),
                            resource=misconf.get("CauseMetadata", {}).get("Resource"),
                            remediation=misconf.get("Resolution"),
                            metadata=misconf
                        ))
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse Trivy output: %s", e)

        return self.filter_excluded_findings(findings, "trivy", "terraform")

    def parse_output(self, output: str, stderr: str, return_code: int) -> List[Finding]:
        """Parse TFLint JSON output"""
        findings = []
        try:
            if output:
                result = json.loads(output)
                for issue in result.get("issues", []):
                    file_path = issue.get("range", {}).get("filename")

                    # Skip excluded paths
                    if file_path and self.is_path_excluded(file_path):
                        self.logger.debug("Skipping excluded path: %s", file_path)
                        continue

                    findings.append(Finding(
                        tool="tflint",
                        severity=self.severity_from_string(issue.get("rule", {}).get("severity", "warning")),
                        rule_id=issue.get("rule", {}).get("name", "UNKNOWN"),
                        title=issue.get("message", "Linting issue"),
                        description=issue.get("message", ""),
                        file_path=file_path,
                        line_number=issue.get("range", {}).get("start", {}).get("line"),
                        metadata=issue
                    ))
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse TFLint output: %s", e)

        return findings

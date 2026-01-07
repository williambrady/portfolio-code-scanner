"""
CloudFormation Scanner
Runs security and compliance tools against CloudFormation templates
"""

import json
from pathlib import Path
from typing import List
from src.scanner_base import ScannerBase, Finding, Severity


class CloudFormationScanner(ScannerBase):
    """Scanner for CloudFormation templates"""

    def _is_cloudformation_template(self, file_path: Path) -> bool:
        """
        Validate if a file is a CloudFormation template

        Args:
            file_path: Path to file to check

        Returns:
            True if file appears to be a CloudFormation template
        """
        # Exclude common non-CFN files
        exclude_patterns = [
            "package.json",
            "package-lock.json",
            "tsconfig.json",
            "manifest.json",
            ".eslintrc.json",
            "jest.config.json",
            "node_modules",
            ".git",
            "test",
            "spec",
        ]

        # Check if file should be excluded
        file_str = str(file_path).lower()
        for pattern in exclude_patterns:
            if pattern in file_str:
                return False

        # Only check files with CFN-like extensions
        if file_path.suffix not in [".template", ".yaml", ".yml", ".json"]:
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read(2000)  # Read enough to find markers

                # Must have CloudFormation-specific markers
                has_cfn_version = "AWSTemplateFormatVersion" in content
                has_aws_resources = "AWS::" in content
                has_resources_section = (
                    '"Resources"' in content or "Resources:" in content
                )

                # Exclude files that look like other types
                is_package_json = '"dependencies"' in content and '"name"' in content
                is_tsconfig = '"compilerOptions"' in content

                if is_package_json or is_tsconfig:
                    return False

                # Consider it CFN if it has the version OR both AWS resources and Resources section
                return has_cfn_version or (has_aws_resources and has_resources_section)

        except Exception as e:  # pylint: disable=broad-exception-caught
            self.logger.debug("Could not read %s: %s", file_path, e)
            return False

    def _find_cfn_templates(self, path: str) -> List[str]:
        """
        Find all CloudFormation templates in the given path

        Args:
            path: Directory to search

        Returns:
            List of CloudFormation template file paths
        """
        path_obj = Path(path)
        templates = []

        # Search for potential template files
        for pattern in ["**/*.template", "**/*.yaml", "**/*.yml", "**/*.json"]:
            for file in path_obj.glob(pattern):
                if self._is_cloudformation_template(file):
                    templates.append(str(file))
                    self.logger.debug("Found CloudFormation template: %s", file)

        return templates

    def is_applicable(self, path: str) -> bool:
        """Check if path contains CloudFormation templates"""
        templates = self._find_cfn_templates(path)
        return len(templates) > 0

    def run(self, path: str) -> List[Finding]:
        """Run all enabled CloudFormation scanners"""
        self.findings = []

        if not self.is_applicable(path):
            self.logger.info("No CloudFormation templates found, skipping CFN scanners")
            return self.findings

        self.logger.info("Running CloudFormation scanners...")

        # Run cfn-lint
        if self.config.get("tools", {}).get("cloudformation", {}).get("cfn_lint", True):
            self.findings.extend(self._run_cfn_lint(path))

        # Run cfn-nag
        if self.config.get("tools", {}).get("cloudformation", {}).get("cfn_nag", True):
            self.findings.extend(self._run_cfn_nag(path))

        # Run checkov
        if self.config.get("tools", {}).get("cloudformation", {}).get("checkov", True):
            self.findings.extend(self._run_checkov(path))

        self.logger.info(
            "CloudFormation scanners found %s findings", len(self.findings)
        )
        return self.findings

    def _run_cfn_lint(self, path: str) -> List[Finding]:
        """Run cfn-lint"""
        findings = []
        self.logger.info("Running cfn-lint...")

        # Find validated CloudFormation templates
        cfn_templates = self._find_cfn_templates(path)

        if not cfn_templates:
            self.logger.info("No CloudFormation templates found for cfn-lint")
            return findings

        self.logger.info("Running cfn-lint on %s templates", len(cfn_templates))

        # Get exclusions from config
        exclude_rules = (
            self.config.get("tools", {})
            .get("cloudformation", {})
            .get("exclude_rules", {})
            .get("cfn_lint", [])
        )

        # Run cfn-lint on all templates
        _, stdout, stderr = self.execute_command(
            ["cfn-lint"] + cfn_templates + ["--format", "json"], cwd=path
        )

        try:
            if stdout:
                issues = json.loads(stdout)
                for issue in issues:
                    rule_id = issue.get("Rule", {}).get("Id", "UNKNOWN")

                    # Skip excluded rules
                    if rule_id in exclude_rules:
                        self.logger.debug("Skipping excluded rule %s", rule_id)
                        continue

                    findings.append(
                        Finding(
                            tool="cfn-lint",
                            severity=self.severity_from_string(
                                issue.get("Level", "Warning")
                            ),
                            rule_id=rule_id,
                            title=issue.get("Rule", {}).get(
                                "ShortDescription", "Validation issue"
                            ),
                            description=issue.get("Message", ""),
                            file_path=issue.get("Filename"),
                            line_number=issue.get("Location", {})
                            .get("Start", {})
                            .get("LineNumber"),
                            metadata=issue,
                        )
                    )
                self.logger.info("cfn-lint found %s findings", len(findings))
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse cfn-lint output: %s", e)
            self.logger.debug("stdout: %s", stdout[:500])
            self.logger.debug("stderr: %s", stderr[:500])

        return findings

    def _run_cfn_nag(self, path: str) -> List[Finding]:
        """Run cfn-nag"""
        findings = []
        self.logger.info("Running cfn-nag...")

        # Find validated CloudFormation templates
        cfn_templates = self._find_cfn_templates(path)

        if not cfn_templates:
            self.logger.info("No CloudFormation templates found for cfn-nag")
            return findings

        self.logger.info("Running cfn-nag on %s templates", len(cfn_templates))

        # Get exclusions from config
        exclude_rules = (
            self.config.get("tools", {})
            .get("cloudformation", {})
            .get("exclude_rules", {})
            .get("cfn_nag", [])
        )
        if exclude_rules:
            self.logger.info("cfn-nag excluding rules: %s", ", ".join(exclude_rules))

        # cfn-nag can scan multiple files with --input-path pointing to individual files
        # We'll scan each template individually to ensure proper validation
        all_results = []
        stderr = ""  # Initialize for error logging
        for template in cfn_templates:
            _, stdout, stderr = self.execute_command(
                ["cfn_nag_scan", "--input-path", template, "--output-format", "json"],
                cwd=path,
            )

            if stdout:
                try:
                    result = json.loads(stdout)
                    all_results.extend(result)
                except json.JSONDecodeError as e:
                    self.logger.debug(
                        "Failed to parse cfn-nag output for %s: %s", template, e
                    )
                    continue

        # Process all results
        excluded_count = 0
        stdout = ""  # Initialize for error logging
        try:
            if all_results:
                for file_result in all_results:
                    file_name = file_result.get("filename", "unknown")

                    # Process violations (can be WARN or FAIL type)
                    violations = file_result.get("file_results", {}).get(
                        "violations", []
                    )
                    for violation in violations:
                        rule_id = violation.get("id", "UNKNOWN")

                        # Skip excluded rules
                        if rule_id in exclude_rules:
                            self.logger.debug("Skipping excluded rule %s", rule_id)
                            excluded_count += 1
                            continue

                        # Determine severity based on type
                        violation_type = violation.get("type", "WARN")
                        severity = (
                            Severity.HIGH
                            if violation_type == "FAIL"
                            else Severity.MEDIUM
                        )

                        line_numbers = violation.get("line_numbers", [])
                        line_number = line_numbers[0] if line_numbers else None

                        findings.append(
                            Finding(
                                tool="cfn-nag",
                                severity=severity,
                                rule_id=rule_id,
                                title=violation.get("message", "Security violation"),
                                description=violation.get("message", ""),
                                file_path=file_name,
                                line_number=line_number,
                                resource=", ".join(
                                    violation.get("logical_resource_ids", [])
                                ),
                                metadata=violation,
                            )
                        )

                if excluded_count > 0:
                    self.logger.info(
                        "cfn-nag excluded %s findings based on config", excluded_count
                    )
                self.logger.info("cfn-nag found %s findings", len(findings))
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse cfn-nag output: %s", e)
            self.logger.debug("stdout: %s", stdout[:500])
            self.logger.debug("stderr: %s", stderr[:500])

        return findings

    def _run_checkov(self, path: str) -> List[Finding]:
        """Run Checkov for CloudFormation"""
        findings = []
        self.logger.info("Running Checkov for CloudFormation...")

        # Find validated CloudFormation templates
        cfn_templates = self._find_cfn_templates(path)

        if not cfn_templates:
            self.logger.info("No CloudFormation templates found for Checkov")
            return findings

        self.logger.info("Running Checkov on %s templates", len(cfn_templates))

        # Get absolute paths for filtering
        cfn_template_basenames = {Path(t).name for t in cfn_templates}

        # Get exclusions from config
        exclude_rules = (
            self.config.get("tools", {})
            .get("cloudformation", {})
            .get("exclude_rules", {})
            .get("checkov", [])
        )
        if exclude_rules:
            self.logger.info("Checkov excluding rules: %s", ", ".join(exclude_rules))

        # Build command with path exclusions
        cmd = [
            "checkov",
            "-d",
            path,
            "--framework",
            "cloudformation",
            "--output",
            "json",
            "--quiet",
        ]

        # Add excluded paths
        excluded_paths = self.get_excluded_paths()
        for exclude_path in excluded_paths:
            cmd.extend(["--skip-path", exclude_path])

        # Checkov scans directory but we'll filter results to only validated templates
        _, stdout, _ = self.execute_command(cmd, cwd=path)

        excluded_count = 0
        try:
            if stdout:
                result = json.loads(stdout)
                for check in result.get("results", {}).get("failed_checks", []):
                    # Only include findings from our validated CloudFormation templates
                    check_file = check.get("file_path", "")
                    check_filename = Path(check_file).name if check_file else ""

                    if check_filename not in cfn_template_basenames:
                        self.logger.debug("Skipping non-CFN file: %s", check_file)
                        continue

                    # Skip excluded rules
                    rule_id = check.get("check_id", "UNKNOWN")
                    if rule_id in exclude_rules:
                        self.logger.debug("Skipping excluded rule %s", rule_id)
                        excluded_count += 1
                        continue

                    # Try to get severity from check metadata, fallback to intelligent mapping
                    severity = self._map_checkov_severity(check)

                    findings.append(
                        Finding(
                            tool="checkov-cfn",
                            severity=severity,
                            rule_id=rule_id,
                            title=check.get("check_name", "Policy violation"),
                            description=check.get("check_result", {}).get("result", ""),
                            file_path=check.get("file_path"),
                            line_number=check.get("file_line_range", [None])[0],
                            resource=check.get("resource", ""),
                            remediation=check.get("guideline"),
                            metadata=check,
                        )
                    )

                if excluded_count > 0:
                    self.logger.info(
                        "Checkov excluded %s findings based on config", excluded_count
                    )
                self.logger.info(
                    "Checkov found %s findings (after filtering)", len(findings)
                )
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
            "public",
            "exposed",
            "secret",
            "password",
            "credential",
            "0.0.0.0/0",
            "open to internet",
            "publicly accessible",
        ]

        # HIGH: Missing encryption, overly permissive policies, security misconfigurations
        high_patterns = [
            "encryption",
            "kms",
            "ssl",
            "tls",
            "https",
            "iam",
            "policy",
            "permission",
            "wildcard",
            "mfa",
            "root account",
            "admin",
        ]

        # MEDIUM: Missing logging, monitoring, best practices
        medium_patterns = [
            "logging",
            "log",
            "monitoring",
            "cloudtrail",
            "cloudwatch",
            "versioning",
            "backup",
            "retention",
            "audit",
        ]

        # LOW: Tags, naming, non-critical configurations
        low_patterns = ["tag", "name", "description", "metadata"]

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

    def parse_output(self, output: str, stderr: str, return_code: int) -> List[Finding]:
        """Parse scanner output - used by base class"""
        # This is handled by individual tool methods
        return []

"""
Secrets Scanner
Detects hardcoded secrets, API keys, passwords, and other sensitive data
"""

import json
import tempfile
from typing import List
from src.scanner_base import ScannerBase, Finding, Severity


class SecretsScanner(ScannerBase):
    """Scanner for detecting secrets in code"""

    def is_applicable(self, path: str) -> bool:
        """Secrets scanner is always applicable"""
        return True

    def run(self, path: str) -> List[Finding]:
        """Run secrets detection tools"""
        self.findings = []

        self.logger.info("Running secrets scanners...")

        # Run gitleaks
        if self.config.get("tools", {}).get("secrets", {}).get("gitleaks", True):
            self.findings.extend(self._run_gitleaks(path))

        self.logger.info("Secrets scanners found %s findings", len(self.findings))
        return self.findings

    def _run_gitleaks(self, path: str) -> List[Finding]:
        """Run Gitleaks to detect secrets"""
        findings = []
        self.logger.info("Running Gitleaks...")

        # Get exclusions from config
        exclude_rules = (
            self.config.get("tools", {})
            .get("secrets", {})
            .get("exclude_rules", {})
            .get("gitleaks", [])
        )
        if exclude_rules:
            self.logger.info("Gitleaks excluding rules: %s", ", ".join(exclude_rules))

        # Create secure temporary file for Gitleaks report
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".json", delete=False
        ) as temp_report:
            report_path = temp_report.name

        try:
            _, _, _ = self.execute_command(
                [
                    "gitleaks",
                    "detect",
                    "--source",
                    path,
                    "--report-format",
                    "json",
                    "--report-path",
                    report_path,
                    "--no-git",
                ],
                cwd=path,
            )

            # Gitleaks writes to file, read it
            excluded_count = 0
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    results = json.load(f)
                for secret in results:
                    rule_id = secret.get("RuleID", "UNKNOWN")

                    # Skip excluded rules
                    if rule_id in exclude_rules:
                        self.logger.debug("Skipping excluded rule %s", rule_id)
                        excluded_count += 1
                        continue

                    findings.append(
                        Finding(
                            tool="gitleaks",
                            severity=Severity.CRITICAL,  # All secrets are critical
                            rule_id=rule_id,
                            title=f"Secret detected: {secret.get('Description', 'Unknown secret type')}",
                            description=f"Potential secret found: {secret.get('Description', '')}",
                            file_path=secret.get("File"),
                            line_number=secret.get("StartLine"),
                            remediation=(
                                "Remove the hardcoded secret and use environment "
                                "variables or secret management service"
                            ),
                            metadata={
                                "match": secret.get("Match", "")[
                                    :100
                                ],  # Truncate for safety
                                "secret_type": secret.get("Description"),
                                "commit": secret.get("Commit", "N/A"),
                            },
                        )
                    )

                    if excluded_count > 0:
                        self.logger.info(
                            "Gitleaks excluded %s findings based on config",
                            excluded_count,
                        )
            except FileNotFoundError:
                self.logger.debug(
                    "No secrets report generated (no secrets found or gitleaks failed)"
                )
            except json.JSONDecodeError as e:
                self.logger.error("Failed to parse Gitleaks output: %s", e)
            except Exception as e:  # pylint: disable=broad-exception-caught
                self.logger.error("Error reading Gitleaks report: %s", e)
        finally:
            # Clean up temporary file
            import os

            try:
                os.unlink(report_path)
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # Ignore cleanup errors

        return findings

    def parse_output(self, output: str, stderr: str, return_code: int) -> List[Finding]:
        """Parse scanner output"""
        # Gitleaks uses file output, so this is not used
        return []

"""
NPM Scanner
Runs npm audit and Snyk for dependency and IaC security scanning
"""

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import List
from src.scanner_base import ScannerBase, Finding, Severity


class NPMScanner(ScannerBase):
    """Scanner for npm projects and IaC using Snyk"""

    def is_applicable(self, path: str) -> bool:
        """Check if path contains npm projects or IaC files"""
        path_obj = Path(path)

        # Check for package.json files
        has_npm = any(path_obj.rglob("package.json"))

        # Check for IaC files that Snyk can scan
        has_iac = (
            any(path_obj.rglob("*.tf"))  # Terraform
            or any(path_obj.rglob("*.yaml"))  # CloudFormation/K8s
            or any(path_obj.rglob("*.yml"))
            or any(path_obj.rglob("*.json"))
            or any(path_obj.rglob("*.template"))
        )

        return has_npm or has_iac

    def run(self, path: str) -> List[Finding]:
        """Run npm and Snyk scanners"""
        self.findings = []

        if not self.is_applicable(path):
            self.logger.info(
                "No npm projects or IaC files found, skipping npm scanners"
            )
            return self.findings

        self.logger.info("Running npm/Snyk scanners...")

        # Run npm audit
        if self.config.get("tools", {}).get("npm", {}).get("npm_audit", True):
            self.findings.extend(self._run_npm_audit(path))

        # Run Snyk IaC
        if self.config.get("tools", {}).get("npm", {}).get("snyk", True):
            self.findings.extend(self._run_snyk_iac(path))

        self.logger.info("NPM/Snyk scanners found %s findings", len(self.findings))
        return self.findings

    def _run_npm_audit(self, path: str) -> List[Finding]:
        """Run npm audit on package.json files"""
        findings = []
        self.logger.info("Running npm audit...")

        # Find all package.json files
        path_obj = Path(path)
        package_files = list(path_obj.rglob("package.json"))

        if not package_files:
            self.logger.info("No package.json files found for npm audit")
            return findings

        self.logger.info(
            "Running npm audit on %s package.json files", len(package_files)
        )

        for package_file in package_files:
            package_dir = package_file.parent

            # Skip excluded paths
            if self.is_path_excluded(str(package_file)):
                self.logger.debug("Skipping excluded path: %s", package_file)
                continue

            # Run npm audit with JSON output
            _, stdout, _ = self.execute_command(
                ["npm", "audit", "--json"], cwd=str(package_dir)
            )

            try:
                if stdout:
                    result = json.loads(stdout)
                    vulnerabilities = result.get("vulnerabilities", {})

                    for vuln_name, vuln_data in vulnerabilities.items():
                        severity = vuln_data.get("severity", "low")

                        findings.append(
                            Finding(
                                tool="npm-audit",
                                severity=self.severity_from_string(severity),
                                rule_id=f"npm-{vuln_name}",
                                title=f"Vulnerable dependency: {vuln_name}",
                                description=(
                                    vuln_data.get("via", [{}])[0].get(
                                        "title", "Dependency vulnerability"
                                    )
                                    if isinstance(vuln_data.get("via"), list)
                                    else str(vuln_data.get("via", ""))
                                ),
                                file_path=str(package_file),
                                remediation=(
                                    f"Update to version {vuln_data.get('fixAvailable', {}).get('version', 'latest')}"
                                    if vuln_data.get("fixAvailable")
                                    else "Review and update dependency"
                                ),
                                metadata=vuln_data,
                            )
                        )

                    self.logger.info(
                        "npm audit found %s vulnerabilities in %s",
                        len(vulnerabilities),
                        package_file,
                    )
            except json.JSONDecodeError as e:
                self.logger.error(
                    "Failed to parse npm audit output for %s: %s", package_file, e
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                self.logger.error(
                    "Error processing npm audit results for %s: %s", package_file, e
                )

        return findings

    def _run_snyk_iac(self, path: str) -> List[Finding]:
        """Run Snyk IaC scanner"""
        findings = []
        self.logger.info("Running Snyk IaC...")

        # Get Snyk token from environment variable
        snyk_token_env = (
            self.config.get("tool_config", {})
            .get("snyk", {})
            .get("auth_token_env", "SNYK_AUTH")
        )
        snyk_token = os.environ.get(snyk_token_env)
        snyk_org = self.config.get("tool_config", {}).get("snyk", {}).get("org")

        if not snyk_token:
            self.logger.warning(
                "Snyk auth token not found in environment variable '%s', skipping Snyk IaC scan",
                snyk_token_env,
            )
            return findings

        # Set environment variable for Snyk authentication
        env = os.environ.copy()
        env["SNYK_TOKEN"] = snyk_token

        # Get exclusions from config
        exclude_rules = (
            self.config.get("tools", {})
            .get("npm", {})
            .get("exclude_rules", {})
            .get("snyk", [])
        )
        if exclude_rules:
            self.logger.info("Snyk excluding rules: %s", ", ".join(exclude_rules))

        excluded_count = 0

        # Scan .template files separately (Snyk doesn't recognize them natively)
        findings.extend(
            self._scan_template_files(
                path, snyk_token, snyk_org, exclude_rules, excluded_count, env
            )
        )

        # Build Snyk command - use "." as path since we set cwd
        cmd = ["snyk", "iac", "test", ".", "--json"]

        if snyk_org:
            cmd.extend(["--org", snyk_org])

        # Get severity threshold from config
        severity_threshold = (
            self.config.get("tool_config", {})
            .get("snyk", {})
            .get("severity_threshold", "low")
        )
        cmd.append(f"--severity-threshold={severity_threshold}")

        self.logger.info("Running Snyk IaC test on %s", path)

        # Run Snyk IaC test - set cwd to path so Snyk scans from that directory
        returncode, stdout, stderr = self.execute_command(
            cmd, cwd=path, timeout=600, env=env
        )

        # Log raw output for debugging
        self.logger.debug("Snyk return code: %s", returncode)
        self.logger.debug("Snyk stdout length: %s", len(stdout))
        self.logger.debug("Snyk stderr length: %s", len(stderr))
        if stdout:
            self.logger.debug("Snyk stdout (first 500 chars): %s", stdout[:500])
        if stderr:
            self.logger.debug("Snyk stderr (first 500 chars): %s", stderr[:500])

        try:
            # Snyk returns exit code 1 when vulnerabilities are found, which is expected
            if not stdout:
                self.logger.warning(
                    "Snyk returned no output. Return code: %s", returncode
                )
                if stderr:
                    self.logger.warning("Snyk stderr: %s", stderr[:500])
                return findings

            if stdout:
                result = json.loads(stdout)

                # Handle Snyk IaC output format
                if isinstance(result, list):
                    # Multiple files scanned
                    for file_result in result:
                        findings.extend(
                            self._parse_snyk_file_result(
                                file_result, exclude_rules, excluded_count
                            )
                        )
                elif isinstance(result, dict):
                    # Single result or error
                    if result.get("infrastructureAsCodeIssues"):
                        findings.extend(
                            self._parse_snyk_file_result(
                                result, exclude_rules, excluded_count
                            )
                        )
                    elif result.get("error"):
                        self.logger.warning("Snyk error: %s", result.get("error"))

                if excluded_count > 0:
                    self.logger.info(
                        "Snyk excluded %s findings based on config", excluded_count
                    )
                self.logger.info("Snyk IaC found %s findings", len(findings))

        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse Snyk output: %s", e)
            self.logger.debug("stdout: %s", stdout[:1000])
            self.logger.debug("stderr: %s", stderr[:1000])
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.logger.error("Error processing Snyk results: %s", e)

        return findings

    def _scan_template_files(
        self,
        path: str,
        snyk_token: str,
        snyk_org: str,
        exclude_rules: list,
        excluded_count: int,
        env: dict,
    ) -> List[Finding]:
        """
        Scan .template files with Snyk by creating temporary .yaml copies
        Workaround for Snyk not recognizing .template extension
        """
        findings = []
        path_obj = Path(path)

        # Find all .template files
        template_files = list(path_obj.rglob("*.template"))

        if not template_files:
            self.logger.debug("No .template files found for Snyk scanning")
            return findings

        # Filter out excluded paths
        template_files = [
            f for f in template_files if not self.is_path_excluded(str(f))
        ]

        if not template_files:
            self.logger.debug("All .template files were excluded")
            return findings

        self.logger.info(
            "Found %s .template files to scan with Snyk", len(template_files)
        )

        # Create temporary directory for .template file copies with .yaml extension
        # Use tempfile module for security (instead of hardcoded /tmp)
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            file_mapping = {}  # Maps temp file paths to original file paths

            # Copy .template files with .yaml extension
            for template_file in template_files:
                # Create unique temp filename preserving directory structure
                relative_path = template_file.relative_to(path_obj)
                # Preserve path structure but change extension to .yaml
                temp_file = temp_path / str(relative_path).replace(".template", ".yaml")
                temp_file.parent.mkdir(parents=True, exist_ok=True)

                # Copy file
                shutil.copy2(str(template_file), str(temp_file))
                # Map both full path and just the filename (Snyk may report either)
                temp_file_name = str(temp_file.relative_to(temp_path))
                original_file_path = str(template_file.relative_to(path_obj))
                file_mapping[temp_file_name] = original_file_path
                file_mapping[str(temp_file)] = str(template_file)
                self.logger.debug(
                    "Copied %s to %s for Snyk scanning", template_file, temp_file
                )

            # Build Snyk command
            cmd = ["snyk", "iac", "test", ".", "--json"]

            if snyk_org:
                cmd.extend(["--org", snyk_org])

            # Get severity threshold from config
            severity_threshold = (
                self.config.get("tool_config", {})
                .get("snyk", {})
                .get("severity_threshold", "low")
            )
            cmd.append(f"--severity-threshold={severity_threshold}")

            self.logger.info(
                "Running Snyk IaC on %s .template files", len(template_files)
            )

            # Run Snyk on temp directory
            returncode, stdout, stderr = self.execute_command(
                cmd, cwd=str(temp_path), timeout=600, env=env
            )

            # Log debug info
            self.logger.debug("Snyk .template scan return code: %s", returncode)
            if stdout:
                self.logger.debug(
                    "Snyk .template stdout (first 500 chars): %s", stdout[:500]
                )
            if stderr:
                self.logger.debug(
                    "Snyk .template stderr (first 500 chars): %s", stderr[:500]
                )

            try:
                if not stdout:
                    self.logger.warning(
                        "Snyk returned no output for .template files. Return code: %s",
                        returncode,
                    )
                    return findings

                result = json.loads(stdout)

                # Handle Snyk IaC output format
                if isinstance(result, list):
                    for file_result in result:
                        # Map temp file path back to original .template file
                        temp_file_path = file_result.get("targetFile", "")
                        # Try direct lookup first, then try as relative path
                        if temp_file_path in file_mapping:
                            file_result["targetFile"] = file_mapping[temp_file_path]
                            self.logger.debug(
                                "Mapped %s to %s",
                                temp_file_path,
                                file_mapping[temp_file_path],
                            )
                        else:
                            self.logger.debug(
                                "Could not map file path: %s (available: %s)",
                                temp_file_path,
                                list(file_mapping.keys())[:3],
                            )

                        findings.extend(
                            self._parse_snyk_file_result(
                                file_result, exclude_rules, excluded_count
                            )
                        )
                elif isinstance(result, dict):
                    if result.get("infrastructureAsCodeIssues"):
                        # Map temp file path back to original
                        temp_file_path = result.get("targetFile", "")
                        if temp_file_path in file_mapping:
                            result["targetFile"] = file_mapping[temp_file_path]
                            self.logger.debug(
                                "Mapped %s to %s",
                                temp_file_path,
                                file_mapping[temp_file_path],
                            )
                        else:
                            self.logger.debug(
                                "Could not map file path: %s", temp_file_path
                            )

                        findings.extend(
                            self._parse_snyk_file_result(
                                result, exclude_rules, excluded_count
                            )
                        )
                    elif result.get("error"):
                        self.logger.warning(
                            "Snyk .template scan error: %s", result.get("error")
                        )

                self.logger.info(
                    "Snyk found %s findings in .template files", len(findings)
                )

            except json.JSONDecodeError as e:
                self.logger.error("Failed to parse Snyk .template output: %s", e)
                self.logger.debug("stdout: %s", stdout[:1000])
            except Exception as e:  # pylint: disable=broad-exception-caught
                self.logger.error("Error processing Snyk .template results: %s", e)

        return findings

    def _parse_snyk_file_result(
        self, file_result: dict, exclude_rules: list, excluded_count: int
    ) -> List[Finding]:
        """Parse Snyk results for a single file"""
        findings = []

        target_file = file_result.get("targetFile", "unknown")
        issues = file_result.get("infrastructureAsCodeIssues", [])

        for issue in issues:
            rule_id = issue.get("id", "UNKNOWN")

            # Skip excluded rules
            if rule_id in exclude_rules:
                self.logger.debug("Skipping excluded rule %s", rule_id)
                excluded_count += 1
                continue

            # Map Snyk severity
            severity_str = issue.get("severity", "medium")
            severity = self._map_snyk_severity(severity_str)

            # Get line number from issue
            line_number = None
            if issue.get("lineNumber"):
                line_number = issue.get("lineNumber")

            # Build description with more context
            description = issue.get("issue", "")
            impact = issue.get("impact", "")
            if impact:
                description = f"{description} Impact: {impact}"

            findings.append(
                Finding(
                    tool="snyk-iac",
                    severity=severity,
                    rule_id=rule_id,
                    title=issue.get("title", "IaC security issue"),
                    description=description,
                    file_path=target_file,
                    line_number=line_number,
                    resource=issue.get("subType", ""),
                    remediation=issue.get("resolve", ""),
                    metadata={
                        "publicId": issue.get("publicId"),
                        "documentation": issue.get("documentation"),
                        "references": issue.get("references", []),
                    },
                )
            )

        return findings

    def _map_snyk_severity(self, severity_str: str) -> Severity:
        """Map Snyk severity to our Severity enum"""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        return severity_map.get(severity_str.lower(), Severity.MEDIUM)

    def parse_output(self, output: str, stderr: str, return_code: int) -> List[Finding]:
        """Parse scanner output - used by base class"""
        # This is handled by individual tool methods
        return []

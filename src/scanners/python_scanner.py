"""
Python Security Scanner
Scans Python code for security vulnerabilities and dependency issues
"""

import json
from pathlib import Path
from typing import List
from src.scanner_base import ScannerBase, Finding, Severity


class PythonScanner(ScannerBase):
    """Scanner for Python code security and dependencies"""

    def is_applicable(self, path: str) -> bool:
        """Check if Python files exist in the path"""
        path_obj = Path(path)
        # Check if any .py files exist
        py_files = list(path_obj.rglob("*.py"))
        return len(py_files) > 0

    def run(self, path: str) -> List[Finding]:
        """Run Python security scanners"""
        self.findings = []

        self.logger.info("Running Python security scanners...")

        # Run Bandit for code security
        if self.config.get("tools", {}).get("python", {}).get("bandit", True):
            self.findings.extend(self._run_bandit(path))

        # Run Safety for dependency vulnerabilities
        if self.config.get("tools", {}).get("python", {}).get("safety", True):
            self.findings.extend(self._run_safety(path))

        # Run Pylint for code quality and style
        if self.config.get("tools", {}).get("python", {}).get("pylint", True):
            self.findings.extend(self._run_pylint(path))

        self.logger.info("Python scanners found %s findings", len(self.findings))
        return self.findings

    def _run_bandit(self, path: str) -> List[Finding]:
        """Run Bandit to detect security issues in Python code"""
        findings = []
        self.logger.info("Running Bandit...")

        # Get exclusions from config
        exclude_rules = self.config.get("tools", {}).get("python", {}).get("exclude_rules", {}).get("bandit", [])
        if exclude_rules:
            self.logger.info("Bandit excluding rules: %s", ', '.join(exclude_rules))

        # Build command with path exclusions
        cmd = ["bandit", "-r", path, "-f", "json", "--quiet"]

        # Add excluded paths (Bandit uses --exclude with comma-separated list)
        excluded_paths = self.get_excluded_paths()
        if excluded_paths:
            cmd.extend(["--exclude", ",".join(excluded_paths)])

        # Run bandit with JSON output
        _, stdout, _ = self.execute_command(cmd, cwd=path)

        excluded_count = 0
        try:
            if stdout:
                results = json.loads(stdout)
                for result in results.get("results", []):
                    rule_id = result.get("test_id", "UNKNOWN")

                    # Skip excluded rules
                    if rule_id in exclude_rules:
                        self.logger.debug("Skipping excluded rule %s", rule_id)
                        excluded_count += 1
                        continue

                    # Map Bandit severity to our severity
                    issue_severity = result.get("issue_severity", "MEDIUM").upper()
                    severity = self._map_bandit_severity(issue_severity)

                    # Get file path relative to scan root
                    file_path = result.get("filename", "")
                    if file_path.startswith(path):
                        file_path = file_path[len(path):].lstrip("/")

                    findings.append(Finding(
                        tool="bandit",
                        severity=severity,
                        rule_id=rule_id,
                        title=result.get("issue_text", "Security issue detected"),
                        description=f"{result.get('issue_text', '')} - {result.get('test_name', '')}",
                        file_path=file_path,
                        line_number=result.get("line_number"),
                        remediation=self._get_bandit_remediation(rule_id),
                        metadata={
                            "confidence": result.get("issue_confidence", "UNKNOWN"),
                            "code": result.get("code", "")[:200],  # Truncate code snippet
                            "cwe": result.get("cwe", {})
                        }
                    ))

                if excluded_count > 0:
                    self.logger.info("Bandit excluded %s findings based on config", excluded_count)

                self.logger.info("Bandit found %s issues", len(findings))
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse Bandit output: %s", e)
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.logger.error("Error running Bandit: %s", e)

        return findings

    def _run_safety(self, path: str) -> List[Finding]:
        """Run Safety to check for known vulnerabilities in dependencies"""
        findings = []
        self.logger.info("Running Safety...")

        # Get exclusions from config
        exclude_rules = self.config.get("tools", {}).get("python", {}).get("exclude_rules", {}).get("safety", [])
        if exclude_rules:
            self.logger.info("Safety excluding CVEs: %s", ', '.join(exclude_rules))

        # Look for requirements files
        path_obj = Path(path)
        requirements_files = list(path_obj.glob("requirements*.txt"))

        if not requirements_files:
            self.logger.debug("No requirements.txt found, skipping Safety scan")
            return findings

        excluded_count = 0
        for req_file in requirements_files:
            self.logger.info("Scanning %s with Safety...", req_file.name)

            # Try new Safety 3.x 'scan' command first (requires API key)
            # If it fails, fall back to old 'check' command
            returncode, stdout, stderr = self.execute_command(
                ["safety", "scan", "--target", str(req_file), "--output", "json"],
                cwd=path
            )

            # Check if Safety requires authentication
            if returncode != 0 and ("authentication" in stderr.lower() or "api" in stderr.lower() or "EOF when reading" in stderr):
                self.logger.warning("Safety 3.x requires API key authentication. Skipping dependency vulnerability scanning.")
                self.logger.warning("To enable Safety scanning: Set SAFETY_API_KEY environment variable or configure in Safety config.")
                self.logger.warning("Alternatively, downgrade to Safety 2.x: pip install 'safety<3.0'")
                return findings

            try:
                if stdout and stdout.strip():
                    # Safety uses different JSON formats depending on version
                    # Try to parse both formats
                    results = json.loads(stdout)

                    # Handle different Safety output formats
                    vulnerabilities = []
                    if isinstance(results, list):
                        vulnerabilities = results
                    elif isinstance(results, dict):
                        # Safety 3.x format
                        vulnerabilities = results.get("vulnerabilities", results.get("scanned_packages", {}).get("vulnerabilities", []))

                    for vuln in vulnerabilities:
                        # Different versions of Safety have different field names
                        cve_id = vuln.get("cve") or vuln.get("vulnerability_id", "UNKNOWN")

                        # Skip excluded CVEs
                        if cve_id in exclude_rules:
                            self.logger.debug("Skipping excluded CVE %s", cve_id)
                            excluded_count += 1
                            continue

                        package = vuln.get("package", vuln.get("package_name", "unknown"))
                        installed = vuln.get("installed_version", vuln.get("analyzed_version", "unknown"))
                        affected = vuln.get("affected_versions", vuln.get("vulnerable_spec", "unknown"))

                        findings.append(Finding(
                            tool="safety",
                            severity=Severity.HIGH,  # All dependency vulnerabilities are HIGH
                            rule_id=cve_id,
                            title=f"Vulnerable dependency: {package} {installed}",
                            description=vuln.get("advisory", vuln.get("description", "Known vulnerability in dependency")),
                            file_path=str(req_file.name),
                            remediation=f"Update {package} to a secure version. Vulnerable: {affected}",
                            metadata={
                                "package": package,
                                "installed_version": installed,
                                "affected_versions": affected,
                                "cve": cve_id
                            }
                        ))

                    if excluded_count > 0:
                        self.logger.info("Safety excluded %s findings based on config", excluded_count)

                    if vulnerabilities:
                        self.logger.info("Safety found %s vulnerable dependencies in %s", len(findings), req_file.name)
                    else:
                        self.logger.info("Safety found no vulnerabilities in %s", req_file.name)
                else:
                    self.logger.debug("Safety produced no output (no vulnerabilities found or authentication required)")
            except json.JSONDecodeError as e:
                self.logger.warning("Failed to parse Safety output (likely requires API key): %s", e)
                self.logger.warning("Safety 3.x requires authentication. Set SAFETY_API_KEY or use Safety 2.x")
            except Exception as e:  # pylint: disable=broad-exception-caught
                self.logger.error("Error running Safety: %s", e)

        return findings

    def _run_pylint(self, path: str) -> List[Finding]:
        """Run Pylint to check code quality and style"""
        findings = []
        self.logger.info("Running Pylint...")

        # Get exclusions from config
        exclude_rules = self.config.get("tools", {}).get("python", {}).get("exclude_rules", {}).get("pylint", [])
        if exclude_rules:
            self.logger.info("Pylint excluding rules: %s", ', '.join(exclude_rules))

        # Find all Python files
        path_obj = Path(path)
        py_files = list(path_obj.rglob("*.py"))

        # Filter out excluded paths
        filtered_files = []
        for py_file in py_files:
            if not self.is_path_excluded(str(py_file)):
                filtered_files.append(str(py_file))

        if not filtered_files:
            self.logger.info("No Python files found for Pylint scan")
            return findings

        self.logger.info("Running Pylint on %s Python files", len(filtered_files))

        # Run pylint with JSON output
        # Use --exit-zero to prevent pylint from returning non-zero exit codes
        cmd = ["pylint", "--output-format=json", "--exit-zero"] + filtered_files

        _, stdout, _ = self.execute_command(cmd, cwd=path, timeout=300)

        excluded_count = 0
        try:
            if stdout and stdout.strip():
                results = json.loads(stdout)

                for result in results:
                    # Pylint message format: type (C/W/E/R/F) + category code
                    msg_id = result.get("message-id", "")
                    symbol = result.get("symbol", "")

                    # Skip excluded rules
                    if msg_id in exclude_rules or symbol in exclude_rules:
                        self.logger.debug("Skipping excluded rule %s", msg_id)
                        excluded_count += 1
                        continue

                    # Map pylint message type to severity
                    msg_type = result.get("type", "convention")
                    severity = self._map_pylint_severity(msg_type)

                    # Get file path relative to scan root
                    file_path = result.get("path", "")
                    if file_path.startswith(path):
                        file_path = file_path[len(path):].lstrip("/")

                    findings.append(Finding(
                        tool="pylint",
                        severity=severity,
                        rule_id=msg_id,
                        title=f"{symbol}: {result.get('message', 'Code quality issue')}",
                        description=result.get("message", ""),
                        file_path=file_path,
                        line_number=result.get("line"),
                        metadata={
                            "column": result.get("column"),
                            "symbol": symbol,
                            "message_type": msg_type,
                            "module": result.get("module")
                        }
                    ))

                if excluded_count > 0:
                    self.logger.info("Pylint excluded %s findings based on config", excluded_count)

                self.logger.info("Pylint found %s issues", len(findings))
            else:
                self.logger.info("Pylint found no issues")
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse Pylint output: %s", e)
            self.logger.debug("stdout: %s", stdout[:500])
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.logger.error("Error running Pylint: %s", e)

        return findings

    def _map_pylint_severity(self, msg_type: str) -> Severity:
        """Map Pylint message type to our Severity enum"""
        severity_map = {
            "fatal": Severity.CRITICAL,
            "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "refactor": Severity.LOW,
            "convention": Severity.INFO,
        }
        return severity_map.get(msg_type.lower(), Severity.INFO)

    def _map_bandit_severity(self, bandit_severity: str) -> Severity:
        """Map Bandit severity to our Severity enum"""
        severity_map = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        return severity_map.get(bandit_severity, Severity.MEDIUM)

    def _get_bandit_remediation(self, rule_id: str) -> str:
        """Get remediation advice for common Bandit rules"""
        remediations = {
            "B201": "Use of wildcard in SQL query. Use parameterized queries instead.",
            "B301": "Pickle usage detected. Avoid unpickling untrusted data.",
            "B302": "Use of marshal module. Avoid deserializing untrusted data.",
            "B303": "Use of insecure MD5 or SHA1 hash. Use SHA256 or better.",
            "B304": "Use of insecure cipher. Use strong encryption like AES-256.",
            "B305": "Use of insecure cipher mode. Use authenticated encryption like GCM.",
            "B306": "Use of tempfile.mktemp(). Use tempfile.mkstemp() instead.",
            "B307": "Use of eval(). Avoid evaluating untrusted input.",
            "B308": "Use of mark_safe(). Ensure input is properly sanitized.",
            "B310": "URL redirect without validation. Validate redirect URLs.",
            "B311": "Use of random for cryptographic purposes. Use secrets module.",
            "B312": "Telnet usage detected. Use SSH instead.",
            "B313": "XML parser vulnerable to XXE. Use defusedxml library.",
            "B314": "XML parser vulnerable to entity expansion. Use defusedxml library.",
            "B315": "XML parser vulnerable to DTD retrieval. Use defusedxml library.",
            "B316": "XML parser vulnerable to namespace issues. Use defusedxml library.",
            "B317": "XML parser vulnerable to entity resolution. Use defusedxml library.",
            "B318": "XML parser vulnerable to external entities. Use defusedxml library.",
            "B319": "XML parser vulnerable to entity expansion. Use defusedxml library.",
            "B320": "XML parser vulnerable to DTD retrieval. Use defusedxml library.",
            "B321": "FTP usage detected. Use SFTP instead.",
            "B322": "Input function usage. Validate all user input.",
            "B323": "Unverified context creation. Use default SSL context.",
            "B324": "Weak hash algorithm. Use SHA256 or better.",
            "B401": "Import of telnetlib. Use paramiko for SSH instead.",
            "B402": "Import of ftplib. Use SFTP instead.",
            "B403": "Import of pickle/cPickle. Avoid unpickling untrusted data.",
            "B404": "Import of subprocess. Validate all inputs and avoid shell=True.",
            "B405": "Import of xml.etree. Use defusedxml library instead.",
            "B406": "Import of xml.sax. Use defusedxml library instead.",
            "B407": "Import of xml.dom. Use defusedxml library instead.",
            "B408": "Import of xml.minidom. Use defusedxml library instead.",
            "B410": "Import of lxml. Use defusedxml library instead.",
            "B411": "Import of xmlrpclib. Use defusedxml library instead.",
            "B412": "Import of httpoxy. Avoid using CGI or set proper headers.",
            "B413": "Import of pyCrypto. Use cryptography library instead.",
            "B501": "Request with verify=False. Always verify SSL certificates.",
            "B502": "SSL with insecure protocol. Use TLS 1.2 or higher.",
            "B503": "SSL with weak cipher. Use strong ciphers only.",
            "B504": "SSL with weak protocol. Use TLS 1.2 or higher.",
            "B505": "Weak cryptographic key. Use at least 2048-bit keys.",
            "B506": "YAML load() usage. Use yaml.safe_load() instead.",
            "B507": "SSH with no host key verification. Always verify host keys.",
            "B601": "Shell injection via paramiko. Validate all inputs.",
            "B602": "Shell injection via subprocess. Use shell=False and validate inputs.",
            "B603": "Subprocess without shell equals true. Always use shell=False.",
            "B604": "Function call with shell=True. Use shell=False and list arguments.",
            "B605": "Shell injection via os.system. Use subprocess with shell=False.",
            "B606": "Shell injection via os.popen. Use subprocess with shell=False.",
            "B607": "Shell injection via subprocess. Validate all inputs.",
            "B608": "SQL injection via string formatting. Use parameterized queries.",
            "B609": "Linux command injection. Validate all inputs.",
            "B610": "SQL injection via string concatenation. Use parameterized queries.",
            "B611": "SQL injection via format string. Use parameterized queries.",
            "B701": "Jinja2 autoescape disabled. Enable autoescape for security.",
            "B702": "Mako templates usage. Use Jinja2 with autoescape enabled.",
            "B703": "Django mark_safe usage. Ensure input is properly sanitized.",
        }
        return remediations.get(rule_id, "Review the code and follow security best practices.")

    def parse_output(self, output: str, stderr: str, return_code: int) -> List[Finding]:
        """Parse scanner output"""
        # Bandit and Safety use JSON output parsed in their specific methods
        return []

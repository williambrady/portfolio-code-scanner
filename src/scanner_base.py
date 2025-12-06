"""
Base Scanner Class
Provides common interface and functionality for all security scanners
"""

import subprocess
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a security finding from a scanner"""
    tool: str
    severity: Severity
    rule_id: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    resource: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "tool": self.tool,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "resource": self.resource,
            "remediation": self.remediation,
            "metadata": self.metadata or {}
        }


class ScannerBase(ABC):
    """Abstract base class for all scanners"""

    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize scanner

        Args:
            config: Scanner configuration dictionary
            logger: Optional logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.findings: List[Finding] = []

    @abstractmethod
    def is_applicable(self, path: str) -> bool:
        """
        Check if this scanner is applicable for the given path

        Args:
            path: Path to scan

        Returns:
            True if scanner should run, False otherwise
        """
        pass

    @abstractmethod
    def run(self, path: str) -> List[Finding]:
        """
        Run the scanner and return findings

        Args:
            path: Path to scan

        Returns:
            List of findings
        """
        pass

    def execute_command(
        self,
        command: List[str],
        cwd: Optional[str] = None,
        timeout: int = 600,
        env: Optional[Dict[str, str]] = None
    ) -> tuple[int, str, str]:
        """
        Execute a command and return results

        Args:
            command: Command and arguments as list
            cwd: Working directory
            timeout: Command timeout in seconds
            env: Optional environment variables to pass to command

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            self.logger.debug("Executing: %s", ' '.join(command))
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            self.logger.error("Command timed out after %ss: %s", timeout, ' '.join(command))
            return -1, "", "Command timed out"
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.logger.error("Command execution failed: %s", e)
            return -1, "", str(e)

    def is_enabled(self) -> bool:
        """Check if this scanner is enabled in configuration"""
        # Override in subclass to check specific config
        return True

    def get_excluded_paths(self) -> List[str]:
        """Get list of paths to exclude from scanning"""
        return self.config.get("repository", {}).get("excluded_paths", [])

    def is_path_excluded(self, file_path: str) -> bool:
        """Check if a file path should be excluded based on configuration"""
        from pathlib import Path

        excluded_paths = self.get_excluded_paths()
        if not excluded_paths:
            return False

        # Normalize the file path
        normalized_path = str(Path(file_path)).replace('\\', '/')

        for exclude_pattern in excluded_paths:
            exclude_pattern = exclude_pattern.strip()

            # Check if any part of the path matches the exclude pattern
            if exclude_pattern in normalized_path:
                return True

            # Handle wildcard patterns like **/fixtures
            if '**' in exclude_pattern:
                pattern_part = exclude_pattern.replace('**/', '').replace('**', '')
                if pattern_part in normalized_path:
                    return True

        return False

    @abstractmethod
    def parse_output(self, output: str, stderr: str, return_code: int) -> List[Finding]:
        """
        Parse scanner output into findings

        Args:
            output: Command stdout
            stderr: Command stderr
            return_code: Command return code

        Returns:
            List of findings
        """
        pass

    def get_findings(self) -> List[Finding]:
        """Return all findings from this scanner"""
        return self.findings

    def severity_from_string(self, severity_str: str) -> Severity:
        """Convert string to Severity enum"""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "informational": Severity.INFO,
            "warning": Severity.MEDIUM,
            "error": Severity.HIGH,
        }
        return severity_map.get(severity_str.lower(), Severity.INFO)

    def filter_excluded_findings(self, findings: List[Finding], tool_name: str, scanner_type: str) -> List[Finding]:
        """
        Filter findings based on exclusion rules from config

        Args:
            findings: List of findings to filter
            tool_name: Name of the tool (e.g., 'tflint', 'tfsec')
            scanner_type: Type of scanner (e.g., 'terraform', 'cloudformation')

        Returns:
            Filtered list of findings with exclusions removed
        """
        exclude_rules = self.config.get("tools", {}).get(scanner_type, {}).get("exclude_rules", {}).get(tool_name, [])

        if not exclude_rules:
            return findings

        self.logger.info("%s excluding rules: %s", tool_name, ', '.join(exclude_rules))

        filtered_findings = []
        excluded_count = 0

        for finding in findings:
            if finding.rule_id in exclude_rules:
                self.logger.debug("Skipping excluded rule %s", finding.rule_id)
                excluded_count += 1
                continue
            filtered_findings.append(finding)

        if excluded_count > 0:
            self.logger.info("%s excluded %s findings based on config", tool_name, excluded_count)

        return filtered_findings

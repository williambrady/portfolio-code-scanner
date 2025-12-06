"""
Report Aggregator
Collects, normalizes, and aggregates findings from all scanners
"""

import hashlib
import logging
from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime
from src.scanner_base import Finding, Severity


class ReportAggregator:
    """Aggregates findings from multiple scanners"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize aggregator

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.findings: List[Finding] = []
        self.deduplicated_findings: List[Finding] = []
        self.stats: Dict[str, Any] = {}

    def add_findings(self, findings: List[Finding]):
        """
        Add findings from a scanner

        Args:
            findings: List of findings to add
        """
        self.findings.extend(findings)

    def aggregate(self, repository_path: str = None, branch: str = None) -> Dict[str, Any]:
        """
        Aggregate all findings and generate statistics

        Args:
            repository_path: Path to the repository being scanned
            branch: Git branch name (optional)

        Returns:
            Aggregated report data
        """
        self.logger.info("Aggregating %s findings...", len(self.findings))

        # Deduplicate findings
        if self.config.get("aggregation", {}).get("deduplicate", True):
            self.deduplicated_findings = self._deduplicate()
        else:
            self.deduplicated_findings = self.findings

        # Calculate statistics
        self.stats = self._calculate_stats()

        # Build report
        report = {
            "scan_timestamp": datetime.utcnow().isoformat(),
            "repository": repository_path,
            "branch": branch,
            "summary": {
                "total_findings": len(self.deduplicated_findings),
                "by_severity": self.stats["by_severity"],
                "by_tool": self.stats["by_tool"],
                "unique_files": self.stats["unique_files"],
            },
            "findings": [f.to_dict() for f in self.deduplicated_findings],
            "metadata": {
                "scanners_run": list(self.stats["by_tool"].keys()),
                "total_raw_findings": len(self.findings),
                "deduplication_enabled": self.config.get("aggregation", {}).get("deduplicate", True),
            }
        }

        self.logger.info("Aggregation complete: %s unique findings", len(self.deduplicated_findings))
        return report

    def _deduplicate(self) -> List[Finding]:
        """
        Deduplicate findings based on hash of key attributes

        Returns:
            List of unique findings
        """
        seen_hashes = set()
        unique_findings = []

        for finding in self.findings:
            # Create hash from key attributes
            finding_hash = self._generate_finding_hash(finding)

            if finding_hash not in seen_hashes:
                seen_hashes.add(finding_hash)
                unique_findings.append(finding)
            else:
                self.logger.debug("Duplicate finding filtered: %s in %s", finding.rule_id, finding.file_path)

        self.logger.info("Deduplication: %s -> %s findings", len(self.findings), len(unique_findings))
        return unique_findings

    def _generate_finding_hash(self, finding: Finding) -> str:
        """
        Generate unique hash for a finding

        Args:
            finding: Finding to hash

        Returns:
            Hash string
        """
        # Use file, line, rule_id, and message to identify duplicates
        # MD5 is used for deduplication only, not cryptographic security
        hash_input = f"{finding.file_path}:{finding.line_number}:{finding.rule_id}:{finding.title}"
        return hashlib.md5(hash_input.encode(), usedforsecurity=False).hexdigest()

    def _calculate_stats(self) -> Dict[str, Any]:
        """
        Calculate statistics about findings

        Returns:
            Dictionary of statistics
        """
        by_severity = defaultdict(int)
        by_tool = defaultdict(int)
        unique_files = set()

        for finding in self.deduplicated_findings:
            by_severity[finding.severity.value] += 1
            by_tool[finding.tool] += 1
            if finding.file_path:
                unique_files.add(finding.file_path)

        return {
            "by_severity": dict(by_severity),
            "by_tool": dict(by_tool),
            "unique_files": len(unique_files),
        }

    def get_findings_by_severity(self, min_severity: Severity) -> List[Finding]:
        """
        Get findings at or above a severity level

        Args:
            min_severity: Minimum severity level

        Returns:
            Filtered list of findings
        """
        severity_order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }

        min_level = severity_order.get(min_severity, 0)
        return [
            f for f in self.deduplicated_findings
            if severity_order.get(f.severity, 0) >= min_level
        ]

    def should_fail(self) -> bool:
        """
        Determine if scan should fail based on findings severity

        Returns:
            True if scan should fail
        """
        fail_on = self.config.get("severity", {}).get("fail_on", "HIGH")
        fail_severity = Severity[fail_on] if fail_on in Severity.__members__ else Severity.HIGH

        critical_findings = self.get_findings_by_severity(fail_severity)
        return len(critical_findings) > 0

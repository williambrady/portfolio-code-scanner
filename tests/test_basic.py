"""
Basic tests for AWS Quick Assess

These tests verify the core scanner infrastructure works correctly.
"""

import pytest
from pathlib import Path


class TestRepoDetector:
    """Tests for repository detection"""

    def test_import_repo_detector(self):
        """Verify RepoDetector can be imported"""
        from src.repo_detector import RepoDetector

        assert RepoDetector is not None

    def test_detect_terraform(self, tmp_path):
        """Test detection of Terraform files"""
        from src.repo_detector import RepoDetector

        # Create a sample Terraform file
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "aws_s3_bucket" "test" {}')

        detector = RepoDetector(str(tmp_path))
        scanners = detector.get_applicable_scanners()

        assert "terraform" in scanners

    def test_detect_cloudformation(self, tmp_path):
        """Test detection of CloudFormation files"""
        from src.repo_detector import RepoDetector

        # Create a sample CloudFormation file
        cfn_file = tmp_path / "template.yaml"
        cfn_file.write_text(
            """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""
        )

        detector = RepoDetector(str(tmp_path))
        scanners = detector.get_applicable_scanners()

        assert "cloudformation" in scanners


class TestConfigLoader:
    """Tests for configuration loading"""

    def test_import_config_loader(self):
        """Verify ConfigLoader can be imported"""
        from src.config_loader import ConfigLoader

        assert ConfigLoader is not None

    def test_load_config(self):
        """Test loading default configuration"""
        from src.config_loader import ConfigLoader

        config_path = Path(__file__).parent.parent / "config" / "config.yaml"
        if config_path.exists():
            loader = ConfigLoader(str(config_path))
            config = loader.load()
            assert config is not None
            assert isinstance(config, dict)


class TestReportAggregator:
    """Tests for report aggregation"""

    def test_import_report_aggregator(self):
        """Verify ReportAggregator can be imported"""
        from src.report_aggregator import ReportAggregator

        assert ReportAggregator is not None


class TestFormatters:
    """Tests for output formatters"""

    def test_import_json_formatter(self):
        """Verify JSONFormatter can be imported"""
        from src.formatters.json_formatter import JSONFormatter

        assert JSONFormatter is not None

    def test_import_html_formatter(self):
        """Verify HTMLFormatter can be imported"""
        from src.formatters.html_formatter import HTMLFormatter

        assert HTMLFormatter is not None

    def test_import_sarif_formatter(self):
        """Verify SARIFFormatter can be imported"""
        from src.formatters.sarif_formatter import SARIFFormatter

        assert SARIFFormatter is not None


class TestScannerBase:
    """Tests for scanner base class"""

    def test_import_scanner_base(self):
        """Verify ScannerBase can be imported"""
        from src.scanner_base import ScannerBase, Finding, Severity

        assert ScannerBase is not None
        assert Finding is not None
        assert Severity is not None

    def test_severity_enum(self):
        """Test Severity enum values"""
        from src.scanner_base import Severity

        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

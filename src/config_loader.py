"""
Configuration Loader
Loads and validates configuration from config.yaml and environment variables
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional


class ConfigLoader:
    """Handles loading and validation of configuration"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration loader

        Args:
            config_path: Path to config.yaml file
        """
        self.config_path = config_path or os.getenv(
            "CONFIG_PATH", "/app/config/config.yaml"
        )
        self.config: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)

    def load(self) -> Dict[str, Any]:
        """
        Load configuration from file and environment variables

        Returns:
            Configuration dictionary
        """
        # Load from YAML file
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = yaml.safe_load(f) or {}
                self.logger.info("Loaded configuration from %s", self.config_path)
            except Exception as e:  # pylint: disable=broad-exception-caught
                self.logger.error(
                    "Failed to load config from %s: %s", self.config_path, e
                )
                self.config = {}
        else:
            self.logger.warning(
                "Config file not found: %s, using defaults", self.config_path
            )
            self.config = self._get_default_config()

        # Override with environment variables
        self._apply_env_overrides()

        return self.config

    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            "tools": {
                "terraform": {
                    "enabled": True,
                    "terraform_fmt": True,
                    "terraform_validate": True,
                    "tflint": True,
                    "checkov": True,
                    "tfsec": True,
                    "trivy": True,
                    "terrascan": False,
                },
                "cloudformation": {
                    "enabled": True,
                    "cfn_lint": True,
                    "cfn_nag": True,
                    "checkov": True,
                    "cfn_guard": False,
                },
                "secrets": {
                    "enabled": True,
                    "gitleaks": True,
                },
            },
            "severity": {
                "fail_on": "HIGH",
                "report_minimum": "LOW",
            },
            "output": {
                "directory": "/app/reports",
                "formats": ["json", "html", "markdown"],
                "verbose": False,
            },
            "execution": {
                "parallel": True,
                "max_workers": 4,
                "timeout_per_scanner": 600,
            },
        }

    def _apply_env_overrides(self):
        """Apply environment variable overrides to configuration"""
        # Log level
        log_level = os.getenv("LOG_LEVEL")
        if log_level:
            if "logging" not in self.config:
                self.config["logging"] = {}
            self.config["logging"]["level"] = log_level

        # Repository path
        repo_path = os.getenv("REPO_PATH")
        if repo_path:
            if "repository" not in self.config:
                self.config["repository"] = {}
            self.config["repository"]["default_path"] = repo_path

        # Output directory
        output_dir = os.getenv("REPORTS_PATH")
        if output_dir:
            if "output" not in self.config:
                self.config["output"] = {}
            self.config["output"]["directory"] = output_dir

        # AWS credentials (stored but not logged)
        aws_region = os.getenv("AWS_REGION")
        if aws_region:
            if "aws" not in self.config:
                self.config["aws"] = {}
            self.config["aws"]["default_region"] = aws_region

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation key

        Args:
            key: Configuration key (e.g., "tools.terraform.enabled")
            default: Default value if key not found

        Returns:
            Configuration value
        """
        keys = key.split(".")
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    def is_tool_enabled(self, category: str, tool: str) -> bool:
        """
        Check if a specific tool is enabled

        Args:
            category: Tool category (e.g., "terraform")
            tool: Tool name (e.g., "tflint")

        Returns:
            True if tool is enabled
        """
        category_enabled = self.get(f"tools.{category}.enabled", True)
        tool_enabled = self.get(f"tools.{category}.{tool}", True)
        return category_enabled and tool_enabled

    def validate(self) -> bool:
        """
        Validate configuration

        Returns:
            True if configuration is valid
        """
        required_keys = [
            "tools",
            "severity",
            "output",
        ]

        for key in required_keys:
            if key not in self.config:
                self.logger.error("Required configuration key missing: %s", key)
                return False

        return True

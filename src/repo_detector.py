"""
Repository Detector
Detects IaC frameworks and languages present in a repository
"""

import os
import json
import logging
from pathlib import Path
from typing import List, Dict


class RepoDetector:
    """Detects IaC frameworks and technologies in a repository"""

    def __init__(self, repo_path: str):
        """
        Initialize repository detector

        Args:
            repo_path: Path to repository to analyze
        """
        self.repo_path = Path(repo_path)
        self.logger = logging.getLogger(__name__)

    def detect_all(self) -> Dict[str, bool]:
        """
        Detect all IaC frameworks and technologies

        Returns:
            Dictionary mapping framework names to boolean presence
        """
        return {
            "terraform": self.has_terraform(),
            "cloudformation": self.has_cloudformation(),
            "cdk": self.has_cdk(),
            "npm": self.has_npm(),
            "python": self.has_python(),
            "typescript": self.has_typescript(),
            "javascript": self.has_javascript(),
        }

    def has_terraform(self) -> bool:
        """Check if repository contains Terraform files"""
        return self._has_files_with_extension([".tf"])

    def has_cloudformation(self) -> bool:
        """Check if repository contains CloudFormation templates"""
        # Check for CFN files with common patterns
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                file_lower = file.lower()
                # Check extensions
                if file_lower.endswith((".yaml", ".yml", ".json", ".template")):
                    file_path = Path(root) / file
                    # Check if file contains CloudFormation keywords
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read(1000)  # Read first 1000 chars
                            if (
                                "AWSTemplateFormatVersion" in content
                                or "AWS::" in content
                            ):
                                return True
                    except Exception:  # pylint: disable=broad-exception-caught
                        continue
        return False

    def has_cdk(self) -> bool:
        """Check if repository contains AWS CDK project"""
        # Check for cdk.json
        if (self.repo_path / "cdk.json").exists():
            return True

        # Check for CDK imports in package.json
        package_json = self.repo_path / "package.json"
        if package_json.exists():
            try:
                with open(package_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    deps = {
                        **data.get("dependencies", {}),
                        **data.get("devDependencies", {}),
                    }
                    if any("aws-cdk" in dep for dep in deps.keys()):
                        return True
            except Exception:  # pylint: disable=broad-exception-caught
                pass

        return False

    def has_npm(self) -> bool:
        """Check if repository contains npm project"""
        return (self.repo_path / "package.json").exists()

    def has_python(self) -> bool:
        """Check if repository contains Python files"""
        return self._has_files_with_extension([".py"])

    def has_typescript(self) -> bool:
        """Check if repository contains TypeScript files"""
        return (
            self._has_files_with_extension([".ts", ".tsx"])
            or (self.repo_path / "tsconfig.json").exists()
        )

    def has_javascript(self) -> bool:
        """Check if repository contains JavaScript files"""
        return self._has_files_with_extension([".js", ".jsx"])

    def get_applicable_scanners(self) -> List[str]:
        """
        Get list of scanner types applicable to this repository

        Returns:
            List of scanner type names
        """
        detections = self.detect_all()
        scanners = []

        if detections["terraform"]:
            scanners.append("terraform")

        if detections["cloudformation"]:
            scanners.append("cloudformation")

        if detections["cdk"]:
            scanners.append("cdk")

        if detections["npm"]:
            scanners.append("npm")

        if detections["python"]:
            scanners.append("python")

        # Always run secrets scanner
        scanners.append("secrets")

        self.logger.info("Detected applicable scanners: %s", ", ".join(scanners))
        return scanners

    def _has_files_with_extension(self, extensions: List[str]) -> bool:
        """
        Check if repository contains files with given extensions

        Args:
            extensions: List of file extensions (e.g., [".tf", ".py"])

        Returns:
            True if files with any of the extensions exist
        """
        for ext in extensions:
            # Use rglob for recursive search
            if any(self.repo_path.rglob(f"*{ext}")):
                return True
        return False

    def get_file_count_by_type(self) -> Dict[str, int]:
        """
        Get count of files by type

        Returns:
            Dictionary mapping file types to counts
        """
        counts = {
            "terraform": len(list(self.repo_path.rglob("*.tf"))),
            "python": len(list(self.repo_path.rglob("*.py"))),
            "javascript": len(list(self.repo_path.rglob("*.js"))),
            "typescript": len(list(self.repo_path.rglob("*.ts"))),
            "yaml": len(list(self.repo_path.rglob("*.yaml")))
            + len(list(self.repo_path.rglob("*.yml"))),
            "json": len(list(self.repo_path.rglob("*.json"))),
        }
        return counts

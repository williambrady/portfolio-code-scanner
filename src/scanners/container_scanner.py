"""
Container Scanner
Scans Docker container images for vulnerabilities using Trivy
"""

import json
import os
import logging
from typing import List, Dict, Any, Optional

from src.scanner_base import ScannerBase, Finding, Severity


class ContainerScanner(ScannerBase):
    """Scanner for Docker container images using Trivy"""

    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)
        self.container_config = config.get("tools", {}).get("container", {})

    def is_applicable(self, path: str) -> bool:
        """Check if repository contains Dockerfiles"""
        return self._has_dockerfile(path)

    def is_enabled(self) -> bool:
        """Check if container scanning is enabled"""
        return self.container_config.get("enabled", True)

    def _has_dockerfile(self, path: str) -> bool:
        """Check if repository contains a Dockerfile"""
        dockerfile_names = ["Dockerfile", "dockerfile", "Containerfile"]

        for root, _, files in os.walk(path):
            # Skip excluded paths
            if self.is_path_excluded(root):
                continue
            for file in files:
                if file in dockerfile_names or file.startswith("Dockerfile."):
                    return True
        return False

    def _find_dockerfiles(self, path: str) -> List[str]:
        """Find all Dockerfiles in the repository"""
        dockerfiles = []
        dockerfile_names = ["Dockerfile", "dockerfile", "Containerfile"]

        for root, _, files in os.walk(path):
            # Skip excluded paths
            if self.is_path_excluded(root):
                continue
            for file in files:
                if file in dockerfile_names or file.startswith("Dockerfile."):
                    dockerfiles.append(os.path.join(root, file))

        return dockerfiles

    def run(self, path: str) -> List[Finding]:
        """Run container image vulnerability scanning"""
        self.findings = []

        if not self.is_enabled():
            self.logger.info("Container scanning is disabled")
            return self.findings

        # Check for trivy availability
        trivy_check, _, _ = self.execute_command(["trivy", "--version"])
        if trivy_check != 0:
            self.logger.warning("Trivy not found, skipping container scanning")
            return self.findings

        # Find Dockerfiles
        dockerfiles = self._find_dockerfiles(path)
        if not dockerfiles:
            self.logger.info("No Dockerfiles found")
            return self.findings

        self.logger.info("Found %d Dockerfile(s)", len(dockerfiles))

        # Check if we should build and scan images
        build_images = self.container_config.get("build_images", True)
        image_name_prefix = self.container_config.get("image_name_prefix", "scan-")

        if build_images:
            # Check for docker availability when building images
            docker_check, _, _ = self.execute_command(["docker", "--version"])
            if docker_check != 0:
                self.logger.warning(
                    "Docker not found, skipping container image building"
                )
                return self.findings

            for dockerfile in dockerfiles:
                self.findings.extend(
                    self._build_and_scan(path, dockerfile, image_name_prefix)
                )
        else:
            # Just scan existing images if specified in config
            images = self.container_config.get("images", [])
            for image in images:
                self.findings.extend(self._scan_image(image))

        return self.findings

    def _build_and_scan(
        self, repo_path: str, dockerfile: str, prefix: str
    ) -> List[Finding]:
        """Build Docker image and scan it"""
        findings = []

        # Determine build context and image name
        dockerfile_dir = os.path.dirname(dockerfile)

        # Use the directory name for the image tag
        if dockerfile_dir == repo_path or dockerfile_dir == ".":
            image_tag = f"{prefix}root:latest"
            build_context = repo_path
        else:
            relative_dir = os.path.relpath(dockerfile_dir, repo_path)
            # Sanitize for Docker image naming: lowercase, alphanumeric and hyphens only
            safe_name = relative_dir.replace("/", "-").replace("\\", "-")
            safe_name = safe_name.lower()
            safe_name = "".join(
                c if c.isalnum() or c == "-" else "-" for c in safe_name
            )
            safe_name = safe_name.strip("-")  # Remove leading/trailing hyphens
            image_tag = f"{prefix}{safe_name}:latest"
            build_context = dockerfile_dir

        self.logger.info("Building image %s from %s", image_tag, dockerfile)

        # Build the image
        build_cmd = [
            "docker",
            "build",
            "-t",
            image_tag,
            "-f",
            dockerfile,
            build_context,
        ]

        return_code, stdout, stderr = self.execute_command(
            build_cmd,
            cwd=repo_path,
            timeout=self.container_config.get("build_timeout", 600),
        )

        if return_code != 0:
            self.logger.error("Failed to build image from %s: %s", dockerfile, stderr)
            # Add a finding for build failure
            findings.append(
                Finding(
                    tool="trivy-container",
                    severity=Severity.HIGH,
                    rule_id="BUILD_FAILURE",
                    title="Docker image build failed",
                    description=f"Failed to build Docker image from {dockerfile}: {stderr[:500]}",
                    file_path=dockerfile,
                )
            )
            return findings

        # Scan the built image
        findings.extend(self._scan_image(image_tag, dockerfile))

        # Clean up the image after scanning (optional)
        if self.container_config.get("cleanup_images", True):
            self.execute_command(["docker", "rmi", "-f", image_tag])

        return findings

    def _scan_image(
        self, image: str, dockerfile: Optional[str] = None
    ) -> List[Finding]:
        """Scan a Docker image with Trivy"""
        findings = []
        self.logger.info("Scanning image: %s", image)

        # Build trivy command
        cmd = ["trivy", "image", "--format", "json", "--exit-code", "0", "--quiet"]

        # Add severity filter if configured
        severities = self.container_config.get(
            "severities", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
        )
        cmd.extend(["--severity", severities])

        # Skip unfixed vulnerabilities if configured
        if self.container_config.get("ignore_unfixed", False):
            cmd.append("--ignore-unfixed")

        cmd.append(image)

        return_code, stdout, stderr = self.execute_command(
            cmd, timeout=self.container_config.get("scan_timeout", 300)
        )

        if return_code != 0 and not stdout:
            self.logger.error("Trivy scan failed for %s: %s", image, stderr)
            return findings

        try:
            if stdout:
                result = json.loads(stdout)
                findings.extend(self._parse_trivy_output(result, image, dockerfile))
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse Trivy output: %s", e)

        return self.filter_excluded_findings(findings, "trivy", "container")

    def _parse_trivy_output(
        self, result: Dict, image: str, dockerfile: Optional[str] = None
    ) -> List[Finding]:
        """Parse Trivy JSON output for container vulnerabilities"""
        findings = []

        for res in result.get("Results", []):
            target = res.get("Target", image)
            target_type = res.get("Type", "")

            # Process vulnerabilities
            for vuln in res.get("Vulnerabilities", []):
                vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
                pkg_name = vuln.get("PkgName", "")
                installed_version = vuln.get("InstalledVersion", "")
                fixed_version = vuln.get("FixedVersion", "")

                title = f"{vuln_id}: {pkg_name}"
                if installed_version:
                    title += f" ({installed_version})"

                description = vuln.get("Description", "")
                if fixed_version:
                    remediation = f"Upgrade {pkg_name} to version {fixed_version}"
                else:
                    remediation = "No fix available yet"

                findings.append(
                    Finding(
                        tool="trivy-container",
                        severity=self.severity_from_string(
                            vuln.get("Severity", "MEDIUM")
                        ),
                        rule_id=vuln_id,
                        title=title,
                        description=description,
                        file_path=dockerfile,
                        resource=f"{target} ({target_type})" if target_type else target,
                        remediation=remediation,
                        metadata={
                            "image": image,
                            "package": pkg_name,
                            "installed_version": installed_version,
                            "fixed_version": fixed_version,
                            "references": vuln.get("References", []),
                            "cvss": vuln.get("CVSS", {}),
                        },
                    )
                )

        return findings

    def parse_output(self, output: str, stderr: str, return_code: int) -> List[Finding]:
        """Parse Trivy output - implemented for interface compliance"""
        # Main parsing is done in _parse_trivy_output
        return []

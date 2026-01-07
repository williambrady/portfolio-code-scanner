#!/usr/bin/env python3
"""
AWS Quick Assess - Main Entry Point
Orchestrates security scanning for AWS IaC and live environments
"""

import sys
import os
import logging
import click
import subprocess
from pathlib import Path
from typing import Optional

from src.config_loader import ConfigLoader
from src.repo_detector import RepoDetector
from src.report_aggregator import ReportAggregator
from src.scanners.terraform_scanner import TerraformScanner
from src.scanners.cloudformation_scanner import CloudFormationScanner
from src.scanners.secrets_scanner import SecretsScanner
from src.scanners.python_scanner import PythonScanner
from src.scanners.npm_scanner import NPMScanner
from src.formatters.json_formatter import JSONFormatter
from src.formatters.html_formatter import HTMLFormatter
from src.formatters.markdown_formatter import MarkdownFormatter
from src.formatters.sarif_formatter import SARIFFormatter


def setup_logging(verbose: bool = False):
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_repository_name(repo_path: str) -> str:
    """
    Determine the repository name from various sources

    Priority:
    1. REPO_NAME environment variable (set by run-local-scan.sh)
    2. Git remote URL (extract repo name from origin)
    3. Directory name from .git/config
    4. Fallback to repo_path
    """
    # Check environment variable first
    repo_name = os.environ.get("REPO_NAME")
    if repo_name:
        return repo_name

    # Try to get from git remote URL
    try:
        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout:
            # Extract repo name from URL
            # Examples: https://github.com/user/repo.git -> repo
            #           git@github.com:user/repo.git -> repo
            url = result.stdout.strip()
            repo_name = url.rstrip("/").split("/")[-1]
            # Remove .git suffix if present
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]
            if repo_name:
                return repo_name
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    # Fallback to repo_path
    return repo_path


def get_git_branch(repo_path: str) -> Optional[str]:
    """
    Get the current git branch name

    Returns:
        Branch name or None if not in a git repository
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return None


@click.group()
@click.version_option(version="0.1.0")
@click.option(
    "--config",
    type=click.Path(exists=True),
    default="/app/config/config.yaml",
    help="Path to configuration file",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, config: str, verbose: bool):
    """AWS Quick Assess - Security scanning tool for AWS Infrastructure-as-Code"""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["verbose"] = verbose


@cli.command()
@click.option(
    "--repo-path",
    type=click.Path(exists=True),
    default="/repo",
    help="Path to repository to scan",
)
@click.option(
    "--output-dir",
    type=click.Path(),
    default="/app/reports",
    help="Output directory for reports",
)
@click.option(
    "--format",
    multiple=True,
    default=["json"],
    help="Report format(s): json, html, markdown, csv, sarif",
)
@click.pass_context
def scan_local(ctx, repo_path: str, output_dir: str, format: tuple):
    """Scan local repository for IaC security issues"""
    setup_logging(ctx.obj.get("verbose", False))
    logger = logging.getLogger(__name__)

    click.echo("=" * 60)
    click.echo("AWS Quick Assess - Local Repository Scan")
    click.echo("=" * 60)
    click.echo(f"Repository: {repo_path}")
    click.echo(f"Output: {output_dir}")
    click.echo(f"Formats: {', '.join(format)}")
    click.echo("")

    try:
        # Load configuration
        config_loader = ConfigLoader(ctx.obj["config"])
        config = config_loader.load()

        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Detect repository type
        click.echo("Detecting repository type...")
        detector = RepoDetector(repo_path)
        applicable_scanners = detector.get_applicable_scanners()
        click.echo(f"Applicable scanners: {', '.join(applicable_scanners)}")
        click.echo("")

        # Initialize aggregator
        aggregator = ReportAggregator(config)

        # Run scanners
        scanners = []
        if "terraform" in applicable_scanners:
            scanners.append(TerraformScanner(config, logger))
        if "cloudformation" in applicable_scanners:
            scanners.append(CloudFormationScanner(config, logger))
        if "python" in applicable_scanners:
            scanners.append(PythonScanner(config, logger))
        # Always run NPM scanner if enabled - it has IaC scanning capability via Snyk
        if config.get("tools", {}).get("npm", {}).get("enabled", True):
            scanners.append(NPMScanner(config, logger))
        if "secrets" in applicable_scanners:
            scanners.append(SecretsScanner(config, logger))

        # Execute scanners
        for scanner in scanners:
            click.echo(f"Running {scanner.__class__.__name__}...")
            findings = scanner.run(repo_path)
            aggregator.add_findings(findings)
            click.echo(f"  Found {len(findings)} findings")

        click.echo("")

        # Aggregate results
        click.echo("Aggregating results...")
        # Determine repository name (tries env var, git remote, or falls back to path)
        repo_name = get_repository_name(repo_path)
        # Get git branch if available
        branch_name = get_git_branch(repo_path)
        report_data = aggregator.aggregate(
            repository_path=repo_name, branch=branch_name
        )

        # Display summary
        summary = report_data.get("summary", {})
        click.echo("")
        click.echo("=" * 60)
        click.echo("SCAN SUMMARY")
        click.echo("=" * 60)
        click.echo(f"Total Findings: {summary.get('total_findings', 0)}")
        click.echo(f"Files Analyzed: {summary.get('unique_files', 0)}")
        click.echo("")

        by_severity = summary.get("by_severity", {})
        if by_severity:
            click.echo("By Severity:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = by_severity.get(sev, 0)
                if count > 0:
                    click.echo(f"  {sev}: {count}")
        click.echo("")

        # Generate reports
        click.echo("Generating reports...")
        formatters = {
            "json": JSONFormatter(),
            "html": HTMLFormatter(),
            "markdown": MarkdownFormatter(),
            "sarif": SARIFFormatter(),
        }

        for fmt in format:
            if fmt in formatters:
                output_file = formatters[fmt].format(report_data, output_dir)
                click.echo(f"  {fmt.upper()}: {output_file}")

        click.echo("")
        click.echo("=" * 60)
        click.echo("Scan complete!")
        click.echo("=" * 60)

        # Exit with appropriate code
        if aggregator.should_fail():
            click.echo("FAIL: Critical/High severity findings detected", err=True)
            sys.exit(2)
        else:
            sys.exit(0)

    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Scan failed: %s", e, exc_info=True)
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--output-dir",
    type=click.Path(),
    default="/app/reports",
    help="Output directory for reports",
)
@click.option(
    "--regions",
    multiple=True,
    help="AWS regions to scan (default: from config)",
)
@click.pass_context
def scan_aws(ctx, output_dir: str, regions: tuple):
    """Scan live AWS account for security issues"""
    click.echo("Scanning AWS account...")
    click.echo(f"Config: {ctx.obj['config']}")
    click.echo(f"Output: {output_dir}")
    if regions:
        click.echo(f"Regions: {', '.join(regions)}")
    click.echo("\nThis is a placeholder. Full implementation coming soon.")


@cli.command()
@click.option(
    "--repo-path",
    type=click.Path(exists=True),
    default="/repo",
    help="Path to repository to scan",
)
@click.option(
    "--output-dir",
    type=click.Path(),
    default="/app/reports",
    help="Output directory for reports",
)
@click.pass_context
def scan_all(ctx, repo_path: str, output_dir: str):
    """Scan both local repository and AWS account"""
    click.echo("Running full scan (local + AWS)...")
    click.echo(f"Repository: {repo_path}")
    click.echo(f"Config: {ctx.obj['config']}")
    click.echo(f"Output: {output_dir}")
    click.echo("\nThis is a placeholder. Full implementation coming soon.")


@cli.command()
@click.pass_context
def list_tools(ctx):
    """List all available scanning tools and their status"""
    click.echo("Available scanning tools:")
    click.echo("\nTerraform:")
    click.echo("  - terraform fmt/validate")
    click.echo("  - TFLint")
    click.echo("  - Checkov")
    click.echo("  - tfsec")
    click.echo("  - Trivy")
    click.echo("  - Terrascan")
    click.echo("\nCloudFormation:")
    click.echo("  - cfn-lint")
    click.echo("  - cfn-nag")
    click.echo("  - Checkov")
    click.echo("\nCDK:")
    click.echo("  - cdk-nag")
    click.echo("  - Language linters (ESLint, pylint)")
    click.echo("\nnpm/Node.js:")
    click.echo("  - npm audit")
    click.echo("  - Snyk")
    click.echo("\nPython:")
    click.echo("  - Bandit (code security)")
    click.echo("  - Safety (dependency vulnerabilities)")
    click.echo("\nSecrets Detection:")
    click.echo("  - Gitleaks")
    click.echo("\nAWS Live:")
    click.echo("  - AWS Security Hub")
    click.echo("  - AWS Config")
    click.echo("  - Prowler")


@cli.command()
@click.pass_context
def validate_config(ctx):
    """Validate configuration file"""
    config_path = ctx.obj["config"]
    click.echo(f"Validating configuration: {config_path}")
    click.echo("\nThis is a placeholder. Full implementation coming soon.")


def main():
    """Main entry point"""
    try:
        # pylint: disable=no-value-for-parameter
        # Click decorators handle the parameters - obj={} initializes the context
        cli(obj={})
    except Exception as e:  # pylint: disable=broad-exception-caught
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

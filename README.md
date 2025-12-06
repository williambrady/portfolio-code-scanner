# AWS Quick Assess

> Comprehensive security assessment tool for AWS Infrastructure-as-Code and live environments

[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-available-2088FF?logo=github-actions&logoColor=white)](https://github.com/marketplace/actions/aws-quick-assess)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

AWS Quick Assess is a Docker-based security scanning platform that orchestrates multiple industry-leading security tools to provide comprehensive analysis of your AWS infrastructure code and live AWS accounts. It implements a multi-layered security scanning approach covering linting, security policies, dependency vulnerabilities, and secrets detection.

**Available as a GitHub Action for seamless CI/CD integration!**

## Features

### Multi-Tool Orchestration
- **17+ Security Tools** integrated in a single container
- **Automated Detection** of IaC frameworks (Terraform, CloudFormation, CDK, npm, Python)
- **Parallel Execution** for faster scan times
- **Finding Deduplication** across multiple tools
- **Rule Exclusions** for customizable scanning policies
- **Path Exclusions** to skip test directories and fixtures

### Comprehensive Coverage

#### Terraform Scanning
- `terraform fmt/validate` - Code formatting and syntax validation
- `TFLint` - Terraform linting and best practices
- `tfsec` - Security scanning for AWS, Azure, GCP resources
- `Checkov` - Policy-as-code and compliance scanning
- `Trivy` - Vulnerability and misconfiguration detection
- `Terrascan` - Policy-based scanning (optional)

#### CloudFormation Scanning
- `cfn-lint` - Template validation and best practices
- `cfn-nag` - Security-focused template analysis
- `Checkov` - Policy and compliance checking

#### Python Scanning
- `Bandit` - Python code security analysis (SQL injection, weak crypto, etc.)
- `Safety` - Dependency vulnerability detection (CVE scanning)

#### Additional Scanning
- `Gitleaks` - Secrets and credentials detection
- `npm audit` - JavaScript/TypeScript dependency vulnerabilities
- `Snyk` - Advanced dependency and license scanning
- `Prowler` - Live AWS account security assessment (planned)

### Reporting

- **JSON** - Structured data for CI/CD integration
- **HTML** - Interactive dashboard with color-coded severity levels
- **Markdown** - Documentation-ready format
- **SARIF** - GitHub Code Scanning integration
- **Severity-based Exit Codes** - Fail builds on critical/high findings

## Quick Start

### GitHub Action (Recommended)

The easiest way to use AWS Quick Assess is as a GitHub Action:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AWS Quick Assess
        uses: crofton-cloud/aws-quick-assess@v1
        with:
          scan-path: '.'
          fail-on-severity: 'HIGH'
```

See [GitHub Action Usage](#github-action) for full documentation.

### Prerequisites

- Docker installed and running (for local usage)
- For AWS scanning: AWS credentials with appropriate permissions

### Build the Docker Image

```bash
docker build -t aws-quick-assess:latest .
```

Or use the pre-built image (if available):

```bash
docker pull croftoncloud/aws-quick-assess:latest
```

### Basic Usage

Scan a local repository:

```bash
docker run --rm \
  -v /path/to/your/repo:/repo:ro \
  -v $(pwd)/reports:/app/reports \
  aws-quick-assess:latest \
  scan-local --repo-path /repo
```

Using the helper script:

```bash
./scripts/run-local-scan.sh /path/to/your/repo
```

## Usage

### Scan Local Repository

Scan your IaC code for security issues:

```bash
docker run --rm \
  -v /path/to/repo:/repo:ro \
  -v $(pwd)/reports:/app/reports \
  aws-quick-assess:latest \
  scan-local \
    --repo-path /repo \
    --output-dir /app/reports \
    --format json \
    --format html \
    --format markdown
```

**Helper Script:**
```bash
./scripts/run-local-scan.sh /path/to/repo [output-dir] [config-file]
```

### Scan AWS Account

Scan your live AWS environment (coming soon):

```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1

docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_REGION \
  -v $(pwd)/reports:/app/reports \
  aws-quick-assess:latest \
  scan-aws --output-dir /app/reports
```

**Helper Script:**
```bash
./scripts/run-aws-scan.sh [output-dir] [config-file]
```

### Full Scan (Local + AWS)

Scan both repository and AWS account:

```bash
./scripts/run-full-scan.sh /path/to/repo [output-dir] [config-file]
```

### List Available Tools

```bash
docker run --rm aws-quick-assess:latest list-tools
```

### Validate Configuration

```bash
docker run --rm \
  -v $(pwd)/config:/app/config:ro \
  aws-quick-assess:latest \
  validate-config
```

## Configuration

The tool is configured via `config/config.yaml`. Key configuration sections:

### Tool Enable/Disable

```yaml
tools:
  terraform:
    enabled: true
    terraform_fmt: true
    tflint: true
    tfsec: true
    checkov: true
    trivy: true
    terrascan: false  # Optional tools can be disabled

  cloudformation:
    enabled: true
    cfn_lint: true
    cfn_nag: true
    checkov: true

  python:
    enabled: true
    bandit: true   # Python code security
    safety: true   # Dependency vulnerabilities

  secrets:
    enabled: true
    gitleaks: true
```

### Rule Exclusions

Exclude specific rules from reporting (false positives, known exceptions):

```yaml
tools:
  terraform:
    exclude_rules:
      tflint: []
      tfsec: []
      checkov: []
      trivy: ["DS026"]  # Example: Skip HEALTHCHECK for CLI tools

  cloudformation:
    exclude_rules:
      cfn_nag: ["W89"]  # Example: Lambda VPC requirement
      cfn_lint: []
      checkov: []

  python:
    exclude_rules:
      bandit: ["B404", "B603"]  # subprocess usage - safe in scanner tool
      safety: []
```

### Path Exclusions

Exclude directories from scanning:

```yaml
repository:
  excluded_paths:
    - "tests"
    - "test"
    - "**/fixtures"
    - "node_modules"
    - ".terraform"
```

### Severity Thresholds

```yaml
severity:
  fail_on: "HIGH"        # Exit with error if findings at this level or above
  report_minimum: "LOW"  # Only report findings at this level or above
```

### Output Configuration

```yaml
output:
  directory: "/app/reports"
  formats:
    - json
    - html
    - markdown
  verbose: false
```

### Execution Settings

```yaml
execution:
  parallel: true      # Run scanners in parallel
  max_workers: 4      # Number of parallel workers
  timeout_per_scanner: 600  # Timeout in seconds
```

## Environment Variables

### Required for AWS Scanning
- `AWS_ACCESS_KEY_ID` - AWS access key
- `AWS_SECRET_ACCESS_KEY` - AWS secret key
- `AWS_REGION` - AWS region (default: us-east-1)
- `AWS_SESSION_TOKEN` - For temporary credentials (optional)

### Optional
- `CONFIG_PATH` - Path to config.yaml (default: /app/config/config.yaml)
- `LOG_LEVEL` - Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `REPO_PATH` - Repository path override
- `REPORTS_PATH` - Reports output path override

## Report Formats

### JSON Report
Structured data suitable for CI/CD pipelines and programmatic processing:

```json
{
  "scan_timestamp": "2025-11-17T01:10:55.945707",
  "summary": {
    "total_findings": 47,
    "by_severity": {
      "CRITICAL": 2,
      "HIGH": 16,
      "MEDIUM": 5,
      "LOW": 6,
      "INFO": 18
    },
    "by_tool": {
      "tfsec": 13,
      "checkov": 18,
      "trivy": 13
    }
  },
  "findings": [...]
}
```

### HTML Report
Interactive dashboard with:
- Summary statistics and metrics
- Color-coded severity badges
- Grouped findings by severity
- Detailed remediation guidance
- Responsive design

### Markdown Report
Documentation-ready format with:
- Scan summary and statistics
- Findings organized by severity
- Code locations and line numbers
- Remediation recommendations

## GitHub Action

AWS Quick Assess is available as a GitHub Action for seamless CI/CD integration with GitHub Code Scanning support.

### Basic Usage

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AWS Quick Assess
        uses: crofton-cloud/aws-quick-assess@v1
        with:
          scan-path: '.'
          fail-on-severity: 'HIGH'
```

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `scan-path` | Path to scan (relative to repository root) | `.` |
| `config-path` | Path to custom config.yaml file | `''` |
| `output-formats` | Comma-separated formats (json,html,markdown,sarif) | `json,sarif` |
| `fail-on-severity` | Fail if findings at this level or above (CRITICAL,HIGH,MEDIUM,LOW,INFO,NONE) | `HIGH` |
| `snyk-token` | Snyk API token for enhanced scanning | `''` |
| `upload-sarif` | Upload SARIF results to GitHub Code Scanning | `true` |
| `verbose` | Enable verbose output | `false` |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of security findings |
| `critical-count` | Number of CRITICAL severity findings |
| `high-count` | Number of HIGH severity findings |
| `medium-count` | Number of MEDIUM severity findings |
| `low-count` | Number of LOW severity findings |
| `report-path` | Path to the generated report directory |
| `sarif-path` | Path to the SARIF report file |
| `scan-status` | Scan result status (passed/failed/error) |

### Full Example with Code Scanning

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AWS Quick Assess
        id: scan
        uses: crofton-cloud/aws-quick-assess@v1
        with:
          scan-path: '.'
          output-formats: 'json,html,sarif'
          fail-on-severity: 'HIGH'
          snyk-token: ${{ secrets.SNYK_TOKEN }}

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-path }}

      - name: Upload reports as artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: .aws-quick-assess-reports/
          retention-days: 30

      - name: Check scan results
        run: |
          echo "Total findings: ${{ steps.scan.outputs.findings-count }}"
          echo "Critical: ${{ steps.scan.outputs.critical-count }}"
          echo "High: ${{ steps.scan.outputs.high-count }}"
```

### Scanning a Subdirectory

```yaml
- name: Scan only infrastructure directory
  uses: crofton-cloud/aws-quick-assess@v1
  with:
    scan-path: 'infrastructure/terraform'
    fail-on-severity: 'MEDIUM'
```

### Using Custom Configuration

```yaml
- name: Scan with custom config
  uses: crofton-cloud/aws-quick-assess@v1
  with:
    config-path: '.github/aws-quick-assess-config.yaml'
```

### Don't Fail on Findings

```yaml
- name: Scan without failing
  uses: crofton-cloud/aws-quick-assess@v1
  with:
    fail-on-severity: 'NONE'
```

## Examples

### GitLab CI

```yaml
security-scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker run --rm
        -v $CI_PROJECT_DIR:/repo:ro
        -v $CI_PROJECT_DIR/reports:/app/reports
        aws-quick-assess:latest
        scan-local --repo-path /repo --format json
  artifacts:
    paths:
      - reports/
    when: always
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: aws-quick-assess
        name: AWS Quick Assess
        entry: ./scripts/run-local-scan.sh
        language: script
        pass_filenames: false
```

## Exit Codes

- `0` - Scan completed successfully, no issues at or above fail threshold
- `1` - Scan failed due to error
- `2` - Scan completed, findings at or above fail threshold detected

## Understanding Findings

### Severity Levels

| Level | Description | Typical Issues |
|-------|-------------|----------------|
| **CRITICAL** | Immediate security risk | Exposed secrets, publicly accessible resources |
| **HIGH** | Serious security concern | Missing encryption, overly permissive access |
| **MEDIUM** | Security best practice violation | Disabled logging, weak configurations |
| **LOW** | Minor security improvement | Outdated patterns, optimization opportunities |
| **INFO** | Informational | Code style, documentation |

### Common Findings

**CRITICAL:**
- Hardcoded secrets (API keys, passwords)
- Security groups open to 0.0.0.0/0
- Public S3 buckets

**HIGH:**
- Unencrypted storage (S3, EBS, RDS)
- Missing IMDSv2 on EC2 instances
- Disabled CloudTrail logging
- IAM policies with wildcards

**MEDIUM:**
- Missing tags
- Disabled versioning
- Insecure protocols (HTTP, TLS 1.0)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AWS Quick Assess                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐      ┌─────────────────────────┐          │
│  │   CLI        │─────→│  Repository Detector    │          │
│  └──────────────┘      └─────────────────────────┘          │
│         │                         │                          │
│         ▼                         ▼                          │
│  ┌──────────────────────────────────────────────┐           │
│  │           Scanner Orchestrator                │           │
│  ├──────────────────────────────────────────────┤           │
│  │  ┌──────────────┐  ┌──────────────┐         │           │
│  │  │  Terraform   │  │ CloudFormation│         │           │
│  │  │   Scanner    │  │    Scanner    │         │           │
│  │  └──────────────┘  └──────────────┘         │           │
│  │  ┌──────────────┐  ┌──────────────┐         │           │
│  │  │   Python     │  │   Secrets    │         │           │
│  │  │   Scanner    │  │   Scanner    │         │           │
│  │  └──────────────┘  └──────────────┘         │           │
│  └──────────────────────────────────────────────┘           │
│         │                                                    │
│         ▼                                                    │
│  ┌──────────────────────────────────────────────┐           │
│  │        Report Aggregator                      │           │
│  │  • Deduplication                              │           │
│  │  • Normalization                              │           │
│  │  • Severity Analysis                          │           │
│  └──────────────────────────────────────────────┘           │
│         │                                                    │
│         ▼                                                    │
│  ┌────────────┬─────────────┬──────────────┐               │
│  │   JSON     │    HTML     │   Markdown   │               │
│  │ Formatter  │  Formatter  │  Formatter   │               │
│  └────────────┴─────────────┴──────────────┘               │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## File Structure

```
aws-quick-assess/
├── .github/
│   └── workflows/
│       ├── ci.yml               # CI workflow for this repo
│       └── example-usage.yml    # Example workflow for users
├── config/
│   └── config.yaml              # Main configuration file
├── src/
│   ├── scanner_base.py          # Base scanner class
│   ├── config_loader.py         # Configuration management
│   ├── repo_detector.py         # Repository type detection
│   ├── report_aggregator.py     # Finding aggregation
│   ├── main.py                  # CLI entry point
│   ├── scanners/
│   │   ├── terraform_scanner.py
│   │   ├── cloudformation_scanner.py
│   │   ├── python_scanner.py
│   │   └── secrets_scanner.py
│   └── formatters/
│       ├── json_formatter.py
│       ├── html_formatter.py
│       ├── markdown_formatter.py
│       └── sarif_formatter.py   # GitHub Code Scanning format
├── scripts/
│   ├── run-local-scan.sh        # Helper script for local scans
│   ├── run-aws-scan.sh          # Helper script for AWS scans
│   └── run-full-scan.sh         # Helper script for full scans
├── tests/
│   └── fixtures/                # Test data
├── action.yml                   # GitHub Action definition
├── entrypoint.sh                # GitHub Action entrypoint
├── Dockerfile                   # Multi-stage Docker build
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## Troubleshooting

### Common Issues

**"No findings detected" but I know there are issues:**
- Check if the scanner is enabled in config.yaml
- Verify the repository path is correct
- Ensure files have proper extensions (.tf, .yaml, etc.)

**"Permission denied" errors:**
- Ensure Docker has access to mounted volumes
- Check file permissions on repository and output directories

**Scanners timing out:**
- Increase `timeout_per_scanner` in config.yaml
- Run scanners individually to identify slow tools
- Consider disabling optional scanners

**High memory usage:**
- Reduce `max_workers` in config.yaml
- Disable `parallel` execution
- Scan smaller directory subsets

## Development

### Adding a New Scanner

1. Create scanner class in `src/scanners/`:
```python
from src.scanner_base import ScannerBase, Finding, Severity

class MyScanner(ScannerBase):
    def is_applicable(self, path: str) -> bool:
        # Return True if scanner should run
        pass

    def run(self, path: str) -> List[Finding]:
        # Execute scanner and return findings
        pass

    def parse_output(self, output: str, stderr: str, return_code: int) -> List[Finding]:
        # Parse scanner output
        pass
```

2. Add tool installation to Dockerfile
3. Update `src/main.py` to include new scanner
4. Add configuration options to `config/config.yaml`
5. Update tests

### Running Tests

```bash
# Unit tests
pytest tests/

# Integration tests
pytest tests/integration/

# With coverage
pytest --cov=src --cov-report=html
```

## Roadmap

- [x] Terraform scanning
- [x] CloudFormation scanning
- [x] Python scanning (Bandit, Safety)
- [x] Secrets detection
- [x] Multi-format reporting
- [x] Rule exclusions
- [x] Path exclusions
- [x] GitHub Action
- [x] SARIF output format (GitHub Code Scanning)
- [ ] AWS live scanning (Prowler integration)
- [ ] CDK scanning
- [ ] npm/Node.js dependency scanning
- [ ] Custom policy definitions
- [ ] Baseline/suppression files
- [ ] Trend analysis and historical tracking

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the terms specified in [LICENSE](LICENSE).

## Support

- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/croftoncloud/aws-quick-assess/issues)
- **Documentation**: See [docs/](docs/) for detailed guides
- **CLAUDE.md**: For development with Claude Code

## Acknowledgments

This tool integrates and orchestrates the following open-source security tools:
- [Terraform](https://www.terraform.io/)
- [TFLint](https://github.com/terraform-linters/tflint)
- [tfsec](https://github.com/aquasecurity/tfsec)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Checkov](https://github.com/bridgecrewio/checkov)
- [cfn-lint](https://github.com/aws-cloudformation/cfn-lint)
- [cfn-nag](https://github.com/stelligent/cfn_nag)
- [Bandit](https://github.com/PyCQA/bandit)
- [Safety](https://github.com/pyupio/safety)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [Snyk](https://snyk.io/)

---

**Built with ❤️ by Crofton Cloud**

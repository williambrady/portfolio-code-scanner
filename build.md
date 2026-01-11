# SDLC Code Scanner - Build Steps

This document enumerates all steps required to build the SDLC Code Scanner system as defined in `plan.md`.

---

## Phase 1: Project Foundation & Setup

### 1.1 Project Structure
- [ ] Create Python project structure
  - [ ] Create `src/` directory for main application code
  - [ ] Create `tests/` directory for unit and integration tests
  - [ ] Create `config/` directory for configuration files
  - [ ] Create `reports/` directory for scan output
  - [ ] Create `scripts/` directory for utility scripts

### 1.2 Configuration Files
- [ ] Create `config.yaml` with:
  - [ ] Docker base image specification
  - [ ] Dockerfile path specification
  - [ ] Tool enable/disable flags for each scanner
  - [ ] Severity thresholds (Critical/High/Medium/Low)
  - [ ] Output format preferences
  - [ ] AWS region settings
  - [ ] Repository path settings
- [ ] Create `requirements.txt` for Python dependencies
- [ ] Create `.env.example` for environment variable template

### 1.3 Docker Setup
- [ ] Create `Dockerfile` with:
  - [ ] Base image (configurable from config.yaml)
  - [ ] Python runtime installation
  - [ ] All scanning tool installations (see Phase 2)
  - [ ] Working directory setup
  - [ ] Volume mount points for repository and reports
  - [ ] Environment variable declarations
- [ ] Create `.dockerignore` file
- [ ] Create `docker-compose.yml` for local development (optional)

---

## Phase 2: Scanner Tool Integration

### 2.1 Terraform Scanners
- [x] Install and configure Terraform CLI
- [x] Install and configure TFLint
- [x] Install and configure Checkov (Terraform support)
- [x] Install and configure tfsec
- [x] Install and configure Trivy (IaC mode)

### 2.2 CloudFormation Scanners
- [x] Install and configure cfn-lint
- [x] Install and configure cfn-nag
- [x] Install and configure Checkov (CFN support)

### 2.3 Python Scanners
- [x] Install and configure Bandit
- [x] Install and configure Safety
- [x] Install and configure Pylint

### 2.4 npm/Node.js Scanners
- [x] Install and configure npm CLI
- [x] Install and configure Snyk CLI

### 2.5 Secrets Detection
- [x] Install and configure Gitleaks

---

## Phase 3: Core Python Application Development

### 3.1 Configuration Management Module
- [ ] Create `config_loader.py`:
  - [ ] YAML parser for config.yaml
  - [ ] Environment variable loader
  - [ ] Configuration validation
  - [ ] Default value handling

### 3.2 Scanner Orchestration Module
- [ ] Create `scanner_base.py`:
  - [ ] Abstract base class for all scanners
  - [ ] Common interface (run, parse_output, get_findings)
  - [ ] Error handling framework
  - [ ] Logging framework

### 3.3 IaC Scanner Implementations
- [x] Create `terraform_scanner.py`:
  - [x] terraform fmt checker
  - [x] terraform validate runner
  - [x] TFLint integration
  - [x] Checkov integration
  - [x] tfsec integration
  - [x] Trivy integration
  - [x] Output parser for each tool
- [x] Create `cloudformation_scanner.py`:
  - [x] cfn-lint integration
  - [x] cfn-nag integration
  - [x] Checkov integration
  - [x] Output parser for each tool
- [x] Create `python_scanner.py`:
  - [x] Bandit integration
  - [x] Safety integration
  - [x] Pylint integration
  - [x] Output parser for each tool
- [x] Create `npm_scanner.py`:
  - [x] npm audit integration
  - [x] Snyk integration
  - [x] Output parser for each tool

### 3.4 Secrets Scanner Implementation
- [x] Create `secrets_scanner.py`:
  - [x] Gitleaks integration
  - [x] Output parser

### 3.5 Repository Detection Module
- [ ] Create `repo_detector.py`:
  - [ ] Detect Terraform files (.tf)
  - [ ] Detect CloudFormation files (.yaml, .json, .template)
  - [ ] Detect CDK projects (cdk.json, package.json with aws-cdk)
  - [ ] Detect npm projects (package.json)
  - [ ] Detect language types (TypeScript, Python, Java, .NET)
  - [ ] Return list of applicable scanners

---

## Phase 4: Reporting & Output

### 4.1 Report Aggregation Module
- [ ] Create `report_aggregator.py`:
  - [ ] Collect findings from all scanners
  - [ ] Normalize finding format across tools
  - [ ] Deduplicate findings
  - [ ] Categorize by severity (Critical/High/Medium/Low)
  - [ ] Categorize by layer (Linting/Security/Dependencies/Secrets)
  - [ ] Calculate statistics and metrics

### 4.2 Report Formatters
- [x] Create `formatters/json_formatter.py`:
  - [x] JSON output with full details
- [x] Create `formatters/html_formatter.py`:
  - [x] HTML report with styling
  - [x] Summary dashboard
  - [x] Detailed findings tables
- [x] Create `formatters/markdown_formatter.py`:
  - [x] Markdown report for documentation
- [x] Create `formatters/sarif_formatter.py`:
  - [x] SARIF format for GitHub Code Scanning integration

### 4.3 Report Output Module
- [ ] Create `report_writer.py`:
  - [ ] Write reports to file system
  - [ ] Support multiple output formats simultaneously
  - [ ] Timestamp and version reports
  - [ ] Archive old reports

---

## Phase 5: Main Application & CLI

### 5.1 Command-Line Interface
- [ ] Create `cli.py`:
  - [ ] Argument parser setup
  - [ ] Commands:
    - [ ] `scan-local` - Scan local repository
    - [ ] `list-tools` - List available scanning tools
    - [ ] `validate-config` - Validate config.yaml
  - [ ] Options:
    - [ ] `--config` - Path to config file
    - [ ] `--repo-path` - Path to repository
    - [ ] `--output-dir` - Output directory for reports
    - [ ] `--format` - Report format(s)
    - [ ] `--severity-threshold` - Minimum severity to report
    - [ ] `--fail-on` - Severity level to exit with error code
    - [ ] `--tools` - Specific tools to run
    - [ ] `--exclude-tools` - Tools to skip
    - [ ] `--verbose` - Verbose logging
    - [ ] `--quiet` - Minimal output

### 5.2 Main Application Logic
- [ ] Create `main.py`:
  - [ ] Load configuration
  - [ ] Validate environment and credentials
  - [ ] Detect repository type(s)
  - [ ] Initialize applicable scanners
  - [ ] Execute scanners in parallel where possible
  - [ ] Aggregate results
  - [ ] Generate reports
  - [ ] Exit with appropriate code based on findings

### 5.3 Logging & Error Handling
- [ ] Create `logger.py`:
  - [ ] Configure Python logging
  - [ ] Log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  - [ ] Log to console and file
  - [ ] Structured logging format
- [ ] Create `exceptions.py`:
  - [ ] Custom exception classes
  - [ ] Scanner-specific exceptions
  - [ ] Configuration exceptions
  - [ ] AWS credential exceptions

---

## Phase 6: Testing

### 6.1 Unit Tests
- [ ] Create `tests/test_config_loader.py`
- [ ] Create `tests/test_repo_detector.py`
- [ ] Create `tests/test_terraform_scanner.py`
- [ ] Create `tests/test_cloudformation_scanner.py`
- [ ] Create `tests/test_python_scanner.py`
- [ ] Create `tests/test_npm_scanner.py`
- [ ] Create `tests/test_secrets_scanner.py`
- [ ] Create `tests/test_report_aggregator.py`
- [ ] Create `tests/test_formatters.py`
- [ ] Create `tests/test_cli.py`

### 6.2 Integration Tests
- [ ] Create `tests/integration/test_terraform_workflow.py`
- [ ] Create `tests/integration/test_cloudformation_workflow.py`
- [ ] Create `tests/integration/test_python_workflow.py`
- [ ] Create `tests/integration/test_npm_workflow.py`
- [ ] Create `tests/integration/test_full_scan.py`

### 6.3 Test Fixtures
- [ ] Create `tests/fixtures/terraform/` with sample .tf files
- [ ] Create `tests/fixtures/cloudformation/` with sample templates
- [ ] Create `tests/fixtures/python/` with sample Python files
- [ ] Create `tests/fixtures/npm/` with sample package.json files
- [ ] Create `tests/fixtures/secrets/` with test secrets (safe)
- [ ] Create `tests/fixtures/config/` with test config.yaml files

### 6.4 Test Configuration
- [ ] Create `pytest.ini` or `pyproject.toml` for pytest configuration
- [ ] Create `tests/conftest.py` for shared fixtures
- [ ] Configure test coverage reporting
- [ ] Set up test data cleanup

---

## Phase 7: Docker Build & Deployment

### 7.1 Docker Image Build
- [ ] Build Docker image with all tools installed
- [ ] Verify all scanners are accessible in container
- [ ] Optimize image size (multi-stage build if needed)
- [ ] Tag image appropriately
- [ ] Test image locally

### 7.2 Docker Run Scripts
- [ ] Create `scripts/run-local-scan.sh`:
  - [ ] Mount local repository
  - [ ] Mount output directory
  - [ ] Pass environment variables
  - [ ] Run scan-local command
- [ ] Create Windows equivalents (.bat or .ps1)

### 7.3 Docker Compose (Optional)
- [ ] Configure services in docker-compose.yml
- [ ] Set up volume mounts
- [ ] Configure environment variables
- [ ] Add health checks

---

## Phase 8: Documentation

### 8.1 User Documentation
- [ ] Update `README.md`:
  - [ ] Project overview
  - [ ] Quick start guide
  - [ ] Installation instructions
  - [ ] Usage examples
  - [ ] Configuration guide
  - [ ] Troubleshooting
- [ ] Create `docs/CONFIGURATION.md`:
  - [ ] Detailed config.yaml reference
  - [ ] Environment variables reference
  - [ ] Tool-specific configuration
- [ ] Create `docs/SCANNERS.md`:
  - [ ] List of all integrated scanners
  - [ ] What each scanner checks
  - [ ] How to enable/disable scanners
- [ ] Create `docs/REPORTS.md`:
  - [ ] Report format descriptions
  - [ ] How to interpret findings
  - [ ] Severity level definitions

### 8.2 Developer Documentation
- [ ] Create `docs/DEVELOPMENT.md`:
  - [ ] Development environment setup
  - [ ] How to add new scanners
  - [ ] Code structure overview
  - [ ] Testing guidelines
- [ ] Create `docs/ARCHITECTURE.md`:
  - [ ] System architecture diagram
  - [ ] Component descriptions
  - [ ] Data flow diagrams
- [ ] Add inline code documentation (docstrings)
- [ ] Generate API documentation (Sphinx or similar)

### 8.3 CI/CD Documentation
- [ ] Create `docs/CICD.md`:
  - [ ] GitHub Actions integration
  - [ ] GitLab CI integration
  - [ ] Jenkins integration
  - [ ] Azure DevOps integration
  - [ ] Pre-commit hook setup

---

## Phase 9: CI/CD Integration Examples

### 9.1 GitHub Actions
- [ ] Create `.github/workflows/scan-pr.yml`:
  - [ ] Trigger on pull requests
  - [ ] Run local repository scan
  - [ ] Comment results on PR
  - [ ] Fail on Critical/High findings
- [ ] Create `.github/workflows/scan-main.yml`:
  - [ ] Trigger on push to main
  - [ ] Run local repository scan
  - [ ] Upload reports as artifacts
  - [ ] Send notifications

### 9.2 Pre-commit Hooks
- [ ] Create `.pre-commit-config.yaml`:
  - [ ] Run secrets detection
  - [ ] Run basic linting
  - [ ] Run formatting checks
- [ ] Create setup script for pre-commit hooks

### 9.3 GitLab CI (Optional)
- [ ] Create `.gitlab-ci.yml` example
- [ ] Configure stages and jobs
- [ ] Artifact handling

---

## Phase 10: Advanced Features (Optional)

### 10.1 SBOM Generation
- [ ] Integrate CycloneDX for SBOM generation
- [ ] Integrate Syft for SBOM generation
- [ ] Add SBOM to report output

### 10.2 Policy as Code
- [ ] Create custom OPA policies directory
- [ ] Create custom cfn-guard rules directory
- [ ] Create custom Checkov policies directory
- [ ] Document policy creation process

### 10.3 Baseline & Suppression
- [ ] Create baseline file format
- [ ] Implement baseline comparison
- [ ] Implement finding suppression
- [ ] Create suppression file format

### 10.4 Trend Analysis
- [ ] Store historical scan results
- [ ] Compare scans over time
- [ ] Generate trend reports
- [ ] Visualize improvements/regressions

### 10.5 Integration with External Tools
- [ ] Jira integration (create tickets)
- [ ] Slack/Teams notifications
- [ ] Email notifications

---

## Phase 11: Quality Assurance & Validation

### 11.1 Code Quality
- [ ] Run linters on Python code (pylint, flake8, black)
- [ ] Run type checker (mypy)
- [ ] Fix all linting issues
- [ ] Ensure code coverage > 80%

### 11.2 Security Validation
- [ ] Run Bandit on Python code
- [ ] Run safety check on dependencies
- [ ] Scan Docker image for vulnerabilities
- [ ] Review and fix security issues

### 11.3 Performance Testing
- [ ] Test with large repositories
- [ ] Measure scan execution time
- [ ] Optimize slow scanners
- [ ] Implement parallel execution where possible

### 11.4 End-to-End Testing
- [ ] Test against real Terraform repositories
- [ ] Test against real CloudFormation stacks
- [ ] Test against real Python projects
- [ ] Validate all report formats
- [ ] Test error handling and edge cases

---

## Phase 12: Release Preparation

### 12.1 Versioning
- [ ] Set up semantic versioning
- [ ] Create `VERSION` file
- [ ] Tag initial release

### 12.2 Distribution
- [ ] Publish Docker image to registry (Docker Hub, ECR, etc.)
- [ ] Create release notes
- [ ] Create installation package (pip, if applicable)

### 12.3 License & Legal
- [ ] Add LICENSE file
- [ ] Add NOTICE file for third-party tools
- [ ] Review license compatibility of all tools

---

## Phase 13: Maintenance & Operations

### 13.1 Monitoring
- [ ] Set up logging aggregation
- [ ] Create dashboard for scan metrics
- [ ] Set up alerts for failures

### 13.2 Updates
- [ ] Create process for updating scanner tools
- [ ] Create process for updating base Docker image
- [ ] Document update procedures

### 13.3 Support
- [ ] Create issue templates
- [ ] Create contributing guidelines
- [ ] Set up discussion forum or chat

---

## Appendix: Tool Installation Commands

### Terraform Tools
```bash
# Terraform
wget https://releases.hashicorp.com/terraform/1.x.x/terraform_1.x.x_linux_amd64.zip
unzip terraform_1.x.x_linux_amd64.zip && mv terraform /usr/local/bin/

# TFLint
curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash

# tfsec
wget https://github.com/aquasecurity/tfsec/releases/download/vX.X.X/tfsec-linux-amd64
chmod +x tfsec-linux-amd64 && mv tfsec-linux-amd64 /usr/local/bin/tfsec

# Checkov
pip install checkov

# Trivy
wget https://github.com/aquasecurity/trivy/releases/download/vX.X.X/trivy_X.X.X_Linux-64bit.tar.gz
tar zxvf trivy_X.X.X_Linux-64bit.tar.gz && mv trivy /usr/local/bin/
```

### CloudFormation Tools
```bash
# cfn-lint
pip install cfn-lint

# cfn-nag
gem install cfn-nag

# cfn-guard
wget https://github.com/aws-cloudformation/cloudformation-guard/releases/download/X.X.X/cfn-guard-vX.X.X-ubuntu-latest.tar.gz
tar xzf cfn-guard-vX.X.X-ubuntu-latest.tar.gz && mv cfn-guard /usr/local/bin/
```

### CDK Tools
```bash
# AWS CDK
npm install -g aws-cdk

# cdk-nag
npm install -g cdk-nag
```

### Dependency Scanners
```bash
# Snyk
npm install -g snyk

# OWASP Dependency-Check
wget https://github.com/jeremylong/DependencyCheck/releases/download/vX.X.X/dependency-check-X.X.X-release.zip
unzip dependency-check-X.X.X-release.zip
```

### Secrets Detection
```bash
# Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/download/vX.X.X/gitleaks_X.X.X_linux_x64.tar.gz
tar xzf gitleaks_X.X.X_linux_x64.tar.gz && mv gitleaks /usr/local/bin/
```

---

## Success Criteria

- [x] All scanners successfully installed in Docker container
- [x] Can scan Terraform repositories and generate reports
- [x] Can scan CloudFormation templates and generate reports
- [x] Can scan Python projects and generate reports
- [x] Can scan npm projects and generate reports
- [x] Can detect secrets in repositories
- [x] Can generate reports in multiple formats (JSON, HTML, Markdown, SARIF)
- [ ] All tests passing with >80% coverage
- [x] Documentation complete and accurate
- [x] Docker image builds successfully
- [x] Can run via command-line with all options
- [x] Configuration via config.yaml works correctly
- [x] Environment variables properly passed and used
- [x] Error handling works for all failure scenarios
- [x] Performance acceptable for typical repositories


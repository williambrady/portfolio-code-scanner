# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SDLC Code Scanner is a Python-based security assessment utility for AWS infrastructure-as-code (IaC). It orchestrates multiple security scanning tools in a Docker container to provide comprehensive security analysis of Terraform, CloudFormation, Python, and npm-based projects.

## Architecture

### Core Components

**Scanner Orchestration Layer**
- `scanner_base.py`: Abstract base class defining the common interface for all scanners (run, parse_output, get_findings)
- Individual scanner implementations inherit from this base and wrap specific tools
- Scanners execute independently and return normalized findings

**Repository Detection**
- `repo_detector.py`: Automatically identifies IaC frameworks and languages in a repository
- Detects: Terraform (.tf), CloudFormation (.yaml/.json/.template), Python (.py), npm (package.json)
- Returns list of applicable scanners to run for that repository

**Report Aggregation Pipeline**
- `report_aggregator.py`: Collects findings from all scanners, normalizes format, deduplicates, categorizes by severity/layer
- Formatters in `formatters/`: Convert aggregated findings to JSON, HTML, Markdown, SARIF formats

**Configuration Management**
- `config.yaml`: Central configuration file for tool enablement, severity thresholds, output settings
- `config_loader.py`: Loads and validates YAML config and environment variables

**CLI Interface**
- `cli.py`: Command-line argument parser exposing commands: `scan-local`, `list-tools`, `validate-config`
- `main.py`: Main orchestration logic that coordinates detection → scanning → aggregation → reporting

### Implemented Scanners

**IaC Scanners**
- `terraform_scanner.py`: terraform fmt/validate, TFLint, Checkov, tfsec, Trivy
- `cloudformation_scanner.py`: cfn-lint, cfn-nag, Checkov

**Code Security Scanners**
- `python_scanner.py`: Bandit (code security), Safety (dependency vulnerabilities), Pylint (code quality)
- `npm_scanner.py`: npm audit, Snyk IaC scanning

**Secrets Detection**
- `secrets_scanner.py`: Gitleaks

## Development Commands

### Docker Operations

Build the Docker image:
```bash
docker build -t sdlc-code-scanner .
```

Run local repository scan:
```bash
./scripts/run-local-scan.sh /path/to/repo
```

### Testing

Run all tests:
```bash
pytest
```

Run specific test file:
```bash
pytest tests/test_terraform_scanner.py
```

Run with coverage:
```bash
pytest --cov=src --cov-report=html
```

Run integration tests:
```bash
pytest tests/integration/
```

### Code Quality

Run linters:
```bash
pylint src/
flake8 src/
black src/ --check
```

Format code:
```bash
black src/
```

Type checking:
```bash
mypy src/
```

Security scanning:
```bash
bandit -r src/
safety check
```

## Key Design Patterns

**Containerization**: All scanning tools run inside Docker to ensure consistent environments and avoid local installation conflicts. Repository and output directories are mounted as volumes.

**Configuration-Driven**: Tools can be enabled/disabled via `config.yaml` rather than code changes. Severity thresholds and output formats are also configurable.

**Parallel Execution**: Scanners execute concurrently where possible to minimize total scan time for large repositories.

**Normalized Output**: Each scanner returns findings in a common format regardless of the underlying tool's output format. The aggregator then deduplicates and categorizes these normalized findings.

**Layered Scanning Model**: Implements defense-in-depth with 4 layers:
1. Formatting & Linting (syntax, structure)
2. IaC Security & Policy (misconfigurations, compliance)
3. Dependency Security (CVEs, licenses)
4. Secrets Detection (credentials, tokens)

## Environment Variables

- `CONFIG_PATH`: Override default config.yaml path
- `LOG_LEVEL`: Set logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)

## File Structure Conventions

```
src/                    # Main application code
  scanners/             # Individual scanner implementations
  formatters/           # Report format generators
  config_loader.py      # Configuration management
  report_aggregator.py  # Finding normalization and aggregation
  cli.py                # Command-line interface
  main.py               # Main orchestration
tests/                  # Unit and integration tests
  fixtures/             # Test data (sample IaC files, configs)
  integration/          # End-to-end workflow tests
config/                 # Configuration files
  config.yaml           # Main configuration
reports/                # Scan output directory
scripts/                # Docker run scripts
docs/                   # Documentation
```

## Adding New Scanners

1. Create new scanner class in `src/scanners/` inheriting from `ScannerBase`
2. Implement required methods: `run()`, `parse_output()`, `get_findings()`
3. Add tool installation to Dockerfile
4. Add configuration options to `config.yaml`
5. Update `repo_detector.py` if scanner applies to specific file types
6. Create unit tests in `tests/test_<scanner_name>.py`
7. Add integration test in `tests/integration/`

## Important Notes

- All scanners must handle tool failures gracefully and return partial results
- Finding deduplication uses MD5 hash of (file, line, rule_id, message) to identify duplicates
- Severity levels follow: CRITICAL > HIGH > MEDIUM > LOW > INFO
- Exit codes: 0 (clean), 1 (error), 2 (findings at or above fail threshold)
- **Rule Exclusions**: Configure in config.yaml under `tools.<scanner>.exclude_rules` to suppress specific findings (e.g., false positives, known exceptions)
- **Path Exclusions**: Configure in config.yaml under `repository.excluded_paths` to skip directories like tests, fixtures, node_modules
- **Security Best Practices**:
  - Use `usedforsecurity=False` when using MD5 for non-cryptographic purposes
  - Use `tempfile` module instead of hardcoded `/tmp` paths
  - Container runs as non-root user (scanner:1000) for security

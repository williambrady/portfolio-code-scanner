# **Standard Code Scanning Practice for AWS Infrastructure (Terraform, CloudFormation, CDK, npm)**

This document defines a recommended, layered scanning standard for Infrastructure-as-Code (IaC) and supporting application code used to deploy AWS infrastructure.
It covers Terraform, CloudFormation, CDK, and npm-based tooling.

This project should create a python utility to be executed against a locally cloned repository. Recommendations for CI/CD pipelines should be considered as options for a scanning tool as well.

The end result is to report on all scan findings from local security tools.

Configuration options should be in config.yaml.

All code tests and execution should be done in a docker container.
The docker container should be built from a Dockerfile.
The docker container should be built from a base image that is specified in config.yaml.
The docker container should be built from a Dockerfile that is specified in config.yaml.
The docker container should be run locally for now.
Credentials for any systems should be passed in as environment variables.
For code scans, the docker container should be run against a locally cloned repository.

---

# **1. Layered Code Scanning Approach**

All repositories should adopt a multi-layer scanning model:

1. **Formatting & Linting**
   Enforce syntactic correctness and best-practice structure (fmt, lint, type checks).

2. **IaC Security & Policy-as-Code**
   Scan templates for cloud misconfigurations, insecure defaults, IAM risks, missing encryption/logging, and compliance misalignments.

3. **Dependency / Supply Chain Security**
   Scan all language dependencies (npm, pip, etc.) for known CVEs and license violations.

4. **Secrets Detection**
   Block commits containing access keys, tokens, passwords, or sensitive config.

5. **CI/CD Enforcement**
   All scanning layers run on:
   - Every Pull Request
   - Every commit to `main`
   - Pre-commit where possible
   Severity gates (e.g., fail on High/Critical) should be configurable per repo.

---

# **2. Stack-Specific Standards**

## **2.1 Terraform**

### **Local / Pre-Commit**
- `terraform fmt -check`
- `terraform validate`
- **TFLint** for style/provider linting

### **CI / PR Pipeline**
1. `terraform fmt -check`
2. `terraform validate`
3. **TFLint**
4. **Checkov**
5. **trivvy** (docker run aquasec/trivy)
6. Optional: **Terrascan**, **KICS**, **Regula**, **OPA/Conftest**

### **Notes**
- This combination balances syntax correctness, best practices, and deep policy analysis.
- Checkov + tfsec is the most common and broad coverage pairing today.

---

## **2.2 CloudFormation (CFN)**

### **Local / Pre-Commit**
- **cfn-lint** for structural validation

### **CI / PR Pipeline**
1. `cfn-lint`
2. **cfn-nag** for security issues (IAM *, open SGs, missing encryption, logging)
3. **Checkov** for additional policy/compliance coverage

### **Notes**
- AWS recommends running both linting and security scans on all CFN templates.
- You may also use CloudFormation Guard for custom policies.

---

## **2.3 AWS CDK (TypeScript, Python, Java, .NET)**

### **Local / Pre-Commit**
- Language linting (ESLint, pylint/flake8, etc.)
- Unit tests
- `cdk synth`

### **Security / Best Practices**
1. **cdk-nag** applied to CDK constructs
2. Run `cdk synth` output through:
   - `cfn-lint`
   - `cfn-nag`
   - Optional: Checkov

### **Notes**
- cdk-nag is the de facto standard for CDK best-practice checks.
- Always scan synthesized CloudFormation since that is the deployed artifact.

---

## **2.4 npm / Node.js (CDK apps, Lambda code, CLI tools)**

### **Local / Pre-Commit**
- ESLint
- TypeScript checks (if applicable)
- Unit tests
- `npm audit` (baseline)

### **CI / PR Pipeline**
1. `npm audit --production` (or `--omit=dev` per policy)
2. **Snyk** for deeper dependency scanning
3. **Dependabot** or **Renovate** for patch automation
4. Optional: **OWASP Dependency-Check** for SBOMs & universal dependency scanning

---

# **3. Top 20 Recommended Tools (Grouped by Benefit)**

---

## **A. IaC Linting & Best Practices (Terraform / CFN / CDK)**

1. **Terraform fmt & validate** – Formatter & syntax validator
2. **TFLint** – Terraform linting
3. **cfn-lint** – CloudFormation structural validation
4. **cdk-nag** – CDK best-practice and compliance rulesets
5. **CloudFormation Guard (cfn-guard)** – Policy-as-code for CFN
6. **OPA / Conftest** – Universal Rego-based policy evaluation

---

## **B. IaC Security Scanners (Misconfiguration + Compliance)**

7. **Checkov** – Multi-IaC security scanning (Terraform, CFN, K8s, etc.)
8. **tfsec** – Terraform security scanning
9. **Terrascan** – IaC misconfig detection (Terraform, CFN, K8s)
10. **KICS** – Multi-IaC misconfiguration detector
11. **Regula** – Rego-based compliance scanning for IaC
12. **Snyk IaC** – SaaS IaC misconfiguration & compliance analysis
13. **Trivy (IaC mode)** – Unified security scanning including IaC
14. **cfn-nag** – CloudFormation security scanning

---

## **C. Dependency & Supply Chain Security (npm / Multi-language)**

15. **npm audit** – Built-in dependency CVE scanning
16. **Snyk (dependencies)** – Advanced CVE detection + fix PRs + license checks
17. **OWASP Dependency-Check** – NVD-based dependency scanning and SBOM
18. **Dependabot** – Automated dependency update PRs
19. **Renovate** – Highly configurable dependency automation

---

## **D. Secrets Detection & Repo Hygiene**

20. **Gitleaks** – Secret scanning (tokens, passwords, AWS keys)
*(alternatives: TruffleHog, git-secrets)*

---

# **4. Standardized Workflow Summary**

### **Terraform**
- fmt → validate → TFLint → Checkov → tfsec

### **CloudFormation**
- cfn-lint → cfn-nag → Checkov

### **CDK**
- ESLint/pylint → tests → cdk-nag → synth → cfn-lint → cfn-nag → Checkov

### **npm / Node**
- ESLint → tests → npm audit → Snyk → Dependabot/Renovate

### **All Repos**
- Gitleaks for secrets scanning
- Optional Conftest/OPA for org-specific rules
- Fail on Critical/High; warn on Medium/Low

---

# **5. Optional Add-Ons**

- **SBOM generation** (CycloneDX, Syft) for supply-chain visibility
- **Artifact signing** (cosign)
- **Pre-commit hooks** to shift-left scanning
- **Central policy repository** for OPA, cfn-guard, or Checkov custom rules

---

If you'd like, I can also generate this as:

- A formal **security standard** (with versioning + compliance statements)
- A **Word document**
- A **GitHub README**
- Or a **Confluence-ready page**

Just tell me the format you want.

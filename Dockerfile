# SDLC Code Scanner - Multi-stage Dockerfile
# Installs all IaC security scanning tools in a single container
# Compatible with GitHub Actions

FROM python:3.11-slim as base

# GitHub Actions labels
LABEL org.opencontainers.image.source="https://github.com/crofton-cloud/sdlc-code-scanner"
LABEL org.opencontainers.image.description="Security scanner for AWS Infrastructure-as-Code"
LABEL org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    unzip \
    tar \
    gnupg \
    ca-certificates \
    build-essential \
    ruby \
    ruby-dev \
    nodejs \
    npm \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# ========================================
# Install Terraform
# ========================================
ARG TERRAFORM_VERSION=1.6.6
RUN wget -q https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip && \
    unzip terraform_${TERRAFORM_VERSION}_linux_amd64.zip && \
    mv terraform /usr/local/bin/ && \
    rm terraform_${TERRAFORM_VERSION}_linux_amd64.zip && \
    terraform --version

# ========================================
# Install TFLint
# ========================================
ARG TFLINT_VERSION=0.50.3
RUN wget -q https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_linux_amd64.zip && \
    unzip tflint_linux_amd64.zip && \
    mv tflint /usr/local/bin/ && \
    rm tflint_linux_amd64.zip && \
    tflint --version

# ========================================
# Install tfsec
# ========================================
ARG TFSEC_VERSION=1.28.5
RUN wget -q https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64 && \
    chmod +x tfsec-linux-amd64 && \
    mv tfsec-linux-amd64 /usr/local/bin/tfsec && \
    tfsec --version

# ========================================
# Install Trivy
# ========================================
ARG TRIVY_VERSION=0.48.3
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz && \
    tar zxvf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz && \
    mv trivy /usr/local/bin/ && \
    rm trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz && \
    trivy --version

# ========================================
# Install Terrascan (Optional)
# ========================================
ARG TERRASCAN_VERSION=1.18.11
RUN wget -q https://github.com/tenable/terrascan/releases/download/v${TERRASCAN_VERSION}/terrascan_${TERRASCAN_VERSION}_Linux_x86_64.tar.gz && \
    tar -xzf terrascan_${TERRASCAN_VERSION}_Linux_x86_64.tar.gz && \
    mv terrascan /usr/local/bin/ && \
    rm terrascan_${TERRASCAN_VERSION}_Linux_x86_64.tar.gz && \
    terrascan version

# ========================================
# CloudFormation Guard - Not implemented yet
# ========================================
# ARG CFN_GUARD_VERSION=3.1.1
# RUN wget https://github.com/aws-cloudformation/cloudformation-guard/releases/download/${CFN_GUARD_VERSION}/cfn-guard-v${CFN_GUARD_VERSION}-ubuntu-latest.tar.gz && \
#     tar -xzf cfn-guard-v${CFN_GUARD_VERSION}-ubuntu-latest.tar.gz -C /tmp/ && \
#     find /tmp -name "cfn-guard" -type f -executable -exec mv {} /usr/local/bin/ \; && \
#     rm -f cfn-guard-v${CFN_GUARD_VERSION}-ubuntu-latest.tar.gz && \
#     cfn-guard --version || echo "cfn-guard installed but version check failed"

# ========================================
# Install Gitleaks
# ========================================
ARG GITLEAKS_VERSION=8.18.1
RUN wget -q https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz && \
    tar xzf gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    rm gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz && \
    gitleaks version

# ========================================
# Install Ruby gems (cfn-nag)
# ========================================
RUN gem install cfn-nag && \
    cfn_nag --version

# ========================================
# Install Node.js/npm tools
# ========================================
RUN npm install -g \
    aws-cdk \
    snyk \
    eslint \
    @typescript-eslint/parser \
    @typescript-eslint/eslint-plugin \
    cdk-nag

# Verify installations
RUN cdk --version && \
    snyk --version && \
    eslint --version

# ========================================
# Install Python dependencies
# ========================================
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Verify Python tool installations
RUN checkov --version && \
    cfn-lint --version

# ========================================
# Copy application code
# ========================================
COPY src/ ./src/
COPY config/ ./config/
COPY entrypoint.sh ./entrypoint.sh

# Create necessary directories and make entrypoint executable
RUN mkdir -p /app/reports /app/logs /repo && \
    chmod +x /app/entrypoint.sh

# Set up volumes
VOLUME ["/repo", "/app/reports", "/app/logs"]

# Environment variables
ENV PYTHONPATH=/app \
    CONFIG_PATH=/app/config/config.yaml \
    LOG_LEVEL=INFO

# Note: Running as root for GitHub Actions compatibility
# The workspace volume permissions require root access to write reports
# For local usage with enhanced security, use: docker run --user 1000:1000 ...

# Default command
ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--help"]

#!/bin/bash
# AWS Quick Assess - AWS Account Scan
# Usage: ./scripts/run-aws-scan.sh
# Requires: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION environment variables

set -e

OUTPUT_DIR="${1:-./reports}"
CONFIG_FILE="${2:-./config/config.yaml}"

echo "AWS Quick Assess - AWS Account Scan"
echo "===================================="
echo "AWS Region: ${AWS_REGION:-us-east-1}"
echo "Output: $OUTPUT_DIR"
echo "Config: $CONFIG_FILE"
echo ""

# Check for AWS credentials
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
  echo "ERROR: AWS credentials not set."
  echo "Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
  exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Run the Docker container
docker run --rm \
  -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
  -e AWS_REGION="${AWS_REGION:-us-east-1}" \
  -e AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-}" \
  -v "$(realpath "$OUTPUT_DIR"):/app/reports" \
  -v "$(realpath "$CONFIG_FILE"):/app/config/config.yaml:ro" \
  aws-quick-assess:latest \
  scan-aws \
  --output-dir /app/reports

echo ""
echo "Scan complete! Reports saved to: $OUTPUT_DIR"

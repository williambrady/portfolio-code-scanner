#!/bin/bash
# AWS Quick Assess - Local Repository Scan
# Usage: ./scripts/run-local-scan.sh /path/to/repo

set -e

REPO_PATH="${1:-.}"
OUTPUT_DIR="${2:-./reports}"
CONFIG_FILE="${3:-./config/config.yaml}"

echo "AWS Quick Assess - Local Repository Scan"
echo "========================================"
echo "Repository: $REPO_PATH"
echo "Output: $OUTPUT_DIR"
echo "Config: $CONFIG_FILE"
echo ""

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Extract repository name from path for reporting
REPO_NAME=$(basename "$(realpath "$REPO_PATH")")

# Build Docker run command with optional environment variables
DOCKER_ARGS=()

# Pass repository name for reporting
DOCKER_ARGS+=(-e "REPO_NAME=$REPO_NAME")

# Pass SNYK_AUTH if set
if [ -n "$SNYK_AUTH" ]; then
  DOCKER_ARGS+=(-e "SNYK_AUTH=$SNYK_AUTH")
  echo "Snyk authentication enabled"
fi

# Run the Docker container
docker run --rm \
  "${DOCKER_ARGS[@]}" \
  -v "$(realpath "$REPO_PATH"):/repo:ro" \
  -v "$(realpath "$OUTPUT_DIR"):/app/reports" \
  -v "$(realpath "$CONFIG_FILE"):/app/config/config.yaml:ro" \
  aws-quick-assess:latest \
  scan-local \
  --repo-path /repo \
  --output-dir /app/reports \
  --format json --format html --format markdown

echo ""
echo "Scan complete! Reports saved to: $OUTPUT_DIR"

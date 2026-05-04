#!/usr/bin/env bash
# KIT-MCP Server — Docker entrypoint
# Passes all CLI arguments directly to the kit-mcp CLI.
# Supports environment variable injection for sensitive values.
#
# Environment variables:
#   KIT_MCP_PASSWORD   — injects --password value (avoids CLI history)
#
# Examples:
#   docker run --rm -i kit-mcp --host 10.0.0.5 --user admin --auth password
#   docker run --rm -i -e KIT_MCP_PASSWORD=s3cr3t kit-mcp --host 10.0.0.5 --user admin --auth password

set -euo pipefail

exec kit-mcp "$@"

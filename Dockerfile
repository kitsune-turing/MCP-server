# ─────────────────────────────────────────────
#  KIT-MCP Server — Docker image
#  Multi-stage: builder (deps + wheel) → runtime (slim)
# ─────────────────────────────────────────────

# ── Stage 1: Builder ──────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only dependency manifests first (layer cache)
COPY pyproject.toml ./
COPY src/ ./src/

# Build wheel
RUN pip install --upgrade pip hatchling \
 && pip wheel --no-deps --wheel-dir /wheels .

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="KIT-MCP Generic Server" \
      org.opencontainers.image.description="MCP server for SSH/Telnet/TCP connections" \
      org.opencontainers.image.source="https://github.com/your-org/KIT-mcp-server"

# Non-root user for security
RUN useradd --create-home --shell /bin/bash mcp

WORKDIR /app

# Install runtime dependencies from pre-built wheels
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links /wheels kit-mcp-server \
 && rm -rf /wheels

# Entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER mcp

# SSH keys mount point (read-only at runtime)
VOLUME ["/home/mcp/.ssh"]

# The container exposes no network port — it communicates via stdio (MCP transport)
# Run with:
#   docker run --rm -i \
#     -v ~/.ssh:/home/mcp/.ssh:ro \
#     kit-mcp \
#     --host 192.168.1.10 --user pi --auth key_file --key /home/mcp/.ssh/id_ed25519

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]

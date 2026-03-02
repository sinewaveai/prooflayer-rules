# =============================================================================
# ProofLayer Runtime Security - Dockerfile
# =============================================================================
# Multi-stage build for minimal production image.
#
# Build:   docker build -t prooflayer .
# Run:     docker run --rm prooflayer scan --tool "run_command" --args '{"cmd":"ls"}'
# =============================================================================

# --------------- build stage ------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt setup.py README.md ./
COPY prooflayer/ prooflayer/

RUN pip install --no-cache-dir --prefix=/install .

# --------------- runtime stage ----------------------------------------------
FROM python:3.12-slim

LABEL maintainer="Sinewave AI <divya@sinewave.ai>"
LABEL description="ProofLayer Runtime Security - MCP prompt injection firewall"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code (needed for packaged rules)
COPY --from=builder /app/prooflayer /app/prooflayer

# Create non-root user
RUN useradd -r -s /bin/false prooflayer \
    && mkdir -p /app/security-reports /app/rules \
    && chown -R prooflayer:prooflayer /app/security-reports /app/rules

USER prooflayer

EXPOSE 9090

ENTRYPOINT ["prooflayer"]

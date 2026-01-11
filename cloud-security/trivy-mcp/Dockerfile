# Trivy MCP Server
# Security scanning for containers, filesystems, and IaC

FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="Trivy MCP Server - Container and IaC security scanner"
LABEL org.opencontainers.image.licenses="MIT"

# Security: Create non-root user
RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

RUN apk add --no-cache \
    ca-certificates \
    tini \
    curl \
    && rm -rf /var/cache/apk/*

# Install Trivy from official releases
ARG TRIVY_VERSION=0.58.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH="64bit"; fi && \
    if [ "$ARCH" = "aarch64" ]; then ARCH="ARM64"; fi && \
    curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH}.tar.gz" | tar -xzf - -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy

# Verify trivy installation
RUN trivy --version

WORKDIR /app

COPY --chown=mcpuser:mcpuser requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=mcpuser:mcpuser . .

RUN mkdir -p /app/output && chown -R mcpuser:mcpuser /app

USER mcpuser

# Create cache directory for trivy DB
RUN mkdir -p /home/mcpuser/.cache/trivy

# Environment variables
ENV TRIVY_OUTPUT_DIR=/app/output
ENV TRIVY_CACHE_DIR=/home/mcpuser/.cache/trivy
ENV TRIVY_TIMEOUT=600
ENV TRIVY_MAX_CONCURRENT=2
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "server.py"]

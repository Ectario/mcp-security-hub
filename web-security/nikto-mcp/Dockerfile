# Nikto MCP Server
# Wrapper for nikto-mcp web server scanner
# Based on: https://github.com/weldpua2008/nikto-mcp

FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="Nikto MCP Server - Web server vulnerability scanner"
LABEL org.opencontainers.image.licenses="MIT"

# Security: Create non-root user
RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

# Install Nikto and dependencies
RUN apk add --no-cache \
    ca-certificates \
    tini \
    git \
    perl \
    perl-net-ssleay \
    && rm -rf /var/cache/apk/*

# Clone and install Nikto
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Verify nikto installation
RUN nikto -Version

WORKDIR /app

# Clone nikto-mcp
RUN git clone --depth 1 https://github.com/weldpua2008/nikto-mcp.git /tmp/nikto-mcp && \
    cp -r /tmp/nikto-mcp/* /app/ && \
    rm -rf /tmp/nikto-mcp

# Install Python dependencies
RUN pip install --no-cache-dir mcp pydantic pydantic-settings

# Set ownership
RUN mkdir -p /app/output && chown -R mcpuser:mcpuser /app /opt/nikto

USER mcpuser

# Environment variables
ENV NIKTO_OUTPUT_DIR=/app/output
ENV NIKTO_TIMEOUT=600
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "server.py"]

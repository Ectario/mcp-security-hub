# Offensive Security MCP Servers

Production-ready, Dockerized MCP (Model Context Protocol) servers for offensive security tools.

## What Makes This Different?

While [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) catalogs security-related MCP servers, this repository provides:

| Feature | awesome-mcp-security | This Repository |
|---------|---------------------|-----------------|
| **Focus** | Comprehensive catalog | Production-ready containers |
| **Docker Support** | Links to repos | Pre-built, hardened images |
| **Security** | Varies by project | Consistent hardening (non-root, minimal images) |
| **Orchestration** | N/A | docker-compose for multi-tool workflows |
| **CI/CD** | N/A | Automated builds, Trivy scanning |
| **Integration** | N/A | FuzzForge workflow examples |

**TL;DR**: awesome-mcp-security tells you *what exists*. This repo gives you *deployable infrastructure*.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/FuzzingLabs/offensive-security-mcps
cd offensive-security-mcps

# Start all MCP servers
docker-compose up -d

# Or start a specific server
docker-compose up nuclei-mcp -d

# Check health
./scripts/healthcheck.sh
```

### Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "nuclei": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/fuzzinglabs/nuclei-mcp:latest"]
    },
    "nmap": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--cap-add=NET_RAW", "ghcr.io/fuzzinglabs/nmap-mcp:latest"]
    }
  }
}
```

## Available MCP Servers

### Reconnaissance
| Server | Description | Status |
|--------|-------------|--------|
| [nmap-mcp](./reconnaissance/nmap-mcp) | Port scanning, service detection, OS fingerprinting | Planned |
| [shodan-mcp](./reconnaissance/shodan-mcp) | Internet-wide device search | Planned |
| [subfinder-mcp](./reconnaissance/subfinder-mcp) | Subdomain discovery | Planned |

### Web Security
| Server | Description | Status |
|--------|-------------|--------|
| [nuclei-mcp](./web-security/nuclei-mcp) | Template-based vulnerability scanning | Planned |
| [sqlmap-mcp](./web-security/sqlmap-mcp) | SQL injection detection & exploitation | Planned |
| [burp-suite-mcp](./web-security/burp-suite-mcp) | Web security testing (integration guide) | Planned |

### Exploitation
| Server | Description | Status |
|--------|-------------|--------|
| [metasploit-mcp](./exploitation/metasploit-mcp) | Exploitation framework | Planned |

### Binary Analysis
| Server | Description | Status |
|--------|-------------|--------|
| [ghidra-mcp](./binary-analysis/ghidra-mcp) | Reverse engineering, decompilation | Planned |
| [radare2-mcp](./binary-analysis/radare2-mcp) | Binary analysis | Planned |

### Mobile Security
| Server | Description | Status |
|--------|-------------|--------|
| [mobsf-mcp](./mobile-security/mobsf-mcp) | Mobile app security analysis | Planned |
| [jadx-mcp](./mobile-security/jadx-mcp) | Android decompilation | Planned |

## Security Hardening

All containers follow these security practices:

- **Non-root execution**: Containers run as `mcpuser` (uid 1000)
- **Minimal base images**: Alpine-based where possible
- **Read-only filesystems**: Where supported
- **Dropped capabilities**: Only essential capabilities enabled
- **No new privileges**: `security_opt: no-new-privileges:true`
- **Resource limits**: CPU and memory constraints
- **Health checks**: Built-in container health monitoring
- **Trivy scanning**: All images scanned for vulnerabilities

## Project Structure

```
offensive-security-mcps/
├── README.md                    # This file
├── LICENSE                      # MIT License
├── SECURITY.md                  # Security policy
├── CONTRIBUTING.md              # Contribution guidelines
├── docker-compose.yml           # Orchestrate all MCPs
├── Dockerfile.template          # Base template for new MCPs
├── .github/
│   └── workflows/
│       ├── build.yml            # CI/CD for Docker builds
│       └── security-scan.yml    # Trivy vulnerability scanning
├── docs/
│   ├── DEPLOYMENT.md            # Production deployment guide
│   ├── FUZZFORGE_INTEGRATION.md # FuzzForge examples
│   └── COMPLIANCE.md            # Legal considerations
├── scripts/
│   ├── setup.sh                 # Quick setup
│   └── healthcheck.sh           # Health check utilities
├── reconnaissance/
│   └── nmap-mcp/
├── web-security/
│   └── nuclei-mcp/
├── exploitation/
│   └── metasploit-mcp/
├── binary-analysis/
│   └── ghidra-mcp/
└── mobile-security/
    └── mobsf-mcp/
```

## FuzzForge Integration

This repository is designed to integrate with [FuzzForge](https://fuzzing-labs.com), enabling automated security workflows:

```python
from temporalio import workflow

@workflow.defn
class SecurityScanWorkflow:
    @workflow.run
    async def run(self, target: str) -> dict:
        # Reconnaissance
        nmap_results = await workflow.execute_activity(
            "nmap_scan", target
        )

        # Vulnerability scanning based on discovered services
        nuclei_results = await workflow.execute_activity(
            "nuclei_scan", target
        )

        return {"nmap": nmap_results, "nuclei": nuclei_results}
```

See [docs/FUZZFORGE_INTEGRATION.md](./docs/FUZZFORGE_INTEGRATION.md) for complete examples.

## Legal & Compliance

**These tools are for authorized security testing only.**

Before using any MCP server:

1. Obtain written authorization from the target owner
2. Define scope, timeline, and allowed activities
3. Maintain audit logs of all operations
4. Follow responsible disclosure practices

See [docs/COMPLIANCE.md](./docs/COMPLIANCE.md) for authorization templates and compliance guidance.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### Adding a New MCP Server

1. Use `Dockerfile.template` as your starting point
2. Follow the security hardening checklist
3. Include health checks and documentation
4. Submit PR with completed checklist

### Acceptance Criteria

- Trivy scan passes (no HIGH/CRITICAL vulnerabilities)
- Non-root user configured
- Health check implemented
- README with usage examples
- License verified and documented

## License

MIT License - See [LICENSE](./LICENSE)

## Acknowledgments

- [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) - Comprehensive MCP security catalog
- [Model Context Protocol](https://modelcontextprotocol.io/) - Protocol specification
- All upstream MCP server maintainers

---

**Maintained by [Fuzzing Labs](https://fuzzing-labs.com)**

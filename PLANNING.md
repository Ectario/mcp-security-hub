# Offensive Security MCP Repository - Complete Planning Document

## Executive Summary

This document contains all research and planning for creating a production-ready repository of Dockerized offensive security MCP servers. Created for Fuzzing Labs to complement existing catalogs with deployment-ready infrastructure.

## Project Goals

1. **Differentiation**: Complement [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) with production-ready Docker containers
2. **Security-First**: Hardened configurations, non-root users, isolated networking
3. **FuzzForge Integration**: Showcase integration with FuzzForge security automation platform
4. **Enterprise-Ready**: Compliance documentation, audit logging, legal considerations

## Repository Structure

**Flat monorepo** - each MCP has only 4 files, shared config at root:

```
mcps-for-security/
├── README.md                           # Main documentation
├── docker-compose.yml                  # Orchestrate all MCPs
├── pytest.ini                          # Shared test config
├── trivy.yaml                          # Shared security scanning
├── .trivyignore                        # Shared ignores
├── .github/
│   └── workflows/
│       ├── build.yml                   # CI/CD for Docker builds
│       └── security-scan.yml           # Trivy scanning
├── scripts/
│   ├── setup.sh                        # Quick setup script
│   └── healthcheck.sh                  # Health check utilities
├── tests/                              # Centralized tests
│   ├── conftest.py                     # Shared fixtures
│   ├── nuclei-mcp/
│   └── nmap-mcp/
├── reconnaissance/
│   ├── nmap-mcp/                       # 4 files only
│   │   ├── Dockerfile
│   │   ├── server.py
│   │   ├── requirements.txt
│   │   └── README.md
│   └── shodan-mcp/
├── web-security/
│   ├── nuclei-mcp/
│   └── sqlmap-mcp/
├── exploitation/
│   └── metasploit-mcp/
├── binary-analysis/
│   ├── ghidra-mcp/
│   └── radare2-mcp/
└── mobile-security/
    └── mobsf-mcp/
```

### MCP Directory Structure (4 files each)

Each MCP server contains only essential files:
- `Dockerfile` - Container build instructions
- `server.py` - MCP server implementation
- `requirements.txt` - Python dependencies
- `README.md` - Usage documentation

---

# Complete MCP Server Catalog

## 🎯 Priority Tier 1: Most Popular & Official Implementations

### 1. Burp Suite MCP (Official - PortSwigger)
- **Repository**: https://github.com/PortSwigger/mcp-server
- **Stars**: 393
- **Status**: Official vendor integration (April 2025)
- **Language**: Kotlin
- **Installation**: BApp Extension
- **Features**: HTTP request manipulation, proxy history, security testing
- **Default Port**: localhost:9876
- **License**: Proprietary (check PortSwigger license)

### 2. HexStrike AI
- **Repository**: https://github.com/0x4m4/hexstrike-ai
- **Stars**: 4,500
- **Status**: Most comprehensive collection
- **Language**: Python
- **Tools**: 150+ (Nmap, Nuclei, SQLMap, Ghidra, Radare2, etc.)
- **Features**: 12 autonomous AI agents, real-time dashboards
- **Install**: `python hexstrike_server.py`
- **License**: Check repository

### 3. cyproxio/mcp-for-security
- **Repository**: https://github.com/cyproxio/mcp-for-security
- **Stars**: 477
- **Status**: Most popular dedicated security collection
- **Language**: Python/Docker
- **Tools**: 22+ (Nmap, Masscan, Nuclei, SQLMap, FFUF, WPScan, MobSF)
- **Install**: Docker `cyprox/mcp-for-security` or `./start.sh`
- **License**: MIT

### 4. Metasploit MCP (GH05TCREW)
- **Repository**: https://github.com/GH05TCREW/MetasploitMCP
- **Stars**: 384
- **Status**: Active
- **Language**: Python
- **Features**: Exploit search, MSFvenom payloads, session management
- **Requirements**: msfrpcd running
- **Environment**: MSF_PASSWORD, MSF_SERVER, MSF_PORT
- **License**: Check repository

### 5. Ghidra MCP
- **Multiple Implementations**:
  - **starsong-consulting/GhydraMCP**: Multi-instance with REST API
  - **jtang613/ghidra-assist**: Popular implementation
- **Features**: Decompilation, function analysis, cross-references
- **Install**: Ghidra plugin + Python bridge via `uvx`
- **License**: Check repository

---

## 🔍 Network Reconnaissance

### Nmap MCP
- **imjdl/nmap-mcpserver**: https://github.com/imjdl/nmap-mcpserver
- **0xPratikPatil/NmapMCP**: Alternative implementation
- **mohdhaji87/Nmap-MCP-Server**: Another option
- **Features**: Port scanning, service detection, OS fingerprinting, NSE scripts

### Masscan MCP
- **Included in**: cyproxio/mcp-for-security, HexStrike AI
- **Features**: High-speed port scanning

### RustScan MCP
- **Included in**: HexStrike AI
- **Features**: Fast port scanner with Nmap integration

### Amass MCP
- **Included in**: cyproxio/mcp-for-security, HexStrike AI
- **Features**: Subdomain enumeration, OSINT

### Subfinder MCP
- **Included in**: HexStrike AI
- **Features**: Subdomain discovery

---

## 🌐 Web Security Scanning

### Nuclei MCP
- **addcontent/nuclei-mcp**: https://github.com/addcontent/nuclei-mcp
  - Language: Go
  - Features: Template management, REST API, result caching
- **marc-shade/security-scanner-mcp**: Cluster-wide scanning
- **mark3labs/nuclei**: Listed on registries
- **Features**: 5000+ vulnerability templates, custom template support

### SQLMap MCP
- **mohdhaji87/sqlmap-mcp**: https://playbooks.com/mcp/mohdhaji87-sqlmap
- **Features**: 12 tools via FastMCP
  - Vulnerability scanning
  - Database enumeration
  - Data extraction
  - Proxy configuration
  - Tor integration
- **Included in**: cyproxio/mcp-for-security

### OWASP ZAP MCP
- **dtkmn/mcp-zap-server**: Java/Spring Boot, Docker Compose
- **LisBerndt/zap-custom-mcp**: AI-powered scanning
- **Features**: Active/passive scanning, spidering, report generation

### Nikto MCP
- **weldpua2008/nikto-mcp**: https://github.com/weldpua2008/nikto-mcp
- **Language**: TypeScript
- **Install**: `npx nikto-mcp@latest`
- **Features**: JSON/CLI output, optional REST API, Docker support

### WPScan MCP
- **Included in**: cyproxio/mcp-for-security, HexStrike AI
- **Features**: WordPress vulnerability scanning

### FFUF MCP
- **Included in**: cyproxio/mcp-for-security, HexStrike AI
- **Features**: Fast web fuzzing

### Gobuster MCP
- **Included in**: HexStrike AI
- **Features**: Directory/file enumeration

### Feroxbuster MCP
- **Included in**: HexStrike AI
- **Features**: Recursive content discovery

---

## 🔐 OSINT & Reconnaissance

### Shodan MCP
- **BurtTheCoder/mcp-shodan**: https://github.com/BurtTheCoder/mcp-shodan
  - Stars: 77
  - Downloads: 9.8K npm
  - Features: IP reconnaissance, DNS ops, vulnerability tracking, CVEDB
- **ADEOSec/mcp-shodan**: https://github.com/ADEOSec/mcp-shodan
  - Features: Combined Shodan + VirusTotal, 11 analysis prompts
- **Cyreslab-AI/shodan-mcp-server**: WebSocket interface
- **x3r0k/shodan-mcp-server**: Listed on LobeHub

### Censys MCP (Official)
- **Official Platform**: https://mcp.platform.censys.io/platform/mcp/
- **Community**: nickpending/mcp-censys
  - Features: Domain/IP lookup, Docker deployment

### Maigret MCP
- **BurtTheCoder/mcp-maigret**: https://github.com/BurtTheCoder/mcp-maigret
- **Features**: Username search across hundreds of social networks, URL analysis, Docker

### DNSTwist MCP
- **BurtTheCoder/mcp-dnstwist**
- **Features**: DNS fuzzing, typosquatting detection, domain permutation

### TheHarvester MCP
- **frishtik/osint-tools-mcp-server**: https://github.com/frishtik/osint-tools-mcp-server
- **Includes**: Sherlock (399+ platforms), Holehe (120+ platforms), GHunt, Maigret (3000+ sites), Blackbird (581 sites)

### VirusTotal MCP
- **BurtTheCoder**: VirusTotal API integration
- **Features**: File/URL analysis for viruses

### WHOIS MCP
- **Included in**: Multiple OSINT collections
- **Features**: Domain registration lookups

---

## 💻 Binary Analysis & Reverse Engineering

### Ghidra MCP
- **starsong-consulting/GhydraMCP**: https://github.com/starsong-consulting/GhydraMCP
  - Features: Multi-instance, HATEOAS REST API
- **jtang613/ghidra-assist**: https://www.pulsemcp.com/servers/jtang613-ghidra-assist
- **Features**: Decompilation, function analysis, cross-references, symbol management

### Radare2 MCP (Official)
- **Repository**: https://github.com/radareorg/radare2-mcp
- **Status**: Official from Radare organization
- **Install**: `r2pm -ci r2mcp`
- **Features**: Binary analysis, disassembly, function listing

### IDA Pro MCP
- **mrexodia/ida-pro-mcp**: https://github.com/mrexodia/ida-pro-mcp
- **Features**: 51+ tools
  - Decompilation, disassembly, cross-references
  - Stack frame analysis, structure creation
  - Debugging operations
- **Requirements**: IDA Pro 8.3+ (9+ recommended)
- **Install**: `pip install ida-pro-mcp`

### Binary Ninja MCP
- **fosdickio/binary-ninja-mcp**: https://www.pulsemcp.com/servers/fosdickio-binary-ninja
- **Features**: Decompilation, IL analysis, symbol management, type system

### Frida MCP
- **dnakov/frida-mcp**: Runtime manipulation
- **s4dp4nd4/frida-c2-mcp**: C2-style integration
- **Features**: Process management, script injection, app spawning (mobile/desktop)

### GDB MCP
- **Included in**: HexStrike AI
- **Features**: GNU debugger with exploit development

### Pwntools MCP
- **Included in**: HexStrike AI
- **Features**: CTF framework, exploit development

### Angr MCP
- **Included in**: HexStrike AI
- **Features**: Binary analysis with symbolic execution

---

## 📱 Mobile Security

### MobSF MCP
- **nkcc-apk/APK-Security-Guard-MCP-Suite**: https://www.pulsemcp.com/servers/nkcc-apk-mobsf
- **Included in**: cyproxio/mcp-for-security
- **Features**: Automated analysis of APK, IPA, APPX files
  - Vulnerability scanning
  - Detailed reporting
  - Comprehensive mobile app security

### JADX MCP
- **zinja-coder/jadx-ai-mcp**: https://github.com/zinja-coder/jadx-ai-mcp
  - Plugin with live reverse engineering
  - Install: `jadx plugins --install "github:zinja-coder:jadx-ai-mcp"`
- **mobilehackinglab/jadx-mcp-plugin**: Official Mobile Hacking Lab version
- **zinja-coder/jadx-mcp-server**: Standalone server
- **Features**: Class search, method retrieval, smali file access, debugger integration

### APKTool MCP
- **zinja-coder/apktool-mcp-server**: https://github.com/zinja-coder/apktool-mcp-server
- **Features**: 
  - APK decompilation/recompilation
  - Manifest analysis
  - Smali modification
  - Permission analysis
- **Requirements**: APKTool in PATH

---

## ☁️ Cloud Security

### Prowler MCP (Official)
- **Repository**: https://github.com/prowler-cloud/prowler
- **Status**: Official Prowler Cloud implementation
- **Platforms**: AWS, Azure, GCP, OCI, Kubernetes, GitHub, Microsoft 365
- **Features**: Hundreds of controls (CIS, NIST 800, MITRE ATT&CK, GDPR, SOC2, PCI-DSS)

### Trivy MCP (Official - Aqua Security)
- **Repository**: https://github.com/aquasecurity/trivy-mcp
- **Status**: Official Aqua Security plugin
- **Install**: `trivy plugin install mcp`
- **Features**:
  - Vulnerability scanning
  - Misconfiguration detection
  - License scanning
  - Secrets detection
  - SBOM generation
- **Transports**: stdio, HTTP, SSE

### Scout Suite MCP
- **Included in**: HexStrike AI
- **Features**: Multi-cloud security auditing

### Kube-hunter MCP
- **Included in**: HexStrike AI
- **Features**: Kubernetes penetration testing

---

## 🔑 Password & Authentication

### Hashcat MCP
- **MorDavid/Hashcat-MCP**: https://github.com/MorDavid/Hashcat-MCP
- **Features**: 
  - GPU-accelerated hash cracking
  - Automatic attack strategy selection
  - 300+ hash types supported
  - Natural language interface

### John the Ripper MCP
- **Included in**: DMontgomery40/pentest-mcp, HexStrike AI
- **Features**: Password cracking

### Hydra MCP
- **Included in**: DMontgomery40/pentest-mcp, HexStrike AI
- **Features**: Network logon cracker

### CrackMapExec MCP
- **Included in**: HexStrike AI
- **Features**: Network penetration testing

---

## 🛡️ Vulnerability Scanning & SAST

### Snyk MCP (Official)
- **Status**: Built-in to Snyk CLI v1.1296.2+
- **Install**: Already in CLI
- **Run**: `snyk mcp -t sse --experimental`
- **Features**: SCA and SAST analysis

### Semgrep MCP
- **mark3labs/semgrep-mcp**: Listed on registries
- **Features**: Static analysis, vulnerability detection, code scanning

---

## 🎮 CTF & Bug Bounty Platforms

### Hack The Box MCP (Official)
- **Endpoint**: https://mcp.hackthebox.ai/v1/ctf/mcp/
- **Status**: Official HTB server
- **Features**: Event management, team collaboration, challenge operations, score tracking

### Bug Bounty MCP Servers
- **gokulapap/bugbounty-mcp-server**: 92+ tools
  - Subdomain enumeration
  - DNS analysis
  - Google Dorking
  - Shodan/Censys integration
- **akinabudu/bug-bounty-mcp**: HackerOne/Bugcrowd API
  - Ethical boundary enforcement
- **slanycukr/bugbounty-mcp**: Specialized bug bounty tools

---

## 🔄 Multi-Tool Pentesting Collections

### DMontgomery40/pentest-mcp
- **Repository**: https://github.com/DMontgomery40/pentest-mcp
- **Features**: Professional pentest suite
  - STDIO/HTTP/SSE support
  - Nmap, gobuster, dirbuster, Nikto
  - John the Ripper, Hashcat
  - Wordlist building

### VyomJain6904/Pentest-MCP-Server
- **Repository**: https://github.com/VyomJain6904/Pentest-MCP-Server
- **Features**: Comprehensive MCP for penetration testing tools

### ibrahimsaleem/PentestThinkingMCP
- **Repository**: https://github.com/ibrahimsaleem/PentestThinkingMCP
- **Features**: Attack path planning with Beam Search and MCTS
  - Automated attack chains
  - CTF/HTB solving
  - Step-by-step reasoning

---

## 🎯 Specialized Tools

### Wireshark/Tshark MCP
- **0xKoda/WireMCP**: Packet analysis
- **kriztalz/SharkMCP**: Protocol statistics
- **khuynh22/mcp-wireshark**: PCAP processing
- **Features**: Packet capture, conversation analysis

### BloodHound MCP
- **MorDavid/BloodHound-MCP-AI**: https://github.com/MorDavid/BloodHound-MCP-AI
- **Features**: Active Directory analysis

### ROADRecon MCP
- **atomicchonk/roadrecon-mcp**: Azure AD data analysis

---

## 📚 Enterprise & Defensive Security

### Google Security MCP (Official)
- **Repository**: https://github.com/google/mcp-security
- **Stars**: 403
- **Features**: 
  - Chronicle SIEM
  - Google Threat Intelligence
  - Security Command Center
- **Install**: pip/uv packages

---

## 🔗 Curated Lists & Resources

### Awesome Lists
- **appcypher/awesome-mcp-servers**: ~5,000 stars, 30+ categories
- **Puliczek/awesome-mcp-security**: Dedicated security threats/vulnerabilities
- **soxoj/awesome-osint-mcp-servers**: 61 stars, OSINT tools
- **rohitg00/awesome-devops-mcp-servers**: DevOps focus with security

### Registries
- **PulseMCP**: https://www.pulsemcp.com/
- **Smithery**: MCP server registry
- **LobeHub**: https://lobehub.com/mcp
- **Glama**: https://glama.ai/mcp/servers
- **MCP Market**: https://mcpmarket.com/
- **Playbooks**: https://playbooks.com/mcp

---

# Recommended Initial Implementation

## Phase 1: Core 7 Tools (MVP)

### Priority Order
1. **Nuclei MCP** - Most versatile vulnerability scanner
2. **Nmap MCP** - Essential reconnaissance 
3. **Burp Suite MCP** - Official, most wanted web security
4. **SQLMap MCP** - SQL injection standard
5. **Shodan MCP** - OSINT reconnaissance
6. **Metasploit MCP** - Exploitation framework
7. **Ghidra MCP** - Binary analysis

### Rationale
- Cover all major categories (recon, web, exploitation, binary)
- Mix of official (Burp) and community favorites
- Docker-friendly implementations
- High community demand

---

# Docker Template Structure

## Base Dockerfile Template

```dockerfile
# Base security MCP template
FROM node:20-alpine AS base

# Security: Create non-root user first
RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

# Install security tools and dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    git \
    curl \
    bash \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Copy and install dependencies
COPY --chown=mcpuser:mcpuser package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application files
COPY --chown=mcpuser:mcpuser . .

# Security: Switch to non-root user
USER mcpuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD node healthcheck.js || exit 1

# Expose MCP port
EXPOSE 3000

# Start server
CMD ["node", "index.js"]
```

## Docker Compose Template

```yaml
version: '3.8'

services:
  nuclei-mcp:
    build: ./vulnerability-scanning/nuclei-mcp
    container_name: nuclei-mcp
    environment:
      - NUCLEI_RATE_LIMIT=150
      - NUCLEI_SEVERITY=critical,high,medium
    ports:
      - "3001:3000"
    networks:
      - security-mcp-network
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW  # Only if needed for specific tool

  nmap-mcp:
    build: ./reconnaissance/nmap-mcp
    container_name: nmap-mcp
    ports:
      - "3002:3000"
    networks:
      - security-mcp-network
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true

networks:
  security-mcp-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

---

# Security Hardening Checklist

## Container Security
- [ ] Non-root user (uid 1000)
- [ ] Read-only root filesystem where possible
- [ ] Drop all capabilities, add only required ones
- [ ] no-new-privileges security option
- [ ] Tmpfs for /tmp directory
- [ ] Multi-stage builds to minimize image size
- [ ] Minimal base images (alpine preferred)
- [ ] No secrets in environment variables
- [ ] Use .dockerignore

## Network Security
- [ ] Isolated Docker network
- [ ] Expose only necessary ports
- [ ] Use internal DNS for service discovery
- [ ] Implement rate limiting
- [ ] Add network policies

## Runtime Security
- [ ] Health checks configured
- [ ] Resource limits (CPU, memory)
- [ ] Restart policies
- [ ] Logging to stdout/stderr
- [ ] Structured logging format

## Supply Chain Security
- [ ] Pin base image versions
- [ ] Verify checksums for downloads
- [ ] Scan images with Trivy/Snyk
- [ ] Sign images
- [ ] SBOM generation

---

# FuzzForge Integration Examples

## 1. Temporal Workflow Integration

```python
# Example: FuzzForge workflow using MCP servers
from temporalio import workflow
from temporalio.client import Client

@workflow.defn
class SecurityScanWorkflow:
    @workflow.run
    async def run(self, target: str) -> dict:
        # 1. Reconnaissance with Nmap MCP
        nmap_results = await workflow.execute_activity(
            "nmap_scan",
            target,
            start_to_close_timeout=timedelta(minutes=5)
        )
        
        # 2. Vulnerability scan with Nuclei MCP
        nuclei_results = await workflow.execute_activity(
            "nuclei_scan",
            target,
            start_to_close_timeout=timedelta(minutes=10)
        )
        
        # 3. If SQL found, run SQLMap MCP
        if "sql" in nuclei_results.get("vulnerabilities", []):
            sqlmap_results = await workflow.execute_activity(
                "sqlmap_scan",
                target,
                start_to_close_timeout=timedelta(minutes=15)
            )
        
        return {
            "nmap": nmap_results,
            "nuclei": nuclei_results,
            "sqlmap": sqlmap_results if "sql" in nuclei_results else None
        }
```

## 2. RAG-Powered Tool Selection

```python
# Example: Using RAG to select appropriate MCP tools
from fuzzforge.rag import ToolSelector

selector = ToolSelector()

# Get target context
target_info = {
    "type": "web_application",
    "tech_stack": ["PHP", "MySQL"],
    "previous_findings": ["SQL injection potential"]
}

# RAG selects appropriate MCP tools
recommended_tools = selector.recommend_mcps(target_info)
# Returns: ["nuclei-mcp", "sqlmap-mcp", "burp-suite-mcp"]
```

## 3. Multi-Agent Coordination

```python
# Example: Agent coordination for complex assessments
class SecurityAssessmentAgent:
    def __init__(self):
        self.mcp_clients = {
            "recon": NmapMCPClient(),
            "vuln_scan": NucleiMCPClient(),
            "exploit": MetasploitMCPClient()
        }
    
    async def assess_target(self, target: str):
        # Agent decides workflow based on results
        recon_data = await self.mcp_clients["recon"].scan(target)
        
        # Analyze and decide next steps
        vulnerabilities = await self._analyze_services(recon_data)
        
        # Execute appropriate scans
        results = []
        for vuln in vulnerabilities:
            scan_result = await self.mcp_clients["vuln_scan"].scan(
                target, 
                templates=vuln.relevant_templates
            )
            results.append(scan_result)
        
        return self._compile_report(results)
```

---

# Compliance & Legal Documentation

## Authorization Template

```markdown
# PENETRATION TESTING AUTHORIZATION

**Date**: [DATE]
**Client**: [CLIENT NAME]
**Tester**: [YOUR ORGANIZATION]

## Scope
The following systems are authorized for security testing:
- [ ] IP Ranges: [LIST]
- [ ] Domains: [LIST]
- [ ] Applications: [LIST]

## Testing Window
- Start: [DATE/TIME]
- End: [DATE/TIME]
- Timezone: [TZ]

## Authorized Activities
- [ ] Network reconnaissance (Nmap, Masscan)
- [ ] Vulnerability scanning (Nuclei, Nikto)
- [ ] Web application testing (Burp Suite, SQLMap)
- [ ] Exploitation attempts (Metasploit)
- [ ] Social engineering: YES / NO

## Contacts
- Technical Contact: [NAME, EMAIL, PHONE]
- Emergency Contact: [NAME, EMAIL, PHONE]

## Signatures
Client Representative: _______________  Date: _______
Tester Representative: _______________  Date: _______
```

## Audit Logging Configuration

```yaml
# Example: Comprehensive audit logging
logging:
  level: INFO
  format: json
  outputs:
    - stdout
    - file: /var/log/mcp-audit.log
  
  fields:
    - timestamp
    - user_id
    - mcp_server
    - tool_name
    - target
    - parameters
    - result_summary
    - duration_ms
    
  retention:
    days: 90
    
  alerts:
    - condition: unauthorized_target
      action: block_and_notify
    - condition: rate_limit_exceeded
      action: throttle
```

---

# Testing & Quality Assurance

## CI/CD Pipeline (.github/workflows/build.yml)

```yaml
name: Build and Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Build Docker images
      run: |
        docker-compose build
    
    - name: Run Trivy vulnerability scan
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'image'
        image-ref: 'offensive-security-mcps:latest'
        severity: 'CRITICAL,HIGH'
        exit-code: '1'
    
    - name: Run container structure tests
      run: |
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
          gcr.io/gcp-runtimes/container-structure-test:latest \
          test --image offensive-security-mcps:latest \
          --config tests/container-structure.yaml
    
    - name: Run functional tests
      run: |
        docker-compose up -d
        ./scripts/run-tests.sh
        docker-compose down
```

---

# Community & Maintenance

## Contributing Guidelines

### Acceptance Criteria for New MCPs
1. **Security**: Must pass Trivy scan with no HIGH/CRITICAL issues
2. **Documentation**: Complete README with examples
3. **Licensing**: Clear license compatible with MIT
4. **Testing**: Includes health check and basic functional test
5. **Docker**: Follows security hardening checklist
6. **Active**: Last commit within 6 months (or explicitly maintained)

### Pull Request Template
```markdown
## Description
[Describe the MCP server being added]

## Checklist
- [ ] Dockerfile follows security template
- [ ] Non-root user configured
- [ ] Health check implemented
- [ ] README documentation complete
- [ ] License verified and documented
- [ ] Trivy scan passed
- [ ] Functional test included
- [ ] docker-compose.yml updated

## Testing
[How to test this MCP server]

## Related Issues
[Link to related issues]
```

---

# Quick Start Commands

## For Repository Creators

```bash
# Clone and setup
git clone https://github.com/fuzzing-labs/offensive-security-mcps
cd offensive-security-mcps

# Quick setup script
./scripts/setup.sh

# Build all containers
docker-compose build

# Start specific MCP server
docker-compose up nuclei-mcp

# Start all MCP servers
docker-compose up -d

# View logs
docker-compose logs -f nuclei-mcp

# Health check
./scripts/healthcheck.sh

# Stop all
docker-compose down
```

## For Users

```bash
# Pull pre-built images
docker pull ghcr.io/fuzzing-labs/nuclei-mcp:latest

# Run single MCP server
docker run -p 3000:3000 ghcr.io/fuzzing-labs/nuclei-mcp:latest

# Configure Claude Desktop
cat >> ~/Library/Application\ Support/Claude/claude_desktop_config.json <<EOF
{
  "mcpServers": {
    "nuclei": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/fuzzing-labs/nuclei-mcp:latest"]
    }
  }
}
EOF
```

---

# Metrics & Success Criteria

## Key Performance Indicators
- **Adoption**: Docker pulls per month
- **Quality**: Average Trivy security score
- **Community**: Contributors, stars, forks
- **Coverage**: Number of MCP servers available
- **Documentation**: Issues closed, average response time

## Success Metrics (6 months)
- [ ] 500+ GitHub stars
- [ ] 10+ contributors
- [ ] 1000+ Docker pulls/month
- [ ] Listed in awesome-mcp-security
- [ ] 3+ blog posts/mentions
- [ ] 0 HIGH/CRITICAL security issues

---

# Next Steps for Implementation

## Week 1: Foundation
1. Create repository structure
2. Write comprehensive README
3. Create base Dockerfile template
4. Setup CI/CD pipelines
5. Write SECURITY.md

## Week 2-3: Core MCPs (Phase 1)
1. Implement Nuclei MCP (most versatile)
2. Implement Nmap MCP (most requested)
3. Implement Burp Suite MCP integration guide
4. Document FuzzForge integration examples
5. Create docker-compose orchestration

## Week 4: Polish & Launch
1. Security scanning and hardening
2. Documentation review
3. Create demo video
4. Write launch blog post
5. Submit PR to awesome-mcp-security
6. Announce on security communities

## Ongoing: Expansion
- Add 1-2 new MCPs per month
- Respond to community requests
- Keep dependencies updated
- Security scanning automation

---

# Contact & Resources

## Maintainer
**Tanguy** - Team Lead, Fuzzing Labs
- Email: [Your Email]
- GitHub: [Your GitHub]
- Twitter: [Your Twitter]

## Resources
- **FuzzForge**: https://fuzzing-labs.com
- **MCP Specification**: https://modelcontextprotocol.io/
- **awesome-mcp-security**: https://github.com/Puliczek/awesome-mcp-security

## License
MIT License - See LICENSE file

---

**Document Version**: 1.0
**Last Updated**: January 6, 2026
**Status**: Ready for Implementation

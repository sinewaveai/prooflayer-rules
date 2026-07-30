# ProofLayer MCP Runtime Integrations - Product Requirements Document

| Field | Value |
|---|---|
| Version | 1.0 |
| Status | DRAFT FOR IMPLEMENTATION |
| Repo | github.com/sinewaveai/prooflayer-rules |
| Current package | prooflayer-rules |
| Target releases | v0.3.0 through v0.6.0 |
| License | Apache-2.0 |
| Owner | Sinewave AI / ProofLayer |
| Strategic goal | Make ProofLayer the default runtime security layer for MCP-connected agents and agent frameworks |

---

## 1. Executive Summary

ProofLayer v0.2.0 established a native LangGraph security wrapper with runtime detection, adversarial evals, and compliance evidence. The next product arc is to generalize that capability across the MCP and agent-runtime ecosystem.

This PRD defines a rigorous build plan for first-class integrations across:

1. Agent frameworks that consume MCP tools
2. MCP hosts and developer environments
3. MCP gateway and infrastructure deployment patterns
4. SIEM, policy, eval, and compliance surfaces

The result should be a coherent integration family under the existing `prooflayer.*` Python namespace, with no sibling package. The package should remain installable from PyPI as `prooflayer-rules`, using optional extras for integration-specific dependencies.

## 2. Strategic Context

MCP has become a standard connection layer between agent hosts and external tools. This creates a new security boundary: every MCP server, tool description, tool argument, tool output, retrieved context item, and agent-to-agent message can become an attack surface.

ProofLayer's position:

| Layer | Example products | ProofLayer role |
|---|---|---|
| Agent orchestration | LangGraph, CrewAI, AutoGen, Semantic Kernel, OpenAI Agents SDK | Wrap agent execution and inspect tool calls |
| Retrieval and indexing | LlamaIndex, Haystack | Inspect retrieved context, MCP tools, and RAG outputs |
| MCP host | Claude Desktop, Claude Code, Cursor, VS Code, OpenCode | Protect local tool use and developer workflows |
| MCP gateway | FastAPI, Express, Docker, Kubernetes, Cloudflare Workers | Enforce security before tools execute |
| Observability and audit | LangSmith, Datadog, Splunk | Emit detection events and compliance evidence |
| Eval and red team | Promptfoo, Garak, custom probes | Validate attack resistance before production |

ProofLayer should be complementary to existing tracing, agent orchestration, and MCP-host products. It should not claim to replace LangSmith, LangGraph, Claude, Cursor, OpenAI Agents SDK, or other framework runtimes.

## 3. Goals

### 3.1 Primary Goals

1. Provide first-class integrations for major MCP-connected runtimes and frameworks.
2. Preserve one canonical detection engine and audit-event schema across all integrations.
3. Support a consistent customer API:
   - configure policy
   - wrap runtime or tool client
   - invoke normally
   - retrieve audit events
4. Detect and block:
   - prompt injection
   - jailbreak
   - tool abuse
   - tool poisoning
   - command injection
   - data exfiltration
   - scope drift
   - state manipulation
   - memory poisoning
   - multi-turn manipulation
   - unsafe handoff or delegation
5. Emit audit-defensible events with rule IDs, rule versions, timestamps, hashes, decisions, and evidence snippets.
6. Provide runnable examples for every integration.
7. Provide mocked and live-compatible tests for every integration.
8. Maintain backward compatibility with existing MCP gateway and LangGraph functionality.
9. Keep hot-path synchronous rules checks under the latency budget for each integration.
10. Keep documentation neutral, factual, and ecosystem-friendly.

### 3.2 Non-Goals

1. Hosted SaaS.
2. Web UI.
3. Auth or multi-tenant account management.
4. Replacing framework-native tracing or observability.
5. Replacing MCP SDKs or agent framework SDKs.
6. Building proprietary integrations in this OSS repo.
7. Shipping unverified benchmark claims.
8. Auto-filing compliance reports as legal attestations.

## 4. Target Integration Inventory

### 4.1 Tier 0 - Already Shipped or In Progress

| Integration | Package surface | Status | Notes |
|---|---|---|---|
| MCP gateway wrapper | `prooflayer.runtime`, `prooflayer.integrations.mcp_gateway` | Existing | Must not break |
| LangGraph | `prooflayer.integrations.langgraph` | Existing v0.2.0 | Foundation for agent-framework pattern |
| Eval harness | `prooflayer.evals` | Existing v0.2.0 | Extend to all integrations |
| Compliance evidence | `prooflayer.compliance` | Existing v0.2.0 | Extend mappings as needed |

### 4.2 Tier 1 - Highest Priority

| Integration | Package surface | Priority | Reason |
|---|---|---:|---|
| LangChain MCP adapters | `prooflayer.integrations.langchain_mcp` | P0 | Direct bridge between MCP tools and LangChain/LangGraph |
| LlamaIndex | `prooflayer.integrations.llamaindex` | P0 | Major RAG and agent framework with MCP tool support |
| OpenAI Agents SDK | `prooflayer.integrations.openai_agents` | P0 | High-growth agent runtime with tool and handoff patterns |
| Claude Desktop / Claude Code MCP | `prooflayer.integrations.claude_mcp` | P0 | Important MCP host and developer workflow |
| Cursor MCP | `prooflayer.integrations.cursor_mcp` | P0 | Developer tool with local tool/file access risk |

### 4.3 Tier 2 - Agent Frameworks

| Integration | Package surface | Priority | Security focus |
|---|---|---:|---|
| CrewAI | `prooflayer.integrations.crewai` | P1 | Role drift, delegation abuse, multi-agent attacks |
| Microsoft AutoGen | `prooflayer.integrations.autogen` | P1 | Multi-agent message and tool-call inspection |
| Semantic Kernel | `prooflayer.integrations.semantic_kernel` | P1 | Enterprise workflows and planner/tool execution |
| Pydantic AI | `prooflayer.integrations.pydantic_ai` | P1 | Typed agents and tool validation |
| Agno | `prooflayer.integrations.agno` | P2 | Lightweight agent examples |
| Haystack | `prooflayer.integrations.haystack` | P2 | RAG pipeline security |
| DSPy | `prooflayer.integrations.dspy` | P2 | Prompt/program optimization eval security |

### 4.4 Tier 3 - MCP Hosts and Developer Environments

| Integration | Package surface | Priority | Security focus |
|---|---|---:|---|
| VS Code / GitHub Copilot MCP | `prooflayer.integrations.vscode_mcp` | P1 | Local tool and workspace exfil risk |
| Claude Desktop | `prooflayer.integrations.claude_desktop` | P1 | Desktop MCP config and server proxying |
| Claude Code | `prooflayer.integrations.claude_code` | P1 | CLI tool execution and repo context |
| Cursor | `prooflayer.integrations.cursor` | P1 | IDE agent command and filesystem safety |
| Windsurf | `prooflayer.integrations.windsurf` | P2 | IDE agent command and context safety |
| OpenCode | `prooflayer.integrations.opencode` | P2 | Coding-agent metadata and tool safety |
| Continue.dev | `prooflayer.integrations.continue_dev` | P2 | Local coding assistant MCP workflows |
| Zed AI | `prooflayer.integrations.zed_ai` | P2 | Editor-integrated MCP workflows |

### 4.5 Tier 4 - Gateways, Infrastructure, and SIEM

| Integration | Package surface | Priority | Security focus |
|---|---|---:|---|
| FastAPI MCP gateway | `prooflayer.integrations.fastapi_mcp` | P0 | Python gateway reference |
| Express / Node MCP gateway | `prooflayer.integrations.node_mcp` | P1 | JS gateway reference |
| Docker MCP gateway | `prooflayer.integrations.docker_gateway` | P1 | Containerized deployment |
| Kubernetes sidecar | `deploy/kubernetes/sidecar` | P1 | Production gateway pattern |
| Kubernetes admission controller | `deploy/kubernetes/admission-controller` | P2 | Policy enforcement at deployment |
| Cloudflare Workers MCP proxy | `prooflayer.integrations.cloudflare_workers` | P2 | Edge proxy pattern |
| Envoy / API gateway plugin | `deploy/envoy` | P2 | Enterprise traffic enforcement |
| Kong / Tyk / NGINX examples | `deploy/gateways` | P3 | Enterprise gateway examples |
| SUSE / NeuVector | `prooflayer.integrations.suse`, `docs/suse-integration.md` | Existing/P1 | Existing positioning, expand docs |
| Datadog SIEM export | `prooflayer.audit.datadog` | P1 | Security event ingestion |
| Splunk SIEM export | `prooflayer.audit.splunk` | P1 | Security event ingestion |

### 4.6 Tier 5 - Security, Policy, and Eval Extensions

| Integration | Package surface | Priority | Security focus |
|---|---|---:|---|
| Prompt-injection scanner MCP | `prooflayer.integrations.scanner_mcp` | P1 | MCP server scanner mode |
| Tool-poisoning scanner MCP | `prooflayer.integrations.tool_poisoning_scanner` | P1 | Tool-description scanning |
| Secrets scanner MCP | `prooflayer.integrations.secrets_scanner` | P1 | Prevent credential leakage |
| OPA / Rego policy | `prooflayer.policy.opa` | P1 | Customer policy as code |
| Garak eval runner | `prooflayer.evals.garak_runner` | Existing/P1 | Extend targets |
| Promptfoo eval runner | `prooflayer.evals.promptfoo_runner` | Existing/P1 | Extend targets |
| OWASP LLM Top 10 mapping | `prooflayer.compliance.owasp_llm` | P1 | Detection taxonomy |
| MITRE ATLAS mapping | `prooflayer.compliance.mitre_atlas` | P1 | Threat taxonomy |

## 5. User Personas

### 5.1 Platform Engineer

Needs to deploy ProofLayer as a gateway or sidecar around MCP tool traffic without modifying every agent app.

Success means:

- one container or middleware component
- low latency
- audit logs flow to SIEM
- policy can block risky tool calls

### 5.2 AI Application Engineer

Needs to wrap a specific agent runtime such as LangGraph, LlamaIndex, CrewAI, or OpenAI Agents SDK.

Success means:

- 3 to 10 lines of integration code
- no major changes to agent logic
- clean exceptions for blocked events
- clear examples and tests

### 5.3 Security Engineer

Needs proof that attacks are detected, blocked, and logged with traceable evidence.

Success means:

- rule IDs and evidence snippets
- deterministic hashes
- SIEM-compatible JSON
- adversarial eval reports
- compliance mapping

### 5.4 Developer Tool User

Uses Claude Code, Cursor, VS Code, or another MCP host locally.

Success means:

- simple local proxy setup
- protection from poisoned tools and repo context
- protection from filesystem and shell exfiltration
- clear block messages

## 6. Core Architecture

### 6.1 Design Principle

Every integration should adapt its runtime-specific events into a shared ProofLayer security contract:

```python
SecurityEnvelope(
    integration="langchain_mcp",
    event_type="tool_call",
    session_id="...",
    actor="agent",
    tool_name="search_docs",
    input={...},
    output=None,
    metadata={...},
)
```

The shared pipeline should then:

1. Normalize input.
2. Scan with deterministic rules.
3. Apply optional policy checks.
4. Decide allow, warn, block, or kill.
5. Emit audit event.
6. Return or raise runtime-specific result.

### 6.2 Shared Modules

Proposed new shared modules:

```text
prooflayer/
  integrations/
    common/
      __init__.py
      envelope.py
      adapter.py
      decisions.py
      exceptions.py
      runtime_proxy.py
      tool_events.py
      config.py
  policy/
    __init__.py
    engine.py
    opa.py
    models.py
  audit/
    datadog.py
    splunk.py
    otel.py
```

### 6.3 Integration Contract

Every integration must expose:

```python
class IntegrationAdapter(Protocol):
    """Runtime adapter contract for ProofLayer integrations."""

    integration_name: str

    def wrap(self, target: Any) -> Any:
        """Return a protected runtime object."""

    def scan_input(self, payload: Any, config: Optional[dict] = None) -> Decision:
        """Inspect runtime input before execution."""

    def scan_output(self, payload: Any, config: Optional[dict] = None) -> Decision:
        """Inspect runtime output after execution."""

    def get_audit_log(self, session_id: Optional[str] = None) -> list[dict]:
        """Return audit events."""
```

### 6.4 Shared Security Config

Existing `SecurityConfig` should be generalized into:

```python
@dataclass
class RuntimeSecurityConfig:
    prompt_injection: DetectionAction = "warn"
    jailbreak: DetectionAction = "warn"
    tool_abuse: DetectionAction = "warn"
    tool_poisoning: DetectionAction = "warn"
    command_injection: DetectionAction = "block"
    exfil: DetectionAction = "block"
    scope_drift: DetectionAction = "warn"
    state_manipulation: DetectionAction = "warn"
    multi_turn: DetectionAction = "warn"
    memory_poisoning: DetectionAction = "warn"
    unsafe_handoff: DetectionAction = "warn"
    allowed_tools: Optional[list[str]] = None
    blocked_tools: Optional[list[str]] = None
    allowed_domains: Optional[list[str]] = None
    blocked_domains: Optional[list[str]] = None
    max_tool_calls_per_turn: Optional[int] = None
    compliance_frameworks: list[str] = field(default_factory=list)
    emit_to: list[str] = field(default_factory=lambda: ["stdout"])
```

Backward compatibility requirement:

- `prooflayer.integrations.langgraph.SecurityConfig` must keep working.
- It may subclass or adapt `RuntimeSecurityConfig`, but public imports must not break.

## 7. Public API Requirements

### 7.1 LangChain MCP Adapter API

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from prooflayer.integrations.langchain_mcp import SecurityMiddleware, SecurityConfig

client = MultiServerMCPClient({...})
tools = await client.get_tools()

middleware = SecurityMiddleware(
    config=SecurityConfig(
        prompt_injection="block",
        tool_poisoning="block",
        exfil="block",
        emit_to=["stdout", "logfile:./audit.jsonl"],
    )
)

safe_tools = middleware.wrap_tools(tools)
```

Acceptance:

- Works with LangChain agents.
- Works with LangGraph agents.
- Blocks malicious tool descriptions before tools are made available to the agent.
- Blocks malicious tool arguments before MCP server execution.
- Scans tool outputs before returning them to the agent.

### 7.2 LlamaIndex API

```python
from prooflayer.integrations.llamaindex import ProofLayerToolWrapper

safe_tools = ProofLayerToolWrapper(config=config).wrap_tools(mcp_tools)
```

Acceptance:

- Works with LlamaIndex tool abstractions.
- Scans retrieved context chunks.
- Scans tool calls and tool outputs.
- Emits audit events with document source metadata when available.

### 7.3 OpenAI Agents SDK API

```python
from prooflayer.integrations.openai_agents import ProofLayerGuardrail

guardrail = ProofLayerGuardrail(config=config)
agent = guardrail.wrap_agent(agent)
```

Acceptance:

- Scans user input, tool input, tool output, and handoff messages.
- Blocks unsafe delegation.
- Preserves native agent invocation semantics.

### 7.4 Claude / Cursor / Local MCP Host API

```bash
prooflayer mcp-proxy \
  --host claude-desktop \
  --config ./prooflayer.yaml \
  --audit ./audit.jsonl
```

Acceptance:

- Can run as a local MCP proxy.
- Reads MCP server configuration.
- Proxies tool calls through ProofLayer.
- Supports stdout, JSONL, and SIEM output.
- Provides clear installation instructions for each host.

### 7.5 Gateway API

```python
from prooflayer.integrations.fastapi_mcp import ProofLayerMCPMiddleware

app.add_middleware(
    ProofLayerMCPMiddleware,
    config=RuntimeSecurityConfig(exfil="block"),
)
```

Acceptance:

- Protects HTTP and stdio MCP transports where applicable.
- Supports streaming responses.
- Supports request IDs, session IDs, and trace IDs.
- Can emit OpenTelemetry-compatible metadata.

## 8. Package Extras

Update `setup.py` and/or `pyproject.toml` with optional extras:

```toml
[project.optional-dependencies]
langchain-mcp = [
    "langchain-mcp-adapters>=0.1.0",
    "langchain-core>=0.3.0",
]
llamaindex = [
    "llama-index>=0.12.0",
]
openai-agents = [
    "openai-agents>=0.1.0",
]
crewai = [
    "crewai>=0.100.0",
]
autogen = [
    "autogen-agentchat>=0.4.0",
]
semantic-kernel = [
    "semantic-kernel>=1.0.0",
]
pydantic-ai = [
    "pydantic-ai>=0.0.20",
]
gateway = [
    "fastapi>=0.110.0",
    "uvicorn>=0.27.0",
]
siem = [
    "structlog>=24.0.0",
]
policy = [
    "requests>=2.31.0",
]
all-integrations = [
    "prooflayer-rules[langgraph,langchain-mcp,llamaindex,openai-agents,crewai,autogen,semantic-kernel,pydantic-ai,gateway,siem,policy]",
]
```

Important:

- Before implementation, verify current package names and minimum versions.
- Do not guess dependency names for frameworks whose packaging changes.
- Pin upper bounds only if compatibility breaks.

## 9. Repository Structure

Target structure:

```text
prooflayer-rules/
  prooflayer/
    integrations/
      common/
      langgraph/                  # existing
      langchain_mcp/
      llamaindex/
      openai_agents/
      claude_mcp/
      cursor_mcp/
      crewai/
      autogen/
      semantic_kernel/
      pydantic_ai/
      fastapi_mcp/
      node_mcp/
    policy/
    audit/
  examples/
    integrations/
      langchain_mcp/
      llamaindex/
      openai_agents/
      claude_mcp/
      cursor_mcp/
      crewai/
      autogen/
      semantic_kernel/
      pydantic_ai/
      gateways/
  tests/
    integrations/
      common/
      langchain_mcp/
      llamaindex/
      openai_agents/
      claude_mcp/
      cursor_mcp/
      crewai/
      autogen/
      semantic_kernel/
      pydantic_ai/
      gateways/
    policy/
    audit/
  docs/
    integrations/
      langchain_mcp.md
      llamaindex.md
      openai_agents.md
      claude_mcp.md
      cursor_mcp.md
      crewai.md
      autogen.md
      semantic_kernel.md
      pydantic_ai.md
      gateways.md
      siem.md
      policy.md
```

## 10. Detection and Policy Requirements

### 10.1 Required Detection Categories

Every integration must support, at minimum:

1. Prompt injection
2. Jailbreak
3. Tool abuse
4. Tool poisoning
5. Command injection
6. Data exfiltration
7. Scope drift
8. State manipulation
9. Multi-turn manipulation
10. Memory poisoning

Agent-framework integrations must additionally support:

11. Unsafe delegation
12. Role drift
13. Cross-agent instruction smuggling

Developer-tool integrations must additionally support:

14. Filesystem exfiltration
15. Shell command injection
16. Repo-context poisoning
17. Secret leakage

Gateway integrations must additionally support:

18. Suspicious transport metadata
19. Unexpected tool schema changes
20. High-risk domain egress

### 10.2 Rule Traceability

Every detection event must include:

```json
{
  "event_type": "detection",
  "integration": "langchain_mcp",
  "category": "tool_poisoning",
  "timestamp": "2026-07-30T00:00:00Z",
  "session_id": "session-123",
  "decision": "block",
  "risk_score": 92,
  "rule_ids": ["poison-hidden-instruction"],
  "rule_sources": [
    {
      "id": "poison-hidden-instruction",
      "category": "tool_poisoning",
      "severity": "critical",
      "source": "prooflayer-rules"
    }
  ],
  "evidence_snippet": "...",
  "hash": "sha256:...",
  "previous_hash": "sha256:..."
}
```

No fabricated evidence. If a finding comes from a heuristic rather than a YAML rule, it must identify itself as a heuristic rule with a stable ID.

## 11. Performance Requirements

| Surface | Target |
|---|---:|
| Synchronous tool-call scan p99 | < 25 ms |
| Synchronous agent input scan p99 | < 50 ms |
| Gateway request hot path p99 | < 50 ms |
| LangGraph node hot path p99 | < 100 ms |
| Audit event append p99 | < 10 ms |

Rules:

- Deterministic rules stay synchronous.
- LLM-based scoring, if added later, must be async or out-of-band.
- Do not weaken latency budgets to pass benchmarks.
- If latency exceeds budget, profile before refactoring.

## 12. Testing Strategy

### 12.1 Unit Tests

Every integration module must include tests for:

- config validation
- benign input allow path
- malicious input block path
- warning path
- audit event emission
- session ID propagation
- rule ID propagation
- exception behavior
- no dependency import when extra is not installed

### 12.2 Integration Tests

Each framework integration must include:

- mocked runtime object test
- minimal real runtime test if dependency is installed
- tool-call inspection test
- tool-output inspection test
- streaming test where applicable
- async invocation test where applicable

### 12.3 End-to-End Examples

Every example must include:

- run command
- expected benign output
- expected blocked attack output
- audit event sample
- "what to try to break" section

### 12.4 Compatibility Tests

CI matrix:

- Python 3.10
- Python 3.11
- Python 3.12
- Python 3.13, if dependencies support it

Dependency strategy:

- Base tests run without optional extras.
- Integration tests are grouped by extra.
- Missing optional dependency should skip, not fail, unless the job is specifically for that extra.

## 13. Documentation Requirements

Each integration doc must include:

1. Overview
2. Install
3. Setup
4. Working example
5. Detection categories
6. Audit output
7. Troubleshooting
8. Compatibility notes
9. Links to upstream framework docs

Docs must use neutral language:

- Say "complements", not "replaces".
- Say "security layer", not "alternative runtime".
- Do not claim benchmark numbers unless generated in this repo.
- Do not claim built-in compliance mappings unless implemented.

## 14. Release Plan

### 14.1 v0.3.0 - MCP Core and LangChain/LlamaIndex

Goal: establish shared integration architecture.

Scope:

- `prooflayer.integrations.common`
- `prooflayer.integrations.langchain_mcp`
- `prooflayer.integrations.llamaindex`
- shared `RuntimeSecurityConfig`
- generalized audit event schema
- SIEM JSONL improvements
- examples and docs

Acceptance:

- LangChain MCP adapter example runs.
- LlamaIndex MCP example runs.
- Tool poisoning is blocked before agent exposure.
- Tool argument exfiltration is blocked before MCP execution.
- Tool output exfiltration is blocked before returning to agent.
- Existing LangGraph and MCP gateway tests still pass.

### 14.2 v0.4.0 - Agent Framework Expansion

Goal: support multi-agent and typed-agent runtimes.

Scope:

- OpenAI Agents SDK
- CrewAI
- AutoGen
- Semantic Kernel
- Pydantic AI
- unsafe delegation detector
- role drift detector
- cross-agent instruction smuggling detector

Acceptance:

- At least 5 framework examples run.
- Multi-agent attack demo blocks instruction smuggling.
- Handoff abuse emits audit evidence.
- Async paths are tested.

### 14.3 v0.5.0 - Developer MCP Hosts and Local Proxy

Goal: protect developer MCP workflows.

Scope:

- local `prooflayer mcp-proxy`
- Claude Desktop setup guide
- Claude Code setup guide
- Cursor setup guide
- VS Code / Copilot setup guide
- OpenCode / Continue / Zed docs as compatibility guides

Acceptance:

- Local proxy can wrap an MCP server config.
- Tool description poisoning is blocked.
- Filesystem exfiltration is blocked.
- Shell command injection is blocked.
- Clear local setup docs exist for each supported host.

### 14.4 v0.6.0 - Gateway, SIEM, Policy, and Enterprise Deploy

Goal: production deployment patterns.

Scope:

- FastAPI MCP gateway middleware
- Docker gateway image
- Kubernetes sidecar manifests
- Datadog exporter
- Splunk exporter
- OPA/Rego policy checks
- OWASP LLM Top 10 mapping
- MITRE ATLAS mapping

Acceptance:

- Docker gateway runs locally.
- Kubernetes sidecar manifests validate.
- Datadog and Splunk JSON schemas are documented.
- OPA policy can block a tool call.
- Compliance and threat taxonomy mappings are documented.

## 15. Detailed Milestones

### Phase 1 - Foundation, 2 Weeks

1. Design `SecurityEnvelope`.
2. Design `RuntimeSecurityConfig`.
3. Implement `IntegrationAdapter` protocol.
4. Refactor LangGraph integration internally to use common primitives without changing public API.
5. Add common audit event hashing.
6. Add common integration test helpers.
7. Add docs for the integration architecture.

Exit criteria:

- Existing test suite passes.
- LangGraph public API unchanged.
- MCP gateway still works.
- New common tests pass.

### Phase 2 - LangChain MCP and LlamaIndex, 3 Weeks

1. Implement `langchain_mcp` wrappers.
2. Implement `llamaindex` wrappers.
3. Add examples for both.
4. Add tool-poisoning tests for tool descriptions.
5. Add tool argument and output tests.
6. Add docs.
7. Benchmark hot path.

Exit criteria:

- Both integrations can wrap tools.
- Both integrations block known attack fixtures.
- Both integrations emit audit events.
- p99 hot path is within budget.

### Phase 3 - OpenAI Agents, CrewAI, AutoGen, Semantic Kernel, 4 Weeks

1. Inspect current public APIs.
2. Add adapters behind optional extras.
3. Build minimal examples.
4. Add multi-agent attack fixtures.
5. Implement unsafe delegation detector.
6. Implement role drift detector.
7. Implement cross-agent instruction smuggling detector.
8. Add docs and tests.

Exit criteria:

- Four integrations have runnable examples.
- Attack demos block or warn as configured.
- Public APIs are type hinted and documented.

### Phase 4 - Developer MCP Hosts, 3 Weeks

1. Implement local proxy command.
2. Add host config readers where safe.
3. Add Claude Desktop guide.
4. Add Claude Code guide.
5. Add Cursor guide.
6. Add VS Code / Copilot guide.
7. Add local attack demo.

Exit criteria:

- Local proxy can sit between host and MCP server.
- Tool poisoning and local exfil tests pass.
- Docs include rollback instructions.

### Phase 5 - Gateway, SIEM, Policy, 4 Weeks

1. Implement FastAPI gateway middleware.
2. Add Docker gateway image.
3. Add Kubernetes sidecar manifests.
4. Add Datadog exporter.
5. Add Splunk exporter.
6. Add OPA/Rego policy integration.
7. Add taxonomy mappings.
8. Add enterprise deployment docs.

Exit criteria:

- Gateway example runs.
- SIEM events validate.
- OPA blocks policy violations.
- Kubernetes manifests pass schema validation.

## 16. Final Acceptance Criteria

The integration program is complete when all of these are true:

- All Tier 1 integrations are implemented, tested, and documented.
- At least four Tier 2 integrations are implemented, tested, and documented.
- Local MCP proxy supports Claude Desktop, Claude Code, Cursor, and VS Code setup guides.
- FastAPI gateway and Docker gateway examples run.
- Datadog and Splunk exporters emit documented schemas.
- OPA/Rego policy can block high-risk tool calls.
- OWASP LLM Top 10 and MITRE ATLAS mappings exist.
- All new public functions have type hints.
- All public classes and functions have docstrings.
- New module coverage is at least 80%.
- Existing MCP gateway integration remains backward compatible.
- Existing LangGraph integration remains backward compatible.
- All examples include benign and attack demonstrations.
- PyPI release includes optional extras.
- README features the integration family clearly.

## 17. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---:|---:|---|
| Upstream APIs change quickly | High | Medium | Optional extras, version-gated tests, adapters isolated by module |
| Too many integrations dilute quality | Medium | High | Tiered release plan, strict acceptance gates |
| Latency exceeds budget | Medium | High | Keep deterministic rules sync; move LLM scoring async |
| Optional dependencies break base install | Medium | High | Import lazily and test base install without extras |
| Maintainers reject docs/partnership PRs | Medium | Medium | Neutral positioning, runnable examples, no inflated claims |
| Developer host setup differs by OS | High | Medium | Document macOS first, then Linux/Windows |
| Compliance claims overreach | Medium | High | Built-in mappings only when implemented; evidence-input language otherwise |
| Security rules generate false positives | Medium | Medium | Allow warn/allow modes, allowlists, and policy exceptions |

## 18. Open Questions - Stop and Ask

Implementation agents must stop and ask before deciding:

1. Which exact package versions should be the minimum supported versions for every optional extra?
2. Should JS/TypeScript runtime integrations live in this repo, a separate repo, or examples only?
3. Should local MCP proxy mutate host config files automatically, or only print instructions?
4. Should Claude Desktop and Cursor support be docs-only at first, or include a tested config generator?
5. Should OPA/Rego policies be embedded in Python, called over HTTP, or both?
6. Should Kubernetes sidecar be Helm-first, raw manifests-first, or both?
7. Should Datadog and Splunk events share one schema or have vendor-specific fields?
8. Should ISO 42001, DPDP Act, RBI AI/ML guidance, CERT-In, and AIUC-1 remain evidence-input docs only until full control registries are implemented?
9. Should `RuntimeSecurityConfig` replace integration-specific `SecurityConfig` names, or should every integration expose a compatibility alias?
10. Should MCP host integrations be branded as "proxy mode" to avoid implying official vendor partnership?

## 19. Dispatch Prompt for Coding Agent

Use this prompt to start implementation:

```text
Read MCP_RUNTIME_INTEGRATIONS_PRD.md top to bottom. This is the integration
program for ProofLayer after the LangGraph v0.2 release.

Hard rules:
- Keep all code inside the existing prooflayer/* package.
- Do not create a sibling package.
- Preserve existing MCP gateway and LangGraph public APIs.
- Use optional extras for integration dependencies.
- Import optional dependencies lazily.
- Every public function must have type hints.
- Every public class and public function must have docstrings.
- Every detection event must include stable rule IDs and timestamps.
- Do not fabricate compliance evidence.
- Keep deterministic hot-path rules synchronous.
- Move any LLM scoring or expensive analysis out of the hot path.
- Add tests with at least 80% coverage for new modules.

Start with Phase 1 only:
1. Inspect the current repo architecture.
2. Restate the Phase 1 implementation plan.
3. Implement prooflayer.integrations.common.
4. Refactor LangGraph internals to use common primitives without breaking public API.
5. Verify existing MCP gateway and LangGraph tests still pass.
6. Commit only after tests pass.

Stop at every open question in section 18. Do not silently guess.
```

## 20. Immediate Next Step

Start with v0.3.0:

1. Create a tracking issue for this PRD.
2. Create a Phase 1 branch.
3. Implement shared integration primitives.
4. Add LangChain MCP adapter as the first new integration.
5. Add LlamaIndex as the second new integration.

Do not start Tier 2 framework integrations until the shared primitives and Tier 1 tool-wrapper pattern are stable.

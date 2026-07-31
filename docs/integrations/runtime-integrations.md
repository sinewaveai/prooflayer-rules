# Runtime Integration Architecture

ProofLayer runtime integrations adapt framework-specific activity into a shared
security contract. The contract lets future integrations reuse the same
detection engine, policy decisions, audit event hashing, and compliance evidence
without duplicating LangGraph-specific code.

## Shared Primitives

Phase 1 adds `prooflayer.integrations.common` with these public primitives:

| Primitive | Purpose |
|---|---|
| `RuntimeSecurityConfig` | Shared detection and audit configuration for runtime adapters |
| `SecurityEnvelope` | Normalized representation of runtime activity before detection |
| `Decision` | Normalized allow, warn, or block decision returned by adapters |
| `IntegrationAdapter` | Protocol for framework-specific wrappers |
| `SecuredRuntimeProxy` | Base proxy that delegates unknown attributes to wrapped runtimes |
| `ToolCallEvent` / `ToolOutputEvent` | Normalized tool activity records |
| `AuditEventRecorder` | In-memory audit recorder with sha256 chain-of-custody hashes |

## Integration Flow

Every runtime integration should follow this flow:

1. Convert runtime input, tool call, state update, or output into a
   `SecurityEnvelope`.
2. Run deterministic ProofLayer rules synchronously.
3. Apply integration or customer policy.
4. Convert the result into a `Decision`.
5. Raise the integration-specific blocked exception when configured to block.
6. Record an audit event with rule IDs, timestamps, and hash-chain fields.
7. Delegate to the underlying runtime when the decision allows execution.

## Backward Compatibility

The LangGraph integration keeps its public API:

```python
from prooflayer.integrations.langgraph import SecurityConfig, SecurityMiddleware
```

Internally, `SecurityConfig` now subclasses `RuntimeSecurityConfig`, and
`SecurityMiddleware` records audit events through the shared recorder. Existing
LangGraph customers can keep using the v0.2 API while later integrations reuse
the shared primitives.

## Audit Hash Fields

Integration audit events include:

```json
{
  "event_type": "detection",
  "session_id": "thread-1",
  "rule_ids": ["direct-ignore-previous"],
  "previous_hash": null,
  "event_hash": "64-character-sha256",
  "hash": "sha256:64-character-sha256"
}
```

`previous_hash` links each event to the prior event in the same recorder. This
supports chain-of-custody evidence without requiring a hosted service.

## Adapter Rules

New integrations must:

- import optional framework dependencies lazily
- preserve the wrapped framework's native invocation semantics
- emit the shared audit schema
- expose a small public wrapper API
- include benign, warn, block, and audit tests
- avoid benchmark claims unless measured in this repository

## Phase 2 Handoff

Phase 2 should add `prooflayer.integrations.langchain_mcp` and
`prooflayer.integrations.llamaindex` using these shared primitives. It should
not add package extras until exact supported dependency versions are confirmed.

## Phase 2 Status

Phase 2 adds the first two shared-primitive integrations:

| Integration | Public API | Protected surfaces |
|---|---|---|
| LangChain MCP | `SecurityMiddleware.wrap_tools(tools)` | tool descriptions, arguments, outputs |
| LlamaIndex | `ProofLayerToolWrapper.wrap_tools(tools)` | tool descriptions, arguments, outputs, retrieved context |

The optional extras are:

```bash
pip install "prooflayer-rules[langchain-mcp]"
pip install "prooflayer-rules[llamaindex]"
```

Both integrations keep optional framework imports out of the base import path.

## Phase 3 Status

Phase 3 adds dependency-light wrappers for agent-framework runtimes:

| Integration | Public API | Protected surfaces |
|---|---|---|
| OpenAI Agents SDK | `ProofLayerGuardrail.wrap_agent(agent)` | agent input, output, tools, handoffs |
| CrewAI | `SecurityMiddleware.wrap_crew(crew)` / `wrap_agent(agent)` | crew input, output, tools, delegation |
| AutoGen | `SecurityMiddleware.wrap_agent(agent)` | messages, output, tools, handoffs |
| Semantic Kernel | `SecurityMiddleware.wrap_kernel(kernel)` / `wrap_agent(agent)` | kernel input, output, tools, handoffs |
| Pydantic AI | `SecurityMiddleware.wrap_agent(agent)` | typed-agent input, output, tools, handoffs |

The optional extras are:

```bash
pip install "prooflayer-rules[openai-agents]"
pip install "prooflayer-rules[crewai]"
pip install "prooflayer-rules[autogen]"
pip install "prooflayer-rules[semantic-kernel]"
pip install "prooflayer-rules[pydantic-ai]"
```

These adapters share role-drift, unsafe-handoff, and cross-agent instruction
smuggling checks through `prooflayer.integrations.common.AgentSecurity`.

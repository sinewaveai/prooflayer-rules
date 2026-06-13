# ProofLayer LangGraph Integration

ProofLayer adds runtime security checks around compiled LangGraph agents. It is complementary to LangGraph and LangSmith: LangGraph runs stateful agents, LangSmith provides tracing and generic evals, and ProofLayer provides adversarial evals, runtime security, and compliance evidence.

## Install

```bash
pip install prooflayer-rules[langgraph]
```

For local development from this repository:

```bash
pip install -e ".[langgraph,dev]"
```

## Three-Line Integration

```python
from prooflayer.integrations.langgraph import SecurityConfig, SecurityMiddleware

middleware = SecurityMiddleware(SecurityConfig(prompt_injection="block"))
secured_graph = middleware.wrap(graph.compile())
result = secured_graph.invoke({"input": user_input})
```

The wrapper preserves the compiled LangGraph interface for `invoke`, `ainvoke`, `stream`, `astream`, `stream_events`, and `astream_events`.

## Configuration

```python
SecurityConfig(
    prompt_injection="block",
    jailbreak="block",
    tool_abuse="block",
    exfil="block",
    scope_drift="warn",
    state_manipulation="block",
    multi_turn="warn",
    compliance_frameworks=["nist_ai_rmf", "soc2"],
    emit_to=["stdout", "logfile:./audit.jsonl"],
    allowed_tools=["search_docs"],
)
```

Each detection action is one of `allow`, `warn`, or `block`.

## Runtime Coverage

- Prompt injection and jailbreak checks run before graph execution.
- Tool abuse checks run on configured tool hooks and input attempts that match command, SQL, SSRF/XXE, or tool-poisoning rules.
- Exfiltration checks run on inputs, tool arguments, graph outputs, and streaming chunks.
- Scope drift checks run on graph outputs.
- State manipulation checks run on state updates and state-like graph inputs.
- Multi-turn checks track suspicious signals per LangGraph `thread_id` or configured session key.

## Tool Validation

Use `middleware.hooks.on_tool_call()` inside tool nodes when you want tool-level validation:

```python
middleware.hooks.on_tool_call("search_docs", {"query": query}, config)
```

When `allowed_tools` is set, unlisted tools are blocked or warned according to `tool_abuse`.

## Streaming

By default, critical streaming detections raise `BlockedError`. To replace blocked chunks instead:

```python
SecurityConfig(
    exfil="block",
    streaming_block_mode="replace",
    blocked_token="[BLOCKED]",
)
```

## Audit Events

The in-memory audit log is available for tests, demos, or handoff to compliance reporting:

```python
events = middleware.get_audit_log(session_id="thread-1")
```

Structured audit emission with hash chaining is available through `prooflayer.audit.AuditLogger`.

## Examples

Run all local examples without external LLM credentials:

```bash
python examples/integrations/langgraph/01_simple_rag.py
python examples/integrations/langgraph/02_tool_calling_agent.py
python examples/integrations/langgraph/03_multi_agent_supervisor.py
python examples/integrations/langgraph/04_memory_attack_demo.py
python examples/integrations/langgraph/05_production_template.py
```

Each example prints a benign path and an attack path that is blocked.

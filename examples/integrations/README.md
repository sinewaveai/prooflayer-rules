# Integration Examples

Patterns for embedding ProofLayer into MCP gateways, proxies, and agent platforms.

## Files

### Agent framework examples

These examples use tiny local runtime objects so the ProofLayer security behavior
can be exercised without API keys:

```bash
python3 examples/integrations/openai_agents/simple_guardrail.py
python3 examples/integrations/crewai/simple_crew.py
python3 examples/integrations/autogen/simple_agent.py
python3 examples/integrations/semantic_kernel/simple_kernel.py
python3 examples/integrations/pydantic_ai/simple_agent.py
```

### [`mcp_gateway_proxy.py`](mcp_gateway_proxy.py)

Reference pattern showing how a gateway (e.g., ToolHive, custom enterprise reverse-proxy) routes MCP tool-call requests through ProofLayer before forwarding to the backend MCP server.

Run it:

```bash
python3 examples/integrations/mcp_gateway_proxy.py
```

You'll see four sample tool calls inspected:

1. A benign `add_system` — **ALLOW**, forwarded
2. A command-injection `add_system` — **BLOCK**, audited
3. A `/etc/passwd` read — **BLOCK**, audited
4. A jailbreak-prompted `set_role` — **WARN** or **BLOCK** depending on configured thresholds

The `MCPGatewayProxy` class wraps a `ProofLayerRuntime` and exposes a single `inspect_and_forward(tool_name, arguments)` method that branches on the four `ThreatAction`s:

| Action  | Decision                                                                 |
| ------- | ------------------------------------------------------------------------ |
| `ALLOW` | Forward to backend                                                       |
| `WARN`  | Forward to backend, emit audit event                                     |
| `BLOCK` | Reject, emit audit event, return structured error to client              |
| `KILL`  | Reject + signal gateway to terminate the upstream MCP session entirely   |

## Adapting to your gateway

The file is dependency-free beyond `prooflayer` itself. To plug into a real gateway:

1. Inject your dispatcher as the `forward_to_backend` callable.
2. Inject your observability sink as the `audit` callable (Datadog, Honeycomb, OpenTelemetry, plain logs — anything).
3. Call `proxy.inspect_and_forward(tool, args, context=...)` from your `tools/call` handler.
4. Map `GatewayDecision.response` back to your gateway's response envelope.

## Detector-assisted mode

To layer model-backed scoring on top of the rules engine, pass `detector_url` (and optional `detector_timeout_ms`) when constructing `ProofLayerRuntime`:

```python
runtime = ProofLayerRuntime(
    action_on_threat="block",
    detector_url="http://127.0.0.1:8088",
    detector_timeout_ms=250,
)
```

The detector tier is a separate commercial offering. Rules-only is the default and degrades gracefully if the detector is unreachable.

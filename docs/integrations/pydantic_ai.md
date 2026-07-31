# Pydantic AI Integration

ProofLayer provides `SecurityMiddleware` for wrapping Pydantic AI-style agents with runtime security checks. The wrapper scans typed-agent input, output, callable tools, and handoff messages. It keeps the agent's native invocation flow intact while emitting ProofLayer audit events.

## Install

```bash
pip install "prooflayer-rules[pydantic-ai]"
```

## Setup

```python
from prooflayer.integrations.pydantic_ai import SecurityConfig, SecurityMiddleware

middleware = SecurityMiddleware(
    config=SecurityConfig(
        prompt_injection="block",
        unsafe_handoff="block",
        exfil="block",
    )
)

secured_agent = middleware.wrap_agent(agent)
```

## Detection Categories

- Prompt injection
- Jailbreak
- Tool abuse
- Tool poisoning
- Data exfiltration
- Role drift
- Unsafe delegation
- Cross-agent instruction smuggling

## Audit Output

Detection events include the `pydantic_ai` integration name, timestamp, decision, rule IDs, evidence payload, and sha256 chain-of-custody hash.

## Compatibility Notes

The adapter is dependency-light and works with agent objects that expose common sync or async invocation methods.

# AutoGen Integration

ProofLayer provides `SecurityMiddleware` for wrapping Microsoft AutoGen-style agents with runtime security checks. The wrapper scans user messages, agent outputs, callable tools, and agent-to-agent handoff messages. It is designed to complement AutoGen's multi-agent conversation patterns without replacing native orchestration.

## Install

```bash
pip install "prooflayer-rules[autogen]"
```

## Setup

```python
from prooflayer.integrations.autogen import SecurityConfig, SecurityMiddleware

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

Detection events include the `autogen` integration name, timestamp, decision, rule IDs, evidence payload, and sha256 chain-of-custody hash.

## Compatibility Notes

The adapter is tested with framework-like runtime objects and keeps optional AutoGen dependencies outside the base install path.

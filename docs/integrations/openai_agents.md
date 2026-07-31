# OpenAI Agents SDK Integration

ProofLayer provides `ProofLayerGuardrail` for wrapping OpenAI Agents SDK-style runtimes with deterministic security checks. The wrapper scans agent input, agent output, callable tools, and handoff messages while preserving common invocation methods such as `run`, `arun`, `invoke`, and `ainvoke`. Optional dependencies are loaded by the customer application; importing ProofLayer's adapter does not require the OpenAI Agents SDK to be installed.

## Install

```bash
pip install "prooflayer-rules[openai-agents]"
```

## Setup

```python
from prooflayer.integrations.openai_agents import ProofLayerGuardrail, SecurityConfig

guardrail = ProofLayerGuardrail(
    config=SecurityConfig(
        prompt_injection="block",
        exfil="block",
        unsafe_handoff="block",
    )
)

secured_agent = guardrail.wrap_agent(agent)
```

## Detection Categories

- Prompt injection
- Jailbreak
- Tool abuse
- Tool poisoning
- Data exfiltration
- Role drift
- Unsafe handoff
- Cross-agent instruction smuggling

## Audit Output

Detection events include the `openai_agents` integration name, timestamp, decision, rule IDs, evidence payload, and sha256 chain-of-custody hash.

## Compatibility Notes

The adapter is dependency-light and method-preserving. It is intended to wrap agent objects that expose common methods such as `run`, `arun`, `invoke`, `ainvoke`, `call`, or `execute`.

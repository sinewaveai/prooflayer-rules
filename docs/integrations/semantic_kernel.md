# Semantic Kernel Integration

ProofLayer provides `SecurityMiddleware` for wrapping Semantic Kernel agents and kernels with runtime security checks. The wrapper scans kernel input, output, callable tools, and agent handoff messages. It complements Semantic Kernel by adding deterministic threat detection and audit events around execution.

## Install

```bash
pip install "prooflayer-rules[semantic-kernel]"
```

## Setup

```python
from prooflayer.integrations.semantic_kernel import SecurityConfig, SecurityMiddleware

middleware = SecurityMiddleware(
    config=SecurityConfig(
        prompt_injection="block",
        unsafe_handoff="block",
        exfil="block",
    )
)

secured_kernel = middleware.wrap_kernel(kernel)
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

Detection events include the `semantic_kernel` integration name, timestamp, decision, rule IDs, evidence payload, and sha256 chain-of-custody hash.

## Compatibility Notes

The adapter does not import Semantic Kernel at module import time. It wraps common runtime methods such as `run`, `invoke`, `call`, and `execute`.

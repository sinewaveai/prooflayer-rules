# CrewAI Integration

ProofLayer provides `SecurityMiddleware` for wrapping CrewAI crews and agents with runtime security checks. The wrapper scans crew inputs, outputs, tools, and delegation messages while preserving common methods such as `kickoff`, `kickoff_async`, `run`, and `invoke`. It complements CrewAI orchestration by adding a deterministic security layer around execution.

## Install

```bash
pip install "prooflayer-rules[crewai]"
```

## Setup

```python
from prooflayer.integrations.crewai import SecurityConfig, SecurityMiddleware

middleware = SecurityMiddleware(
    config=SecurityConfig(
        prompt_injection="block",
        unsafe_handoff="block",
        exfil="block",
    )
)

secured_crew = middleware.wrap_crew(crew)
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

Detection events include the `crewai` integration name, timestamp, decision, rule IDs, evidence payload, and sha256 chain-of-custody hash.

## Compatibility Notes

The adapter does not import CrewAI at module import time. Base `prooflayer-rules` installs remain independent of CrewAI's dependency graph.

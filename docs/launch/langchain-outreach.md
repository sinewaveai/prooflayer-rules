# LangChain DevRel Outreach

Subject: ProofLayer Rules v0.2.0: Apache-2.0 runtime security layer for LangGraph

Hi LangChain team,

We are the Sinewave AI / ProofLayer team. We just built first-class LangGraph support into `prooflayer-rules`, our Apache-2.0 runtime security package for AI agents and MCP servers.

The integration is designed to complement LangGraph and LangSmith:

| Layer | What it does | Provided by |
|---|---|---|
| Agent orchestration | Build, deploy, run agents | LangGraph |
| Tracing + observability | See what agents did | LangSmith |
| Generic evals | LLM-as-judge, regression tests | LangSmith |
| Adversarial evals | GARAK / PromptFoo red-team probes | ProofLayer |
| Runtime security | Real-time prompt injection, tool abuse, exfil detection + blocking | ProofLayer |
| Compliance evidence | NIST AI RMF / EU AI Act / SOC 2 / HIPAA audit-defensible reports | ProofLayer |

What is included in the v0.2.0 sprint:

- `prooflayer.integrations.langgraph.SecurityMiddleware`
- support for `invoke`, `ainvoke`, `stream`, `astream`, `stream_events`, and `astream_events`
- runtime checks for prompt injection, jailbreaks, tool abuse, exfiltration, scope drift, state manipulation, multi-turn attacks, and streaming output risks
- built-in LangGraph adversarial eval suite
- GARAK and PromptFoo Docker runners
- compliance evidence mapped to NIST AI RMF, EU AI Act, SOC 2, and HIPAA
- five local runnable examples

We would appreciate your feedback on API shape, docs clarity, and whether this fits any community examples or security guidance you are already planning.

Thanks,

Sinewave AI / ProofLayer

# LinkedIn Launch Post

We just added first-class LangGraph support to ProofLayer Rules.

ProofLayer Rules is our Apache-2.0 runtime security layer for AI agents and MCP servers. With the v0.2.0 LangGraph sprint, teams can wrap a compiled LangGraph agent with runtime security checks, run adversarial evals, and emit compliance evidence.

What is included:

- 3-line LangGraph wrapper
- runtime blocking for prompt injection, jailbreaks, tool abuse, exfiltration, scope drift, state manipulation, multi-turn attacks, and streaming output risks
- built-in 30-probe LangGraph adversarial suite
- GARAK and PromptFoo Docker runners
- compliance evidence mapped to NIST AI RMF, EU AI Act Articles 13-15, SOC 2 CC6/CC7, and HIPAA Security Rule
- five runnable examples covering RAG, tool calling, multi-agent supervision, memory attacks, and production compliance reporting

We built this to complement the LangChain ecosystem. LangGraph handles orchestration. LangSmith handles tracing and generic evals. ProofLayer focuses on adversarial evals, runtime security, and audit-defensible evidence.

The package is local, inspectable, and Apache-2.0.

If your team is deploying LangGraph agents in production, we would love your feedback.

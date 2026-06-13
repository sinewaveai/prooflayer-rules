# HN Submission

Title:

Show HN: ProofLayer Rules — runtime security, red-team evals, and compliance evidence for LangGraph

First comment:

Hi HN, we built ProofLayer Rules as an Apache-2.0 runtime security layer for MCP servers and LangGraph agents.

The new v0.2.0 LangGraph sprint adds:

- a 3-line wrapper for compiled LangGraph agents
- runtime detection for prompt injection, jailbreaks, tool abuse, exfiltration, scope drift, state manipulation, multi-turn attacks, and streaming output
- a built-in LangGraph adversarial eval suite
- Docker-backed GARAK and PromptFoo runners
- compliance evidence mapped to NIST AI RMF, EU AI Act Articles 13-15, SOC 2 CC6/CC7, and HIPAA Security Rule
- five runnable examples with attack-blocking demos

We designed this to complement LangSmith. LangSmith gives tracing and generic evals; ProofLayer focuses on adversarial evals, runtime blocking, and audit evidence.

Everything is local and inspectable. The rules are YAML, the package is Python, and the license is Apache-2.0.

Would love feedback from teams deploying LangGraph or MCP agents in production.

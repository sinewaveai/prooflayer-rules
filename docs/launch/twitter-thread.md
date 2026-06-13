# Twitter/X Thread

1. We just added first-class LangGraph support to ProofLayer Rules.

2. ProofLayer Rules is an Apache-2.0 runtime security layer for AI agents and MCP servers.

3. The new LangGraph integration wraps a compiled graph in 3 lines:

```python
middleware = SecurityMiddleware(SecurityConfig(prompt_injection="block"))
secured_graph = middleware.wrap(graph.compile())
result = secured_graph.invoke({"input": user_input})
```

4. It checks the agent hot path for prompt injection, jailbreaks, tool abuse, exfiltration, scope drift, state manipulation, multi-turn attacks, and unsafe streaming output.

5. The wrapper preserves `invoke`, `ainvoke`, `stream`, `astream`, `stream_events`, and `astream_events`.

6. We also added a built-in LangGraph adversarial suite with 30 probes.

7. For deeper red-team runs, ProofLayer can orchestrate GARAK and PromptFoo through pinned Docker runners.

8. Findings render to JSON and Markdown so they can fit CI, release reviews, and security workflows.

9. The compliance layer maps detection and eval events to NIST AI RMF, EU AI Act Articles 13-15, SOC 2 CC6/CC7, and HIPAA Security Rule controls.

10. Every evidence record includes a timestamp, source event, control ID, previous hash, and evidence hash.

11. This is designed to complement LangSmith: LangSmith gives tracing and generic evals; ProofLayer adds adversarial evals, runtime security, and compliance evidence.

12. We shipped five runnable examples: RAG, tool calling, multi-agent supervisor, memory attack demo, and production template.

13. Benchmark: secured LangGraph invocation p99 is 32.72 ms on the local sprint benchmark, below the 100 ms budget.

14. Install locally:

```bash
pip install prooflayer-rules[langgraph]
```

15. Feedback welcome from anyone deploying LangGraph agents in production.

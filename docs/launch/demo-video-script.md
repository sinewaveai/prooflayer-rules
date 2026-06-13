# 60-Second Demo Video Script

## Goal

Show ProofLayer wrapping a LangGraph agent, blocking attacks, running evals, and producing compliance evidence.

## Storyboard

### 0-5 seconds

Title card:

ProofLayer Rules for LangGraph

Voiceover:

"LangGraph is powerful for production agents. ProofLayer adds runtime security, adversarial evals, and compliance evidence."

### 5-15 seconds

Show code:

```python
middleware = SecurityMiddleware(SecurityConfig(prompt_injection="block"))
secured_graph = middleware.wrap(graph.compile())
result = secured_graph.invoke({"input": user_input})
```

Voiceover:

"The integration is a small wrapper around the graph you already compile."

### 15-25 seconds

Terminal:

```bash
python examples/integrations/langgraph/01_simple_rag.py
```

Show benign answer, then blocked prompt injection.

Voiceover:

"A normal request passes. A prompt injection is blocked before the graph executes."

### 25-35 seconds

Terminal:

```bash
python examples/integrations/langgraph/02_tool_calling_agent.py
python examples/integrations/langgraph/04_memory_attack_demo.py
```

Voiceover:

"Tool abuse and multi-turn memory attacks are detected too."

### 35-45 seconds

Terminal:

```bash
python examples/evals/langgraph_adversarial.py
```

Show findings summary and report path.

Voiceover:

"The eval harness runs adversarial probes and writes JSON plus Markdown findings."

### 45-55 seconds

Terminal:

```bash
python examples/integrations/langgraph/05_production_template.py
```

Show compliance report path.

Voiceover:

"Detection events map to NIST AI RMF, EU AI Act, SOC 2, and HIPAA evidence records with hash chaining."

### 55-60 seconds

End card:

ProofLayer Rules
Apache-2.0
Runtime security for LangGraph and MCP agents

Voiceover:

"ProofLayer complements LangSmith with adversarial evals, runtime security, and compliance evidence."

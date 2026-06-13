# Sprint Progress

- Day 1: Started LangGraph v0.2.0 sprint scaffolding, added integration/test/example directories, and pinned optional LangGraph dependencies.
- Day 2: Added SecurityConfig validation and a pass-through SecurityMiddleware base for compiled LangGraph objects.
- Day 3: Added LangGraph hook adapters, graph-level audit events, and an audit checkpointer wrapper.
- Day 4: Wired prompt injection detection into LangGraph node-entry scans with allow, warn, and block handling.
- Day 5: Added structured audit events with sha256 chain-of-custody hashes, JSONL, stdout, and SIEM outputs.
- Day 6: Added a runnable simple LangGraph RAG sample that demonstrates ProofLayer prompt-injection blocking.
- Day 7: Week 1 acceptance gate passed: fresh LangGraph install verified, sample RAG blocks attacks, full suite passed, and new-module coverage is 90%.
- Day 8: Added LangGraph tool validation with allowlists, suspicious argument scanning, output capture, and hook wiring.
- Day 9: Added output exfiltration scanning and deterministic scope drift detection on LangGraph after-node hooks.
- Day 10: Added state manipulation and multi-turn slow-burn attack detection for LangGraph state and input hooks.
- Day 11: Added streaming output filtering for stream, astream, stream_events, and astream_events with configurable block handling.
- Day 12-13: Added adversarial evals with GARAK and PromptFoo Docker runners, LangGraph target adaptation, a 30-probe built-in suite, JSON/Markdown reports, and a local eval example.
- Day 15: Added NIST AI RMF, EU AI Act, SOC 2, and HIPAA compliance framework registries with 20 AI-applicable controls each and schema tests.
- Day 16: Added compliance evidence records, deterministic event-to-control mapping, Markdown report generation, optional PDF rendering, and tests.
- Day 17: Added four additional LangGraph sample apps for tool validation, multi-agent state monitoring, multi-turn memory attacks, and production compliance reporting.
- Day 18: Added LangGraph integration, evals, compliance, architecture, and API docs; updated README positioning and CHANGELOG for v0.2.0.
- Day 19: Added a LangGraph hot-path latency benchmark and recorded p99 32.72 ms for secured graph invocation, under the 100 ms budget.

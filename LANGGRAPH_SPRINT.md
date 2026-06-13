# v0.2.0 Sprint — LangGraph Integration + Evals + Compliance

| Field | Value |
|---|---|
| Repo | github.com/sinewaveai/prooflayer-rules |
| Current version | 0.1.0 |
| Target version | 0.2.0 |
| Sprint window | 21 days from build start |
| License | Apache-2.0 (unchanged) |
| Distribution | PyPI as `prooflayer-rules`, with optional install extras |
| Strategic goal | GTM traction with LangChain community + path to formal partnership |
| Owner | Sinewave AI / ProofLayer co-founders |

---

## 1. What this sprint exists to do

v0.1.0 of prooflayer-rules shipped a runtime detection rules engine with an MCP gateway integration example. v0.2.0 extends this into three new surfaces — all within the same repo, under the same `prooflayer.*` namespace, with the same Apache-2.0 license:

1. **LangGraph runtime wrapper** — `prooflayer.integrations.langgraph` — the largest new surface
2. **Adversarial evals module** — `prooflayer.evals` — GARAK + PromptFoo orchestration
3. **Compliance evidence emitter** — `prooflayer.compliance` — NIST AI RMF / EU AI Act / SOC 2 / HIPAA framework mapping

The LangGraph integration is the centerpiece. Evals and compliance support it as the "auditor-defensible" pitch that differentiates from LangSmith, which has tracing + generic evals, but no adversarial evals or compliance evidence mapping.

After this sprint, prooflayer-rules is no longer just "a detection rules engine" — it's "the open-source runtime security, adversarial evals, and compliance evidence layer for AI agents," with LangGraph as the first first-class agent framework integration.

## 2. Hard rules (non-negotiable)

1. Every detection event traces to a specific rule ID, with rule version, OSS tool source if applicable, and timestamp. No fabricated evidence.
2. All new code goes under the existing `prooflayer/` Python package — do not create a separate sibling package.
3. Apache-2.0 license throughout. No proprietary code in this repo.
4. Hot-path detection latency: p99 sub-100ms on a representative LangGraph node, using synchronous rules check.
5. Test coverage on new modules: >=80%.
6. Type hints on every public function. Docstrings on every public class and function.
7. Every daily milestone ends with a git commit, all tests passing, and a one-line entry in `SPRINT_PROGRESS.md`.
8. Stop at every "Open question" in this doc and ask. Do not silently guess.
9. The v0.1.0 MCP gateway integration must continue to work without modification. Backward compatibility is required.

## 3. Strategic positioning (must be reflected in docs + README)

The README, docs, and examples must position prooflayer-rules as **complementary to LangSmith**, not competitive. Use this exact framing in any LangSmith-adjacent text:

| Layer | What it does | Provided by |
|---|---|---|
| Agent orchestration | Build, deploy, run agents | LangGraph |
| Tracing + observability | See what agents did | LangSmith |
| Generic evals | LLM-as-judge, regression tests | LangSmith |
| Adversarial evals | GARAK / PromptFoo red-team probes | ProofLayer |
| Runtime security | Real-time prompt injection, tool abuse, exfil detection + blocking | ProofLayer |
| Compliance evidence | NIST AI RMF / EU AI Act / SOC 2 / HIPAA audit-defensible reports | ProofLayer |

Do NOT use language like "replaces," "instead of," or "alternative to" LangSmith anywhere in the codebase, docs, or README.

## 4. Goals

### Primary goals (v0.2.0)

1. Wrap any LangGraph `StateGraph` with security middleware in 3 lines of customer code
2. Detect and optionally block: prompt injection, jailbreak, tool abuse, output exfiltration, scope drift, multi-turn attacks, memory manipulation
3. Adversarial eval suite that runs GARAK + PromptFoo against a LangGraph agent and produces a JSON + Markdown findings report
4. Compliance evidence emission mapped to NIST AI RMF (Govern/Map/Measure), EU AI Act (Articles 13-15), SOC 2 CC6/CC7, HIPAA Security Rule
5. Audit-defensible evidence chain — every detection event timestamped, hashed, source-tagged, mapped to a rule ID
6. Ship 5 working sample LangGraph applications in `examples/integrations/langgraph/` that demonstrate the wrapper across common patterns
7. Documentation: quickstart, architecture, API reference, compliance guide
8. PyPI release of v0.2.0 with optional install extras
9. Community-launch-ready artifacts: blog post draft, HN submission text, Twitter thread, demo video script

### Non-goals (v0.2.0)

- Web UI for the wrapper (CLI + Python API only)
- Hosted / SaaS deployment of the wrapper
- Integration with CrewAI, AutoGen, or other agent frameworks (those are future sprints)
- New detection rule authoring (use the existing 45+ rules from v0.1.0; you may add LangGraph-specific rules as needed but do not refactor the existing ones)
- Refactoring v0.1.0's MCP gateway integration
- Multi-tenancy or auth (handled at deployment layer, not in this library)

## 5. Architecture

### Repo structure after this sprint

```text
prooflayer-rules/
├── prooflayer/
│   ├── __init__.py
│   ├── detection/                  # existing — extend with 2 new modules
│   │   ├── prompt_injection.py
│   │   ├── jailbreak.py
│   │   ├── tool_abuse.py
│   │   ├── exfil.py
│   │   ├── scope_drift.py
│   │   ├── state_manipulation.py   # NEW
│   │   └── multi_turn.py           # NEW
│   ├── rules/                      # existing — unchanged
│   │   └── *.yaml
│   ├── engine/                     # existing — minor extensions only
│   │   └── rule_engine.py
│   ├── integrations/
│   │   ├── __init__.py
│   │   ├── mcp_gateway/            # existing — unchanged
│   │   │   └── ...
│   │   └── langgraph/              # NEW
│   │       ├── __init__.py
│   │       ├── middleware.py        # SecurityMiddleware class
│   │       ├── config.py            # SecurityConfig dataclass
│   │       ├── hooks.py             # before/after node hooks
│   │       ├── tool_validator.py    # tool call inspection
│   │       ├── streaming.py         # output stream filtering
│   │       ├── checkpointer.py      # custom checkpointer for audit
│   │       └── exceptions.py        # SecurityException, BlockedError
│   ├── evals/                      # NEW
│   │   ├── __init__.py
│   │   ├── runner.py               # EvalRunner orchestrates probes
│   │   ├── garak_runner.py         # GARAK Docker invocation + parser
│   │   ├── promptfoo_runner.py      # PromptFoo Docker invocation + parser
│   │   ├── langgraph_target.py      # adapt LangGraph agent as eval target
│   │   ├── adversarial_suite.py     # ~30 LangGraph-specific probes
│   │   └── report.py               # JSON + Markdown report generation
│   ├── compliance/                 # NEW
│   │   ├── __init__.py
│   │   ├── frameworks/
│   │   │   ├── __init__.py
│   │   │   ├── nist_ai_rmf.yaml
│   │   │   ├── eu_ai_act.yaml
│   │   │   ├── soc2.yaml
│   │   │   └── hipaa.yaml
│   │   ├── emitter.py              # event → framework mapping
│   │   ├── evidence.py             # Evidence record schema
│   │   └── report.py               # compliance report generation
│   └── audit/                      # NEW
│       ├── __init__.py
│       ├── logger.py               # structured event logger
│       ├── siem.py                 # SIEM-compatible output (Splunk, Datadog)
│       └── integrity.py            # sha256 hashing + chain-of-custody
├── examples/
│   ├── integrations/
│   │   ├── mcp_gateway_proxy.py    # existing
│   │   └── langgraph/              # NEW
│   │       ├── README.md
│   │       ├── 01_simple_rag.py
│   │       ├── 02_tool_calling_agent.py
│   │       ├── 03_multi_agent_supervisor.py
│   │       ├── 04_memory_attack_demo.py
│   │       └── 05_production_template.py
│   └── evals/                      # NEW
│       └── langgraph_adversarial.py
├── tests/
│   ├── integrations/
│   │   └── langgraph/              # NEW
│   │       ├── test_middleware.py
│   │       ├── test_tool_validator.py
│   │       ├── test_streaming.py
│   │       ├── test_checkpointer.py
│   │       └── test_e2e.py
│   ├── evals/                      # NEW
│   ├── compliance/                 # NEW
│   └── audit/                      # NEW
├── docs/
│   ├── integrations/
│   │   ├── mcp_gateway.md          # existing
│   │   └── langgraph.md            # NEW — primary integration doc
│   ├── evals.md                    # NEW
│   ├── compliance.md               # NEW
│   ├── architecture.md             # NEW or extended
│   └── api.md                      # NEW
├── pyproject.toml                  # extend with optional dependencies
├── CHANGELOG.md                    # append v0.2.0 entry
└── README.md                       # extend with LangGraph section
```

### Install pattern (pyproject.toml additions)

```toml
[project.optional-dependencies]
langgraph = [
    "langgraph>=0.2.0",
    "langchain-core>=0.3.0",
]
evals = [
    "docker>=7.0.0",          # for GARAK + PromptFoo container invocation
    "pyyaml>=6.0",
]
compliance = [
    "jinja2>=3.1.0",          # for report templates
    "weasyprint>=60.0",       # for PDF generation
]
audit = [
    "structlog>=24.0.0",
]
all = [
    "prooflayer-rules[langgraph,evals,compliance,audit]",
]
```

Install patterns customers use:

```bash
pip install prooflayer-rules
pip install prooflayer-rules[langgraph]
pip install prooflayer-rules[all]
```

### Core API surface (the customer-facing pattern)

```python
from langgraph.graph import StateGraph
from prooflayer.integrations.langgraph import SecurityMiddleware, SecurityConfig

# Customer builds their LangGraph agent normally
graph = StateGraph(MyState)
graph.add_node("agent", agent_function)
graph.add_node("tool_call", tool_function)
# ... etc

# Three-line ProofLayer wrap
middleware = SecurityMiddleware(
    config=SecurityConfig(
        prompt_injection="block",        # block | warn | allow
        tool_abuse="block",
        exfil="block",
        scope_drift="warn",
        multi_turn="warn",
        compliance_frameworks=["nist_ai_rmf", "soc2"],
        emit_to=["stdout", "logfile:./audit.jsonl"],
    )
)

secured_graph = middleware.wrap(graph.compile())

# Customer invokes normally; security is transparent
result = secured_graph.invoke({"input": user_input})

# Access audit log
events = middleware.get_audit_log(session_id=result["session_id"])
```

## 6. Sprint plan — 21 days

### Week 1 — Foundation + LangGraph hooks (Days 1-7)

Goal: working middleware end-to-end with one detection category live.

#### Day 1 — Scaffolding

- Create `prooflayer/integrations/langgraph/` directory with empty `__init__.py`
- Update `pyproject.toml` with optional dependencies for `[langgraph]`
- Create `tests/integrations/langgraph/` with empty test files
- Verify `pip install -e ".[langgraph]"` works in a fresh venv
- Create `examples/integrations/langgraph/README.md` placeholder
- Commit: `feat(langgraph): scaffold integration package`

#### Day 2 — SecurityConfig + Middleware base

- Implement `SecurityConfig` dataclass in `config.py` with all options from the customer-facing API spec above
- Implement `SecurityMiddleware` base class in `middleware.py` with `__init__`, `wrap()`, and `get_audit_log()` method signatures
- Stub all detection methods to return ALLOW for now
- Write 5 unit tests covering `SecurityConfig` construction, validation, defaults
- Commit: `feat(langgraph): SecurityMiddleware base class + SecurityConfig`

#### Day 3 — LangGraph hook integration

- Implement `hooks.py` with `before_node`, `after_node`, `on_tool_call`, `on_state_update` hook adapters
- Wire hooks into LangGraph's native interrupt + checkpoint mechanisms
- Custom Checkpointer subclass in `checkpointer.py` that captures state for audit
- Write 6 integration tests using a minimal LangGraph 1-node echo agent
- Commit: `feat(langgraph): runtime hooks for node + tool + state events`

#### Day 4 — Prompt injection detection wired in

- Connect the existing `prooflayer/detection/prompt_injection.py` rule engine to the `before_node` hook
- Implement block vs warn vs allow action handling
- Raise `BlockedError` exception, defined in `exceptions.py`, when action is block
- Write 8 tests including: clean input passes, attack input blocked, attack input warned, attack input allowed logged only
- Commit: `feat(langgraph): prompt injection detection at node-entry hook`

#### Day 5 — Audit logger + structured events

- Implement `audit/logger.py` with `AuditEvent` schema: timestamp, session_id, rule_id, severity, decision, evidence_snippet, hash
- Output formats: stdout human-readable, JSONL one event per line, SIEM Splunk-compatible JSON
- Sha256 chain-of-custody hash linking events into a verifiable sequence
- Tests for each output format
- Commit: `feat(audit): structured event logger + SIEM-compatible output`

#### Day 6 — First sample app

- Create `examples/integrations/langgraph/01_simple_rag.py`: a working RAG agent that fetches docs, asks an LLM a question, returns a response
- Wrap with ProofLayer
- Include README with run instructions, expected output, what to try to break
- Verify the sample blocks "ignore previous instructions" attack pattern
- Commit: `examples(langgraph): simple RAG with ProofLayer wrapping`

#### Day 7 — Week 1 acceptance gate

- Run full test suite — all tests pass
- Run `examples/integrations/langgraph/01_simple_rag.py` end to end
- Update `SPRINT_PROGRESS.md` with week 1 summary
- Commit: `chore: week 1 complete — LangGraph hooks + prompt injection live`

Week 1 acceptance criteria:

- [ ] `pip install -e ".[langgraph]"` works clean
- [ ] `SecurityMiddleware` wraps a real LangGraph and intercepts node execution
- [ ] Prompt injection detection blocks known attack patterns
- [ ] Audit log emits structured events
- [ ] Sample RAG app runs end to end with ProofLayer wrapping
- [ ] All tests pass; coverage >=80% on new modules

### Week 2 — Comprehensive detection + adversarial evals (Days 8-14)

Goal: all detection categories live, plus a working adversarial eval harness.

#### Day 8 — Tool abuse + tool validator

- Implement `tool_validator.py` with allowlist enforcement, argument inspection, output capture
- Wire into `on_tool_call` hook for pre-call validation
- Block calls to tools not on the customer's allowlist
- Block calls with arguments matching exfil patterns, such as URLs to suspicious domains
- 10 tests covering: allowed tool, blocked tool, allowed args, blocked args, edge cases
- Commit: `feat(langgraph): tool call validation + abuse detection`

#### Day 9 — Output exfiltration + scope drift

- Connect existing `prooflayer/detection/exfil.py` rules to the `after_node` hook for LLM output inspection
- Implement `scope_drift.py` detection comparing LLM output to system prompt intent
- 12 tests covering: clean output, exfil patterns, scope drift cases
- Commit: `feat(detection): output exfiltration + scope drift detection`

#### Day 10 — State manipulation + memory poisoning

- Implement `detection/state_manipulation.py` to detect adversarial writes to LangGraph state, such as overwriting system prompts via tool outputs
- Implement `detection/multi_turn.py` to detect slow-burn attacks across conversation turns
- Wire both into the `on_state_update` and `before_node` hooks
- 10 tests
- Commit: `feat(detection): state manipulation + multi-turn attack detection`

#### Day 11 — Streaming output filtering

- Implement `streaming.py` to handle LangGraph's streaming events
- Real-time inspection of streamed tokens for exfil + injection patterns
- Stream-pause-and-block on critical findings
- 6 tests using LangGraph's `astream_events` and `astream`
- Commit: `feat(langgraph): streaming output filtering`

#### Day 12 — Evals module: GARAK runner

- Implement `evals/garak_runner.py` to invoke GARAK in the `leondz/garak` container against a LangGraph agent endpoint
- Implement `evals/langgraph_target.py` adapter that exposes a LangGraph agent as an OpenAI-compatible endpoint for GARAK to probe
- Parse GARAK JSON output into structured `EvalFinding` records
- 4 tests with mocked Docker invocation
- Commit: `feat(evals): GARAK runner against LangGraph agents`

#### Day 13 — Evals module: PromptFoo runner + adversarial suite

- Implement `evals/promptfoo_runner.py` to invoke PromptFoo against LangGraph agent
- Implement `evals/adversarial_suite.py` with a bundle of ~30 LangGraph-specific adversarial test cases: prompt injection, tool abuse, scope drift, exfil
- Implement `evals/runner.py` top-level `EvalRunner` that orchestrates GARAK + PromptFoo + adversarial suite and produces a unified findings report
- Implement `evals/report.py` for JSON + Markdown report generation
- 6 tests
- Commit: `feat(evals): PromptFoo runner + adversarial suite + report generator`

#### Day 14 — Week 2 acceptance gate

- All detection categories live and tested
- Adversarial eval suite runs end to end against the Day 6 sample RAG agent and produces a real report
- Update `SPRINT_PROGRESS.md`
- Commit: `chore: week 2 complete — full detection coverage + adversarial evals`

Week 2 acceptance criteria:

- [ ] 7 detection categories live: prompt injection, jailbreak, tool abuse, exfil, scope drift, state manipulation, multi-turn
- [ ] Tool call validation works with allowlists and argument inspection
- [ ] Streaming output filtering works on `astream_events`
- [ ] `EvalRunner` runs GARAK + PromptFoo + adversarial suite against a LangGraph agent and produces a JSON + Markdown report
- [ ] All tests pass; coverage >=80% on new modules

### Week 3 — Compliance + polish + community launch artifacts (Days 15-21)

Goal: compliance evidence module, full documentation, 5 sample apps, community-launch-ready artifacts.

#### Day 15 — Compliance framework registry

- Create `compliance/frameworks/*.yaml` for NIST AI RMF, EU AI Act, SOC 2, HIPAA
- Each YAML contains: controls, descriptions, evidence types required, audit perspective, cross-mappings
- 20+ controls per framework, focused on the AI-applicable subset
- Tests verifying YAML schema loads cleanly
- Commit: `feat(compliance): framework registries (NIST AI RMF, EU AI Act, SOC 2, HIPAA)`

#### Day 16 — Compliance event mapping

- Implement `compliance/emitter.py` to map detection events to control satisfactions
- Implement `compliance/evidence.py` evidence record schema with chain-of-custody hash
- Implement `compliance/report.py` to generate compliance reports, Markdown + PDF via WeasyPrint
- 8 tests
- Commit: `feat(compliance): event-to-control mapping + report generation`

#### Day 17 — Remaining sample apps

- `02_tool_calling_agent.py` — LangGraph agent with multiple tools, demonstrates tool validation
- `03_multi_agent_supervisor.py` — supervisor pattern with multiple sub-agents, demonstrates state monitoring
- `04_memory_attack_demo.py` — demonstrates multi-turn attack detection blocking a slow-burn injection
- `05_production_template.py` — production-ready template with all features enabled, compliance reporting
- README for each with run instructions, expected behavior, what attacks they demonstrate blocking
- Commit: `examples(langgraph): 4 additional sample applications`

#### Day 18 — Documentation

- `docs/integrations/langgraph.md` — primary integration guide with quickstart, API reference, configuration options, troubleshooting
- `docs/evals.md` — eval harness guide with GARAK + PromptFoo usage
- `docs/compliance.md` — compliance guide with framework mappings explained
- `docs/architecture.md` — architecture diagram + sequence diagrams for hot path
- `docs/api.md` — full API reference, auto-generated from docstrings where possible
- Update top-level `README.md` to feature LangGraph integration prominently
- Update `CHANGELOG.md` with v0.2.0 entry
- Commit: `docs: v0.2.0 documentation`

#### Day 19 — Performance + benchmarks

- Benchmark hot-path latency on representative LangGraph node — measure p50, p95, p99
- Add results to `benchmarks/README.md`
- Optimize any hot path showing p99 >100ms
- Update README with benchmark numbers
- Commit: `perf: hot-path latency benchmarks + optimizations`

#### Day 20 — Community launch artifacts

- Draft technical blog post, 1500 words: "Securing LangGraph Agents in Production: Adversarial Evals + Runtime Detection + Compliance Evidence" — save as `docs/blog/v0.2.0-launch.md`
- Draft HN Show HN submission title + first comment — save as `docs/launch/hn-submission.md`
- Draft Twitter/X thread, 12-15 tweets — save as `docs/launch/twitter-thread.md`
- Draft LinkedIn launch post — save as `docs/launch/linkedin-post.md`
- Draft email to LangChain DevRel team — save as `docs/launch/langchain-outreach.md`
- Storyboard for a 60-second demo video — save as `docs/launch/demo-video-script.md`
- Commit: `docs(launch): v0.2.0 community launch artifacts`

#### Day 21 — Release

- Final integration test against all 5 sample apps
- Final full test suite run with coverage report
- Tag v0.2.0 in git
- Build wheel and source distribution
- Publish to PyPI as `prooflayer-rules==0.2.0`
- Create GitHub release with auto-generated release notes
- Update `SPRINT_PROGRESS.md` with sprint completion summary
- Commit: `chore: v0.2.0 release`

Week 3 acceptance criteria:

- [ ] 4 compliance frameworks live with detection-event-to-control mapping
- [ ] 5 sample applications working, documented, and demonstrably blocking real attacks
- [ ] Documentation complete: quickstart, integration guide, evals guide, compliance guide, architecture, API reference
- [ ] All 6 community launch artifacts drafted and ready
- [ ] PyPI release of v0.2.0 published
- [ ] All tests passing; coverage >=80% on new modules
- [ ] Hot-path p99 latency <100ms

## 7. Final acceptance criteria for the sprint

The sprint is DONE when all of these are true:

- [ ] `pip install prooflayer-rules[langgraph]` works from PyPI
- [ ] 3-line integration pattern works on any LangGraph `StateGraph`
- [ ] 7 detection categories live: prompt injection, jailbreak, tool abuse, exfil, scope drift, state manipulation, multi-turn
- [ ] Adversarial eval harness runs GARAK + PromptFoo + custom suite end-to-end and produces a real findings report against a real LangGraph agent
- [ ] 4 compliance frameworks live: NIST AI RMF, EU AI Act, SOC 2, HIPAA
- [ ] 5 sample LangGraph applications work, including the attack-blocking demos
- [ ] Audit log emits SIEM-compatible structured events with sha256 chain-of-custody
- [ ] Hot-path p99 latency <100ms on a representative LangGraph node
- [ ] Documentation complete with at minimum: quickstart, architecture diagram, API reference, compliance guide
- [ ] All 6 community launch artifacts drafted: blog, HN, Twitter, LinkedIn, LangChain DevRel email, demo video script
- [ ] PyPI release published; GitHub release tagged v0.2.0
- [ ] All tests pass; new module coverage >=80%
- [ ] v0.1.0 MCP gateway integration still works, preserving backward compatibility
- [ ] README updated to feature LangGraph integration prominently

## 8. Open questions — STOP and ask

If you hit any of these, stop and ask Divya or Dheeraj:

1. **LangGraph version pinning.** What's the minimum version we should support? Recommendation: pin `langgraph>=0.2.0` and test against latest stable.
2. **GARAK + PromptFoo container versions.** Pin specific versions for reproducibility, or use latest? Recommendation: pin `leondz/garak:0.10.0`, `promptfoo/promptfoo:0.95.0`, or current stable.
3. **EU AI Act risk classification.** Auto-detect from customer config, or require explicit declaration? Recommendation: require explicit declaration to reduce liability for incorrect classification.
4. **Compliance framework conflict resolution.** If detection evidence satisfies multiple frameworks' overlapping controls, how to handle? Recommendation: each framework evaluates independently; cross-mappings are advisory.
5. **Streaming output: block-and-replace or block-and-error?** When critical content is detected mid-stream, replace with `[BLOCKED]` token or raise an exception? Recommendation: configurable, default to raising.
6. **Async support.** Wrap `ainvoke` / `astream` as well as `invoke` / `stream`? Recommendation: yes, both. This is non-negotiable for production LangGraph users.
7. **Customer audit log retention.** Library handles writes; customer handles rotation/retention? Recommendation: yes, library is stateless; customer rotates their JSONL files.

## 9. Dependencies — environment + tooling assumed

- Python 3.10+
- Docker for GARAK + PromptFoo evals
- PyPI account with publish permission for `prooflayer-rules`, already configured for v0.1.0
- GitHub Actions configured, already in repo from v0.1.0
- A real Anthropic / OpenAI API key in the test environment for running the sample apps end to end, used in CI integration tests only and not committed

## 10. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | LangGraph internals change between sprint start and ship | Medium | Medium | Pin `langgraph>=0.2.0,<1.0.0` in optional deps. Test against the latest patch version weekly. |
| 2 | Hot-path latency exceeds 100ms p99 | Medium | High | Day 19 is dedicated to perf benchmarking. Rules check stays synchronous; GARAK eval stays async. |
| 3 | LangSmith team perceives this as competitive and discourages community engagement | Low | High | Positioning section above is the mitigation. Use complementary-categories framing consistently in README, docs, blog. |
| 4 | Sample apps do not actually block real attacks reliably | Medium | High | Each sample app README must include a "what to try to break" section and verified blocking. CI runs adversarial probes against each sample app. |
| 5 | PyPI release fails | Low | Medium | Test release on TestPyPI first. Day 21 dedicated to release. |
| 6 | Coverage drops below 80% | Medium | Medium | Daily commits include test additions. CI gate fails the PR if coverage drops. |

## 11. After the sprint — what we'll need

When the sprint completes, return to office-hours with:

- The PyPI v0.2.0 release link
- A demo of all 5 sample apps running, including the attack-blocking demonstrations
- A demo of an end-to-end adversarial eval run
- A demo of compliance report generation
- The 6 launch artifacts ready to publish
- Any architectural surprises that surfaced during the build

We then run the community launch (HN, Twitter, LinkedIn, LangChain DevRel outreach) in a coordinated 4-hour window, ideally on a Tuesday or Wednesday morning PT.

## 12. What this sprint does NOT include — explicit out-of-scope

To prevent scope spiral, the following are deliberately out of scope:

- Web UI for the wrapper (Python API + CLI only)
- Multi-tenant / hosted SaaS deployment
- Auth, authz, or any access-control mechanism
- CrewAI, AutoGen, Llama Agents, or other agent framework integrations (future sprints)
- Custom rule authoring CLI (rules are still YAML-edited)
- Performance optimizations beyond hitting the <100ms p99 target
- Marketing site, landing page, or website updates (handled separately by Divya)
- Customer onboarding documentation beyond the integration quickstart
- Acquihire / partnership negotiation activities

End of PRD.

---

## Dispatch prompt for your coding agent

Read `LANGGRAPH_SPRINT.md` in this repo top to bottom. This is the 21-day v0.2.0 sprint to add a LangGraph integration, adversarial evals module, and compliance evidence emitter to prooflayer-rules, currently v0.1.0.

Architectural intent: keep everything inside the existing `prooflayer/*` Python package. Do NOT create a separate sibling package. LangGraph is one integration; we already have an MCP gateway integration; future integrations such as CrewAI and AutoGen will follow the same pattern.

Hard rules from section 2:

- Apache-2.0 license throughout
- Hot-path p99 latency <100ms, synchronous rules check
- Test coverage >=80% on new modules
- Type hints + docstrings on all public API
- v0.1.0 MCP gateway integration must continue to work unchanged
- Daily commits + `SPRINT_PROGRESS.md` updates
- Stop at every open question in section 8; do not silently guess

Start by:

1. Reading `LANGGRAPH_SPRINT.md` completely
2. Restating Week 1 in your own words so I can verify you understood
3. Reviewing the existing prooflayer-rules v0.1.0 codebase to confirm the assumed architecture matches reality
4. Beginning Day 1 scaffolding and showing me the directory structure + `pyproject.toml` changes before moving to Day 2

After each daily milestone, summarize: what shipped, tests passing, what's open, what changed in scope.

Strategic context for tone: this is for community/GTM launch with the LangChain ecosystem. The README, docs, and blog post tone should position ProofLayer as complementary to LangSmith, not competitive. See section 3 of the PRD for the exact framing.

---

## Two things to flag before dispatch

1. **Backward compatibility with v0.1.0.** The MCP gateway integration shipped in v0.1.0 must continue to work after this sprint. The coding agent should verify this with an explicit test in week 1.
2. **Hot-path latency is the hidden risk.** The 100ms p99 budget is tight when running rules-based detection on every LangGraph node transition. If benchmarks show p99 of 300ms, the fix is to make the LLM-scoring path async (rules sync, LLM async), not to drop the budget. This is a hard constraint.

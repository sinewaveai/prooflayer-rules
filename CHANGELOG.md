# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — Unreleased

### Added

- **LangGraph integration** — `prooflayer.integrations.langgraph.SecurityMiddleware` wraps compiled LangGraph agents and supports sync, async, streaming, tool-call, state-update, and audit-log paths.
- **Runtime detection categories for LangGraph** — prompt injection, jailbreak, tool abuse, output/input exfiltration, scope drift, state manipulation, multi-turn slow-burn attacks, and streaming output filtering.
- **Adversarial evals** — `prooflayer.evals` adds a 30-probe built-in LangGraph suite, GARAK Docker runner, PromptFoo Docker runner, LangGraph target adapter, and JSON/Markdown findings reports.
- **Compliance evidence** — `prooflayer.compliance` adds NIST AI RMF, EU AI Act, SOC 2, and HIPAA framework registries, event-to-control mapping, hashed evidence records, Markdown reports, and optional PDF output.
- **Audit logging** — `prooflayer.audit` emits structured events with sha256 chain-of-custody hashes and SIEM-compatible JSON.
- **Examples** — five LangGraph examples covering RAG, tool calling, multi-agent supervision, memory attacks, and production compliance reporting.

### Notes

- ProofLayer is positioned as complementary to LangSmith: LangSmith covers tracing and generic evals; ProofLayer covers adversarial evals, runtime security, and compliance evidence.
- v0.1.0 MCP runtime and proxy integrations remain supported.

## [0.1.0] — 2026-05-12

Initial open-source release of ProofLayer's runtime rules layer.

### Added

- **Detection engine** — 45 YAML rules across four attack categories (command injection, prompt injection, jailbreaks, data exfiltration), plus inline heuristics for Shannon entropy and semantic-mismatch checks.
- **Runtime wrapping** — `ProofLayerRuntime` wraps MCP servers and intercepts `call_tool` invocations.
- **Risk scoring + actions** — 0-100 score with `ALLOW` / `WARN` / `BLOCK` / `KILL` thresholds (configurable).
- **MCP Python SDK support** via `pip install -e ".[mcp]"`.
- **HTTP proxy mode** — `prooflayer proxy` inspects JSON-RPC `tools/call` traffic and forwards or rejects per scoring.
- **CLI** — `prooflayer scan`, `prooflayer proxy`, rule validation, report inspection, version commands.
- **Optional detector-assisted scoring** — runtime can call a `prooflayer-detector` service over `/v1/detect` for model-backed scoring of ambiguous events. Rules-only mode is the default; runtime degrades to rules-only on detector failure (does not block traffic on detector unavailability).
- **Reporting** — JSON and SARIF reports for blocked or high-risk calls.
- **Input normalization** for encoded, nested, and obfuscated arguments.
- **Configuration** via `prooflayer.yaml` (detection thresholds, response actions, detector integration, logging).
- **Examples** — `examples/basic/` (simple wrapped server), `examples/attack-scenarios/` (command injection, data exfiltration, prompt injection, jailbreak attempts), `examples/suse/` (SUSE Multi-Linux Manager integration with systemd service + config).
- **Docker support** — `Dockerfile` and `docker-compose.yml`.
- **Test suite** — 246 tests covering adversarial inputs, fuzz-like random inputs, end-to-end integration, and detector-client behavior.
- **OSS project hygiene** — Apache-2.0 LICENSE, SECURITY.md (responsible disclosure to `founders@sinewaveai.com`), CODE_OF_CONDUCT.md (Contributor Covenant v2.1), CONTRIBUTING.md.

### Notes

- This is the initial OSS release. Public API is alpha — minor versions may introduce breaking changes until 1.0.
- The commercial ML scoring tier (`prooflayer-detector`) is a separate offering; this repo is the open rules-only layer plus optional client for that service.

[0.1.0]: https://github.com/sinewaveai/prooflayer-rules/releases/tag/v0.1.0

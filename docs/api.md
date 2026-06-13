# API Reference

This reference covers the v0.2.0 LangGraph, evals, compliance, and audit surfaces.

## `prooflayer.integrations.langgraph`

### `SecurityConfig`

Runtime security configuration for LangGraph middleware.

Key fields:

- `prompt_injection`
- `jailbreak`
- `tool_abuse`
- `exfil`
- `scope_drift`
- `state_manipulation`
- `multi_turn`
- `compliance_frameworks`
- `emit_to`
- `allowed_tools`
- `session_id_key`
- `streaming_block_mode`
- `blocked_token`

Detection actions are `allow`, `warn`, or `block`.

### `SecurityMiddleware`

Wraps compiled LangGraph objects and exposes:

- `wrap(compiled_graph)`
- `get_audit_log(session_id=None)`
- `scan_input(payload, config=None)`
- `scan_output(payload, config=None)`
- `scan_state_update(state_update, config=None)`
- `record_event(event)`

### `ToolValidator`

Validates LangGraph tool calls:

- allowlist enforcement
- suspicious argument inspection
- output capture events

### `StreamingFilter`

Filters streamed chunks and event payloads for critical output detections.

### Exceptions

- `SecurityException`
- `BlockedError`

## `prooflayer.evals`

### `LangGraphEvalTarget`

Adapts a secured LangGraph object for eval runners:

- `invoke(prompt, config=None)`
- `ainvoke(prompt, config=None)`
- `handle_chat_completions(request)`

### `EvalRunner`

Top-level orchestration:

- `run_builtin_suite(target)`
- `run_all(target, output_dir, endpoint_url=None, promptfoo_config=None, garak_probes=None)`

### `GarakRunner`

Docker-backed GARAK runner:

- `build_command(endpoint_url, output_dir, probes=None)`
- `run(endpoint_url, output_dir, probes=None)`
- `parse_report(output_dir)`

### `PromptFooRunner`

Docker-backed PromptFoo runner:

- `build_command(config_path, output_path, env=None)`
- `run(config_path, output_path, env=None)`
- `parse_report(output_path)`

### `ReportGenerator`

Renders eval reports as JSON and Markdown.

## `prooflayer.compliance`

### `ComplianceEmitter`

Maps runtime events into framework controls:

- `emit(event, previous_hash=None)`
- `load_framework(framework)`

### `EvidenceRecord`

Auditor-facing evidence schema with sha256 chain-of-custody hashing.

### `ComplianceReportGenerator`

Renders compliance evidence:

- `build(evidence_records, title=...)`
- `to_markdown(evidence_records, title=..., output_path=None)`
- `to_pdf(markdown, output_path)`

## `prooflayer.audit`

### `AuditEvent`

Structured runtime event with:

- session ID
- rule ID
- severity
- decision
- evidence snippet
- timestamp
- source
- metadata
- previous hash
- event hash

### `AuditLogger`

Emits audit events to:

- stdout
- JSONL files
- SIEM-compatible JSON

# Architecture

ProofLayer Runtime Security is a transparent security layer that intercepts MCP tool calls, scans them for threats, and takes action based on computed risk scores.

## Component Diagram

```
                          MCP Protocol
                              |
                              v
+------------------------------------------------------------------+
|                    ProofLayerRuntime                              |
|                                                                  |
|  +------------------+    +------------------+                    |
|  |   MCP Server     |--->| ProtectedMCP     |                   |
|  |  (original)      |    |   Server         |                   |
|  +------------------+    +--------+---------+                   |
|                                   |                              |
|                          call_tool() intercepted                 |
|                                   |                              |
|                                   v                              |
|                     +-------------+-------------+                |
|                     |    DetectionEngine        |                |
|                     |                           |                |
|                     |  +---------------------+  |                |
|                     |  | RuleLoader (YAML)   |  |                |
|                     |  +---------------------+  |                |
|                     |  | PatternMatcher      |  |                |
|                     |  +---------------------+  |                |
|                     |  | MetacharScorer      |  |                |
|                     |  +---------------------+  |                |
|                     |  | EntropyAnalyzer     |  |                |
|                     |  +---------------------+  |                |
|                     |  | SemanticAnalyzer    |  |                |
|                     |  +---------------------+  |                |
|                     |  | InputNormalizer     |  |                |
|                     |  +---------------------+  |                |
|                     +-------------+-------------+                |
|                                   |                              |
|                          risk_score (0-100)                      |
|                          matched_rules[]                         |
|                                   |                              |
|                                   v                              |
|                     +-------------+-------------+                |
|                     |    ResponseAction         |                |
|                     |                           |                |
|                     |  ALLOW (0-29)  -> pass    |                |
|                     |  WARN  (30-69) -> log     |                |
|                     |  BLOCK (70-89) -> reject  |                |
|                     |  KILL  (90-100)-> SIGTERM |                |
|                     +-------------+-------------+                |
|                                   |                              |
|                                   v                              |
|                     +-------------+-------------+                |
|                     |   SecurityReporter        |                |
|                     |                           |                |
|                     |  JSON reports             |                |
|                     |  SARIF reports            |                |
|                     |  Emergency logs           |                |
|                     +---------------------------+                |
|                                                                  |
+------------------------------------------------------------------+
```

## Message Flow

A tool call follows this path through ProofLayer:

```
User/LLM Request
       |
       v
1. MCP Server receives call_tool(name, arguments)
       |
       v
2. ProtectedMCPServer intercepts the call
       |
       v
3. Input Validation
   - Check argument size (max 1 MB)
   - Check nesting depth (max 10 levels)
   - Strip null bytes
       |
       v
4. Allowlist Check
   - If tool/args match allowlist -> score 0, skip detection
       |
       v
5. Input Normalization
   - Flatten nested arguments
   - Decode unicode homoglyphs
   - Decode hex/octal/URL/base64 encodings
   - Normalize whitespace and case
       |
       v
6. Detection Engine Scan
   a. Pattern Matching (YAML rules)
      - Each matched rule adds its score (5-35 points)
      - ReDoS protection with 100ms timeout per regex
      - Circuit breaker after 3 consecutive timeouts
   b. Cross-Parameter Correlation
      - Combine values across parameters
      - Detect split-payload attacks
   c. Shell Metacharacter Detection
      - ; | && || ` $ > < each add +10 points
   d. Entropy Analysis
      - Shannon entropy > 4.5 adds +20 points
   e. Semantic Analysis
      - URLs in hostname fields: +15
      - Commands in ID fields: +20
       |
       v
7. Risk Score Computed (capped at 100)
       |
       v
8. ResponseAction decides action
   - ALLOW: tool call proceeds normally
   - WARN:  tool call proceeds, warning logged
   - BLOCK: tool call rejected, SecurityViolation raised
   - KILL:  security report written, server process terminated via SIGTERM
       |
       v
9. SecurityReporter generates report (on WARN/BLOCK/KILL)
   - JSON report written to report_dir
   - Emergency log on KILL (/tmp/prooflayer-emergency.log)
       |
       v
10. Result returned to LLM (if ALLOW/WARN)
    or error returned (if BLOCK)
    or process terminated (if KILL)
```

## Scoring Pipeline

ProofLayer uses an additive scoring model. Each detection signal contributes points to a total risk score (capped at 100):

### 1. Pattern Matching

The core detection mechanism. 53+ YAML rules across 6 categories are evaluated against normalized input text. Each rule contributes a configurable score (typically 10-35 points).

```yaml
# Example rule
- id: cmd-inject-curl
  severity: critical
  category: command_injection
  message: "Command injection: 'curl' command detected"
  pattern: "\\bcurl\\s+"
  score: 25
```

### 2. Shell Metacharacter Detection

Independent of pattern rules, the engine checks for dangerous shell characters. Each occurrence adds +10 points:

| Character | Description |
|-----------|-------------|
| `;`       | Command separator |
| `\|`      | Pipe operator |
| `&&`      | AND chaining |
| `\|\|`    | OR chaining |
| `` ` ``   | Backtick execution |
| `$`       | Variable/command substitution |
| `>`       | Output redirection |
| `<`       | Input redirection |

### 3. Entropy Analysis

Shannon entropy measures the randomness of the input text. High entropy (above 4.5) suggests encoded or obfuscated payloads and adds +20 points.

### 4. Semantic Analysis

Parameter names are checked against their values for semantic mismatches:

- A `hostname` field containing URLs: +15 points
- An `id` or `system_id` field containing shell commands: +20 points

### 5. Cross-Parameter Correlation

Values from different parameters are concatenated and re-scanned. This catches split-payload attacks where an attacker distributes a malicious command across multiple fields (e.g., `"arg1": "cur"`, `"arg2": "l http://evil.com"`).

## Risk Levels

| Level | Score Range | Action   | Description |
|-------|------------|----------|-------------|
| ALLOW | 0 -- 29    | Pass     | Tool call is safe. No intervention. |
| WARN  | 30 -- 69   | Log      | Suspicious activity detected. Tool call proceeds but a warning is logged and a report may be generated. |
| BLOCK | 70 -- 89   | Reject   | High-confidence threat. Tool call is rejected. Security report is written. `SecurityViolation` exception is raised. |
| KILL  | 90 -- 100  | Terminate| Critical threat. Security report is written. MCP server process is terminated via `SIGTERM`/`SIGKILL`. Emergency log is written to `/tmp/prooflayer-emergency.log`. |

## Input Normalization

Before scanning, all inputs pass through a normalization pipeline that defeats common evasion techniques:

- **Unicode homoglyph normalization** -- Cyrillic "a" (U+0430) is mapped to Latin "a"
- **Encoding decoding** -- hex (`\x63\x75\x72\x6c`), octal (`\143\165\162\154`), URL encoding (`%63%75%72%6c`), and base64 are decoded
- **Case normalization** -- all text is lowercased
- **Whitespace normalization** -- multiple spaces, tabs, and newlines are collapsed
- **Nested object flattening** -- deeply nested JSON structures are recursively unpacked to extract all string values

## Fail-Closed Design

ProofLayer defaults to a fail-closed security model:

- If detection rules fail to load, all requests are blocked (score 100)
- If regex evaluation times out repeatedly (3+ consecutive), the circuit breaker trips and blocks all requests
- The `fail_closed` flag can be set to `False` to fall back to inline rules (not recommended for production)

## MCP SDK Integration

For servers built with the official MCP Python SDK, `ProofLayerMCPWrapper` provides async-compatible integration:

- **Input scanning** -- scans `call_tool` arguments before the handler executes
- **Output scanning** -- scans tool outputs before they are returned to the LLM
- **Tool poisoning detection** -- scans `list_tools` descriptions for injected instructions

All three scanning points use the same `DetectionEngine` and scoring pipeline.

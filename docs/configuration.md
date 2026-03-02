# Configuration Reference

ProofLayer is configured via a YAML file, typically named `prooflayer.yaml` at the project root. Pass the path to the runtime:

```python
from prooflayer import ProofLayerRuntime

runtime = ProofLayerRuntime(config_path="prooflayer.yaml")
```

Or pass parameters directly (they override config file values):

```python
runtime = ProofLayerRuntime(
    action_on_threat="kill",
    report_dir="./security-reports",
    score_threshold={
        "allow": (0, 29),
        "warn": (30, 69),
        "block": (70, 100),
    }
)
```

## Full YAML Reference

```yaml
# ============================================================
# ProofLayer Runtime Security Configuration
# ============================================================

# ----------------------------------------------------------
# Detection Settings
# ----------------------------------------------------------
detection:
  # Enable or disable the detection engine entirely.
  # Type: bool | Default: true
  enabled: true

  # Directory containing YAML rule files.
  # Set to null to use the packaged rules shipped with prooflayer-runtime.
  # Type: string | null | Default: null
  rules_dir: null

  # Risk score thresholds that map scores to actions.
  # Each key maps to a [min, max] inclusive range.
  # Type: dict | Default: shown below
  score_threshold:
    allow: [0, 29]
    warn: [30, 69]
    block: [70, 100]

  # Fail-closed mode. When true (default), ProofLayer blocks all
  # requests if detection rules fail to load. When false, it falls
  # back to inline rules with a warning.
  # Type: bool | Default: true
  fail_closed: true

# ----------------------------------------------------------
# Response Settings
# ----------------------------------------------------------
response:
  # Default action when a threat is detected.
  # Options: allow, warn, block, kill
  # Type: string | Default: warn
  on_threat: warn

  # Directory for security report output (JSON and SARIF).
  # Created automatically if it does not exist.
  # Type: string | Default: ./security-reports
  report_dir: ./security-reports

  # Webhook URL for real-time alerts (e.g., Slack, PagerDuty, SIEM).
  # POST request with JSON report payload.
  # Type: string | null | Default: null
  alert_webhook: null

# ----------------------------------------------------------
# Performance Settings
# ----------------------------------------------------------
performance:
  # Target maximum latency for a single scan in milliseconds.
  # This is advisory -- regex timeouts are enforced at 100ms per rule.
  # Type: int | Default: 10
  max_latency_ms: 10

  # Cache compiled regex patterns in memory.
  # Type: bool | Default: true
  cache_rules: true

# ----------------------------------------------------------
# Logging Settings
# ----------------------------------------------------------
logging:
  # Log level.
  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
  # Type: string | Default: INFO
  level: INFO

  # Log format.
  # Options: json, text
  # Type: string | Default: json
  format: json

# ----------------------------------------------------------
# Metrics Settings
# ----------------------------------------------------------
metrics:
  # Enable Prometheus metrics endpoint.
  # Metrics are served at http://0.0.0.0:{port}/metrics
  # Type: bool | Default: false
  enabled: false

  # TCP port for the metrics HTTP server.
  # Type: int | Default: 9090
  port: 9090
```

## Section Details

### `detection`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Master switch for the detection engine. Set to `false` to pass all tool calls through without scanning. |
| `rules_dir` | string / null | `null` | Path to a directory containing custom YAML rule files. When `null`, the packaged rules under `prooflayer/rules/` are used. |
| `score_threshold` | dict | see above | Maps risk score ranges to actions. Each value is a `[min, max]` list (inclusive). |
| `fail_closed` | bool | `true` | When `true`, all requests are blocked if rules fail to load. When `false`, inline fallback rules are used (reduced protection). |

### `response`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `on_threat` | string | `warn` | Default action on threat detection. One of: `allow`, `warn`, `block`, `kill`. |
| `report_dir` | string | `./security-reports` | Directory where JSON and SARIF security reports are written. Created automatically with `0700` permissions. |
| `alert_webhook` | string / null | `null` | URL to POST alert payloads to when threats are detected. |

### `performance`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_latency_ms` | int | `10` | Advisory latency target per scan. Individual regex evaluations are hard-capped at 100ms with a circuit breaker after 3 consecutive timeouts. |
| `cache_rules` | bool | `true` | Cache compiled regex patterns in memory for faster matching. |

### `logging`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `INFO` | Minimum log level. One of: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `format` | string | `json` | Log output format. `json` produces structured JSON lines; `text` produces human-readable lines. |

### `metrics`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Start a Prometheus-compatible metrics HTTP server on a background thread. |
| `port` | int | `9090` | TCP port for the metrics endpoint. Metrics are served at `/metrics`. |

#### Exposed Metrics

When metrics are enabled, the following are exposed:

| Metric | Type | Description |
|--------|------|-------------|
| `prooflayer_scans_total` | counter | Total scans performed, labeled by `action` |
| `prooflayer_scan_duration_seconds` | summary | Scan duration with p50/p95/p99 quantiles |
| `prooflayer_rules_matched_total` | counter | Total rule matches, labeled by `rule_id` and `category` |
| `prooflayer_risk_score` | gauge | Last and average risk scores |
| `prooflayer_active_rules` | gauge | Number of currently loaded detection rules |

## Score Thresholds and Actions

The `score_threshold` configuration determines which action is taken for a given risk score:

| Score Range | Action | Behavior |
|-------------|--------|----------|
| 0 -- 29 | ALLOW | Tool call proceeds. No report generated. |
| 30 -- 69 | WARN | Tool call proceeds. Warning logged. Report may be generated. |
| 70 -- 89 | BLOCK | Tool call rejected. `SecurityViolation` raised. Report generated. |
| 90 -- 100 | KILL | MCP server terminated via `SIGTERM`. Report and emergency log generated. Only triggered when `on_threat: kill`. |

The KILL action is only activated when `response.on_threat` is set to `kill`. Otherwise, scores of 90+ result in BLOCK.

## Environment Variables

ProofLayer reads the following environment variables:

| Variable | Description |
|----------|-------------|
| `MCP_SERVER_NAME` | Server name included in security reports (default: `unknown`) |

## Loading Priority

Configuration values are resolved in this order (highest priority first):

1. Constructor parameters (`action_on_threat`, `report_dir`, `score_threshold`)
2. YAML config file (`config_path`)
3. Built-in defaults

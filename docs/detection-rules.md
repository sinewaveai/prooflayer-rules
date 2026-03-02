# Detection Rules Reference

ProofLayer ships with 71 built-in detection rules across 8 categories. Rules are stored as YAML files in `prooflayer/rules/` and loaded at startup by the `RuleLoader`.

Each rule has:

- **id** -- Unique identifier
- **category** -- Detection category
- **severity** -- critical, high, medium, or low
- **score** -- Risk score contribution (5-35 points)
- **pattern** -- Regular expression matched against normalized input
- **message** -- Human-readable description
- **owasp** -- Mapped OWASP categories (LLM Top 10, MCP Top 10, ASI Top 10)

## Summary by Category

| Category | Rules | File |
|----------|------:|------|
| Prompt Injection | 12 | `prompt-injection.yaml` |
| Jailbreaks | 8 | `jailbreaks.yaml` |
| Command Injection | 15 | `command-injection.yaml` |
| Data Exfiltration | 10 | `data-exfiltration.yaml` |
| Role Manipulation | 8 | `role-manipulation.yaml` |
| Tool Poisoning | 6 | `tool-poisoning.yaml` |
| SSRF/XXE | 6 | `ssrf-xxe.yaml` |
| SQL Injection | 6 | `sql-injection.yaml` |
| **Total** | **71** | |

---

## Prompt Injection (12 rules)

Detects attempts to override system prompts and inject new instructions.

| ID | Severity | Score | OWASP | Description |
|----|----------|------:|-------|-------------|
| `direct-ignore-previous` | critical | 30 | LLM01, MCP06, ASI01 | "ignore previous instructions" detected |
| `direct-disregard-system` | critical | 30 | LLM01, MCP06, ASI01 | "disregard system prompt" detected |
| `direct-new-instructions` | high | 20 | LLM01, MCP06, ASI01 | "new instructions" detected |
| `direct-ignore-all` | critical | 25 | LLM01, MCP06, ASI01 | "ignore all" detected |
| `direct-reset-context` | high | 20 | LLM01, MCP06, ASI01 | "reset context/memory/history" detected |
| `direct-system-override` | critical | 30 | -- | System override attempt detected |
| `direct-skip-checks` | critical | 35 | -- | "skip security checks" detected |
| `direct-admin-mode` | critical | 30 | -- | Admin mode activation attempt |
| `direct-unrestricted` | high | 25 | -- | "unrestricted mode" detected |
| `direct-act-as-system` | critical | 30 | -- | "act as system/root/admin" detected |
| `direct-backdoor` | critical | 35 | -- | Backdoor/secret mode activation attempt |
| `direct-jailbreak` | critical | 30 | -- | Explicit "jailbreak" mention |

---

## Jailbreaks (8 rules)

Detects DAN mode, developer mode, roleplay, and alignment override attempts.

| ID | Severity | Score | OWASP | Description |
|----|----------|------:|-------|-------------|
| `jailbreak-dan-mode` | critical | 30 | LLM01, MCP06, ASI01 | DAN (Do Anything Now) mode detected |
| `jailbreak-developer-mode` | critical | 30 | LLM01, MCP06, ASI01 | Developer/debug mode activation detected |
| `jailbreak-act-as` | high | 20 | LLM01, MCP06, ASI01 | "act as / pretend as" role manipulation |
| `jailbreak-roleplay` | high | 15 | LLM01, MCP06, ASI01 | Roleplay manipulation detected |
| `jailbreak-simulation` | high | 15 | LLM01, MCP06, ASI01 | Simulation mode detected |
| `jailbreak-evil-mode` | critical | 30 | -- | Evil/bad/malicious mode detected |
| `jailbreak-unrestricted-ai` | critical | 30 | -- | "unrestricted AI" prompt detected |
| `jailbreak-aligned-false` | high | 25 | -- | Alignment override detected |

---

## Command Injection (15 rules)

Detects shell metacharacters, dangerous commands, and command substitution.

| ID | Severity | Score | OWASP | Description |
|----|----------|------:|-------|-------------|
| `cmd-inject-semicolon` | critical | 20 | LLM01, LLM06, MCP05, ASI02 | Shell metacharacter `;` detected |
| `cmd-inject-pipe` | critical | 20 | LLM01, LLM06, MCP05, ASI02 | Pipe operator `\|` detected |
| `cmd-inject-double-ampersand` | critical | 15 | LLM01, LLM06, MCP05, ASI02 | Command chaining `&&` detected |
| `cmd-inject-double-pipe` | high | 15 | LLM01, LLM06, MCP05, ASI02 | OR operator `\|\|` detected |
| `cmd-inject-curl` | critical | 25 | LLM01, LLM06, MCP05, ASI02 | `curl` command detected |
| `cmd-inject-wget` | critical | 25 | -- | `wget` command detected |
| `cmd-inject-bash` | critical | 30 | -- | `bash`/`sh`/`zsh -c` invocation detected |
| `cmd-inject-nc` | critical | 30 | -- | `nc` (netcat) detected |
| `cmd-inject-exec` | critical | 25 | -- | `exec` detected |
| `cmd-inject-eval` | critical | 25 | -- | `eval()` detected |
| `cmd-inject-backticks` | critical | 25 | -- | Backtick command execution detected |
| `cmd-inject-dollar-parens` | high | 20 | -- | `$()` command substitution detected |
| `cmd-inject-redirect-output` | medium | 10 | -- | Output redirection `>` detected |
| `cmd-inject-redirect-input` | medium | 10 | -- | Input redirection `<` detected |
| `cmd-inject-rm-rf` | critical | 35 | -- | Destructive `rm -rf` detected |

---

## Data Exfiltration (10 rules)

Detects attempts to read sensitive files and send data to external systems.

| ID | Severity | Score | OWASP | Description |
|----|----------|------:|-------|-------------|
| `exfil-send-to-url` | critical | 25 | LLM06, MCP01, ASI02 | "send/post/upload to URL" detected |
| `exfil-base64-encode` | high | 15 | LLM06, MCP01, ASI02 | Base64 encoding detected |
| `exfil-file-read-passwd` | critical | 30 | LLM06, MCP01, ASI02 | `/etc/passwd` access detected |
| `exfil-file-read-shadow` | critical | 35 | LLM06, MCP01, ASI02 | `/etc/shadow` access detected |
| `exfil-ssh-keys` | critical | 30 | LLM06, MCP01, ASI02 | SSH key file access detected |
| `exfil-env-file` | critical | 25 | -- | `.env` file access detected |
| `exfil-credentials` | critical | 25 | -- | Credentials/secrets file access detected |
| `exfil-cat-command` | medium | 10 | -- | `cat` file read detected |
| `exfil-xxd-hex` | high | 15 | -- | `xxd` hex dump detected |
| `exfil-dns-tunnel` | critical | 30 | -- | DNS tunneling pattern detected |

---

## Role Manipulation (8 rules)

Detects attempts to override LLM personas and escalate privileges.

| ID | Severity | Score | OWASP | Description |
|----|----------|------:|-------|-------------|
| `role-you-are-now` | critical | 20 | -- | "you are now [malicious role]" detected |
| `role-pretend-to-be` | high | 20 | -- | "pretend to be [hacker/admin/root]" detected |
| `role-roleplay-as-admin` | critical | 25 | -- | Roleplay as admin/root/superuser detected |
| `role-act-as-root` | critical | 25 | -- | "act as root/admin/superuser" detected |
| `role-assume-the-role` | high | 20 | -- | "assume the role of" detected |
| `role-switch-personality` | high | 20 | -- | Personality/persona switch detected |
| `role-become-unrestricted` | critical | 30 | -- | "become unrestricted/unfiltered" detected |
| `role-impersonate` | high | 20 | -- | Impersonation attempt detected |

---

## SSRF/XXE (6 rules)

Detects Server-Side Request Forgery and XML External Entity attacks.

| ID | Severity | Score | OWASP | Description |
|----|----------|------:|-------|-------------|
| `ssrf-cloud-metadata` | critical | 30 | LLM06, MCP01, ASI02 | Cloud metadata endpoint access detected |
| `ssrf-internal-ip` | high | 25 | LLM06, MCP01, ASI02 | Internal/private IP address in URL detected |
| `ssrf-file-scheme` | high | 25 | LLM06, MCP01, ASI02 | `file://` scheme detected |
| `xxe-entity-declaration` | critical | 30 | LLM06, MCP01, ASI02 | DOCTYPE or ENTITY declaration detected |
| `xxe-system-entity` | critical | 30 | LLM06, MCP01, ASI02 | SYSTEM entity reference detected |
| `ssrf-gopher-scheme` | high | 25 | LLM06, MCP01, ASI02 | `gopher://` scheme detected |

---

## SQL Injection (6 rules)

Detects common SQL injection patterns.

| ID | Severity | Score | OWASP | Description |
|----|----------|------:|-------|-------------|
| `sql-union-select` | critical | 25 | LLM06, MCP05, ASI02 | UNION SELECT detected |
| `sql-drop-table` | critical | 30 | LLM06, MCP05, ASI02 | DROP TABLE/DATABASE detected |
| `sql-or-equals` | high | 20 | LLM06, MCP05, ASI02 | OR/AND tautology detected |
| `sql-comment-bypass` | medium | 15 | LLM06, MCP05, ASI02 | SQL comment bypass detected |
| `sql-sleep-benchmark` | critical | 25 | LLM06, MCP05, ASI02 | Time-based injection (SLEEP/BENCHMARK) detected |
| `sql-information-schema` | high | 20 | LLM06, MCP05, ASI02 | information_schema/sys access detected |

---

## Additional Heuristics

Beyond YAML rules, the DetectionEngine applies these additional scoring heuristics:

| Heuristic | Score | Trigger |
|-----------|------:|---------|
| Shell metacharacter | +10 each | Any of: `; \| && \|\| \` $ > <` found in input |
| High entropy | +20 | Shannon entropy > 4.5 (suggests encoded payload) |
| Semantic mismatch (URL in hostname) | +15 | A `hostname`/`server`/`host`/`endpoint`/`target`/`address` parameter contains URL schemes |
| Semantic mismatch (command in ID) | +20 | An `id` or `system_id` parameter contains shell commands |
| Semantic mismatch (command in numeric) | +15 | A `port`/`timeout`/`count`/`limit` parameter contains commands |
| Semantic mismatch (injection in path) | +20 | A `path`/`file` parameter contains pipe `\|` or semicolon `;` |
| Cross-parameter correlation | varies | Concatenated parameter values match a rule that individual values did not |

## Custom Rules

To add custom rules, create a YAML file following this schema:

```yaml
rules:
  - id: custom-my-rule
    severity: high
    category: custom
    message: "Description of what was detected"
    pattern: "regex_pattern_here"
    score: 20
    owasp: []
```

Point ProofLayer at your custom rules directory:

```yaml
# prooflayer.yaml
detection:
  rules_dir: /path/to/custom-rules/
```

Validate your rules before deploying:

```bash
prooflayer validate-rules --rules-dir /path/to/custom-rules/
```

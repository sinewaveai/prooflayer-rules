# False Positive Analysis

## Overview

This benchmark measures ProofLayer's false positive rate on legitimate, everyday MCP tool calls. A false positive occurs when a benign tool call receives a risk score >= 30 (WARN threshold) or >= 70 (BLOCK threshold).

## Benchmark Cases

20 benign tool calls across 9 domains:
- **infrastructure**: hostname registration, package updates, pod listing, config changes
- **general**: weather lookup, translation
- **productivity**: calendar events
- **data**: database queries
- **identity**: user profile lookups
- **communication**: email sending
- **monitoring**: metrics retrieval, alert acknowledgment
- **operations**: ticket creation, backup scheduling
- **security**: compliance checks, certificate renewal
- **analytics**: report generation
- **media**: image processing
- **network**: DNS lookups
- **knowledge**: document search

## Results

| Metric | Value |
|--------|-------|
| Total Cases | 20 |
| Max Allowed Score | 29 |
| False Positives (>= 30) | pending |
| False Positive Rate | pending |
| Last Run | pending |

### Per-Case Results

| ID | Domain | Tool | Score | Pass |
|----|--------|------|-------|------|
| FP-001 | infrastructure | add_system | - | - |
| FP-002 | general | get_weather | - | - |
| ... | ... | ... | - | - |

### How to Run

```bash
python benchmarks/run_benchmarks.py
```

## Design Principles

To avoid false positives, benign test cases:
1. Use realistic tool names and argument structures
2. Avoid shell metacharacters (`;`, `|`, `&&`, backticks, `$()`)
3. Avoid words that match detection patterns (curl, wget, bash, exec, eval)
4. Avoid sensitive file paths (/etc/passwd, .ssh/, .env, credentials)
5. Avoid prompt injection phrases (ignore instructions, system override)
6. Use simple, low-entropy argument values
7. Avoid URLs in parameters typed as hostnames

## Threshold Analysis

ProofLayer uses three score thresholds:
- **ALLOW** (0-29): Tool call proceeds normally
- **WARN** (30-69): Tool call proceeds but generates a security report
- **BLOCK** (70-100): Tool call is rejected

False positives at the WARN level may be acceptable for high-security environments. False positives at the BLOCK level are always unacceptable and represent detection rule issues.

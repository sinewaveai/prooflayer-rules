# OWASP LLM Top 10 - Benchmark Results

## LLM01: Prompt Injection

ProofLayer detection coverage for OWASP LLM01 prompt injection attacks via MCP tool calls.

### Test Summary

| Metric | Value |
|--------|-------|
| Total Payloads | 15 |
| Detection Target | score >= 70 |
| Last Run | pending |
| Detection Rate | pending |

### Techniques Covered

| Technique | Payloads | Detected | Rate |
|-----------|----------|----------|------|
| direct_override | 2 | - | - |
| instruction_replacement | 1 | - | - |
| privilege_escalation | 1 | - | - |
| context_manipulation | 1 | - | - |
| safety_bypass | 2 | - | - |
| jailbreak | 1 | - | - |
| role_manipulation | 1 | - | - |
| tool_poisoning | 1 | - | - |
| hidden_instruction | 1 | - | - |
| combined_attack | 1 | - | - |
| backdoor | 1 | - | - |
| alignment_override | 1 | - | - |
| output_manipulation | 1 | - | - |

### How to Run

```bash
python benchmarks/run_benchmarks.py
```

Results will be printed to stdout and this file will be updated with actual scores.

### Scoring Breakdown

Each payload is scored using ProofLayer's multi-signal detection:
- **Pattern matching**: YAML rule regex patterns (+5 to +35 per rule)
- **Shell metacharacters**: Dangerous characters like `;`, `|`, `&&` (+10 each)
- **Entropy analysis**: High Shannon entropy indicating encoded payloads (+20)
- **Semantic analysis**: Parameter type mismatches (+15 to +20)
- **Cross-parameter correlation**: Combined argument scanning

### Notes

- All payloads are designed to be detected with score >= 70 (BLOCK threshold)
- Real-world attacks may use evasion techniques (encoding, unicode homoglyphs) not covered here
- ProofLayer's normalizer handles many evasion techniques before rule matching
- See `tests/test_adversarial.py` for evasion-specific tests

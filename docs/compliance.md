# Compliance Evidence

ProofLayer emits compliance evidence by mapping runtime and eval events to packaged framework registries. It does not claim certification; it creates auditor-defensible evidence records with timestamps, source events, control IDs, and sha256 hash chaining.

## Install

```bash
pip install prooflayer-rules[compliance]
```

## Supported Frameworks

- NIST AI RMF
- EU AI Act Articles 13-15
- SOC 2 CC6/CC7
- HIPAA Security Rule

Each framework registry lives in `prooflayer/compliance/frameworks/` and includes at least 20 AI-applicable controls.

## Emitting Evidence

```python
from prooflayer.compliance import ComplianceEmitter

emitter = ComplianceEmitter(["nist_ai_rmf", "soc2"])
records = emitter.emit(
    {
        "event_type": "detection",
        "category": "prompt_injection",
        "timestamp": "2026-06-13T00:00:00Z",
        "decision": "BLOCK",
        "rule_ids": ["direct-ignore-previous"],
        "event_hash": "abc123",
    }
)
```

Each `EvidenceRecord` includes:

- framework
- control ID
- evidence type
- source event
- event ID
- timestamp
- previous hash
- evidence hash

## Reports

```python
from pathlib import Path
from prooflayer.compliance import ComplianceReportGenerator

ComplianceReportGenerator().to_markdown(
    records,
    output_path=Path("security-reports/compliance/report.md"),
)
```

PDF rendering is optional and requires:

```bash
pip install prooflayer-rules[compliance]
```

Then:

```python
ComplianceReportGenerator().to_pdf(markdown, Path("security-reports/compliance/report.pdf"))
```

## Mapping Rules

ProofLayer maps evidence conservatively:

- `prompt_injection`, `jailbreak`, `exfil`, and `state_manipulation` map to runtime monitoring and audit controls.
- `tool_abuse` maps to tool access and unauthorized-action controls.
- `scope_drift` maps to intended-purpose and authorized-use controls.
- `multi_turn` and `eval_report` map to adversarial robustness and evaluation controls.
- `benchmark` maps to performance and robustness controls.

If an event does not match a known category or event type, no evidence is emitted.

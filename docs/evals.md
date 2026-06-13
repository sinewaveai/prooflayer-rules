# Adversarial Evals

ProofLayer includes an adversarial eval harness for LangGraph agents. It can run the built-in ProofLayer suite locally and can orchestrate GARAK and PromptFoo through pinned Docker images.

## Install

```bash
pip install prooflayer-rules[evals,langgraph]
```

## Built-In Suite

```python
from prooflayer.evals import EvalRunner, LangGraphEvalTarget

target = LangGraphEvalTarget(secured_graph, name="support-agent")
report = EvalRunner().run_builtin_suite(target)

print(report.passed_count, report.failed_count)
```

The built-in suite includes 30 LangGraph-oriented probes across prompt injection, jailbreak, tool abuse, exfiltration, scope drift, state manipulation, memory manipulation, multi-agent, streaming, encoding, and benign cases.

## JSON and Markdown Reports

```python
from pathlib import Path
from prooflayer.evals import EvalRunner

report = EvalRunner().run_all(
    target,
    output_dir=Path("security-reports/evals/support-agent"),
)
```

This writes:

- `findings.json`
- `findings.md`

## GARAK

`GarakRunner` invokes `leondz/garak:0.10.0` against an OpenAI-compatible endpoint:

```python
from pathlib import Path
from prooflayer.evals import GarakRunner

findings = GarakRunner().run(
    endpoint_url="http://127.0.0.1:8000/v1",
    output_dir=Path("security-reports/evals/garak"),
)
```

## PromptFoo

`PromptFooRunner` invokes `promptfoo/promptfoo:0.95.0`:

```python
from pathlib import Path
from prooflayer.evals import PromptFooRunner

findings = PromptFooRunner().run(
    config_path=Path("promptfooconfig.yaml"),
    output_path=Path("security-reports/evals/promptfoo-results.json"),
)
```

## Interpreting Results

An eval finding has:

- `id`
- `source`
- `category`
- `severity`
- `prompt`
- `outcome`
- `passed`
- `details`

Failed findings are retained as evidence. They should be reviewed, fixed, or explicitly risk-accepted before launch.

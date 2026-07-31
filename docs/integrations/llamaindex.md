# LlamaIndex Integration

ProofLayer wraps LlamaIndex-compatible tools and can scan retrieved context
chunks before they are added to an agent or RAG prompt. The integration is
dependency-light at import time and only requires LlamaIndex when customers use
real LlamaIndex objects.

## Install

```bash
pip install "prooflayer-rules[llamaindex]"
```

The optional extra installs `llama-index>=0.14.23`.

## Usage

```python
from prooflayer.integrations.llamaindex import ProofLayerToolWrapper, SecurityConfig

wrapper = ProofLayerToolWrapper(
    config=SecurityConfig(
        prompt_injection="block",
        tool_poisoning="block",
        exfil="block",
        emit_to=["stdout", "logfile:./audit.jsonl"],
    )
)

safe_tools = wrapper.wrap_tools(mcp_tools)
safe_context = wrapper.scan_context_chunks(retrieved_nodes)
```

Use `safe_tools` anywhere the original LlamaIndex tools would be passed. The
wrapper preserves common LlamaIndex tool methods including `call`, `acall`, and
direct calls.

## Security Checks

- Tool descriptions are scanned for tool poisoning before agent exposure.
- Tool arguments are scanned before tool execution.
- Tool outputs are scanned before returning to the agent.
- Retrieved context chunks are scanned for prompt injection and exfiltration.
- Context audit events include source metadata when the chunk exposes it.

## Local Example

```bash
python3 examples/integrations/llamaindex/basic_tool_security.py
```

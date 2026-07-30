# LlamaIndex Integration Example

This example shows how to wrap LlamaIndex-compatible tools and scan retrieved
context chunks before they are added to an agent or RAG prompt.

Run:

```bash
python3 examples/integrations/llamaindex/basic_tool_security.py
```

The example uses local fake objects with common LlamaIndex `metadata`, `call()`,
and context-node surfaces. It demonstrates:

- clean tool calls passing through
- exfiltrating tool arguments blocked before execution
- retrieved prompt-injection context blocked with source metadata in the audit log

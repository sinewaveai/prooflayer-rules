# LangChain MCP Integration Example

This example shows how to wrap LangChain-compatible MCP tools before they are
passed to a LangChain or LangGraph agent.

Run:

```bash
python3 examples/integrations/langchain_mcp/basic_tool_security.py
```

The example uses a local fake tool with the same `name`, `description`, and
`invoke()` surface used by LangChain tools. It demonstrates:

- clean calls passing through
- exfiltrating arguments blocked before tool execution
- poisoned tool descriptions blocked before agent exposure

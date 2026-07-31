# LangChain MCP Integration

ProofLayer wraps LangChain-compatible MCP tools before they are made available to
LangChain or LangGraph agents. The integration scans tool descriptions, tool
arguments, and tool outputs with the same deterministic rules engine used by the
MCP gateway and LangGraph integration.

## Install

```bash
pip install "prooflayer-rules[langchain-mcp]"
```

The optional extra installs `langchain-mcp-adapters>=0.3.1` and
`langchain-core>=0.3.0`.

## Usage

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from prooflayer.integrations.langchain_mcp import SecurityConfig, SecurityMiddleware

client = MultiServerMCPClient({...})
tools = await client.get_tools()

middleware = SecurityMiddleware(
    config=SecurityConfig(
        tool_poisoning="block",
        exfil="block",
        tool_abuse="block",
        emit_to=["stdout", "logfile:./audit.jsonl"],
    )
)

safe_tools = middleware.wrap_tools(tools)
```

Use `safe_tools` anywhere the original LangChain tools would be passed. The
wrapper preserves common LangChain tool methods including `invoke`, `ainvoke`,
`run`, `arun`, and direct calls.

## Security Checks

- Tool descriptions are scanned for tool poisoning before agent exposure.
- Tool arguments are scanned before MCP server execution.
- Tool outputs are scanned before returning to the agent.
- Explicit `allowed_tools` and `blocked_tools` policy is enforced before calls.
- Audit events include `integration="langchain_mcp"`, rule IDs, timestamps, and
  sha256 chain-of-custody fields.

## Local Example

```bash
python3 examples/integrations/langchain_mcp/basic_tool_security.py
```

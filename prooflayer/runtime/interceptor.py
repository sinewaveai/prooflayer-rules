"""
MCP Interceptor
================

JSON-RPC parsing utilities shared between the HTTP proxy transport
and the MCP SDK wrapper.
"""

import json
import logging
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)


class MCPInterceptor:
    """Utilities for parsing and creating MCP JSON-RPC messages."""

    @staticmethod
    def parse_jsonrpc(body: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse JSON-RPC from bytes.

        Args:
            body: Raw HTTP body bytes.

        Returns:
            Parsed dict, or None if not valid JSON.
        """
        if not body:
            return None
        try:
            return json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    @staticmethod
    def extract_tool_call(payload: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Extract tool name and arguments from a tools/call JSON-RPC request.

        Args:
            payload: Parsed JSON-RPC dict.

        Returns:
            (tool_name, arguments) tuple, or None if not a tools/call.
        """
        method = payload.get("method", "")
        if method != "tools/call":
            return None

        params = payload.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if not tool_name:
            return None

        return tool_name, arguments

    @staticmethod
    def make_block_response(
        request_id: Any,
        tool_name: str,
        score: int,
    ) -> Dict[str, Any]:
        """
        Create a JSON-RPC response that blocks a tool call.

        Args:
            request_id: The JSON-RPC request ID.
            tool_name: Name of the blocked tool.
            score: Risk score that triggered the block.

        Returns:
            JSON-RPC response dict with isError: True.
        """
        return {
            "jsonrpc": "2.0",
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Tool call blocked by ProofLayer: {tool_name} "
                                f"(risk score: {score})",
                    }
                ],
                "isError": True,
            },
            "id": request_id,
        }

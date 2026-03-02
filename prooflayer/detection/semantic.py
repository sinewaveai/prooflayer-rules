"""
Semantic Analyzer
=================

Parameter-level semantic validation for MCP tool calls.
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class SemanticAnalyzer:
    """
    Detects semantic mismatches in tool call arguments.

    For example, a "hostname" parameter should not contain URLs or shell commands.
    """

    def analyze(self, tool_name: str, arguments: Dict[str, Any]) -> int:
        """
        Run semantic analysis on tool call arguments.

        Args:
            tool_name: Name of the MCP tool being called.
            arguments: Tool call arguments dict.

        Returns:
            Semantic risk score (0+).
        """
        score = 0

        for param_name, param_value in arguments.items():
            param_lower = param_name.lower()
            param_value_str = str(param_value).lower()

            # Hostname/server/endpoint should not contain URLs
            if any(kw in param_lower for kw in [
                "hostname", "server", "host", "endpoint", "target", "address",
            ]):
                if any(proto in param_value_str for proto in [
                    "http://", "https://", "ftp://",
                    "ssh://", "file://", "data://", "gopher://",
                ]):
                    score += 15
                    logger.debug("Semantic mismatch: hostname/server contains URL (+15 points)")

            # System ID should be numeric or alphanumeric, not commands
            if "system_id" in param_lower or "id" in param_lower:
                if any(cmd in param_value_str for cmd in [
                    "curl", "wget", "bash", "sh",
                    "nc", "netcat", "python", "perl", "ruby", "ncat",
                ]):
                    score += 20
                    logger.debug("Semantic mismatch: ID contains command (+20 points)")

            # Numeric params containing non-numeric content with commands
            if any(kw in param_lower for kw in ["port", "timeout", "count", "limit"]):
                if any(cmd in param_value_str for cmd in [
                    "curl", "wget", "bash", "sh", "nc", "netcat",
                    "python", "perl", "ruby", "ncat",
                ]):
                    score += 15
                    logger.debug("Semantic mismatch: numeric param contains command (+15 points)")

            # Path/file params containing pipe or semicolon
            if any(kw in param_lower for kw in ["path", "file"]):
                if "|" in param_value_str or ";" in param_value_str:
                    score += 20
                    logger.debug("Semantic mismatch: path/file param contains pipe or semicolon (+20 points)")

        return score

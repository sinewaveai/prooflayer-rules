"""
Allowlist
=========

Allowlisting mechanism for known-safe tool calls so legitimate
operations are not flagged by the detection engine.
"""

import fnmatch
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Allowlist:
    """
    Manages allowlist rules loaded from YAML configuration.

    Supports allowlisting by:
    - Exact tool name
    - Tool name glob pattern
    - Argument value patterns (glob)
    - Combined tool + argument bypass rules
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize allowlist from configuration dictionary.

        Args:
            config: The ``allowlist`` section from the YAML config.
                    Expected keys: tools, tool_patterns, argument_allowlist,
                    bypass_rules.
        """
        config = config or {}

        self.tools: List[str] = config.get("tools", [])
        self.tool_patterns: List[str] = config.get("tool_patterns", [])
        self.argument_allowlist: Dict[str, List[str]] = config.get(
            "argument_allowlist", {}
        )
        self.bypass_rules: List[Dict[str, Any]] = config.get("bypass_rules", [])

        logger.info(
            "Allowlist loaded: %d tools, %d patterns, %d argument rules, %d bypass rules",
            len(self.tools),
            len(self.tool_patterns),
            len(self.argument_allowlist),
            len(self.bypass_rules),
        )

    def is_allowed(
        self, tool_name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Check whether a tool call matches any allowlist rule.

        Args:
            tool_name: Name of the MCP tool being called.
            arguments: Tool call arguments (may be None).

        Returns:
            True if the call is allowlisted and should skip detection.
        """
        arguments = arguments or {}

        # 1. Exact tool name match
        if tool_name in self.tools:
            logger.info("Allowlisted by exact tool name: %s", tool_name)
            return True

        # 2. Tool name glob pattern match
        for pattern in self.tool_patterns:
            if fnmatch.fnmatch(tool_name, pattern):
                logger.info(
                    "Allowlisted by tool pattern '%s': %s", pattern, tool_name
                )
                return True

        # 3. Argument value pattern match — all specified argument keys must
        #    have a value matching at least one of the allowed patterns.
        if self.argument_allowlist and arguments:
            if self._arguments_match(arguments):
                logger.info(
                    "Allowlisted by argument values: %s %s", tool_name, arguments
                )
                return True

        # 4. Combined bypass rules
        for rule in self.bypass_rules:
            if self._bypass_rule_matches(rule, tool_name, arguments):
                logger.info(
                    "Allowlisted by bypass rule for tool '%s': %s",
                    rule.get("tool"),
                    tool_name,
                )
                return True

        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _arguments_match(self, arguments: Dict[str, Any]) -> bool:
        """Check if all specified argument keys match their allowed patterns."""
        matched_any = False
        for key, patterns in self.argument_allowlist.items():
            value = arguments.get(key)
            if value is None:
                continue
            value_str = str(value)
            if any(fnmatch.fnmatch(value_str, p) for p in patterns):
                matched_any = True
            else:
                # If the key is present but does not match, fail.
                return False
        return matched_any

    def _bypass_rule_matches(
        self,
        rule: Dict[str, Any],
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> bool:
        """Check if a combined bypass rule matches."""
        rule_tool = rule.get("tool")
        if rule_tool and rule_tool != tool_name:
            return False

        rule_args = rule.get("arguments", {})
        for key, expected_value in rule_args.items():
            actual = arguments.get(key)
            if actual is None or str(actual) != str(expected_value):
                return False

        return True

"""
Detection Engine
================

Scans MCP tool calls for prompt injection, command injection, and other threats.
"""

import re
import logging
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path

from ..utils.entropy import calculate_shannon_entropy
from .models import DetectionRule
from .rules import RuleLoader

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Detection engine for MCP tool call security scanning.

    Implements 59+ detection rules across 6 categories:
    - Direct injection (12 rules)
    - Jailbreaks (8 rules)
    - Command injection (15 rules)
    - Data exfiltration (10 rules)
    - Role manipulation (8 rules)
    - Tool poisoning (6 rules)
    """

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        score_threshold: Optional[Dict[str, tuple]] = None
    ):
        """
        Initialize detection engine.

        Args:
            rules_dir: Directory containing YAML rule files
            score_threshold: Score thresholds for ALLOW/WARN/BLOCK
        """
        self.rules: List[DetectionRule] = []
        self.score_threshold = score_threshold or {
            "allow": (0, 29),
            "warn": (30, 69),
            "block": (70, 100)
        }

        # Load rules
        self._load_rules(rules_dir)

        logger.info(f"Detection engine initialized with {len(self.rules)} rules")

    def _load_rules(self, rules_dir: Optional[str]):
        """Load detection rules from YAML files."""
        if rules_dir and Path(rules_dir).exists():
            self.rules = RuleLoader.load_from_directory(rules_dir)
        else:
            # Load built-in rules
            builtin_rules_dir = Path(__file__).parent.parent / "rules"
            if builtin_rules_dir.exists():
                self.rules = RuleLoader.load_from_directory(str(builtin_rules_dir))
            else:
                logger.warning("No rules directory found, using inline rules")
                self.rules = self._get_inline_rules()

    def _get_inline_rules(self) -> List[DetectionRule]:
        """
        Get inline detection rules (fallback when YAML files not available).
        """
        return [
            # Direct Injection (12 rules)
            DetectionRule(
                id="direct-ignore-previous",
                severity="critical",
                message="Direct injection: 'ignore previous instructions' detected",
                pattern=r"ignore\s+(previous|all|prior)\s+(instructions?|prompts?|commands?)",
                score=30,
                category="direct_injection"
            ),
            DetectionRule(
                id="direct-disregard-system",
                severity="critical",
                message="Direct injection: 'disregard system prompt' detected",
                pattern=r"(disregard|forget|override)\s+(system|original)\s+(prompt|instructions?)",
                score=30,
                category="direct_injection"
            ),
            DetectionRule(
                id="direct-new-instructions",
                severity="high",
                message="Direct injection: 'new instructions' detected",
                pattern=r"(new|updated|revised)\s+instructions?",
                score=20,
                category="direct_injection"
            ),

            # Jailbreaks (8 rules)
            DetectionRule(
                id="jailbreak-dan-mode",
                severity="critical",
                message="Jailbreak: DAN (Do Anything Now) mode detected",
                pattern=r"\b(DAN|do anything now)\b",
                score=30,
                category="jailbreak"
            ),
            DetectionRule(
                id="jailbreak-developer-mode",
                severity="critical",
                message="Jailbreak: Developer mode activation detected",
                pattern=r"(enable|activate|enter)\s+(developer|dev|debug)\s+mode",
                score=30,
                category="jailbreak"
            ),
            DetectionRule(
                id="jailbreak-act-as",
                severity="high",
                message="Jailbreak: 'act as' role manipulation detected",
                pattern=r"(act|pretend|behave)\s+as\s+(if|though|a)",
                score=20,
                category="jailbreak"
            ),

            # Command Injection (15 rules)
            DetectionRule(
                id="cmd-inject-semicolon",
                severity="critical",
                message="Command injection: Shell metacharacter ';' detected",
                pattern=r";[\s]*[a-z]",
                score=20,
                category="command_injection"
            ),
            DetectionRule(
                id="cmd-inject-pipe",
                severity="critical",
                message="Command injection: Pipe operator '|' detected",
                pattern=r"\|[\s]*[a-z]",
                score=20,
                category="command_injection"
            ),
            DetectionRule(
                id="cmd-inject-double-ampersand",
                severity="critical",
                message="Command injection: Command chaining '&&' detected",
                pattern=r"&&",
                score=15,
                category="command_injection"
            ),
            DetectionRule(
                id="cmd-inject-curl",
                severity="critical",
                message="Command injection: 'curl' command detected",
                pattern=r"\bcurl\s+",
                score=25,
                category="command_injection"
            ),
            DetectionRule(
                id="cmd-inject-wget",
                severity="critical",
                message="Command injection: 'wget' command detected",
                pattern=r"\bwget\s+",
                score=25,
                category="command_injection"
            ),
            DetectionRule(
                id="cmd-inject-bash",
                severity="critical",
                message="Command injection: 'bash' invocation detected",
                pattern=r"\b(bash|sh|zsh)\s+-c",
                score=30,
                category="command_injection"
            ),
            DetectionRule(
                id="cmd-inject-nc",
                severity="critical",
                message="Command injection: 'nc' (netcat) detected",
                pattern=r"\b(nc|netcat)\s+",
                score=30,
                category="command_injection"
            ),

            # Data Exfiltration (10 rules)
            DetectionRule(
                id="exfil-send-to-url",
                severity="critical",
                message="Data exfiltration: 'send to URL' detected",
                pattern=r"(send|post|upload)\s+(to|at)\s+https?://",
                score=25,
                category="data_exfiltration"
            ),
            DetectionRule(
                id="exfil-base64-encode",
                severity="high",
                message="Data exfiltration: Base64 encoding detected",
                pattern=r"base64\s+(encode|--encode|-e)",
                score=15,
                category="data_exfiltration"
            ),
            DetectionRule(
                id="exfil-file-read",
                severity="critical",
                message="Data exfiltration: Sensitive file access detected",
                pattern=r"(/etc/(passwd|shadow)|\.ssh/|\.env|credentials)",
                score=30,
                category="data_exfiltration"
            ),

            # Role Manipulation (8 rules)
            DetectionRule(
                id="role-you-are-now",
                severity="high",
                message="Role manipulation: 'you are now' detected",
                pattern=r"you are now\s+",
                score=20,
                category="role_manipulation"
            ),
            DetectionRule(
                id="role-pretend-to-be",
                severity="high",
                message="Role manipulation: 'pretend to be' detected",
                pattern=r"pretend\s+to\s+be\s+",
                score=20,
                category="role_manipulation"
            ),
            DetectionRule(
                id="role-admin-override",
                severity="critical",
                message="Role manipulation: Admin override attempt detected",
                pattern=r"(admin|root|sudo)\s+(override|access|mode)",
                score=25,
                category="role_manipulation"
            ),
        ]

    def scan(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Tuple[int, List[DetectionRule]]:
        """
        Scan MCP tool call for threats.

        Args:
            tool_name: Name of the MCP tool being called
            arguments: Tool call arguments

        Returns:
            Tuple of (risk_score, matched_rules)
        """
        matched_rules = []
        total_score = 0

        # Convert arguments to searchable text
        search_text = self._prepare_search_text(tool_name, arguments)

        # Pattern matching
        for rule in self.rules:
            if rule.compiled_pattern and rule.compiled_pattern.search(search_text):
                matched_rules.append(rule)
                total_score += rule.score
                logger.debug(f"Rule matched: {rule.id} (+{rule.score} points)")

        # Shell metacharacter detection (additional scoring)
        dangerous_chars = [';', '|', '&&', '||', '`', '$', '>', '<']
        for char in dangerous_chars:
            if char in search_text:
                total_score += 10
                logger.debug(f"Dangerous char '{char}' detected (+10 points)")

        # Entropy analysis (high entropy = possible encoded payload)
        entropy = calculate_shannon_entropy(search_text)
        if entropy > 4.5:
            total_score += 20
            logger.debug(f"High entropy detected: {entropy:.2f} (+20 points)")

        # Semantic analysis - check for mismatches
        semantic_score = self._semantic_analysis(tool_name, arguments)
        total_score += semantic_score

        # Cap score at 100
        risk_score = min(total_score, 100)

        logger.info(f"Scan complete: {tool_name} - Score: {risk_score} - Rules matched: {len(matched_rules)}")

        return risk_score, matched_rules

    def _prepare_search_text(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Convert tool call to searchable text."""
        parts = [tool_name]

        for key, value in arguments.items():
            parts.append(f"{key}={value}")

        return " ".join(str(p) for p in parts)

    def _semantic_analysis(self, tool_name: str, arguments: Dict[str, Any]) -> int:
        """
        Semantic analysis for parameter validation.

        Example: "hostname" parameter should not contain URLs or shell commands.
        """
        score = 0

        for param_name, param_value in arguments.items():
            param_value_str = str(param_value).lower()

            # Hostname should not contain URLs
            if "hostname" in param_name.lower():
                if any(proto in param_value_str for proto in ["http://", "https://", "ftp://"]):
                    score += 15
                    logger.debug(f"Semantic mismatch: hostname contains URL (+15 points)")

            # System ID should be numeric or alphanumeric, not commands
            if "system_id" in param_name.lower() or "id" in param_name.lower():
                if any(cmd in param_value_str for cmd in ["curl", "wget", "bash", "sh"]):
                    score += 20
                    logger.debug(f"Semantic mismatch: ID contains command (+20 points)")

        return score

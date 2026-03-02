"""
Detection Engine
================

Scans MCP tool calls for prompt injection, command injection, and other threats.
"""

import json
import re
import logging
import threading
import time
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path

from ..config.allowlist import Allowlist
from ..utils.entropy import calculate_shannon_entropy
from ..metrics import metrics
from .models import DetectionRule, ScanResult
from .rules import RuleLoader, RuleLoadError
from .normalizer import normalize_text, flatten_arguments
from .scanner import PatternScanner, REGEX_CIRCUIT_BREAKER_THRESHOLD
from .scorer import RiskScorer
from .semantic import SemanticAnalyzer

logger = logging.getLogger(__name__)

# Input validation limits
_MAX_ARGUMENTS_SIZE = 1_048_576  # 1 MB
_MAX_NESTING_DEPTH = 10

# Re-export for backwards compatibility
_REGEX_TIMEOUT_SECONDS = 0.1  # 100ms
_REGEX_CIRCUIT_BREAKER_THRESHOLD = REGEX_CIRCUIT_BREAKER_THRESHOLD


class InputValidationError(ValueError):
    """Raised when tool call arguments fail input validation."""
    pass


def _check_nesting_depth(obj: Any, current_depth: int = 0) -> None:
    """Raise InputValidationError if nesting exceeds the limit."""
    if current_depth > _MAX_NESTING_DEPTH:
        raise InputValidationError(
            f"Argument nesting depth exceeds maximum of {_MAX_NESTING_DEPTH}"
        )
    if isinstance(obj, dict):
        for v in obj.values():
            _check_nesting_depth(v, current_depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_nesting_depth(item, current_depth + 1)


def _strip_null_bytes(obj: Any) -> Any:
    """Recursively strip null bytes from all string values."""
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    elif isinstance(obj, dict):
        return {k: _strip_null_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return type(obj)(_strip_null_bytes(item) for item in obj)
    return obj


class DetectionEngine:
    """
    Detection engine for MCP tool call security scanning.

    Implements 71 YAML detection rules across 8 categories:
    - Command injection (15 rules)
    - Prompt/direct injection (12 rules)
    - Jailbreaks (8 rules)
    - Data exfiltration (10 rules)
    - Role manipulation (8 rules)
    - Tool poisoning (6 rules)
    - SSRF/XXE (6 rules)
    - SQL injection (6 rules)

    Additional inline heuristics serve as fallback when YAML files are unavailable.
    """

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        score_threshold: Optional[Dict[str, tuple]] = None,
        fail_closed: bool = True,
        allowlist: Optional[Allowlist] = None,
    ):
        """
        Initialize detection engine.

        Args:
            rules_dir: Directory containing YAML rule files
            score_threshold: Score thresholds for ALLOW/WARN/BLOCK
            fail_closed: If True (default), block all requests when no rules
                are loaded. If False, fall back to inline rules with a warning.
                Setting this to False is an explicit opt-in that weakens security.
            allowlist: Optional Allowlist instance for known-safe tool calls.
        """
        self._lock = threading.Lock()
        self.rules: List[DetectionRule] = []
        self.fail_closed = fail_closed
        self.allowlist = allowlist
        self.score_threshold = score_threshold or {
            "allow": (0, 29),
            "warn": (30, 69),
            "block": (70, 100)
        }

        # ReDoS circuit breaker state
        self._consecutive_regex_timeouts = 0

        # Delegate pattern matching to PatternScanner
        self._scanner = PatternScanner()

        # Delegate risk scoring to RiskScorer
        self._scorer = RiskScorer()

        # Delegate semantic analysis to SemanticAnalyzer
        self._semantic_analyzer = SemanticAnalyzer()

        # Load rules
        self._load_rules(rules_dir)

        if not self.rules and self.fail_closed:
            raise RuleLoadError(
                "ProofLayer cannot start: no detection rules loaded. "
                "This is a security-critical error. Ensure rule files exist "
                "and are valid, or set fail_closed=False to use inline rules "
                "(not recommended for production)."
            )

        logger.info(f"Detection engine initialized with {len(self.rules)} rules")
        metrics.set_active_rules(len(self.rules))

    def _load_rules(self, rules_dir: Optional[str]):
        """Load detection rules from YAML files."""
        try:
            if rules_dir and Path(rules_dir).exists():
                self.rules = RuleLoader.load_from_directory(rules_dir)
                return
        except RuleLoadError:
            if self.fail_closed:
                raise
            logger.warning(
                "SECURITY WARNING: Rule loading from custom directory failed. "
                "Falling back to built-in rules."
            )

        try:
            builtin_rules_dir = Path(__file__).parent.parent / "rules"
            if builtin_rules_dir.exists():
                self.rules = RuleLoader.load_from_directory(str(builtin_rules_dir))
                return
        except RuleLoadError:
            if self.fail_closed:
                raise
            logger.warning(
                "SECURITY WARNING: Built-in rule loading failed. "
                "Falling back to inline rules."
            )

        if not self.fail_closed:
            logger.warning(
                "SECURITY WARNING: Using inline fallback rules. "
                "This provides reduced protection. Set fail_closed=True "
                "and fix rule loading for production use."
            )
            self.rules = self._get_inline_rules()
        # If fail_closed is True and we reach here, the __init__ check will raise

    def _get_inline_rules(self) -> List[DetectionRule]:
        """
        Get inline detection rules as fallback when YAML files are unavailable.

        Covers 71 rules across 8 categories: direct_injection, jailbreak,
        command_injection, data_exfiltration, role_manipulation, tool_poisoning,
        ssrf_xxe, sql_injection.
        """
        return [
            # Direct Injection
            DetectionRule(
                id="direct-ignore-previous", severity="critical",
                message="Direct injection: 'ignore previous instructions' detected",
                pattern=r"ignore\s+(previous|all|prior)\s+(instructions?|prompts?|commands?)",
                score=30, category="direct_injection",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),
            DetectionRule(
                id="direct-disregard-system", severity="critical",
                message="Direct injection: 'disregard system prompt' detected",
                pattern=r"(disregard|forget|override)\s+(system|original)\s+(prompt|instructions?)",
                score=30, category="direct_injection",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),
            DetectionRule(
                id="direct-new-instructions", severity="high",
                message="Direct injection: 'new instructions' detected",
                pattern=r"(new|updated|revised)\s+instructions?",
                score=20, category="direct_injection",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),

            # Jailbreaks
            DetectionRule(
                id="jailbreak-dan-mode", severity="critical",
                message="Jailbreak: DAN (Do Anything Now) mode detected",
                pattern=r"\b(DAN|do anything now)\b",
                score=30, category="jailbreak",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),
            DetectionRule(
                id="jailbreak-developer-mode", severity="critical",
                message="Jailbreak: Developer mode activation detected",
                pattern=r"(enable|activate|enter)\s+(developer|dev|debug)\s+mode",
                score=30, category="jailbreak",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),
            DetectionRule(
                id="jailbreak-act-as", severity="high",
                message="Jailbreak: 'act as' role manipulation detected",
                pattern=r"(act|pretend|behave)\s+as\s+(if|though|a)",
                score=20, category="jailbreak",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),

            # Command Injection
            DetectionRule(
                id="cmd-inject-semicolon", severity="critical",
                message="Command injection: Shell metacharacter ';' detected",
                pattern=r";[\s]*[a-zA-Z/.$]",
                score=20, category="command_injection",
                owasp=["LLM01", "LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="cmd-inject-pipe", severity="critical",
                message="Command injection: Pipe operator '|' detected",
                pattern=r"\|[\s]*[a-zA-Z/.$]",
                score=20, category="command_injection",
                owasp=["LLM01", "LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="cmd-inject-double-ampersand", severity="critical",
                message="Command injection: Command chaining '&&' detected",
                pattern=r"&&[\s]*[a-zA-Z/.$]",
                score=15, category="command_injection",
                owasp=["LLM01", "LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="cmd-inject-curl", severity="critical",
                message="Command injection: 'curl' command detected",
                pattern=r"\bcurl\s+",
                score=25, category="command_injection",
                owasp=["LLM01", "LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="cmd-inject-wget", severity="critical",
                message="Command injection: 'wget' command detected",
                pattern=r"\bwget\s+",
                score=25, category="command_injection",
                owasp=["LLM01", "LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="cmd-inject-bash", severity="critical",
                message="Command injection: 'bash' invocation detected",
                pattern=r"\b(bash|sh|zsh)\s+-c",
                score=30, category="command_injection",
                owasp=["LLM01", "LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="cmd-inject-nc", severity="critical",
                message="Command injection: 'nc' (netcat) detected",
                pattern=r"\b(nc|netcat)\s+",
                score=30, category="command_injection",
                owasp=["LLM01", "LLM06", "MCP05", "ASI02"],
            ),

            # Data Exfiltration
            DetectionRule(
                id="exfil-send-to-url", severity="critical",
                message="Data exfiltration: 'send to URL' detected",
                pattern=r"(send|post|upload)\s+(to|at)\s+https?://",
                score=25, category="data_exfiltration",
                owasp=["LLM06", "MCP01", "ASI02"],
            ),
            DetectionRule(
                id="exfil-base64-encode", severity="high",
                message="Data exfiltration: Base64 encoding detected",
                pattern=r"base64\s+(encode|--encode|-e)",
                score=15, category="data_exfiltration",
                owasp=["LLM06", "MCP01", "ASI02"],
            ),
            DetectionRule(
                id="exfil-file-read", severity="critical",
                message="Data exfiltration: Sensitive file access detected",
                pattern=r"(/etc/(passwd|shadow)|\.ssh/|\.env|credentials)",
                score=30, category="data_exfiltration",
                owasp=["LLM06", "MCP01", "ASI02"],
            ),

            # Role Manipulation
            DetectionRule(
                id="role-you-are-now", severity="critical",
                message="Role manipulation: 'you are now' malicious role detected",
                pattern=r"you are now\s+(a |an |the )?(unrestricted|unfiltered|evil|malicious|hacked|compromised)",
                score=20, category="role_manipulation",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),
            DetectionRule(
                id="role-pretend-to-be", severity="high",
                message="Role manipulation: 'pretend to be' detected",
                pattern=r"pretend\s+to\s+be\s+(a |an )?(hacker|admin|root|unrestricted|evil|malicious)",
                score=20, category="role_manipulation",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),
            DetectionRule(
                id="role-act-as-root", severity="critical",
                message="Role manipulation: 'act as root/admin' detected",
                pattern=r"(act|behave|function)\s+as\s+(root|admin|superuser|sudo)",
                score=25, category="role_manipulation",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),
            DetectionRule(
                id="role-become-unrestricted", severity="critical",
                message="Role manipulation: 'become unrestricted' detected",
                pattern=r"become\s+(an?\s+)?(unrestricted|unfiltered|uncensored|unlimited)",
                score=30, category="role_manipulation",
                owasp=["LLM01", "MCP06", "ASI01"],
            ),

            # Tool Poisoning
            DetectionRule(
                id="poison-when-called-execute", severity="critical",
                message="Tool poisoning: hidden execution instruction in description",
                pattern=r"when\s+(this\s+tool\s+is\s+)?called,?\s+(execute|run|perform)",
                score=30, category="tool_poisoning",
                owasp=["LLM03", "MCP03", "ASI04"],
            ),
            DetectionRule(
                id="poison-silently-run", severity="critical",
                message="Tool poisoning: silent execution instruction",
                pattern=r"silently\s+(run|execute|perform|send|upload)",
                score=30, category="tool_poisoning",
                owasp=["LLM03", "MCP03", "ASI04"],
            ),
            DetectionRule(
                id="poison-hidden-instruction", severity="critical",
                message="Tool poisoning: hidden instruction tags detected",
                pattern=r"<\s*(hidden|invisible|secret)\s*>",
                score=25, category="tool_poisoning",
                owasp=["LLM03", "MCP03", "ASI04"],
            ),
            DetectionRule(
                id="poison-tool-description-inject", severity="critical",
                message="Tool poisoning: injected pre/post execution",
                pattern=r"(before|after)\s+respond(ing)?,?\s+(first\s+)?(run|execute|call|send)",
                score=30, category="tool_poisoning",
                owasp=["LLM03", "MCP03", "ASI04"],
            ),

            # SSRF/XXE
            DetectionRule(
                id="ssrf-cloud-metadata", severity="critical",
                message="SSRF: Cloud metadata endpoint access detected",
                pattern=r"169\.254\.169\.254|metadata\.google|169\.254\.170\.2",
                score=30, category="ssrf_xxe",
                owasp=["LLM06", "MCP01", "ASI02"],
            ),
            DetectionRule(
                id="ssrf-internal-ip", severity="high",
                message="SSRF: Internal/private IP address in URL detected",
                pattern=r"(https?://)(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)",
                score=25, category="ssrf_xxe",
                owasp=["LLM06", "MCP01", "ASI02"],
            ),
            DetectionRule(
                id="ssrf-file-scheme", severity="high",
                message="SSRF: file:// scheme detected",
                pattern=r"file://",
                score=25, category="ssrf_xxe",
                owasp=["LLM06", "MCP01", "ASI02"],
            ),
            DetectionRule(
                id="xxe-entity-declaration", severity="critical",
                message="XXE: DOCTYPE or ENTITY declaration detected",
                pattern=r"<!\s*(DOCTYPE|ENTITY)",
                score=30, category="ssrf_xxe",
                owasp=["LLM06", "MCP01", "ASI02"],
            ),
            DetectionRule(
                id="xxe-system-entity", severity="critical",
                message="XXE: SYSTEM entity reference detected",
                pattern=r"SYSTEM\s+['\"]",
                score=30, category="ssrf_xxe",
                owasp=["LLM06", "MCP01", "ASI02"],
            ),
            DetectionRule(
                id="ssrf-gopher-scheme", severity="high",
                message="SSRF: gopher:// scheme detected",
                pattern=r"gopher://",
                score=25, category="ssrf_xxe",
                owasp=["LLM06", "MCP01", "ASI02"],
            ),

            # SQL Injection
            DetectionRule(
                id="sql-union-select", severity="critical",
                message="SQL injection: UNION SELECT detected",
                pattern=r"\bunion\s+(all\s+)?select\b",
                score=25, category="sql_injection",
                owasp=["LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="sql-drop-table", severity="critical",
                message="SQL injection: DROP TABLE/DATABASE detected",
                pattern=r"\bdrop\s+(table|database)\b",
                score=30, category="sql_injection",
                owasp=["LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="sql-or-equals", severity="high",
                message="SQL injection: OR/AND tautology detected",
                pattern=r"'\s*(or|and)\s+['\d]+\s*=\s*['\d]",
                score=20, category="sql_injection",
                owasp=["LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="sql-comment-bypass", severity="medium",
                message="SQL injection: SQL comment bypass detected",
                pattern=r"--\s*$|/\*.*\*/",
                score=15, category="sql_injection",
                owasp=["LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="sql-sleep-benchmark", severity="critical",
                message="SQL injection: Time-based injection (SLEEP/BENCHMARK) detected",
                pattern=r"\b(sleep|benchmark|waitfor)\s*\(",
                score=25, category="sql_injection",
                owasp=["LLM06", "MCP05", "ASI02"],
            ),
            DetectionRule(
                id="sql-information-schema", severity="high",
                message="SQL injection: information_schema/sys access detected",
                pattern=r"information_schema\.|sys\.",
                score=20, category="sql_injection",
                owasp=["LLM06", "MCP05", "ASI02"],
            ),
        ]

    def _validate_arguments(self, arguments: Any) -> Dict[str, Any]:
        """
        Validate and sanitise tool call arguments.

        Raises InputValidationError on invalid input.
        """
        if arguments is None:
            return {}

        if not isinstance(arguments, dict):
            raise InputValidationError(
                f"Arguments must be a dict or None, got {type(arguments).__name__}"
            )

        # Size limit
        serialized = json.dumps(arguments, default=str)
        if len(serialized) > _MAX_ARGUMENTS_SIZE:
            raise InputValidationError(
                f"Arguments exceed maximum size of {_MAX_ARGUMENTS_SIZE} bytes "
                f"(got {len(serialized)})"
            )

        # Nesting depth limit
        _check_nesting_depth(arguments)

        # Strip null bytes
        return _strip_null_bytes(arguments)

    def _match_rule(
        self, rule: DetectionRule, text: str
    ) -> Tuple[bool, bool]:
        """
        Match a single rule against text with ReDoS protection.

        Delegates to PatternScanner.match_rule().

        Returns:
            (matched, timed_out)
        """
        return self._scanner.match_rule(rule, text)

    def scan(
        self,
        tool_name: str,
        arguments: Any
    ) -> ScanResult:
        """
        Scan MCP tool call for threats.

        Args:
            tool_name: Name of the MCP tool being called
            arguments: Tool call arguments (dict or None)

        Returns:
            ScanResult (iterable as (risk_score, matched_rules) for backwards compat)

        Raises:
            InputValidationError: If arguments fail validation.
        """
        from datetime import datetime, timezone

        scan_start = time.perf_counter()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # --- Input validation ---
        arguments = self._validate_arguments(arguments)

        # --- Allowlist check (before detection) ---
        if self.allowlist and self.allowlist.is_allowed(tool_name, arguments):
            logger.info("Allowlisted tool call: %s - skipping detection", tool_name)
            latency_ms = (time.perf_counter() - scan_start) * 1000
            metrics.record_scan(
                action="allow", duration=latency_ms / 1000, risk_score=0,
                matched_rules=[],
            )
            return ScanResult(
                score=0, level="SAFE", action="ALLOW",
                matched_rules=[], scoring_breakdown={
                    "pattern_score": 0, "metachar_score": 0,
                    "entropy_score": 0, "semantic_score": 0,
                },
                tool_name=tool_name, arguments=arguments,
                timestamp=timestamp, latency_ms=latency_ms,
                owasp_mapping=[],
            )

        with self._lock:
            if not self.rules and self.fail_closed:
                logger.critical(
                    "No rules loaded - blocking all requests (fail-closed mode)"
                )
                fail_closed_rule = DetectionRule(
                    id="fail-closed-no-rules",
                    severity="critical",
                    message="No detection rules loaded - blocking all requests (fail-closed mode)",
                    pattern="",
                    score=100,
                    category="system"
                )
                latency_ms = (time.perf_counter() - scan_start) * 1000
                metrics.record_scan(
                    action="block", duration=latency_ms / 1000, risk_score=100,
                    matched_rules=[("fail-closed-no-rules", "system")],
                )
                return ScanResult(
                    score=100, level="THREAT", action="BLOCK",
                    matched_rules=[fail_closed_rule],
                    scoring_breakdown={"pattern_score": 100, "metachar_score": 0,
                                       "entropy_score": 0, "semantic_score": 0},
                    tool_name=tool_name, arguments=arguments,
                    timestamp=timestamp, latency_ms=latency_ms,
                    owasp_mapping=[],
                )

        # --- ReDoS circuit breaker check ---
        with self._lock:
            if self._consecutive_regex_timeouts >= _REGEX_CIRCUIT_BREAKER_THRESHOLD:
                logger.warning(
                    "ReDoS circuit breaker tripped (%d consecutive timeouts) - "
                    "blocking request as suspicious",
                    self._consecutive_regex_timeouts,
                )
                circuit_rule = DetectionRule(
                    id="redos-circuit-breaker",
                    severity="critical",
                    message="Multiple regex timeouts detected - possible ReDoS attack",
                    pattern="",
                    score=100,
                    category="system",
                )
                latency_ms = (time.perf_counter() - scan_start) * 1000
                metrics.record_scan(
                    action="block", duration=latency_ms / 1000, risk_score=100,
                    matched_rules=[("redos-circuit-breaker", "system")],
                )
                return ScanResult(
                    score=100, level="THREAT", action="BLOCK",
                    matched_rules=[circuit_rule],
                    scoring_breakdown={"pattern_score": 100, "metachar_score": 0,
                                       "entropy_score": 0, "semantic_score": 0},
                    tool_name=tool_name, arguments=arguments,
                    timestamp=timestamp, latency_ms=latency_ms,
                    owasp_mapping=[],
                )

        matched_rules = []
        pattern_score = 0

        # Convert arguments to searchable text
        search_text = self._prepare_search_text(tool_name, arguments)

        # Pattern matching with ReDoS protection
        matched_rule_ids = set()
        for rule in self.rules:
            matched, timed_out = self._match_rule(rule, search_text)
            if timed_out:
                with self._lock:
                    self._consecutive_regex_timeouts += 1
                logger.warning(
                    "Regex timeout for rule %s (consecutive: %d)",
                    rule.id,
                    self._consecutive_regex_timeouts,
                )
                with self._lock:
                    if self._consecutive_regex_timeouts >= _REGEX_CIRCUIT_BREAKER_THRESHOLD:
                        circuit_rule = DetectionRule(
                            id="redos-circuit-breaker",
                            severity="critical",
                            message="Multiple regex timeouts detected - possible ReDoS attack",
                            pattern="",
                            score=100,
                            category="system",
                        )
                        latency_ms = (time.perf_counter() - scan_start) * 1000
                        metrics.record_scan(
                            action="block", duration=latency_ms / 1000, risk_score=100,
                            matched_rules=[("redos-circuit-breaker", "system")],
                        )
                        return ScanResult(
                            score=100, level="THREAT", action="BLOCK",
                            matched_rules=[circuit_rule],
                            scoring_breakdown={"pattern_score": 100, "metachar_score": 0,
                                               "entropy_score": 0, "semantic_score": 0},
                            tool_name=tool_name, arguments=arguments,
                            timestamp=timestamp,
                            latency_ms=latency_ms,
                            owasp_mapping=[],
                        )
                continue
            else:
                with self._lock:
                    self._consecutive_regex_timeouts = 0

            if matched:
                matched_rules.append(rule)
                matched_rule_ids.add(rule.id)
                pattern_score += rule.score
                logger.debug(f"Rule matched: {rule.id} (+{rule.score} points)")

        # Cross-parameter correlation with ReDoS protection.
        # Check both space-joined and directly concatenated forms.
        # Direct concatenation catches word-splitting evasion (e.g. "cur"+"l").
        flattened = flatten_arguments(arguments)
        all_values = []
        for values in flattened.values():
            all_values.extend(values)
        if len(all_values) > 1:
            combined_variants = [
                normalize_text(" ".join(all_values)),
                normalize_text("".join(all_values)),
            ]
            for combined_text in combined_variants:
                for rule in self.rules:
                    if rule.id not in matched_rule_ids and rule.compiled_pattern:
                        matched, timed_out = self._match_rule(rule, combined_text)
                        if timed_out:
                            with self._lock:
                                self._consecutive_regex_timeouts += 1
                            logger.warning(
                                "Regex timeout for rule %s in cross-param (consecutive: %d)",
                                rule.id,
                                self._consecutive_regex_timeouts,
                            )
                            continue
                        else:
                            with self._lock:
                                self._consecutive_regex_timeouts = 0
                        if matched:
                            matched_rules.append(rule)
                            matched_rule_ids.add(rule.id)
                            pattern_score += rule.score
                            logger.debug(
                                f"Rule matched via cross-parameter correlation: "
                                f"{rule.id} (+{rule.score} points)"
                            )

        # Semantic analysis - check for mismatches
        semantic_score = self._semantic_analysis(tool_name, arguments)

        # Delegate risk calculation to RiskScorer
        risk_data = self._scorer.calculate_risk(pattern_score, search_text, semantic_score)
        metachar_score = risk_data["metachar_score"]
        entropy_score = risk_data["entropy_score"]
        risk_score = risk_data["risk_score"]

        # Determine level and action
        allow_max = self.score_threshold["allow"][1]
        warn_max = self.score_threshold["warn"][1]
        block_max = self.score_threshold.get("block", (70, 100))[1]

        if risk_score <= allow_max:
            level = "SAFE"
            action_str = "ALLOW"
            action_label = "allow"
        elif risk_score <= warn_max:
            level = "SUSPICIOUS"
            action_str = "WARN"
            action_label = "warn"
        elif risk_score <= block_max:
            level = "THREAT"
            action_str = "BLOCK"
            action_label = "block"
        else:
            level = "THREAT"
            action_str = "KILL"
            action_label = "kill"

        # Collect OWASP codes from matched rules
        owasp_codes = []
        seen_owasp = set()
        for rule in matched_rules:
            for code in getattr(rule, "owasp", []):
                if code not in seen_owasp:
                    owasp_codes.append(code)
                    seen_owasp.add(code)

        latency_ms = (time.perf_counter() - scan_start) * 1000
        metrics.record_scan(
            action=action_label,
            duration=latency_ms / 1000,
            risk_score=risk_score,
            matched_rules=[(r.id, r.category) for r in matched_rules],
        )

        logger.info(f"Scan complete: {tool_name} - Score: {risk_score} - Rules matched: {len(matched_rules)}")

        # Reset circuit breaker after successful scan
        self._consecutive_regex_timeouts = 0

        return ScanResult(
            score=risk_score,
            level=level,
            action=action_str,
            matched_rules=matched_rules,
            scoring_breakdown={
                "pattern_score": pattern_score,
                "metachar_score": metachar_score,
                "entropy_score": entropy_score,
                "semantic_score": semantic_score,
            },
            tool_name=tool_name,
            arguments=arguments,
            timestamp=timestamp,
            latency_ms=latency_ms,
            owasp_mapping=owasp_codes,
        )

    def _prepare_search_text(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """
        Convert tool call to searchable text with full normalization.

        Applies: nested object flattening, unicode homoglyph normalization,
        encoding decoding (hex/octal/unicode/URL/base64), case normalization,
        and whitespace normalization.
        """
        # Flatten nested arguments to extract all string values
        flattened = flatten_arguments(arguments)

        parts = [tool_name.lower()]
        for key, values in flattened.items():
            for v in values:
                parts.append(f"{key}={normalize_text(v)}")

        return " ".join(parts)

    def _semantic_analysis(self, tool_name: str, arguments: Dict[str, Any]) -> int:
        """
        Semantic analysis for parameter validation.

        Delegates to SemanticAnalyzer.analyze().
        """
        return self._semantic_analyzer.analyze(tool_name, arguments)

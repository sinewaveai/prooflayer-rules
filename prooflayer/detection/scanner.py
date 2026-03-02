"""
Pattern Scanner
===============

Regex-based pattern matching with ReDoS protection for threat detection.
"""

import logging
import threading
from typing import List, Set, Tuple

from .models import DetectionRule

logger = logging.getLogger(__name__)

# ReDoS protection constants
REGEX_TIMEOUT_SECONDS = 0.1  # 100ms
REGEX_CIRCUIT_BREAKER_THRESHOLD = 3


class PatternScanner:
    """
    Scans text against detection rules using regex with ReDoS protection.

    Each regex match runs in a daemon thread with a timeout. A circuit breaker
    trips after consecutive timeouts to block suspicious requests.
    """

    def match_rule(
        self, rule: DetectionRule, text: str
    ) -> Tuple[bool, bool]:
        """
        Match a single rule against text with ReDoS protection.

        Args:
            rule: Detection rule with a compiled regex pattern.
            text: Text to scan.

        Returns:
            (matched, timed_out)
        """
        if not rule.compiled_pattern:
            return False, False

        matched_flag = [None]

        def _search():
            matched_flag[0] = rule.compiled_pattern.search(text) is not None

        t = threading.Thread(target=_search, daemon=True)
        t.start()
        t.join(timeout=REGEX_TIMEOUT_SECONDS)

        if t.is_alive():
            return False, True  # timed out

        return bool(matched_flag[0]), False

    def scan_text(
        self,
        rules: List[DetectionRule],
        text: str,
        consecutive_timeouts: int,
        lock: threading.Lock,
    ) -> Tuple[List[DetectionRule], int, Set[str], int]:
        """
        Scan text against all rules.

        Args:
            rules: List of detection rules to match.
            text: Normalized search text.
            consecutive_timeouts: Current consecutive timeout count.
            lock: Threading lock for timeout counter.

        Returns:
            (matched_rules, pattern_score, matched_rule_ids, updated_consecutive_timeouts)
            Returns None for the first element if the circuit breaker tripped.
        """
        matched_rules: List[DetectionRule] = []
        pattern_score = 0
        matched_rule_ids: Set[str] = set()

        for rule in rules:
            matched, timed_out = self.match_rule(rule, text)
            if timed_out:
                with lock:
                    consecutive_timeouts += 1
                logger.warning(
                    "Regex timeout for rule %s (consecutive: %d)",
                    rule.id,
                    consecutive_timeouts,
                )
                with lock:
                    if consecutive_timeouts >= REGEX_CIRCUIT_BREAKER_THRESHOLD:
                        return matched_rules, pattern_score, matched_rule_ids, consecutive_timeouts
                continue
            else:
                with lock:
                    consecutive_timeouts = 0

            if matched:
                matched_rules.append(rule)
                matched_rule_ids.add(rule.id)
                pattern_score += rule.score
                logger.debug("Rule matched: %s (+%d points)", rule.id, rule.score)

        return matched_rules, pattern_score, matched_rule_ids, consecutive_timeouts

    def scan_cross_param(
        self,
        rules: List[DetectionRule],
        combined_variants: List[str],
        matched_rule_ids: Set[str],
        consecutive_timeouts: int,
        lock: threading.Lock,
    ) -> Tuple[List[DetectionRule], int, Set[str], int]:
        """
        Cross-parameter correlation scan.

        Args:
            rules: List of detection rules.
            combined_variants: List of combined text variants to scan.
            matched_rule_ids: Already-matched rule IDs to skip.
            consecutive_timeouts: Current consecutive timeout count.
            lock: Threading lock for timeout counter.

        Returns:
            (new_matched_rules, additional_score, updated_matched_rule_ids, updated_consecutive_timeouts)
        """
        new_matched_rules: List[DetectionRule] = []
        additional_score = 0

        for combined_text in combined_variants:
            for rule in rules:
                if rule.id not in matched_rule_ids and rule.compiled_pattern:
                    matched, timed_out = self.match_rule(rule, combined_text)
                    if timed_out:
                        with lock:
                            consecutive_timeouts += 1
                        logger.warning(
                            "Regex timeout for rule %s in cross-param (consecutive: %d)",
                            rule.id,
                            consecutive_timeouts,
                        )
                        continue
                    else:
                        with lock:
                            consecutive_timeouts = 0
                    if matched:
                        new_matched_rules.append(rule)
                        matched_rule_ids.add(rule.id)
                        additional_score += rule.score
                        logger.debug(
                            "Rule matched via cross-parameter correlation: "
                            "%s (+%d points)",
                            rule.id,
                            rule.score,
                        )

        return new_matched_rules, additional_score, matched_rule_ids, consecutive_timeouts

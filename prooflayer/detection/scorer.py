"""
Risk Scorer
============

Calculates composite risk scores from multiple detection signals.
"""

import logging
from typing import Dict

from ..utils.entropy import calculate_shannon_entropy

logger = logging.getLogger(__name__)

# Shell metacharacters that indicate potential command injection
DANGEROUS_CHARS = [';', '|', '&&', '||', '`', '$', '>', '<']


class RiskScorer:
    """
    Calculates risk scores from 4 components:
    pattern matching, shell metacharacters, entropy, and semantic analysis.
    """

    def calculate_risk(
        self,
        pattern_score: int,
        search_text: str,
        semantic_score: int,
    ) -> Dict[str, int]:
        """
        Calculate composite risk score.

        Args:
            pattern_score: Sum of matched rule scores.
            search_text: Normalized text for metachar/entropy analysis.
            semantic_score: Score from semantic analysis.

        Returns:
            Dict with pattern_score, metachar_score, entropy_score,
            semantic_score, total_score, and risk_score (capped at 100).
        """
        metachar_score = 0
        for char in DANGEROUS_CHARS:
            if char in search_text:
                metachar_score += 10
                logger.debug("Dangerous char '%s' detected (+10 points)", char)

        entropy_score = 0
        entropy = calculate_shannon_entropy(search_text)
        if entropy > 4.5:
            entropy_score = 20
            logger.debug("High entropy detected: %.2f (+20 points)", entropy)

        total_score = pattern_score + metachar_score + entropy_score + semantic_score
        risk_score = min(total_score, 100)

        return {
            "pattern_score": pattern_score,
            "metachar_score": metachar_score,
            "entropy_score": entropy_score,
            "semantic_score": semantic_score,
            "total_score": total_score,
            "risk_score": risk_score,
        }

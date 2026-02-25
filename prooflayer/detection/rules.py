"""Rule loader for YAML detection rules."""

import yaml
import logging
from pathlib import Path
from typing import List

from .models import DetectionRule

logger = logging.getLogger(__name__)


class RuleLoader:
    """Load detection rules from YAML files."""

    @staticmethod
    def load_from_directory(rules_dir: str) -> List[DetectionRule]:
        """
        Load all YAML rule files from directory.

        Args:
            rules_dir: Directory containing YAML rule files

        Returns:
            List of DetectionRule objects
        """
        rules = []
        rules_path = Path(rules_dir)

        if not rules_path.exists():
            logger.warning(f"Rules directory not found: {rules_dir}")
            return rules

        for yaml_file in rules_path.glob("*.yaml"):
            try:
                file_rules = RuleLoader.load_from_file(str(yaml_file))
                rules.extend(file_rules)
                logger.info(f"Loaded {len(file_rules)} rules from {yaml_file.name}")
            except Exception as e:
                logger.error(f"Failed to load rules from {yaml_file}: {e}")

        return rules

    @staticmethod
    def load_from_file(file_path: str) -> List[DetectionRule]:
        """
        Load detection rules from a single YAML file.

        Args:
            file_path: Path to YAML file

        Returns:
            List of DetectionRule objects
        """
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return []

        rules = []
        for rule_data in data["rules"]:
            try:
                rule = DetectionRule(
                    id=rule_data["id"],
                    severity=rule_data.get("severity", "medium"),
                    message=rule_data["message"],
                    pattern=rule_data["pattern"],
                    score=rule_data.get("score", 10),
                    category=rule_data.get("category", "unknown")
                )
                rules.append(rule)
            except KeyError as e:
                logger.warning(f"Skipping invalid rule in {file_path}: missing {e}")

        return rules

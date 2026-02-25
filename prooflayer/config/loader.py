"""Configuration file loader."""

import yaml
from typing import Dict, Any
from pathlib import Path


class ConfigLoader:
    """Load ProofLayer configuration from YAML files."""

    @staticmethod
    def load(config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to YAML config file

        Returns:
            Configuration dictionary
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(path, "r") as f:
            config = yaml.safe_load(f)

        return config or {}

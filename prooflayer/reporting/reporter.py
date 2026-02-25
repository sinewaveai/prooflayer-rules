"""
Security Reporter
=================

Generates security reports in JSON and SARIF formats.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


class SecurityReporter:
    """
    Generates security reports for detected threats.
    """

    def __init__(self, report_dir: str = "./security-reports"):
        """
        Initialize security reporter.

        Args:
            report_dir: Directory to write reports
        """
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        threat_type: str,
        tool_name: str,
        arguments: Dict[str, Any],
        risk_score: int,
        matched_rules: List[Any],
        action: str
    ) -> Dict[str, Any]:
        """
        Generate a security report.

        Args:
            threat_type: Type of threat detected
            tool_name: MCP tool name
            arguments: Tool arguments
            risk_score: Calculated risk score
            matched_rules: List of matched detection rules
            action: Action taken (ALLOW/WARN/BLOCK/KILL)

        Returns:
            Dict containing report data and file path
        """
        timestamp = datetime.utcnow()
        timestamp_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        report = {
            "prooflayer_version": "0.1.0",
            "timestamp": timestamp_str,
            "threat": {
                "type": threat_type,
                "tool": tool_name,
                "arguments": arguments,
                "risk_score": risk_score,
                "action": action
            },
            "detection": {
                "rules_matched": [
                    {
                        "id": rule.id,
                        "severity": rule.severity,
                        "message": rule.message,
                        "category": rule.category
                    }
                    for rule in matched_rules
                ],
                "confidence": "HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 30 else "LOW"
            },
            "context": {
                "timestamp_detected": timestamp_str,
                "server": os.environ.get("MCP_SERVER_NAME", "unknown")
            }
        }

        # Write JSON report
        report_filename = f"threat-{timestamp.strftime('%Y%m%d-%H%M%S')}.json"
        report_path = self.report_dir / report_filename

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        report["report_path"] = str(report_path)

        return report

    def generate_sarif_report(
        self,
        threats: List[Dict[str, Any]]
    ) -> str:
        """
        Generate SARIF format report for CI/CD integration.

        Args:
            threats: List of threat detections

        Returns:
            Path to SARIF report file
        """
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ProofLayer Runtime Security",
                            "version": "0.1.0",
                            "informationUri": "https://www.proof-layer.com"
                        }
                    },
                    "results": [
                        {
                            "ruleId": threat["threat"]["type"],
                            "level": self._sarif_level(threat["threat"]["risk_score"]),
                            "message": {
                                "text": f"Security threat detected in {threat['threat']['tool']}"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": threat["threat"]["tool"]
                                        }
                                    }
                                }
                            ]
                        }
                        for threat in threats
                    ]
                }
            ]
        }

        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        sarif_path = self.report_dir / f"sarif-report-{timestamp}.sarif"

        with open(sarif_path, "w") as f:
            json.dump(sarif, f, indent=2)

        return str(sarif_path)

    def _sarif_level(self, risk_score: int) -> str:
        """Convert risk score to SARIF severity level."""
        if risk_score >= 70:
            return "error"
        elif risk_score >= 30:
            return "warning"
        else:
            return "note"

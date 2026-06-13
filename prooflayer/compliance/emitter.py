"""Map ProofLayer events to compliance framework evidence records."""

from importlib import resources
from typing import Any, Dict, Iterable, List, Optional, Set

import yaml

from . import frameworks
from .evidence import EvidenceRecord

SUPPORTED_FRAMEWORKS = {"nist_ai_rmf", "eu_ai_act", "soc2", "hipaa"}

_CATEGORY_CONTROL_MAP: Dict[str, Dict[str, List[str]]] = {
    "prompt_injection": {
        "nist_ai_rmf": ["nist-measure-01"],
        "eu_ai_act": ["eu-ai-act-15-04"],
        "soc2": ["soc2-cc7-03"],
        "hipaa": ["hipaa-164-312-b"],
    },
    "jailbreak": {
        "nist_ai_rmf": ["nist-measure-01"],
        "eu_ai_act": ["eu-ai-act-15-04"],
        "soc2": ["soc2-cc7-03"],
        "hipaa": ["hipaa-164-312-b"],
    },
    "tool_abuse": {
        "nist_ai_rmf": ["nist-map-04", "nist-manage-01"],
        "eu_ai_act": ["eu-ai-act-14-04", "eu-ai-act-15-02"],
        "soc2": ["soc2-cc6-06", "soc2-cc6-07"],
        "hipaa": ["hipaa-164-312-a1"],
    },
    "exfil": {
        "nist_ai_rmf": ["nist-measure-01"],
        "eu_ai_act": ["eu-ai-act-15-04"],
        "soc2": ["soc2-cc7-03"],
        "hipaa": ["hipaa-164-312-e1"],
    },
    "scope_drift": {
        "nist_ai_rmf": ["nist-map-01"],
        "eu_ai_act": ["eu-ai-act-13-03"],
        "soc2": ["soc2-cc6-04"],
        "hipaa": ["hipaa-164-308-a1"],
    },
    "state_manipulation": {
        "nist_ai_rmf": ["nist-measure-01"],
        "eu_ai_act": ["eu-ai-act-14-05"],
        "soc2": ["soc2-cc7-03"],
        "hipaa": ["hipaa-164-312-c1"],
    },
    "multi_turn": {
        "nist_ai_rmf": ["nist-measure-01", "nist-measure-02"],
        "eu_ai_act": ["eu-ai-act-15-05"],
        "soc2": ["soc2-cc7-05"],
        "hipaa": ["hipaa-164-308-a8"],
    },
}

_EVENT_TYPE_CONTROL_MAP: Dict[str, Dict[str, List[str]]] = {
    "eval_report": {
        "nist_ai_rmf": ["nist-measure-02"],
        "eu_ai_act": ["eu-ai-act-15-05"],
        "soc2": ["soc2-cc7-05"],
        "hipaa": ["hipaa-164-308-a8"],
    },
    "benchmark": {
        "nist_ai_rmf": ["nist-measure-03"],
        "eu_ai_act": ["eu-ai-act-15-06"],
        "soc2": ["soc2-cc7-06"],
        "hipaa": ["hipaa-164-308-a8"],
    },
}


class ComplianceEmitter:
    """Emit compliance evidence records from ProofLayer runtime events."""

    def __init__(self, frameworks: Optional[Iterable[str]] = None) -> None:
        """Initialize the emitter with one or more compliance frameworks."""
        selected = list(frameworks or sorted(SUPPORTED_FRAMEWORKS))
        invalid = sorted(set(selected) - SUPPORTED_FRAMEWORKS)
        if invalid:
            raise ValueError(
                "Unsupported compliance framework(s): " + ", ".join(invalid)
            )
        self.frameworks = selected
        self._control_ids = {
            framework: self._load_control_ids(framework) for framework in selected
        }

    def emit(
        self,
        event: Dict[str, Any],
        previous_hash: Optional[str] = None,
    ) -> List[EvidenceRecord]:
        """Map one runtime or eval event to hashed evidence records."""
        controls_by_framework = self._controls_for_event(event)
        evidence_records: List[EvidenceRecord] = []
        current_previous_hash = previous_hash
        for framework in self.frameworks:
            control_ids = controls_by_framework.get(framework, [])
            for control_id in control_ids:
                if control_id not in self._control_ids[framework]:
                    continue
                record = EvidenceRecord.from_event(
                    framework=framework,
                    control_id=control_id,
                    evidence_type=self._evidence_type(event),
                    event=event,
                    previous_hash=current_previous_hash,
                )
                current_previous_hash = record.evidence_hash
                evidence_records.append(record)
        return evidence_records

    def _controls_for_event(self, event: Dict[str, Any]) -> Dict[str, List[str]]:
        category = str(event.get("category", ""))
        event_type = str(event.get("event_type", ""))
        controls: Dict[str, Set[str]] = {
            framework: set() for framework in self.frameworks
        }
        for mapping in (
            _CATEGORY_CONTROL_MAP.get(category, {}),
            _EVENT_TYPE_CONTROL_MAP.get(event_type, {}),
        ):
            for framework, control_ids in mapping.items():
                if framework in controls:
                    controls[framework].update(control_ids)
        return {
            framework: sorted(control_ids)
            for framework, control_ids in controls.items()
            if control_ids
        }

    def _evidence_type(self, event: Dict[str, Any]) -> str:
        event_type = str(event.get("event_type", "detection"))
        if event_type == "eval_report":
            return "eval_report"
        if event_type == "benchmark":
            return "benchmark"
        if event.get("event_type") == "tool_call":
            return "tool_call_event"
        return "detection_event"

    def _load_control_ids(self, framework: str) -> Set[str]:
        payload = self.load_framework(framework)
        return {str(control["id"]) for control in payload["controls"]}

    @staticmethod
    def load_framework(framework: str) -> Dict[str, Any]:
        """Load a packaged compliance framework registry by name."""
        if framework not in SUPPORTED_FRAMEWORKS:
            raise ValueError(f"Unsupported compliance framework: {framework}")
        path = resources.files(frameworks).joinpath(f"{framework}.yaml")
        return yaml.safe_load(path.read_text(encoding="utf-8"))
